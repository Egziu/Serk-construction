-- 0012: findings of the independent RE-verification of 0010
-- (docs/security/INDEPENDENT_REVIEW_2_2026-10-21.md). Each was reproduced by
-- the re-verifier's probes (internal/kernel/attestation_reverify_test.go).
--
--  M-1  fx_snapshots: a genuine withdraw/reject let the statement rewrite the
--       approval record (approved_by, decided_at, approver_mfa, ...).
--       -> authority_frozen per transition; DB time; flags only from evidence.
--  M-2  workflow_history: 'system:%' actors were exempt and any evidence of the
--       actor in the transaction sufficed.
--       -> each kind is bound to its own evidence on THIS instance (or, for
--          timer kinds, to the instance state the timer just produced).
--  L-1  approval_use() was callable directly by the tenant login with a
--       caller-chosen consumption label, which two checks trusted.
--       -> approval_use() runs only inside a trigger (pg_trigger_depth() > 0;
--          the tenant login cannot create triggers or functions); readers look
--          evidence up by action/subject/ctx, not by label.
--  L-2  close, reopen, close in one transaction collided on the label lookup.
--       -> fixed by the same lookup (latest matching consumption).
--  L-3  workflow_definitions.body_hash was not verified by SQL.
--       -> body_hash must equal workflow_body_digest(body) for new rows (the
--          kernel now stores the SQL digest and verifies it on load; legacy
--          Go-canonical hashes on existing rows remain readable).
--  workflow_decide_definition's own approval check moves into an UPDATE
--  trigger (it called approval_require at trigger depth 0).

-- ---------------------------------------------------------------------------
-- L-1: approval_use only from triggers
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION approval_use(p_action text, p_type text, p_id text, p_actor text, p_perms text[], p_mfa boolean,
                                        p_ctx text, p_used_for text)
RETURNS approval_attestations
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE r approval_attestations;
BEGIN
  IF pg_trigger_depth() < 1 THEN
    RAISE EXCEPTION 'approval evidence is used only by the transition it authorises' USING ERRCODE = 'insufficient_privilege';
  END IF;
  r := approval_in_tx(p_action, p_type, p_id, p_actor);
  IF r.nonce IS NULL THEN
    RAISE EXCEPTION '% of % % requires a verified approval attestation for %', p_action, p_type, p_id, COALESCE(p_actor, 'an authorised person')
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_ctx IS NOT NULL AND r.ctx IS DISTINCT FROM p_ctx THEN
    RAISE EXCEPTION 'the attestation authorises a different decision (%), not %', r.ctx, p_ctx USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT (r.perms && p_perms) THEN
    RAISE EXCEPTION '% requires permission %; the attested person holds none of them', p_action, array_to_string(p_perms, ' or ')
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_mfa AND NOT r.mfa_fresh THEN
    RAISE EXCEPTION '% requires a recent multi-factor authentication in the attestation', p_action USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF r.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'approval attestation expired before use' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF r.subject_type <> 'workflow_definition_body'
     AND approval_subject_hash(r.subject_type, r.subject_id) IS DISTINCT FROM r.subject_hash THEN
    RAISE EXCEPTION '% % changed after the approval was attested', r.subject_type, r.subject_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  INSERT INTO approval_consumptions(nonce, tenant_id, txid, used_for)
  VALUES (r.nonce, r.tenant_id, txid_current(), COALESCE(p_used_for, p_action || ':' || p_type || ':' || p_id));
  RETURN r;
END$$;

-- Evidence consumed in THIS transaction for an action on a subject (lookup by
-- the attested fields, never by a label).
CREATE OR REPLACE FUNCTION approval_consumed_in_tx(p_actions text[], p_type text, p_id text, p_ctx text) RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT a.nonce FROM approval_consumptions c JOIN approval_attestations a ON a.nonce = c.nonce
   WHERE c.tenant_id = current_tenant() AND c.txid = txid_current()
     AND a.action = ANY (p_actions) AND a.subject_type = p_type AND a.subject_id = p_id
     AND (p_ctx IS NULL OR a.ctx = p_ctx)
   ORDER BY c.used_at DESC LIMIT 1
$$;
GRANT EXECUTE ON FUNCTION approval_consumed_in_tx(text[], text, text, text) TO serk_app;

-- Reversal binding (journals_attest) without labels.
CREATE OR REPLACE FUNCTION journals_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cols text[] := ARRAY['approved_by','approved_at','posted_by','posted_at','reversed_by'];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL OR NEW.posted_by IS NOT NULL
       OR NEW.posted_at IS NOT NULL OR NEW.reversed_by IS NOT NULL THEN
      RAISE EXCEPTION 'journals are created DRAFT without approval fields' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'journal');
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['approved_by','approved_at'], 'journal');
    PERFORM approval_use('journal.approve', 'journal', NEW.id::text, NEW.approved_by, ARRAY['journal.approve'], false, NULL, NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'POSTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['posted_by','posted_at'], 'journal');
    PERFORM approval_use('journal.post', 'journal', NEW.id::text, NEW.posted_by, ARRAY['journal.post'], false, NULL, NULL);
    NEW.posted_at := now();
  ELSIF NEW.status = 'CANCELLED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'journal');
    PERFORM approval_use('journal.cancel', 'journal', NEW.id::text, NULL, ARRAY['journal.approve', 'journal.post'], false, NULL, NULL);
  ELSIF OLD.status = 'POSTED' AND NEW.status = 'REVERSED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['reversed_by'], 'journal');
    IF NOT EXISTS (SELECT 1 FROM journals r WHERE r.id = NEW.reversed_by AND r.reversal_of = NEW.id AND r.status = 'POSTED')
       OR approval_consumed_in_tx(ARRAY['journal.post'], 'journal', NEW.reversed_by::text, NULL) IS NULL THEN
      RAISE EXCEPTION 'a journal is reversed only by the attested posting of its reversal' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'journal');
  END IF;
  RETURN NEW;
END$$;

-- Close records (L-1, L-2): linked to the attestation that authorised THIS
-- period's transition to THIS target, found by its attested fields.
CREATE OR REPLACE FUNCTION fiscal_period_close_record(p_period uuid, p_target text, p_action text, p_actor text, p_reason text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE per fiscal_periods; tb record; n uuid;
BEGIN
  IF pg_trigger_depth() < 1 THEN
    RAISE EXCEPTION 'period close records are written only by the period transition' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_target = 'OPEN' THEN
    n := approval_consumed_in_tx(ARRAY['period.reopen'], 'fiscal_period', p_period::text, NULL);
  ELSE
    n := approval_consumed_in_tx(ARRAY['period.close'], 'fiscal_period', p_period::text, p_target);
  END IF;
  IF n IS NULL OR NOT EXISTS (SELECT 1 FROM approval_attestations a WHERE a.nonce = n AND a.actor = p_actor) THEN
    RAISE EXCEPTION 'period close record without the attested transition by %', p_actor USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO per FROM fiscal_periods WHERE id = p_period AND tenant_id = current_tenant();
  SELECT * INTO tb FROM fiscal_period_tb(per);
  INSERT INTO fiscal_period_closes(tenant_id, legal_entity_id, period_id, action, actor, reason, journal_count, tb_debits, tb_credits, tb_hash, attestation)
  VALUES (per.tenant_id, per.legal_entity_id, per.id, p_action, p_actor, p_reason, tb.journal_count, tb.debits, tb.credits, tb.tb_hash, n);
END$$;

-- ---------------------------------------------------------------------------
-- M-1: fx_snapshots approval record frozen per transition
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fx_snapshots_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  r approval_attestations;
  cols text[] := ARRAY['approved_by','rejected_by','decided_at','decision_reason','variance_exception','approver_mfa'];
BEGIN
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;  -- birth state (PENDING, no decision fields) is enforced by fx_snapshots_guard
  END IF;
  IF NEW.approval_status IS NOT DISTINCT FROM OLD.approval_status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx snapshot');
    RETURN NEW;
  END IF;
  IF OLD.approval_status = 'PENDING' AND NEW.approval_status = 'APPROVED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols,
      ARRAY['approved_by','decided_at','decision_reason','variance_exception','approver_mfa'], 'fx snapshot');
    r := approval_use('fx.snapshot.approve', 'fx_snapshot', NEW.snapshot_id::text, NEW.approved_by, ARRAY['fx.approve'], false, NULL, NULL);
    NEW.approver_mfa := r.mfa_fresh;
    NEW.decided_at := now();
    IF NEW.variance_exception AND NOT ('fx.approve_exception' = ANY (r.perms) AND r.mfa_fresh) THEN
      RAISE EXCEPTION 'a variance exception requires fx.approve_exception and a recent MFA in the attestation' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF OLD.approval_status = 'PENDING' AND NEW.approval_status = 'REJECTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['rejected_by','decided_at','decision_reason'], 'fx snapshot');
    PERFORM approval_use('fx.snapshot.reject', 'fx_snapshot', NEW.snapshot_id::text, NEW.rejected_by, ARRAY['fx.approve'], false, NULL, NULL);
    NEW.decided_at := now();
  ELSIF NEW.approval_status = 'DISPUTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['decision_reason'], 'fx snapshot');
    PERFORM approval_use('fx.snapshot.withdraw', 'fx_snapshot', NEW.snapshot_id::text, NULL, ARRAY['fx.approve'], false, NULL, NULL);
  ELSE
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx snapshot');
  END IF;
  RETURN NEW;
END$$;

-- ---------------------------------------------------------------------------
-- M-2: history bound to its own evidence or to the state the timer produced
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION workflow_history_attest() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE w workflow_instances; ok boolean;
BEGIN
  SELECT * INTO w FROM workflow_instances WHERE id = NEW.instance_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown workflow instance' USING ERRCODE = 'foreign_key_violation';
  END IF;
  ok := CASE
    WHEN NEW.kind = 'STARTED' THEN
      EXISTS (SELECT 1 FROM approval_attestations a WHERE a.tenant_id = current_tenant() AND a.txid = txid_current()
               AND a.action = 'workflow.start' AND a.actor = NEW.actor AND a.subject_id = w.subject_id::text AND a.ctx = w.definition_id::text)
    WHEN NEW.kind IN ('DECIDED', 'STEP_COMPLETED', 'COMPLETED', 'EFFECT', 'REJECTED') THEN
      EXISTS (SELECT 1 FROM approval_attestations a WHERE a.tenant_id = current_tenant() AND a.txid = txid_current()
               AND a.action = 'workflow.decide' AND a.actor = NEW.actor AND a.subject_type = 'workflow_instance' AND a.subject_id = NEW.instance_id::text)
    WHEN NEW.kind = 'CANCELLED' THEN
      EXISTS (SELECT 1 FROM approval_attestations a WHERE a.tenant_id = current_tenant() AND a.txid = txid_current()
               AND a.action = 'workflow.cancel' AND a.actor = NEW.actor AND a.subject_type = 'workflow_instance' AND a.subject_id = NEW.instance_id::text)
    -- Timer narrations: only the timer identity, only when the instance is in
    -- the state the narration claims.
    WHEN NEW.kind = 'EXPIRED' THEN NEW.actor = 'system:workflow-timer' AND w.status = 'EXPIRED'
    WHEN NEW.kind = 'ESCALATED' THEN NEW.actor = 'system:workflow-timer' AND w.escalated_at IS NOT NULL
    -- Effect failures are recorded after the failed decision rolled back, so
    -- no evidence exists; they must match a recorded failure on the instance.
    WHEN NEW.kind = 'EFFECT_FAILED' THEN NEW.actor NOT LIKE 'system:%' AND (w.last_error IS NOT NULL OR
      EXISTS (SELECT 1 FROM approval_attestations a WHERE a.tenant_id = current_tenant() AND a.txid = txid_current()
               AND a.action = 'workflow.decide' AND a.actor = NEW.actor AND a.subject_id = NEW.instance_id::text))
    ELSE false
  END;
  IF NOT ok THEN
    RAISE EXCEPTION 'workflow history entry % by % is not backed by the matching verified evidence or instance state', NEW.kind, NEW.actor
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END$$;

-- ---------------------------------------------------------------------------
-- L-3 + decide_definition at trigger depth
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION workflow_definitions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.body_hash IS DISTINCT FROM workflow_body_digest(NEW.body) THEN
      RAISE EXCEPTION 'workflow definition body_hash must be the digest of its body' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('workflow.define', 'workflow_definition_body', NEW.body_hash, NEW.proposed_by,
                         ARRAY['workflow.define'], false, NEW.key, NULL);
    RETURN NEW;
  END IF;
  -- UPDATE: the decision on a DRAFT (publish/reject) needs the decider's
  -- attestation for exactly that outcome; MFA for publication.
  IF OLD.status = 'DRAFT' AND NEW.status IN ('PUBLISHED', 'REJECTED') THEN
    PERFORM approval_use('workflow.decide_definition', 'workflow_definition', NEW.id::text, NEW.decided_by,
                         ARRAY['workflow.publish'], NEW.status = 'PUBLISHED', NEW.status, NULL);
  END IF;
  RETURN NEW;
END$$;
DROP TRIGGER workflow_definitions_attest ON workflow_definitions;
CREATE TRIGGER workflow_definitions_attest BEFORE INSERT OR UPDATE ON workflow_definitions FOR EACH ROW EXECUTE FUNCTION workflow_definitions_attest();

CREATE OR REPLACE FUNCTION workflow_decide_definition(p_id uuid, p_status text, p_by text, p_reason text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE d workflow_definitions%ROWTYPE;
BEGIN
  IF p_status NOT IN ('PUBLISHED', 'REJECTED') THEN
    RAISE EXCEPTION 'a definition is decided PUBLISHED or REJECTED' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO d FROM workflow_definitions WHERE id = p_id AND tenant_id = current_tenant();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown workflow definition' USING ERRCODE = 'foreign_key_violation';
  END IF;
  -- Fail fast (no lock taken) when no matching evidence is pending; the
  -- binding check itself is workflow_definitions_attest on the UPDATE below.
  IF approval_in_tx('workflow.decide_definition', 'workflow_definition', p_id::text, p_by) IS NULL THEN
    RAISE EXCEPTION 'workflow.decide_definition of workflow_definition % requires a verified approval attestation for %', p_id, p_by
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  PERFORM workflow_gate_lock(d.tenant_id, d.subject, true);
  SELECT * INTO d FROM workflow_definitions WHERE id = p_id FOR UPDATE;
  IF d.status <> 'DRAFT' THEN
    RAISE EXCEPTION 'workflow definition is %', d.status USING ERRCODE = 'check_violation';
  END IF;
  IF p_status = 'PUBLISHED' THEN
    IF EXISTS (SELECT 1 FROM workflow_definitions WHERE tenant_id = d.tenant_id AND key = d.key AND status IN ('PUBLISHED', 'RETIRED') AND version > d.version) THEN
      RAISE EXCEPTION 'a newer version of % was already published; propose a new version instead', d.key USING ERRCODE = 'check_violation';
    END IF;
    PERFORM set_config('serk.wf_decide', 'retire:' || d.key, true);
    UPDATE workflow_definitions SET status = 'RETIRED' WHERE tenant_id = d.tenant_id AND key = d.key AND status = 'PUBLISHED';
  END IF;
  PERFORM set_config('serk.wf_decide', 'decide:' || d.id::text, true);
  UPDATE workflow_definitions SET status = p_status, decided_by = p_by, decision_reason = NULLIF(p_reason, '') WHERE id = d.id;
  PERFORM set_config('serk.wf_decide', '', true);
END$$;
