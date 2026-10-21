-- 0010: approval attestation hardening — findings of the independent review of
-- 0007 (docs/security/ADVERSARIAL_RESULTS.md §6). Each item below was
-- reproduced by a failing test before this migration (internal/kernel/
-- attestation_review_test.go, from the reviewer's probes).
--
--  H1/H2  Authority columns (closed_by, approved_by, posted_by, ...) could be
--         rewritten without a status change, defeating close/reopen SoD.
--         -> every *_attest trigger freezes authority columns except the ones
--            the specific transition sets; approval timestamps are DB time.
--  M1     The decision outcome was not part of the evidence (a REJECT
--         superseded the approved predecessor; close evidence allowed lock).
--         -> ctx carries the target status and is checked; supersede/retire
--            need the successor's attested APPROVE and a deferred check that an
--            approved successor exists at commit.
--  M2     workflow.define evidence named a Go-computed hash that SQL never
--         checked against the body; one evidence admitted several rows.
--         -> the body is bound by an SQL digest (workflow_body_digest) and the
--            key by ctx; evidence is single-use (M4).
--  M3     fiscal_period_closes and workflow_history were tenant-insertable
--         evidence; workflow_effects needed no evidence.
--         -> close records are written only by a definer function tied to the
--            consumed attestation (INSERT revoked); authority-kind history rows
--            and effects require the actor's evidence in the transaction.
--  M4     Evidence was matched, never consumed, and its subject hash checked
--         only at registration.
--         -> approval_use(): single use (approval_consumptions), live subject
--            hash and expiry re-checked at the moment of use.
--  L1     The canonical message could be re-parsed (separator inside a field,
--         a missing field dropped by concat_ws, JSON type confusion).
--         -> exact key set, exact JSON types, no U+001F anywhere, no comma in
--            permissions.
--  L3     Expiry was compared with the transaction start time.
--         -> clock_timestamp() at registration and at use.

-- ---------------------------------------------------------------------------
-- Single-use evidence
-- ---------------------------------------------------------------------------
CREATE TABLE approval_consumptions (
  nonce     uuid PRIMARY KEY REFERENCES approval_attestations(nonce),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  txid      bigint NOT NULL,
  used_for  text NOT NULL,
  used_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX approval_consumptions_tx ON approval_consumptions (tenant_id, txid, used_for);
ALTER TABLE approval_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_consumptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approval_consumptions USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
CREATE TRIGGER approval_consumptions_append_only BEFORE UPDATE OR DELETE ON approval_consumptions FOR EACH ROW EXECUTE FUNCTION append_only();
REVOKE ALL ON approval_consumptions FROM PUBLIC;
GRANT SELECT ON approval_consumptions TO serk_app;

-- ---------------------------------------------------------------------------
-- Strict verification (L1, L3)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION approval_authorize(a jsonb) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  t uuid := current_tenant();
  k bytea;
  now_s bigint := floor(extract(epoch FROM clock_timestamp()))::bigint;
  iat bigint; exp bigint; at bigint;
  fresh boolean;
  want text;
  n uuid;
  f text;
BEGIN
  IF t IS NULL THEN
    RAISE EXCEPTION 'approval attestation: no tenant session' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF a IS NULL OR jsonb_typeof(a) <> 'object'
     OR (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(a) AS key) IS DISTINCT FROM
        ARRAY['action','actor','auth_time','ctx','exp','iat','kid','mfa','nonce','perms','sig','subject_hash','subject_id','subject_type','tenant','v']::text[] THEN
    RAISE EXCEPTION 'approval attestation: malformed (unexpected or missing fields)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOREACH f IN ARRAY ARRAY['action','actor','ctx','kid','nonce','sig','subject_hash','subject_id','subject_type','tenant'] LOOP
    IF jsonb_typeof(a->f) <> 'string' OR position(chr(31) IN a->>f) > 0 THEN
      RAISE EXCEPTION 'approval attestation: malformed field %', f USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  FOREACH f IN ARRAY ARRAY['v','auth_time','iat','exp'] LOOP
    IF jsonb_typeof(a->f) <> 'number' OR (a->>f) !~ '^[0-9]{1,12}$' THEN
      RAISE EXCEPTION 'approval attestation: malformed field %', f USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  IF jsonb_typeof(a->'mfa') <> 'boolean' OR jsonb_typeof(a->'perms') <> 'array'
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(a->'perms') e
                 WHERE jsonb_typeof(e) <> 'string' OR e #>> '{}' = '' OR position(chr(31) IN e #>> '{}') > 0 OR position(',' IN e #>> '{}') > 0) THEN
    RAISE EXCEPTION 'approval attestation: malformed permissions or mfa' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (a->>'v') <> '1' OR (a->>'tenant') IS DISTINCT FROM t::text THEN
    RAISE EXCEPTION 'approval attestation: malformed or for another tenant' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF a->>'actor' = '' OR a->>'action' = '' OR a->>'sig' !~ '^[0-9a-f]{64}$' OR (a->>'nonce') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'approval attestation: missing fields' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT key INTO k FROM approval_keys WHERE tenant_id = t AND key_id = a->>'kid' AND active;
  IF k IS NULL THEN
    RAISE EXCEPTION 'approval attestation: unknown signing key' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF encode(hmac(convert_to(approval_canonical(a), 'UTF8'), k, 'sha256'), 'hex') <> a->>'sig' THEN
    RAISE EXCEPTION 'approval attestation: bad signature' USING ERRCODE = 'insufficient_privilege';
  END IF;
  iat := (a->>'iat')::bigint; exp := (a->>'exp')::bigint; at := NULLIF((a->>'auth_time')::bigint, 0);
  IF iat > now_s + 60 OR exp <= now_s OR exp - iat > 300 OR exp <= iat THEN
    RAISE EXCEPTION 'approval attestation: expired or not yet valid' USING ERRCODE = 'insufficient_privilege';
  END IF;
  want := approval_subject_hash(a->>'subject_type', a->>'subject_id');
  IF want IS NULL OR want IS DISTINCT FROM a->>'subject_hash' THEN
    RAISE EXCEPTION 'approval attestation: subject changed or unknown' USING ERRCODE = 'insufficient_privilege';
  END IF;
  fresh := (a->>'mfa')::boolean AND at IS NOT NULL AND at <= now_s + 60 AND now_s - at <= 600;
  n := (a->>'nonce')::uuid;
  BEGIN
    INSERT INTO approval_attestations(nonce, tenant_id, txid, actor, action, subject_type, subject_id, subject_hash, ctx, perms,
      mfa_claimed, mfa_fresh, auth_time, issued_at, expires_at, key_id, signature)
    VALUES (n, t, txid_current(), a->>'actor', a->>'action', a->>'subject_type', a->>'subject_id', a->>'subject_hash', a->>'ctx',
      ARRAY(SELECT jsonb_array_elements_text(a->'perms')), (a->>'mfa')::boolean, fresh,
      CASE WHEN at IS NULL THEN NULL ELSE to_timestamp(at) END, to_timestamp(iat), to_timestamp(exp), a->>'kid', a->>'sig');
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'approval attestation: already used (replay)' USING ERRCODE = 'insufficient_privilege';
  END;
  RETURN n;
END$$;

-- Unconsumed evidence in this transaction (lookup only).
CREATE OR REPLACE FUNCTION approval_in_tx(p_action text, p_type text, p_id text, p_actor text) RETURNS approval_attestations
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT a.* FROM approval_attestations a
   WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = p_action
     AND a.subject_type = p_type AND a.subject_id = p_id AND (p_actor IS NULL OR a.actor = p_actor)
     AND NOT EXISTS (SELECT 1 FROM approval_consumptions c WHERE c.nonce = a.nonce)
   ORDER BY a.recorded_at DESC LIMIT 1
$$;

-- Use (consume) evidence for exactly one transition (M4). The subject must
-- still hash to what was attested and the evidence must not have expired by
-- the wall clock. p_ctx NULL = the action has a single outcome.
CREATE OR REPLACE FUNCTION approval_use(p_action text, p_type text, p_id text, p_actor text, p_perms text[], p_mfa boolean,
                                        p_ctx text, p_used_for text)
RETURNS approval_attestations
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE r approval_attestations;
BEGIN
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
REVOKE ALL ON FUNCTION approval_use(text, text, text, text, text[], boolean, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approval_use(text, text, text, text, text[], boolean, text, text) TO serk_app;

-- 0007's entry point keeps its signature but now consumes.
CREATE OR REPLACE FUNCTION approval_require(p_action text, p_type text, p_id text, p_actor text, p_perms text[], p_mfa boolean)
RETURNS approval_attestations LANGUAGE sql VOLATILE SET search_path = pg_catalog, public AS $$
  SELECT approval_use(p_action, p_type, p_id, p_actor, p_perms, p_mfa, NULL, NULL)
$$;

-- Raises when an authority column changed that the transition does not set.
CREATE OR REPLACE FUNCTION authority_frozen(o jsonb, n jsonb, cols text[], allowed text[], what text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS $$
DECLARE c text;
BEGIN
  FOREACH c IN ARRAY cols LOOP
    IF NOT (c = ANY (allowed)) AND (o->c) IS DISTINCT FROM (n->c) THEN
      RAISE EXCEPTION '% % is part of the approval record and cannot be changed here', what, c USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END$$;
GRANT EXECUTE ON FUNCTION authority_frozen(jsonb, jsonb, text[], text[], text) TO serk_app;

-- ---------------------------------------------------------------------------
-- Journals (H-class: posted_by on an APPROVED journal; reversal binding)
-- ---------------------------------------------------------------------------
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
    PERFORM approval_use('journal.approve', 'journal', NEW.id::text, NEW.approved_by, ARRAY['journal.approve'], false, NULL,
                         'journal:' || NEW.id || ':APPROVED');
    NEW.approved_at := now();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'POSTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['posted_by','posted_at'], 'journal');
    PERFORM approval_use('journal.post', 'journal', NEW.id::text, NEW.posted_by, ARRAY['journal.post'], false, NULL,
                         'journal:' || NEW.id || ':POSTED');
    NEW.posted_at := now();
  ELSIF NEW.status = 'CANCELLED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'journal');
    PERFORM approval_use('journal.cancel', 'journal', NEW.id::text, NULL, ARRAY['journal.approve', 'journal.post'], false, NULL,
                         'journal:' || NEW.id || ':CANCELLED');
  ELSIF OLD.status = 'POSTED' AND NEW.status = 'REVERSED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['reversed_by'], 'journal');
    -- Only together with the attested posting, in this transaction, of the
    -- journal that reverses exactly this one.
    IF NOT EXISTS (SELECT 1 FROM journals r WHERE r.id = NEW.reversed_by AND r.reversal_of = NEW.id AND r.status = 'POSTED')
       OR NOT EXISTS (SELECT 1 FROM approval_consumptions c
                       WHERE c.tenant_id = current_tenant() AND c.txid = txid_current() AND c.used_for = 'journal:' || NEW.reversed_by || ':POSTED') THEN
      RAISE EXCEPTION 'a journal is reversed only by the attested posting of its reversal' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'journal');
  END IF;
  RETURN NEW;
END$$;

-- ---------------------------------------------------------------------------
-- Fiscal periods (H1) and their close records (M3)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fiscal_periods_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cols text[] := ARRAY['closed_by','closed_at','reopened_by','reopen_reason'];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'OPEN' OR NEW.closed_by IS NOT NULL OR NEW.closed_at IS NOT NULL OR NEW.reopened_by IS NOT NULL OR NEW.reopen_reason IS NOT NULL THEN
      RAISE EXCEPTION 'fiscal periods are created OPEN' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fiscal period');
    RETURN NEW;
  END IF;
  IF NEW.status IN ('CLOSED', 'LOCKED') THEN
    -- closed_at and the reopen fields are set by fiscal_periods_transition.
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['closed_by'], 'fiscal period');
    PERFORM approval_use('period.close', 'fiscal_period', NEW.id::text, NEW.closed_by, ARRAY['period.close'], false, NEW.status,
                         'fiscal_period:' || NEW.id || ':' || NEW.status);
  ELSIF OLD.status = 'CLOSED' AND NEW.status = 'OPEN' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, ARRAY['reopened_by','reopen_reason'], 'fiscal period');
    PERFORM approval_use('period.reopen', 'fiscal_period', NEW.id::text, NEW.reopened_by, ARRAY['period.reopen'], true, NULL,
                         'fiscal_period:' || NEW.id || ':OPEN');
  ELSE
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fiscal period');
  END IF;
  RETURN NEW;
END$$;

ALTER TABLE fiscal_period_closes ADD COLUMN attestation uuid UNIQUE REFERENCES approval_attestations(nonce);

-- The only writer of close records: called from fiscal_periods_transition
-- (trigger depth > 0) and only with the attestation consumed for exactly this
-- period and target status in this transaction.
CREATE OR REPLACE FUNCTION fiscal_period_close_record(p_period uuid, p_target text, p_action text, p_actor text, p_reason text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE per fiscal_periods; tb record; n uuid;
BEGIN
  IF pg_trigger_depth() < 1 THEN
    RAISE EXCEPTION 'period close records are written only by the period transition' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT c.nonce INTO n FROM approval_consumptions c
   WHERE c.tenant_id = current_tenant() AND c.txid = txid_current() AND c.used_for = 'fiscal_period:' || p_period || ':' || p_target;
  IF n IS NULL THEN
    RAISE EXCEPTION 'period close record without the attested transition' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO per FROM fiscal_periods WHERE id = p_period AND tenant_id = current_tenant();
  SELECT * INTO tb FROM fiscal_period_tb(per);
  INSERT INTO fiscal_period_closes(tenant_id, legal_entity_id, period_id, action, actor, reason, journal_count, tb_debits, tb_credits, tb_hash, attestation)
  VALUES (per.tenant_id, per.legal_entity_id, per.id, p_action, p_actor, p_reason, tb.journal_count, tb.debits, tb.credits, tb.tb_hash, n);
END$$;
REVOKE ALL ON FUNCTION fiscal_period_close_record(uuid, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fiscal_period_close_record(uuid, text, text, text, text) TO serk_app;
REVOKE INSERT ON fiscal_period_closes FROM serk_app;

CREATE OR REPLACE FUNCTION fiscal_periods_transition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pending integer; act text;
BEGIN
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  IF NOT ((OLD.status = 'OPEN' AND NEW.status IN ('CLOSED', 'LOCKED')) OR
          (OLD.status = 'CLOSED' AND NEW.status IN ('OPEN', 'LOCKED'))) THEN
    RAISE EXCEPTION 'illegal fiscal period transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status IN ('CLOSED', 'LOCKED') THEN
    IF NEW.closed_by IS NULL THEN
      RAISE EXCEPTION 'closing a period requires closed_by' USING ERRCODE = 'check_violation';
    END IF;
    SELECT COUNT(*) INTO pending FROM journals
     WHERE tenant_id = OLD.tenant_id AND legal_entity_id = OLD.legal_entity_id AND status = 'APPROVED'
       AND (business_event_at AT TIME ZONE 'UTC')::date BETWEEN OLD.starts_on AND OLD.ends_on;
    IF pending > 0 THEN
      RAISE EXCEPTION 'period % has % approved journal(s) awaiting posting; post or cancel them before closing', OLD.name, pending
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.closed_at := clock_timestamp();
    NEW.reopen_reason := NULL;
    NEW.reopened_by := NULL;
    act := CASE WHEN NEW.status = 'LOCKED' THEN 'LOCK' ELSE 'CLOSE' END;
  ELSE -- CLOSED -> OPEN
    IF NEW.reopen_reason IS NULL OR length(trim(NEW.reopen_reason)) < 5 OR NEW.reopened_by IS NULL THEN
      RAISE EXCEPTION 'reopening a closed period requires reopened_by and a reason' USING ERRCODE = 'check_violation';
    END IF;
    -- OLD.closed_by is frozen by fiscal_periods_attest (H1), so this SoD
    -- check compares against the attested closer.
    IF NEW.reopened_by = OLD.closed_by THEN
      RAISE EXCEPTION 'the user who closed a period cannot reopen it (segregation of duties)' USING ERRCODE = 'check_violation';
    END IF;
    act := 'REOPEN';
  END IF;
  PERFORM fiscal_period_close_record(OLD.id, NEW.status, act,
          CASE WHEN act = 'REOPEN' THEN NEW.reopened_by ELSE NEW.closed_by END, NEW.reopen_reason);
  IF act = 'REOPEN' THEN
    NEW.closed_by := NULL;
    NEW.closed_at := NULL;
  END IF;
  RETURN NEW;
END$$;

-- ---------------------------------------------------------------------------
-- FX sources, policies, snapshots
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fx_sources_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cols text[] := ARRAY['approved_by','approved_at'];
BEGIN
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx source');
  ELSIF NEW.status = 'APPROVED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, cols, 'fx source');
    PERFORM approval_use('fx.source.approve', 'fx_source', NEW.source_id, NEW.approved_by, ARRAY['fx.approve'], false, NULL, NULL);
    NEW.approved_at := now();
  ELSE
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx source');
    PERFORM approval_use('fx.source.retire', 'fx_source', NEW.source_id, NULL, ARRAY['fx.approve'], false, NULL, NULL);
  END IF;
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION fx_policies_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cols text[] := ARRAY['approved_by','approved_at'];
BEGIN
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx policy');
  ELSIF NEW.status = 'APPROVED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, cols, 'fx policy');
    PERFORM approval_use('fx.policy.decide', 'fx_policy', NEW.id::text, NEW.approved_by, ARRAY['fx.policy.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF NEW.status = 'REJECTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx policy');
    PERFORM approval_use('fx.policy.decide', 'fx_policy', NEW.id::text, NULL, ARRAY['fx.policy.approve'], false, 'REJECTED', NULL);
  ELSIF NEW.status = 'RETIRED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'fx policy');
    -- Only while an attested APPROVE of a successor for the same
    -- entity/purpose is pending in this transaction (and see the deferred
    -- check below).
    IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN fx_policies p ON p.id::text = a.subject_id
                    WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'fx.policy.decide' AND a.ctx = 'APPROVED'
                      AND p.legal_entity_id = NEW.legal_entity_id AND p.purpose = NEW.purpose AND p.id <> NEW.id) THEN
      RAISE EXCEPTION 'an FX policy is retired only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION fx_policies_successor_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM fx_policies p WHERE p.tenant_id = NEW.tenant_id AND p.legal_entity_id = NEW.legal_entity_id
                    AND p.purpose = NEW.purpose AND p.status = 'APPROVED') THEN
    RAISE EXCEPTION 'retiring an FX policy requires an approved successor at commit' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER fx_policies_successor_check AFTER UPDATE ON fx_policies DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.status = 'RETIRED' AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION fx_policies_successor_check();

CREATE OR REPLACE FUNCTION fx_snapshots_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r approval_attestations;
BEGIN
  IF TG_OP = 'INSERT' OR NEW.approval_status IS NOT DISTINCT FROM OLD.approval_status THEN
    IF TG_OP = 'UPDATE' AND row(NEW.approver_mfa, NEW.variance_exception) IS DISTINCT FROM row(OLD.approver_mfa, OLD.variance_exception) THEN
      RAISE EXCEPTION 'fx snapshot approval evidence is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.approval_status = 'APPROVED' THEN
    r := approval_use('fx.snapshot.approve', 'fx_snapshot', NEW.snapshot_id::text, NEW.approved_by, ARRAY['fx.approve'], false, NULL, NULL);
    NEW.approver_mfa := r.mfa_fresh;
    NEW.decided_at := now();
    IF NEW.variance_exception AND NOT ('fx.approve_exception' = ANY (r.perms) AND r.mfa_fresh) THEN
      RAISE EXCEPTION 'a variance exception requires fx.approve_exception and a recent MFA in the attestation' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF NEW.approval_status = 'REJECTED' THEN
    PERFORM approval_use('fx.snapshot.reject', 'fx_snapshot', NEW.snapshot_id::text, NEW.rejected_by, ARRAY['fx.approve'], false, NULL, NULL);
    NEW.decided_at := now();
  ELSIF NEW.approval_status = 'DISPUTED' THEN
    PERFORM approval_use('fx.snapshot.withdraw', 'fx_snapshot', NEW.snapshot_id::text, NULL, ARRAY['fx.approve'], false, NULL, NULL);
  END IF;
  RETURN NEW;
END$$;

-- ---------------------------------------------------------------------------
-- WBS versions (H2, M1)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION wbs_versions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cols text[] := ARRAY['approved_by','approved_at'];
BEGIN
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'WBS version');
  ELSIF NEW.status = 'APPROVED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, cols, 'WBS version');
    PERFORM approval_use('wbs.decide', 'wbs_version', NEW.id::text, NEW.approved_by, ARRAY['wbs.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF NEW.status = 'REJECTED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'WBS version');
    PERFORM approval_use('wbs.decide', 'wbs_version', NEW.id::text, NULL, ARRAY['wbs.approve'], false, 'REJECTED', NULL);
  ELSIF NEW.status = 'SUPERSEDED' THEN
    PERFORM authority_frozen(to_jsonb(OLD), to_jsonb(NEW), cols, '{}', 'WBS version');
    IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN wbs_versions v ON v.id::text = a.subject_id
                    WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'wbs.decide' AND a.ctx = 'APPROVED'
                      AND v.project_id = NEW.project_id AND v.id <> NEW.id) THEN
      RAISE EXCEPTION 'a WBS version is superseded only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION wbs_versions_successor_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM wbs_versions v WHERE v.tenant_id = NEW.tenant_id AND v.project_id = NEW.project_id AND v.status = 'APPROVED') THEN
    RAISE EXCEPTION 'superseding a WBS version requires an approved successor at commit' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER wbs_versions_successor_check AFTER UPDATE ON wbs_versions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.status = 'SUPERSEDED' AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION wbs_versions_successor_check();

-- ---------------------------------------------------------------------------
-- Workflow definitions (M2), history and effects (M3)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION workflow_body_digest(b jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $$
  SELECT 'sha256:' || encode(digest(convert_to(b::text, 'UTF8'), 'sha256'), 'hex')
$$;
GRANT EXECUTE ON FUNCTION workflow_body_digest(jsonb) TO serk_app;

CREATE OR REPLACE FUNCTION workflow_definitions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Exactly this body (digest computed here, not supplied), this key, this
  -- author; the evidence is consumed, so one attestation = one definition.
  PERFORM approval_use('workflow.define', 'workflow_definition_body', workflow_body_digest(NEW.body), NEW.proposed_by,
                       ARRAY['workflow.define'], false, NEW.key, 'workflow_definition:' || NEW.key || ':' || NEW.version);
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION workflow_history_attest() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  -- Entries that narrate a person's authority must be written in the same
  -- transaction as that person's verified evidence. Informational entries
  -- (EFFECT_FAILED, EXPIRED, ESCALATED) and system actors are exempt.
  IF NEW.kind IN ('STARTED', 'DECIDED', 'EFFECT', 'STEP_COMPLETED', 'COMPLETED', 'REJECTED', 'CANCELLED')
     AND NEW.actor NOT LIKE 'system:%'
     AND NOT EXISTS (SELECT 1 FROM approval_attestations a
                      WHERE a.tenant_id = current_tenant() AND a.txid = txid_current() AND a.actor = NEW.actor) THEN
    RAISE EXCEPTION 'workflow history entry % for % without that person''s verified approval in this transaction', NEW.kind, NEW.actor
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_history_attest BEFORE INSERT ON workflow_history FOR EACH ROW EXECUTE FUNCTION workflow_history_attest();

CREATE OR REPLACE FUNCTION workflow_effects_attest() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  -- An effect is executed only by the person whose verified decision on this
  -- instance completes the step, in that same transaction (the effect row
  -- precedes the subject transition, which has its own attestation).
  IF NOT EXISTS (SELECT 1 FROM approval_attestations a
                  WHERE a.tenant_id = current_tenant() AND a.txid = txid_current() AND a.action = 'workflow.decide'
                    AND a.subject_type = 'workflow_instance' AND a.subject_id = NEW.instance_id::text AND a.actor = NEW.executed_by
                    AND a.ctx = NEW.step_index || ':APPROVE') THEN
    RAISE EXCEPTION 'workflow effect on % % without the executing person''s verified decision in this transaction', NEW.subject_type, NEW.subject_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_effects_attest BEFORE INSERT ON workflow_effects FOR EACH ROW EXECUTE FUNCTION workflow_effects_attest();

REVOKE ALL ON FUNCTION workflow_history_attest(), workflow_effects_attest(), fx_policies_successor_check(), wbs_versions_successor_check() FROM PUBLIC;
