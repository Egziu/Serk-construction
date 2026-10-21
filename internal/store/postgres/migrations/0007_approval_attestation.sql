-- 0007 — GATEA-APPROVAL-01: verified approval provenance at the SQL trust
-- boundary.
--
-- Before: tenant logins wrote approver identities (approved_by, decided_by,
-- closed_by, ...) and MFA flags as plain text/booleans. A stolen or injected
-- tenant credential could therefore manufacture approvals — reproduced in
-- docs/security/evidence/approval-forgery-before.txt (two invented approvers
-- with mfa=true took a journal to POSTED under a mandatory workflow).
--
-- After: every sensitive transition requires, in the SAME transaction, a
-- verified approval attestation for that action, subject, subject content
-- and person. Attestations are HMAC-SHA256-signed by the API kernel after it
-- has verified the person's OIDC token, permissions, scope and step-up MFA
-- (pkg/attest). PostgreSQL verifies them with a per-tenant key stored in a
-- table no application login can read, rejects replays (single-use nonce),
-- expiry, tenant/subject/content substitution, and records them as immutable
-- evidence. Approver columns and MFA flags must match the verified evidence;
-- MFA flags are overwritten from it.
--
-- Residual (documented in docs/security/APPROVAL_ATTESTATION_DESIGN.md):
-- whoever holds the signing secret (the API process) can sign; maker-side
-- attribution (created_by of drafts) is still asserted by the tenant login.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- ---------------------------------------------------------------------------
-- Keys: owner-only. No grant to any application role.
-- ---------------------------------------------------------------------------
CREATE TABLE approval_keys (
  tenant_id  uuid NOT NULL REFERENCES tenants(id),
  key_id     text NOT NULL CHECK (key_id ~ '^[a-z0-9_-]{1,32}$'),
  key        bytea NOT NULL CHECK (octet_length(key) >= 32),
  active     boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key_id)
);
REVOKE ALL ON approval_keys FROM PUBLIC;

-- Installs or rotates a tenant verification key (provisioning only).
CREATE OR REPLACE FUNCTION approval_key_install(p_tenant uuid, p_kid text, p_key bytea) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO approval_keys(tenant_id, key_id, key) VALUES (p_tenant, p_kid, p_key)
  ON CONFLICT (tenant_id, key_id) DO UPDATE SET key = EXCLUDED.key, active = true;
$$;
REVOKE ALL ON FUNCTION approval_key_install(uuid, text, bytea) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Evidence: one row per verified attestation. Written only by
-- approval_authorize() (owner rights); readable by the tenant (RLS).
-- ---------------------------------------------------------------------------
CREATE TABLE approval_attestations (
  nonce        uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  txid         bigint NOT NULL,
  actor        text NOT NULL,
  action       text NOT NULL,
  subject_type text NOT NULL,
  subject_id   text NOT NULL,
  subject_hash text NOT NULL,
  ctx          text NOT NULL,
  perms        text[] NOT NULL,
  mfa_claimed  boolean NOT NULL,
  mfa_fresh    boolean NOT NULL,
  auth_time    timestamptz,
  issued_at    timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  key_id       text NOT NULL,
  signature    text NOT NULL,
  recorded_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX approval_attestations_tx ON approval_attestations(txid, tenant_id, action, subject_type, subject_id);
CREATE INDEX approval_attestations_subject ON approval_attestations(tenant_id, subject_type, subject_id);
CREATE TRIGGER approval_attestations_append_only BEFORE UPDATE OR DELETE ON approval_attestations FOR EACH ROW EXECUTE FUNCTION append_only();
ALTER TABLE approval_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approval_attestations USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
GRANT SELECT ON approval_attestations TO serk_app;

-- ---------------------------------------------------------------------------
-- Content binding: the hash of the subject as it is now. Computed by the
-- database for both the signer (which asks before signing) and the verifier.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION approval_subject_hash(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE h text; t uuid := current_tenant();
BEGIN
  -- Always scoped to the session's tenant: this also runs with owner rights
  -- (inside approval_authorize), where RLS may not apply.
  IF p_type = 'journal' THEN
    -- Live content: header and every line as stored now (a DRAFT line added
    -- or edited after review changes the hash and voids pending approvals).
    SELECT concat_ws('|', j.id, j.legal_entity_id, COALESCE(j.project_id::text, ''), j.functional_currency,
             extract(epoch FROM j.business_event_at)::text, j.description, j.source_type, COALESCE(j.source_ref, ''),
             COALESCE(j.reversal_of::text, ''), j.created_by, j.command_hash,
             (SELECT string_agg(concat_ws(',', l.line_no, l.account_id, l.side, l.amount::text, l.currency, COALESCE(l.txn_amount::text, ''),
                       COALESCE(l.txn_currency, ''), COALESCE(l.fx_snapshot_id::text, ''), COALESCE(l.project_id::text, ''),
                       COALESCE(l.cost_code_id::text, ''), COALESCE(l.memo, '')), ';' ORDER BY l.line_no)
                FROM journal_lines l WHERE l.journal_id = j.id))
      INTO h FROM journals j WHERE j.tenant_id = t AND j.id::text = p_id;
  ELSIF p_type = 'fx_snapshot' THEN
    SELECT concat_ws('|', snapshot_id, base_currency, quote_currency, rate::text, rate_type, source_id,
                     extract(epoch FROM effective_from_utc)::text, source_document_hash, approval_status)
      INTO h FROM fx_snapshots WHERE tenant_id = t AND snapshot_id::text = p_id;
  ELSIF p_type = 'fx_source' THEN
    SELECT concat_ws('|', source_id, source_type, max_variance::text, requires_document_hash::text, status, created_by)
      INTO h FROM fx_sources WHERE tenant_id = t AND source_id = p_id;
  ELSIF p_type = 'fx_policy' THEN
    SELECT concat_ws('|', id, legal_entity_id, purpose, version, rate_type, array_to_string(source_priority, ','),
                     extract(epoch FROM max_staleness)::text, allow_inverse::text, status, created_by)
      INTO h FROM fx_policies WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type = 'wbs_version' THEN
    SELECT concat_ws('|', v.id, v.project_id, v.version, v.status, v.created_by,
             (SELECT string_agg(n.code || '=' || n.name, ';' ORDER BY n.code COLLATE "C") FROM wbs_nodes n WHERE n.version_id = v.id),
             (SELECT string_agg(c.code || '=' || c.cost_type, ';' ORDER BY c.code COLLATE "C") FROM cost_codes c JOIN wbs_nodes n ON n.id = c.wbs_node_id WHERE n.version_id = v.id))
      INTO h FROM wbs_versions v WHERE v.tenant_id = t AND v.id::text = p_id;
  ELSIF p_type = 'fiscal_period' THEN
    SELECT concat_ws('|', id, legal_entity_id, starts_on, ends_on, status, COALESCE(closed_by, ''))
      INTO h FROM fiscal_periods WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type = 'workflow_definition' THEN
    SELECT concat_ws('|', id, key, version, status, body_hash, proposed_by) INTO h FROM workflow_definitions WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type = 'workflow_definition_body' THEN
    h := p_id; -- the subject IS the canonical body hash
  ELSIF p_type = 'workflow_instance' THEN
    SELECT concat_ws('|', id, definition_id, current_step, status, facts->>'fingerprint') INTO h FROM workflow_instances WHERE tenant_id = t AND id::text = p_id;
  END IF;
  IF h IS NULL THEN
    RETURN NULL;
  END IF;
  IF p_type <> 'workflow_definition_body' THEN
    h := encode(sha256(convert_to(h, 'UTF8')), 'hex');
  END IF;
  RETURN h;
END$$;
GRANT EXECUTE ON FUNCTION approval_subject_hash(text, text) TO serk_app;

-- Canonical message (pkg/attest Claims.Canonical): fields joined by U+001F;
-- permissions sorted byte-wise.
CREATE OR REPLACE FUNCTION approval_canonical(a jsonb) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT concat_ws(chr(31),
    a->>'v', a->>'kid', a->>'tenant', a->>'actor', a->>'action', a->>'subject_type', a->>'subject_id', a->>'subject_hash', a->>'ctx',
    COALESCE((SELECT string_agg(p, ',' ORDER BY p COLLATE "C") FROM jsonb_array_elements_text(a->'perms') AS p), ''),
    CASE WHEN (a->>'mfa')::boolean THEN '1' ELSE '0' END,
    a->>'auth_time', a->>'iat', a->>'exp', a->>'nonce')
$$;

-- ---------------------------------------------------------------------------
-- Verification. The only way to create approval evidence.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION approval_authorize(a jsonb) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  t uuid := current_tenant();
  k bytea;
  now_s bigint := extract(epoch FROM now())::bigint;
  iat bigint; exp bigint; at bigint;
  fresh boolean;
  want text;
  n uuid;
BEGIN
  IF t IS NULL THEN
    RAISE EXCEPTION 'approval attestation: no tenant session' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF a IS NULL OR jsonb_typeof(a) <> 'object' OR (a->>'v') IS DISTINCT FROM '1' OR (a->>'tenant') IS DISTINCT FROM t::text THEN
    RAISE EXCEPTION 'approval attestation: malformed or for another tenant' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF COALESCE(a->>'actor', '') = '' OR COALESCE(a->>'action', '') = '' OR COALESCE(a->>'sig', '') = ''
     OR jsonb_typeof(a->'perms') IS DISTINCT FROM 'array' OR (a->>'nonce') !~ '^[0-9a-f-]{36}$' THEN
    RAISE EXCEPTION 'approval attestation: missing fields' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT key INTO k FROM approval_keys WHERE tenant_id = t AND key_id = a->>'kid' AND active;
  IF k IS NULL THEN
    RAISE EXCEPTION 'approval attestation: unknown signing key' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF encode(hmac(convert_to(approval_canonical(a), 'UTF8'), k, 'sha256'), 'hex') <> a->>'sig' THEN
    RAISE EXCEPTION 'approval attestation: bad signature' USING ERRCODE = 'insufficient_privilege';
  END IF;
  iat := (a->>'iat')::bigint; exp := (a->>'exp')::bigint; at := NULLIF(a->>'auth_time', '')::bigint;
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
    VALUES (n, t, txid_current(), a->>'actor', a->>'action', a->>'subject_type', a->>'subject_id', a->>'subject_hash', COALESCE(a->>'ctx', ''),
      ARRAY(SELECT jsonb_array_elements_text(a->'perms')), (a->>'mfa')::boolean, fresh,
      CASE WHEN at IS NULL THEN NULL ELSE to_timestamp(at) END, to_timestamp(iat), to_timestamp(exp), a->>'kid', a->>'sig');
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'approval attestation: already used (replay)' USING ERRCODE = 'insufficient_privilege';
  END;
  RETURN n;
END$$;
REVOKE ALL ON FUNCTION approval_authorize(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approval_authorize(jsonb) TO serk_app;

-- The verified evidence for an action on a subject recorded in THIS
-- transaction (p_actor NULL = any person).
CREATE OR REPLACE FUNCTION approval_in_tx(p_action text, p_type text, p_id text, p_actor text) RETURNS approval_attestations
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT * FROM approval_attestations
   WHERE txid = txid_current() AND tenant_id = current_tenant() AND action = p_action
     AND subject_type = p_type AND subject_id = p_id AND (p_actor IS NULL OR actor = p_actor)
   ORDER BY recorded_at DESC LIMIT 1
$$;

-- Raises unless verified evidence authorises the transition.
CREATE OR REPLACE FUNCTION approval_require(p_action text, p_type text, p_id text, p_actor text, p_perms text[], p_mfa boolean)
RETURNS approval_attestations LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE r approval_attestations;
BEGIN
  r := approval_in_tx(p_action, p_type, p_id, p_actor);
  IF r.nonce IS NULL THEN
    RAISE EXCEPTION '% of % % requires a verified approval attestation for %', p_action, p_type, p_id, COALESCE(p_actor, 'an authorised person')
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NOT (r.perms && p_perms) THEN
    RAISE EXCEPTION '% requires permission %; the attested person holds none of them', p_action, array_to_string(p_perms, ' or ')
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_mfa AND NOT r.mfa_fresh THEN
    RAISE EXCEPTION '% requires a recent multi-factor authentication in the attestation', p_action USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN r;
END$$;

-- ---------------------------------------------------------------------------
-- Journals
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION journals_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL OR NEW.posted_by IS NOT NULL
       OR NEW.posted_at IS NOT NULL OR NEW.reversed_by IS NOT NULL THEN
      RAISE EXCEPTION 'journals are created DRAFT without approval fields' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM approval_require('journal.approve', 'journal', NEW.id::text, NEW.approved_by, ARRAY['journal.approve'], false);
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'POSTED' THEN
    PERFORM approval_require('journal.post', 'journal', NEW.id::text, NEW.posted_by, ARRAY['journal.post'], false);
  ELSIF NEW.status = 'CANCELLED' THEN
    PERFORM approval_require('journal.cancel', 'journal', NEW.id::text, NULL, ARRAY['journal.approve', 'journal.post'], false);
  ELSIF OLD.status = 'POSTED' AND NEW.status = 'REVERSED' THEN
    -- Only together with the attested posting of its reversal.
    PERFORM approval_require('journal.post', 'journal', NEW.reversed_by::text, NULL, ARRAY['journal.post'], false);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_attest BEFORE INSERT OR UPDATE ON journals FOR EACH ROW EXECUTE FUNCTION journals_attest();

-- ---------------------------------------------------------------------------
-- Fiscal periods
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fiscal_periods_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'OPEN' OR NEW.closed_by IS NOT NULL OR NEW.closed_at IS NOT NULL OR NEW.reopened_by IS NOT NULL THEN
      RAISE EXCEPTION 'fiscal periods are created OPEN' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;
  IF NEW.status IN ('CLOSED', 'LOCKED') THEN
    PERFORM approval_require('period.close', 'fiscal_period', NEW.id::text, NEW.closed_by, ARRAY['period.close'], false);
  ELSIF OLD.status = 'CLOSED' AND NEW.status = 'OPEN' THEN
    PERFORM approval_require('period.reopen', 'fiscal_period', NEW.id::text, NEW.reopened_by, ARRAY['period.reopen'], true);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fiscal_periods_attest BEFORE INSERT OR UPDATE ON fiscal_periods FOR EACH ROW EXECUTE FUNCTION fiscal_periods_attest();

-- ---------------------------------------------------------------------------
-- FX sources, policies, snapshots
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fx_sources_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'APPROVED' THEN
      PERFORM approval_require('fx.source.approve', 'fx_source', NEW.source_id, NEW.approved_by, ARRAY['fx.approve'], false);
    ELSE
      PERFORM approval_require('fx.source.retire', 'fx_source', NEW.source_id, NULL, ARRAY['fx.approve'], false);
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_sources_attest BEFORE UPDATE ON fx_sources FOR EACH ROW EXECUTE FUNCTION fx_sources_attest();

CREATE OR REPLACE FUNCTION fx_policies_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'APPROVED' THEN
      PERFORM approval_require('fx.policy.decide', 'fx_policy', NEW.id::text, NEW.approved_by, ARRAY['fx.policy.approve'], false);
    ELSIF NEW.status = 'REJECTED' THEN
      PERFORM approval_require('fx.policy.decide', 'fx_policy', NEW.id::text, NULL, ARRAY['fx.policy.approve'], false);
    ELSIF NEW.status = 'RETIRED' THEN
      -- Only while an attested approval of the next version of the same
      -- entity/purpose runs in this transaction.
      IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN fx_policies p ON p.id::text = a.subject_id
                      WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'fx.policy.decide'
                        AND p.legal_entity_id = NEW.legal_entity_id AND p.purpose = NEW.purpose AND p.id <> NEW.id) THEN
        RAISE EXCEPTION 'an FX policy is retired only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_policies_attest BEFORE UPDATE ON fx_policies FOR EACH ROW EXECUTE FUNCTION fx_policies_attest();

-- Runs before fx_snapshots_guard (trigger order is by name): the MFA flag is
-- taken from the verified evidence, never from the statement.
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
    r := approval_require('fx.snapshot.approve', 'fx_snapshot', NEW.snapshot_id::text, NEW.approved_by, ARRAY['fx.approve'], false);
    NEW.approver_mfa := r.mfa_fresh;
    IF NEW.variance_exception AND NOT ('fx.approve_exception' = ANY (r.perms) AND r.mfa_fresh) THEN
      RAISE EXCEPTION 'a variance exception requires fx.approve_exception and a recent MFA in the attestation' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF NEW.approval_status = 'REJECTED' THEN
    PERFORM approval_require('fx.snapshot.reject', 'fx_snapshot', NEW.snapshot_id::text, NEW.rejected_by, ARRAY['fx.approve'], false);
  ELSIF NEW.approval_status = 'DISPUTED' THEN
    PERFORM approval_require('fx.snapshot.withdraw', 'fx_snapshot', NEW.snapshot_id::text, NULL, ARRAY['fx.approve'], false);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_snapshots_attest BEFORE INSERT OR UPDATE ON fx_snapshots FOR EACH ROW EXECUTE FUNCTION fx_snapshots_attest();

-- ---------------------------------------------------------------------------
-- WBS versions
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION wbs_versions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'APPROVED' THEN
      PERFORM approval_require('wbs.decide', 'wbs_version', NEW.id::text, NEW.approved_by, ARRAY['wbs.approve'], false);
    ELSIF NEW.status = 'REJECTED' THEN
      PERFORM approval_require('wbs.decide', 'wbs_version', NEW.id::text, NULL, ARRAY['wbs.approve'], false);
    ELSIF NEW.status = 'SUPERSEDED' THEN
      IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN wbs_versions v ON v.id::text = a.subject_id
                      WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'wbs.decide'
                        AND v.project_id = NEW.project_id AND v.id <> NEW.id) THEN
        RAISE EXCEPTION 'a WBS version is superseded only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER wbs_versions_attest BEFORE UPDATE ON wbs_versions FOR EACH ROW EXECUTE FUNCTION wbs_versions_attest();

-- ---------------------------------------------------------------------------
-- Workflow: definitions, instances, decisions
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION workflow_definitions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Only the author's attested proposal of exactly this (validated) body.
  PERFORM approval_require('workflow.define', 'workflow_definition_body', NEW.body_hash, NEW.proposed_by, ARRAY['workflow.define'], false);
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_definitions_attest BEFORE INSERT ON workflow_definitions FOR EACH ROW EXECUTE FUNCTION workflow_definitions_attest();

-- Same signature as 0006 (the application call is unchanged); the checker
-- is now the attested person, not a caller-supplied name.
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
  IF (approval_require('workflow.decide_definition', 'workflow_definition', p_id::text, p_by, ARRAY['workflow.publish'], p_status = 'PUBLISHED')).ctx
     IS DISTINCT FROM p_status THEN
    RAISE EXCEPTION 'the attestation authorises a different decision' USING ERRCODE = 'insufficient_privilege';
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

CREATE OR REPLACE FUNCTION workflow_instances_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE sp text; rej text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT body->>'start_permission' INTO sp FROM workflow_definitions WHERE id = NEW.definition_id;
    IF (approval_require('workflow.start', NEW.subject_type, NEW.subject_id::text, NEW.initiated_by, ARRAY[sp], false)).ctx
       IS DISTINCT FROM NEW.definition_id::text THEN
      RAISE EXCEPTION 'the attestation authorises starting a different definition' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'CANCELLED' THEN
      PERFORM approval_require('workflow.cancel', 'workflow_instance', NEW.id::text, NEW.ended_by, ARRAY['workflow.admin'], false);
    ELSIF NEW.status = 'REJECTED' THEN
      -- The rejecting person is whoever recorded the (attested) REJECT.
      SELECT decided_by INTO rej FROM workflow_decisions
       WHERE instance_id = NEW.id AND step_index = OLD.current_step AND decision = 'REJECT' ORDER BY decided_at DESC LIMIT 1;
      NEW.ended_by := rej;
    ELSIF NEW.status = 'EXPIRED' THEN
      NEW.ended_by := 'system:workflow-timer';
    ELSIF NEW.status = 'COMPLETED' THEN
      NEW.ended_by := NULL;
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_instances_attest BEFORE INSERT OR UPDATE ON workflow_instances FOR EACH ROW EXECUTE FUNCTION workflow_instances_attest();

-- Runs before workflow_decisions_guard: the decider and the MFA flag come
-- from the verified evidence for this instance at its current step.
CREATE OR REPLACE FUNCTION workflow_decisions_attest() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE perm text; r approval_attestations;
BEGIN
  SELECT route->NEW.step_index->>'permission' INTO perm FROM workflow_instances WHERE id = NEW.instance_id;
  r := approval_require('workflow.decide', 'workflow_instance', NEW.instance_id::text, NEW.decided_by, ARRAY[COALESCE(perm, '')], false);
  IF r.ctx IS DISTINCT FROM NEW.step_index::text || ':' || NEW.decision THEN
    RAISE EXCEPTION 'the attestation authorises a different step or decision' USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.mfa := r.mfa_fresh;
  NEW.attestation := r.nonce;
  RETURN NEW;
END$$;
ALTER TABLE workflow_decisions ADD COLUMN attestation uuid REFERENCES approval_attestations(nonce);
CREATE TRIGGER workflow_decisions_attest BEFORE INSERT ON workflow_decisions FOR EACH ROW EXECUTE FUNCTION workflow_decisions_attest();
-- Line memos become immutable (R-08): a memo edited on a DRAFT changed the
-- creation command hash, so such a journal could be approved but never
-- posted (and then blocked period close). Corrections: cancel and re-create.
REVOKE UPDATE (memo) ON journal_lines FROM serk_app;

-- End details: REJECTED/EXPIRED/COMPLETED derive ended_by above; CANCELLED
-- requires the attested administrator.
