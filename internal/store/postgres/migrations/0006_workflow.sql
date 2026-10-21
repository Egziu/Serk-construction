-- 0006 — Controlled-approval workflow engine.
--
-- Automation may route, remind, escalate and execute; it never authorizes.
-- The database enforces the parts of that rule it can see:
--   * definitions are versioned, immutable once proposed, and published by a
--     different person than the one who proposed them (maker/checker);
--   * decisions are append-only, one per person per step, and respect the
--     step's segregation-of-duties rules;
--   * an effect (the kernel transition a step triggers) can only be recorded
--     once the step's quorum of distinct approvers exists, and only by one of
--     those approvers;
--   * when a MANDATORY workflow is published for a subject type, the
--     sensitive transition of that subject (journal approve/post, FX rate
--     approval, period close) is refused unless the same transaction recorded
--     the matching effect, executed by the person the transition names.
-- What the database cannot see — the end user's permissions and MFA — is
-- enforced by the kernel, which executes every effect as the approving human.

-- ---------------------------------------------------------------------------
-- Definitions
-- ---------------------------------------------------------------------------
CREATE TABLE workflow_definitions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  key             text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.]{2,60}$'),
  version         integer NOT NULL CHECK (version > 0),
  subject         text NOT NULL CHECK (subject IN ('journal', 'fx_snapshot', 'fiscal_period')),
  mandatory       boolean NOT NULL,
  body            jsonb NOT NULL,
  body_hash       text NOT NULL CHECK (body_hash ~ '^sha256:[0-9a-f]{64}$'),
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'PUBLISHED', 'REJECTED', 'RETIRED')),
  proposed_by     text NOT NULL,
  proposed_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
  decided_by      text,
  decided_at      timestamptz,
  decision_reason text,
  UNIQUE (tenant_id, key, version),
  CHECK (decided_by IS NULL OR decided_by <> proposed_by)
);
CREATE UNIQUE INDEX workflow_definitions_one_published ON workflow_definitions(tenant_id, key) WHERE status = 'PUBLISHED';
CREATE UNIQUE INDEX workflow_definitions_one_mandatory ON workflow_definitions(tenant_id, subject) WHERE status = 'PUBLISHED' AND mandatory;

-- Per-(tenant, subject type) gate lock. Publishing/retiring takes it FOR
-- UPDATE; subject gates, starts and decisions take it FOR SHARE before they
-- read which definition governs. A row lock (not an advisory lock) because
-- row locks obey RLS: one tenant cannot block another tenant's gate.
CREATE TABLE workflow_gate_locks (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  subject   text NOT NULL CHECK (subject IN ('journal', 'fx_snapshot', 'fiscal_period')),
  PRIMARY KEY (tenant_id, subject)
);
CREATE OR REPLACE FUNCTION workflow_gate_locks_frozen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'workflow gate lock rows are immutable' USING ERRCODE = 'integrity_constraint_violation';
END$$;
CREATE TRIGGER workflow_gate_locks_frozen BEFORE UPDATE OR DELETE ON workflow_gate_locks FOR EACH ROW EXECUTE FUNCTION workflow_gate_locks_frozen();

-- VOLATILE: statements after the lock wait read a fresh snapshot.
CREATE OR REPLACE FUNCTION workflow_gate_lock(t uuid, stype text, exclusive boolean) RETURNS void LANGUAGE plpgsql VOLATILE AS $$
BEGIN
  INSERT INTO workflow_gate_locks(tenant_id, subject) VALUES (t, stype) ON CONFLICT DO NOTHING;
  IF exclusive THEN
    PERFORM 1 FROM workflow_gate_locks WHERE tenant_id = t AND subject = stype FOR UPDATE;
  ELSE
    PERFORM 1 FROM workflow_gate_locks WHERE tenant_id = t AND subject = stype FOR SHARE;
  END IF;
END$$;

CREATE OR REPLACE FUNCTION workflow_definitions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'workflow definitions are never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.decided_by IS NOT NULL THEN
      RAISE EXCEPTION 'a workflow definition is proposed as DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.body->>'key') IS DISTINCT FROM NEW.key OR (NEW.body->>'subject') IS DISTINCT FROM NEW.subject
       OR COALESCE((NEW.body->>'mandatory')::boolean, false) <> NEW.mandatory THEN
      RAISE EXCEPTION 'definition columns must match its body' USING ERRCODE = 'check_violation';
    END IF;
    NEW.proposed_at := clock_timestamp();
    RETURN NEW;
  END IF;
  IF row(NEW.tenant_id, NEW.key, NEW.version, NEW.subject, NEW.mandatory, NEW.body, NEW.body_hash, NEW.proposed_by, NEW.proposed_at)
     IS DISTINCT FROM
     row(OLD.tenant_id, OLD.key, OLD.version, OLD.subject, OLD.mandatory, OLD.body, OLD.body_hash, OLD.proposed_by, OLD.proposed_at) THEN
    RAISE EXCEPTION 'workflow definition % v% is immutable; propose a new version', OLD.key, OLD.version USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status = OLD.status THEN
    IF row(NEW.decided_by, NEW.decided_at, NEW.decision_reason) IS DISTINCT FROM row(OLD.decided_by, OLD.decided_at, OLD.decision_reason) THEN
      RAISE EXCEPTION 'decision of workflow definition % v% is immutable', OLD.key, OLD.version USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- Status changes happen only inside workflow_decide_definition() (owner
  -- rights + a transaction-local marker). The application role has no UPDATE
  -- privilege on this table, so it can neither retire a definition nor run a
  -- trigger that does.
  IF current_user <> (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'workflow_definitions'::regclass)
     OR COALESCE(current_setting('serk.wf_decide', true), '') = '' THEN
    RAISE EXCEPTION 'workflow definitions change status only through workflow_decide_definition()' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status IN ('PUBLISHED', 'REJECTED') THEN
    IF NEW.decided_by IS NULL OR NEW.decided_by = OLD.proposed_by THEN
      RAISE EXCEPTION 'a workflow definition is published or rejected by someone other than its author' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'REJECTED' AND (NEW.decision_reason IS NULL OR length(trim(NEW.decision_reason)) < 5) THEN
      RAISE EXCEPTION 'rejecting a workflow definition requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    NEW.decided_at := clock_timestamp();
    RETURN NEW;
  END IF;
  IF OLD.status = 'PUBLISHED' AND NEW.status = 'RETIRED' THEN
    -- Only while publishing the next version of the same key.
    IF current_setting('serk.wf_decide', true) <> 'retire:' || OLD.key THEN
      RAISE EXCEPTION 'a published workflow is retired only by publishing its next version' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'illegal workflow definition transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
END$$;
CREATE TRIGGER workflow_definitions_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_definitions
  FOR EACH ROW EXECUTE FUNCTION workflow_definitions_guard();

-- The only way to publish or reject a definition. Runs with the owner's
-- rights; RLS still confines it to the caller's tenant (current_tenant() is
-- derived from session_user). Publishing retires the previous version of the
-- key in the same transaction, under the exclusive gate lock.
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
REVOKE ALL ON FUNCTION workflow_decide_definition(uuid, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workflow_decide_definition(uuid, text, text, text) TO serk_app;

-- ---------------------------------------------------------------------------
-- Instances
-- ---------------------------------------------------------------------------
-- route is the server-computed list of steps that apply to this subject,
-- frozen at start: [{id, permission, approvals, distinct_from[], require_mfa,
-- effect, sla_seconds, expire_seconds, escalate_to}]. facts holds the routing
-- inputs and the subject fingerprint.
CREATE TABLE workflow_instances (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  definition_id   uuid NOT NULL REFERENCES workflow_definitions(id),
  subject_type    text NOT NULL CHECK (subject_type IN ('journal', 'fx_snapshot', 'fiscal_period')),
  subject_id      uuid NOT NULL,
  facts           jsonb NOT NULL,
  route           jsonb NOT NULL CHECK (jsonb_typeof(route) = 'array' AND jsonb_array_length(route) BETWEEN 1 AND 12),
  status          text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'COMPLETED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
  current_step    integer NOT NULL DEFAULT 0 CHECK (current_step >= 0),
  initiated_by    text NOT NULL,
  started_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
  step_started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  sla_due_at      timestamptz,
  expires_at      timestamptz,
  escalated_at    timestamptz,
  ended_at        timestamptz,
  ended_by        text,
  end_reason      text,
  effect_failures integer NOT NULL DEFAULT 0 CHECK (effect_failures >= 0),
  last_error      text,
  version         integer NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX workflow_instances_one_active ON workflow_instances(tenant_id, subject_type, subject_id) WHERE status = 'ACTIVE';
CREATE INDEX workflow_instances_due ON workflow_instances(tenant_id, LEAST(sla_due_at, expires_at)) WHERE status = 'ACTIVE';

CREATE TABLE workflow_decisions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  instance_id uuid NOT NULL REFERENCES workflow_instances(id),
  step_index  integer NOT NULL CHECK (step_index >= 0),
  step_id     text NOT NULL,
  decided_by  text NOT NULL,
  decision    text NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
  reason      text,
  mfa         boolean NOT NULL DEFAULT false,
  decided_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (instance_id, step_index, decided_by),
  CHECK (decision = 'APPROVE' OR (reason IS NOT NULL AND length(trim(reason)) >= 5))
);

CREATE TABLE workflow_effects (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  instance_id  uuid NOT NULL REFERENCES workflow_instances(id),
  step_index   integer NOT NULL,
  action       text NOT NULL,
  subject_type text NOT NULL,
  subject_id   uuid NOT NULL,
  executed_by  text NOT NULL,
  txid         bigint NOT NULL DEFAULT txid_current(),
  executed_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (instance_id, step_index)
);
CREATE INDEX workflow_effects_gate ON workflow_effects(tenant_id, subject_type, subject_id, action, txid);

CREATE TABLE workflow_history (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  instance_id uuid NOT NULL REFERENCES workflow_instances(id),
  at          timestamptz NOT NULL DEFAULT clock_timestamp(),
  kind        text NOT NULL CHECK (kind IN ('STARTED', 'DECIDED', 'STEP_COMPLETED', 'EFFECT', 'EFFECT_FAILED', 'ESCALATED',
                                            'COMPLETED', 'REJECTED', 'EXPIRED', 'CANCELLED')),
  actor       text NOT NULL,
  step_index  integer,
  detail      jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX workflow_history_instance ON workflow_history(instance_id, id);

CREATE TRIGGER workflow_decisions_append_only BEFORE UPDATE OR DELETE ON workflow_decisions FOR EACH ROW EXECUTE FUNCTION append_only();
CREATE TRIGGER workflow_effects_append_only BEFORE UPDATE OR DELETE ON workflow_effects FOR EACH ROW EXECUTE FUNCTION append_only();
CREATE TRIGGER workflow_history_append_only BEFORE UPDATE OR DELETE ON workflow_history FOR EACH ROW EXECUTE FUNCTION append_only();

-- People excluded from deciding step `idx` of instance `i` by its SoD rules.
CREATE OR REPLACE FUNCTION workflow_excluded(i workflow_instances, idx integer) RETURNS text[] LANGUAGE plpgsql STABLE AS $$
DECLARE ref text; out text[] := '{}'; prior integer;
BEGIN
  FOR ref IN SELECT jsonb_array_elements_text(COALESCE(i.route->idx->'distinct_from', '[]'::jsonb)) LOOP
    IF ref = 'initiator' THEN
      out := out || i.initiated_by;
    ELSIF ref = 'subject.creator' THEN
      out := out || COALESCE(i.facts->>'created_by', '');
    ELSIF ref LIKE 'step:%' THEN
      SELECT ord - 1 INTO prior FROM jsonb_array_elements(i.route) WITH ORDINALITY AS r(s, ord)
       WHERE r.s->>'id' = substr(ref, 6) AND ord - 1 < idx;
      IF prior IS NOT NULL THEN
        out := out || ARRAY(SELECT decided_by FROM workflow_decisions
                             WHERE instance_id = i.id AND step_index = prior AND decision = 'APPROVE');
      ELSIF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(i.route) r WHERE r->>'id' = substr(ref, 6)) THEN
        -- The referenced step was skipped because it already happened before
        -- this instance (journal started while APPROVED): exclude whoever
        -- performed it.
        out := out || COALESCE(NULLIF(i.facts->>'approved_by', ''), '')
                   || ARRAY(SELECT DISTINCT pd.decided_by FROM workflow_decisions pd
                             JOIN workflow_instances pi ON pi.id = pd.instance_id
                            WHERE pi.tenant_id = i.tenant_id AND pi.subject_type = i.subject_type
                              AND pi.subject_id = i.subject_id AND pi.id <> i.id AND pd.decision = 'APPROVE');
      END IF;
    END IF;
  END LOOP;
  RETURN out;
END$$;

-- An instance may act only while its definition version is the published
-- one and, when a mandatory definition governs the subject type, only if it
-- is that definition (an optional or superseded definition never satisfies
-- or bypasses a mandatory one).
-- VOLATILE on purpose: after waiting for the lock, the reads below must take
-- a fresh snapshot (a STABLE function would reuse the caller's).
CREATE OR REPLACE FUNCTION workflow_assert_governing(i workflow_instances) RETURNS void LANGUAGE plpgsql VOLATILE AS $$
DECLARE st text; mand uuid;
BEGIN
  PERFORM workflow_gate_lock(i.tenant_id, i.subject_type, false);
  SELECT status INTO st FROM workflow_definitions WHERE id = i.definition_id;
  IF st IS DISTINCT FROM 'PUBLISHED' THEN
    RAISE EXCEPTION 'workflow definition version is %; cancel this instance and start the current version', st USING ERRCODE = 'check_violation';
  END IF;
  SELECT id INTO mand FROM workflow_definitions
   WHERE tenant_id = i.tenant_id AND subject = i.subject_type AND status = 'PUBLISHED' AND mandatory;
  IF mand IS NOT NULL AND mand <> i.definition_id THEN
    RAISE EXCEPTION 'a mandatory workflow governs %; this instance belongs to another definition', i.subject_type USING ERRCODE = 'check_violation';
  END IF;
END$$;

CREATE OR REPLACE FUNCTION workflow_approvals(iid uuid, idx integer) RETURNS integer LANGUAGE sql STABLE AS $$
  SELECT COUNT(*)::integer FROM workflow_decisions WHERE instance_id = iid AND step_index = idx AND decision = 'APPROVE'
$$;

CREATE OR REPLACE FUNCTION workflow_decisions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i workflow_instances%ROWTYPE;
BEGIN
  SELECT * INTO i FROM workflow_instances WHERE id = NEW.instance_id FOR UPDATE;
  IF NOT FOUND OR i.tenant_id <> NEW.tenant_id THEN
    RAISE EXCEPTION 'unknown workflow instance' USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF i.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'workflow instance is %', i.status USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.step_index <> i.current_step OR (i.route->NEW.step_index->>'id') IS DISTINCT FROM NEW.step_id THEN
    RAISE EXCEPTION 'decision must target the open step (%)', i.route->i.current_step->>'id' USING ERRCODE = 'check_violation';
  END IF;
  IF i.expires_at IS NOT NULL AND i.expires_at <= now() THEN
    RAISE EXCEPTION 'the open step expired at %', i.expires_at USING ERRCODE = 'check_violation';
  END IF;
  PERFORM workflow_assert_governing(i);
  IF NEW.decided_by = ANY (workflow_excluded(i, NEW.step_index)) THEN
    RAISE EXCEPTION 'segregation of duties: % may not decide step %', NEW.decided_by, NEW.step_id USING ERRCODE = 'check_violation';
  END IF;
  IF COALESCE((i.route->NEW.step_index->>'require_mfa')::boolean, false) AND NOT NEW.mfa THEN
    RAISE EXCEPTION 'step % requires a recent multi-factor authentication', NEW.step_id USING ERRCODE = 'check_violation';
  END IF;
  NEW.decided_at := clock_timestamp();
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_decisions_guard BEFORE INSERT ON workflow_decisions FOR EACH ROW EXECUTE FUNCTION workflow_decisions_guard();

CREATE OR REPLACE FUNCTION workflow_effects_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i workflow_instances%ROWTYPE; need integer;
BEGIN
  SELECT * INTO i FROM workflow_instances WHERE id = NEW.instance_id FOR UPDATE;
  IF NOT FOUND OR i.tenant_id <> NEW.tenant_id OR i.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'effects run only for an ACTIVE workflow instance' USING ERRCODE = 'check_violation';
  END IF;
  IF i.expires_at IS NOT NULL AND i.expires_at <= now() THEN
    RAISE EXCEPTION 'the open step expired at %', i.expires_at USING ERRCODE = 'check_violation';
  END IF;
  PERFORM workflow_assert_governing(i);
  IF NEW.step_index <> i.current_step OR (i.route->NEW.step_index->>'effect') IS DISTINCT FROM NEW.action
     OR NEW.subject_type <> i.subject_type OR NEW.subject_id <> i.subject_id THEN
    RAISE EXCEPTION 'effect % is not the effect of the open step', NEW.action USING ERRCODE = 'check_violation';
  END IF;
  need := COALESCE((i.route->NEW.step_index->>'approvals')::integer, 1);
  IF workflow_approvals(i.id, NEW.step_index) < need THEN
    RAISE EXCEPTION 'step % has not reached its quorum of % approval(s)', i.route->NEW.step_index->>'id', need USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM workflow_decisions WHERE instance_id = i.id AND step_index = NEW.step_index
                    AND decided_by = NEW.executed_by AND decision = 'APPROVE') THEN
    RAISE EXCEPTION 'an effect is executed by one of the step''s approvers' USING ERRCODE = 'check_violation';
  END IF;
  NEW.txid := txid_current();
  NEW.executed_at := clock_timestamp();
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_effects_guard BEFORE INSERT ON workflow_effects FOR EACH ROW EXECUTE FUNCTION workflow_effects_guard();

-- The route and facts of a new instance are recomputed from the published
-- definition and the stored subject, so application code (even compromised)
-- cannot start an instance with a weakened route: fewer approvers, missing
-- SoD rules, a skipped threshold step, a different effect, longer deadlines,
-- or facts that do not match the subject.
CREATE OR REPLACE FUNCTION workflow_check_start(d workflow_definitions, i workflow_instances) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
  s jsonb; r jsonb; c jsonb; k integer := 0; amt numeric; cur text; want jsonb := '[]'::jsonb;
  skipping boolean := false; matched boolean;
  j record; f record; p record;
BEGIN
  -- Facts must be the subject's own.
  IF i.subject_type = 'journal' THEN
    SELECT jn.status, jn.created_by, COALESCE(jn.approved_by, '') AS approved_by, COALESCE(jn.project_id::text, '') AS project_id,
           jn.functional_currency AS cur,
           (SELECT COALESCE(SUM(l.amount), 0) FROM journal_lines l WHERE l.journal_id = jn.id AND l.side = 'DEBIT') AS debits
      INTO j FROM journals jn WHERE jn.id = i.subject_id AND jn.tenant_id = i.tenant_id;
    IF NOT FOUND OR j.status NOT IN ('DRAFT', 'APPROVED') THEN
      RAISE EXCEPTION 'a journal workflow starts on an existing DRAFT or APPROVED journal' USING ERRCODE = 'check_violation';
    END IF;
    IF (i.facts->>'created_by') IS DISTINCT FROM j.created_by OR COALESCE(i.facts->>'project_id', '') <> j.project_id
       OR COALESCE(i.facts->>'approved_by', '') <> j.approved_by
       OR (i.facts->>'currency') IS DISTINCT FROM j.cur OR NULLIF(i.facts->>'amount', '')::numeric IS DISTINCT FROM j.debits THEN
      RAISE EXCEPTION 'workflow facts do not match the journal' USING ERRCODE = 'check_violation';
    END IF;
    -- An APPROVED journal resumes after the step that approves journals.
    skipping := j.status = 'APPROVED'
                AND EXISTS (SELECT 1 FROM jsonb_array_elements(d.body->'steps') x WHERE x->>'effect' = 'journal.approve');
  ELSIF i.subject_type = 'fx_snapshot' THEN
    SELECT approval_status, created_by INTO f FROM fx_snapshots WHERE snapshot_id = i.subject_id AND tenant_id = i.tenant_id;
    IF NOT FOUND OR f.approval_status <> 'PENDING' THEN
      RAISE EXCEPTION 'an FX workflow starts on an existing PENDING rate' USING ERRCODE = 'check_violation';
    END IF;
    IF (i.facts->>'created_by') IS DISTINCT FROM f.created_by OR COALESCE(i.facts->>'amount', '') <> ''
       OR COALESCE(i.facts->>'approved_by', '') <> '' OR COALESCE(i.facts->>'project_id', '') <> '' THEN
      RAISE EXCEPTION 'workflow facts do not match the rate' USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    SELECT status INTO p FROM fiscal_periods WHERE id = i.subject_id AND tenant_id = i.tenant_id;
    IF NOT FOUND OR p.status <> 'OPEN' THEN
      RAISE EXCEPTION 'a period workflow starts on an existing OPEN period' USING ERRCODE = 'check_violation';
    END IF;
    IF COALESCE(i.facts->>'created_by', '') <> '' OR COALESCE(i.facts->>'amount', '') <> ''
       OR COALESCE(i.facts->>'approved_by', '') <> '' OR COALESCE(i.facts->>'project_id', '') <> '' THEN
      RAISE EXCEPTION 'workflow facts do not match the period' USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  -- Expected route: the definition's steps (after the approval step when
  -- resuming an APPROVED journal) whose threshold the amount meets.
  amt := NULLIF(i.facts->>'amount', '')::numeric;
  cur := i.facts->>'currency';
  FOR s IN SELECT x FROM jsonb_array_elements(d.body->'steps') AS x LOOP
    IF skipping THEN
      skipping := (s->>'effect') IS DISTINCT FROM 'journal.approve';
      CONTINUE;
    END IF;
    IF jsonb_typeof(s->'when') = 'array' THEN
      CONTINUE WHEN amt IS NULL;
      matched := false;
      FOR c IN SELECT y FROM jsonb_array_elements(s->'when') AS y LOOP
        IF c->>'currency' = cur THEN
          matched := true;
          EXIT;
        END IF;
      END LOOP;
      IF NOT matched THEN
        RAISE EXCEPTION 'step % has no threshold for %', s->>'id', cur USING ERRCODE = 'check_violation';
      END IF;
      CONTINUE WHEN amt < (c->>'amount_gte')::numeric;
    END IF;
    want := want || jsonb_build_array(s);
  END LOOP;
  IF jsonb_array_length(want) <> jsonb_array_length(i.route) THEN
    RAISE EXCEPTION 'workflow route does not match definition % v% for this subject', d.key, d.version USING ERRCODE = 'check_violation';
  END IF;
  FOR s IN SELECT x FROM jsonb_array_elements(want) AS x LOOP
    r := i.route->k;
    IF (r->>'id') IS DISTINCT FROM (s->>'id')
       OR (r->>'permission') IS DISTINCT FROM (s->>'permission')
       OR NULLIF(r->>'approvals', '')::integer IS DISTINCT FROM GREATEST(COALESCE(NULLIF(s->>'approvals', '')::integer, 0), 1)
       OR COALESCE(r->'distinct_from', '[]'::jsonb) <> COALESCE(s->'distinct_from', '[]'::jsonb)
       OR COALESCE((r->>'require_mfa')::boolean, false) <> COALESCE((s->>'require_mfa')::boolean, false)
       OR COALESCE(r->>'effect', '') <> COALESCE(s->>'effect', '')
       OR COALESCE(r->>'escalate_to', '') <> COALESCE(s->>'escalate_to', '')
       OR COALESCE(NULLIF(r->>'sla_seconds', '')::bigint, 0) <> COALESCE(EXTRACT(EPOCH FROM (NULLIF(s->>'sla', ''))::interval)::bigint, 0)
       OR COALESCE(NULLIF(r->>'expire_seconds', '')::bigint, 0) <> COALESCE(EXTRACT(EPOCH FROM (NULLIF(s->>'expire_after', ''))::interval)::bigint, 0) THEN
      RAISE EXCEPTION 'workflow route step % does not match definition % v%', k, d.key, d.version USING ERRCODE = 'check_violation';
    END IF;
    k := k + 1;
  END LOOP;
END$$;

CREATE OR REPLACE FUNCTION workflow_instances_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d workflow_definitions%ROWTYPE; n integer; need integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'workflow instances are never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    -- The shared gate lock keeps the definition's status stable until commit
    -- (publishing/retiring needs the exclusive lock).
    PERFORM workflow_gate_lock(NEW.tenant_id, NEW.subject_type, false);
    SELECT * INTO d FROM workflow_definitions WHERE id = NEW.definition_id;
    IF NOT FOUND OR d.tenant_id <> NEW.tenant_id OR d.status <> 'PUBLISHED' THEN
      RAISE EXCEPTION 'instances start only from a PUBLISHED definition' USING ERRCODE = 'check_violation';
    END IF;
    IF d.subject <> NEW.subject_type OR NEW.status <> 'ACTIVE' OR NEW.current_step <> 0 OR NEW.ended_at IS NOT NULL
       OR NEW.escalated_at IS NOT NULL OR NEW.effect_failures <> 0 THEN
      RAISE EXCEPTION 'an instance starts ACTIVE at its first step' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM workflow_assert_governing(NEW);
    PERFORM workflow_check_start(d, NEW);
    NEW.started_at := clock_timestamp();
    NEW.step_started_at := NEW.started_at;
    NEW.sla_due_at := NEW.started_at + make_interval(secs => NULLIF(NEW.route->0->>'sla_seconds', '')::bigint);
    NEW.expires_at := NEW.started_at + make_interval(secs => NULLIF(NEW.route->0->>'expire_seconds', '')::bigint);
    RETURN NEW;
  END IF;
  IF row(NEW.tenant_id, NEW.definition_id, NEW.subject_type, NEW.subject_id, NEW.facts, NEW.route, NEW.initiated_by, NEW.started_at)
     IS DISTINCT FROM
     row(OLD.tenant_id, OLD.definition_id, OLD.subject_type, OLD.subject_id, OLD.facts, OLD.route, OLD.initiated_by, OLD.started_at) THEN
    RAISE EXCEPTION 'workflow instance identity, facts and route are immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'workflow instance is % and final', OLD.status USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status = OLD.status AND row(NEW.ended_at, NEW.ended_by, NEW.end_reason) IS DISTINCT FROM row(OLD.ended_at, OLD.ended_by, OLD.end_reason) THEN
    RAISE EXCEPTION 'end details are recorded only when the instance ends' USING ERRCODE = 'check_violation';
  END IF;
  n := jsonb_array_length(OLD.route);
  IF NEW.current_step <> OLD.current_step THEN
    IF NEW.current_step <> OLD.current_step + 1 THEN
      RAISE EXCEPTION 'a workflow advances one step at a time' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.expires_at IS NOT NULL AND OLD.expires_at <= now() THEN
      RAISE EXCEPTION 'the open step expired at %', OLD.expires_at USING ERRCODE = 'check_violation';
    END IF;
    need := COALESCE((OLD.route->OLD.current_step->>'approvals')::integer, 1);
    IF workflow_approvals(OLD.id, OLD.current_step) < need THEN
      RAISE EXCEPTION 'step % has not reached its quorum', OLD.route->OLD.current_step->>'id' USING ERRCODE = 'check_violation';
    END IF;
    IF (OLD.route->OLD.current_step->>'effect') IS NOT NULL AND NOT EXISTS
       (SELECT 1 FROM workflow_effects WHERE instance_id = OLD.id AND step_index = OLD.current_step) THEN
      RAISE EXCEPTION 'step % cannot complete before its effect ran', OLD.route->OLD.current_step->>'id' USING ERRCODE = 'check_violation';
    END IF;
    NEW.step_started_at := clock_timestamp();
    NEW.escalated_at := NULL;
    IF NEW.current_step < n THEN
      NEW.sla_due_at := NEW.step_started_at + make_interval(secs => NULLIF(OLD.route->NEW.current_step->>'sla_seconds', '')::bigint);
      NEW.expires_at := NEW.step_started_at + make_interval(secs => NULLIF(OLD.route->NEW.current_step->>'expire_seconds', '')::bigint);
    ELSE
      NEW.sla_due_at := NULL;
      NEW.expires_at := NULL;
    END IF;
  ELSE
    IF row(NEW.step_started_at, NEW.sla_due_at, NEW.expires_at) IS DISTINCT FROM row(OLD.step_started_at, OLD.sla_due_at, OLD.expires_at) THEN
      RAISE EXCEPTION 'workflow deadlines are derived, not set' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF NEW.escalated_at IS DISTINCT FROM OLD.escalated_at AND NEW.current_step = OLD.current_step THEN
    IF OLD.escalated_at IS NOT NULL OR OLD.sla_due_at IS NULL OR OLD.sla_due_at > now() THEN
      RAISE EXCEPTION 'a step escalates once, after its SLA' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF NEW.status <> OLD.status THEN
    IF NEW.status = 'COMPLETED' THEN
      IF NEW.current_step <> n THEN
        RAISE EXCEPTION 'a workflow completes only after its last step' USING ERRCODE = 'check_violation';
      END IF;
    ELSIF NEW.status = 'REJECTED' THEN
      IF NOT EXISTS (SELECT 1 FROM workflow_decisions WHERE instance_id = OLD.id AND step_index = OLD.current_step AND decision = 'REJECT')
         OR NEW.current_step <> OLD.current_step THEN
        RAISE EXCEPTION 'a workflow is rejected only by a recorded REJECT decision' USING ERRCODE = 'check_violation';
      END IF;
    ELSIF NEW.status = 'EXPIRED' THEN
      IF OLD.expires_at IS NULL OR OLD.expires_at > now() OR NEW.current_step <> OLD.current_step THEN
        RAISE EXCEPTION 'a workflow expires only after its deadline' USING ERRCODE = 'check_violation';
      END IF;
    ELSIF NEW.status = 'CANCELLED' THEN
      IF NEW.ended_by IS NULL OR NEW.end_reason IS NULL OR length(trim(NEW.end_reason)) < 5 THEN
        RAISE EXCEPTION 'cancelling a workflow requires who and why' USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      RAISE EXCEPTION 'illegal workflow transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
    NEW.ended_at := clock_timestamp();
  ELSIF NEW.current_step = n AND OLD.status = 'ACTIVE' THEN
    RAISE EXCEPTION 'the last step completes the workflow' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.effect_failures < OLD.effect_failures THEN
    RAISE EXCEPTION 'effect failure count only grows' USING ERRCODE = 'check_violation';
  END IF;
  NEW.version := OLD.version + 1;
  RETURN NEW;
END$$;
CREATE TRIGGER workflow_instances_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_instances
  FOR EACH ROW EXECUTE FUNCTION workflow_instances_guard();

-- ---------------------------------------------------------------------------
-- The gate on the subjects' sensitive transitions.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION workflow_require_effect(t uuid, stype text, sid uuid, act text, actor text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE mand uuid;
BEGIN
  -- Shared lock first, then a fresh read: a concurrent publish/retire holds
  -- the lock exclusively, so this read sees either the old or the new
  -- mandatory version, never neither.
  PERFORM workflow_gate_lock(t, stype, false);
  SELECT id INTO mand FROM workflow_definitions WHERE tenant_id = t AND subject = stype AND status = 'PUBLISHED' AND mandatory;
  IF mand IS NULL THEN
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM workflow_effects e JOIN workflow_instances i ON i.id = e.instance_id
                  WHERE e.tenant_id = t AND e.subject_type = stype AND e.subject_id = sid AND e.action = act
                    AND e.txid = txid_current() AND e.executed_by = actor AND i.definition_id = mand) THEN
    RAISE EXCEPTION '% of % % requires its mandatory approval workflow', act, stype, sid USING ERRCODE = 'check_violation';
  END IF;
END$$;

CREATE OR REPLACE FUNCTION journals_workflow_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM workflow_require_effect(NEW.tenant_id, 'journal', NEW.id, 'journal.approve', NEW.approved_by);
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'POSTED' THEN
    PERFORM workflow_require_effect(NEW.tenant_id, 'journal', NEW.id, 'journal.post', NEW.posted_by);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_workflow_gate BEFORE UPDATE OF status ON journals FOR EACH ROW EXECUTE FUNCTION journals_workflow_gate();

CREATE OR REPLACE FUNCTION fx_snapshots_workflow_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.approval_status = 'PENDING' AND NEW.approval_status = 'APPROVED' THEN
    PERFORM workflow_require_effect(NEW.tenant_id, 'fx_snapshot', NEW.snapshot_id, 'fx.approve', NEW.approved_by);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_snapshots_workflow_gate BEFORE UPDATE OF approval_status ON fx_snapshots FOR EACH ROW EXECUTE FUNCTION fx_snapshots_workflow_gate();

CREATE OR REPLACE FUNCTION fiscal_periods_workflow_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Closing an OPEN period is the gated transition. Locking an already
  -- CLOSED period only removes the ability to reopen it, so it is not gated.
  IF OLD.status = 'OPEN' AND NEW.status IN ('CLOSED', 'LOCKED') THEN
    PERFORM workflow_require_effect(NEW.tenant_id, 'fiscal_period', NEW.id, 'period.close', NEW.closed_by);
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fiscal_periods_workflow_gate BEFORE UPDATE OF status ON fiscal_periods FOR EACH ROW EXECUTE FUNCTION fiscal_periods_workflow_gate();

-- ---------------------------------------------------------------------------
-- Privileges and tenant isolation
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON workflow_definitions, workflow_instances, workflow_decisions, workflow_effects, workflow_history TO serk_app;
GRANT SELECT, INSERT ON workflow_gate_locks TO serk_app;
GRANT UPDATE (subject) ON workflow_gate_locks TO serk_app; -- required for FOR SHARE/UPDATE; updates are refused by trigger
GRANT UPDATE (status, current_step, escalated_at, ended_at, ended_by, end_reason, effect_failures, last_error, version) ON workflow_instances TO serk_app;
GRANT USAGE ON SEQUENCE workflow_history_id_seq TO serk_app;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workflow_definitions', 'workflow_instances', 'workflow_decisions', 'workflow_effects', 'workflow_history', 'workflow_gate_locks'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END$$;

-- ---------------------------------------------------------------------------
-- Timer scheduling: which tenants have due instances. The timer worker logs
-- in as a member of serk_scheduler and learns ONLY tenant ids; it then acts
-- inside each tenant through that tenant's own role (kernel.RunWorkflowTimers).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_scheduler') THEN
    CREATE ROLE serk_scheduler NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  -- The definer function below reads across tenants as the schema owner;
  -- FORCE RLS applies to the owner too, so it gets a read-only policy.
  EXECUTE format('CREATE POLICY owner_timer_scan ON workflow_instances FOR SELECT TO %I USING (true)', current_user);
END$$;

CREATE OR REPLACE FUNCTION workflow_due_tenants(max_tenants integer) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT DISTINCT tenant_id FROM workflow_instances
   WHERE status = 'ACTIVE' AND (expires_at <= now() OR (sla_due_at <= now() AND escalated_at IS NULL))
   LIMIT LEAST(GREATEST(max_tenants, 1), 10000)
$$;
REVOKE ALL ON FUNCTION workflow_due_tenants(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workflow_due_tenants(integer) TO serk_scheduler;

-- Temporary objects are not needed by any SERK login; without TEMP a login
-- cannot create helper functions/triggers in pg_temp.
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'cannot revoke TEMPORARY: run deploy/02-restrict-advisory-locks.sql as a superuser';
END$$;

-- Advisory locks are cluster-wide and ignore RLS: any login could block a
-- key used by another tenant or by the relay. Only the roles that need them
-- keep EXECUTE. Revoking privileges on pg_catalog functions needs a
-- superuser; when migrations run as a non-superuser owner the operator must
-- run deploy/02-restrict-advisory-locks.sql.
DO $$
DECLARE f regprocedure; me text := current_user;
BEGIN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE NOTICE 'not superuser: run deploy/02-restrict-advisory-locks.sql as a superuser';
    RETURN;
  END IF;
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO serk_publisher, %I', f, me);
  END LOOP;
END$$;
