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
  IF OLD.status = 'DRAFT' AND NEW.status IN ('PUBLISHED', 'REJECTED') THEN
    IF NEW.decided_by IS NULL OR NEW.decided_by = OLD.proposed_by THEN
      RAISE EXCEPTION 'a workflow definition is published or rejected by someone other than its author' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'REJECTED' AND (NEW.decision_reason IS NULL OR length(trim(NEW.decision_reason)) < 5) THEN
      RAISE EXCEPTION 'rejecting a workflow definition requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    NEW.decided_at := clock_timestamp();
    IF NEW.status = 'PUBLISHED' THEN
      -- The previous version of the same key retires in the same statement.
      UPDATE workflow_definitions SET status = 'RETIRED'
       WHERE tenant_id = NEW.tenant_id AND key = NEW.key AND status = 'PUBLISHED' AND id <> NEW.id;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'PUBLISHED' AND NEW.status = 'RETIRED' THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'illegal workflow definition transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
END$$;
CREATE TRIGGER workflow_definitions_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_definitions
  FOR EACH ROW EXECUTE FUNCTION workflow_definitions_guard();

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
      END IF;
    END IF;
  END LOOP;
  RETURN out;
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

CREATE OR REPLACE FUNCTION workflow_instances_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d workflow_definitions%ROWTYPE; n integer; need integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'workflow instances are never deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO d FROM workflow_definitions WHERE id = NEW.definition_id FOR SHARE;
    IF NOT FOUND OR d.tenant_id <> NEW.tenant_id OR d.status <> 'PUBLISHED' THEN
      RAISE EXCEPTION 'instances start only from a PUBLISHED definition' USING ERRCODE = 'check_violation';
    END IF;
    IF d.subject <> NEW.subject_type OR NEW.status <> 'ACTIVE' OR NEW.current_step <> 0 OR NEW.ended_at IS NOT NULL
       OR NEW.escalated_at IS NOT NULL OR NEW.effect_failures <> 0 THEN
      RAISE EXCEPTION 'an instance starts ACTIVE at its first step' USING ERRCODE = 'check_violation';
    END IF;
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
    IF NEW.status <> OLD.status OR NEW.current_step <> OLD.current_step OR NEW.ended_at IS DISTINCT FROM OLD.ended_at THEN
      RAISE EXCEPTION 'workflow instance is % and final', OLD.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  n := jsonb_array_length(OLD.route);
  IF NEW.current_step <> OLD.current_step THEN
    IF NEW.current_step <> OLD.current_step + 1 THEN
      RAISE EXCEPTION 'a workflow advances one step at a time' USING ERRCODE = 'check_violation';
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
BEGIN
  -- FOR SHARE: a concurrent publish/retire of the mandatory definition
  -- serializes with this check.
  PERFORM 1 FROM workflow_definitions WHERE tenant_id = t AND subject = stype AND status = 'PUBLISHED' AND mandatory FOR SHARE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM workflow_effects
                  WHERE tenant_id = t AND subject_type = stype AND subject_id = sid AND action = act
                    AND txid = txid_current() AND executed_by = actor) THEN
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
GRANT UPDATE (status, decided_by, decided_at, decision_reason) ON workflow_definitions TO serk_app;
GRANT UPDATE (status, current_step, escalated_at, ended_at, ended_by, end_reason, effect_failures, last_error, version) ON workflow_instances TO serk_app;
GRANT USAGE ON SEQUENCE workflow_history_id_seq TO serk_app;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['workflow_definitions', 'workflow_instances', 'workflow_decisions', 'workflow_effects', 'workflow_history'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END$$;
