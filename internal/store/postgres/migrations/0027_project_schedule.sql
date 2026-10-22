-- 0027: project schedules by the critical path method, baselines and
-- progress with earned value (GATED-02, ADR 0013).
--
--   planner records a DRAFT schedule version (calendar, activities with
--   durations, cost codes and budgets, precedence links) -> the kernel
--   computes CPM (pkg/schedule) and stores early/late dates and floats ->
--   submits -> the database re-verifies the computation locally (every
--   activity's early start is exactly the latest constraint from its
--   predecessors or 0; every late finish exactly the earliest constraint
--   from its successors or the project finish; floats and the finish follow;
--   the network is acyclic), budgets fit the approved BOQ per cost code ->
--   a project manager (different person, human) approves it as the BASELINE,
--   superseding the previous baseline.
--
--   progress: the planner records percent complete (and actual dates) per
--   baseline activity at a status date; a project manager approves it.
--   Earned value (schedule_evm) is computed from the baseline (PV, spread
--   linearly over each activity's working days), the latest approved
--   progress (EV) and the posted ledger cost on the project (AC).

CREATE TABLE schedule_versions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id  uuid NOT NULL,
  project_id       uuid NOT NULL,
  version          integer NOT NULL CHECK (version >= 1),
  description      text NOT NULL CHECK (length(btrim(description)) BETWEEN 3 AND 500),
  start_date       date NOT NULL,
  working_weekdays smallint[] NOT NULL CHECK (cardinality(working_weekdays) BETWEEN 1 AND 7 AND working_weekdays <@ ARRAY[0, 1, 2, 3, 4, 5, 6]::smallint[]),
  holidays         date[] NOT NULL DEFAULT '{}',
  required_finish  date,
  finish_offset    integer,
  finish_date      date,
  algorithm        text,
  status           text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'BASELINE', 'REJECTED', 'SUPERSEDED')),
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  submitted_at     timestamptz,
  approved_by      text,
  approved_at      timestamptz,
  decision_reason  text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, version),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  CONSTRAINT schedule_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE UNIQUE INDEX schedule_versions_one_baseline ON schedule_versions (tenant_id, project_id) WHERE status = 'BASELINE';

CREATE TABLE schedule_activities (
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  version_id   uuid NOT NULL,
  code         text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9._-]{0,31}$'),
  name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 300),
  duration     integer NOT NULL CHECK (duration BETWEEN 0 AND 3650),
  cost_code_id uuid,
  budget       numeric(24,6) NOT NULL DEFAULT 0 CHECK (budget >= 0),
  es           integer, ef integer, ls integer, lf integer,
  total_float  integer, free_float integer,
  critical     boolean,
  early_start  date, early_finish date, late_start date, late_finish date,
  PRIMARY KEY (version_id, code),
  FOREIGN KEY (tenant_id, version_id) REFERENCES schedule_versions(tenant_id, id),
  FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id),
  CONSTRAINT schedule_activity_budget_coded CHECK (budget = 0 OR cost_code_id IS NOT NULL)
);

CREATE TABLE schedule_links (
  tenant_id  uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  version_id uuid NOT NULL,
  pred_code  text NOT NULL,
  succ_code  text NOT NULL,
  link_type  text NOT NULL CHECK (link_type IN ('FS', 'SS', 'FF', 'SF')),
  lag        integer NOT NULL DEFAULT 0 CHECK (lag BETWEEN -3650 AND 3650),
  PRIMARY KEY (version_id, pred_code, succ_code),
  FOREIGN KEY (version_id, pred_code) REFERENCES schedule_activities(version_id, code),
  FOREIGN KEY (version_id, succ_code) REFERENCES schedule_activities(version_id, code),
  CONSTRAINT schedule_link_not_self CHECK (pred_code <> succ_code)
);

CREATE TABLE schedule_progress (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  version_id      uuid NOT NULL,
  project_id      uuid NOT NULL,
  number          text NOT NULL,
  status_date     date NOT NULL,
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  approved_by     text,
  approved_at     timestamptz,
  decision_reason text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, version_id) REFERENCES schedule_versions(tenant_id, id),
  CONSTRAINT schedule_progress_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE UNIQUE INDEX schedule_progress_one_per_date ON schedule_progress (version_id, status_date) WHERE status <> 'REJECTED';

CREATE TABLE schedule_progress_lines (
  tenant_id        uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  progress_id      uuid NOT NULL,
  version_id       uuid NOT NULL,
  activity_code    text NOT NULL,
  percent_complete numeric(5,2) NOT NULL CHECK (percent_complete BETWEEN 0 AND 100),
  actual_start     date,
  actual_finish    date,
  PRIMARY KEY (progress_id, activity_code),
  FOREIGN KEY (tenant_id, progress_id) REFERENCES schedule_progress(tenant_id, id),
  FOREIGN KEY (version_id, activity_code) REFERENCES schedule_activities(version_id, code),
  CONSTRAINT schedule_progress_dates CHECK (actual_finish IS NULL OR (actual_start IS NOT NULL AND actual_finish >= actual_start)),
  CONSTRAINT schedule_progress_finished CHECK ((percent_complete = 100) = (actual_finish IS NOT NULL)),
  CONSTRAINT schedule_progress_started CHECK (percent_complete = 0 OR actual_start IS NOT NULL)
);

-- ===========================================================================
-- Calendar helpers (the same rules as pkg/schedule.Calendar)
-- ===========================================================================
CREATE OR REPLACE FUNCTION schedule_is_working(v schedule_versions, d date) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT extract(dow FROM d)::smallint = ANY (v.working_weekdays) AND NOT (d = ANY (v.holidays))
$$;

-- Date of working day `n` (n >= 0; day 0 is the start date).
CREATE OR REPLACE FUNCTION schedule_date(v schedule_versions, n integer) RETURNS date
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS $$
DECLARE d date := v.start_date; k integer := n;
BEGIN
  WHILE k > 0 LOOP
    d := d + 1;
    IF schedule_is_working(v, d) THEN k := k - 1; END IF;
  END LOOP;
  RETURN d;
END$$;

-- Working days from the start up to and including d (d after the start);
-- the planned fraction of an activity at a status date uses it.
CREATE OR REPLACE FUNCTION schedule_offset(v schedule_versions, d date) RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN d <= v.start_date THEN 0
              ELSE (SELECT count(*)::integer FROM generate_series(v.start_date + 1, d, interval '1 day') g(x) WHERE schedule_is_working(v, g.x::date)) END
$$;

-- ===========================================================================
-- Guards
-- ===========================================================================
CREATE OR REPLACE FUNCTION schedule_versions_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE pr projects; bad record; n_bad integer; fin integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO pr FROM projects WHERE id = NEW.project_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.finish_offset IS NOT NULL OR NEW.decision_reason IS NOT NULL THEN
      RAISE EXCEPTION 'schedule versions are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    NEW.legal_entity_id := pr.legal_entity_id;
    NEW.version := COALESCE((SELECT max(version) FROM schedule_versions WHERE project_id = NEW.project_id), 0) + 1;
    IF NOT schedule_is_working(NEW, NEW.start_date) THEN
      RAISE EXCEPTION 'the schedule starts on a non-working day (%)', NEW.start_date USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status AND OLD.status = 'DRAFT' THEN
    -- While DRAFT only the computed finish may change (kernel CPM).
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['finish_offset', 'finish_date', 'algorithm'], 'schedule');
  ELSIF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'schedule');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'schedule');
    IF NOT EXISTS (SELECT 1 FROM schedule_activities WHERE version_id = NEW.id) OR NEW.finish_offset IS NULL OR NEW.algorithm IS NULL THEN
      RAISE EXCEPTION 'a schedule is submitted with activities and its computed dates' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM schedule_assert_cpm(NEW);
    -- Budgets fit the approved BOQ per cost code, and cost codes are the project's.
    SELECT a.cost_code_id, sum(a.budget) AS planned INTO bad FROM schedule_activities a
      LEFT JOIN cost_codes cc ON cc.id = a.cost_code_id
     WHERE a.version_id = NEW.id AND a.cost_code_id IS NOT NULL
     GROUP BY a.cost_code_id, cc.project_id
    HAVING cc.project_id IS DISTINCT FROM NEW.project_id
        OR sum(a.budget) > COALESCE((SELECT sum(i.amount) FROM boq_items i JOIN boq_versions bv ON bv.id = i.version_id
                                      WHERE i.cost_code_id = a.cost_code_id AND bv.status = 'APPROVED'), 0)
     LIMIT 1;
    IF bad.cost_code_id IS NOT NULL THEN
      RAISE EXCEPTION 'activity budgets on cost code % (%) exceed its approved BOQ budget or the code is not the project''s', bad.cost_code_id, bad.planned
        USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('schedule.submit', 'schedule_version', NEW.id::text, NEW.created_by, ARRAY['schedule.manage'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'BASELINE' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'schedule');
    PERFORM schedule_assert_cpm(NEW);
    PERFORM approval_use('schedule.approve', 'schedule_version', NEW.id::text, NEW.approved_by, ARRAY['schedule.approve'], false, 'BASELINE', NULL);
    -- The previous baseline is superseded in the same transaction.
    UPDATE schedule_versions SET status = 'SUPERSEDED' WHERE project_id = NEW.project_id AND status = 'BASELINE' AND id <> NEW.id;
    NEW.approved_at := now();
  ELSIF OLD.status = 'BASELINE' AND NEW.status = 'SUPERSEDED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'schedule');
    IF NOT EXISTS (SELECT 1 FROM schedule_versions WHERE project_id = NEW.project_id AND status = 'SUBMITTED' AND id <> NEW.id
                    AND approval_consumed_in_tx(ARRAY['schedule.approve'], 'schedule_version', id::text, 'BASELINE') IS NOT NULL) THEN
      RAISE EXCEPTION 'a baseline is superseded only by the approval of the next one' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'schedule');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a schedule requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('schedule.reject', 'schedule_version', NEW.id::text, NULL, ARRAY['schedule.approve'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal schedule transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- Local verification of a CPM computation. On an acyclic network the early
-- and late dates are the unique solution of these equations, so checking
-- them verifies the whole schedule without trusting the kernel.
CREATE OR REPLACE FUNCTION schedule_assert_cpm(v schedule_versions) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE bad record; fin integer; target integer; cyclic boolean;
BEGIN
  -- Acyclic: no activity reaches itself.
  WITH RECURSIVE reach(origin, node, depth) AS (
    SELECT l.pred_code, l.succ_code, 1 FROM schedule_links l WHERE l.version_id = v.id
    UNION
    SELECT r.origin, l.succ_code, r.depth + 1 FROM reach r JOIN schedule_links l ON l.version_id = v.id AND l.pred_code = r.node
     WHERE r.depth < 10000 AND r.node <> r.origin)
  SELECT EXISTS (SELECT 1 FROM reach WHERE node = origin) INTO cyclic;
  IF cyclic THEN
    RAISE EXCEPTION 'the schedule network has a dependency cycle' USING ERRCODE = 'check_violation';
  END IF;
  SELECT max(ef) INTO fin FROM schedule_activities WHERE version_id = v.id;
  IF fin IS DISTINCT FROM v.finish_offset OR v.finish_date IS DISTINCT FROM schedule_date(v, greatest(fin - 1, 0)) THEN
    RAISE EXCEPTION 'the schedule finish (% / %) is not the latest early finish (%)', v.finish_offset, v.finish_date, fin USING ERRCODE = 'check_violation';
  END IF;
  target := CASE WHEN v.required_finish IS NULL THEN fin ELSE schedule_offset(v, v.required_finish) + 1 END;
  SELECT a.code, a.es, a.ef, a.ls, a.lf INTO bad FROM schedule_activities a
   WHERE a.version_id = v.id AND (
         a.es IS NULL OR a.ef IS DISTINCT FROM a.es + a.duration OR a.lf IS DISTINCT FROM a.ls + a.duration
      OR a.total_float IS DISTINCT FROM a.ls - a.es
      OR a.es IS DISTINCT FROM greatest(0, COALESCE((
           SELECT max(CASE l.link_type WHEN 'FS' THEN p.ef + l.lag WHEN 'SS' THEN p.es + l.lag
                                       WHEN 'FF' THEN p.ef + l.lag - a.duration ELSE p.es + l.lag - a.duration END)
             FROM schedule_links l JOIN schedule_activities p ON p.version_id = v.id AND p.code = l.pred_code
            WHERE l.version_id = v.id AND l.succ_code = a.code), 0))
      OR a.lf IS DISTINCT FROM least(target, COALESCE((
           SELECT min(CASE l.link_type WHEN 'FS' THEN s.ls - l.lag WHEN 'SS' THEN s.ls - l.lag + a.duration
                                       WHEN 'FF' THEN s.lf - l.lag ELSE s.lf - l.lag + a.duration END)
             FROM schedule_links l JOIN schedule_activities s ON s.version_id = v.id AND s.code = l.succ_code
            WHERE l.version_id = v.id AND l.pred_code = a.code), target))
      OR a.early_start IS DISTINCT FROM schedule_date(v, a.es)
      OR a.early_finish IS DISTINCT FROM schedule_date(v, CASE WHEN a.duration = 0 THEN a.es ELSE a.ef - 1 END))
   LIMIT 1;
  IF bad.code IS NOT NULL THEN
    RAISE EXCEPTION 'activity % does not satisfy the critical path equations (ES % EF % LS % LF %)', bad.code, bad.es, bad.ef, bad.ls, bad.lf
      USING ERRCODE = 'check_violation';
  END IF;
END$$;

CREATE OR REPLACE FUNCTION schedule_children_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st text; vid uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.version_id ELSE NEW.version_id END;
BEGIN
  SELECT status INTO st FROM schedule_versions WHERE id = vid AND tenant_id = current_tenant() FOR SHARE;
  IF st IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'schedule activities and links change only while the version is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_TABLE_NAME = 'schedule_activities' AND TG_OP = 'UPDATE' THEN
    -- Only the computed columns change after creation.
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['es', 'ef', 'ls', 'lf', 'total_float', 'free_float', 'critical',
      'early_start', 'early_finish', 'late_start', 'late_finish'], 'schedule activity');
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END$$;
CREATE TRIGGER schedule_activities_guard BEFORE INSERT OR UPDATE OR DELETE ON schedule_activities FOR EACH ROW EXECUTE FUNCTION schedule_children_guard();
CREATE TRIGGER schedule_links_guard BEFORE INSERT OR UPDATE OR DELETE ON schedule_links FOR EACH ROW EXECUTE FUNCTION schedule_children_guard();
CREATE TRIGGER schedule_versions_guard BEFORE INSERT OR UPDATE ON schedule_versions FOR EACH ROW EXECUTE FUNCTION schedule_versions_guard();

CREATE OR REPLACE FUNCTION schedule_progress_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v schedule_versions; bad record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO v FROM schedule_versions WHERE id = NEW.version_id AND tenant_id = current_tenant() FOR SHARE;
    IF v.status IS DISTINCT FROM 'BASELINE' OR NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'progress is recorded DRAFT against the current BASELINE schedule' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status_date > current_date OR NEW.status_date < v.start_date THEN
      RAISE EXCEPTION 'the status date is between the schedule start and today' USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM schedule_progress WHERE version_id = v.id AND status = 'APPROVED' AND status_date >= NEW.status_date) THEN
      RAISE EXCEPTION 'progress is reported forward: a later status date is already approved' USING ERRCODE = 'check_violation';
    END IF;
    NEW.project_id := v.project_id;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'progress');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'progress');
    IF (SELECT status FROM schedule_versions WHERE id = NEW.version_id) IS DISTINCT FROM 'BASELINE' THEN
      RAISE EXCEPTION 'the schedule is no longer the baseline' USING ERRCODE = 'check_violation';
    END IF;
    -- Percent complete never goes backwards against the last approved report.
    SELECT l.activity_code, l.percent_complete, prev.percent_complete AS before INTO bad
      FROM schedule_progress_lines l
      JOIN LATERAL (SELECT pl.percent_complete FROM schedule_progress_lines pl JOIN schedule_progress p ON p.id = pl.progress_id
                     WHERE p.version_id = NEW.version_id AND p.status = 'APPROVED' AND pl.activity_code = l.activity_code
                     ORDER BY p.status_date DESC LIMIT 1) prev ON true
     WHERE l.progress_id = NEW.id AND l.percent_complete < prev.percent_complete LIMIT 1;
    IF bad.activity_code IS NOT NULL THEN
      RAISE EXCEPTION 'activity % goes back from % to % percent complete', bad.activity_code, bad.before, bad.percent_complete USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('schedule.progress.approve', 'schedule_progress', NEW.id::text, NEW.approved_by, ARRAY['schedule.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'progress');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a progress report requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('schedule.progress.reject', 'schedule_progress', NEW.id::text, NULL, ARRAY['schedule.approve'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal progress transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER schedule_progress_guard BEFORE INSERT OR UPDATE ON schedule_progress FOR EACH ROW EXECUTE FUNCTION schedule_progress_guard();

CREATE OR REPLACE FUNCTION schedule_progress_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE p schedule_progress;
BEGIN
  SELECT * INTO p FROM schedule_progress WHERE id = NEW.progress_id AND tenant_id = current_tenant() FOR SHARE;
  IF p.status IS DISTINCT FROM 'DRAFT' OR NEW.version_id IS DISTINCT FROM p.version_id THEN
    RAISE EXCEPTION 'progress lines are added to a DRAFT report of the same schedule' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.actual_start > p.status_date OR NEW.actual_finish > p.status_date THEN
    RAISE EXCEPTION 'actual dates are not after the status date' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER schedule_progress_lines_guard BEFORE INSERT ON schedule_progress_lines FOR EACH ROW EXECUTE FUNCTION schedule_progress_lines_guard();

CREATE OR REPLACE FUNCTION schedule_created() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_TABLE_NAME = 'schedule_versions' THEN
    PERFORM approval_use('schedule.create', 'schedule_version', NEW.id::text, NEW.created_by, ARRAY['schedule.manage'], false, NULL, NULL);
  ELSE
    PERFORM approval_use('schedule.progress.create', 'schedule_progress', NEW.id::text, NEW.created_by, ARRAY['schedule.manage'], false, NULL, NULL);
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER schedule_versions_created_by AFTER INSERT ON schedule_versions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION schedule_created();
CREATE CONSTRAINT TRIGGER schedule_progress_created_by AFTER INSERT ON schedule_progress DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION schedule_created();

-- ===========================================================================
-- Earned value at a status date (nominal basis, ADR 0013)
--   PV  = sum of budget x planned fraction (working days of [ES, EF) elapsed
--         by the status date; milestones count when due)
--   EV  = sum of budget x latest approved percent complete at or before it
--   AC  = posted ledger cost (EXPENSE lines) on the project up to it
-- ===========================================================================
CREATE OR REPLACE FUNCTION schedule_evm(p_project uuid, p_status date)
RETURNS TABLE (version_id uuid, bac numeric, pv numeric, ev numeric, ac numeric, sv numeric, cv numeric, spi numeric, cpi numeric, progress_date date)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE v schedule_versions; ccy char(3); n integer; pd date;
BEGIN
  SELECT * INTO v FROM schedule_versions WHERE project_id = p_project AND status = 'BASELINE' AND tenant_id = current_tenant();
  IF v.id IS NULL THEN
    RETURN;
  END IF;
  SELECT le.functional_currency INTO ccy FROM legal_entities le WHERE le.id = v.legal_entity_id;
  n := schedule_offset(v, p_status) + CASE WHEN schedule_is_working(v, p_status) AND p_status >= v.start_date THEN 1 ELSE 0 END;
  SELECT max(p.status_date) INTO pd FROM schedule_progress p WHERE p.version_id = v.id AND p.status = 'APPROVED' AND p.status_date <= p_status;
  version_id := v.id;
  progress_date := pd;
  SELECT COALESCE(sum(a.budget), 0),
         COALESCE(sum(p2p_round(a.budget * CASE WHEN a.duration = 0 THEN (CASE WHEN n > a.es THEN 1 ELSE 0 END)
                                               ELSE least(1, greatest(0, (n - a.es)::numeric / a.duration)) END, ccy)), 0)
    INTO bac, pv FROM schedule_activities a WHERE a.version_id = v.id;
  SELECT COALESCE(sum(p2p_round(a.budget * COALESCE(l.percent_complete, 0) / 100, ccy)), 0) INTO ev
    FROM schedule_activities a
    LEFT JOIN schedule_progress p ON p.version_id = v.id AND p.status = 'APPROVED' AND p.status_date = pd
    LEFT JOIN schedule_progress_lines l ON l.progress_id = p.id AND l.activity_code = a.code
   WHERE a.version_id = v.id;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO ac
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id JOIN accounts acc ON acc.id = jl.account_id
   WHERE jl.tenant_id = current_tenant() AND jl.project_id = p_project AND acc.type = 'EXPENSE' AND j.status IN ('POSTED', 'REVERSED')
     AND (j.business_event_at AT TIME ZONE 'UTC')::date <= p_status;
  sv := ev - pv; cv := ev - ac;
  spi := CASE WHEN pv = 0 THEN NULL ELSE round(ev / pv, 4) END;
  cpi := CASE WHEN ac = 0 THEN NULL ELSE round(ev / ac, 4) END;
  RETURN NEXT;
END$$;

-- ===========================================================================
-- Approval subject text (the 0026 body with the schedule branches).
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_subject_text(p_type text, p_id text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE t uuid := current_tenant(); j jsonb;
BEGIN
  IF p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN NULL;
  END IF;
  CASE p_type
  WHEN 'p2p_policy' THEN SELECT to_jsonb(x) INTO j FROM p2p_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier' THEN SELECT to_jsonb(x) INTO j FROM suppliers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', p2p_account_digest(x.account_number)) INTO j FROM supplier_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'company_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', p2p_account_digest(x.account_number)) INTO j FROM company_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'boq_version' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'items', (SELECT jsonb_agg(to_jsonb(i) ORDER BY i.item_no COLLATE "C") FROM boq_items i WHERE i.version_id = x.id))
      INTO j FROM boq_versions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'purchase_requisition' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM pr_lines l WHERE l.pr_id = x.id))
      INTO j FROM purchase_requisitions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'rfq' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'suppliers', (SELECT jsonb_agg(s.supplier_id ORDER BY s.supplier_id) FROM rfq_suppliers s WHERE s.rfq_id = x.id),
             'quotes', (SELECT jsonb_agg(jsonb_build_object('q', to_jsonb(q), 'lines',
                          (SELECT jsonb_agg(to_jsonb(ql) ORDER BY ql.pr_line_no) FROM rfq_quote_lines ql WHERE ql.quote_id = q.id)) ORDER BY q.id)
                          FROM rfq_quotes q WHERE q.rfq_id = x.id))
      INTO j FROM rfqs x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'rfq_quote' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.pr_line_no) FROM rfq_quote_lines l WHERE l.quote_id = x.id))
      INTO j FROM rfq_quotes x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'purchase_order' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM po_lines l WHERE l.po_id = x.id))
      INTO j FROM purchase_orders x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'grn' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id', 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.po_line_no) FROM grn_lines l WHERE l.grn_id = x.id))
      INTO j FROM grns x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_invoice' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id', 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.po_line_no) FROM invoice_lines l WHERE l.invoice_id = x.id))
      INTO j FROM supplier_invoices x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'payment_instruction' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'release_journal_id',
             'alloc', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.invoice_id) FROM payment_allocations a WHERE a.payment_id = x.id),
             'payee', (SELECT to_jsonb(b) || jsonb_build_object('account_number', p2p_account_digest(b.account_number)) FROM supplier_bank_accounts b WHERE b.id = x.supplier_bank_id))
      INTO j FROM payment_instructions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'bank_statement_line' THEN
    SELECT jsonb_build_object('l', to_jsonb(x) - 'journal_id', 's', (SELECT to_jsonb(s) FROM bank_statements s WHERE s.id = x.statement_id))
      INTO j FROM bank_statement_lines x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer' THEN SELECT to_jsonb(x) INTO j FROM customers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract_policy' THEN SELECT to_jsonb(x) INTO j FROM contract_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM contract_lines l WHERE l.contract_id = x.id))
      INTO j FROM contracts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'measurement' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.contract_line_no) FROM measurement_lines l WHERE l.measurement_id = x.id))
      INTO j FROM measurements x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'ipc' THEN SELECT to_jsonb(x) INTO j FROM ipcs x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer_invoice' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM customer_invoices x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer_receipt' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id',
             'alloc', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.line_no) FROM receipt_allocations a WHERE a.receipt_id = x.id),
             'line', (SELECT to_jsonb(l) - 'journal_id' FROM bank_statement_lines l WHERE l.id = x.statement_line_id))
      INTO j FROM customer_receipts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_item' THEN SELECT to_jsonb(x) INTO j FROM stock_items x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'warehouse' THEN SELECT to_jsonb(x) INTO j FROM warehouses x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_receipt' THEN SELECT to_jsonb(x) INTO j FROM stock_receipts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_issue' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM stock_issues x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_count' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM stock_counts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer_credit_note' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM customer_credit_notes x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'retention_release' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM retention_releases x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_transfer' THEN SELECT to_jsonb(x) INTO j FROM stock_transfers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'schedule_version' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'activities', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.code COLLATE "C") FROM schedule_activities a WHERE a.version_id = x.id),
             'links', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.pred_code COLLATE "C", l.succ_code COLLATE "C") FROM schedule_links l WHERE l.version_id = x.id))
      INTO j FROM schedule_versions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'schedule_progress' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.activity_code COLLATE "C") FROM schedule_progress_lines l WHERE l.progress_id = x.id))
      INTO j FROM schedule_progress x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract_variation' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM variation_lines l WHERE l.variation_id = x.id))
      INTO j FROM contract_variations x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- A required finish is a working day (the same rule the kernel's calendar uses).
CREATE OR REPLACE FUNCTION schedule_versions_calendar() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.required_finish IS NOT NULL AND (NEW.required_finish < NEW.start_date OR NOT schedule_is_working(NEW, NEW.required_finish)) THEN
    RAISE EXCEPTION 'the required finish is a working day on or after the start' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER schedule_versions_xcalendar BEFORE INSERT ON schedule_versions FOR EACH ROW EXECUTE FUNCTION schedule_versions_calendar();

DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['schedule_versions', 'schedule_activities', 'schedule_links', 'schedule_progress', 'schedule_progress_lines'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;
GRANT UPDATE (status, approved_by, decision_reason, finish_offset, finish_date, algorithm) ON schedule_versions TO serk_app;
GRANT UPDATE (es, ef, ls, lf, total_float, free_float, critical, early_start, early_finish, late_start, late_finish) ON schedule_activities TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON schedule_progress TO serk_app;
REVOKE ALL ON FUNCTION schedule_is_working(schedule_versions, date), schedule_date(schedule_versions, integer), schedule_offset(schedule_versions, date),
  schedule_assert_cpm(schedule_versions), schedule_evm(uuid, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION schedule_is_working(schedule_versions, date), schedule_date(schedule_versions, integer), schedule_offset(schedule_versions, date),
  schedule_assert_cpm(schedule_versions), schedule_evm(uuid, date) TO serk_app;
