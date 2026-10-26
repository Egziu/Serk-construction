-- 0038 Platform: tenant portal settings, server-side notifications,
-- customer-configurable automation rules, deterministic risk snapshots and
-- data-access accounting (anti-exfiltration).
--
-- Governance (unchanged by this migration):
--   * Automation and intelligence never approve, post, pay or release. A rule
--     may notify, escalate or record; a person decides. The database keeps
--     enforcing attested human decisions regardless of what any rule says.
--   * A rule is proposed by one person (automation.manage) and activated by a
--     different person (automation.activate): maker/checker, as for workflow
--     definitions.
--   * Everything is tenant-isolated by row-level security like every other
--     table; the vendor (SERK Construction OS) has no row in any tenant.

-- --------------------------------------------------------- tenant settings
-- One row per tenant: how the construction company presents itself in its
-- portal and on its exports. The vendor name is not stored here; it is the
-- product.
CREATE TABLE tenant_settings (
  tenant_id          uuid PRIMARY KEY DEFAULT current_tenant() REFERENCES tenants(id),
  display_name       text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 2 AND 120),
  short_code         text NOT NULL CHECK (short_code ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
  letterhead_name    text NOT NULL DEFAULT '' CHECK (length(letterhead_name) <= 160),
  country            char(2) NOT NULL DEFAULT 'ET',
  timezone           text NOT NULL DEFAULT 'Africa/Addis_Ababa' CHECK (length(timezone) BETWEEN 1 AND 64),
  locale             text NOT NULL DEFAULT 'en' CHECK (locale IN ('en', 'am', 'ti')),
  export_daily_limit integer NOT NULL DEFAULT 200 CHECK (export_daily_limit BETWEEN 1 AND 100000),
  theme_accent       text NOT NULL DEFAULT '' CHECK (theme_accent = '' OR theme_accent ~ '^#[0-9a-f]{6}$'),
  version            integer NOT NULL DEFAULT 1,
  updated_by         text NOT NULL,
  updated_at         timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------ notifications
-- Produced by automation rules, the intelligence layer and security
-- controls; read by the person or role they address. dedupe_key makes rule
-- re-evaluation idempotent: the same finding is recorded once until it is
-- resolved (resolved_at), after which it may recur with a new key.
CREATE TABLE notifications (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  recipient_user text,
  recipient_role text,
  kind           text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{1,63}$'),
  severity       text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warn', 'critical')),
  title          text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
  body           text NOT NULL DEFAULT '' CHECK (length(body) <= 4000),
  subject_type   text NOT NULL DEFAULT '',
  subject_id     text NOT NULL DEFAULT '',
  project_id     uuid,
  href           text NOT NULL DEFAULT '' CHECK (href = '' OR href ~ '^#/[A-Za-z0-9/_.?=&-]{1,200}$'),
  rule_id        uuid,
  dedupe_key     text NOT NULL,
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  read_at        timestamptz,
  resolved_at    timestamptz,
  UNIQUE (tenant_id, dedupe_key),
  CONSTRAINT notification_addressed CHECK (recipient_user IS NOT NULL OR recipient_role IS NOT NULL),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);
CREATE INDEX notifications_open ON notifications (tenant_id, created_at DESC) WHERE resolved_at IS NULL;

-- ------------------------------------------------------- automation rules
-- The rule body is validated by the kernel against a fixed catalogue of
-- conditions and actions (pkg/automation); the database stores it and keeps
-- the lifecycle honest.
CREATE TABLE automation_rules (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  code         text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9_-]{1,39}$'),
  name         text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 120),
  description  text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
  body         jsonb NOT NULL,
  status       text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ACTIVE', 'RETIRED')),
  version      integer NOT NULL DEFAULT 1,
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  activated_by text,
  activated_at timestamptz,
  retired_by   text,
  retired_at   timestamptz,
  retire_reason text,
  last_run_at  timestamptz,
  last_run_findings integer NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, code),
  CONSTRAINT automation_rule_maker_checker CHECK (activated_by IS NULL OR activated_by <> created_by),
  CONSTRAINT automation_rule_lifecycle CHECK (
    (status = 'DRAFT' AND activated_by IS NULL AND retired_by IS NULL) OR
    (status = 'ACTIVE' AND activated_by IS NOT NULL AND retired_by IS NULL) OR
    (status = 'RETIRED' AND retired_by IS NOT NULL))
);

-- An ACTIVE or RETIRED rule's body never changes (edit = new draft version).
CREATE OR REPLACE FUNCTION automation_rules_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF OLD.status <> 'DRAFT' AND (NEW.body IS DISTINCT FROM OLD.body OR NEW.code <> OLD.code OR NEW.created_by <> OLD.created_by) THEN
    RAISE EXCEPTION 'automation rule % is %: its body is frozen (create a new version)', OLD.code, OLD.status USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'RETIRED' AND NEW.status <> 'RETIRED' THEN
    RAISE EXCEPTION 'automation rule % is retired', OLD.code USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER automation_rules_guard BEFORE UPDATE ON automation_rules FOR EACH ROW EXECUTE FUNCTION automation_rules_guard();

-- --------------------------------------------------------- risk snapshots
-- The intelligence layer is deterministic; snapshots keep its history so
-- that trends can be shown and, later, forecasts evaluated against outcomes
-- (a prediction without a recorded baseline is not a prediction).
CREATE TABLE risk_snapshots (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  project_id  uuid NOT NULL,
  computed_at timestamptz NOT NULL DEFAULT now(),
  overall     text NOT NULL CHECK (overall IN ('low', 'medium', 'high', 'unknown')),
  findings    jsonb NOT NULL,
  algorithm   text NOT NULL,
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);
CREATE INDEX risk_snapshots_project ON risk_snapshots (tenant_id, project_id, computed_at DESC);

-- ---------------------------------------------------- data access events
-- Exports and reveals, counted per person and day for the export budget and
-- for bulk-read anomaly rules. Append-only.
CREATE TABLE data_access_events (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  user_id     text NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('export', 'reveal', 'bulk_read')),
  subject     text NOT NULL DEFAULT '',
  bytes       bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0),
  occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX data_access_events_user_day ON data_access_events (tenant_id, user_id, occurred_at DESC);

-- ----------------------------------------------- subject scope (0036 map)
-- Rules, notifications and snapshots are tenant-level subjects for
-- attestation scope purposes (the fail-closed default already returns '').

-- ------------------------------------------------- row security, grants ---
DO $$
DECLARE tbl text; owner text := current_user;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['tenant_settings', 'notifications', 'automation_rules', 'risk_snapshots', 'data_access_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('CREATE POLICY owner_maintenance ON %I TO %I USING (serk_maintenance_session()) WITH CHECK (serk_maintenance_session())', tbl, owner);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;
GRANT UPDATE (display_name, short_code, letterhead_name, country, timezone, locale, export_daily_limit, theme_accent, version, updated_by, updated_at) ON tenant_settings TO serk_app;
GRANT UPDATE (read_at, resolved_at) ON notifications TO serk_app;
GRANT UPDATE (name, description, body, status, version, activated_by, activated_at, retired_by, retired_at, retire_reason, last_run_at, last_run_findings) ON automation_rules TO serk_app;
GRANT USAGE ON SEQUENCE risk_snapshots_id_seq, data_access_events_id_seq TO serk_app;

-- The automation worker learns which tenants have active rules the same way
-- the workflow timer learns its tenants: a definer function returning ids
-- only, executable by serk_scheduler.
DO $$
BEGIN
  EXECUTE format('CREATE POLICY owner_rule_scan ON automation_rules FOR SELECT TO %I USING (true)', current_user);
END$$;
CREATE OR REPLACE FUNCTION automation_due_tenants(max_tenants integer) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT DISTINCT tenant_id FROM automation_rules WHERE status = 'ACTIVE'
   LIMIT LEAST(GREATEST(max_tenants, 1), 10000)
$$;
REVOKE ALL ON FUNCTION automation_due_tenants(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION automation_due_tenants(integer) TO serk_scheduler;
REVOKE ALL ON FUNCTION automation_rules_guard() FROM PUBLIC;
