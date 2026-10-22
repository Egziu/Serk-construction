-- 0034: cross-tenant maintenance with a NON-superuser schema owner
-- (found by independent review 10: every test, and tenant provisioning,
-- failed when the schema owner is not a superuser, which is the normal case
-- on managed PostgreSQL such as RDS, Cloud SQL or Azure).
--
-- Every tenant table has FORCE ROW LEVEL SECURITY, which also binds the
-- table owner. A superuser ignores it, so with the superuser owner used in
-- development everything worked; with a real non-superuser owner:
--   * serk-migrate provision-tenant could not insert into tenants;
--   * owner-run tools (encrypt-bank-accounts, validate-constraints) saw no
--     rows;
--   * the cross-tenant SECURITY DEFINER functions used by monitoring
--     (ops_health_metrics, ledger_integrity_scan via it, posture checks)
--     silently saw nothing, so integrity alerts could never fire.
--
-- Fix: one permissive policy per RLS table, TO the owner role, that admits
-- a row only when the SESSION is a maintenance session:
--   * session_user is not a tenant login (not in tenant_db_roles), and
--   * session_user is the owner itself (serk-migrate and operator tools) or
--     a login in one of the platform roles serk_monitor, serk_scheduler,
--     serk_publisher, serk_health (which hold no table privileges and reach
--     data only through the owner's SECURITY DEFINER functions).
--
-- session_user cannot be changed by a non-superuser (SET ROLE changes only
-- current_user), so a tenant login calling an owner-rights function still
-- sees only its own tenant: the function runs with current_user = owner,
-- the policy applies, and serk_maintenance_session() is false.

CREATE OR REPLACE FUNCTION serk_maintenance_session() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT NOT EXISTS (SELECT 1 FROM public.tenant_db_roles WHERE role_name = session_user)
     AND (session_user = (SELECT r.rolname FROM pg_roles r JOIN pg_namespace n ON n.nspowner = r.oid WHERE n.nspname = 'public')
          OR pg_has_role(session_user, 'serk_monitor', 'MEMBER')
          OR pg_has_role(session_user, 'serk_scheduler', 'MEMBER')
          OR pg_has_role(session_user, 'serk_publisher', 'MEMBER')
          OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') AND pg_has_role(session_user, 'serk_health', 'MEMBER')))
$$;
REVOKE ALL ON FUNCTION serk_maintenance_session() FROM PUBLIC;

DO $$
DECLARE r record; owner text := current_user;
BEGIN
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity LOOP
    EXECUTE format('DROP POLICY IF EXISTS owner_maintenance ON %I', r.relname);
    EXECUTE format('CREATE POLICY owner_maintenance ON %I TO %I USING (serk_maintenance_session()) WITH CHECK (serk_maintenance_session())',
                   r.relname, owner);
  END LOOP;
END$$;

-- The posture check (0032 body) treated the schema owner as a tenant login
-- when the owner is not a superuser, so production could never start.
CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH tenant_logins AS (
    SELECT r.oid, r.rolname FROM pg_roles r
     WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid, 'serk_app', 'MEMBER')
       -- The schema owner administers serk_app (it creates tenant roles IN
       -- ROLE serk_app) and is a member by that grant; it is not a tenant
       -- login and its own privileges are expected (0034).
       AND r.oid <> (SELECT n.nspowner FROM pg_namespace n WHERE n.nspname = 'public'))
  SELECT 'TEMP is granted on the database to tenant login ' || t.rolname
    FROM tenant_logins t WHERE has_database_privilege(t.oid, current_database(), 'TEMP')
  UNION ALL
  SELECT 'tenant login ' || t.rolname || ' may CREATE in schema ' || n.nspname
    FROM tenant_logins t CROSS JOIN pg_namespace n
   WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND has_schema_privilege(t.oid, n.oid, 'CREATE')
  UNION ALL
  SELECT 'advisory-lock function ' || p.proname || ' is executable by tenant login ' || t.rolname
    FROM tenant_logins t CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege(t.oid, p.oid, 'EXECUTE')
  UNION ALL
  SELECT DISTINCT 'advisory-lock function ' || p.proname || ' is executable by serk_app'
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege('serk_app', p.oid, 'EXECUTE')
  UNION ALL
  SELECT 'bank account numbers stored in plaintext: ' || n || ' row(s); run serk-migrate encrypt-bank-accounts'
    FROM (SELECT serk_bank_plaintext_rows() AS n) x WHERE n > 0
  UNION ALL
  -- Query parameters (account numbers travel as parameters) must not be
  -- logged in full.
  SELECT 'log_parameter_max_length is ' || current_setting('log_parameter_max_length') || ' (set 0 so bound parameters are never logged)'
   WHERE current_setting('log_parameter_max_length') NOT IN ('0')
$$;

-- Future migrations that create an RLS table must add the same policy; the
-- privilege test TestPrivileges_OwnerMaintenancePolicyEverywhere enforces it.
