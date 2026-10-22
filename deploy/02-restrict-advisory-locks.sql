-- Run as a superuser in the SERK database after migrations when the
-- migrations themselves did not run as a superuser. Advisory locks ignore
-- row-level security; tenant logins must not be able to take them.
-- Replace serk_owner with the role that owns the schema (runs migrations).
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO serk_publisher, serk_owner', f);
  END LOOP;
END$$;
-- Tenant logins must not hold TEMP (R7-F9): the API refuses to start in
-- production while serk_database_posture() reports it.
DO $$ BEGIN EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database()); END $$;
