-- Cluster roles for SERK Construction. Run once per cluster by the operator.
-- No passwords are set here: set them from your secret store, e.g.
--   ALTER ROLE serk_health PASSWORD '<from secret store>';
-- Tenant roles (serk_t_<uuid>) are created by `serk-migrate provision-tenant`.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_app') THEN
    CREATE ROLE serk_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_publisher') THEN
    CREATE ROLE serk_publisher NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  -- Readiness probe login: no table privileges at all.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') THEN
    CREATE ROLE serk_health LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  -- Workflow timer login: may learn which tenants have due timers, nothing
  -- else (EXECUTE on workflow_due_tenants only, granted by migration 0006).
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_scheduler') THEN
    CREATE ROLE serk_scheduler NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_timer') THEN
    CREATE ROLE serk_timer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT IN ROLE serk_scheduler;
  END IF;
  -- Outbox relay login: cross-tenant outbox access only.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_relay') THEN
    CREATE ROLE serk_relay LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT IN ROLE serk_publisher;
  END IF;
END$$;
-- The 0.1.0 shared application login is retired (SC-04): it no longer sees
-- any rows, and should be removed from existing clusters:
--   DROP ROLE IF EXISTS serk_api;
-- Metrics login (GATEA-11): EXECUTE ops_health_metrics() only (migration 0011).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_monitor') THEN
    CREATE ROLE serk_monitor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_metrics') THEN
    CREATE ROLE serk_metrics LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT IN ROLE serk_monitor;
  END IF;
END$$;
-- Abuse-limit login (migration 0029): EXECUTE abuse_hit/abuse_blocked only;
-- no table privileges, no tenant data. Used by every API replica so limits
-- and lockouts are shared (SERK_ABUSE_DSN).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_abuse') THEN
    CREATE ROLE serk_abuse NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_ratelimit') THEN
    CREATE ROLE serk_ratelimit LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT IN ROLE serk_abuse;
  END IF;
END$$;
