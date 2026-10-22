-- Schema owner for managed PostgreSQL (RDS, Cloud SQL, Azure) and for any
-- cluster where migrations should NOT run as a superuser (recommended
-- everywhere). Run once per cluster as the platform administrator, after
-- 00-roles.sql, then create the database owned by this role.
--
-- What the owner needs, and why:
--   LOGIN, CREATEROLE        serk-migrate provision-tenant creates one LOGIN
--                            role per tenant (serk_t_<uuid>) IN ROLE serk_app
--   ADMIN OPTION on serk_app, serk_publisher, serk_scheduler, serk_monitor,
--   serk_abuse, serk_health  to place tenant and platform logins in them
--   ownership of schema public and of the database
--   NOT superuser, NOT BYPASSRLS: every tenant table forces row-level
--   security on its owner too; cross-tenant maintenance works only from a
--   maintenance session (migration 0034, serk_maintenance_session()).
--
-- Replace the password from your secret store.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_owner') THEN
    CREATE ROLE serk_owner LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS NOCREATEDB NOREPLICATION;
  END IF;
END$$;
GRANT serk_app, serk_publisher, serk_scheduler, serk_monitor, serk_abuse, serk_health TO serk_owner WITH ADMIN OPTION;
-- Then, as the administrator:
--   CREATE DATABASE serk OWNER serk_owner;
--   \c serk
--   ALTER SCHEMA public OWNER TO serk_owner;
--   CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- run `serk-migrate` as serk_owner, and finally deploy/02-restrict-advisory-locks.sql
-- (as the administrator: it revokes pg_catalog functions, which only a superuser can).
