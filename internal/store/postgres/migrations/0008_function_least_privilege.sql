-- 0008: least privilege for functions (GATEA-06).
--
-- Finding (docs/security/DB_PRIVILEGE_MATRIX.md, generated from the live
-- catalog): every SECURITY INVOKER helper in schema public still carried
-- PostgreSQL's default EXECUTE grant to PUBLIC, so any login on the cluster
-- (serk_health, serk_relay, a future reporting role) could call
-- approval_require, ledger_integrity_scan, workflow_gate_lock, ... These run
-- with the caller's privileges, so this was not a privilege escalation, but it
-- violates "only what each principal needs" and widens the surface for the
-- next defect. This migration:
--   1. revokes EXECUTE from PUBLIC on every non-extension function in public;
--   2. grants back to the tenant runtime (serk_app) the helpers its statements
--      and guard triggers call; the relay (serk_publisher) and the timer
--      (serk_scheduler) need none beyond their existing explicit grants
--      (current_tenant, workflow_due_tenants) — the full suite passes so;
--   3. makes future functions created by the migrator default-closed;
--   4. pins audit_log_chain and audit_log_verify search_path (pg_catalog first)
--      like every other DEFINER function.
-- Trigger functions are revoked too: PostgreSQL checks EXECUTE on a trigger
-- function only at CREATE TRIGGER time, never when it fires.

DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN
    SELECT p.oid::regprocedure
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
END $$;

-- Tenant runtime: helpers reached from its own statements and from the guard
-- triggers that fire on its writes (those run as the tenant login).
GRANT EXECUTE ON FUNCTION
  approval_canonical(jsonb),
  approval_in_tx(text, text, text, text),
  approval_require(text, text, text, text, text[], boolean),
  approval_subject_hash(text, text),
  assert_currency_precision(numeric, character, text),
  audit_hash(text, bigint, bigint, uuid, timestamptz, text, text, text, text, text, jsonb),
  currency_minor_units(character),
  fiscal_period_tb(fiscal_periods),
  fx_assert_eligible(uuid, uuid, integer, character, character, uuid, timestamptz, timestamptz),
  journal_balance_assert(uuid),
  ledger_integrity_scan(),
  workflow_approvals(uuid, integer),
  workflow_assert_governing(workflow_instances),
  workflow_check_start(workflow_definitions, workflow_instances),
  workflow_excluded(workflow_instances, integer),
  workflow_gate_lock(uuid, text, boolean),
  workflow_require_effect(uuid, text, uuid, text, text)
TO serk_app;

-- current_tenant(), approval_authorize, audit_log_verify,
-- workflow_decide_definition and workflow_due_tenants keep the explicit grants
-- their own migrations gave them (REVOKE ... FROM PUBLIC does not touch those).

ALTER FUNCTION audit_log_chain() SET search_path = pg_catalog, public;
ALTER FUNCTION audit_log_verify(uuid) SET search_path = pg_catalog, public;

-- Default-closed for the future: functions created later by the migrating
-- role get no PUBLIC EXECUTE; each migration must grant what it needs.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
