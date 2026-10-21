# Database privilege matrix (GATEA-06)

**Generated from the live catalog**, not transcribed from migrations: the tables
below are the verbatim output of `psql -At -f docs/security/privilege_matrix.sql`
run as superuser against a freshly migrated PostgreSQL 16.15 database
(`serk_full`, migrations 0001–0012)
at commit 74fb7d4. Re-generate after every migration; the invariants are enforced
by `internal/kernel/privilege_test.go` (`TestPrivileges_*`), which fails the build if
they regress.

## 1. Principal model

| Principal | SQL role | LOGIN | Holds | Purpose / boundary |
|---|---|---|---|---|
| Tenant runtime (API, one per tenant) | `serk_t_<hex>` member of `serk_app` | yes (HMAC-derived password, SC-04) | grants of `serk_app` | Business writes for exactly one tenant: `current_tenant()` is derived from `session_user`, every tenant table has FORCE RLS. **Cannot** create approval evidence except through `approval_authorize()` with a valid signature from the API's approval key (see APPROVAL_ATTESTATION_DESIGN.md). |
| Outbox relay | `serk_relay` member of `serk_publisher` | yes | outbox SELECT + delivery-bookkeeping columns, processed_events | Cross-tenant event delivery; no business tables, no approval functions. |
| Workflow timer | `serk_timer` member of `serk_scheduler` | yes | EXECUTE `workflow_due_tenants(int)` only | Learns which tenants have due timers; then acts as each tenant through the tenant runtime path. |
| Readiness probe | `serk_health` | yes | nothing | `SELECT 1`. |
| Metrics scraper | `serk_metrics` member of `serk_monitor` | yes | EXECUTE `ops_health_metrics()` only | Aggregate health numbers; no table, no tenant data (0011). |
| Migrator / provisioner | schema owner (`postgres` in the test cluster; `<owner>` DSN in deploy/docker-compose.prod.yml) | yes, used only by `serk-migrate` | owner of all objects, CREATEROLE | Applies migrations, provisions tenant roles and installs per-tenant approval verification keys. Owner can disable triggers — see residual R-DBA. |
| Database administrator / superuser | `postgres` | operator only | everything | Out of band; can override every control (residual R-DBA). |
| Authenticator, reporting user, analyst, backup account, break-glass | **do not exist yet** | — | — | NOT IMPLEMENTED. Required by directive §2.1/§3.1; tracked as open items. A backup account would use `pg_basebackup`/REPLICATION, never `serk_app`. |
| AI / automation principals | **none** | — | — | No SQL role exists for AI; the only roles that can reach `approval_authorize` are tenant logins, and an attestation requires the API's signing key (GATEF-01 still NOT TESTED as a gate). |

Retired: `serk_api` (shared 0.1.0 login) sees no rows (SC-04) and should be dropped.

## 2. Invariants enforced by tests (all PASS on 1371d63)

| Invariant | Test |
|---|---|
| No non-extension function in schema public is EXECUTE-able by PUBLIC | TestPrivileges_CatalogInvariants |
| Every SECURITY DEFINER function pins `search_path=pg_catalog, public` | TestPrivileges_CatalogInvariants |
| No app role has DELETE/TRUNCATE/TRIGGER/REFERENCES on any table | TestPrivileges_CatalogInvariants |
| Every tenant table readable by serk_app has FORCE RLS | TestPrivileges_CatalogInvariants |
| No runtime role can read `approval_keys`, call `approval_key_install`, or write `approval_attestations` | TestPrivileges_CatalogInvariants |
| relay/timer/health cannot call `approval_authorize`, `workflow_decide_definition`, or write journals | TestPrivileges_CatalogInvariants |
| No runtime role is SUPERUSER/CREATEROLE/CREATEDB/BYPASSRLS/REPLICATION | TestPrivileges_CatalogInvariants |
| serk_health, serk_publisher, serk_scheduler logins are refused *at the function boundary* for ledger scan, approval evidence, attestation, subject hash, gate lock | TestPrivileges_NonTenantRolesAreRefused (real connections) |
| Tenant login cannot DELETE/TRUNCATE journals, disable triggers, rewrite approval evidence, journal lines, journal dates or the audit log | TestPrivileges_TenantLoginCannotRewriteHistory (real connection) |
| Tenant login cannot read keys, install a key, SET ROLE, CREATE in public, CREATE TEMP, or use a GUC to switch tenant | TestAttestation_TenantLoginCannotReachKeysOrEscalate |

Mutation check (executed): removing the REVOKE loop from 0008 makes both
`TestPrivileges_CatalogInvariants` and `TestPrivileges_NonTenantRolesAreRefused` fail.

## 3. Finding fixed by 0008

Before 0008 the live catalog showed **every SECURITY INVOKER helper executable by
PUBLIC** (e.g. `approval_require`, `ledger_integrity_scan`, `workflow_gate_lock`)
and `audit_log_chain`/`audit_log_verify` with `search_path=public` (no
`pg_catalog` first). Not an escalation (invoker functions run with the caller's
rights), but a least-privilege violation. 0008 revokes PUBLIC on all, grants
`serk_app` what its statements and guard triggers call, pins both search paths,
and attempted to close future functions with `ALTER DEFAULT PRIVILEGES IN SCHEMA public …`.
**That last statement was a no-op** (R-10: per-schema default privileges can only
add to the global defaults). It was caught by the catalog invariant when 0009
created a trigger function; 0009 applies the global form, and
`TestPrivileges_NewFunctionsAreClosedByDefault` now proves it (its mutant fails).

## 4. Generated matrix (verbatim)

Column grants are shown as `UPDATE(col,…)` when the role lacks table-level UPDATE.
"RLS forced = enabled" means RLS on but not forced (owner-only tables).

## Tables: effective privileges per role (has_table_privilege / has_column_privilege)

| table | serk_app (tenant logins) | serk_publisher (relay) | serk_scheduler (timers) | PUBLIC | RLS forced |
|---|---|---|---|---|---|
| accounts | SELECT INSERT · UPDATE(name,active,cost_coding) | — | — | — | yes |
| approval_attestations | SELECT | — | — | — | yes |
| approval_consumptions | SELECT | — | — | — | yes |
| approval_keys | — | — | — | — | no |
| audit_heads | — | — | — | — | enabled |
| audit_log | SELECT INSERT | — | — | — | yes |
| cost_codes | SELECT INSERT · UPDATE(status,valid_to) | — | — | — | yes |
| currencies | SELECT | — | — | — | no |
| fiscal_period_closes | SELECT | — | — | — | yes |
| fiscal_periods | SELECT INSERT · UPDATE(status,closed_by,closed_at,reopen_reason,reopened_by) | — | — | — | yes |
| fx_policies | SELECT INSERT · UPDATE(status,approved_by,approved_at) | — | — | — | yes |
| fx_snapshots | SELECT INSERT · UPDATE(approval_status,approved_by,decided_at,decision_reason,rejected_by,variance_exception,approver_mfa) | — | — | — | yes |
| fx_sources | SELECT INSERT · UPDATE(status,approved_by,approved_at) | — | — | — | yes |
| journal_lines | SELECT INSERT | — | — | — | yes |
| journals | SELECT INSERT · UPDATE(status,approved_by,approved_at,posted_by,posted_at,reversed_by) | — | — | — | yes |
| legal_entities | SELECT INSERT · UPDATE(name,presentation_currency) | — | — | — | yes |
| migration_exceptions | — | — | — | — | no |
| outbox | SELECT INSERT | SELECT · UPDATE(published_at,attempts,next_attempt_at,last_error,dead_at) | — | — | yes |
| processed_events | — | SELECT INSERT | — | — | no |
| projects | SELECT INSERT · UPDATE(name,status) | — | — | — | yes |
| schema_migrations | — | — | — | — | no |
| session_revocations | SELECT INSERT | — | — | — | yes |
| tenant_db_roles | — | — | — | — | no |
| tenants | SELECT | — | — | — | yes |
| wbs_nodes | SELECT INSERT | — | — | — | yes |
| wbs_versions | SELECT INSERT · UPDATE(status,approved_by,approved_at) | — | — | — | yes |
| workflow_decisions | SELECT INSERT | — | — | — | yes |
| workflow_definitions | SELECT INSERT | — | — | — | yes |
| workflow_effects | SELECT INSERT | — | — | — | yes |
| workflow_gate_locks | SELECT INSERT · UPDATE(subject) | — | — | — | yes |
| workflow_history | SELECT INSERT | — | — | — | yes |
| workflow_instances | SELECT INSERT · UPDATE(status,current_step,escalated_at,ended_at,ended_by,end_reason,effect_failures,last_error,version) | — | — | — | yes |

## Functions callable by application roles (excluding trigger functions, which cannot be called directly)

| function | security | serk_app | serk_publisher | serk_scheduler | serk_monitor | PUBLIC |
|---|---|---|---|---|---|---|
| approval_authorize(jsonb) | **DEFINER** | EXECUTE | — | — | — | — |
| approval_key_install(uuid,text,bytea) | **DEFINER** | — | — | — | — | — |
| approval_use(text,text,text,text,text[],boolean,text,text) | **DEFINER** | EXECUTE | — | — | — | — |
| audit_log_verify(uuid) | **DEFINER** | EXECUTE | — | — | — | — |
| current_tenant() | **DEFINER** | EXECUTE | EXECUTE | — | — | — |
| fiscal_period_close_record(uuid,text,text,text,text) | **DEFINER** | EXECUTE | — | — | — | — |
| ops_health_metrics() | **DEFINER** | — | — | — | EXECUTE | — |
| provision_tenant_role(uuid,name) | **DEFINER** | — | — | — | — | — |
| workflow_decide_definition(uuid,text,text,text) | **DEFINER** | EXECUTE | — | — | — | — |
| workflow_due_tenants(integer) | **DEFINER** | — | — | EXECUTE | — | — |
| approval_canonical(jsonb) | invoker | EXECUTE | — | — | — | — |
| approval_consumed_in_tx(text[],text,text,text) | invoker | EXECUTE | — | — | — | — |
| approval_in_tx(text,text,text,text) | invoker | EXECUTE | — | — | — | — |
| approval_require(text,text,text,text,text[],boolean) | invoker | EXECUTE | — | — | — | — |
| approval_subject_hash(text,text) | invoker | EXECUTE | — | — | — | — |
| assert_currency_precision(numeric,character,text) | invoker | EXECUTE | — | — | — | — |
| audit_hash(text,bigint,bigint,uuid,timestamp with time zone,text,text,text,text,text,jsonb) | invoker | EXECUTE | — | — | — | — |
| authority_frozen(jsonb,jsonb,text[],text[],text) | invoker | EXECUTE | — | — | — | — |
| currency_minor_units(character) | invoker | EXECUTE | — | — | — | — |
| fiscal_period_tb(fiscal_periods) | invoker | EXECUTE | — | — | — | — |
| fx_assert_eligible(uuid,uuid,integer,character,character,uuid,timestamp with time zone,timestamp with time zone) | invoker | EXECUTE | — | — | — | — |
| journal_balance_assert(uuid) | invoker | EXECUTE | — | — | — | — |
| ledger_integrity_scan() | invoker | EXECUTE | — | — | — | — |
| session_is_revoked(text,text,timestamp with time zone) | invoker | EXECUTE | — | — | — | — |
| workflow_approvals(uuid,integer) | invoker | EXECUTE | — | — | — | — |
| workflow_assert_governing(workflow_instances) | invoker | EXECUTE | — | — | — | — |
| workflow_body_digest(jsonb) | invoker | EXECUTE | — | — | — | — |
| workflow_check_start(workflow_definitions,workflow_instances) | invoker | EXECUTE | — | — | — | — |
| workflow_excluded(workflow_instances,integer) | invoker | EXECUTE | — | — | — | — |
| workflow_gate_lock(uuid,text,boolean) | invoker | EXECUTE | — | — | — | — |
| workflow_require_effect(uuid,text,uuid,text,text) | invoker | EXECUTE | — | — | — | — |

## SECURITY DEFINER functions: owner and pinned search_path

| function | owner | search_path |
|---|---|---|
| approval_authorize(jsonb) | postgres | search_path=pg_catalog, public |
| approval_key_install(uuid,text,bytea) | postgres | search_path=pg_catalog, public |
| approval_use(text,text,text,text,text[],boolean,text,text) | postgres | search_path=pg_catalog, public |
| audit_log_chain() | postgres | search_path=pg_catalog, public |
| audit_log_verify(uuid) | postgres | search_path=pg_catalog, public |
| current_tenant() | postgres | search_path=pg_catalog, public |
| fiscal_period_close_record(uuid,text,text,text,text) | postgres | search_path=pg_catalog, public |
| ops_health_metrics() | postgres | search_path=pg_catalog, public |
| provision_tenant_role(uuid,name) | postgres | search_path=pg_catalog, public |
| workflow_decide_definition(uuid,text,text,text) | postgres | search_path=pg_catalog, public |
| workflow_due_tenants(integer) | postgres | search_path=pg_catalog, public |

## Database-level privileges of PUBLIC

- TEMPORARY for PUBLIC: no; CREATE on schema public for PUBLIC: no; advisory-lock functions EXECUTE for PUBLIC: no
