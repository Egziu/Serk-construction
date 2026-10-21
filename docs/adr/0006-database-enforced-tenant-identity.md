# ADR 0006 — Tenant identity comes from the database login, not a session variable

**Status:** Accepted · 2026-10-21 · supersedes the tenancy part of ADR 0002

## Context
Audit finding SC-04: in 0.1.0 every request used one login (`serk_api`) and
selected its tenant with `set_config('app.tenant_id', …)`. RLS keyed on a
settable GUC contains application *bugs*; it does not stop anyone who can run
SQL as that login — they simply set another tenant id. The audit reproduced
this (`docs/audit/evidence/SC-14-SC-04-before.txt`).

## Decision
1. Each tenant gets its own PostgreSQL LOGIN role `serk_t_<uuid hex>`, a member
   of the privilege group `serk_app`, never superuser, never `BYPASSRLS`.
2. `tenant_db_roles` maps role → tenant. `current_tenant()` (SECURITY DEFINER,
   pinned `search_path`) returns the tenant of `session_user`. `session_user`
   cannot be changed by `SET ROLE` or `set_config`. Every RLS policy uses
   `current_tenant()`.
3. The API connects through a `Router` that keeps one small pool per tenant.
   Passwords are `HMAC-SHA256(secret, "serk-tenant-db:" + tenant)` so the
   application holds one secret rather than N passwords; a leaked tenant
   password does not reveal another tenant's.
4. A `DEDICATED_DB` tier maps a tenant to its own database/cluster DSN.
5. The transaction-binding step verifies the connection's `current_tenant()`
   equals the requested tenant and fails closed on mismatch (misrouting).
6. The shared `serk_api` login is retired; it sees no rows.

## Consequences
+ Arbitrary SQL with one tenant's credentials cannot read or write another
  tenant's rows (`TestSC04_CompromisedTenantCredentialCannotReachOtherTenant`).
+ Cross-tenant system jobs need explicit, narrow grants (`serk_publisher` for
  the relay; `serk_scheduler` learns only tenant ids for workflow timers).
− Compromise of the **API process** yields the derivation secret, and thus
  every tenant role. That is the residual risk (THREAT_MODEL T-3); the next
  step for high-value tenants is per-tenant secrets from a vault or the
  dedicated tier.
− Connection count grows with active tenants; the Router evicts idle pools
  (LRU + idle timeout). PgBouncer in transaction mode is compatible because the
  identity is the login, not session state.
