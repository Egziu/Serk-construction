# ADR 0016: Running with a non-superuser schema owner

Status: accepted by the delivering team (2026-10-22); awaiting human review. Migration 0034.

## Context

Managed PostgreSQL (RDS, Cloud SQL, Azure) never grants a true superuser, and running migrations as a superuser is bad practice anyway. Every tenant table uses FORCE ROW LEVEL SECURITY, which also applies to the table owner. All development and test evidence up to checkpoint 0.6.0 used a superuser owner, which ignores RLS, so this was never exercised. A partial independent review run with a non-superuser owner had 0 of 245 tests pass: tenant provisioning failed, and every owner-side cross-tenant function (integrity scan, health metrics, plaintext-bank count, constraint validation, the bank-number converter) would silently see no rows. The posture check also listed the owner as a tenant login, so production could not start.

## Decision

- One permissive policy, `owner_maintenance`, on every RLS table, granted only TO the schema owner role, with `USING` and `WITH CHECK` = `serk_maintenance_session()`.
- `serk_maintenance_session()` is true only when `session_user` is not a tenant login and is either the schema owner itself (serk-migrate, operator tools) or a login in one of the platform roles `serk_monitor`, `serk_scheduler`, `serk_publisher` or `serk_health`. None of those holds table privileges; they reach data only through the owner's SECURITY DEFINER functions.
- `session_user` cannot be changed by a non-superuser, so a tenant login calling an owner-rights function (current_user = owner) still matches only its own tenant: the predicate is false for its session.
- The posture check excludes the schema owner from "tenant logins".
- `deploy/01-schema-owner.sql` documents the owner role (LOGIN, CREATEROLE, ADMIN on the platform roles, not superuser, not BYPASSRLS).
- Tests run as a non-superuser owner; a separate superuser connection (`SERK_TEST_SUPERUSER_DSN`) is used only by tests that simulate an out-of-band superuser, scratch databases, cluster-level grants and other roles' lock waits.

## Consequences

- Every future migration that creates an RLS table must add the same policy; `TestPrivileges_OwnerMaintenancePolicyEverywhere` fails otherwise.
- A compromised ops login (monitor, scheduler, publisher, health) can read through the owner-rights functions granted to it; this was already the case with a superuser owner.
