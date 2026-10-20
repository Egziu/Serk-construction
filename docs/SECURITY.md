# Security posture — Financial Kernel 0.1.0

Target: OWASP ASVS 5.0 **Level 2** for the API and **Level 3** for the
accounting kernel (financial data of record). This file maps controls that
exist *and are tested* to ASVS chapters; untested or absent controls are listed
as gaps. Nothing here claims the system is impenetrable (LAW 07).

## Implemented and tested

| ASVS area | Control | Where | Test |
|---|---|---|---|
| V2 Authentication | Bearer JWT, HS256 only; `alg=none`, tampered payload, foreign key, expiry, issuer/audience all rejected; constant-time MAC compare; ≥32-byte secret enforced | `internal/httpapi/token.go` | `TestTokenRejections` |
| V4 Access control | Server-side RBAC per command; tenant bound from the token, never from the body (unknown `tenant_id` field → 400); project ABAC; SoD preparer≠approver (also a DB CHECK) and strict poster separation | `pkg/auth`, `internal/kernel` | `TestSegregationOfDuties`, `TestProjectAttributeRestriction`, `TestAPIRejections` |
| V4 Multi-tenancy | PostgreSQL RLS with `FORCE` on every tenant table; app role is not owner/superuser; composite `(tenant_id, legal_entity_id, id)` foreign keys so a row can never reference another tenant's or entity's row; 404 (not 403) for foreign resources. **Limit:** RLS keyed on a session GUC is defeated by anyone who can run `set_config` as the app role (i.e. arbitrary SQL execution); it is a defect-containment control, not an attacker boundary — see gaps | `0001_kernel.sql`, `store.go` | `TestTenantIsolation`, `TestJournalBoundToLegalEntity` |
| V5 Input validation | Strict JSON decoding (`DisallowUnknownFields`, no trailing data), 1 MiB body cap, content-type enforcement, UUID path validation, strict decimal parsing (plain notation only, no more decimals than the currency allows — never silently rounded) | `server.go`, `pkg/money` | `TestAPIRejections`, `TestJSONRoundTrip` |
| V6/V11 Business logic | Balance, state machine, immutability from APPROVED, approval-content hash re-check at post, reversal-link mirror validation, period gate, FX reconciliation, account/entity binding — enforced in Go **and** at COMMIT in PostgreSQL; atomic idempotency (`ON CONFLICT`) with creator-scoped command hash; optimistic concurrency | `ledger`, `repo.go`, triggers | `TestUnbalancedRejectedInGoAndInDatabase`, `TestApprovedContentIsFrozen`, `TestReversedLinkCannotBeForged`, `TestFXLineMustReconcileToApprovedSnapshotOfRightPair`, `TestJournalBoundToLegalEntity`, `TestConcurrentIdenticalCreatesAreIdempotent`, `TestOptimisticConcurrency` |
| V7 Logging | Append-only, SHA-256 hash-chained audit log (hash covers seq, chain position, timestamp, actor, action, payload) computed by a SECURITY DEFINER trigger serialised on a per-tenant head row the app role cannot read or write; `audit_log_verify()` checks chain order and head; request ids propagated | `0001_kernel.sql`, `kernel.go` | `TestAuditChainLinearUnderConcurrency` (80 parallel commands, zero forks) |
| V8 Data protection | No DELETE grant on any financial table; all 15 FX observation fields immutable and referenced snapshots cannot be withdrawn; account type/code/currency and entity functional currency frozen once referenced; LOCKED periods terminal; outbox content immutable and only `serk_publisher` may mark rows sent | grants, triggers | `TestFXLineMustReconcileToApprovedSnapshotOfRightPair`, `TestJournalBoundToLegalEntity`, `TestOutboxAndPeriodsCannotBeTamperedByAppRole` |
| V11 Rate limiting | Per-principal fixed window, 429 + Retry-After | `server.go` | `TestAPIRateLimit` |
| V13/V14 API & config | Security headers (nosniff, no-store, CSP none, HSTS), hardened `http.Server` timeouts, 16 KiB header cap, distroless non-root container, secrets only via env | `server.go`, `deploy/Dockerfile` | `TestAPIRejections` |
| Supply chain | Pinned Go modules; `govulncheck` in CI; `-trimpath` reproducible builds | `go.mod`, CI | CI |

## Known gaps (tracked in NEXT.md)

- **Tenant isolation against SQL-level attackers.** With one application role,
  RLS cannot stop code that calls `set_config('app.tenant_id', …)`. There is
  no SQL injection path in this codebase (all queries parameterised, verified
  by review), so the practical exposure is a compromised `serk_api` credential,
  which then exposes all tenants in the shared database. Strong isolation =
  DEDICATED_DB mode or per-tenant database roles (NEXT #0).
- No OIDC federation, MFA, `nbf`/`jti`/revocation or key rotation yet (NEXT #2).
- Rate limiter is per-process; multi-replica deployments need a shared store.
- No TLS termination in the binary: deploy behind a TLS-terminating proxy.
- No external penetration test or dependency SBOM yet (NEXT #17).
- Audit chain protects integrity, not confidentiality: enable PostgreSQL TDE
  or disk encryption and restrict `audit.read`.
- `serk_api` password in `deploy/00-roles.sql` is a development default.

## Threat model summary

| Threat | Mitigation |
|---|---|
| Compromised application credentials | No DELETE grant; posted/approved history cannot be altered; audit chain exposes tampering; outbox cannot be suppressed. Does **not** confine the attacker to one tenant in SHARED mode (see gaps) |
| Insider posts fraudulent entries | SoD across three roles, approver≠preparer enforced in DB, every step audited with actor and request id |
| Replay / duplicate submission from flaky field networks | Idempotency key + canonical command hash; replays are no-ops, conflicting reuse is refused |
| Back-dated postings into closed periods | DB trigger refuses POSTED unless an OPEN period covers the business event date |
| FX manipulation | Only APPROVED snapshots selectable; observation fields immutable; selection and rate bound to the line |
| AI output written as fact | No AI component holds `journal.*` permissions; kernel has no AI dependency (LAW 01/02) |
