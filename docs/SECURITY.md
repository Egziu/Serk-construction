# Security posture — 0.2.0-gate-a

Target: OWASP ASVS 5.0 **Level 2** for the API and **Level 3** for the
accounting kernel. This file maps controls that exist *and are tested*; the
threat model is `docs/architecture/THREAT_MODEL.md`, the per-finding record is
`docs/audit/ISSUE_REGISTER.md`. Nothing here claims the system is impenetrable,
and no third-party assessment has been performed.

## Changes since 0.1.0 (all tested)

| Area | Control | Test |
|---|---|---|
| V2 Authentication | OIDC/JWKS verifier (RS256/ES256, `kid`, refresh), `nbf`/`auth_time`/`jti` parsing, MFA from `amr` factor categories; HS256 restricted to development/staging; token minting moved out of the API binary | `TestJWKSVerifier`, `TestIsMFA`, `TestTokenTimeClaims`, config tests |
| V2 Step-up | Recent-MFA requirement (10 min) for FX variance exceptions, period reopen, workflow publishing and MFA workflow steps; RFC 9470 challenge | `TestStepUp`, `TestAPIFXMakerCheckerFlow`, `TestAPIWorkflowConsole` |
| V4 Multi-tenancy | Tenant identity derived from the database login (`current_tenant()` from `session_user`); per-tenant roles; fail-closed binding; dedicated tier. The 0.1.0 gap ("RLS keyed on a settable GUC") is **closed** | `TestSC04_*` |
| V4 Access control | Explicit `scope.tenant_wide`; maker/checker on rates, sources, policies, WBS, workflow definitions; SoD in workflow steps enforced in Go and SQL | `TestScopeSC05`, `TestSC03_*`, `TestWorkflow_*` |
| V11 Business logic | Ledger line identity immutable; FX eligibility at insert and post; period/rate locks against races; mandatory approval workflows enforced by database gates | `TestSC01_*`, `TestSC02_*`, `TestSC08_*`, `TestWorkflow_DatabaseRefusesForgedTrail` |
| V11 Anti-automation | Pre-auth per-IP limiter, invalid-token lockout, in-flight cap | `TestAPIPreAuthFloodProtection` |
| V14 Configuration | Fail-closed config (production default); refuses weak secrets, non-`verify-full` TLS, superuser logins, wildcard proxies | config tests |
| Supply chain | `go.sum` with provenance; actions pinned by SHA; govulncheck; CycloneDX SBOM | CI definition (not yet executed) |

## Remaining gaps

- Compromise of the API process exposes every tenant (shared credential
  derivation secret) — THREAT_MODEL T-4.
- The database cannot verify end-user identity in workflow decisions; a
  tenant-login attacker could fabricate decisions in other people's names that
  satisfy SoD — detectable, not prevented (T-3a).
- No session revocation; rate limits per process; no TLS in the binary (TLS
  proxy in the production profile); no external penetration test; Docker and
  CI not executed in this environment.

---

# Controls carried over from 0.1.0 (still tested)

Where a row below conflicts with the table above (multi-tenancy, HS256-only authentication, `serk_api` role), the table above supersedes it.

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
