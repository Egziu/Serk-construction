# SERK Construction — Delivery Status (LAW 08 register)

**Release:** 0.1.0 — Financial Kernel Vertical Slice
**Date:** 2026-10-20
**Spec:** SERK-CONSTRUCTION-MASTER-2026 v1.0

This register states, per capability, exactly how far it has been taken. A
capability is never marked further right than the evidence supports. An
independent adversarial review (`docs/REVIEW-2026-10-20.md`) was run against
the first cut; every finding was fixed and is now covered by a regression test
listed below. Columns: **A** architecture defined · **C** code implemented ·
**U** unit tests pass · **I** integration tests pass (real PostgreSQL 16) ·
**S** security tested (adversarial raw-SQL / API tests) · **O** operationally
validated · **P** production-release approved.

| Capability | A | C | U | I | S | O | P | Evidence |
|---|---|---|---|---|---|---|---|---|
| Exact-decimal money, ISO 4217 registry (41 currencies incl. all African ones named in §3.2), 4 rounding policies, lossless allocation, strict external parsing (no silent rounding) | ✅ | ✅ | ✅ | — | ✅ | — | — | `pkg/money`, 7 tests |
| FX snapshot model (all 15 spec fields), policy-driven selection with knowledge cutoff, source priority, staleness, explicit inverse, exception errors (never a fabricated rate) | ✅ | ✅ | ✅ | ✅ | — | — | — | `pkg/fx`, 9 tests; `TestFXSnapshotsAndConversion` |
| FX line provenance: line must reference an APPROVED snapshot of the right pair, reconcile to it, and store the applied rate; referenced snapshots cannot be withdrawn; all observation fields immutable | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestFXLineMustReconcileToApprovedSnapshotOfRightPair` |
| IAS 21 monetary remeasurement with asset/liability sign (library) | ✅ | ✅ | ✅ | — | — | — | — | `pkg/fx` |
| Journal domain: balance invariant, line rules, state machine DRAFT→APPROVED→POSTED→REVERSED, mirrored reversals, line project = header project | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `pkg/ledger`, 6 tests; `TestProjectRestrictionCoversLines` |
| Entity binding: journal currency = entity functional currency (FK), lines → accounts/projects of the same entity (composite FKs), active accounts, account currency restriction, frozen reference data | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestJournalBoundToLegalEntity` |
| PostgreSQL kernel: RLS (FORCE), deferred balance constraint trigger, immutability from APPROVED, approval-content hash re-check at post, reversal-link mirror validation, fiscal-period gate (LOCKED terminal), SoD CHECK | ✅ | ✅ | n/a | ✅ | ✅ | — | — | `0001_kernel.sql`; `TestUnbalancedRejectedInGoAndInDatabase`, `TestApprovedContentIsFrozen`, `TestReversedLinkCannotBeForged`, `TestPostedJournalIsImmutable`, `TestClosedPeriodBlocksPosting` |
| Tenant isolation (RLS + composite FKs) against application defects and cross-tenant references | ✅ | ✅ | n/a | ✅ | ✅ | — | — | `TestTenantIsolation` |
| Tenant isolation against **SQL-level attackers** (arbitrary SQL as the app role) | ✅ (DEDICATED_DB mode / per-tenant roles) | ❌ | — | — | ❌ (review showed GUC can be reset) | — | — | NEXT #0 |
| Hash-chained, append-only audit log: SECURITY DEFINER trigger, per-tenant head row, linear under concurrency, hash covers seq/position/time/actor/payload, `audit_log_verify()` | ✅ | ✅ | n/a | ✅ | ✅ | — | — | `TestAuditChainLinearUnderConcurrency`, `TestPostedJournalIsImmutable` |
| Transactional outbox written with every command; content immutable; API role cannot mark rows sent (separate `serk_publisher` role) | ✅ | ✅ | n/a | ✅ | ✅ | — | — | `TestHappyPathPostsAndBalancesAccounts`, `TestOutboxAndPeriodsCannotBeTamperedByAppRole` |
| Outbox **relay / broker delivery** (NATS JetStream) | ✅ | ❌ | — | — | — | — | — | `PendingOutbox`/`MarkPublished` exist; no relay process yet (NEXT #1) |
| Idempotent commands: atomic `ON CONFLICT` reservation, creator-scoped canonical hash, concurrent identical retries replay, reversal retries replay | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestIdempotentReplayAndConflict`, `TestConcurrentIdenticalCreatesAreIdempotent`, `TestReversalFlow` |
| RBAC + project ABAC + segregation of duties (preparer≠approver always, also a DB CHECK; poster≠approver≠preparer in strict mode) | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `pkg/auth`; `TestSegregationOfDuties`, `TestProjectAttributeRestriction` |
| EVM nominal & constant-price with basis guard and zero-denominator policy; cost-to-cost progress | ✅ | ✅ | ✅ | — | — | — | — | `pkg/evm`, 4 tests |
| Effective-dated, jurisdiction-scoped tax rules (VAT net/gross, WHT thresholds, exemptions, recoverability); ambiguity is an error | ✅ | ✅ | ✅ | — | — | — | — | `pkg/tax`, 6 tests. **Rules are data; no real rate is shipped.** |
| REST API v1 (journals lifecycle, FX snapshots/convert), OpenAPI 3.1 contract, identifier-stripped error messages | ✅ | ✅ | — | ✅ | ✅ (auth, alg=none, tamper, oversize, strict JSON, rate limit, headers) | ✅ (binary smoke test) | — | `api/openapi.yaml`; `internal/httpapi` 6 tests |
| Authentication: HS256 bearer tokens, constant-time verify | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `TestTokenRejections` |
| **OIDC / OAuth 2.0 federation, MFA, revocation** | ✅ | ❌ | — | — | — | — | — | `TokenVerifier` interface is the seam (NEXT #2) |
| Migrator with checksum-locked history, race-safe; roles separated (owner / `serk_api` / `serk_publisher`) | ✅ | ✅ | — | ✅ | — | ✅ (binary, idempotent re-run) | — | `cmd/serk-migrate` |
| Containers (distroless, non-root), compose, CI with govulncheck | ✅ | ✅ | — | — | — | ❌ not executed in this delivery (no Docker/CI in build sandbox) | — | `deploy/`, `.github/workflows/ci.yml` |
| **Inflation (IAS 29) restatement** | ✅ (formulas; basis guard implemented) | ❌ | — | — | — | — | — | NEXT #13 |
| **Cross-border logistics, customs, demurrage, trade-bloc packages** | ✅ (entity list in spec) | ❌ | — | — | — | — | — | NEXT #12 |
| **BOQ, procurement, inventory, payroll, contracts, BIM, scheduling, WIP close process** | partial | ❌ | — | — | — | — | — | NEXT #6–10 |
| **Offline field edge (SQLite, op-log, CRDT for mergeable data)** | ✅ (LAW 05 boundary honoured: server-only authoritative commits) | ❌ | — | — | — | — | — | NEXT #11 |
| **AI advisory layer** | ✅ (LAW 02 boundary: outbox → read projection) | ❌ | — | — | — | — | — | NEXT #14 |
| **React/TypeScript web ERP, Flutter field app** | ❌ | ❌ | — | — | — | — | — | NEXT #15 |
| **Workflow engine (BPMN), dynamic configuration** | ❌ | ❌ | — | — | — | — | — | NEXT #16 |
| **OpenTelemetry tracing/metrics** | ✅ | ❌ (structured JSON logs + request ids only) | — | — | — | — | — | NEXT #3 |

## Test evidence (this delivery, fresh database, `-race`)

```
pkg/money    7 tests   PASS
pkg/fx       9 tests   PASS
pkg/ledger   6 tests   PASS
pkg/auth     4 tests   PASS
pkg/evm      4 tests   PASS
pkg/tax      6 tests   PASS
internal/kernel   19 integration/adversarial tests  PASS   (PostgreSQL 16.15, app role under RLS)
internal/httpapi   6 tests (4 e2e over httptest + real DB) PASS
go vet ./...  clean     gofmt  clean
```

## Not claimed

- No capability above is **production-release approved**. Gates still open:
  strong tenant isolation (NEXT #0), OIDC + MFA, outbox relay, OpenTelemetry,
  backup/restore drill, load test, external penetration test, accounting-policy
  sign-off by a qualified accountant for the FX/IAS 21 treatment, and a
  tax-rule dataset reviewed per jurisdiction.
- `go.sum` is not in the tree: the build sandbox reaches `golang.org/x/*` only
  through GitHub mirrors, so the recorded hashes would be wrong. Run
  `go mod tidy` once on a machine with normal module-proxy access and commit the
  result before the first CI run. Until then `make vet`/`make build` outside
  the sandbox fail with "missing go.sum entry".
- Docker build and the GitHub Actions workflow have not been executed.
