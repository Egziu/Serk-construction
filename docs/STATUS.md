# SERK Construction — Delivery Status (LAW 08 register)

**Release:** 0.2.0-gate-a (branch `remediation/gate-a`) · **Date:** 2026-10-21
**Spec:** SERK-CONSTRUCTION-MASTER-2026 v1.0 · audit package v0.1.0

Columns: **A** architecture defined · **C** code implemented · **U** unit tests
pass · **I** integration tests pass (real PostgreSQL 16.15) · **S** security
tested (adversarial raw-SQL / API / concurrency tests) · **O** operationally
validated (deployed and run) · **P** production-release approved. A cell is
never marked further than its evidence. Nothing is **P**. Nothing is **O**
except the local binaries and test database: Docker, CI and a staging
environment have not been executed here.

| Capability | A | C | U | I | S | O | P | Evidence |
|---|---|---|---|---|---|---|---|---|
| Exact-decimal money, ISO 4217 registry, rounding policies, allocation, strict parsing | ✅ | ✅ | ✅ | — | ✅ | — | — | `pkg/money` |
| DB currency minor-unit enforcement (SC-14) | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestSC14_*` |
| Journal lifecycle, balance, immutability, reversals; line identity immutable; OLD+NEW journal checks (SC-01) | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `TestSC01_*`, kernel suites |
| Ledger integrity scan + period close prerequisites + closing TB record; reopen with MFA, reason, SoD | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestSC01_IntegrityScan…`, `TestClosedPeriodBlocksPosting`, workflow close tests |
| FX: trusted sources, versioned entity policies, eligibility at insert and post, maker/checker, variance exceptions with MFA (SC-02, SC-03) | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `TestSC02_*`, `TestSC03_*`, API flow |
| Concurrency of close/post and withdraw/line (SC-08) | ✅ | ✅ | — | ✅ | ✅ (mutation-verified) | — | — | `TestSC08_*` |
| Tenant identity from DB login; Router; dedicated tier (SC-04) | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestSC04_*`, `GATE-A-after.txt` |
| Explicit tenant-wide scope; project ABAC (SC-05) | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `TestScopeSC05`, `TestSC05_*` |
| WBS versions + cost codes, account cost-coding policy (SC-10) | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestSC10_*` |
| EVM v2 with price-basis rules and provenance (SC-09) | ✅ | ✅ | ✅ | — | — | — | — | `TestSC09_*` |
| Hash-chained audit; atomic audit+outbox for every command (SC-07) | ✅ | ✅ | — | ✅ | ✅ | — | — | `TestSC07_*`, `TestAuditChainLinearUnderConcurrency` |
| Outbox relay: leader lock, ordering, backoff, dead-letter, replay, HMAC webhooks, consumer dedupe | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `internal/relay` (5 tests) |
| Authentication: OIDC JWKS (RS256/ES256), MFA from `amr`, `auth_time`, `nbf`; HS256 dev/staging only | ✅ | ✅ | ✅ | ✅ | ✅ | — (no real IdP connected) | — | `TestJWKSVerifier`, `TestIsMFA`, `TestTokenTimeClaims` |
| Pre-auth abuse controls (SC-13) | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | `TestAPIPreAuthFloodProtection` |
| Fail-closed configuration; production compose (SC-06) | ✅ | ✅ | ✅ | — | ✅ | ❌ not executed | — | `internal/config` tests |
| Reproducible build: `go.sum`, pinned CI actions, govulncheck, SBOM (SC-12) | ✅ | ✅ | — | ✅ (cold-cache build+test) | — | ❌ CI not executed | — | `SC-12-gosum-provenance.json` |
| **Controlled-approval workflow engine**: versioned governed definitions, validator, thresholds, quorum, SoD (Go + SQL), MFA steps, effects as the decider, mandatory DB gate, compensation, durable timers, dry run, console API, metrics | ✅ | ✅ | ✅ | ✅ | ✅ (forged-trail attacks, concurrency, mutation-verified) | — | — | `TestWorkflow_*`, `TestValidatorRefusesUnsafeDefinitions`, `TestAPIWorkflowConsole`; ADR 0007 |
| Workflow delegation, business calendars, designer UI | ✅ (ADR 0007 consequences) | ❌ | — | — | — | — | — | NEXT #2 |
| Session revocation, OpenTelemetry, backup/PITR drill (SC-11 remainder) | ✅ | ❌ | — | — | — | — | — | NEXT #1 |
| Tax rules engine (data-driven; **no real rates shipped**) | ✅ | ✅ | ✅ | — | — | — | — | `pkg/tax` |
| BOQ, procurement/AP, inventory, contracts/IPC, scheduling, site, BIM, payroll, logistics (ERP-01…07) | partial | ❌ | — | — | — | — | — | NEXT #4–9 |
| Web UI, field app (ERP-05, ERP-08) | ❌ | ❌ | — | — | — | — | — | NEXT #8–9 |
| AI advisory layer (ERP-09) | ✅ (boundary only) | ❌ | — | — | — | — | — | NEXT #10 |

## Test evidence (fresh database, `-race`, empty module cache, `-mod=readonly`)

See `docs/release/READINESS.md` for the exact command, counts and output.
