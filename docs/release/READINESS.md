# Release readiness — gate results

Values: **PASS** (evidence attached) · **FAIL** · **BLOCKED** (cannot be
executed here; blocker named) · **NOT TESTED**. Nothing is assumed PASS.
Production deployment, tax/financial treatment, customer data migration and
real-money operations require named human approvals that have **not** been
given.

## Gate A — Security and accounting integrity

| Check | Result | Evidence |
|---|---|---|
| SC-01, SC-02, SC-03, SC-04, SC-05, SC-08, SC-14 reproduced before, refused after | **PASS** | `docs/audit/evidence/*-before.txt`, `GATE-A-after.txt`, `TestSC0*`, `TestSC14_*` |
| SC-06 production configuration refuses demo defaults | **PASS** (unit level) | config tests |
| SC-06 production compose actually starts with TLS, secrets, no exposed DB | **BLOCKED** — no Docker in this environment | — |
| SC-07, SC-09, SC-10, SC-13 | **PASS** | register |
| SC-11 relay, OIDC verifier, MFA step-up, workflow engine | **PASS** | register |
| SC-11 staging end-to-end acceptance, session revocation, telemetry, backup/PITR drill | **NOT TESTED** (not built) | NEXT #1 |
| SC-12 cold build and tests with pinned dependencies (`-mod=readonly`, empty module cache, no `go.work`) | **PASS** | command below |
| SC-12 `go.sum` hashes verified against `sum.golang.org`; CI run; govulncheck; SBOM | **BLOCKED** — sandbox network allowlist excludes `proxy.golang.org`/`sum.golang.org`; no CI runner | CI job defined |
| Controlled-approval workflow engine: governed definitions, DB-enforced trail, mandatory gates, timers | **PASS** | `TestWorkflow_*` (11), `TestReview_*` (10), `TestReverify_*` (7), validator (2), examples (1), API (1); mutation tables in IMPLEMENTATION_LOG |
| Independent adversarial review of the workflow engine (two rounds) | **PASS** — 9 + 6 defects found, all fixed with regression tests that fail on the pre-fix commits | IMPLEMENTATION_LOG §9, §10 |
| Advisory-lock / TEMP restriction when migrations run as a non-superuser | **NOT TESTED** (test cluster runs migrations as superuser) | `deploy/02-restrict-advisory-locks.sql` |

**Gate A overall: NOT PASSED** — SC-11 and SC-12 remain PARTIAL and the
deployment profile has not been executed. The financial-integrity, privilege
and tenant-boundary findings (the part of Gate A that blocks new modules) are
closed with evidence; module work may begin on this foundation while the
operational items proceed in parallel.

## Gates B–F

| Gate | Result |
|---|---|
| B — Core ERP (BOQ, procurement/AP, inventory, contracts/IPC, UI) | **NOT TESTED** — not built |
| C — Required business workflows (BOQ→purchase→GRN→invoice→payment controls→ledger; measurement→IPC→AR→settlement) | **NOT TESTED** — not built |
| D — Field and operational execution | **NOT TESTED** |
| E — BIM/logistics/payroll | **NOT TESTED** |
| F — Governed intelligence | **NOT TESTED** |

## Test run recorded for this release

```
GOWORK=off GOFLAGS=-mod=readonly GOSUMDB=off GOPROXY=file://<local module mirror> GOMODCACHE=<new empty dir>
go clean -cache && gofmt -l . && go vet ./...
SERK_TEST_ADMIN_DSN='postgres://postgres@/serk_final?host=/tmp&port=5433' go test -race -count=1 -p 1 -v ./...
```

Go 1.24.7 · PostgreSQL 16.15 · fresh database · exit status 0 ·
**126 tests passed, 0 failed, 0 skipped**:

```
internal/config    ok     internal/httpapi  ok     internal/kernel  ok
internal/relay     ok     pkg/auth          ok     pkg/evm          ok
pkg/fx             ok     pkg/ledger        ok     pkg/money        ok
pkg/tax            ok     pkg/workflow      ok
```

The same suite also passes with packages in parallel (CI mode, no `-p 1`)
and the timing-sensitive tests passed 5 consecutive repetitions.
