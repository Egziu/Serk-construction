# Baseline — what was received and what it actually did

Recorded 2026-10-21 before any remediation, from the supplied package.

## Inputs
| Item | SHA-256 |
|---|---|
| `SERK_Construction_Engineering_Agent_Package.zip` | `913f68c3dfdcd88e0e9116c8a573691b7f7f7f1f3d974ff7bc0d7d2a7d2fde3a` |
| `02_Source/serk-construction-0.1.0.zip` (= commit `a754814`) | `8cbb520d3134b997d48a6f500094f62d0f83996f756687c41ea91e30e985231d` |

Commit `a754814` — 45 files, 7,152 lines: Go module
`github.com/serk-group/serk-construction`, migration `0001_kernel.sql`,
`cmd/serk-api`, `cmd/serk-migrate`, packages `money`, `fx`, `ledger`, `auth`,
`evm`, `tax`, `internal/kernel`, `internal/store/postgres`, `internal/httpapi`,
`deploy/` (compose, Dockerfile, roles), CI workflow, OpenAPI 3.1, docs.

## Tooling used for every result in this repository
- Go 1.24.7 linux/amd64 · PostgreSQL 16.15 (Ubuntu build), local cluster, unix socket
- Dependencies: pgx/v5 5.7.2, shopspring/decimal 1.4.0, google/uuid 1.6.0 (+ indirect x/crypto 0.31.0, x/sync 0.10.0, x/text 0.21.0, puddle 2.2.2)
- Not available in this environment: Docker, GitHub Actions runners, `proxy.golang.org`/`sum.golang.org` (blocked by the sandbox network allowlist)

## Baseline build and tests (v0.1.0, untouched)
- `go.sum` was **absent**; `go build` failed with "missing go.sum entry" under
  `-mod=readonly`. The baseline run therefore used a temporary `go.work`
  outside the repository (recorded, not committed).
- `go vet ./...` clean, `gofmt` clean.
- **61 tests, all PASS** against a fresh PostgreSQL 16 database, `-race`
  (`money` 7, `fx` 9, `ledger` 6, `auth` 4, `evm` 4, `tax` 6, `kernel` 19
  integration, `httpapi` 6). Full log kept in the working notes.
- **Every test passed while SC-01, SC-02, SC-03, SC-04, SC-05, SC-08 and
  SC-14 were exploitable.** The suite tested the happy paths and the attacks the
  original authors thought of; it did not cover the audit's findings.

## Baseline reproductions (controlled local database)
| Finding | Reproduced? | Evidence |
|---|---|---|
| SC-01 move POSTED line into DRAFT journal | **yes** — `UPDATE 1`; posted journal left unbalanced | `evidence/SC-01-before.txt` |
| SC-04 shared login switches tenant via `set_config` | **yes** — tenant B's secret row read | `evidence/SC-14-SC-04-before.txt` |
| SC-14 sub-minor ETB amount | **yes** — `100.0049` stored | `evidence/SC-14-SC-04-before.txt` |
| SC-08 post/close and withdraw/line races | **yes** — interleavings commit illegal states | `evidence/SC-08-before.txt` |
| SC-02, SC-03, SC-05 | confirmed by code reading and by the new tests failing on the old code paths | test history in `IMPLEMENTATION_LOG.md` |
| SC-06 | confirmed by inspection of `deploy/docker-compose.yml` (published DB port, default passwords, fixed JWT secret) | — |
| SC-12 | confirmed (no `go.sum`) | — |
| SC-07, SC-09, SC-10, SC-11, SC-13 | confirmed by inspection | — |

## Current capabilities at baseline
Journal lifecycle (create/approve/post/reverse) with balance and immutability
triggers, FX snapshots with policy selection (library), hash-chained audit,
transactional outbox (no relay), HS256 tokens, RBAC with SoD, EVM and tax
libraries. No ERP modules (BOQ, procurement, inventory, contracts, schedule),
no UI, no workflow engine, no OIDC/MFA, no relay.
