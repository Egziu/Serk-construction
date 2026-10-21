# SERK Construction — Financial Kernel + Controlled-Approval Workflow (0.2.0-gate-a)

Africa-first construction ERP, built on a **deterministic financial core**:
exact-decimal money, policy-bound FX, balanced and immutable journals,
database-enforced tenant identity, a hash-chained audit log, a transactional
outbox with a relay, and a **workflow engine in which automation routes and
escalates but only people authorize**. No AI component sits in the
transaction path.

This branch is the Gate A remediation of release 0.1.0: every audit finding
SC-01…SC-14 was reproduced, fixed and covered by regression tests before any
new ERP module (BOQ, procurement, inventory, contracts) was started, so those
modules inherit a sound financial and security foundation.

Start with: `docs/release/READINESS.md` (gate results — what passed, what is
not tested), `docs/audit/ISSUE_REGISTER.md` (every finding, fix, test,
residual risk), `docs/architecture/THREAT_MODEL.md`, ADRs in `docs/adr/`.

## Layout

```
cmd/serk-api          HTTP API; runs workflow timers when SERK_SCHEDULER_DSN is set
cmd/serk-migrate      checksum-locked migrator; `provision-tenant` creates a tenant + its DB role
cmd/serk-relay        outbox → signed webhook relay (ordering, retries, dead-letter, `replay`)
cmd/serk-devtoken     HS256 tokens for development/staging only (refuses production)
pkg/money             exact decimal money, ISO 4217 registry, rounding, allocation
pkg/fx                FX snapshots, policies, selection, conversion, IAS 21 remeasurement
pkg/ledger            accounts, journals, invariants, state machine, reversals
pkg/auth              RBAC, explicit project scope, SoD, step-up MFA
pkg/workflow          workflow definitions: strict parser, control-invariant validator, routing, dry run
pkg/evm               EVM with price-basis rules (nominal / constant), provenance
pkg/tax               effective-dated jurisdiction tax rules — data, not code
internal/store/postgres   migrations 0001–0006, repositories, tenant Router
internal/kernel       commands: authorise → validate → ACID commit → audit → outbox; workflow engine
internal/httpapi      hardened REST API, OIDC/JWKS + HS256 verifiers, abuse controls
internal/relay        relay and webhook signing/verification
internal/config       fail-closed runtime configuration
api/openapi.yaml      v1 contract (0.2.0)
deploy/               Dockerfile, dev and production compose, cluster roles, Caddy TLS proxy
docs/                 audit register, baseline, implementation log, readiness, threat model, ADRs
```

## Run the tests (the only claims this README makes are those the tests prove)

```bash
# A disposable PostgreSQL 16 database whose login can CREATE ROLE:
export SERK_TEST_ADMIN_DSN='postgres://postgres@/serk_test?host=/tmp&port=5432'
go vet ./...
go test -race -count=1 -p 1 ./...
```

The integration suites attack the database directly with raw SQL as a
tenant's own login and as the schema owner, race concurrent transactions at
controlled points, and drive the API over HTTP. `docs/audit/evidence/` holds
before/after transcripts of the audit's attacks.

## Run locally (development profile)

```bash
make dev-up        # PostgreSQL 16 (127.0.0.1 only), migrations, API with dev-only secrets
SERK_DB=postgres://postgres:dev-only-postgres-password-not-for-production@localhost:5432/serk_construction?sslmode=disable
SERK_ADMIN_DSN=$SERK_DB SERK_TENANT_DB_SECRET=dev-only-tenant-db-secret-0123456789abcdefABCDEF \
  go run ./cmd/serk-migrate provision-tenant --tenant <tenant-uuid> --name "Demo Contractor PLC"
SERK_ENV=development SERK_TOKEN_SECRET=dev-only-hs256-token-secret-0123456789abcdefABCDEF \
  go run ./cmd/serk-devtoken --sub alice --tenant <tenant-uuid> --roles accountant
```

The development compose file uses published, well-known secrets and is
refused by the API outside `SERK_ENV=development`. If migrations do not run
as a PostgreSQL superuser, run `deploy/02-restrict-advisory-locks.sql` as a
superuser afterwards (tenant logins must not hold advisory locks or create
temporary objects). Production uses
`deploy/docker-compose.prod.yml` (secrets from files, internal database
network, TLS proxy, OIDC required) — **not yet executed in this environment**.

## What the kernel guarantees (each item has a test; see ISSUE_REGISTER)

- A journal reaches POSTED only if it balances, uses whole minor units of
  each currency, binds every FX line to an approved rate that the entity's
  approved FX policy selects for the business-event time (re-checked at post),
  was approved by someone other than the preparer, is unchanged since
  approval, and an OPEN period covers its date — checked in Go and again by
  PostgreSQL at COMMIT, with locks that make close/post and withdraw/line
  races serialise.
- Posted history cannot be altered by any application login; even the schema
  owner is stopped by triggers (only disabling triggers bypasses them, which
  the integrity scan and audit chain detect).
- A tenant's database login can see and change only that tenant's rows, even
  when running arbitrary SQL; the tenant is derived from the login, not from a
  settable variable.
- FX rates, rate sources, FX policies, WBS versions and workflow definitions
  are maker/checker; out-of-tolerance rates and definition publishing need a
  fresh MFA.
- Every command writes its audit entry and outbox event atomically; the relay
  delivers in per-aggregate order with retries, dead-lettering and replay.

## Controlled-approval workflows

Definitions (JSON, versioned) declare steps, permissions, quorums, SoD rules,
MFA, amount thresholds, SLA escalation, expiry and compensation. The
validator refuses definitions that would weaken controls. A step's effect
(approve/post a journal, approve/reject a rate, close a period) runs as the
person who completed the step, through the same kernel command the API uses.
When a definition is published as **mandatory**, the database refuses the
subject's sensitive transition unless the same transaction recorded the
workflow effect, which in turn requires the step's quorum of distinct,
SoD-eligible approvers. Console API: tasks, instances, history, metrics,
dry-run simulation. See ADR 0007.

## Not built yet

BOQ/estimating, procurement → AP, inventory, contracts/IPC, scheduling, site
diary, offline field app, BIM, payroll, logistics/customs, reports, web UI,
AI advisory layer, OpenTelemetry, backup/PITR drill, session revocation.
`docs/NEXT.md` is the ordered sequence.

## Licence

Proprietary — SERK Technologies Group.
