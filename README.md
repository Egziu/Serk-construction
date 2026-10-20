# SERK Construction — Financial Kernel (release 0.1.0)

Africa-first construction ERP, built on a **deterministic financial core**:
exact-decimal money, policy-selected FX snapshots, balanced and immutable
journals, tenant isolation enforced by PostgreSQL row-level security, a
hash-chained audit log and a transactional outbox. No AI component sits in the
transaction path (LAW 01/02 of SERK-CONSTRUCTION-MASTER-2026).

This release is the **first vertical slice**: the kernel every later module
(BOQ, procurement, payroll, logistics, BIM cost allocation) posts through.
`docs/STATUS.md` states precisely what is implemented, tested and still open;
`docs/NEXT.md` is the ordered implementation sequence.

## Layout

```
cmd/serk-api          HTTP API binary (+ `token` dev sub-command)
cmd/serk-migrate      checksum-locked SQL migrator
pkg/money             exact decimal money, ISO 4217 registry, rounding, allocation
pkg/fx                FX snapshot model, selection policy, conversion, IAS 21 remeasurement
pkg/ledger            accounts, journals, invariants, posting state machine, reversals
pkg/auth              RBAC, project ABAC, segregation of duties
pkg/evm               nominal / constant-price EVM, cost-to-cost progress
pkg/tax               effective-dated jurisdiction tax rules (VAT, WHT, …) — data, not code
internal/store/postgres   migrations (RLS, triggers, audit chain, outbox), repository
internal/kernel       command service: authorise → validate → ACID commit → audit → outbox
internal/httpapi      hardened REST API, token verification, rate limiting
api/openapi.yaml      v1 contract
deploy/               Dockerfile (distroless), docker-compose, DB roles
docs/                 STATUS (LAW 08 register), NEXT, SECURITY (ASVS map), ADRs
```

## Run locally

```bash
make db-up                      # PostgreSQL 16 + application roles
make migrate                    # apply migrations as the schema owner
export SERK_TOKEN_SECRET=$(openssl rand -hex 32)
make run                        # API on :8080 as the RLS-constrained serk_api role
```

Mint a token and post a journal (see `api/openapi.yaml` for the full contract):

```bash
TENANT=<uuid of a tenant row>
TOK=$(go run ./cmd/serk-api token --sub alice --tenant $TENANT --roles accountant)
curl -X POST localhost:8080/v1/journals -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d @journal.json
```

Lifecycle: `POST /v1/journals` (accountant) → `/approve` (finance_manager, must
differ from preparer) → `/post` (controller, must differ from both in strict
mode) → `/reverse` creates a draft compensating journal that follows the same
path and marks the original `REVERSED` when it posts.

## Test

```bash
make test-unit                  # pure domain packages, race detector
make test-integration           # real PostgreSQL: RLS, triggers, audit chain, API e2e
```

The integration suite includes adversarial tests that bypass the Go layer with
raw SQL and confirm the database still refuses unbalanced postings, tampering
with posted rows, cross-tenant writes and postings into closed periods.

## Guarantees in this release

- A journal reaches `POSTED` only if it balances, every line is positive, in
  the legal entity's functional currency (enforced by foreign key), on an
  active account of that entity, an approver ≠ preparer approved it, its
  content is byte-identical to what was approved (lines frozen at APPROVED,
  command hash re-checked at post), and an OPEN fiscal period covers its
  business-event date — checked in Go and again by PostgreSQL at COMMIT.
- Approved and posted journals and their lines cannot be updated or deleted
  by any role the application uses; corrections are reversals, and a journal
  can only be marked REVERSED by a POSTED reversal whose lines mirror it
  exactly (validated by trigger).
- Every command writes an audit row and an outbox event in the same
  transaction. The audit chain is computed in-database under a per-tenant
  row lock, is linear under concurrent load (tested with 80 parallel
  commands), and the API role cannot update the outbox or the chain head.
- A foreign-currency line must reference an APPROVED snapshot of the pair
  `txn_currency/functional_currency` (or its inverse); the kernel checks
  `amount = round_half_even(txn_amount × rate)`, stores the applied rate on the
  line, and the database re-checks pair, approval and reconciliation; a
  referenced snapshot can no longer be withdrawn. `/v1/fx/convert` uses only
  APPROVED rates valid at the event time and published before the knowledge
  cutoff; a missing rate is an explicit error, never a fabricated one.
- Identical command retries — including concurrent ones — return the original
  journal; the same key with a different payload or a different user is a 409.
- Row-level security confines every statement to the tenant bound in the
  transaction and refuses rows that claim another tenant. **Scope:** this
  protects against application defects and limits a compromised request to one
  tenant; it is not a boundary against an attacker who can execute arbitrary
  SQL as the application role (that role can call `set_config`). Tenants that
  need that guarantee use the DEDICATED_DB mode (NEXT #0).

## Not in this release

OIDC/MFA, outbox relay, OpenTelemetry, IAS 29 restatement, logistics/customs,
BOQ/procurement/inventory/payroll, offline field app, AI advisory layer, web
UI, BPMN workflow. See `docs/NEXT.md` for the sequence and `docs/STATUS.md`
for the evidence-backed register.

## Licence

Proprietary — SERK Technologies Group.
