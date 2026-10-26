# SERK Construction OS — module map and maintenance guide

SERK Construction OS is the product (the vendor). Each construction company
that uses it (for example Senselet Construction PLC) is a **tenant**: its own
database role, its own rows under row-level security, its own portal
settings, its own rules. The vendor has no row in any tenant.

## Layers (one direction of dependency: top depends on bottom)

| Layer | Package | Rule |
|---|---|---|
| Console | `internal/webui` (static SPA, no framework) | Holds no authority. Every action is an API call. |
| HTTP API | `internal/httpapi` | Authentication, rate limits, decoding, mapping errors. No business rules. |
| Kernel | `internal/kernel` | Every business command and read. Permission + scope + SoD checks first, then one tenant transaction. |
| Store | `internal/store/postgres` | SQL only. Migrations in `migrations/` (additive, never edited once committed). |
| Pure packages | `pkg/*` | No I/O: money, ledger, fx, tax, evm, schedule, workflow, attest, auth, datakey, automation. |
| Formats | `internal/export` | PDF/DOCX/XLSX writers, stdlib only. |
| Adapters | `internal/aiphrase`, `internal/relay` | Outside systems, each behind an interface with a fake in tests. |

The database is the last line of defence: triggers re-verify attested human
decisions, immutability of posted records, period rules and tenant isolation
even if the kernel is bypassed (`review*_regression_test.go` prove it).

## Modules

| Module | Kernel file(s) | Migration(s) | API | Console |
|---|---|---|---|---|
| Ledger, periods, FX | `kernel.go`, `period.go`, `fx.go` | 0001–0004, 0010–0012 | `/v1/journals`, `/v1/periods`, `/v1/fx` | Journals, Reconciliation, Trial balance |
| WBS and cost codes | `wbs.go` | 0005 | (kernel) | Cost report |
| Workflow engine | `workflow.go` | 0006, 0008 | `/v1/workflow/*` | — |
| Approvals (attestations, signer) | `docscope.go`, `pkg/attest` | 0007, 0009, 0010, 0012, 0035, 0036 | — | — |
| Procure to pay (Journey A) | `p2p.go` | 0013–0017, 0032 | `/v1/requisitions … /v1/payments`, `/v1/bank-statements` | Procurement, Payables, Treasury |
| Contract to cash (Journey B) | `contract.go`, `credit.go`, `retention.go`, `variation.go` | 0018–0020, 0022, 0023, 0026, 0033 | `/v1/contracts … /v1/receipts` | Revenue |
| Stock valuation (Journey C) | `stock.go`, `stock_transfer.go` | 0021, 0024, 0025, 0031 | `/v1/stock-*` | Stores |
| Planning and EVM | `schedule.go`, `pkg/schedule`, `pkg/evm` | 0027 | `/v1/schedules`, `/v1/progress`, `/v1/projects/{id}/evm` | Planning |
| Site operations, offline sync | `site.go` | 0037 | `/v1/site/*`, `/v1/sync` | Site |
| Sessions, abuse limits | `sessions.go`, `httpapi/abuse*.go` | 0009, 0029 | `/v1/identity/*` | — |
| Reports and exports | `reports.go`, `internal/export` | — | `/v1/reports/*`, `/v1/export` | Reports, export buttons |
| **Platform** (0038): company settings, notifications, automation rules, intelligence | `platform.go`, `intelligence.go`, `pkg/automation` | 0038 | `/v1/tenant/settings`, `/v1/notifications`, `/v1/automation/*`, `/v1/intelligence/*`, `/v1/assistant/ask` | Company settings, bell, Automation rules, Risks, Ask, Control review |

## Governance invariants (do not break)

1. **No AI principal and no automation decides.** `auth.IsDraftAction` and the
   database's `approval_is_draft_action` reserve every approve/post/pay/release
   to human principals. Automation rules can only notify. The assistant only
   reads.
2. **Maker/checker everywhere**: journals, documents, workflow definitions,
   automation rules (author ≠ activator, enforced by a CHECK constraint).
3. **Additive migrations**: never edit a committed migration; corrections are
   new migrations.
4. **Money is decimal** (`pkg/money`, `shopspring/decimal`, `numeric` in SQL).
5. **Exports show no more than the screen**: `/v1/export` re-issues the read as
   the caller.
6. **Tenant isolation is RLS**, not navigation: every table has
   `tenant_isolation` and the tests in `gate_a_tenancy_test.go` and
   `platform_test.go` prove the boundary.

## How to add a module

1. Migration `NNNN_<name>.sql`: tables with `tenant_id DEFAULT current_tenant()`,
   RLS + `owner_maintenance` policy, `REVOKE ALL … FROM PUBLIC`, explicit
   column-level `GRANT`s to `serk_app`, guard triggers for lifecycle and
   immutability, `search_path` pinned on every function.
2. Store: `internal/store/postgres/<name>repo.go`, SQL only, typed structs.
3. Kernel: `internal/kernel/<name>.go`: permission → scope → `store.WithTenant`
   → audit entry. New permissions in `pkg/auth` with role grants, keeping
   maker/checker pairs on different seed roles.
4. API: `internal/httpapi/<name>_handlers.go` registered from `New()`.
5. Console: a `DOCS` entry (lists, detail, actions) or a page function + nav.
6. Tests: kernel test on a disposable database (`testdb.Setup`), an API test,
   and a regression probe for each guard.
7. Seed: `cmd/serk-seed` for staging data; `docs/BACKLOG.md` status update.

## Operations

- `cmd/serk-api` (API + workers: workflow timers, automation), `cmd/serk-signer`
  (isolated approval key), `cmd/serk-migrate`, `cmd/serk-relay` (outbox),
  `cmd/serk-seed` and `cmd/serk-devtoken` (test environments only).
- Configuration is validated at start (`internal/config`); production refuses
  every test-only setting.
- Deployment: `deploy/Dockerfile` (production, distroless), `deploy/railway/`
  (staging), `deploy/docker-compose.*.yml`.
