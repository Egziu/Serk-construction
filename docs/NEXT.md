# Next implementation sequence

Ordered so that each step is a complete, testable vertical slice building on
the previous one. Estimates are engineering effort for a focused team of
2–3 engineers and assume the kernel in this release is the base.

| # | Slice | Scope | Done when |
|---|---|---|---|
| 0 | **Strong tenant isolation** | Implement DEDICATED_DB mode in `postgres.Store` (DSN per tenant from a routing table) and, for SHARED mode, per-tenant login roles with policies keyed on `current_user` instead of a settable GUC; revoke `set_config` reliance. | A test that calls `set_config('app.tenant_id', other)` as the app role still sees zero foreign rows. |
| 1 | **Outbox relay + NATS JetStream** | `cmd/serk-relay`: poll `outbox` with `FOR UPDATE SKIP LOCKED`, publish with event_id as the dedup key, mark published; consumer library with idempotent handler contract. | Event delivered at-least-once in a kill -9 test; no duplicates processed by the idempotent consumer. |
| 2 | **OIDC / OAuth 2.0 + MFA** | `JWKSVerifier` (RS256/ES256, key rotation, `kid`), implement `TokenVerifier`; enforce `amr` contains MFA for `journal.post`, `period.close`, `fx.manage`. | Login via a real IdP (Keycloak in compose); posting rejected without MFA claim. |
| 3 | **OpenTelemetry** | Traces across HTTP → kernel → pgx (pgx tracer), metrics for command latency and outbox lag, logs correlated by trace id. | Grafana/Tempo dashboards in `deploy/observability/`. |
| 4 | **Chart of accounts + fiscal period API** | CRUD endpoints with `account.manage` / `period.close`; period close is a two-person command. | Closing blocks posting (already enforced in DB) and is itself audited. |
| 5 | **Trial balance, GL drill-down, account statements** | Read models (SQL views) over posted journals, presentation-currency translation using `fx.Select` with `CLOSING` rate type. | Trial balance sums to zero for every tenant in a property test. |
| 6 | **AP: supplier invoices → journals** | Suppliers, invoices (multi-currency), VAT/WHT via `pkg/tax`, three-way match stub, payment commands; each invoice posts through the kernel. | Invoice in CNY posts an ETB journal with snapshot-bound lines and WHT credit. |
| 7 | **IAS 21 period-end remeasurement job** | Deterministic job that proposes a remeasurement journal per monetary account using `fx.Remeasure`; human approve/post. | Gain/loss journal reproducible from stored inputs. |
| 8 | **Projects, WBS/cost codes, budgets, commitments** | Budget control at posting (soft/hard limits per cost code), EVM read model feeding `pkg/evm`. | CPI/SPI dashboard per project from posted data. |
| 9 | **BOQ + measurement sheets** | Deterministic quantity calc with unit/dimension registry, model-revision provenance, interim payment certificates generating journals. | IPC → journal → AR invoice end-to-end. |
| 10 | **Inventory + site stores** | Stock ledger (FIFO/weighted average, exact decimal), issues to cost codes, GRN from logistics. | Stock value reconciles to GL inventory account. |
| 11 | **Offline field edge** | Flutter app + SQLite, versioned operation log, server replay through the idempotent command path (LAW 05); CRDTs only for daily-log text/photos. | 48-hour offline capture replays with zero duplicate financial effects. |
| 12 | **Logistics & customs** | Corridor/shipment entities from §3.4, demurrage/detention/storage engines, duty assessment via `pkg/tax` rules, trade-bloc eligibility matrix as data. | Djibouti–Mekelle shipment costed into inventory. |
| 13 | **IAS 29 engine** | Index registry, monetary/non-monetary classification, policy flag per entity (never automatic), restated management views labelled by basis. | Restatement reproducible; statutory and management views never mixed (basis guard). |
| 14 | **AI advisory layer** | Python workers consume outbox → read projections; forecasts/risk simulations stored as *advisories* with explanations; UI surfaces them as proposals requiring a new authorised command. | No write path from AI to kernel exists (verified by role grants and tests). |
| 15 | **Web ERP (React/TS)** | Journal workbench, approvals inbox, FX desk, project cost dashboard; TanStack Query against `api/openapi.yaml` generated client. | Accessibility audit (WCAG 2.2 AA) passes. |
| 16 | **Workflow + dynamic configuration** | BPMN approval chains per tenant, custom fields on journals/projects as JSONB with schema validation. | Approval chain change is versioned and audited. |
| 17 | **Production gates** | Backup/PITR drill, load test (≥ 500 journal posts/s on a 4-vCPU DB), external pen-test against ASVS L2, accountant sign-off, DR runbook. | Gate report filed in `docs/release/`. |
