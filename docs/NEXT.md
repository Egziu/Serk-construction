# Next implementation sequence (after Gate A)

Gate A (security and accounting integrity) items are in
`docs/audit/ISSUE_REGISTER.md`; the two still PARTIAL there (SC-11, SC-12)
come first because they gate any staging deployment. Each later slice is a
vertical slice (schema + invariants in PostgreSQL + kernel commands + API +
workflow subjects/effects + tests + UI) and is not started until the
previous one's tests pass.

| # | Slice | Done when |
|---|---|---|
| 0 | **Close SC-12 / execute CI** — run `.github/workflows/ci.yml` on GitHub (go.sum re-derivation vs `sum.golang.org`, govulncheck, SBOM, Docker build, integration suite on `postgres:16`). | CI green; the four unverified `go.sum` hashes match; image digest recorded. |
| 1 | **Staging deployment + operations (SC-11)** — production compose on a staging host with a real IdP (Keycloak/Entra), TLS, secrets; OpenTelemetry traces/metrics (command latency, outbox lag, workflow overdue); session revocation (token `jti` deny-list); backup + PITR restore drill with a recorded RTO/RPO. | Staging runbook executed end-to-end; restore drill report filed in `docs/release/`. |
| 2 | **Workflow hardening** — delegation/out-of-office with SoD carried to the delegate; business calendars for SLAs; idempotency keys on start; signed decision assertions so the database can verify decider identity (THREAT_MODEL T-3a); designer/console web screens. | Delegated approval cannot satisfy SoD the delegator could not; forged decision without a valid assertion refused by SQL. |
| 3 | **Chart of accounts, fiscal calendar, trial balance, GL drill-down** (read models over posted journals). | TB sums to zero per entity in a property test; drill-down reaches every source line. |
| 4 | **ERP-01 BOQ + estimating** — versioned BOQ hierarchy on the WBS/cost codes from SC-10, unit/dimension registry, measurement sheets, approved baseline via a mandatory workflow. | Measurement → budget traceable; unapproved BOQ never changes the baseline. |
| 5 | **ERP-02 Procurement → AP** — requisition → RFQ → award (workflow) → PO → GRN → invoice → three-way match → AP journal through the kernel → payment *instruction* (human-released, never automatic). | First required business workflow (master prompt Stage 7) passes end-to-end with reconciled ledger. |
| 6 | **Inventory / site stores** — stock ledger (exact decimal, FIFO/WAC), issues to cost codes. | Stock value reconciles to the GL inventory account. |
| 7 | **ERP-03 Contracts / IPC** — measurement → engineer approval → IPC (workflow) → AR → settlement, retention, advances. | Second required business workflow passes end-to-end. |
| 8 | **ERP-08 Web UI** — approvals inbox (workflow tasks), journal workbench, FX desk, BOQ, procurement, IPC; permissions from the backend. | Key journeys usable without raw API; WCAG 2.2 AA checks. |
| 9 | ERP-04 scheduling/CPM · ERP-05 offline field app · ERP-07 quality/HSE · ERP-06 BIM/IFC · logistics/customs · payroll · IAS 29 | per master prompt gates D–E. |
| 10 | **ERP-09 governed AI** — advisory only, consumes outbox projections; no workflow effect or kernel command reachable from an AI principal. | Verified by role grants and tests. |
| 11 | **Production gates** — load test, external penetration test (ASVS L2), accountant sign-off on FX/IAS 21 policy content, tax-rule dataset review per jurisdiction, DR runbook. | Gate report signed by the named human approvers. |
