# Engineering backlog and gap register

Against the Master Engineering Directive (docs/audit, 2026-10-26). States:
**1** verified · **2** implemented, insufficiently tested · **3** partial ·
**4** UI-only/placeholder · **5** disconnected · **6** incorrect · **7** missing ·
**8** blocked by an external dependency.

Production decision: **NOT READY FOR PRODUCTION** (`docs/release/GO_NO_GO.md`).
Nothing below is a human sign-off.

## Inventory and status

| Area (directive phase) | State | Evidence / what is missing |
|---|---|---|
| Tenant isolation, roles, SoD, attested approvals (3.2, 14.1, 14.2) | 1 | RLS on every table; `gate_a_tenancy_test`, `review*` probes; isolated signer in staging |
| Ledger, periods, reversals, FX (5.3) | 1 | Balanced journals, period gates, SC-09 price basis, reconciliations; 0 differences in journeys A–C |
| Budget vs commitment vs actual (5.1, 5.2) | 3 | Approved BOQ budget, commitments, receipts, invoices, posted actuals; **missing**: budget revisions/transfers, contingency, original-vs-revised versions |
| Cash-flow forecast (5.4) | 3 | 90-day outlook from approved invoices and ledger cash (`CashOutlookOf`); **missing**: payroll, taxes, supplier schedules, confirmed-vs-forecast ledger |
| Profitability and forecast final cost (5.5) | 3 | Posted margin; EAC/ETC/VAC from EVM; **missing**: phase/work-package/client/portfolio roll-ups, scenario analysis |
| Financial control dashboard (5.6) | 3 | Risks page + Control review; **missing**: one KPI board with drill-down to transactions |
| Procure to pay (6.1, 6.3) | 1 | PR→RFQ→quotes→award→PO→GRN→3-way match→dual approval→release→bank reconciliation; duplicate invoice and near-threshold flags |
| Inventory (6.2) | 3 | FIFO/WAC, transfers, counts, GL reconciliation; **missing**: reservations, batches/serials, reorder points (rule `stock_below` is a stand-in), returns, unit conversions |
| Contracts, variations, IPC, retention, advances (7) | 1 (B) / 3 | Journey B complete; **missing**: claims, extensions of time, notices, LDs, subcontracts, expiry alerts |
| Scheduling (4.3) | 3 | CPM (FS/SS/FF/SF, lags, calendars), baselines, progress, EVM; **missing**: constraints, resources, multiple baselines comparison, recovery scenarios |
| Progress measurement (4.4) | 3 | Approved progress reports and measurements; **missing**: weighted milestones, installed-quantity methods |
| Project lifecycle, phases, stage gates (4.1) | 7 | Projects exist as references only |
| WBS (4.2) | 3 | Versions, nodes, cost codes; **missing**: multi-level roll-up validation, responsibility |
| Document control, RFIs, transmittals (8, 8.1) | 7 | — |
| BIM / IFC (8.2) | 7 | — |
| Field capture, offline sync (9) | 1 | Site diaries, devices, idempotent sync with conflict detection (0037) |
| Workforce / payroll (10.1) | 7 | — |
| Equipment (10.2) | 7 | (diary equipment hours only) |
| Quality (10.3), Safety (10.4) | 7 | — |
| Assistant (11.1) | 2 | Deterministic intent router over computed facts with sources, freshness, assumptions, missing data; optional model phrasing guarded against invented numbers. **Unverified:** no live model endpoint reachable from the build environment |
| Predictive intelligence (11.2) | 3 | Rule-based assessments (SPI/CPI/EAC, budget consumption, overdue POs, cash, controls) recorded as snapshots so a model can later be compared to this baseline. No ML (no outcome history yet) |
| Document intelligence / OCR (11.3) | 7 | — |
| AI security (11.5) | 1 | Model receives only permission-filtered facts, no tools, no secrets; numbers verified; AI principals cannot decide |
| Localisation (12) | 3 | ETB, FX policies, VAT per policy, Ethiopic in exports and fonts; locale stored; **missing**: translated interface, withholding rules, statutory reports |
| Role workspaces, command centre (13) | 3 | My work queues, bell, risks; **missing**: global search, saved filters, templates |
| Security review (14) | 3 | 12 independent reviews resolved; export budget, watermark, access events; **blocked**: external pentest, real IdP, HSM signer, vault, PITR offsite (see GO_NO_GO) |
| Integrations (15) | 7/8 | Outbox relay with webhooks exists; no accounting/bank/payment provider connected (no sandbox credentials) |
| Reports (16) | 3 | 11 of 25 listed reports exist (trial balance, AP/AR aging, reconciliations, cost, EVM, stock, journals, risk register, control review, recent activity) |
| Database integrity, performance (17) | 2 | Constraints, RLS, idempotency; **missing**: load tests beyond the review-9 abuse test, index review on large data |
| Automated testing (18) | 1 | Race suite on fresh databases, browser journeys A–C, planning, site; security probes |
| Performance testing (18.5) | 7 | Not done at scale |
| Operational readiness (19 E) | 8 | Backups, monitoring, alerting, restore drill: documented, not operated |

## Prioritised next work

| # | Item | Severity | Acceptance |
|---|---|---|---|
| 1 | Budget revisions and transfers with approval; original vs current approved budget | High (financial) | Cost report shows both; revision needs attestation; tests |
| 2 | Financial control dashboard with documented KPI formulas and drill-down | High | Every KPI traces to a report row and then to documents |
| 3 | Document control: numbered documents, revisions, supersession, RFIs | High (missing module) | Superseded never shown as current; tests |
| 4 | Equipment and job cost (GATED-03), QHSE (GATED-04) | Medium | Modules with maker/checker and ledger links |
| 5 | Cash forecast: payroll/tax/supplier schedules; confirmed vs forecast | Medium | Outlook distinguishes confirmed from forecast |
| 6 | Interface translation (am, ti) with canonical data untouched | Medium | Language switch without data loss |
| 7 | External items: IdP with step-up, HSM signer, vault, PITR, pentest, load test | Blocked | Named humans and infrastructure |
