# Process catalog: Journey A, procure-to-pay

This catalog covers the business processes that exist and are tested today. Journey B (measurement → IPC → receivable → receipt) and the other modules of the master directive are **not built yet**; they are listed at the end.

Notes on the table below:
- Every step is one API command. The kernel checks permission, project scope and maker/checker. PostgreSQL then enforces the state machine, the numbers and the attestation (ADR 0008, ADR 0009).
- **Screen** is the route in the web console (`/console/`).
- **Event** is the outbox event, written in the same transaction as the audit record.

| # | Step | Who (seed role) | Permission | API | Screen | Database control (refuses when…) | Event / journal |
|---|---|---|---|---|---|---|---|
| 0a | Propose P2P policy (tolerances, VAT rate, thresholds, control accounts) | controller | `p2p.policy.manage` | `POST /v1/p2p/policies` | P2P policies → New | creator not attested; control account is a bank, clearing or PO account; successor changes the GRNI or AP account | `p2p.policy.proposed` |
| 0b | Approve policy (retires the predecessor) | cfo | `p2p.policy.approve` | `POST /v1/p2p/policies/{id}/approve` | policy page | approver = proposer; no attestation | — |
| 0c | Create / approve supplier | procurement_officer / procurement_manager | `supplier.manage` / `supplier.approve` | `POST /v1/suppliers`, `…/{id}/approve`, `…/{id}/block` | Suppliers | creator not attested; approver = creator | `supplier.*` |
| 0d | Add / approve supplier bank account | procurement_officer / finance_manager (MFA) | `supplier.manage` / `supplier.bank.approve` | `POST /v1/suppliers/{id}/bank-accounts`, `/v1/supplier-bank-accounts/{id}/approve` | Supplier banks | creator not attested; approver = creator; no MFA | `supplier.bank_account.*` |
| 0e | Register / approve company bank account | treasury_officer / cfo (MFA) | `bankacct.manage` / `bankacct.approve` | `POST /v1/company-bank-accounts`, `…/{id}/approve` | Company banks | creator not attested; GL account = clearing account or a control account | `company_bank_account.*` |
| 1 | BOQ version: create, submit, approve | estimator / commercial_manager | `boq.manage` / `boq.approve` | `POST /v1/boqs`, `…/submit`, `…/approve`, `…/reject` | BOQ | items changed after DRAFT; approver = author | `boq.*` |
| 2 | Requisition: create, submit | site_engineer | `pr.create` | `POST /v1/requisitions`, `…/submit` | Requisitions → New | cost code not in the approved WBS; lines changed after DRAFT | `pr.*` |
| 3 | Approve requisition | project_manager | `pr.approve` | `…/{id}/approve`, `…/reject` | requisition page | over the BOQ budget for the cost code; approver = requester | `pr.approved` |
| 4 | RFQ: create, issue | procurement_officer | `rfq.manage` | `POST /v1/rfqs`, `…/issue` | RFQs, from the requisition | fewer than the minimum suppliers without a single-source reason; supplier not ACTIVE | `rfq.*` |
| 5 | Record quotes | procurement_officer | `rfq.manage` | `POST /v1/rfqs/{id}/quotes` | Record a quote | quote after the due time; RFQ not ISSUED; recorder not attested | `rfq.quote_received` |
| 6 | Technical evaluation | site_engineer | `rfq.evaluate` | `POST /v1/quotes/{id}/evaluate` | Quotes | evaluator = recorder; non-compliant without a note | — |
| 7 | Award | procurement_manager | `rfq.award` | `POST /v1/rfqs/{id}/award` | RFQ page | non-compliant quote; not the lowest without a 20-character reason | `rfq.awarded` |
| 8 | PO from award | procurement_officer | `po.manage` | `POST /v1/purchase-orders` | Create purchase order | price, quantity or cost code differs from the award; PO line posts to a control account; creator not attested | `po.created` |
| 9 | Approve PO | procurement_manager (cfo with `budget.override` and MFA above budget) | `po.approve` | `…/{id}/approve` | PO page | over budget without override, MFA and reason; approver = creator | `po.approved` |
| 10 | Goods receipt: record, submit | storekeeper | `grn.create` | `POST /v1/goods-receipts`, `…/submit` | Record goods receipt | cumulative receipts above PO quantity + over-receipt tolerance | `grn.*` |
| 11 | Confirm receipt | site_engineer | `grn.confirm` | `…/{id}/confirm` | GRN page | confirmer = recorder; generated journal ≠ expected accounting | `P2P_GRN` journal (Dr cost or inventory / Cr GRNI) |
| 12 | Invoice: enter, submit (three-way match) | ap_clerk | `ap.enter` | `POST /v1/invoices`, `…/submit` | Enter supplier invoice | billed quantity > confirmed receipts; VAT ≠ subtotal × policy rate; duplicate supplier invoice number | `ap.invoice_submitted` |
| 13 | Approve invoice | ap_supervisor (finance_manager with MFA and reason for price exceptions) | `ap.approve` / `ap.approve_exception` | `…/{id}/approve`, `…/reject` | invoice page | exception approved without elevated right, MFA and reason; approver = entering clerk | `P2P_INVOICE` journal (Dr GRNI, price variance, VAT input / Cr AP) |
| 14 | Approve and post subledger journals | finance_manager / controller | `journal.approve` / `journal.post` | `POST /v1/journals/approve-batch`, `post-batch` | Journals | journal content ≠ document accounting (re-checked at approve and post); lines written outside the generating transaction | `journal.*` |
| 15 | Prepare and submit payment | treasury_officer | `payment.prepare` | `POST /v1/payments`, `…/submit` | Prepare payment | invoice paid beyond its total; payee not the approved account; supplier not ACTIVE | `payment.*` |
| 16 | Approve payment (dual above threshold) | finance_manager, cfo (MFA, human) | `payment.approve` | `…/{id}/approve` | payment page | approver = preparer; same person twice; single approval for an amount or invoice ≥ threshold; no `principal.human` marker; payee details changed | `payment.approved` |
| 17 | Release payment | a different treasury_officer (MFA, human) | `payment.release` | `…/{id}/release` | payment page | releaser = preparer or approver | `P2P_PAYMENT` journal (Dr AP / Cr payments in transit) |
| 18 | Import bank statement | bank_statement_officer | `bank.import` | `POST /v1/bank-statements` (body = the file) | Bank statements | stored lines ≠ parsed content of the attested file; back-dated; opening ≠ previous closing; does not balance | `bank.statement_imported` |
| 19 | Reconcile | accountant | `bank.reconcile` | `POST /v1/bank-statements/{id}/reconcile` | Bank statements → Reconcile | amount, account or reference does not match a RELEASED payment; importer or reconciler involved in the payment | `P2P_SETTLEMENT` journal (Dr payments in transit / Cr bank); payment SETTLED |
| 20 | Reports | project_manager / controller | `p2p.read` / `journal.read` | `GET /v1/projects/{id}/cost-report`, `/v1/entities/{id}/p2p-reconciliation` | Cost report; Reconciliation | — | — |

## Automation that exists

- **Automatic three-way match** at invoice submit. The result and per-line detail are stored and shown on the invoice.
- **Automatic bank reconciliation.** Each released payment is matched by amount, account and payment number in the reference. Unmatched lines are left with a reason, never forced.
- **Generated accounting.** Each document produces its journal from the database's own expected lines. Finance handles journals in batches.
- **Worklists.** "My work" counts, per permission, the documents waiting for that person.

All of these are idempotent per document state and race-safe through row locks and single-use attestations. None of them can authorise anything: approvals, releases and postings are always attested human commands.

## Not built yet (per directive §4)

- Journey B: measurement → IPC → AR → receipt.
- Inventory (FIFO/WAC) and logistics.
- Contracts, variations and retention.
- Scheduling and EVM screens.
- Payroll.
- Equipment.
- Quality and HSE.
- Document control and BIM.
- Offline mobile.
- Dashboards.
- Governed AI.

Missing Journey A paths:
- cancel/reject of goods receipts;
- PO close/cancel;
- debit notes and returns;
- partial payment scheduling;
- supplier-level aggregation for dual approval (R-SPLIT-SUPPLIER).
