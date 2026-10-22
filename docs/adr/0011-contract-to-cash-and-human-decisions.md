# ADR 0011: Contract to cash on the subledger pattern; decisions are made by people

Status: accepted (migrations 0018 and 0019). Date: 2026-10-22.

## Context

Journey B is the revenue side of a construction contract: client contract → measured work → interim payment certificate (IPC) → customer invoice → bank receipt → general ledger.

The figures that matter are cumulative: retention, advance recovery and VAT on each certificate depend on everything certified before it. Most disputes between contractors and clients are about exactly these figures. A slip in them is a misstatement of revenue and receivables.

Journey A (ADR 0009) established the pattern:

- documents are state machines guarded in PostgreSQL;
- the database computes the money;
- documents generate bound DRAFT journals that finance approves and posts.

Journey B reuses it without weakening any part.

## Decision

1. **Contracts.**
   - A commercial manager records the contract for an ACTIVE customer. Customer creation and approval are attested maker and checker steps.
   - A contract's lines may reference items of the project's approved BOQ.
   - The CFO activates the contract, with fresh MFA, and may not be its author.
   - The contract value is computed by the database from the lines at submission. The agreed advance may not exceed it.
2. **Measurements.**
   - A quantity surveyor records the quantities for a period; a site engineer verifies them.
   - The database refuses:
     - a cumulative verified quantity above the contract quantity (a variation is required);
     - a line that does not exist on the contract;
     - a second sheet for the same period.
3. **IPCs are computed, never entered.** `ipc_compute` derives every figure from the verified measurements, the previous certificates, the contract terms and the contract policy:
   - cumulative and previous gross, and the gross for this certificate;
   - retention;
   - advance recovery, limited to what the client has actually paid;
   - VAT on gross or on gross less advance;
   - the amount due.

   The database recomputes the IPC at submission and again at certification. An IPC whose basis changed meanwhile (a newly verified measurement, a certificate, an advance receipt) is **stale** and must be cancelled and prepared again.

   Certification is by a different person from the preparer, with fresh MFA, recording the client's certificate reference and the SHA-256 of the signed certificate file.
4. **Customer invoice.**
   - An AR clerk issues the customer invoice from a CERTIFIED IPC only, with the certificate's amounts. One invoice per IPC.
   - An AR supervisor approves it, which generates the `AR_INVOICE` journal:

     | Side | Account | Amount |
     |---|---|---|
     | Dr | AR | amount due |
     | Dr | Retention receivable | retention |
     | Dr | Advances received | recovery |
     | Cr | Revenue (on the project) | certified gross |
     | Cr | VAT output | VAT |

5. **Receipts come from the bank, not from a form.**
   - A receipt is recorded only for an unmatched money-in line of an imported statement. Its amount, date and bank are the line's.
   - The AR clerk allocates the whole amount to approved invoices and/or contract advances. The kernel refuses a partial allocation at recording, and the database refuses it again at confirmation.
   - An AR supervisor confirms the receipt, which generates the `AR_RECEIPT` journal:

     | Side | Account | Amount |
     |---|---|---|
     | Dr | Bank | amount received |
     | Cr | AR | invoice allocations |
     | Cr | Advances received | advance allocations |

   - At confirmation the database refuses:
     - allocations that over-allocate an invoice;
     - advances above the agreed advance;
     - a receipt allocated or confirmed by the person who imported the statement.
6. **Subledger journals.**
   - `AR_*` journals are bound to their document, frozen at birth, and re-checked at approval and posting, exactly like `P2P_*`. The guards now cover both prefixes.
   - One entry point, `subledger_expected_lines`, gives the expected accounting of every subledger document.
   - AR control accounts may not be bank or P2P control accounts.
7. **Reconciliation.**
   - `ar_gl_reconciliation` compares the AR, retention and advance subledgers with their control accounts, counting only documents whose journals are posted. It also reports money in that no confirmed receipt has applied.
   - `p2p_gl_reconciliation` is extended so that a posted receipt counts as a reconciled movement of the bank account. Without that, every receipt would show as a false bank difference.
   - `project_profitability` reads revenue and cost posted on the project.
8. **Decisions are made by people (migration 0019).** This was found while testing Journey B: an AI-kind principal could approve a customer invoice. Until then only payment approval and release required the platform-signed `principal.human` marker.
   - Every attested action is now a *decision* unless it is a draft action (`*.create`, `*.submit`, `rfq.quote.record`, `bank.import`, `workflow.start`). A decision requires the marker, both in the kernel (clear error) and in SQL on every attestation insert (cannot be bypassed with a validly signed attestation).
   - New actions are human-only by default.
   - AI assistants and integration services may prepare drafts for a person to decide on. They can never approve, certify, verify, confirm, post, release, close or configure.

## Consequences

- **Tokens must carry `pkind`.** Tokens without `pkind=human` can no longer approve anything. The development token tool now issues `pkind=human` by default (`-kind` to override). The production identity provider must assert the kind; an absent kind is never treated as human.
- **Not yet covered** (follow-ups, recorded in the release register):
  - Variations (change orders) to increase contract quantities.
  - Retention release.
  - Credit notes and invoice cancellation after approval.
  - Customer statements and dunning.
  - Foreign-currency contracts (contracts are in the entity's functional currency).
  - Withholding tax on receipts.
- **VAT is tenant configuration.** The VAT rate and base are configured per tenant in the contract policy. They are test data here, not a statement of any jurisdiction's law, and need sign-off by a tax professional before production use.

## Tests

- **Kernel happy path:** `TestJourneyB_ContractToCashToGL`. Two IPCs with exact figures, three receipts, every journal posted. The contract position, six GL balances, four AR checks and the bank check all reconcile to the cent.
- **Kernel controls:** `TestJourneyB_Controls`. Each refusal asserts its reason:
  - 22 refusals, including self-approval, stale MFA, over-measurement, a stale IPC, receipt independence, over-allocation, an advance above the agreed amount, journal tampering and a closed period.
- **Governed AI:** `TestGovernedAI_DraftOnly`.
  - An AI drafts an invoice.
  - AI, service and unknown kinds cannot approve an invoice, a customer or a contract.
  - The SQL trigger refuses a signed attestation that lacks the marker.
  - The SQL and Go lists of draft actions agree.

## Addendum: independent review 6 (2026-10-22), migration 0020

- **Contract policy succession works.** The insert guard no longer counts the entity's own contract policies as conflicting control accounts (R6-F1).
- **Draft receipts can be cancelled** (attested, by a person, with a reason). A cancelled receipt releases its statement line. Recording now refuses anything that could never be confirmed: sub-cent amounts, currency or entity mismatch, the statement importer, or a partial allocation (R6-F2).
- **Advance recovery is capped** at the certificate's gross less retention, so the amount due is never negative (R6-F3).
  - Recovery is limited to the advance actually received, and a shortfall is **not** caught up by later certificates. Each certificate recovers at most its percentage of its own gross. This is deliberate and keeps each certificate explainable on its own. A catch-up rule would be a contract-policy option.
- **Subledger journals (`P2P_*`, `AR_*`) are never reversed** (R6-F4), in the kernel and in SQL. A reversal would leave the document and the ledger disagreeing while reconciliation shows zero.
  - Correction belongs at the document. The customer credit note that does this is not built yet (JB-CREDIT-NOTE, open).
  - This also supersedes "corrected by reversal" in ADR 0009.
- **Control accounts.** Bank accounts and P2P policies may not use contract-policy control accounts (R6-F5).
- **IPC periods** follow the contract and the work (R6-F6).


## Addendum: customer credit notes (2026-10-22), migration 0022

Closes JB-CREDIT-NOTE. An approved customer invoice and its `AR_INVOICE` journal stay as they are; a reduction of what was billed is a **credit note**, a separate document against one approved invoice.

- **Who.** The AR clerk issues it (`ar.credit.create`), giving only the amount before VAT, the date and a reason. A commercial manager approves it (`ar.credit.approve`): a different person, a human, with fresh MFA. The issuer or an approver may cancel a draft, with a reason.
- **Figures come from the database.** Entity, project, contract, customer, policy and currency are copied from the invoice by the insert trigger. VAT is the net amount times the invoice policy's VAT rate, rounded to the currency.
- **Limits.**
  - All live credits of an invoice never exceed its gross (checked at issue and approval).
  - An approved credit never exceeds what is still open on the invoice: total less confirmed receipts less earlier approved credits. This is checked under a row lock on the invoice that receipt confirmation also takes, so a credit and a full receipt cannot both succeed (`TestJourneyB_CreditNoteRacesReceipt`).
  - Receipt confirmation now counts approved credits, so cash cannot be allocated to the credited part of an invoice.
  - The credit date is in an open fiscal period and not before the invoice date.
- **Accounting.** Approval generates `AR_CREDIT`: Dr revenue (on the project), Dr VAT output; Cr accounts receivable, on the invoice policy's accounts. Like every subledger journal it is bound to its document, frozen at birth, re-checked at approval and posting, and never cancelled or reversed.
- **Reports.** The AR reconciliation nets posted credits and counts unposted ones. The contract position has a `credited_total` column, and the open receivable is invoiced less credited less received. Project profitability, which reads the ledger, shows revenue net of credits.

**What a credit note is not.**

- It does not change the certificate. Retention and advance recovery are not adjusted, and the IPC stays INVOICED.
- It must not be used to correct measured quantities. IPCs are cumulative: a quantity corrected downward in the next measurement already reduces the next certificate, so crediting the same quantity as well would deduct it twice. Credit notes are for commercial settlements and concessions. This rule is procedural and is **not** enforced by the system (residual risk, recorded as JB-CREDIT-QTY).
- Cancelling an invoice outright and reopening its IPC is not built.

**Tests.**

- Kernel: `TestJourneyB_CreditNote`, with figures in docs/testing/E2E_JOURNEY_B.md. It covers 15 refusals, each asserting its reason, and the GL, reconciliation, position and profitability after posting.
- Kernel: `TestJourneyB_CreditNoteRacesReceipt`.
- HTTP: `TestAPIJourneyB_ContractToCash`, which issues and approves a credit note on IPC 2's invoice, with MFA, permission and visibility probes.
- Browser: `TestConsoleBrowserJourneyB` issues a credit note from the invoice page. The commercial manager opens it from the approval queue, the database refuses the approval because the invoice is settled, and the clerk withdraws it.

## Addendum: retention release (2026-10-22), migration 0023

Retention deducted on each certificate is debited to retention receivable when the invoice is approved. It becomes due when the client certifies its release.

- **Who.** The AR clerk records a DRAFT release (`ar.retention.create`) on an ACTIVE contract, with:
  - the amount and the date;
  - the milestone: `TAKING_OVER`, `DEFECTS_LIABILITY_END` or `NEGOTIATED`;
  - the client's release certificate reference and the SHA-256 of the signed file. The console computes the hash in the browser; the file is not uploaded.

  A commercial manager approves it (`ar.retention.approve`): a different person, a human, with fresh MFA. The issuer or an approver may cancel a draft, with a reason.
- **Limits.**
  - Approved releases plus drafts never exceed the retention held on approved invoices (checked at recording).
  - Approved releases never exceed it either, checked again under `FOR UPDATE` on the contract at approval.
  - The date is in an open fiscal period and not before the contract signature.
- **Accounting.** Approval generates `AR_RETENTION`: Dr accounts receivable / Cr retention receivable, on the contract policy. There is no VAT, because VAT was charged on the full certified gross at invoice time. The journal is bound, frozen and never reversed.
- **Payment.** A receipt allocation may now name a retention release: exactly one of invoice, contract advance or release. Receipt confirmation refuses unapproved releases and over-allocation, under a row lock on the release.
- **Reports.**
  - Accounts receivable includes posted releases.
  - Retention receivable nets them.
  - The contract position shows `retention_held` (net) and `retention_released`, and the open receivable includes releases.

**Not built:** retention bonds or guarantees in place of cash retention; release that depends on a defects list.

**Tests.**

- Kernel: `TestJourneyB_RetentionRelease`, with figures in docs/testing/E2E_JOURNEY_B.md. It covers 11 refusals and a receipt split across a release and an invoice.
- Kernel: `TestJourneyB_RetentionReleaseRace`.
- HTTP: `TestAPIJourneyB_ContractToCash`.
- Browser: `TestConsoleBrowserJourneyB`, where the release is recorded with the certificate hashed in the browser and approved from the document page.

## Addendum: contract variations (2026-10-22), migration 0026

A variation (change order) changes the scope of an ACTIVE contract on the client's written instruction.

- **Who.**
  - A commercial manager (`contract.manage`) records a DRAFT variation with the client's instruction reference and the SHA-256 of the signed instruction (computed in the browser), then submits it.
  - The CFO (`contract.approve`) approves it with fresh MFA, as a different person and a human, or rejects it with a reason.
  - Commercial staff may cancel a draft or submitted variation, with a reason.
- **Lines.**
  - **CHANGE** adds a quantity, or removes one (an omission), on an existing contract line. It is priced at the contract rate, which a quantity change cannot renegotiate. The unit and BOQ link are taken from the contract line.
  - **NEW** adds a contract line with its own rate. Its line number must be unused on the contract and on every live variation, and a BOQ link must point to the project's approved BOQ.
  - The database prices every line. Nothing changes after submission.
- **Effective quantity.** Signed contract lines are never edited. A line's effective quantity is its signed quantity plus approved CHANGEs (`contract_line_qty`), and measurement verification is capped by it. An omission can never take a line below the quantity already verified: this is checked when the line is recorded and again at approval, under the contract row lock that measurement verification also takes.
- **Approval.** On approval the NEW lines are inserted into `contract_lines`. The contract-line guard now accepts an insert into an ACTIVE contract only as an exact copy of a NEW line of a variation approved in the same transaction. A deferred check makes sure every NEW line arrived.
- **Value.** `contract_value` stays as signed. The position reports `variations_approved` and `revised_contract_value`.
- **Accounting.** There is no journal. Revenue follows certification: IPCs value verified quantities of all contract lines, including variation lines.

**Not built:** daywork, claims and extension-of-time records; variations priced by star rates or by re-rating existing work; variation-specific retention or advance terms.

**Tests.**

- Kernel: `TestJourneyB_Variation`, with figures in docs/testing/E2E_JOURNEY_B.md. It covers 13 refusals, including a reduction overtaken by verified work.
- HTTP: `TestAPIJourneyB_ContractToCash`.
- Browser: `TestConsoleBrowserJourneyB`, where the variation is recorded with the instruction hashed in the browser and approved by the CFO.

## Addendum: independent review 8 (2026-10-22), migration 0028

- **Dates (R8-F1, R8-F4).** A credit note or retention release is dated today or earlier, in an OPEN fiscal period of its entity, checked when it is recorded and again when it is approved. A document whose period closes while it is a draft can no longer be approved; it is cancelled and re-issued in an open period. This is the rule stock documents follow since R7-F3, and it exists because subledger journals are never cancelled or reversed.
- **Who cancels a draft (R8-I2).** The preparer, or a holder of the approval permission.
- **VAT on credit notes (R8-F5, proposed acceptance).** VAT is computed per credit note: `round(net × rate)` under the contract policy. Each credit note is a tax document and its VAT must be its own net times the rate; cumulative rounding would produce notes whose stated VAT is not that. Consequence: n credit notes may carry VAT that differs from the VAT on their summed net by at most n × 0.005 (asserted by `TestR8_CreditVATPerNoteRounding`); credited totals remain capped by the invoice total. **This acceptance is proposed by the delivering team and is not in force until a named human tax/finance risk owner accepts it** (register R8-F5).
