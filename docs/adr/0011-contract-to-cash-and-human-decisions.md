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
