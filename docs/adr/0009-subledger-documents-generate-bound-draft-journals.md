# ADR 0009: Procure-to-pay documents generate bound DRAFT journals; the database computes the money

Status: accepted (migration 0013, hardened by 0014 after independent review 3). Date: 2026-10-22.

## Context

Journey A (BOQ → requisition → RFQ → PO → goods receipt → invoice → payment → bank reconciliation → GL) is the first business slice built on the Gate A kernel.

The kernel already guarantees three things. Ledger entries are double-entry and immutable once posted (ADR 0002). Journals are approved and posted by different people. Every authority transition is proven by a signed attestation verified in PostgreSQL (ADR 0008).

The subledger must not weaken any of this. Two shortcuts would weaken it:

- letting procurement users post to the ledger;
- letting the application compute amounts that the database merely stores.

## Decision

1. **Documents are state machines guarded in PostgreSQL.** Every maker step (submit, issue) and checker step (approve, award, confirm, release, reconcile) is an attested transition. Since 0014 the *creation* of master data, quotes and purchase orders is attested too: the named creator's own attestation is consumed at commit, so a maker identity is never free text.
2. **The database computes the money.** It computes line amounts (half-even to the currency's minor unit, differential-tested against Go), totals, VAT, budget availability (BOQ budget − commitments − reservations − other actuals), three-way match results and the expected accounting of each document (`p2p_expected_lines`). Values the caller sends are recomputed, never trusted.
3. **Subledger documents generate DRAFT journals with reserved source types.** The four types are `P2P_GRN`, `P2P_INVOICE`, `P2P_PAYMENT` and `P2P_SETTLEMENT`.
   - The document transition asserts that the journal's lines equal the expected accounting.
   - A deferred check binds the journal to exactly one document.
   - Finance approves and posts the journal through the ordinary journal commands, so ledger separation of duties is unchanged.
   - Subledger journals are never cancelled. A wrong document is corrected by reversal.
   - Since 0014, lines can be written only by the generating transaction (`journals.created_txid`, not grantable). The binding is re-checked when the journal is approved and again when it is posted.
4. **Payments are instructions, not money movement.** A RELEASED payment records an instruction. Settlement is recognised only from an imported bank statement line, matched under the reconciler's attestation.
   - Since 0014 the stored statement lines must equal the content the API parsed from the attested file. Text fields are hex-encoded in the digest, so no separator can be forged.
   - The importer must be independent of the payment, and so must the reconciler.
5. **Control accounts are protected.** PO lines cannot post receipts to bank, clearing, GRNI, AP, VAT-input or price-variance accounts. A successor P2P policy keeps the GRNI and AP accounts, so a document's expected accounting stays stable between its transition and its posting.
6. **Payment authority is human-only, by signed assertion.** The identity provider asserts the principal kind (`pkind`). The API adds the reserved `principal.human` marker to the signed permission list only for human principals, and a role can never grant it. The database requires the marker for payment approval and release.
7. **Fixed separation baselines for payments.**
   - Above the policy threshold, two different approvers are required. The threshold is also applied to each paid invoice's total, so splitting a payment does not avoid dual approval.
   - Neither approver may release, and the preparer may not release either.
   - Statement import is a separate role from treasury.

## Consequences

**Gained**
- Every number in the cost report and the subledger-to-GL reconciliation is derived in one place, the database. Journey A reconciles to the cent: `TestJourneyA_BOQToBankReconciliationToGL`, `TestAPIJourneyA_EndToEnd`, `TestConsoleBrowserJourneyA`.
- Review 3's probes are kept as regression tests: `internal/kernel/review3_regression_test.go`.

**Cost**
- The SQL is large (0013 plus 0014). Every new subledger document needs a guard, a subject-text branch, an expected-lines branch and a binding branch.
- Policy changes cannot move the GRNI or AP control accounts. Moving them requires a reviewed ledger migration.

**Not solved**
- The authenticity of a bank statement file still depends on how it is obtained. A bank-signed host-to-host feed is not integrated (R-BANKFEED).
- Collusion between an independent importer and a payment person is not prevented, only made to require two people.
- Splitting a large purchase across several invoices from the same supplier is not aggregated for dual approval (R-SPLIT-SUPPLIER).
- The R-SIGNER, R-DBA and R-MFA-SOURCE risks of ADR 0008 apply unchanged.

## Alternatives considered

- **Post subledger accounting automatically, without finance approval.** This is faster, but it would give procurement and AP users an indirect posting path. Rejected.
- **Compute amounts in Go and store them.** This is simpler, but a second writer (tenant SQL, a future service) could store different numbers. Rejected in favour of database computation, with Go/SQL rounding differentially tested.
- **Trust the uploaded statement lines with only a file hash.** That was the 0013 design. Review 3 (H2) showed the lines were not bound to the file, so it was replaced by the parsed-content digest verified at commit.

**Amendment (2026-10-22, 0020):** subledger journals are no longer corrected by reversal. A reversal leaves the source document live while its accounting is undone, so reversal of `P2P_*` and `AR_*` journals is refused. Corrections are document-level (see ADR 0011, R6-F4).

