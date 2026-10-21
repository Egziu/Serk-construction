# Independent review 3: commit a1f337c (0013 procure-to-pay)

Scope: `internal/store/postgres/migrations/0013_procure_to_pay.sql`, `internal/kernel/p2p.go`, `internal/store/postgres/p2prepo.go`, and the attestation layer they rely on (0010/0012).
All work was done in a copy (`$SP/review3/repo`) against the throwaway databases `serk_review3` and `serk_review3_probe`. `/home/claude/serk-construction` was not modified.

Artifacts:
- Probe file: `$SP/review3/zz_review3_test.go` (copied into `repo/internal/kernel/`).
- Probe output: `$SP/review3/probe-output.txt`. Last run: 13 tests, 79 `held:`, 15 `OPEN:`. 7 tests PASS; 6 FAIL, and the FAILs are the findings.
- Full kernel suite, run without the probe file: `$SP/review3/full-suite.txt`. Result: `ok … internal/kernel 18.931s`, 108 top-level PASS, 0 FAIL/SKIP. That includes all 8 `TestJourneyA_*`.

`$SP` = `/tmp/claude-0/-home-claude/4f5b9a43-cc97-5a22-a4b2-841d028358f2/scratchpad`

---

## Per area

### 1. Money (amounts, quantities, totals, tax, allocations, budget, journal binding)

**What I checked**
- UPDATE grants on child tables.
- INSERT on child tables after the parent leaves DRAFT.
- DELETE/TRUNCATE on every new table.
- Header totals the database recomputes, and lines added after attestation.
- `p2p_expected_lines`: GROUP BY, NULL/`concat_ws`, `amount > 0` filter, duplicate lines.
- Rounding: `round_half_even` by reading, plus the existing differential test.
- What happens to a generated journal after the binding check.

**Probes**
- TestR3_02: DELETE/TRUNCATE on all 23 tables, all `permission denied` (held).
- TestR3_03: 18 attempts, all held. Examples:
  ```
  held: INSERT boq_items into APPROVED BOQ          BOQ items change only while the version is DRAFT
  held: UPDATE po_lines price/qty/amount of APPROVED PO   permission denied for table po_lines
  held: INSERT grn_lines into CONFIRMED GRN          receipt lines are added only while the receipt is DRAFT
  held: INSERT payment_allocations into SUBMITTED payment  allocations are added only while the payment is DRAFT
  ```
- TestR3_04: held.
  ```
  held: GRN submitted after an extra line was added post-attestation   grn … changed after the approval was attested
  held: payment submitted after amount+allocation changed post-attestation   allocations (101.000000) must equal the payment amount (100.000000)
  ```
- TestR3_01: OPEN, see M1.
  ```
  OPEN: raw append of a balanced pair to a CONFIRMED receipt's DRAFT journal succeeded
  OBSERVATION: journal still equals the receipt's accounting: false
  held: finance approval refused: ledger: illegal status transition: journal content changed after creation
  OBSERVATION: recovery by cancelling the tampered receipt journal: subledger journals are not cancelled; correct the source document
  OPEN: raw journal.approve (genuine finance attestation) of the tampered P2P_GRN journal succeeded
  OPEN: raw journal.post (genuine controller attestation) of the tampered P2P_GRN journal succeeded
  OBSERVATION: cost code posted actual now 1422500.000000; budget available before 9940000.000000, after 9940000.000000 (actual_other 0)
  OBSERVATION: p2p_gl_reconciliation: … Bank (reconciled movements): CBE Operating diff=-1000000.000000
  ```
- TestR3_12: OPEN, see M3.
  ```
  OPEN: PO line whose receipt debits the bank GL account (Cash at Bank) succeeded
  ```

**Conclusion**
- Document content is well frozen. Child rows can only be inserted while the parent is DRAFT, there are no UPDATE grants on priced child rows, there is no DELETE, and the subject hash covers children.
- The expected-lines SQL is sound:
  - every field is present in the canonical text (project and cost code are COALESCEd);
  - duplicate lines change the text, so they are caught;
  - the GRN and invoice GRNI groupings have exactly one group per document;
  - a NULL policy account only produces a mismatch, never a pass.
- I found no rounding exploit. Per-receipt rounding can leave small GRNI residues; I judged this by reading and did not probe it.
- The weak point is the generated journal **after** binding. It stays DRAFT and is still writable (M1).

### 2. Maker/checker and separation

**What I checked**
- Self-approval, both with forged and with genuine identities.
- One attestation used for two transitions, and one document's attestation used on another.
- Dual approval (same approver twice, skipping PARTIALLY_APPROVED).
- MFA, the human-only rule, budget, 3-way match, over-receipt, duplicate invoice, overpayment.
- Payee snapshot, and separation between releaser and reconciler.

**Probes**
- TestR3_05: held.
  ```
  held: one CFO attestation: PARTIALLY_APPROVED then APPROVED   … requires a verified approval attestation for u-finance-manager
  held: single approval straight to APPROVED above the dual threshold   payments of 500000.000000 ETB or more need two approvers
  held: same person as first and second approver   violates check constraint "payment_dual_distinct"
  ```
- TestR3_06: held.
  ```
  held: confirm GRN 2 with GRN 1's confirm attestation   grn.confirm of grn … requires a verified approval attestation
  ```
- TestR3_07: OPEN ×5, see H1.
  ```
  OPEN: finance manager approves bank details they inserted as 'u-buyer' succeeded   (ghost account status = APPROVED)
  OPEN: procurement manager activates a supplier they inserted as 'u-buyer' succeeded
  OPEN: CFO activates a company bank account they inserted as 'u-treasury' succeeded
  OPEN: CFO approves a policy they inserted as 'u-controller' (25% tolerances, no dual approval) succeeded
  OPEN: site engineer evaluates a quote they inserted as 'u-buyer' succeeded
  ```
- TestR3_08: OPEN ×2, see M2.
  ```
  OPEN: payment approved by non-human principal ai.payments-copilot succeeded
  OPEN: payment approved by non-human principal svc/payments-bot succeeded
  ```
- TestR3_13: observations.
  ```
  OBSERVATION: invoice above the dual threshold paid by 2 single-approver payments
  OBSERVATION: extra 1 ETB allocation beyond total refused … would be paid 971751.000000   (overpayment control holds)
  OBSERVATION: payment released by its preparer (u-treasury): err=<nil>
  ```
- The existing tests (all PASS) also cover:
  - budget (PR and PO);
  - over-receipt, 3-way match, VAT, exception plus MFA, duplicate invoice;
  - bank-detail change after preparation;
  - releaser cannot reconcile.

**Conclusion**
- Attestations are single-use and bound to the subject, the actor and ctx.
- Dual approval, MFA, budget, 3-way match, over-receipt, duplicate-invoice, overpayment and payee-snapshot controls hold.
- Maker/checker is **bypassable wherever creation is not attested** (H1).
- The human-only rule is only a naming convention (M2).

### 3. Statements, settlement, reconciliation

**Probes**
- TestR3_10:
  ```
  held: append a line to an existing statement   statement lines are imported together with their statement
  held: rewrite a statement line amount/reference   permission denied
  held: rewrite statement closing balance   permission denied
  OPEN: back-dated statement with an opening balance that continues nothing succeeded
  ```
- TestR3_09: OPEN, see H2. The setup used raw SQL plus ONE `bank.import` attestation for an arbitrary digest.
  ```
  OPEN: statement with lines typed by the payment's releaser (no bank evidence) succeeded
  OPEN: payment PAY-2026-000001 SETTLED from a statement fabricated by its releaser (matched 1)
  ```
- The existing test covers raw settlement without a statement (held).

**Conclusion**
- Held:
  - raw `SETTLED`;
  - appending lines to an existing statement;
  - editing a statement;
  - matching to a payment that is not RELEASED, has a different amount or account, or whose number is not in the reference;
  - reconciliation by the releaser.
- Not held: the statement *content* is not bound to any bank evidence (H2), and continuity can be skipped by back-dating (L1).
- Matching to the wrong payment is possible only when one reference contains two RELEASED payments' numbers with the same amount. This is by design and I did not probe it.

### 4. Tenant isolation

**Probe (TestR3_11)**
```
held: (no rows of any of the 23 tables visible to tenant 2)
held: functions return nothing for tenant 1 ids (expected_lines=0, subject_text=NULL, lines_text='', recon rows=0)
held: tenant 2 inserts a supplier into tenant 1   new row violates row-level security policy for table "suppliers"
held: tenant 2 sets tenant 1's counters   new row violates row-level security policy for table "p2p_counters"
held: tenant 2 UPDATE of tenant 1 invoice: 0 rows (RLS hides the row)
held: no new p2p function or P2P trigger function is SECURITY DEFINER
```

**Conclusion:** Isolation holds.
- All 23 tables have ENABLE plus FORCE RLS.
- Every new function runs as invoker, so RLS applies inside triggers.
- Foreign keys are composite on `(tenant_id, id)`.
- The global `UNIQUE(journal_id)` columns cannot act as an existence oracle, because the BEFORE trigger rejects foreign journals first. This was established by reading the code.

### 5. Other

**Checked by reading, not probed:**
- `p2p_counters` is tenant-writable, and `lpad` truncates past 999,999. Observed: `next payment number "PAY-2026-100000"`.
- Quotes are accepted after `due_at`; `rfq_quotes_guard` does not check it.
- GRNs and PRs have no cancel or reject path.
- Over-receipt within tolerance creates cost that is neither committed nor in `actual_other`, because `actual_other` excludes `P2P_GRN`.
- The header cites "ADR 0009", which does not exist in `docs/adr/`.
- Every function granted to `serk_app` is read-only or trigger-only, and the only definer function, `approval_use`, is depth-guarded by 0012. I found no directly callable function that does harm.

---

## Findings (ranked)

### High

**H1. The maker identity is free text on documents whose creation is not attested, so the checker can approve "someone else's" document alone.**
- Where in 0013:
  - `suppliers_guard` INSERT branch, :820-825
  - `supplier_bank_accounts_guard`, :848-852
  - `company_bank_accounts_guard`, :1414-1421
  - `p2p_policies_guard`, :772-783
  - `rfq_quotes_guard` (`received_by`), :1106-1111
  - `purchase_orders_guard` INSERT, :1166-1180 (by inspection; PO content is fixed by the award, so the impact there is low)
- The CHECKs `approved_by <> created_by` compare against a value the tenant login chose.
- Proven by TestR3_07 with ONE genuine attestation of the checker:
  - a finance manager alone approves new supplier bank details, which defeats the bank-detail fraud control;
  - a procurement manager alone activates a ghost supplier;
  - the CFO alone activates a company bank account;
  - the CFO alone replaces the P2P policy with 25% tolerances and a dual threshold of 999,999,999,999, which disables dual approval and 3-way price control;
  - an evaluator evaluates a quote they keyed themselves.
- Fix: bind the creator at INSERT. Either require `approval_use('<doc>.create', …, NEW.created_by, …)` in the INSERT branch (the subject being the row's canonical content or a client nonce), or add an attested `submit` step whose actor must equal `created_by`, as BOQ/PR/GRN/invoice/payment already do. Then make the approval transitions require `status = 'SUBMITTED'`.

**H2. Bank statement lines are not bound to bank evidence, so the releaser of a payment can "confirm" it themselves.**
- `bank.import` attests only `source_sha256`, and `approval_subject_hash('bank_statement_source', p_id)` returns `p_id` (0013:1767-1768).
- The lines are inserted separately (0013:1609-1623). `ImportBankStatement` (p2p.go:1240-1278) never parses `in.Raw`: the lines come from the caller.
- `treasury_officer` holds both `payment.release` and `bank.import` (pkg/auth/auth.go:106-107). Nothing in the DB separates the importer from the releaser.
- TestR3_09: the releaser imported a fabricated one-line statement using raw SQL and one `bank.import` attestation on an arbitrary digest. The accountant's AutoReconcile then matched it and the payment became SETTLED.
- Fix:
  - parse the lines server-side from the raw file, keep the file, and attest a digest over the canonical *parsed lines* (put it in ctx and verify in SQL at commit);
  - in `bank_statement_lines_guard` MATCHED, refuse when `st.imported_by = p.released_by` (also `p.created_by`/approvers if desired);
  - split `bank.import` from `payment.release` in the role catalogue.

### Medium

**M1. Generated subledger journals stay DRAFT and writable after binding; the DB never re-checks the binding.**
- `p2p_assert_journal` runs only at the document transition (0013:1303, 1380, 1541, 1637). `journal_lines` keeps INSERT for DRAFT journals (0002:33-58; 0001:604).
- TestR3_01: one raw INSERT, needing no attestation, appended Dr expense / Cr bank 1,000,000 to a CONFIRMED receipt's journal. The result:
  - The journal is permanently stuck for the normal flow. The Go command-hash check refuses it (kernel.go:186-188), it cannot be cancelled (`journals_subledger_guard`, 0013:1650-1657), and its lines cannot be deleted.
  - Raw approve and post with genuine finance and controller attestations still put it in the GL. That needs two attestations, made over the tampered content.
  - The extra cost is invisible to the budget, because `p2p_cost_position` excludes every `P2P_GRN` journal (0013:563-566).
- Fix:
  - in `journals_attest`, for `source_type LIKE 'P2P\_%'`, call `p2p_assert_journal` against the bound document on DRAFT→APPROVED and APPROVED→POSTED;
  - refuse `journal_lines` INSERT on a P2P journal outside the transaction that created it (compare the journal's `xmin`, as the statement guard does);
  - compute `actual_other` by excluding the *expected* GRN lines rather than every line of the journal.

**M2. The "human-only" payment authority is a regular expression on the user id.**
- `p2p_assert_human` (0013:1458-1464) refuses only `^(system|ai|agent|bot|service)[:_-]`. TestR3_08: `ai.payments-copilot` and `svc/payments-bot` approved payments.
- Fix: carry a signed principal kind in the attestation (`kind: human|service|ai`, from the IdP) and check `r.kind = 'human'` in SQL for `payment.approve` and `payment.release`; or keep an operator-managed table of human principals.

**M3. A PO line may route receipt cost to any ASSET or EXPENSE account, including bank, clearing and VAT-input accounts.**
- `po_lines_guard`, 0013:1247-1250. TestR3_12: a PO line was accepted whose receipt would debit "Cash at Bank".
- Fix: allow only accounts flagged as inventory or cost (an account category or allow-list on the policy), and exclude accounts referenced by `company_bank_accounts` or `p2p_policies`.

### Low

- **L1. Statement continuity can be skipped by back-dating.** `bank_statements_guard` compares only with statements dated on or before the new one (0013:1585-1589). TestR3_10 imported a statement dated 10 days earlier with an arbitrary opening balance. Fix: require `statement_date >=` the latest statement, or also check the next statement's opening balance.
- **L2. Dual approval can be avoided by splitting.** There is no per-invoice or per-supplier aggregate (0013:1524). TestR3_13 paid a 971,750 invoice with two single-approver payments of 485,875. Fix: apply the threshold to the invoice total, or to the sum of open payments per invoice or supplier.
- **L3. Release and reconciliation separation is narrow.**
  - `payment_release_separation` (0013:484) does not exclude `created_by`. The preparer released in TestR3_13, and the journey test does the same.
  - The DB does not separate the reconciler from the importer or approvers (0013:1633).
  - Confirm whether this is intended; if not, extend the CHECKs.

### Info

- `p2p_next_number` (0013:755-763): `lpad(n, 6)` truncates above 999,999, so `PAY-2026-100000` repeats. `p2p_counters` is also tenant-writable (`GRANT UPDATE (last)`, :1879). The result is unique-violation DoS only. Use `greatest(6, length)` and keep counter updates inside a definer helper.
- Quotes are accepted after `due_at` (`rfq_quotes_guard`, :1105-1111). Not probed.
- GRNs and requisitions have no cancel or reject path, so a wrong SUBMITTED GRN is stuck. Not probed.
- Over-receipt within tolerance creates cost outside both the commitment and `actual_other`. Found by reading.
- The 0013 header cites "ADR 0009", which is missing from `docs/adr/`.

## What holds (summary)
- Single-use, subject-hashed, actor-bound and ctx-bound attestations, including children in the hash.
- Frozen document content and child rows.
- No DELETE or TRUNCATE.
- Totals, VAT and the match result computed by the DB.
- Dual approval with distinct approvers, and MFA where required.
- Budget at PR and PO, with escalation.
- 3-way match, over-receipt, duplicate invoice, overpayment.
- Payee snapshot.
- Raw settlement blocked, statement immutability, no appended statement lines.
- RLS isolation.
- No new SECURITY DEFINER functions.
- The full kernel suite passes: 108 top-level tests, 0 failures.
