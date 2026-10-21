# Independent review 4: re-verification of 0014 (fixes for review 3)

Scope:
- `internal/store/postgres/migrations/0014_p2p_hardening.sql`
- Go changes in `internal/kernel/p2p.go`, `internal/kernel/kernel.go`, `pkg/auth/auth.go` and `internal/httpapi/token.go`
- the 0013/0010/0012 functions these changes rely on

Environment:
- All work was done in the copy `$SP/review4/repo`, on the local PostgreSQL 16.15 cluster (`/tmp:5433`), using only the database `serk_review4`, which was recreated before every run.
- `/home/claude/serk-construction` was not touched.
- `$SP` = `/tmp/claude-0/-home-claude/4f5b9a43-cc97-5a22-a4b2-841d028358f2/scratchpad`

Artifacts:
- Probe tests: `$SP/review4/repo/internal/kernel/zz_review4_test.go` (`TestR4_01` … `TestR4_09`).
- Probe-only change elsewhere: `journey_a_test.go` got a no-op hook, `newP2PWorldHook`, called between proposing and approving the first P2P policy. TestR4_07 needs it.
- Probe run (`-run 'TestR4_|TestJourneyA|TestR3_'`): `$SP/review4/probe-output.txt`.
  - 8 `TestJourneyA_*` and 14 `TestR3_*`: all PASS.
  - `TestR4_02` and `TestR4_03`: PASS.
  - `TestR4_01` and `TestR4_04` to `TestR4_09`: FAIL. Each FAIL is a finding below.
  - Totals: 130 `held:` lines, 7 `OPEN` lines.
- Full suite: `$SP/review4/full-suite.txt`. Command: `go test -race -count=1 -p 1 -skip 'TestR4_' -run . ./internal/kernel ./internal/httpapi`.
  - `ok internal/kernel 27.851s`, `ok internal/httpapi 5.359s`.
  - 138 top-level PASS, 0 FAIL, 0 SKIP.

Convention:
- An attack "with a genuine attestation" uses `f.authorizeIn`, which models what a tenant DB login holding that person's real signed evidence can do.
- All raw SQL runs as the tenant login, through `f.app.WithTenant`.

---

## 1. H1: creator binding

**What I checked**
- What the tenant login itself is allowed to do:
  - `session_replication_role`, `ALTER TABLE … DISABLE TRIGGER`, `CREATE FUNCTION`;
  - UPDATE of `created_by` / `received_by`;
  - `SET CONSTRAINTS ALL IMMEDIATE` and `SET CONSTRAINTS <trigger> DEFERRED`.
- Reusing another row's creation attestation.
- Two rows inserted with one attestation.
- Attesting a row and then changing it before commit.
- Changing creator-attributed content in a *later* transaction.

**Probe TestR4_01**
```
held: tenant login SET session_replication_role = replica   permission denied to set parameter "session_replication_role"
held: tenant login ALTER TABLE suppliers DISABLE TRIGGER suppliers_created_by   must be owner of table suppliers
held: tenant login UPDATE suppliers.created_by               permission denied for table suppliers
held: tenant login UPDATE supplier_bank_accounts.created_by  permission denied for table supplier_bank_accounts
held: tenant login UPDATE rfq_quotes.received_by             permission denied for table rfq_quotes
held: tenant login CREATE FUNCTION (to call approval_use from its own trigger)   permission denied for schema public
held: SET CONSTRAINTS ALL IMMEDIATE, forged supplier + checker's own create attestation   supplier.create of supplier … requires a verified approval attestation for u-buyer
held: SET CONSTRAINTS suppliers_created_by DEFERRED then forged insert   … requires a verified approval attestation for u-buyer
held: forged row X alongside row Y that carries u-buyer's genuine create attestation   … requires a verified approval attestation for u-buyer
held: two supplier rows in one INSERT with one create attestation   … requires a verified approval attestation for u-buyer
held: bank details attested at creation then approved (mutated) in the same transaction   supplier_bank_account … changed after the approval was attested
OPEN: unattested raw INSERT of a quote line into a quote 'received_by u-buyer' (total 85000.000000 -> 85010.000000)
OBSERVATION: the altered quote is then evaluated (err=<nil>) and awarded (err=<nil>); received_by=u-buyer
```
The baseline `TestR3_07` also holds for all five forged-maker inserts.

**Conclusion**
- **Holds for the six header rows.** The deferred constraint trigger consumes the named creator's own attestation, the subject hash is re-checked at commit, and the tenant login cannot disable, skip or re-time it. Deferral only moves the check to commit; it cannot move it past commit.
- `created_by` and `received_by` are `NOT NULL` (0013:72, 104, 125, 269, 304, 437). So the `approval_in_tx` "NULL actor matches anyone" path cannot be reached through these columns.
- **Gap (finding M-A):** a quote's *lines* can still be added after the attested creation, in a later transaction, with no attestation at all. The added lines appear under `received_by = u-buyer`.
- PO lines are not exposed in the same way: PO price, quantity, cost code and description are all forced from the award (0013 `po_lines_guard`), and the approver checks that every quote line is present.
- Not tested: `PREPARE TRANSACTION`. PostgreSQL fires deferred triggers at PREPARE, so I expect no difference. Also not tested: rows that existed before 0014 was applied (they remain un-attested).

## 2. H2: statement binding

**What I checked**
- Whether the Go `ContentDigest` and the SQL `p2p_statement_digest` agree on awkward input: 15 cases, all imported through the real `ImportBankStatement`, then the Go digest compared with the SQL digest of the stored rows.
- Raw tampering under a genuine statement-officer attestation: reordered lines, an extra line, a `line_no` gap, a case change in a reference.
- Importer/reconciler separation: `matched_by` NULL, and user ids that differ only in case.

**Probes**

TestR4_02 (differential):
```
DIFF negative-zero opening            imported; go digest == sql digest (a0ce6ce2d48b...) stored=-1.500000 5041597c310a58
DIFF pipe/newline/CR in text          imported; go digest == sql digest (0b7cc76e7a32...) stored=-2.000000 617c620d0a7c63
DIFF combining vs precomposed         imported; go digest == sql digest (edec7873f1e4...) stored=-0.010000 65cc81
DIFF 6 decimals on a 2-decimal currency import refused: … statement line -0.000001 ETB has more than 2 decimal place(s) (SC-14)
DIFF emoji, tab, U+2028               imported; go digest == sql digest (28a9f1b4a41f...) stored=100.000000 f09f988009e280a8
DIFF lone surrogate                   imported; go digest == sql digest (865975c7f17f...) stored=-2.000000 efbfbd
DIFF invalid UTF-8 byte               imported; go digest == sql digest (040103ed3df3...) stored=-3.000000 626164efbfbd62797465
DIFF 7 decimals non-zero              parse refused: … line 1 amount has more than 6 decimal places
DIFF NUL in reference                 import refused: ERROR: invalid byte sequence for encoding "UTF8": 0x00 (SQLSTATE 22021)
DIFF 18 integer digits                imported; go digest == sql digest (f0d7879563bf...)
DIFF 19 integer digits                import refused: ERROR: numeric field overflow (SQLSTATE 22003)
DIFF zero amount                      import refused: … violates check constraint "bank_statement_lines_amount_check"
DIFF unicode statement_no             imported; go digest == sql digest (a459aa27b27a...)
DIFF duplicate JSON key (last wins)   imported; go digest == sql digest (06ce00a88bd2...) stored=-5.000000
DIFF amount as string with spaces     parse refused: … can't convert  -1  to decimal
```

TestR4_03 (raw tampering):
```
held: stored lines reordered (same multiset) vs attested file   statement R4-L1: the stored lines are not the content parsed from the attested statement file
held: extra line inserted in the same tx after the header       statement R4-L2 does not balance …
held: line_no gap (1,3) with otherwise identical lines          statement R4-L3: the stored lines are not the content parsed …
held: reference changed only in letter case                     statement R4-L4: the stored lines are not the content parsed …
held: control: the same raw path stores the unaltered file
```

TestR4_04 (reconciler separation):
```
held: control: releaser reconciles own payment, matched_by = releaser   the person who released a payment cannot reconcile it
OPEN: releaser's own reconcile attestation settled PAY-2026-000002 with matched_by NULL (status SETTLED, matched_by <NULL>)
OBSERVATION: principal 'U-TREASURY-2' (case variant of the releaser 'u-treasury-2') AutoReconcile: err=<nil> matched=2 …; PAY-2026-000003 status=SETTLED
```

Baseline `TestR3_09`: all held.

**Conclusion**
- **The digests agree on every input that both layers accept.** The Go and SQL encodings matched in every case. Text fields are hex-encoded, amounts are fixed at 6 decimals, and `-0` normalises to `0.000000` on both sides.
- Every disagreement between the layers is a rejection in one layer only:
  - NUL characters, 19-digit amounts, zero amounts and too many decimals for the currency are rejected by the database, not by Go. This is an import error only, never a binding bypass.
  - Duplicate JSON keys are accepted, with the last value winning (Info).
- Stored lines are bound to the attested parse: order, `line_no`, content and count are all enforced.
- Remaining limit, by design: the importer chooses the file. Nothing proves the file came from the bank, so evidence quality now rests on the separation between the `bank_statement_officer` and the payment people.
- That separation **has a NULL hole** (finding M-B), and it compares ids byte for byte (Info I-3).
- Importer = `second_approved_by` is covered explicitly at 0014:284. I checked it by reading only; I did not probe it.
- Note on the existing regression test: `TestR3_09`'s last check ("raw match of the releaser's statement line") is stopped by `P2P_SETTLEMENT … has no generated journal`, not by the separation trigger. TestR4_04 supplies a real settlement journal, and its non-NULL control shows the trigger itself works.

## 3. M1: journal freeze and rebind

**What I checked**
- Grants on `created_txid`, `journal_lines` UPDATE/DELETE, and moving a line between journals.
- A P2P journal created with a chosen `created_txid`.
- Lines appended inside the generating transaction after `p2p_assert_journal` has run.
- The txid type.
- The legitimate flow when a successor policy is approved between GRN confirmation and journal posting.
- Inputs to `p2p_expected_lines` that can change after the document transition.

**Probe TestR4_06**
```
OBSERVATION: tenant login column privilege on journals.created_txid INSERT/UPDATE = true/false
OPEN (Info): journals.created_txid is insertable by the tenant login (table-level INSERT grant), contrary to the 0014 comment
OBSERVATION: types: txid_current()=bigint, journals.created_txid=bigint, current txid=102822
held: UPDATE journals.created_txid of a P2P journal        permission denied for table journals
held: DELETE a P2P journal line                            permission denied for table journal_lines
held: UPDATE a P2P journal line amount                     permission denied for table journal_lines
held: UPDATE journal_lines.journal_id moving a line into the P2P journal   permission denied for table journal_lines
held: raw GRN confirm whose P2P journal is inserted with created_txid = txid_current()+5   lines of subledger journal … are written only by the transaction that generated it
OBSERVATION: lines appended after p2p_assert_journal in the generating tx were committed (journal 923caec9-…); M1 now rests on the rebind trigger
held: raw journal.approve (genuine attestation) of that journal   subledger journal … no longer equals the accounting of P2P_GRN …
held: legitimate P2P_GRN journal approved and posted
```

**Probe TestR4_09** (legitimate successor with a new VAT-input account, approved between confirmation and posting):
```
held: legitimate successor between confirm and post: approve ok, post ok=true
```

**Probe TestR4_07**: see finding L-A.

**Conclusion**
- **Holds.** Lines of a P2P journal cannot be added, changed or deleted outside the generating transaction.
- `created_txid` is a 64-bit, epoch-extended `bigint`, so wraparound is not an issue for it.
- It *is* insertable (`GRANT INSERT ON journals`, 0001:604; the table-level grant covers new columns). This does not help an attacker:
  - a future `created_txid` stops the generating transaction from writing the lines that `p2p_assert_journal` needs;
  - `journals_subledger_binding` requires the referencing document at commit of that same transaction.
- Content appended inside the generating transaction after binding is caught by `journals_p2p_rebind` at approve/post. The cost is that the journal is permanently stuck: it can be neither approved nor cancelled.
- Other inputs to the expected lines:
  - The GRNI credit of a GRN journal comes from the **current** approved policy (`p2p_policy_for`, 0013 `p2p_expected_lines`).
  - Invoices and payments use their bound `policy_id`.
  - Bank and clearing accounts and PO line accounts have no UPDATE grant.
- So the only moving input is the GRNI account, and R3-X1 can be bypassed (finding L-A). When it is, legitimate pending GRN journals are blocked from approval.

## 4. M2: human marker

**Probe TestR4_08**
```
OBSERVATION: Permissions() with a role granting principal.human: [Principal.human ap.approve_exception … payment.approve …]
held: AI principal whose role lists principal.human approves a payment   payments are authorised only by principals the identity provider asserts are human (actor u-fm-bot)
held: principal with kind 'Human' (wrong case) approves a payment         … (actor u-fm-unknown)
held: AI-kind attestation + same actor's human journal.approve attestation in the tx   … (actor u-finance-manager)
OPEN (Low): payment approved on an attestation without the human marker (consumed attestation has marker: false); the marker came from the same user id's attestation for another payment
```
Baseline `TestR3_08`: held. The `TestR3_05` dual-approval probe is now also stopped by the human check.

**Conclusion**
- Roles cannot grant `principal.human`. A case variant such as `Principal.human` passes the Go filter but does not satisfy the exact SQL comparison.
- A `pkind` other than exactly `human` is never treated as human.
- A marker on an unrelated action does not count.
- **Weakness (finding L-C):** the SQL check is not bound to the attestation that is actually consumed. Any `payment.approve`/`payment.release` attestation by the same user id in the transaction is enough. Exploiting this requires that one user id can obtain both a human and a non-human assertion.
- Not tested: how the identity provider sets `pkind`. HS256 tokens from the SERK identity service are trusted as issued.

## 5. M3, L1, L2, L3, Info items and R3-X1

**Probes**

TestR4_09:
```
held: company bank account registered on an account PO lines already use   bank and payments-in-transit accounts must be distinct and not used as P2P control or PO cost accounts
OPEN (Low): PO line accepted on the RETIRED policy's VAT input account 1300 (still carries VAT input balances)
OBSERVATION: PO line accepted on an unregistered cash-type ASSET account 1010 'Petty cash' (only registered control accounts are excluded)
held: PO line on payments-in-transit: PO line 1 cannot post receipts to a control account …
```

TestR4_05 (L1):
```
OPEN: two concurrent statements both continue the same previous closing balance: R4-A:-10.000000->-30.000000, R4-B:-10.000000->-50.000000, R4-P:0.000000->-10.000000
```

TestR4_07 (R3-X1):
```
OPEN: successor policy with a different GRNI account approved (it was DRAFTed before the first approval)
OBSERVATION: pending GRN journal after the successor: approve ok=false
OBSERVATION: GRNI credit account: journal=2100 expected-now=2200
```

Baseline, all held:
- `TestR3_10` (back-dating), `TestR3_12` (bank GL account on a PO line);
- `TestR3_13` (split payments refused under an invoice at or above the threshold, preparer cannot release, numbering past 999,999 gives `PAY-2026-1000000`);
- `TestR3_14` (GRNI/AP swap, bank account as VAT input, late quote).

**Conclusion**
- **M3 holds** for the bank, clearing, and current or DRAFT policy accounts, in both directions: a PO line cannot use a control account, and a new bank account or policy cannot claim an account that PO lines already use.
- It does not cover:
  - the accounts of RETIRED policies (finding L-D);
  - unregistered cash-like ASSET accounts (Info).
- **L1:**
  - Back-dating is fixed.
  - Concurrent imports can fork the balance chain, because nothing serialises them (finding L-B).
  - Same-date imports in separate transactions chain correctly, since the latest `imported_at` wins. That was checked by reading, plus the R4-P → R4-A ordering above.
- **L2 holds** for any invoice at or above the threshold. Splitting one obligation across two supplier invoices that are each below the threshold remains possible. This is inherent to the design and I did not probe it.
- **L3:**
  - The preparer cannot release (held).
  - Reconciler separation can be bypassed with a NULL `matched_by` (M-B).
- **R3-X1** is enforced only when a policy is INSERTed, and only against the policy that is APPROVED at that moment. A DRAFT created before any policy was approved keeps a different GRNI and can be approved later (finding L-A).

## 6. Regressions

- Full kernel and httpapi suites pass: 138 top-level tests, 0 failures (`full-suite.txt`).
- Every legitimate flow I built worked:
  - the whole of Journey A;
  - a successor policy between GRN confirmation and posting;
  - genuine raw-path statement imports.
- The one legitimate-flow break I found is the stuck GRN journal under L-A.
- Behaviour change, by design: creating and approving master data in the same transaction is no longer possible (TestR4_01).

---

## Findings (ranked)

### Medium

**M-A. Quote content can be added after the attested creation, unattested, under the receiver's name.**
- Where:
  - 0013:1137-1150, `rfq_quote_lines_guard`: allows INSERT while the RFQ is ISSUED and the quote is PENDING, in any transaction;
  - 0014:29-45, `p2p_creation_attested`: binds only the header INSERT.
- Proof: TestR4_01. A raw INSERT with no attestation changed the quote total from 85,000 to 85,010. The quote was then evaluated and awarded, still showing `received_by = u-buyer`.
- Impact: a leaked tenant login can plant supplier prices that the buyer never keyed. This is exactly the H1 class of problem, for quotes.
- Fix: in `rfq_quote_lines_guard`, require that the quote was created in the current transaction (`xmin` / a `created_txid` comparison, as for statements). Alternatively, add an attested `rfq.quote.submit` step by `received_by` and require `technical_status`/submission before evaluation.

**M-B. A NULL `matched_by` bypasses reconciler separation and attribution.**
- Where:
  - 0013:1633 `IF NEW.matched_by = p.released_by` is NULL-unsafe;
  - 0013:1636 `approval_use(…, NEW.matched_by, …)` with a NULL actor accepts **any** actor's `bank.reconcile` evidence (`approval_in_tx`: `p_actor IS NULL OR …`);
  - 0014:287 `NEW.matched_by IN (…)` is NULL-unsafe.
- Proof: TestR4_04. The releaser, given the accountant role, settled their own payment with `matched_by` NULL. The same attempt with `matched_by = releaser` is refused.
- Impact:
  - The releaser-vs-reconciler and importer-vs-reconciler rules are both bypassed.
  - The MATCHED line records no reconciler.
  - It needs a user holding `bank.reconcile` plus a payment or import role. The statement line itself is still independent evidence.
- Fix:
  - `CHECK (status <> 'MATCHED' OR matched_by IS NOT NULL)`;
  - in the guard, `IF NEW.matched_by IS NULL OR NEW.matched_by = p.released_by`;
  - generally, never pass a nullable column as `p_actor` to `approval_use`.

### Low

**L-A. R3-X1 can be bypassed by a policy DRAFTed before the first approval; pending GRN journals then become permanently stuck.**
- Where: 0014:105-110. The check runs only BEFORE INSERT and compares only with the policy APPROVED at that moment.
- Proof: TestR4_07. The CFO approved the successor, which moved GRNI from 2100 to 2200. The open GRN journal (credit 2100) now fails rebind against the expected 2200, and P2P journals cannot be cancelled.
- Fix: repeat the GRNI/AP equality check on DRAFT→APPROVED, in `p2p_policies_guard` or a trigger on UPDATE OF status. Alternatively, bind GRN expected lines to a policy id stored on the GRN.

**L-B. Concurrent statement imports fork continuity.**
- Where: 0014:250-258, which reads earlier statements without locking.
- Proof: TestR4_05. Two transactions both continued the previous closing balance of −10.
- Fix: `SELECT … FROM company_bank_accounts WHERE id = NEW.company_bank_id FOR UPDATE` (or `pg_advisory_xact_lock`) at the top of `bank_statements_guard`, or a unique "previous statement" link.

**L-C. The human marker is not bound to the consumed attestation.**
- Where: 0014:190-193, `p2p_assert_human`, which searches any payment attestation by the actor in the transaction. It is called before `approval_use` (0013:1521/1532/1538).
- Proof: TestR4_08. Payment B was approved on an AI-kind attestation; the marker came from the same user id's attestation for payment A.
- Fix: check `'principal.human' = ANY(r.perms)` on the record returned by `approval_use`, or pass the subject id and ctx into `p2p_assert_human`.

**L-D. Accounts of a RETIRED policy are no longer treated as control accounts.**
- Where: 0014:67-68 and 84 (`status IN ('DRAFT','APPROVED')`).
- Proof: TestR4_09. A PO line was accepted on the old VAT-input account.
- Fix: include RETIRED policies, or keep a permanent control-account register. Consider an allow-list of cost and inventory accounts (which would also cover unregistered cash accounts).

### Info

- **I-1.** `journals.created_txid` is insertable by the tenant login, so the comment at 0014:118-119 is wrong. It is not exploitable (TestR4_06). Fix: revoke the table-level INSERT and grant INSERT on explicit columns.
- **I-2.** Lines appended in the generating transaction after binding are committed, and the rebind check catches them at approval (TestR4_06). The journal is then stuck. That is a self-inflicted DoS needing a genuine confirm attestation.
- **I-3.** Separation compares user ids byte for byte. `U-TREASURY-2` reconciled payments released by `u-treasury-2` (TestR4_04). This is safe only if the identity provider guarantees canonical ids; consider canonicalising `sub` at token verification.
- **I-4.** The statement parser accepts input the database then rejects (NUL, more than 18 integer digits, zero amounts, too many decimals for the currency). The result is a raw SQL error, not a binding bypass. Duplicate JSON keys are accepted with the last value winning; reject them to avoid parser differentials with other viewers of the file.
- **I-5.** `TestR3_09`'s raw-match probe passes for an unrelated reason (missing settlement journal). Strengthen it as in TestR4_04.
- **I-6.** Not probed, by reading only:
  - Rows created before 0014 remain un-attested and approvable.
  - The 0013 statement-line guard compares `xmin` with `txid_current() % 2^32`, so it could in theory collide after 2^32 transactions.
  - There is no locking in the M3 cross-checks (a race similar to L-B).

## Could not test

- `PREPARE TRANSACTION`.
- txid wraparound.
- How `pkind` is issued by a real identity provider.
- Migration behaviour on pre-existing data.
- L2 splitting across separate supplier invoices.
- Importer = `second_approved_by` (by reading only).
