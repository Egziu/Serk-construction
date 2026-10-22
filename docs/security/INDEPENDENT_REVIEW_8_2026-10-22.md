# Independent review 8: credit notes, retention release, review 7 corrections, stock transfers (migrations 0022–0025) at commit 8caddaa

Independent review. Every claim below comes from a probe that was run against a dedicated disposable database `serk_review8` (PostgreSQL 16, Go 1.26.10, `-race`). The shared `postgres` database was not used.

- Probes: written as `internal/kernel/zz_review8_test.go`; kept after the fixes as `internal/kernel/review8_regression_test.go` (`TestR8_*`). No HTTP probes were needed; the kernel is the policy point for every route probed.
- Raw output before the fixes: `docs/testing/evidence/review8-probes-before-fix.txt`
- Regression run: `full-suite.txt` (`go test -race -count=1 -skip 'TestR8_' ./internal/kernel ./internal/httpapi`)

## Verdict

**Not ready to sign off. Three Medium defects need fixing first. None is Critical or High.**

The money engine holds under attack:
- Credits, receipts and releases cannot over-collect an invoice or a release. This held under concurrency (three rounds of two credits racing a receipt; two receipts racing on one release) and under ordering (credit after partial payment, then release, then a further credit).
- AR_CREDIT and AR_RETENTION accounting matches the subledger. After a full cycle, GL AR, the retention account, the contract position and every AR reconciliation row are 0.
- Transfers move FIFO and WAC cost with no residue. This held across split layers, a COUNT layer moved back, and 6-decimal prices with 4-decimal quantities.
- Raw SQL as the tenant role was refused for every attempt.
- Human-only decisions and project scope hold for the new documents.

The defects:
- **Period re-check missing for AR.** Credit notes and retention releases re-check their period only at recording. The R7-F3 rule, now applied to stock, was not carried over. After the period closes they are approved, change the receivable, and their journals cannot post.
- **The R7-F9 posture check always fails.** It names every superuser as a "tenant login", so `serk-api` refuses to start in production on any PostgreSQL cluster.
- **The R7-F4 budget netting does not track where stock came from.** Stock bought on one project and consumed by another (through a 0025 transfer) is charged to both budgets. Stock that did not come from a cost code's commitment is consumed on that code with no budget effect.

Smaller items:
- future-dated credits and releases are accepted;
- VAT on credits is rounded per note;
- a project-scoped approver can move stock into a warehouse they cannot see;
- the posture check is incomplete (it misses CREATE on a schema and the other advisory-lock functions);
- R7-F5 is fixed only for designated PO lines.

## Findings

| ID | Severity | Finding |
|---|---|---|
| R8-F1 | Medium | A credit note and a retention release were approved after their fiscal period was CLOSED. Both are APPROVED and in the contract position, and the credit blocks receipts. Their journals cannot post: "fiscal period is CLOSED — posting refused". |
| R8-F2 | Medium | `serk_database_posture()` reports `TEMP is granted on the database to tenant login postgres` on a correctly hardened database. Every cluster has a superuser, and `cmd/serk-api` exits in production whenever the check reports anything. |
| R8-F3 | Medium | R7-F4 netting nets by amount on the cost code, not by the stock's origin. In one probe, 12 t (1,014,000) bought on P-001 and consumed by P-002 left P-001's available unchanged and reduced P-002's by 1,014,000 (double count). In another, 17 t consumed on 01-MAT, 5 t of it a count surplus (422,500), left 01-MAT's available unchanged. |
| R8-F4 | Low | Credit notes and retention releases dated in the future (2026-11-11, today 2026-10-22) are recorded and approved now. Stock documents refuse future dates since R7-F3. |
| R8-F5 | Low | Credit note VAT is rounded per note. Ten credits of 0.10 credit VAT 0.20 where 15% of 1.00 is 0.15. Ten credits of 0.30 credit 0.40 instead of 0.45. |
| R8-F6 | Low | A transfer is scoped by its source warehouse only. A P-001-scoped inventory controller, for whom the P-002 warehouse is "not found", approved moving 12 t into it. The P-002 storekeeper holds the 12 t but sees 0 transfer documents, and gets "not found" on the transfer. |
| R8-F7 | Low (conditional) | The posture check misses equivalent exposures. With CREATE on schema `public`, the tenant login wrote `stock_balances` (+1,000 t) through its own trigger. With `pg_try_advisory_xact_lock(bigint)` re-granted, it took the relay leader lock 727002. The posture output was unchanged both times. |
| R8-F8 | Low | R7-F5 is fixed only for designated PO lines. On an undesignated line, the storekeeper's first put-away chooses the item: "Reinforcement steel" was put away as CU-WIRE-16 (12 t, 1,014,000) with no checker. |
| R8-I1 | Info | The surplus cost basis "this warehouse first" takes the warehouse's own older receipt (84,500). That warehouse holds only transferred layers at 120,000. |
| R8-I2 | Info | Any `ar.credit.create` / `ar.retention.create` holder can cancel another clerk's draft credit or release. Stock transfers restrict this to the preparer. |

---

### R8-F1 (Medium): AR documents approved after their period closed

**Evidence** (`TestR8_ARApprovalAfterPeriodClose`):
```
period FY2026-Q4 (the only period, covering 2026-10-22) CLOSED while credit note 729ef6cc and release ac3ebe83 are DRAFT
OPEN: credit note APPROVED after its period was closed; its journal 4fbf78fd: approve ok=true  / post ok=false fiscal period is CLOSED — posting refused
OPEN: retention release APPROVED after its period was closed; its journal 42b0cc21: approve ok=true  / post ok=false fiscal period is CLOSED — posting refused
contract position: invoiced 5841000 credited 230000 retention held 165500 released 100000 receivable open 5711000
  AR recon Accounts receivable   sub 5841000 gl 5841000 diff 0 open 2
  AR recon Retention receivable  sub  265500 gl  265500 diff 0 open 1
receipt of the full original invoice after the closed-period credit: ... invoice CINV-2026-000001 cannot take this allocation ... is credited
```

**Cause.**
- The period is checked only at recording:
  - `customer_credit_notes_period` is `BEFORE INSERT` only (0022:132–140);
  - `retention_releases_period` is `BEFORE INSERT` only (0023:112–120).
- The approval branches have no period check:
  - credit note, 0022:100–117;
  - release, 0023:84–98.
- The kernel does not check either (`credit.go:69–104`, `retention.go:84–119`).
- 0024/0025 added exactly this re-check at approval for stock documents (`stk_document_date`, 0025:104–117), but it was not applied to the two new AR documents.

**Why it matters.**
- An approved credit immediately reduces what the invoice can receive (`ar_invoice_credited`), as the refused receipt above shows.
- An approved release immediately becomes collectable.
- The GL cannot follow. AR_* journals cannot be cancelled or reversed: the existing tests assert "not reversed".
- So the subledger and the closed period disagree until someone reopens a closed period to post into it.
- The reconciliation flags it only as "open 2 / open 1" with difference 0.

**Fix.**
- Re-check `credit_date` / `release_date` against an OPEN period of the entity in the DRAFT→APPROVED branch of both guards. Reuse a generic date trigger like `stk_document_date`.
- Mirror the check in Go so the API returns 422.

### R8-F2 (Medium): the posture check flags every superuser, so production cannot start

**Evidence** (`TestR8_PostureCheck`). TEMP is revoked from PUBLIC, and the tenant login does not hold it.
```
posture with TEMP revoked from PUBLIC and from serk_t_1c13fc93…: ["TEMP is granted on the database to tenant login postgres"]; superusers [postgres]
OPEN: the posture check reports superuser "postgres" as a tenant login (...); cmd/serk-api exits in production whenever it reports anything
```
Database survey (psql on `serk_review8`):
- `has_schema_privilege('serk_app','public','CREATE') = f`;
- `has_database_privilege('public', db, 'TEMP') = f`;
- no advisory function is executable by `serk_app`.

**Cause.** The query at 0024:351–353 is `pg_has_role(r.oid, 'serk_app', 'MEMBER') AND has_database_privilege(r.oid, current_database(), 'TEMP')`.
- Both functions return true for a superuser.
- Every PostgreSQL cluster has the bootstrap superuser, and managed services have their own (for example `rdsadmin`).
- `cmd/serk-api/main.go:58–63` exits with status 1 in production when the list is non-empty.
- The R7 regression test asserts only that the tenant role *is* listed, never that nothing else is.

**Why it matters.**
- After 0024, the API cannot start in production on any correctly hardened database.
- An always-failing control invites a workaround, such as running with a non-production environment or removing the check. Either one also disables the R7-F9 protection.

**Fix.**
- Exclude `rolsuper` roles, and the schema owner and migration roles, from the TEMP query. Better, enumerate the tenant login roles from the tenant registry.
- Add a test that a hardened database reports an empty posture.

### R8-F3 (Medium): budget netting counts stock by amount, not by where it came from

**Evidence 1: double count across projects** (`TestR8_TransferAcrossProjects`). The PO is on P-001 01-MAT; 12 t of steel is put away in the P-001 store, transferred to P002-STORE, and issued there to P-002 02-MAT.
```
before: P-001 01-MAT committed 2160000 actual 0 available 9940000; P-002 02-MAT actual 0 available 0
after P-002 consumed the 12 t (1014000): P-001 committed 2160000 actual 0 available 9940000; P-002 actual 1014000 available -1014000
OPEN: the 12 t (1014000) bought on P-001's commitment and consumed by P-002 is counted against both budgets
```

**Evidence 2: under-count** (`TestR8_BudgetNettingByCount`). 12 t is received of a 20 t + 500-bag PO, a count finds 5 t more, and all 17 t is issued to 01-MAT.
```
before: committed 2160000 actual 0 available 9940000; ... all 17 t issued to 01-MAT (1436500): committed 723500 actual 1436500 available 9940000
OPEN: 01-MAT consumed 1436500 of stock (12 t received + 5 t surplus) while 8 t of its PO are still open, yet its available budget is unchanged
```

**Cause.** `p2p_cost_position` (0024:248–270):
- computes `committed + greatest(0, inv_committed - stk_actual)`, where `stk_actual` is every STK_* journal on the code, whatever stock it consumed;
- leaves the source code's inventory commitment in full when its stock is consumed elsewhere;
- nets any stock consumed on the code against that code's own open purchase commitment.

The R7 report warned that keeping the commitment "breaks if the stock is issued to a different cost code or project". Migration 0025 makes cross-project movement a supported flow.

**Why it matters.** The PR/PO budget gate and the project cost report use this function.
- Case 1 refuses legitimate purchases on P-001, the same harm R7-F4 described.
- Case 2 shows 422,500 more budget than the code actually has, until the rest of its PO is consumed. A PR approved in that window passes the gate.

**Fix.** Choose one of these:
- Follow R7's first option: exclude PO lines on inventory accounts from the cost-code commitment, and let STK_ISSUE actuals carry the cost (inventory is an asset until issued).
- Or net per stock origin: link `stock_consumptions` → layer → `stock_receipts` → PO line → cost code. Release the commitment of the *source* code, and charge the consuming code only for stock that came from elsewhere.

### R8-F4 (Low): future-dated credit notes and releases

**Evidence** (`TestR8_ARFutureDated`):
```
OPEN: credit note dated 2026-11-11 (today 2026-10-22) recorded and APPROVED now; credited 230000 already counts in the position and blocks receipts
OPEN: retention release dated 2026-11-11 APPROVED today (stock documents refuse future dates since R7-F3)
```

**Cause.**
- The period triggers (0022:132–140, 0023:112–120) accept any date in an OPEN period. The Go layer checks only `IsPositive` and the hash.
- Compare `stockDate` (`stock.go:411–416`) and `stk_document_date`.

**Why it matters.**
- A concession dated next month reduces the receivable today.
- The journal carries a future business date.
- The SoD approver sees only the date string.

**Fix.** Refuse `credit_date` / `release_date` later than `current_date`, both in SQL at insert and approval and in Go.

### R8-F5 (Low): credit-note VAT rounded per note

**Evidence** (`TestR8_CreditVATPerNoteRounding`):
```
OPEN: 10 credit notes of net 0.10 credit VAT 0.2; VAT at 15% on the credited 1 is 0.15 (difference 0.05, 133% of the correct VAT)
OPEN: 10 credit notes of net 0.30 credit VAT 0.4; VAT at 15% on the credited 3 is 0.45 (difference -0.05, 89% of the correct VAT)
```

**Cause.** `NEW.vat_amount := p2p_round(NEW.net_amount * pol.vat_rate, …)` per note (0022:88), using half-even rounding.
- Neither the cumulative credited VAT nor the invoice's own VAT bounds it. The approval caps only the total and the net (0022:107–113).

**Why it matters.**
- Output VAT can be reduced by more, or less, than the VAT on the credited revenue.
- The gain is under half a cent per note, and each note needs an MFA approval, so the money is small. It does break VAT-to-revenue consistency per invoice.

**Fix.**
- Use cumulative rounding: `vat := round((credited_net + net) × rate) − credited_vat`, mirroring R7-F7.
- Cap the credited VAT at the invoice's `vat_amount`.

### R8-F6 (Low): transfer scope covers the source warehouse only

**Evidence** (`TestR8_TransferAcrossProjects`):
```
held: a P-001 storekeeper requesting a transfer into a P-002 warehouse refused: store: not found
OPEN: a P-001-scoped inventory controller, for whom the destination warehouse is "store: not found", approved moving 12 t into it
info: P-002 storekeeper sees 12 t on hand in P002-STORE, 0 stock_transfer documents in the list, and the transfer detail -> store: not found
```

**Cause.**
- `docProject("stock_transfer")` uses only `from_warehouse_id` (`kernel/p2p.go:86–88`), and so does the list SQL (`p2prepo.go:305`).
- `CreateStockTransfer` checks both warehouses (`stock_transfer.go:43–47`), but `ApproveStockTransfer` uses only `loadDoc` (`stock_transfer.go:75`).

**Why it matters.**
- The checker approves a movement into a store, and a project, they are not entitled to see.
- The receiving custodian cannot see the document that delivered the stock into their store.
- The list label also discloses the destination warehouse code to source-project readers.

**Fix.**
- Require visibility of both warehouses at approval, reject and cancel.
- Make a transfer visible to principals who can see either warehouse, in both detail and list.

### R8-F7 (Low, conditional): the posture check misses equivalent exposures

**Evidence** (`TestR8_PostureCheck`; grants applied only inside `serk_review8` and reverted):
```
with CREATE on schema public granted to serk_t_…: posture ["TEMP … postgres"]; trigger write: <nil>; steel now 1012 t at 1014001
OPEN: (conditional) with CREATE on a schema, the tenant login wrote stock_balances (+1,000 t) through its own trigger and the posture check did not name it
with pg_catalog.pg_try_advisory_xact_lock(bigint) executable by PUBLIC: posture [unchanged]; tenant login takes it: true <nil>
OPEN: (conditional) a tenant login takes advisory lock 727002 (the relay leader lock) …
```

**Cause.**
- The function checks only TEMP (0024:351–353) and `pg_advisory_lock(bigint)` for `serk_app` (0024:355–356).
- The trigger-depth guard can be raised from *any* schema where the login can create a table and trigger, or from a table it owns.
- There are 12 advisory-lock functions. `deploy/02` revokes all of them; the check verifies one.
- The relay uses `pg_try_advisory_xact_lock(727002)` (`internal/relay/relay.go:103`).

**Why it matters.**
- The R7-F9 compensating control can show clean while the same bypass is open.
- Both cases need a misconfiguration (PG16 defaults are safe), hence Low.

**Fix.**
- Also report:
  - CREATE on any schema;
  - ownership of any relation or function;
  - TRIGGER privilege for tenant logins;
  - every `pg_catalog` function named `%advisory%`, checked for each login.
- Better, close R7-F9 at the root: make the `stk_*` writers SECURITY DEFINER and revoke the tenant role's write grants on the valuation tables.

### R8-F8 (Low): put-away item identity for undesignated PO lines

**Evidence** (`TestR8_PutAwayUndesignatedLine`):
```
OPEN: PO line 1 'Reinforcement steel Grade 60' (no designated item) put away by the storekeeper as CU-WIRE-16: 12 t valued 1014000, no checker
```

**Cause.**
- The identity check runs only when `pl.stock_item_id IS NOT NULL` (0024:92–94). The "one line is one item" check (0024:96–101) binds to whatever item the *first* put-away chose.
- `CreatePOFromAward` still creates inventory-account lines with no item.

**Why it matters.** This is the R7-F5 scenario on any PO raised without item designation: item-level quantities and values are assigned by the custodian alone. The GL is unaffected.

**Fix.** Require `stock_item_id` on PO lines whose account is a stock inventory account, at PO creation, or require a checker for the first put-away of an undesignated line.

### R8-I1 (Info): the surplus cost basis after transfers

**Evidence** (`TestR8_SurplusCostAfterTransfer`):
```
info: store A holds only transferred layers at 120000; a surplus there is valued at 84500 (A's own older receipt), the latest receipt of the item is 120000
```

**Cause.** `stk_last_receipt_cost` orders by `(r.warehouse_id = p_wh) DESC, r.created_at DESC` (0024:62–67). Transfer layers are not receipts.

The value is fixed at recording and shown to the approver, so this is a disclosed choice, not a hidden one. Consider "latest receipt of the item" or "latest layer in this warehouse".

### R8-I2 (Info): who may cancel AR drafts

**Evidence** (`TestR8_HumanDecisionsAndScope`):
```
info: a second AR clerk (not the issuer, not an approver) cancelled credit note 84bfb3aa (stock transfers allow only the preparer)
info: a second AR clerk cancelled retention release 9ab8cb4e
```

**Cause.** `CancelCreditNote` / `CancelRetentionRelease` accept any holder of the create or approve permission (`credit.go:112`, `retention.go:126`). The doc comment says "the issuer or an approver".

---

## Held (with executed evidence)

**Over- and under-collection.**

`TestR8_CreditAfterPartialPaymentAndRelease`, in order:
1. 5,000,000 received on a 5,841,000 invoice.
2. A credit totalling 920,000 is refused: `exceeds what is open … received 5000000, credited 0`.
3. A credit of net 731,304.35 (total 841,000) is approved.
4. A receipt of 0.01 is refused (`is credited`).
5. Release 265,500 is approved, and a further credit of 1.00 is refused.
6. The release is received.

After posting:
- GL AR 0, retention 0, VAT −686,804.35, revenue −4,578,695.65;
- position open 0;
- every AR reconciliation row is 0, and only the 0.01 line is unapplied.

**Concurrency.**
- `TestR8_ConcurrentCreditsAndReceipt`: 3 rounds of two credits (49% of gross each) racing a 30% receipt.
  - In every round exactly one credit and the receipt succeeded.
  - Credited plus received stayed at or below the invoice total: 4,744,485 ≤ 5,841,000; 2,975,355 ≤ 3,663,000; 1,644,040 ≤ 2,024,000.
- `TestR8_ConcurrentReleaseReceipts`: two receipts of 200,000 on a 265,500 release. One was confirmed; the other was refused with `would be over-allocated`.
- `TestR8_TransferLifecycleAndRaces`:
  - Two concurrent whole-balance transfers: one was approved, the other refused with `insufficient stock … 0.0000 on hand`.
  - A destination count followed by an incoming transfer: the count was refused as `stale`.
  - A transfer approved after period close was refused (`not in an open fiscal period`).

**Transfer valuation** (`TestR8_TransferFractionalNoResidue`). FIFO steel at 84,500.333333 / 86,000.777777 / 85,123.456789, and WAC cement at 940.37 / 951.13 / 947.777777, went through:
- 6 transfers (1.5 and 2.7777 t splitting layers; 111.1111 and 77.7777 bags);
- a surplus COUNT layer at B, followed by moving B's whole steel, including that layer, back to A;
- 21 fractional issues and exact closes.

Results:
- Each transfer's amount equals its consumptions and, for FIFO, its destination layers. For example, 391,255.74 = 391,255.74 = 391,255.74.
- Balances = layers = documents after every step.
- Closing balances 0, layers 0, documents 0, GL 0, no residue rows.
- All six stock reconciliation rows are 0.

**Raw SQL as the tenant role.** Every attempt below was refused, with the stated error (`TestR8_RawSQL_AR`, `TestR8_RawSQL_Stock`):

| Attempt | Refused with |
|---|---|
| Credit note insert with forged VAT 0 / total 1000 | The trigger rewrote it to 150 / 1150; refused at commit: `requires a verified approval attestation` |
| Swap `journal_id` on an APPROVED credit | `column journal_id cannot be changed` |
| APPROVED→CANCELLED on a credit | `illegal … transition` |
| Raw approval of a credit, reusing another credit's journal | attestation required |
| Raw approval of a release | attestation required |
| Release insert of 999,999 | `would exceed the retention held 265500` |
| Contract line into an ACTIVE contract | `change only while the contract is DRAFT` |
| Allocation with two targets | `receipt_allocation_one_target` |
| Receipt to a DRAFT release | refused at confirm: `status DRAFT` |
| Allocation added to a CONFIRMED receipt | refused |
| Tenant-role journal insert | `permission denied for table journals` |
| Schema-owner journal with key `P2P:AR_CREDIT:…` | reserved-key trigger |
| Schema-owner journal with key `p2p:ar_credit:…` | reserved-key trigger |
| Schema-owner journal with an upper-case `source_ref` | binding trigger: `no AR_CREDIT document references it` |
| Transfer insert with an amount | refused |
| Transfer insert, unattested | attestation required |
| Raw transfer approval | attestation required |
| Change of quantity or destination | permission denied |
| `stock_layers` TRANSFER insert | `written only by stock documents` |
| `po_lines.stock_item_id` update | permission denied |
| New PO line on an APPROVED PO | `added only while the PO is DRAFT` |
| APPROVED transfer → DRAFT or CANCELLED | `illegal transition` |

After the key attempts, the draft credit still approved, so no pre-claim DoS occurred.

**Human decisions, SoD, scope** (`TestR8_HumanDecisionsAndScope`, plus the existing Journey tests):
- AI and service principals cannot approve credits or releases (`reserved to human principals`).
- Go `IsDraftAction` and SQL `approval_is_draft_action` agree on all 11 new or changed actions, including `stock.receipt.create` = not draft.
- Another project's commercial manager gets `not found` on the detail, 0 rows in the list, and `not found` on approval.
- The AR clerk, commercial manager and controller can read and list credit notes and releases. The storekeeper, inventory controller and controller can read and list transfers. There is no R7-F6-style 500.

## Not tested

- HTTP-level behaviour of the new routes (validation codes, JSON shape). The kernel is the policy point, and the existing httpapi suite passes (`full-suite.txt`).
- Multi-entity tenants, and contract-policy version changes between invoice and credit or release. `contract_policy_for` (current policy) is used for receipts while invoices and credits use their own policy, so a policy change could split AR across accounts. This is pre-existing and not probed.
- Reopening a closed period and then posting an R8-F1 journal, and the period-close prerequisites for unposted AR journals.
- Allocation of a receipt to another customer's release or invoice within the same entity. The guards check entity and currency only; this is pre-existing for invoices.
- An invoice VAT base of `GROSS` (only `GROSS_LESS_ADVANCE`, the fixture policy, was exercised), and credits on invoices with advance recovery.
- Load: `stock_gl_reconciliation`, `p2p_cost_position` and FIFO loops on large data.
- Browser UI.

---

## Resolution (delivering team, 2026-10-22): migration 0028 and kernel changes

The fixes below were written by the delivering team, not by the reviewer. They are **AI-verified with executed tests and have not been independently re-reviewed**. Every finding is in `docs/audit/ISSUE_REGISTER.md` and `docs/release/REMEDIATION_REGISTER.yaml`.

**A note on provenance.** The reviewer's probe file was lost when its worktree was removed. It was reconstructed from the review session's recorded edits before the fixes were applied. The reconstruction reproduced every OPEN result in this report (`docs/testing/evidence/review8-probes-before-fix.txt`). The probes were then kept as regression tests (`internal/kernel/review8_regression_test.go`). Two of them were rewritten to assert the corrected semantics, as noted below, rather than the original "OPEN" condition.

| ID | Resolution | Proof after the fix |
|---|---|---|
| R8-F1 | `ar_document_date()` triggers on both tables: the date must fall in an OPEN period of the entity, both at recording and on DRAFT→APPROVED. | `held: credit note approval in a closed period refused: … document date 2026-10-22 is not in an open fiscal period`; the same holds for the release. |
| R8-F2 | The posture check examines only LOGIN, non-superuser members of `serk_app`. | `posture with TEMP revoked …: []; superusers [postgres]` |
| R8-F3 | **Semantics changed** (ADR 0012 addendum). An inventory PO line commits `greatest(0, commitment − put-away value)`, and the issue's cost code bears the cost. The R7-F4 netting was removed. | Across projects: put-away released 1,014,000 on P-001 (available 9,940,000 → 10,954,000), the transfer and the P-002 issue left P-001 unchanged, and P-002 fell by 1,014,000. By count: 17 t issued to 01-MAT (1,436,500) reduced available 10,954,000 → 9,517,500. `TestR7_BudgetDoubleCount` was rewritten to the same semantics. |
| R8-F4 | Future dates are refused in SQL at insert, and in Go (422). | `credit note dated 2026-11-11 refused`; the same holds for the release. |
| R8-F5 | **Acceptance proposed, not in force** (ADR 0011 addendum). VAT stays per document, because each note's VAT must equal its own net × rate. The test asserts that per-note VAT equals 10 × round(net × 15%) and that the total drift is at most 10 × 0.005. Acceptance requires a named human tax/finance risk owner. | `accepted (R8-F5): 10 notes of net 0.10 carry VAT 0.2; VAT on the total 1 would be 0.15` |
| R8-F6 | Approving a transfer requires visibility of both warehouses. | `held: P-001-scoped controller cannot approve into P-002: store: not found` |
| R8-F7 | The posture check also reports CREATE on any schema and every `pg%advisory%` function executable by `serk_app`. | Both conditional grants are now named in the posture output. Residual: R7-F9's root fix (SECURITY DEFINER stock writers) is not built, so this guard still depends on the posture staying clean. |
| R8-F8 | Put-away from an undesignated line is refused. Procurement designates the item once, through the kernel. That designation is attested (`po.line.designate`), human-only in both Go and SQL, matched to the line's unit, account and entity, and allowed only before any put-away. Console: "Designate stock items" on an approved PO. | `held: … does not name its stock item`; raw tenant-role designation refused (attestation required); AI and service principals refused; a mismatched item refused; re-designation after put-away refused. Browser Journey C step 1b. |
| R8-I1 | The surplus cost basis is the item's most recent receipt in any warehouse. | `TestR8_SurplusCostAfterTransfer` PASS |
| R8-I2 | Only the preparer or an approver can cancel a draft credit or release. | `TestR8_HumanDecisionsAndScope` PASS |

**Executed evidence**
- Full race suite on a fresh database (`serk_full28`): 291 PASS, 0 FAIL, 0 SKIP, including the four browser journeys (A, B, C, planning). See `docs/testing/evidence/full-suite-review8-fixes-fresh-db.txt`.
- After that run, `TestR8_PutAwayUndesignatedLine` was extended with the designation-path probes. The R7 and R8 sets were then re-run with `-race` on a fresh database (`serk_r8final`): 29 PASS, 0 FAIL. See `docs/testing/evidence/review8-regression-after-fix.txt`.

**Not done.** An independent re-review of 0028 and of 0026–0027 (variations, planning) is still outstanding. The HTTP-level and multi-entity items listed under "Not tested" remain untested.
