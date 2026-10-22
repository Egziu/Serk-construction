# Review 7: Journey C stock valuation (migration 0021) at commit 067e08d

Independent review. Every claim below comes from a probe that was run against the disposable database `serk_review7` (PostgreSQL 16, Go 1.26.10, `-race`).

- Probes:
  - `internal/kernel/zz_review7_test.go`
  - `internal/httpapi/zz_review7_test.go`
- Raw output: `probe-output.txt`
- Regression run: `full-suite.txt`

## Verdict

**Not ready to sign off for books-of-record use. Four Medium defects need fixing first. None is Critical or High.**

The core engine holds up well under attack:
- FIFO and WAC arithmetic leaves no residue.
- The tenant runtime role cannot write valuation state directly, either with raw SQL or through attestation games.
- Put-away and issue/count concurrency are serialised.
- Separation of duties and the human-only rule hold.

The defects are around the edges of the engine:
- **Surplus valuation.** A surplus count is valued at the "average" of a near-empty balance, which rounding has distorted. The book value can be pushed to zero or inflated.
- **Reconciliation.** It never compares the stock subledger to the GL, so it can show all zeros while the two differ.
- **Unvalidated dates.** Issue and count dates can produce approved documents whose journals can never be posted.
- **Budget.** Issued stock consumes the cost-code budget a second time.

The existing suite has no regressions:
- `go test -race ./internal/kernel ./internal/httpapi` (with the R7 probes skipped) passes.
- The browser tests for Journeys A, B and C also pass.

## Findings

| ID | Severity | Finding |
|---|---|---|
| R7-F1 | Medium | A surplus count is valued at `value/qty` of the current balance even when that balance is a rounding remainder. 1,000 bags were booked at 0 (then issued to the project free), or at 167% of cost. |
| R7-F2 | Medium | `stock_gl_reconciliation` never compares stock balances with the GL. Put-away from a GRN whose journal is unposted leaves stock 422,500 above GL, yet every row shows difference 0 and open 0. |
| R7-F3 | Medium | `issue_date` and `count_date` are not validated (no future-date check, no period check). Approved issues and counts move stock, but their STK journals can never post. Subledger journals cannot be cancelled or reversed, so the break is permanent. |
| R7-F4 | Medium | Budget is double-counted. The inventory PO stays committed on the cost code, and the STK_ISSUE expense is added as `actual_other`. Available budget fell by the full issue value (845,000). |
| R7-F5 | Low | Put-away is not tied to the PO line's item. A steel GRN line was put away as "Copper wire" because only unit and account must match. An AI principal can also perform this final, unchecked movement. |
| R7-F6 | Low | `GET /v1/p2p/stock_receipt/{id}` returns 500 for every receipt, because `stock_receipts` has no `status` column. |
| R7-F7 | Low | Partial put-aways are not capped by the line's remaining value. Stock exceeded the GRN debit, the completing put-away is permanently refused, and the reconciliation still shows all-zero differences. |
| R7-F8 | Low | A `journal.create` holder can pre-claim the idempotency key `p2p:STK_ISSUE:<issue id>` with a manual journal. That issue then can never be approved. |
| R7-F9 | Low (conditional) | `stk_state_guard` depends only on `pg_trigger_depth()`. Where TEMP is not revoked (0006 only issues a NOTICE when not run as superuser), a tenant login wrote `stock_balances` (+1,000 t) through a `pg_temp` trigger. |
| R7-I1 | Info | List and detail differ for central stock. A project storekeeper's `stock_receipt` list includes put-aways into a central warehouse (code and amount), while that warehouse is "not found" to them. Project storekeepers also cannot issue from central warehouses. |

---

### R7-F1 (Medium): surplus valued from a rounding remainder

**Evidence** (`TestR7_SurplusValuedFromRoundingRemainder`):
```
after issuing 299.9999 of 300 at 10.40: book 0.0001 bags valued 0
surplus of 1000 bags valued 0 (journal ""); at the receipt price it is 10400; book now 1000.0001 bags at 0
OPEN: 500 of those bags then issued to the project at cost 0 (no STK_ISSUE journal)
after issuing 299.9999 of 300 at 60.00: book 0.0001 bags valued 0.01
surplus of 1000 bags valued 100000 (journal "f409…"); at the receipt price it is 60000 ...  (167% of cost)
```

**Cause.** `stock_counts_guard` sets `unit := b.value / b.qty` whenever `b.qty > 0`.

- `stk_consume` rounds each WAC/FIFO take to the currency unit.
- So a residual balance (for example 0.0001 units) carries a value of 0.00 or 0.01, which says nothing about real cost.
- The balance CHECK `qty > 0 OR value = 0` explicitly allows qty > 0 with value 0.

**Why it matters.**
- The storekeeper controls the issue quantities and the count quantity.
- The inventory controller approves a count before its value exists: the amount is computed inside the approval.
- Inventory, the variance account and later project cost are then misstated. In the zero case, stock issued afterwards carries no cost and no journal at all.

**Fix.**
- Value surpluses at a cost basis that cannot be distorted. Options:
  - the last receipt cost, or a configured standard cost;
  - for FIFO, the latest layer's `unit_cost`;
  - the average only when the balance is material, for example above a qty threshold or when `value >= qty * min_unit_cost`.
- Refuse a surplus valued at zero.
- Show the computed amount to the approver; ideally fix the value at count creation and re-check it at approval.

### R7-F2 (Medium): the reconciliation does not reconcile stock to the GL

**Evidence** (`TestR7_ReconSharedAccountUnposted`). Two GRNs were received. GRN A's journal was posted; GRN B's (5 t, 422,500) was left DRAFT. Both were put away into two stores.
```
recon Inventory: 1200 Inventory           sub 685500  gl 685500  diff 0 open 0
recon Received, not yet put away: 1200    sub      0  gl      0  diff 0 open 0
recon Stock balances vs documents: 1200   sub 1108000 gl 1108000 diff 0 open 0
recon Cost layers vs stock balances: 1200 sub 1108000 gl 1108000 diff 0 open 0
GL inventory 685500; stock balances 1108000
```

**What the rows actually compare:**
- The "Inventory" row compares the GL with *GRN documents plus movements*. It never uses `stock_balances`.
- "Received, not yet put away" filters both terms on posted GRN journals. Put-aways from unposted GRNs therefore drop out of every row.
- That row also has `difference = NULL` (shown as 0 through `COALESCE` in the Go layer), so a negative value is never flagged. See F7, where the row reads −0.01 with difference 0.
- Unposted GRNs are not counted in `unposted_documents`.

**Why it matters.** The report shows zero differences and zero open documents while the stock subledger exceeds the GL by 422,500. That is precisely the situation a stock-to-GL reconciliation exists to catch. ADR 0012 §8 calls this check "Inventory against GL".

**Fix.**
- Add a row: Σ`stock_balances.value` against the GL, with explicit reconciling items:
  - put-away from GRNs whose journal is not POSTED;
  - posted GRN value not yet put away;
  - approved issues and counts whose journal is not POSTED.
- Require the residual to be 0.
- Give "Received, not yet put away" a difference column, flag it when it is negative, and count unposted GRNs on the account.

### R7-F3 (Medium): issue and count dates can strand journals permanently

**Evidence** (`TestR7_IssueDateOutsidePeriods`, and over HTTP in `TestR7_API_StockReceiptDetailAndIssueDate`):
```
OPEN: issue dated 2031-01-01 APPROVED (stock now 11 t), journal …: approve ok=true / post ok=false no fiscal period covers 2031-01-01 ...
OPEN: count dated 2025-06-30 APPROVED (stock 11 -> 10.5 t), journal …: approve ok=true / post ok=false no fiscal period covers 2025-06-30 ...
OPEN: count dated 2031-01-01 APPROVED (stock 10.5 -> 10 t) ... post ok=false
recon Inventory: 1200 Inventory  sub 1014000 gl 1014000 diff 0 open 3
HTTP: POST /v1/stock-issues {"issue_date":"2031-01-01"} -> 201; approve 200; post-batch: "no fiscal period covers 2031-01-01"
```

**Where the dates are and are not checked:**
- A past-dated *issue* was refused only by accident: the cost code's `valid_from` caught it.
- Counts carry no cost code, so a past-dated count is accepted.
- The fiscal-period check runs only at POST.
- By contrast, `grns_guard` refuses a future `received_on` (0013 line 1273).

**Why it matters.**
- The storekeeper chooses the date and the approver does not see its effect.
- Stock moves and project cost is recognised in the subledger, but the GL never receives the journal.
- STK journals cannot be cancelled (`journals_subledger_guard`) or reversed, and the document cannot be corrected.
- The only way out is an operator creating or reopening a period for that date. A closed or locked period behaves the same way.

**Fix.**
- In `stock_issues_guard` and `stock_counts_guard` on INSERT, require the date to be `<= current_date`.
- Require it to fall in an OPEN fiscal period of the entity. Re-check this at approval, and possibly a back-dating window.
- Mirror the check in Go so the API returns 422.

### R7-F4 (Medium): budget consumed twice for issued stock

**Evidence** (`TestR7_BudgetDoubleCount`, `ProjectCostReport` on cost code 01-MAT):
```
before issue: budget 12100000 committed 2160000 actual_other 0      available 9940000
after issue of 845000: budget 12100000 committed 2160000 actual_other 845000 available 9095000
```

**Cause.** `p2p_cost_position` works as follows:
- It counts the inventory PO line as committed against its cost code.
- It excludes only `P2P_GRN` journals from `actual_other`.
- The new STK_ISSUE expense line carries the issue's cost code. The same stock therefore reduces available budget twice: once as the PO commitment and again as the issue actual.

**Why it matters.**
- The project cost report understates available budget.
- The PR/PO budget gate (0013 line 960) uses the same function, so legitimate purchases are refused once the stock has been issued.

**Fix.** Choose one of these:
- Exclude PO lines on stock inventory accounts from the cost-code commitment, and let issues carry the cost.
- Or keep the commitment and exclude STK_ISSUE actuals, though this breaks if the stock is issued to a different cost code or project.

The first option is consistent with "inventory is an asset until issued".

### R7-F5 (Low): put-away item identity; AI put-away

**Evidence** (`TestR7_PutAwayItemIdentityAndAI`):
```
OPEN: PO line 1 (Reinforcement steel Grade 60) put away as CU-WIRE-16: 12 t valued 1014000
OPEN (design): an AI principal put away 300 bags (receipt …) - a final, unchecked valuation movement under a draft action name
```

**Cause.**
- `stock_receipts_guard` checks only `pl.account_id = it.inventory_account_id` and the unit. Nothing links a PO line to an item.
- `stock.receipt.create` matches the `.create` draft pattern, so AI and service principals pass the human rule.
- Yet a put-away is immediately effective and has no checker.

The GL is unaffected, but item-level quantities and valuations can be reassigned at will by the custodian.

**Fix.**
- Carry `stock_item_id` on PR/PO lines, or require it at GRN, and enforce equality at put-away.
- Treat put-away as a human decision, or add a checker.
- Correct ADR 0012's statement that put-aways are "drafts".

### R7-F6 (Low): stock receipt detail is broken

**Evidence:**
```
GET /v1/p2p/stock_receipt/4feb2f61 by storekeeper -> 500 {"code":"internal"}
kernel: can't scan into dest[2] (col: coalesce): cannot scan NULL into *string
```

**Cause.** `postgres.GetDoc` selects `COALESCE(status, technical_status)`, and `stock_receipts` has neither column. Every receipt detail read, and any `loadDoc` on a receipt, fails.

**Fix.** Give `stock_receipts` a status (for example the constant 'POSTED', as the list query already shows), or make GetDoc tolerate a NULL status.

### R7-F7 (Low): partial put-aways can exceed the line's value

**Evidence** (`TestR7_PartialPutAwayOvershoot`). The GRN line was 0.0106 at 1.5, which debited 0.02.
```
three put-aways of 0.0035 carry 0.03; completing put-away: put-away value would be negative (integrity)
recon Received, not yet put away: 1200  sub -0.01 ... diff 0
```

**Cause.**
- Each non-completing put-away rounds `qty*price` independently, and nothing caps the running sum at `line_amt`.
- Stock is then worth more than the GL debit.
- The line can never be completed, so the last 0.0001 is stranded.
- The reconciliation does not flag the negative remainder (see F2).

The gain is under 0.005 per put-away, so the money involved is small, but it breaks the ADR's "no rounding residue" claim.

**Fix.** Value each put-away as `round(cum_qty*price) - done_amt`, which is cumulative rounding. Refuse a put-away when `done_amt + amount > line_amt`.

### R7-F8 (Low): denial of service by pre-claiming the idempotency key

**Evidence** (`TestR7_IdempotencyKeyPreclaim`):
```
accountant creates manual journal with key p2p:STK_ISSUE:dc0a4d17: <nil>
OPEN: ... blocks the stock issue approval: store: idempotency key reused with a different command
```

**Cause.**
- `subledgerJournal` uses the predictable key `"p2p:"+doc+":"+id`.
- Manual journals may use any key.
- The issue stays DRAFT; it must be cancelled and re-requested, and the manual journal can repeat the block.

I did not test the same pattern for P2P_* or AR_* documents, but they share the code.

**Fix.** Reserve the `p2p:` key namespace (and any subledger prefix) for non-MANUAL source types in `CreateJournal` or in SQL. Alternatively, bind replay to `source_type` and `source_ref`.

### R7-F9 (Low, conditional on deployment): the trigger-depth guard depends on TEMP being revoked

**Evidence** (`TestR7_TriggerDepthGuardNeedsTempRevoked`). TEMP was granted to the tenant role to simulate a deployment where `deploy/02` was not run.
```
OPEN (conditional on TEMP not revoked): tenant login wrote stock_balances through a pg_temp trigger: steel now 1012 t at 1014001
```

**Context.**
- In the test database TEMP is revoked (`datacl {=c/postgres,...}`), so this does not reproduce by default.
- However, 0006 only raises a NOTICE when the migration owner is not a superuser.
- `deploy/02-restrict-advisory-locks.sql` hard-codes the database name `serk`.
- `serk_app` holds `UPDATE (qty, value)` on `stock_balances` and `UPDATE (qty_remaining, value_remaining)` on `stock_layers`. Any depth ≥ 2 context can write them, and `stk_consume` and `stk_receive` are callable at depth ≥ 1.

**Fix.**
- Make `stk_receive` and `stk_consume` `SECURITY DEFINER`, owned by the schema owner.
- Revoke INSERT and UPDATE on the three valuation tables from `serk_app`.
- In the guard, check `current_user` = owner rather than trigger depth.
- Fail the migration, not merely NOTICE, if TEMP is still granted to PUBLIC.

### R7-I1 (Info): list and detail parity for central stock

- `ListP2PDocs(stock_receipt)` for the project storekeeper returned 2 rows, including the put-away into CENTRAL-01, with its code and amount.
- `GetP2PDoc(warehouse, central)` returns "not found" for the same user.
- `CreateStockIssue` from the central warehouse by a project storekeeper also returns "not found". Central stores are usable only by tenant-wide principals.

This is consistent with ADR 0010's "by PO project" rule, but it discloses central-warehouse codes and values.

---

## Held (with executed evidence)

**Valuation.** FIFO was tested over 3 PO layers (6-decimal prices), each put away in 2 splits, followed by 23 issues of 0.4321 t and the exact remaining balance (`TestR7_FIFOManyLayersSmallIssues`):
- receipts 852,073.37 = issued 852,073.37;
- stock 0, layers 0, GL inventory 0;
- all four reconciliation rows 0.

WAC was tested with 3 fractional prices (940.37 / 951.13 / 947.777777) and 4-decimal splits, then 17 issues of 37.0037, a shortage count of 1.2345, and the exact balance (`TestR7_WACFractionalToZero`): stock 0 and GL 0, with no residue.

**Raw SQL as the tenant runtime role** (`TestR7_RawSQLBypass`). Each of these was refused, with the stated error:

| Attempt | Refused with |
|---|---|
| INSERT into `stock_consumptions` | `written only by stock documents` |
| DELETE from `stock_layers` | permission denied |
| UPDATE of a layer's value | refused |
| `stock_balances` INSERT … ON CONFLICT | refused |
| `stk_consume` inside a CTE | `consumed only by a stock document` |
| `stk_receive` inside INSERT … SELECT | `received only by a stock document` |
| `SET session_replication_role` | permission denied |
| `SET CONSTRAINTS ALL IMMEDIATE`, then a balance write | refused |
| Raw `stock_receipts` insert with forged amount, unattested | `requires a verified approval attestation` |
| Swapping `journal_id` after approval | `attached once, by the approving transaction` |
| Updating `amount` on an APPROVED issue | permission denied |
| Editing STK journal lines in a later transaction | permission denied |
| Cancelling an STK journal | attestation required |
| Inserting an orphan STK_ISSUE journal | permission denied |
| Raw DRAFT→APPROVED for an issue or a count | attestation required |

A posted manual 100,000 journal to inventory showed as `diff 100000` in the reconciliation.

**Concurrency** (`TestR7_ConcurrentPutAwayAndCount`):
- Of 4 concurrent put-aways of 8 t on a 12 t line, exactly 1 succeeded: `exceeds what the goods receipt line still holds`.
- Over 5 rounds of count approval racing issue approval, either the count was refused as stale or both applied in series (285 → 277). Balance = documents = layers after every round.
- The existing concurrent over-issue test passes.

**Separation of duties and human decisions:**
- AI and service inventory controllers cannot approve counts (`reserved to human principals`).
- Go `IsDraftAction` and SQL `approval_is_draft_action` agree on all 11 stock action strings.
- Self-approval, storekeeper count approval and AI issue approval are refused (existing `TestJourneyC_Controls`, passing).

**Tenant isolation.** A tenant-2 controller sees 0 stock lines for the tenant-1 entity and gets no reconciliation rows.

**Regression.** Full kernel and httpapi suites pass, and Browser A, B and C pass (`full-suite.txt`).

## Not tested

- FX: P2P is functional-currency only (`grns`/`po` guards require it), so a foreign-currency PO was not attempted.
- Period close or reopen while an STK journal is APPROVED-unposted. This affects only the close-blocking rule from 0002.
- The idempotency pre-claim for P2P_* and AR_* documents (likely the same as F8).
- An inventory account that later becomes a control account. The control check runs only at item creation.
- Load and performance of `stock_gl_reconciliation` and `stock_on_hand` on large data, and the per-row `stk_consume` loop over thousands of layers.
- Multi-entity tenants: only one legal entity was exercised in the probes.
- Browser UI behaviour for the defects above (for example the receipt detail 500 in the console).

---

## Resolution (migration 0024, 2026-10-22)

Each probe is kept as a regression test: `internal/kernel/review7_regression_test.go` and `internal/httpapi/review7_regression_test.go`. A former OPEN line now fails the test. The after-run is `docs/security/evidence/independent-review-7-after.txt`, and the full race suite is `docs/testing/evidence/full-suite-review7-fixes.txt`.

| ID | Fix | Regression test |
|---|---|---|
| R7-F1 | A surplus is valued at the item's last receipt cost (this warehouse first). The cost is recorded with the count, so the approver sees it before approving. A zero-valued surplus is refused. | `TestR7_SurplusValuedFromRoundingRemainder` (both cases within 5% of the receipt price, unit cost recorded at count time) |
| R7-F2 | New reconciliation row "Stock balances vs GL", with explicit reconciling items: put-away from unposted receipts, posted receipts not yet put away, and approved issues and counts not yet posted. New informational row "Put away from goods receipts not yet posted". "Received, not yet put away" flags a negative value. Unposted goods receipts are counted. | `TestR7_ReconSharedAccountUnposted` (422,500 shown on 1 receipt; a manual 100,000 inventory journal is a stock-to-GL difference) |
| R7-F3 | Issue and count dates are not in the future and fall in an OPEN fiscal period, checked at recording and again at approval (SQL). Go returns 422 for future or missing dates. | `TestR7_IssueDateOutsidePeriods`, `TestR7_API_StockReceiptDetailAndIssueDate` |
| R7-F4 | Stock issued to a cost code first consumes that code's open inventory purchase commitment (`p2p_cost_position`). | `TestR7_BudgetDoubleCount` (available budget unchanged by the issue) |
| R7-F5 | PO lines may designate their stock item (`po_lines.stock_item_id`, checked against entity, unit and inventory account), and put-away must match it. An undesignated line is one item: a later put-away as another item is refused. Put-away is a human decision in Go and SQL, despite its `.create` name. | `TestR7_PutAwayItemIdentityAndAI` |
| R7-F6 | `stock_receipts.status` (always POSTED). | `TestR7_Visibility`, `TestR7_API_StockReceiptDetailAndIssueDate` |
| R7-F7 | Cumulative rounding. Each put-away takes round(cumulative qty × price) less what was already taken, capped at the line's debit. | `TestR7_PartialPutAwayOvershoot` (the completing put-away succeeds and stock equals the receipt debit) |
| R7-F8 | `p2p:` idempotency keys are reserved to the subledger journal of the named document (kernel 422, and a SQL trigger on journals). | `TestR7_IdempotencyKeyPreclaim` |
| R7-F9 | `serk_database_posture()` reports tenant logins holding TEMP, or tenant logins that can execute advisory locks. The API refuses to start in production while it reports anything. `deploy/02` no longer hard-codes the database name. The SQL guard itself is unchanged: it remains a depth check, sound only while TEMP is revoked. | `TestR7_TriggerDepthGuardNeedsTempRevoked` (the posture check names the role once TEMP is granted) |
| R7-I1 | Put-aways are scoped by their warehouse: a put-away into a central warehouse needs tenant-wide scope, both in lists and in detail. | `TestR7_Visibility` |

Changed figures. Journey C's surplus of 5 bags is now valued at the last receipt cost, 950, giving **4,750** instead of the average 4,716.67. The test figures and `docs/testing/E2E_JOURNEY_C.md` are updated.

Not re-reviewed. These fixes have not been reviewed independently, and they need a human or external review before release.
