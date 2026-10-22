# ADR 0012: Stock valuation (FIFO and moving average) on the subledger pattern

Status: accepted (migration 0021). Date: 2026-10-22.

## Context

Construction materials are bought in bulk, held in project or central stores, and consumed by the work. Before this change, a goods receipt could post to an inventory (ASSET) account, but nothing tracked:

- what was then on the shelf;
- what it cost when it was used;
- which project and cost code consumed it.

Stock was therefore invisible to the project cost report and to the books after receipt.

The order (GATEB-05) asks for inventory valued FIFO or weighted average and integrated with the project and the GL. The pattern of ADRs 0009 and 0011 applies:

- documents are guarded state machines;
- the database computes the money;
- subledger journals are bound to their documents and are never reversed.

## Decision

1. **Stock items** are entity master data. Each item has:
   - a unit, which must match the purchase order line's unit;
   - a valuation method, FIFO or WAC;
   - an inventory account, which must be an ASSET and not a bank, payables or receivables control account.

   A procurement officer creates an item and a finance manager approves it.
2. **Warehouses** are project stores or central warehouses. A project store is visible only within its project's scope.
3. **Put-away** moves quantity of a CONFIRMED goods receipt line into a warehouse.
   - **No journal.** The goods receipt already debited the inventory account. The put-away only records where the stock is and creates its cost.
   - **Priced at the PO.** The line must have been posted to the item's inventory account, and the cost is the PO price.
   - **No rounding residue.** The put-away that completes a line takes the exact remainder of what the receipt debited, so no rounding residue is left between the subledger and the GL.
4. **Issues** charge stock to a project cost code.
   - The storekeeper requests an issue. A site engineer or project manager approves it; this is a human decision, and the approver must differ from the requester.
   - At approval the database values the issue:
     - FIFO consumes the oldest cost layers. A fully consumed layer gives its exact remaining value.
     - WAC uses the moving average. Issuing the whole balance gives its exact value.
   - The database refuses negative stock under a row lock, so concurrent issues cannot overdraw.
   - Approval generates `STK_ISSUE`: Dr expense (project, cost code), Cr inventory.
5. **Counts.**
   - The storekeeper records a counted quantity. The book quantity and the difference are taken by the database at that moment.
   - An **inventory controller** approves the count. This is a separate role from the journal chain, because the count's approver becomes the preparer of its journal, and that person may not also approve or post it.
   - A count is **stale** if the book quantity moved after it was recorded.
   - A shortage consumes stock at FIFO or WAC cost.
   - A surplus is valued at the current average. With nothing on hand it uses the last receipt cost; with no cost basis at all it is refused.
   - Approval generates `STK_ADJUST` between inventory and an EXPENSE variance account.
6. **Valuation state** (`stock_balances`, `stock_layers`, `stock_consumptions`) is written only inside the document triggers. Direct statements by the tenant login, or direct calls to the valuation functions, are refused (`stk_state_guard` by trigger depth).
7. **`STK_*` journals** are bound to their document, frozen at birth, re-checked at approval and posting, never cancelled and never reversed. This is the same rule as `P2P_*` and `AR_*`; the guards and the dispatch (`subledger_expected_lines`) now cover all three prefixes.
8. **Reconciliation** (`stock_gl_reconciliation`) runs per inventory account:
   - **Inventory against GL.** The subledger is the posted goods receipts on the account, plus posted surpluses, minus posted issues and shortages.
   - **Received, not yet put away.** This is a reconciling item.
   - **Running balances against documents.**
   - **FIFO cost layers against balances.**

## Consequences and limits

- Transfers between warehouses are **not** built. Moving stock today means an issue and a new receipt, which is wrong for value. This is recorded as JC-TRANSFER.
- Returns to suppliers are not built.
- Landed costs (freight, duty) are not built.
- Stock reservations against requisitions are not built.
- Serial and lot tracking is not built.
- When a supplier invoice price differs from the PO, the variance goes to the P2P price-variance account (Journey A). It is not revalued into the stock still on hand. This is the standard-cost simplification, recorded as JC-INVOICE-REVALUE.
- AI and service principals may create items, requests, put-aways and counts as drafts, but cannot approve them (0019).

## Tests

- **Kernel happy path:** `TestJourneyC_StockValuationToGL`.
  - Two POs at different prices, partial put-away.
  - A FIFO issue of 1,272,000 and a WAC issue of 113,200.
  - A shortage of 43,000 and a surplus of 4,716.67.
  - GL inventory of 922,516.67 equals the subledger. 47,500 is received but not put away.
  - Balances equal the documents, and the layers equal the balances.
  - Project cost of 1,423,483.33.
- **Kernel controls:** `TestJourneyC_Controls`. Each refusal asserts its reason:
  - a control account used as the inventory account;
  - self-approval of an item;
  - put-away beyond the receipt line;
  - put-away from a line posted to expense;
  - direct balance and engine writes;
  - negative stock;
  - self-approval of an issue;
  - AI approval;
  - journal edit and reversal;
  - a stale count, and a count that agrees with the books;
  - a surplus with no cost basis;
  - visibility across projects;
  - a concurrent over-issue.
- **HTTP:** `TestAPIJourneyC_StockValuation`.
- **Browser:** `TestConsoleBrowserJourneyC`, with 7 people doing every stock step in the UI.

## Addendum: independent review 7 (2026-10-22), migration 0024

The review findings and their fixes are in docs/security/INDEPENDENT_REVIEW_7_2026-10-22.md. Decision changes:

- **Surplus valuation (amends point 5).** A surplus is valued at the item's last receipt cost, preferring this warehouse, and never at the average of what is left. A near-empty balance is mostly rounding, so its average says nothing about cost. The unit cost is recorded with the count, so the inventory controller sees the amount before approving. A surplus with no receipt history, or with a zero value, is refused when it is recorded.
- **Put-away (amends point 3).** A put-away is immediately effective valuation with no checker step, so it is a decision reserved to human principals, not a draft. Its `.create` action name notwithstanding, the Go and SQL lists agree.
  - A purchase-order line may name its stock item when the PO is raised (`stock_items` in `POST /v1/purchase-orders`), and the put-away must match it.
  - A line raised without one is fixed to the first item put away from it.
  - Put-away values are rounded cumulatively, so they never exceed the receipt line's debit.
- **Dates.** Issues and counts are dated today or earlier, in an OPEN fiscal period. This is checked again at approval, because their journals can be neither cancelled nor reversed.
- **Budget.** Stock issued to a cost code first consumes that code's open inventory purchase commitment, so a purchase and its issue are counted once.
- **Reconciliation (amends point 8).** Two rows are added per inventory account:
  - "Stock balances vs GL", which reconciles the running stock value to the GL through explicit reconciling items;
  - "Put away from goods receipts not yet posted".
- **Visibility.** A put-away is scoped by the warehouse it went into.
- **Deployment posture.** The stock guards' trigger-depth check assumes tenant logins hold no TEMP. The API checks this at start-up through `serk_database_posture()` and refuses to start in production otherwise.

## Addendum: stock transfers (2026-10-22), migration 0025

Closes JC-TRANSFER.

- **Who.** The storekeeper requests a DRAFT transfer of one item between two warehouses of the same entity, and must be able to see both. An inventory controller approves it: a different person, a human. The approver may reject it and the preparer may cancel it, each with a reason.
- **Valuation.** At approval the database consumes the quantity from the source at cost, through the same engine as issues: FIFO layers, or the moving average. It then receives exactly that cost at the destination.
  - FIFO items keep their cost history: each consumed layer becomes a destination layer with the same unit cost, in the same order.
  - WAC items arrive at the source's average.
- **No journal.** The item, and therefore its inventory account, is the same on both sides. GL inventory, project cost and the reconciliation are unchanged; only the location changes. Transfers net to zero in "balances vs documents".
- **Dates and visibility.** Dates follow R7-F3: today or earlier, in an OPEN fiscal period, re-checked at approval. A transfer is listed under its source warehouse's project.

**Not built:** in-transit stock (goods dispatched but not yet arrived); transfers between entities, which would need an intercompany journal.

**Tests.**

- Kernel: `TestJourneyC_StockTransfer`, with figures in docs/testing/E2E_JOURNEY_C.md. It covers 9 refusals and proves that FIFO layer order survives a transfer.
- HTTP: `TestAPIJourneyC_StockValuation`.
- Browser: `TestConsoleBrowserJourneyC`, with transfer request and approval in the UI.

## Addendum: independent review 8 (2026-10-22), migration 0028

- **Budget semantics (R8-F3, replaces the R7-F4 netting).** Stock is an asset from put-away until it is issued. In `p2p_cost_position`, a purchase-order line on a stock inventory account commits `greatest(0, commitment − put-away value)`; what has been put away no longer burdens the ordering cost code, and the cost code named on the stock issue bears it as actual (`STK_ISSUE`). Count variances are actual cost of the code they are charged to. Consequences: stock bought on one project and transferred to and issued on another is charged once, to the consumer; budget released by put-away returns to the ordering code; between put-away and issue the stock is in no project's budget (it is visible in the stock valuation report).
- **Item designation (R8-F8).** Nothing is put away from a purchase-order line on a stock inventory account until the line names its stock item. Procurement (`po.manage`, human-only) may designate an undesignated line of an approved order once, by an attested decision (`po.line.designate`), while nothing has been put away from it. The storekeeper cannot.
- **Surplus cost basis (R8-I1).** A count surplus is valued at the item's most recent receipt cost in any warehouse (transfer layers are not receipts).
- **Transfer scope (R8-F6).** Approving a transfer requires visibility of both warehouses.
