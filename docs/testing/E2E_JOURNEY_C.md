# Journey C: stock valuation, worked figures

These are the expected numbers of `TestJourneyC_StockValuationToGL` (internal/kernel/journey_c_test.go), worked out by hand. The test checks each figure against PostgreSQL. All data is synthetic, and the currency is ETB with 2 decimals.

Items: steel `STEEL-G60` (t, **FIFO**) and cement `CEM-OPC50` (bag, **WAC**). Both are on inventory account 1200, in the project store.

## Receipts

| PO | Steel | Cement |
|---|---|---|
| PO 1 | 20 t @ 84,500 | 500 @ 940 |
| PO 2 | 20 t @ 86,000 | 500 @ 950 |

**GRN 1** (PO 1): steel 12 t, cement 300 bags.

- `P2P_GRN`: Dr inventory 1,014,000 + 282,000 = 1,296,000.
- Put-away: steel 12 t (FIFO layer L1: 12 @ 84,500 = 1,014,000).
- Put-away: cement 200 bags = 188,000, then 100 bags. The second put-away completes the line, so it takes the exact remainder: 282,000 − 188,000 = 94,000.

**GRN 2** (PO 2): steel 10 t, cement 200 bags.

- `P2P_GRN`: Dr inventory 860,000 + 190,000 = 1,050,000.
- Put-away: steel 10 t (FIFO layer L2: 10 @ 86,000 = 860,000).
- Put-away: cement 150 bags = 142,500. The other **50 bags stay received but not put away**: 47,500.

**On hand after put-away**

| Item | Quantity | Value |
|---|---|---|
| Steel | 22 t | 1,874,000 |
| Cement | 450 bags | 424,500 (average 943.333…) |

## Issues (to project P-001, cost code 01-MAT, expense 5000)

**Steel, 15 t, FIFO**

| Layer | Quantity | Value |
|---|---|---|
| L1, whole layer | 12 t | 1,014,000 |
| L2 | 3 t @ 86,000 | 258,000 |
| **Issue cost** | | **1,272,000** |

Steel left: 7 t at 602,000.

**Cement, 120 bags, WAC:** 120 × 424,500 / 450 = **113,200.00**. Cement left: 330 bags at 311,300.

## Counts (variance account 5200, approved by the inventory controller)

| Item | Counted | Book | Difference | Valuation | Amount | Journal |
|---|---|---|---|---|---|---|
| Steel | 6.5 t | 7 | shortage 0.5 t | FIFO, from L2: 0.5 × 86,000 | **43,000** | Dr 5200 / Cr 1200 |
| Cement | 335 | 330 | surplus 5 | last receipt cost 950 (0024, R7-F1), so 5 × 950 | **4,750.00** | Dr 1200 / Cr 5200 |

## End state (all journals posted)

| Measure | Value |
|---|---|
| Steel | 6.5 t, 559,000 |
| Cement | 335 bags, 316,050 |
| Stock value | 875,050 |
| Received, not yet put away | 47,500 |
| **GL inventory (1200)** | 1,296,000 + 1,050,000 − 1,272,000 − 113,200 − 43,000 + 4,750 = **922,550** |
| Stock plus not put away | 875,050 + 47,500 = 922,550 ✓ |
| Project cost posted | 1,272,000 + 113,200 + 43,000 − 4,750 = **1,423,450** |

**Reconciliation checks** (`stock_gl_reconciliation`)

| Check | Result |
|---|---|
| Inventory vs GL | difference 0 |
| Received, not yet put away | 47,500 on 1 line |
| Balances vs documents | difference 0 |
| FIFO layers vs balances | difference 0 |
| Stock balances vs GL (0024) | 922,550 = 922,550, difference 0 |
| Put away from receipts not yet posted (0024) | 0 |

The P2P reconciliation (GRNI) is unchanged at 0.

**HTTP and browser journeys** use the same pattern on one receipt (12 t @ 84,500, 300 bags @ 940):

| Item | Value |
|---|---|
| Steel issued | 5 t = 422,500 |
| Shortage | 0.5 t = 42,250 |
| Inventory = GL | 831,250 |
| Steel on hand | 6.5 t = 549,250 |
| Cement received, not yet put away | 282,000 |

## Transfers (`TestJourneyC_StockTransfer`, migration 0025)

Stores A (P001-STORE) and B (P001-STORE-B).

**Receipts into A**

| Item | Received | Value |
|---|---|---|
| Steel (FIFO) | 12 t @ 84,500, then 10 t @ 86,000 | |
| Cement (WAC) | 300 @ 940 + 200 @ 950 = 500 bags | 472,000 (average 944) |

**Transfers A → B**

- Steel 15 t: 12 @ 84,500 + 3 @ 86,000 = **1,272,000**. B's layers are `12.00@84500 3.00@86000`.
- Cement 100 bags at the average: **94,400**.

**Issue 13 t of steel from B:** 12 @ 84,500 + 1 @ 86,000 = **1,100,000**. This proves the transferred layers kept their order and cost.

**After posting**

| Location | Item | Quantity | Value |
|---|---|---|---|
| A | Steel | 7 t | 602,000 |
| B | Steel | 2 t | 172,000 |
| A | Cement | 400 | 377,600 |
| B | Cement | 100 | 94,400 |

- GL inventory: 2,346,000 − 1,100,000 = **1,246,000** = stock.
- No transfer journal.
- Every reconciliation row: difference 0.

**HTTP journey:** 2.5 t moved from P-STORE to P-STORE-B at 211,250. Stock on hand is 4 t / 338,000 and 2.5 t / 211,250.

**Browser journey:** 1 t moved at 84,500. Stock on hand is 5.5 t / 464,750 and 1 t / 84,500.
