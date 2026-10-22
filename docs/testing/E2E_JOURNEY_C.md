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
| Cement | 335 | 330 | surplus 5 | average 311,300 / 330 = 943.3333…, so 5 × 943.3333… | **4,716.67** | Dr 1200 / Cr 5200 |

## End state (all journals posted)

| Measure | Value |
|---|---|
| Steel | 6.5 t, 559,000 |
| Cement | 335 bags, 316,016.67 |
| Stock value | 875,016.67 |
| Received, not yet put away | 47,500 |
| **GL inventory (1200)** | 1,296,000 + 1,050,000 − 1,272,000 − 113,200 − 43,000 + 4,716.67 = **922,516.67** |
| Stock plus not put away | 875,016.67 + 47,500 = 922,516.67 ✓ |
| Project cost posted | 1,272,000 + 113,200 + 43,000 − 4,716.67 = **1,423,483.33** |

**Reconciliation checks** (`stock_gl_reconciliation`)

| Check | Result |
|---|---|
| Inventory vs GL | difference 0 |
| Received, not yet put away | 47,500 on 1 line |
| Balances vs documents | difference 0 |
| FIFO layers vs balances | difference 0 |

The P2P reconciliation (GRNI) is unchanged at 0.

**HTTP and browser journeys** use the same pattern on one receipt (12 t @ 84,500, 300 bags @ 940):

| Item | Value |
|---|---|
| Steel issued | 5 t = 422,500 |
| Shortage | 0.5 t = 42,250 |
| Inventory = GL | 831,250 |
| Steel on hand | 6.5 t = 549,250 |
| Cement received, not yet put away | 282,000 |
