package kernel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// TestJourneyC_StockTransfer (migration 0025, JC-TRANSFER). Figures (ETB,
// synthetic), stores A (P001-STORE) and B (P001-STORE-B) of project P-001:
//
//	Steel FIFO into A: 12 t @ 84,500 (GRN 1) then 10 t @ 86,000 (GRN 2).
//	Cement WAC into A: 300 @ 940 + 200 @ 950 = 500 bags, 472,000 (avg 944).
//	Transfer 15 t steel A->B: 12 @ 84,500 + 3 @ 86,000 = 1,272,000; B gets
//	two layers with those costs, in that order.
//	Transfer 100 bags cement A->B at the average: 94,400.
//	Issue 13 t steel from B: 12 @ 84,500 + 1 @ 86,000 = 1,100,000 (proves the
//	layers kept their order and cost).
//	GL inventory 2,346,000 - 1,100,000 = 1,246,000 = stock (A steel 7 t
//	602,000; B steel 2 t 172,000; A cement 377,600; B cement 94,400).
func TestJourneyC_StockTransfer(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pmgr := auth.Principal{Kind: auth.KindHuman, UserID: "u-proc-manager", TenantID: f.tenant, Roles: []string{"procurement_manager"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	storeB, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Project 001 second store")
	must(t, "store B", err)

	po1 := w.inventoryPO(t, "20", "500", "84500", "940")
	g1, j1 := w.receipt(t, po1, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	po2 := w.inventoryPO(t, "20", "500", "86000", "950")
	g2, j2 := w.receipt(t, po2, GRNLine{POLineNo: 1, QtyReceived: dec("10")}, GRNLine{POLineNo: 2, QtyReceived: dec("200")})
	w.putAway(t, g1, 1, w.itemSteel, "12")
	w.putAway(t, g1, 2, w.itemCement, "300")
	w.putAway(t, g2, 1, w.itemSteel, "10")
	w.putAway(t, g2, 2, w.itemCement, "200")

	transfer := func(item, from, to, qty string) (string, error) {
		return f.svc.CreateStockTransfer(f.ctx, c.store, StockTransferInput{StockItemID: item, FromWarehouseID: from, ToWarehouseID: to,
			Quantity: dec(qty), TransferDate: today(), Note: "Second pour area"})
	}

	// Controls.
	_, err = transfer(w.itemSteel, w.store, w.store, "1")
	arDenied(t, "a transfer to the same warehouse", err, "different warehouses")
	_, err = f.svc.CreateStockTransfer(f.ctx, c.store, StockTransferInput{StockItemID: w.itemSteel, FromWarehouseID: w.store, ToWarehouseID: storeB,
		Quantity: dec("1"), TransferDate: today().AddDate(0, 0, 2)})
	arDenied(t, "a future-dated transfer", err, "dated today or earlier")
	other := auth.Principal{Kind: auth.KindHuman, UserID: "u-store-2", TenantID: f.tenant, Roles: []string{"storekeeper"}, ProjectIDs: []string{"8c1d4c2e-0000-4000-8000-000000000001"}, IssuedAt: time.Now().Add(-time.Minute)}
	_, err = f.svc.CreateStockTransfer(f.ctx, other, StockTransferInput{StockItemID: w.itemSteel, FromWarehouseID: w.store, ToWarehouseID: storeB,
		Quantity: dec("1"), TransferDate: today()})
	arDenied(t, "a transfer by a storekeeper of another project", err, "not found")
	big, err := transfer(w.itemSteel, w.store, storeB, "23")
	must(t, "oversized transfer request", err)
	arDenied(t, "a transfer of more than is on hand", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, big), "insufficient stock")
	arDenied(t, "approval by the storekeeper", f.svc.ApproveStockTransfer(f.ctx, c.store, big), "forbidden")
	both := c.store
	both.Roles = append([]string{"inventory_controller"}, both.Roles...)
	arDenied(t, "self-approval of a transfer", f.svc.ApproveStockTransfer(f.ctx, both, big), "segregation of duties")
	ai := w.invCtl
	ai.UserID, ai.Kind = "u-inventory-agent", auth.KindAI
	arDenied(t, "approval by an AI principal", f.svc.ApproveStockTransfer(f.ctx, ai, big), "reserved to human principals")
	arDenied(t, "cancellation by someone other than the preparer", f.svc.CancelStockTransfer(f.ctx, other, big, "Not my transfer"), "not found")
	must(t, "cancel oversized", f.svc.CancelStockTransfer(f.ctx, c.store, big, "Quantity typed wrongly"))
	err = f.svc.ApproveStockTransfer(f.ctx, w.invCtl, big)
	arDenied(t, "approving a cancelled transfer", err, "CANCELLED")

	// Steel FIFO and cement WAC transfers.
	ts, err := transfer(w.itemSteel, w.store, storeB, "15")
	must(t, "steel transfer", err)
	must(t, "approve steel transfer", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, ts))
	tc, err := transfer(w.itemCement, w.store, storeB, "100")
	must(t, "cement transfer", err)
	must(t, "approve cement transfer", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, tc))
	for id, want := range map[string]string{ts: "1272000", tc: "94400"} {
		if got := w.stockValue(t, `SELECT amount FROM stock_transfers WHERE id = $1::uuid`, id); !got.Equal(dec(want)) {
			t.Errorf("transfer %s valued %s, want %s", id[:8], got, want)
		}
	}
	var layers string
	must(t, "layers", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT string_agg(qty_remaining::numeric(20,2) || '@' || unit_cost::numeric(24,0), ' ' ORDER BY seq) FROM stock_layers
			WHERE warehouse_id = $1::uuid AND stock_item_id = $2::uuid AND qty_remaining > 0`, storeB, w.itemSteel).Scan(&layers)
	}))
	if layers != "12.00@84500 3.00@86000" {
		t.Errorf("store B steel layers %q, want 12.00@84500 3.00@86000", layers)
	}

	// Issue 13 t from store B: FIFO across the transferred layers.
	is, err := f.svc.CreateStockIssue(f.ctx, c.store, StockIssueInput{WarehouseID: storeB, StockItemID: w.itemSteel, ProjectID: f.project,
		CostCodeID: w.costCode, ExpenseAccountID: w.acct["5000"], Quantity: dec("13"), IssueDate: today()})
	must(t, "issue from B", err)
	ji, err := f.svc.ApproveStockIssue(f.ctx, c.siteEng, is)
	must(t, "approve issue from B", err)
	if got := w.stockValue(t, `SELECT amount FROM stock_issues WHERE id = $1::uuid`, is); !got.Equal(dec("1100000")) {
		t.Errorf("issue of 13 t from B valued %s, want 1,100,000", got)
	}
	w.financePost(t, j1, j2, ji)

	for _, x := range []struct{ wh, item, qty, value string }{
		{w.store, w.itemSteel, "7", "602000"}, {storeB, w.itemSteel, "2", "172000"},
		{w.store, w.itemCement, "400", "377600"}, {storeB, w.itemCement, "100", "94400"}} {
		var q, v = w.stockValue(t, `SELECT COALESCE(sum(qty), 0) FROM stock_balances WHERE warehouse_id = $1::uuid AND stock_item_id = $2::uuid`, x.wh, x.item),
			w.stockValue(t, `SELECT COALESCE(sum(value), 0) FROM stock_balances WHERE warehouse_id = $1::uuid AND stock_item_id = $2::uuid`, x.wh, x.item)
		if !q.Equal(dec(x.qty)) || !v.Equal(dec(x.value)) {
			t.Errorf("balance %s/%s: %s at %s, want %s at %s", x.wh[:8], x.item[:8], q, v, x.qty, x.value)
		}
	}
	if got := w.glBalance(t, "1200"); !got.Equal(dec("1246000")) {
		t.Errorf("GL inventory %s, want 1,246,000", got)
	}
	for _, r := range w.recon(t) {
		if strings.HasPrefix(r.Check, "Received, not yet put away") {
			continue
		}
		if !r.Difference.IsZero() || r.Unposted != 0 {
			t.Errorf("%s does not reconcile after transfers: %+v", r.Check, r)
		}
	}
	// No journal for a transfer.
	if n := w.stockValue(t, `SELECT count(*) FROM journals WHERE source_ref IN ($1, $2)`, ts, tc); !n.IsZero() {
		t.Errorf("transfers generated %s journals", n)
	}
}
