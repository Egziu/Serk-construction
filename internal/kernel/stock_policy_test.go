package kernel

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// JC-INVOICE-REVALUE, pinned as accounting policy (ADR 0012 addendum,
// proposed for a human finance owner): stock is carried at the goods
// receipt cost (the purchase order price). A supplier invoice priced
// differently, within tolerance, posts its difference to the purchase price
// variance account on the cost code; the stock on hand, its layers and its
// later issues are not revalued.
func TestStockPolicy_InvoiceVarianceIsNotRevaluedIntoStock(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("500")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	w.putAway(t, grn, 2, w.itemCement, "500")
	qty0, val0 := w.balanceOf(t, w.itemCement)
	layers0 := w.stockValue(t, `SELECT COALESCE(sum(value_remaining), 0) FROM stock_layers WHERE stock_item_id = $1::uuid`, w.itemSteel)

	// Cement invoiced at 945 against a PO price of 940 (within tolerance).
	inv, match := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "ABC/2026/0901", InvoiceDate: today(), DueDate: today().AddDate(0, 0, 30),
		Subtotal: dec("1486500"), TaxAmount: dec("222975"), Total: dec("1709475"),
		Lines: []InvoiceLine{{1, dec("12"), dec("84500")}, {2, dec("500"), dec("945")}}})
	if match != "MATCHED" {
		t.Fatalf("match = %s", match)
	}
	jInv, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv, "")
	must(t, "approve invoice", err)
	w.financePost(t, jInv)

	var ppv, invLines string
	must(t, "journal", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0)::text
			FROM journal_lines jl JOIN accounts a ON a.id = jl.account_id WHERE jl.journal_id = $1::uuid AND a.code = '5100'`, jInv).Scan(&ppv); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT string_agg(a.code || ' ' || jl.side || ' ' || jl.amount, '; ' ORDER BY a.code, jl.side)
			FROM journal_lines jl JOIN accounts a ON a.id = jl.account_id WHERE jl.journal_id = $1::uuid`, jInv).Scan(&invLines)
	}))
	t.Logf("invoice journal: %s", invLines)
	if !decimal.RequireFromString(ppv).Equal(dec("2500")) {
		t.Errorf("purchase price variance posted %s, want 2,500 (500 bags x 5)", ppv)
	}
	qty1, val1 := w.balanceOf(t, w.itemCement)
	layers1 := w.stockValue(t, `SELECT COALESCE(sum(value_remaining), 0) FROM stock_layers WHERE stock_item_id = $1::uuid`, w.itemSteel)
	if !qty1.Equal(qty0) || !val1.Equal(val0) || !layers1.Equal(layers0) {
		t.Errorf("stock changed on invoicing: cement %s/%s -> %s/%s, steel layers %s -> %s (policy: stock stays at receipt cost)", qty0, val0, qty1, val1, layers0, layers1)
	}
	// An issue after the invoice still costs at the receipt price.
	amt := w.issueApprovePost(t, w.itemSteel, "10")
	if !amt.Equal(dec("845000")) {
		t.Errorf("issue of 10 t cost %s, want 845,000 at the receipt price 84,500", amt)
	}
	// The stock-to-GL reconciliation stays at 0: the variance sits in
	// expense, not in inventory.
	var diff string
	must(t, "recon", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(string_agg(check_name || '=' || difference, ', ') FILTER (WHERE difference <> 0), 'all 0') FROM stock_gl_reconciliation($1::uuid)`, f.entity).Scan(&diff)
	}))
	if diff != "all 0" {
		t.Errorf("stock reconciliation after the variance: %s", diff)
	}
}
