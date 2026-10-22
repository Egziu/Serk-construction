package httpapi

// Review 7 HTTP probes (stock valuation slice, docs/security/INDEPENDENT_REVIEW_7_2026-10-22.md),
// kept as regression tests after migration 0024: R7-F6 (receipt detail) and
// R7-F3 (future-dated issue refused with 422).

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func TestR7_API_StockReceiptDetailAndIssueDate(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	if err := a.db.AdminStore.WithTenant(a.db.Ctx, a.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, x := range []struct{ code, typ string }{{"1200", "ASSET"}, {"5200", "EXPENSE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: a.tenant, LegalEntityID: a.entity, Code: x.code, Name: x.code, Type: ledger.AccountType(x.typ), Active: true})
			if err != nil {
				return err
			}
			a.accounts[x.code] = id
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	grn, _ := a.seedInventoryGRN(t)
	buyer, finMgr := a.tok("u-buyer", P, false, "procurement_officer"), a.tok("u-finance-manager", nil, true, "finance_manager")
	procMgr, store := a.tok("u-proc-manager", P, false, "procurement_manager"), a.tok("u-storekeeper", P, false, "storekeeper")
	siteEng, controller := a.tok("u-site-engineer", P, false, "site_engineer"), a.tok("u-controller", nil, false, "controller")
	steel := a.id("POST", "/v1/stock-items", buyer, map[string]any{"legal_entity_id": a.entity, "code": "STEEL-G60", "name": "Reinforcement steel",
		"unit": "t", "valuation_method": "FIFO", "inventory_account_id": a.accounts["1200"]})
	a.call(200, "POST", "/v1/stock-items/"+steel+"/approve", finMgr, nil)
	// R8-F8/R9-I2: a procurement approver names the stock item of the inventory PO line before put-away.
	poID := a.call(200, "GET", "/v1/p2p/grn/"+grn, buyer, nil)["detail"].(map[string]any)["h"].(map[string]any)["po_id"].(string)
	if st, _ := a.do("POST", "/v1/purchase-orders/"+poID+"/lines/1/stock-item", a.tok("u-storekeeper", P, false, "storekeeper"), map[string]any{"stock_item_id": steel}); st != 403 {
		t.Errorf("the storekeeper designates the stock item of a PO line: %d, want 403", st)
	}
	if st, _ := a.do("POST", "/v1/purchase-orders/"+poID+"/lines/1/stock-item", buyer, map[string]any{"stock_item_id": steel}); st != 403 {
		t.Errorf("the buyer who raised the PO designates its stock item: %d, want 403 (R9-I2)", st)
	}
	a.call(200, "POST", "/v1/purchase-orders/"+poID+"/lines/1/stock-item", procMgr, map[string]any{"stock_item_id": steel})
	wh := a.id("POST", "/v1/warehouses", procMgr, map[string]any{"legal_entity_id": a.entity, "project_id": a.project, "code": "P-STORE", "name": "Project site store"})
	rcpt := a.id("POST", "/v1/goods-receipts/"+grn+"/put-away", store, map[string]any{"po_line_no": 1, "stock_item_id": steel, "warehouse_id": wh, "quantity": "12"})
	for name, tok := range map[string]string{"storekeeper": store, "controller": controller} {
		st, body := a.do("GET", "/v1/p2p/stock_receipt/"+rcpt, tok, nil)
		if st != 200 {
			t.Errorf("OPEN: GET /v1/p2p/stock_receipt/%s by %s -> %d %v", rcpt[:8], name, st, body)
		} else {
			t.Logf("held: receipt detail %d", st)
		}
	}
	st, body := a.do("POST", "/v1/stock-issues", store, map[string]any{"warehouse_id": wh, "stock_item_id": steel, "project_id": a.project, "cost_code_id": a.costCode,
		"expense_account_id": a.accounts["5000"], "quantity": "5", "issue_date": "2031-01-01"})
	if st != 422 {
		t.Errorf("OPEN: issue dated 2031-01-01: %d %v, want 422", st, body)
	} else {
		t.Logf("held: future-dated issue refused: %v", body)
	}
	_ = siteEng
}
