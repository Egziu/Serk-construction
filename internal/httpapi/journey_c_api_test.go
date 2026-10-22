package httpapi

// Journey C over HTTP. Purchasing (already covered by the Journey A API and
// browser tests) is seeded through the kernel; every stock step is a real
// request by the person who would make it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

// seedInventoryGRN creates policy, suppliers, an approved BOQ and a PO whose
// lines post to inventory, and confirms a goods receipt of 12 t steel at
// 84,500 and 300 bags of cement at 940. It returns the GRN and its journal.
func (a *p2pAPI) seedInventoryGRN(t *testing.T) (grn, journal string) {
	t.Helper()
	ctx, svc := a.db.Ctx, a.svc
	mk := func(id string, projects []string, roles ...string) auth.Principal {
		return auth.Principal{Kind: auth.KindHuman, UserID: id, TenantID: a.tenant, Roles: roles, ProjectIDs: projects, IssuedAt: time.Now().Add(-time.Minute), MFA: true, AuthTime: time.Now()}
	}
	P := []string{a.project}
	ctl, cfo, buyer, pmgr := mk("s-ctl", nil, "controller"), mk("s-cfo", nil, "cfo"), mk("s-buyer", P, "procurement_officer"), mk("s-pmgr", P, "procurement_manager")
	est, com, se, pm, store := mk("s-est", P, "estimator"), mk("s-com", P, "commercial_manager"), mk("s-se", P, "site_engineer"), mk("s-pm", P, "project_manager"), mk("s-store", P, "storekeeper")
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	d := decimal.RequireFromString
	pol, err := svc.ProposeP2PPolicy(ctx, ctl, postgres.P2PPolicy{LegalEntityID: a.entity, PriceTolerancePct: d("0.02"), OverReceiptPct: d("0.05"), VATRate: d("0.15"),
		HighValuePOThreshold: d("5000000"), DualPaymentThreshold: d("500000"), GRNIAccountID: a.accounts["2100"], APAccountID: a.accounts["2000"],
		VATInputAccountID: a.accounts["1300"], PPVAccountID: a.accounts["5100"]})
	must("policy", err)
	must("policy approve", svc.DecideP2PPolicy(ctx, cfo, pol, true))
	var sup [3]string
	for i, code := range []string{"ABC-STEEL", "HABESHA-CEMENT", "SAFARI-BUILD"} {
		sup[i], err = svc.CreateSupplier(ctx, buyer, a.entity, code, code+" PLC", "TIN-C-"+code)
		must("supplier", err)
		must("supplier approve", svc.ApproveSupplier(ctx, pmgr, sup[i]))
	}
	boq, err := svc.CreateBOQ(ctx, est, a.project, "Tender BOQ", []kernel.BOQItem{
		{ItemNo: "3.1", Description: "Reinforcement steel", Unit: "t", Quantity: d("120"), Rate: d("85000"), CostCodeID: a.costCode},
		{ItemNo: "3.2", Description: "OPC cement 50kg", Unit: "bag", Quantity: d("2000"), Rate: d("950"), CostCodeID: a.costCode}})
	must("boq", err)
	must("boq submit", svc.SubmitBOQ(ctx, est, boq))
	must("boq approve", svc.DecideBOQ(ctx, com, boq, true, ""))
	pr, err := svc.CreatePR(ctx, se, a.project, "Site store replenishment", nil, []kernel.PRLine{
		{LineNo: 1, CostCodeID: a.costCode, Description: "Reinforcement steel", Unit: "t", Quantity: d("20"), EstUnitPrice: d("86000")},
		{LineNo: 2, CostCodeID: a.costCode, Description: "OPC cement 50kg", Unit: "bag", Quantity: d("500"), EstUnitPrice: d("960")}})
	must("pr", err)
	must("pr submit", svc.SubmitPR(ctx, se, pr))
	must("pr approve", svc.DecidePR(ctx, pm, pr, true, ""))
	rfq, err := svc.CreateRFQ(ctx, buyer, pr, time.Now().Add(72*time.Hour), 3, "", sup[:])
	must("rfq", err)
	must("rfq issue", svc.IssueRFQ(ctx, buyer, rfq))
	var q0 string
	for i, prices := range [][2]string{{"84500", "940"}, {"86000", "950"}, {"90000", "980"}} {
		q, err := svc.RecordQuote(ctx, buyer, rfq, sup[i], time.Now().AddDate(0, 1, 0), "CQ-"+uuid.NewString()[:6], []kernel.QuoteLine{{PRLineNo: 1, UnitPrice: d(prices[0])}, {PRLineNo: 2, UnitPrice: d(prices[1])}})
		must("quote", err)
		must("eval", svc.EvaluateQuote(ctx, se, q, true, "Certificates provided"))
		if i == 0 {
			q0 = q
		}
	}
	must("award", svc.AwardRFQ(ctx, pmgr, rfq, q0, ""))
	po, err := svc.CreatePOFromAward(ctx, buyer, rfq, map[int]string{1: a.accounts["1200"], 2: a.accounts["1200"]})
	must("po", err)
	must("po approve", svc.ApprovePO(ctx, pmgr, po, ""))
	grn, err = svc.CreateGRN(ctx, store, po, time.Now(), "DN-C-1", []kernel.GRNLine{{POLineNo: 1, QtyReceived: d("12")}, {POLineNo: 2, QtyReceived: d("300")}})
	must("grn", err)
	must("grn submit", svc.SubmitGRN(ctx, store, grn))
	journal, err = svc.ConfirmGRN(ctx, se, grn)
	must("grn confirm", err)
	return grn, journal
}

func TestAPIJourneyC_StockValuation(t *testing.T) {
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
	grn, jGRN := a.seedInventoryGRN(t)
	buyer, finMgr := a.tok("u-buyer", P, false, "procurement_officer"), a.tok("u-finance-manager", nil, true, "finance_manager")
	procMgr, store := a.tok("u-proc-manager", P, false, "procurement_manager"), a.tok("u-storekeeper", P, false, "storekeeper")
	siteEng, invCtl := a.tok("u-site-engineer", P, false, "site_engineer"), a.tok("u-inventory-controller", nil, false, "inventory_controller")
	controller := a.tok("u-controller", nil, false, "controller")
	otherStore := a.tok("u-store-2", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, false, "storekeeper")
	today := time.Now().UTC().Format("2006-01-02")

	steel := a.id("POST", "/v1/stock-items", buyer, map[string]any{"legal_entity_id": a.entity, "code": "STEEL-G60", "name": "Reinforcement steel",
		"unit": "t", "valuation_method": "FIFO", "inventory_account_id": a.accounts["1200"]})
	if st, _ := a.do("POST", "/v1/stock-items/"+steel+"/approve", buyer, nil); st != 403 {
		t.Errorf("stock item approved by the procurement officer: %d", st)
	}
	a.call(200, "POST", "/v1/stock-items/"+steel+"/approve", finMgr, nil)
	store1 := a.id("POST", "/v1/warehouses", procMgr, map[string]any{"legal_entity_id": a.entity, "project_id": a.project, "code": "P-STORE", "name": "Project site store"})
	a.call(201, "POST", "/v1/goods-receipts/"+grn+"/put-away", store, map[string]any{"po_line_no": 1, "stock_item_id": steel, "warehouse_id": store1, "quantity": "12"})
	if st, _ := a.do("POST", "/v1/goods-receipts/"+grn+"/put-away", store, map[string]any{"po_line_no": 1, "stock_item_id": steel, "warehouse_id": store1, "quantity": "1"}); st < 400 || st >= 500 {
		t.Errorf("put-away beyond the receipt line: %d", st)
	}
	if st, _ := a.do("POST", "/v1/goods-receipts/"+grn+"/put-away", store, map[string]any{"po_line_no": 1, "stock_item_id": "not-a-uuid", "warehouse_id": store1, "quantity": "1"}); st != 422 {
		t.Errorf("malformed item id: %d, want 422", st)
	}

	iss := a.id("POST", "/v1/stock-issues", store, map[string]any{"warehouse_id": store1, "stock_item_id": steel, "project_id": a.project, "cost_code_id": a.costCode,
		"expense_account_id": a.accounts["5000"], "quantity": "5", "issue_date": today})
	now := time.Now()
	aiTok, err := testVerifier.Sign(Claims{Subject: "u-site-assistant", TenantID: a.tenant, Roles: []string{"site_engineer"}, Projects: P, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", Kind: "ai", TokenID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := a.do("POST", "/v1/stock-issues/"+iss+"/approve", aiTok, nil); st != 403 {
		t.Errorf("AI principal approves a stock issue: %d", st)
	}
	if st, _ := a.do("GET", "/v1/p2p/stock_issue/"+iss, otherStore, nil); st != 404 {
		t.Errorf("another project's storekeeper reads the issue: %d", st)
	}
	jIss := a.call(200, "POST", "/v1/stock-issues/"+iss+"/approve", siteEng, nil)["journal_id"].(string)
	cnt := a.id("POST", "/v1/stock-counts", store, map[string]any{"warehouse_id": store1, "stock_item_id": steel, "counted_qty": "6.5",
		"variance_account_id": a.accounts["5200"], "count_date": today})
	if st, _ := a.do("POST", "/v1/stock-counts/"+cnt+"/approve", store, nil); st != 403 {
		t.Errorf("count approved by the storekeeper: %d", st)
	}
	jCnt := a.call(200, "POST", "/v1/stock-counts/"+cnt+"/approve", invCtl, nil)["journal_id"].(string)
	// Transfer 2.5 t to a second store (0025): no journal, value moves at FIFO cost.
	store2 := a.id("POST", "/v1/warehouses", procMgr, map[string]any{"legal_entity_id": a.entity, "project_id": a.project, "code": "P-STORE-B", "name": "Second site store"})
	tr := a.id("POST", "/v1/stock-transfers", store, map[string]any{"stock_item_id": steel, "from_warehouse_id": store1, "to_warehouse_id": store2,
		"quantity": "2.5", "transfer_date": today})
	if st, _ := a.do("POST", "/v1/stock-transfers/"+tr+"/approve", store, nil); st != 403 {
		t.Errorf("transfer approved by the storekeeper: %d", st)
	}
	if st, _ := a.do("POST", "/v1/stock-transfers", store, map[string]any{"stock_item_id": steel, "from_warehouse_id": store1, "to_warehouse_id": store1,
		"quantity": "1", "transfer_date": today}); st != 422 {
		t.Errorf("transfer to the same store: %d, want 422", st)
	}
	a.call(200, "POST", "/v1/stock-transfers/"+tr+"/approve", invCtl, nil)
	if d := a.call(200, "GET", "/v1/p2p/stock_transfer/"+tr, store, nil)["detail"].(map[string]any); !decOf(t, d["amount"]).Equal(decimal.RequireFromString("211250")) {
		t.Errorf("transfer valued %v, want 211,250", d["amount"])
	}
	ids := []string{jGRN, jIss, jCnt}
	for _, path := range []string{"/v1/journals/approve-batch", "/v1/journals/post-batch"} {
		tok := map[string]string{"/v1/journals/approve-batch": finMgr, "/v1/journals/post-batch": controller}[path]
		for _, r := range a.call(200, "POST", path, tok, map[string]any{"journal_ids": ids})["results"].([]any) {
			if !r.(map[string]any)["ok"].(bool) {
				t.Fatalf("%s: %v", path, r)
			}
		}
	}
	// Steel 12 x 84,500 = 1,014,000; issued 5 (422,500); counted 6.5 of 7 (shortage 42,250).
	lines := a.call(200, "GET", "/v1/entities/"+a.entity+"/stock-on-hand", store, nil)["lines"].([]any)
	byStore := map[string]string{}
	for _, l := range lines {
		m := l.(map[string]any)
		byStore[m["warehouse_code"].(string)] = decOf(t, m["qty"]).String() + "@" + decOf(t, m["value"]).String()
	}
	if len(lines) != 2 || byStore["P-STORE"] != "4@338000" || byStore["P-STORE-B"] != "2.5@211250" {
		t.Errorf("stock on hand after the transfer: %v", byStore)
	}
	if got := a.call(200, "GET", "/v1/entities/"+a.entity+"/stock-on-hand", otherStore, nil)["lines"].([]any); len(got) != 0 {
		t.Errorf("another project's storekeeper sees %d stock lines", len(got))
	}
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/stock-reconciliation", controller, nil)["checks"].([]any) {
		m := c.(map[string]any)
		t.Logf("stock recon %v: subledger %v gl %v difference %v", m["check"], m["subledger"], m["gl"], m["difference"])
		if !strings.HasPrefix(m["check"].(string), "Received") && !decOf(t, m["difference"]).IsZero() {
			t.Errorf("does not reconcile: %v", m)
		}
	}
	if st, _ := a.do("GET", "/v1/entities/"+a.entity+"/stock-reconciliation", store, nil); st != 403 {
		t.Errorf("storekeeper reads the stock reconciliation: %d", st)
	}
}
