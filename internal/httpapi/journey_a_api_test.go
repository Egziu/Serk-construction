package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

// Journey A over HTTP (GATEC-01, API level): every business step is an HTTP
// call made with a signed bearer token for a different person; nothing is
// done through the kernel directly except operator reference data (project,
// chart of accounts, fiscal period) and the approved WBS that the BOQ prices.

type p2pAPI struct {
	*env
	project, costCode, period string
}

// tok issues a token for a person (the identity provider asserts
// pkind=human) with roles, project scope and optional MFA.
func (e *env) tok(user string, projects []string, mfa bool, roles ...string) string {
	now := time.Now()
	c := Claims{Subject: user, TenantID: e.tenant, Roles: roles, Projects: projects, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Issuer: "serk-id", Audience: "serk-construction", Kind: "human", TokenID: uuid.NewString()}
	if mfa {
		c.AMR, c.AuthTime = []string{"pwd", "otp"}, now.Unix()
	}
	t, err := testVerifier.Sign(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return t
}

func newP2PAPI(t *testing.T) *p2pAPI {
	t.Helper()
	e := newEnv(t)
	a := &p2pAPI{env: e}
	err := e.db.AdminStore.WithTenant(e.db.Ctx, e.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if a.project, err = postgres.CreateProject(ctx, tx, e.tenant, e.entity, "P-API", "Addis Ring Road Lot 2", "ETB"); err != nil {
			return err
		}
		for _, x := range []struct{ code, typ string }{{"1050", "ASSET"}, {"1300", "ASSET"}, {"2000", "LIABILITY"}, {"2100", "LIABILITY"}, {"5100", "EXPENSE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: e.tenant, LegalEntityID: e.entity, Code: x.code, Name: x.code, Type: ledger.AccountType(x.typ), Active: true})
			if err != nil {
				return err
			}
			e.accounts[x.code] = id
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Approved WBS (the WBS API is outside Journey A's scope).
	pm := auth.Principal{Kind: auth.KindHuman, UserID: "u-wbs", TenantID: e.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{a.project}}
	v, _, err := e.svc.ProposeWBSVersion(e.db.Ctx, pm, a.project, "Tender WBS", []postgres.WBSNode{{Code: "01", Name: "Superstructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "Structural materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	fm := auth.Principal{Kind: auth.KindHuman, UserID: "u-wbs-approver", TenantID: e.tenant, Roles: []string{"finance_manager"}}
	if err := e.svc.DecideWBSVersion(e.db.Ctx, fm, v.ID, true, "approved"); err != nil {
		t.Fatal(err)
	}
	_ = e.db.Router.WithTenant(e.db.Ctx, e.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT c.id::text FROM cost_codes c JOIN wbs_nodes n ON n.id = c.wbs_node_id WHERE n.version_id = $1::uuid`, v.ID).Scan(&a.costCode)
	})
	return a
}

// call fails the test unless the response status is want; returns the body.
func (a *p2pAPI) call(want int, method, path, token string, body any) map[string]any {
	a.t.Helper()
	st, out := a.do(method, path, token, body)
	if st != want {
		a.t.Fatalf("%s %s: status %d, want %d: %v", method, path, st, want, out)
	}
	return out
}

func (a *p2pAPI) id(method, path, token string, body any) string {
	a.t.Helper()
	return a.call(201, method, path, token, body)["id"].(string)
}

func TestAPIJourneyA_EndToEnd(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	// One person per role. Project roles carry project scope; finance roles
	// are tenant-wide; payment approvers authenticate with MFA.
	estimator := a.tok("u-estimator", P, false, "estimator")
	commercial := a.tok("u-commercial", P, false, "commercial_manager")
	siteEng := a.tok("u-site-engineer", P, false, "site_engineer")
	pm := a.tok("u-pm", P, false, "project_manager")
	buyer := a.tok("u-buyer", P, false, "procurement_officer")
	procMgr := a.tok("u-proc-manager", P, false, "procurement_manager")
	store := a.tok("u-storekeeper", P, false, "storekeeper")
	apClerk := a.tok("u-ap-clerk", P, false, "ap_clerk")
	apSup := a.tok("u-ap-supervisor", P, false, "ap_supervisor")
	treasury := a.tok("u-treasury", nil, true, "treasury_officer")
	treasury2 := a.tok("u-treasury-2", nil, true, "treasury_officer")
	bankOfficer := a.tok("u-bank-officer", nil, false, "bank_statement_officer")
	finMgr := a.tok("u-finance-manager", nil, true, "finance_manager")
	cfo := a.tok("u-cfo", nil, true, "cfo")
	controller := a.tok("u-controller", nil, false, "controller")
	accountant := a.tok("u-accountant", nil, false, "accountant")
	today := time.Now().UTC().Format("2006-01-02")
	in30 := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")

	// Policy (controller proposes, CFO approves).
	pol := a.id("POST", "/v1/p2p/policies", controller, map[string]any{"legal_entity_id": a.entity, "price_tolerance_pct": "0.02", "over_receipt_pct": "0.05",
		"vat_rate": "0.15", "high_value_po_threshold": "5000000", "dual_payment_threshold": "500000", "grni_account_id": a.accounts["2100"],
		"ap_account_id": a.accounts["2000"], "vat_input_account_id": a.accounts["1300"], "ppv_account_id": a.accounts["5100"]})
	// Adversarial: the proposer cannot approve their own policy.
	if st, out := a.do("POST", "/v1/p2p/policies/"+pol+"/approve", a.tok("u-controller", nil, true, "controller", "cfo"), nil); st < 400 || st >= 500 {
		t.Fatalf("self-approval of policy: %d %v", st, out)
	}
	a.call(200, "POST", "/v1/p2p/policies/"+pol+"/approve", cfo, nil)

	// Suppliers and bank accounts.
	var sup [3]string
	for i, code := range []string{"ABC-STEEL", "HABESHA-CEMENT", "SAFARI-BUILD"} {
		sup[i] = a.id("POST", "/v1/suppliers", buyer, map[string]any{"legal_entity_id": a.entity, "code": code, "name": code + " PLC", "tax_id": fmt.Sprintf("TIN-API-%d", i)})
		a.call(200, "POST", "/v1/suppliers/"+sup[i]+"/approve", procMgr, nil)
	}
	supBank := a.id("POST", "/v1/suppliers/"+sup[0]+"/bank-accounts", buyer, map[string]any{"bank_name": "Commercial Bank of Ethiopia",
		"account_name": "ABC Steel PLC", "account_number": "1000123456789", "currency": "ETB"})
	a.call(200, "POST", "/v1/supplier-bank-accounts/"+supBank+"/approve", finMgr, nil)
	bank := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Operating",
		"account_number": "1000999888777", "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)

	// BOQ -> PR.
	boq := a.id("POST", "/v1/boqs", estimator, map[string]any{"project_id": a.project, "description": "Tender BOQ rev A", "items": []map[string]any{
		{"item_no": "3.1", "description": "Reinforcement steel", "unit": "t", "quantity": "120", "rate": "85000", "cost_code_id": a.costCode},
		{"item_no": "3.2", "description": "OPC cement 50kg", "unit": "bag", "quantity": "2000", "rate": "950", "cost_code_id": a.costCode}}})
	a.call(200, "POST", "/v1/boqs/"+boq+"/submit", estimator, nil)
	a.call(200, "POST", "/v1/boqs/"+boq+"/approve", commercial, map[string]any{"reason": "priced to tender"})
	pr := a.id("POST", "/v1/requisitions", siteEng, map[string]any{"project_id": a.project, "justification": "Level 3 slab", "needed_by": in30,
		"lines": []map[string]any{
			{"line_no": 1, "cost_code_id": a.costCode, "description": "Reinforcement steel", "unit": "t", "quantity": "20", "est_unit_price": "86000"},
			{"line_no": 2, "cost_code_id": a.costCode, "description": "OPC cement 50kg", "unit": "bag", "quantity": "500", "est_unit_price": "960"}}})
	a.call(200, "POST", "/v1/requisitions/"+pr+"/submit", siteEng, nil)
	// Adversarial: the requester cannot approve their own requisition, even holding the approver role.
	if st, out := a.do("POST", "/v1/requisitions/"+pr+"/approve", a.tok("u-site-engineer", P, false, "site_engineer", "project_manager"), nil); st < 400 || st >= 500 {
		t.Fatalf("self-approval of requisition: %d %v", st, out)
	}
	// Adversarial: a project manager without this project in scope sees nothing.
	if st, _ := a.do("POST", "/v1/requisitions/"+pr+"/approve", a.tok("u-other-pm", nil, false, "project_manager"), nil); st != 404 && st != 403 {
		t.Fatalf("out-of-scope approval: %d", st)
	}
	a.call(200, "POST", "/v1/requisitions/"+pr+"/approve", pm, nil)

	// RFQ -> quotes -> evaluation -> award -> PO.
	rfq := a.id("POST", "/v1/rfqs", buyer, map[string]any{"pr_id": pr, "due_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
		"min_suppliers": 3, "supplier_ids": sup[:]})
	a.call(200, "POST", "/v1/rfqs/"+rfq+"/issue", buyer, nil)
	var q [3]string
	for i, pr := range [][2]string{{"84500", "940"}, {"86000", "930"}, {"90000", "980"}} {
		q[i] = a.id("POST", "/v1/rfqs/"+rfq+"/quotes", buyer, map[string]any{"supplier_id": sup[i], "valid_until": in30, "supplier_reference": fmt.Sprintf("Q-%d", i),
			"lines": []map[string]any{{"pr_line_no": 1, "unit_price": pr[0]}, {"pr_line_no": 2, "unit_price": pr[1]}}})
	}
	a.call(200, "POST", "/v1/quotes/"+q[0]+"/evaluate", siteEng, map[string]any{"compliant": true, "note": "mill certificates"})
	a.call(200, "POST", "/v1/quotes/"+q[1]+"/evaluate", siteEng, map[string]any{"compliant": true})
	a.call(200, "POST", "/v1/quotes/"+q[2]+"/evaluate", siteEng, map[string]any{"compliant": false, "note": "no mill certificates"})
	// Adversarial: awarding a non-compliant quote is refused.
	if st, out := a.do("POST", "/v1/rfqs/"+rfq+"/award", procMgr, map[string]any{"quote_id": q[2], "reason": "preferred"}); st < 400 || st >= 500 {
		t.Fatalf("award of non-compliant quote: %d %v", st, out)
	}
	a.call(200, "POST", "/v1/rfqs/"+rfq+"/award", procMgr, map[string]any{"quote_id": q[0]})
	po := a.id("POST", "/v1/purchase-orders", buyer, map[string]any{"rfq_id": rfq, "accounts": map[string]string{"1": a.accounts["5000"], "2": a.accounts["5000"]}})
	a.call(200, "POST", "/v1/purchase-orders/"+po+"/approve", procMgr, nil)

	// Receipts: storekeeper records, site engineer confirms (GRNI journals).
	grn := func(lines []map[string]any) string {
		g := a.id("POST", "/v1/goods-receipts", store, map[string]any{"po_id": po, "received_on": today, "delivery_note": "DN-" + time.Now().Format("150405.000"), "lines": lines})
		a.call(200, "POST", "/v1/goods-receipts/"+g+"/submit", store, nil)
		// Adversarial: the storekeeper who received cannot confirm their own receipt.
		if st, _ := a.do("POST", "/v1/goods-receipts/"+g+"/confirm", a.tok("u-storekeeper", P, false, "storekeeper", "site_engineer"), nil); st < 400 || st >= 500 {
			t.Fatalf("self-confirmation of GRN: %d", st)
		}
		return a.call(200, "POST", "/v1/goods-receipts/"+g+"/confirm", siteEng, nil)["journal_id"].(string)
	}
	j1 := grn([]map[string]any{{"po_line_no": 1, "qty_received": "12"}, {"po_line_no": 2, "qty_received": "500"}})
	j2 := grn([]map[string]any{{"po_line_no": 1, "qty_received": "8"}})

	// Invoices: 3-way match, then AP supervisor approval (AP journals).
	inv := func(no, sub, tax, tot string, lines []map[string]any) (string, string) {
		id := a.id("POST", "/v1/invoices", apClerk, map[string]any{"po_id": po, "invoice_number": no, "invoice_date": today, "due_date": in30,
			"subtotal": sub, "tax_amount": tax, "total": tot, "lines": lines})
		if m := a.call(200, "POST", "/v1/invoices/"+id+"/submit", apClerk, nil)["match_status"]; m != "MATCHED" {
			t.Fatalf("invoice %s match %v", no, m)
		}
		return id, a.call(200, "POST", "/v1/invoices/"+id+"/approve", apSup, nil)["journal_id"].(string)
	}
	inv1, j3 := inv("ABC/2026/0417", "1486500", "222975", "1709475", []map[string]any{{"po_line_no": 1, "quantity": "12", "unit_price": "84500"}, {"po_line_no": 2, "quantity": "500", "unit_price": "945"}})
	// Adversarial: an over-billed invoice (more than received) does not match and cannot be approved.
	over := a.id("POST", "/v1/invoices", apClerk, map[string]any{"po_id": po, "invoice_number": "ABC/2026/9999", "invoice_date": today, "due_date": in30,
		"subtotal": "1690000", "tax_amount": "253500", "total": "1943500", "lines": []map[string]any{{"po_line_no": 1, "quantity": "20", "unit_price": "84500"}}})
	// Billing beyond confirmed receipts is refused by the database at submit.
	if st, out := a.do("POST", "/v1/invoices/"+over+"/submit", apClerk, nil); st != 409 {
		t.Fatalf("submit of over-billed invoice: %d %v", st, out)
	}
	if st, out := a.do("POST", "/v1/invoices/"+over+"/approve", apSup, nil); st < 400 || st >= 500 {
		t.Fatalf("approval of unsubmitted invoice: %d %v", st, out)
	}
	inv2, j4 := inv("ABC/2026/0431", "676000", "101400", "777400", []map[string]any{{"po_line_no": 1, "quantity": "8", "unit_price": "84500"}})

	// Finance batch-approves and posts the subledger journals (maker != checker).
	batch := func(ids ...string) {
		for _, step := range []struct{ path, tok string }{{"/v1/journals/approve-batch", finMgr}, {"/v1/journals/post-batch", controller}} {
			res := a.call(200, "POST", step.path, step.tok, map[string]any{"journal_ids": ids})["results"].([]any)
			for _, r := range res {
				if m := r.(map[string]any); m["ok"] != true {
					t.Fatalf("%s %v", step.path, m)
				}
			}
		}
	}
	// The draft-journal worklist shows exactly the P2P drafts waiting.
	drafts := a.call(200, "GET", "/v1/journals?status=DRAFT&source_prefix=P2P_", finMgr, nil)["journals"].([]any)
	if len(drafts) != 4 {
		t.Fatalf("draft P2P journals = %d, want 4", len(drafts))
	}
	batch(j1, j2, j3, j4)

	// Payments: treasury prepares; two different MFA approvers; release.
	pay := func(invID, amount string) (string, string) {
		id := a.id("POST", "/v1/payments", treasury, map[string]any{"legal_entity_id": a.entity, "supplier_id": sup[0], "supplier_bank_id": supBank,
			"company_bank_id": bank, "value_date": today, "allocations": []map[string]any{{"invoice_id": invID, "amount": amount}}})
		a.call(200, "POST", "/v1/payments/"+id+"/submit", treasury, nil)
		// Adversarial: approval without a fresh MFA login is challenged (step-up).
		if st, _ := a.do("POST", "/v1/payments/"+id+"/approve", a.tok("u-finance-manager", nil, false, "finance_manager"), nil); st != 401 && st != 403 {
			t.Fatalf("non-MFA payment approval: %d", st)
		}
		if s := a.call(200, "POST", "/v1/payments/"+id+"/approve", finMgr, nil)["status"]; s != "PARTIALLY_APPROVED" {
			t.Fatalf("first approval: %v", s)
		}
		// Adversarial: the same approver cannot give the second approval.
		if st, _ := a.do("POST", "/v1/payments/"+id+"/approve", finMgr, nil); st < 400 || st >= 500 {
			t.Fatalf("duplicate approver accepted: %d", st)
		}
		// Adversarial: release before full approval is refused.
		if st, _ := a.do("POST", "/v1/payments/"+id+"/release", treasury2, nil); st < 400 || st >= 500 {
			t.Fatalf("release before dual approval: %d", st)
		}
		if s := a.call(200, "POST", "/v1/payments/"+id+"/approve", cfo, nil)["status"]; s != "APPROVED" {
			t.Fatalf("second approval: %v", s)
		}
		// Adversarial: the preparer cannot release; a second treasury officer does.
		if st, _ := a.do("POST", "/v1/payments/"+id+"/release", treasury, nil); st < 400 || st >= 500 {
			t.Fatalf("release by the preparer: %d", st)
		}
		// Adversarial: a service principal with the right roles is not a person.
		now := time.Now()
		svc, err := testVerifier.Sign(Claims{Subject: "payments-automation", TenantID: a.tenant, Roles: []string{"treasury_officer"}, IssuedAt: now.Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", AMR: []string{"pwd", "otp"}, AuthTime: now.Unix(), Kind: "service"})
		if err != nil {
			t.Fatal(err)
		}
		if st, out := a.do("POST", "/v1/payments/"+id+"/release", svc, nil); st < 400 || st >= 500 {
			t.Fatalf("release by a non-human principal: %d %v", st, out)
		}
		jid := a.call(200, "POST", "/v1/payments/"+id+"/release", treasury2, nil)["journal_id"].(string)
		doc := a.call(200, "GET", "/v1/p2p/payment_instruction/"+id, treasury, nil)
		return doc["number"].(string), jid
	}
	pay1, j5 := pay(inv1, "1709475")
	pay2, j6 := pay(inv2, "777400")
	batch(j5, j6)

	// Bank statement import (digest of the uploaded bytes) and auto-reconciliation.
	// Adversarial: treasury (prepares and releases payments) cannot import statements.
	if st, _ := a.do("POST", "/v1/bank-statements", treasury2, map[string]any{"company_bank_id": bank, "statement_no": "X", "statement_date": today,
		"opening_balance": "0", "closing_balance": "0", "lines": []any{}}); st != 403 {
		t.Fatalf("statement import by treasury: %d", st)
	}
	stmt := a.id("POST", "/v1/bank-statements", bankOfficer, map[string]any{"company_bank_id": bank, "statement_no": "CBE-API-001", "statement_date": today,
		"opening_balance": "50000000", "closing_balance": "47812600", "lines": []map[string]any{
			{"booking_date": today, "amount": "-1709475", "reference": "TRF " + pay1 + " ABC STEEL", "counterparty": "ABC STEEL PLC"},
			{"booking_date": today, "amount": "300000", "reference": "CUSTOMER RECEIPT IPC-07", "counterparty": "MINISTRY OF ROADS"},
			{"booking_date": today, "amount": "-777400", "reference": pay2 + "/ABC", "counterparty": "ABC STEEL PLC"},
			{"booking_date": today, "amount": "-525", "reference": "SERVICE CHARGE", "counterparty": "CBE"}}})
	rec := a.call(200, "POST", "/v1/bank-statements/"+stmt+"/reconcile", accountant, nil)
	matched, unmatched := rec["matched"].([]any), rec["unmatched"].([]any)
	if len(matched) != 2 || len(unmatched) != 2 {
		t.Fatalf("reconciliation: %v", rec)
	}
	batch(matched[0].(map[string]any)["journal_id"].(string), matched[1].(map[string]any)["journal_id"].(string))

	// Subledgers reconcile to the GL; the project cost report is exact.
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/p2p-reconciliation", controller, nil)["checks"].([]any) {
		m := c.(map[string]any)
		t.Logf("recon %-45v subledger %12v gl %12v diff %v", m["check"], m["subledger"], m["gl"], m["difference"])
		if m["difference"] != "0" {
			t.Errorf("reconciliation break: %v", m)
		}
	}
	cost := a.call(200, "GET", "/v1/projects/"+a.project+"/cost-report", pm, nil)["cost_codes"].([]any)
	if len(cost) != 1 {
		t.Fatalf("cost report: %v", cost)
	}
	r := cost[0].(map[string]any)
	for k, want := range map[string]string{"budget": "12100000", "committed": "2160000", "received": "2160000", "invoiced": "2162500", "actual_posted": "2162500", "available": "9937500"} {
		if r[k] != want {
			t.Errorf("cost report %s = %v, want %s", k, r[k], want)
		}
	}
	t.Logf("cost report: %v", r)

	// Worklists: everything ended in its terminal state.
	for typ, want := range map[string]int{"supplier_invoice": 2, "payment_instruction": 2} {
		st := map[string]string{"supplier_invoice": "APPROVED", "payment_instruction": "SETTLED"}[typ]
		items := a.call(200, "GET", "/v1/p2p/"+typ+"?status="+st, controller, nil)["items"].([]any)
		if len(items) != want {
			t.Errorf("%s in %s: %d, want %d", typ, st, len(items), want)
		}
	}
	// Adversarial: unknown document types and malformed ids are 404, not 500.
	if st, _ := a.do("GET", "/v1/p2p/journal_lines", controller, nil); st != 404 {
		t.Errorf("unknown doc type: %d", st)
	}
	if st, _ := a.do("GET", "/v1/p2p/purchase_order/not-a-uuid", controller, nil); st != 404 {
		t.Errorf("malformed id: %d", st)
	}
	// Adversarial: an out-of-scope project user lists no purchase orders.
	if items := a.call(200, "GET", "/v1/p2p/purchase_order", a.tok("u-other-buyer", []string{"00000000-0000-0000-0000-000000000001"}, false, "procurement_officer"), nil)["items"].([]any); len(items) != 0 {
		t.Errorf("out-of-scope user sees %d purchase orders", len(items))
	}
}
