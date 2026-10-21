package kernel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

// Journey A (GATEC-01): BOQ -> PR -> RFQ -> PO -> GRN (partial) -> invoice
// (3-way match) -> payment instruction (dual approval, MFA) -> bank statement
// -> automatic reconciliation -> GL, with every maker/checker step done by a
// different person and every number reconciled to the ledger.

type p2pCast struct {
	estimator, commercial, siteEng, pm, buyer, procMgr, store, apClerk, apSup, treasury, treasury2, bankOfficer, finMgr, cfo, controller, accountant auth.Principal
}

type p2pWorld struct {
	f        *fixture
	cast     p2pCast
	policy   string
	costCode string
	acct     map[string]string
	bank     string
	sup      [3]string
	supBank  string
}

// newP2PWorldHook runs between proposing and approving the first policy.
var newP2PWorldHook = func(w *p2pWorld) {}

func dec(s string) decimal.Decimal { return decimal.RequireFromString(s) }

func must(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func newP2PWorld(t *testing.T) *p2pWorld {
	t.Helper()
	f := newFixture(t)
	w := &p2pWorld{f: f, acct: map[string]string{}}
	now := time.Now()
	proj := []string{f.project}
	mk := func(id string, mfa bool, projects []string, roles ...string) auth.Principal {
		// Every cast member is a person (identity-provider assertion).
		p := auth.Principal{UserID: id, TenantID: f.tenant, Roles: roles, ProjectIDs: projects, IssuedAt: now.Add(-time.Minute), Kind: auth.KindHuman}
		if mfa {
			p.MFA, p.AuthTime = true, now
		}
		return p
	}
	w.cast = p2pCast{
		estimator: mk("u-estimator", false, proj, "estimator"), commercial: mk("u-commercial", false, proj, "commercial_manager"),
		siteEng: mk("u-site-engineer", false, proj, "site_engineer"), pm: mk("u-pm", false, proj, "project_manager"),
		buyer: mk("u-buyer", false, proj, "procurement_officer"), procMgr: mk("u-proc-manager", false, proj, "procurement_manager"),
		store: mk("u-storekeeper", false, proj, "storekeeper"), apClerk: mk("u-ap-clerk", false, proj, "ap_clerk"),
		apSup: mk("u-ap-supervisor", false, proj, "ap_supervisor"), treasury: mk("u-treasury", true, nil, "treasury_officer"),
		treasury2: mk("u-treasury-2", true, nil, "treasury_officer"), bankOfficer: mk("u-bank-officer", false, nil, "bank_statement_officer"),
		finMgr: mk("u-finance-manager", true, nil, "finance_manager"), cfo: mk("u-cfo", true, nil, "cfo"),
		controller: mk("u-controller", false, nil, "controller"), accountant: mk("u-accountant", false, nil, "accountant"),
	}
	// Chart of accounts additions (operator setup, synthetic data).
	err := f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, a := range []struct{ code, name, typ string }{{"1050", "Payments in transit", "ASSET"}, {"2100", "Goods received not invoiced", "LIABILITY"},
			{"5100", "Purchase price variance", "EXPENSE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: a.code, Name: a.name, Type: ledger.AccountType(a.typ), Active: true})
			if err != nil {
				return err
			}
			w.acct[a.code] = id
		}
		return nil
	})
	must(t, "accounts", err)
	for k, v := range f.accounts {
		w.acct[k] = v
	}
	// Approved WBS with one material cost code.
	wbsPM := auth.Principal{UserID: "u-wbs-planner", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: proj}
	v, _, err := f.svc.ProposeWBSVersion(f.ctx, wbsPM, f.project, "Tender WBS", []postgres.WBSNode{{Code: "01", Name: "Superstructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "Structural materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	must(t, "wbs", err)
	must(t, "wbs approve", f.svc.DecideWBSVersion(f.ctx, f.appr, v.ID, true, "approved for construction"))
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT c.id::text FROM cost_codes c JOIN wbs_nodes n ON n.id = c.wbs_node_id WHERE n.version_id = $1::uuid AND c.code = '01-MAT'`, v.ID).Scan(&w.costCode)
	})
	c := w.cast
	// P2P policy: proposed by the controller, approved by the CFO. The VAT
	// rate is tenant-configured test data, not a statement of current law.
	w.policy, err = f.svc.ProposeP2PPolicy(f.ctx, c.controller, postgres.P2PPolicy{LegalEntityID: f.entity, PriceTolerancePct: dec("0.02"),
		OverReceiptPct: dec("0.05"), VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: w.acct["2100"], APAccountID: w.acct["2000"], VATInputAccountID: w.acct["1300"], PPVAccountID: w.acct["5100"]})
	must(t, "policy", err)
	newP2PWorldHook(w) // review 4 probe hook (no-op by default)
	must(t, "policy approve", f.svc.DecideP2PPolicy(f.ctx, c.cfo, w.policy, true))
	// Suppliers (buyer creates, procurement manager approves).
	for i, code := range []string{"ABC-STEEL", "HABESHA-CEMENT", "SAFARI-BUILD"} {
		w.sup[i], err = f.svc.CreateSupplier(f.ctx, c.buyer, f.entity, code, strings.ReplaceAll(code, "-", " ")+" PLC", "TIN-000"+string(rune('1'+i)))
		must(t, "supplier", err)
		must(t, "supplier approve", f.svc.ApproveSupplier(f.ctx, c.procMgr, w.sup[i]))
	}
	w.supBank, err = f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "Commercial Bank of Ethiopia", "ABC Steel PLC", "1000123456789", "ETB")
	must(t, "supplier bank", err)
	must(t, "supplier bank approve", f.svc.ApproveSupplierBankAccount(f.ctx, c.finMgr, w.supBank))
	// Company bank account (treasury registers, CFO approves).
	w.bank, err = f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "CBE Operating", "1000999888777", "ETB", w.acct["1000"], w.acct["1050"])
	must(t, "company bank", err)
	must(t, "company bank approve", f.svc.ApproveCompanyBankAccount(f.ctx, c.cfo, w.bank))
	return w
}

// approvedBOQ: 120 t steel @ 85,000 + 2,000 bags cement @ 950 on 01-MAT.
func (w *p2pWorld) approvedBOQ(t *testing.T) string {
	t.Helper()
	f, c := w.f, w.cast
	boq, err := f.svc.CreateBOQ(f.ctx, c.estimator, f.project, "Tender BOQ rev A", []BOQItem{
		{ItemNo: "3.1", Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec("120"), Rate: dec("85000"), CostCodeID: w.costCode},
		{ItemNo: "3.2", Description: "OPC cement 50kg", Unit: "bag", Quantity: dec("2000"), Rate: dec("950"), CostCodeID: w.costCode}})
	must(t, "boq", err)
	must(t, "boq submit", f.svc.SubmitBOQ(f.ctx, c.estimator, boq))
	must(t, "boq approve", f.svc.DecideBOQ(f.ctx, c.commercial, boq, true, ""))
	return boq
}

// awardedPO runs PR -> RFQ -> award -> PO approval and returns the PO id.
func (w *p2pWorld) awardedPO(t *testing.T, steelQty, cementQty string) (pr, rfq, po string) {
	t.Helper()
	f, c := w.f, w.cast
	var err error
	pr, err = f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Level 3 slab reinforcement and concrete", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec(steelQty), EstUnitPrice: dec("86000")},
		{LineNo: 2, CostCodeID: w.costCode, Description: "OPC cement 50kg", Unit: "bag", Quantity: dec(cementQty), EstUnitPrice: dec("960")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err = f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(72*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "rfq issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	valid := time.Now().AddDate(0, 1, 0)
	q := make([]string, 3)
	for i, prices := range [][2]string{{"84500", "940"}, {"86000", "930"}, {"90000", "980"}} {
		q[i], err = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[i], valid, "Q-"+string(rune('A'+i)), []QuoteLine{{1, dec(prices[0])}, {2, dec(prices[1])}})
		must(t, "quote", err)
	}
	must(t, "eval 1", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[0], true, "Mill certificates provided"))
	must(t, "eval 2", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[1], true, ""))
	must(t, "eval 3", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[2], false, "No mill test certificates"))
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q[0], ""))
	po, err = f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["5000"], 2: w.acct["5000"]})
	must(t, "po", err)
	must(t, "po approve", f.svc.ApprovePO(f.ctx, c.procMgr, po, ""))
	return pr, rfq, po
}

func (w *p2pWorld) receipt(t *testing.T, po string, lines ...GRNLine) (grn, journal string) {
	t.Helper()
	f, c := w.f, w.cast
	grn, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now(), "DN-"+key("x"), lines)
	must(t, "grn", err)
	must(t, "grn submit", f.svc.SubmitGRN(f.ctx, c.store, grn))
	journal, err = f.svc.ConfirmGRN(f.ctx, c.siteEng, grn)
	must(t, "grn confirm", err)
	return grn, journal
}

func (w *p2pWorld) invoice(t *testing.T, in InvoiceInput) (id, match string) {
	t.Helper()
	f, c := w.f, w.cast
	id, err := f.svc.EnterInvoice(f.ctx, c.apClerk, in)
	must(t, "invoice", err)
	match, err = f.svc.SubmitInvoice(f.ctx, c.apClerk, id)
	must(t, "invoice submit", err)
	return id, match
}

func (w *p2pWorld) financePost(t *testing.T, ids ...string) {
	t.Helper()
	for _, r := range w.f.svc.ApproveJournals(w.f.ctx, w.cast.finMgr, ids) {
		if !r.OK {
			t.Fatalf("approve journal %s: %s", r.JournalID, r.Error)
		}
	}
	for _, r := range w.f.svc.PostJournals(w.f.ctx, w.cast.controller, ids) {
		if !r.OK {
			t.Fatalf("post journal %s: %s", r.JournalID, r.Error)
		}
	}
}

func today() time.Time { return time.Now().UTC().Truncate(24 * time.Hour) }

// stmt renders a statement file in the SERK interchange format; each line is
// {amount, reference, counterparty} booked on the statement date.
func stmt(bank, no string, date time.Time, opening, closing string, lines ...[3]string) []byte {
	type line struct {
		BookingDate  string `json:"booking_date"`
		Amount       string `json:"amount"`
		Reference    string `json:"reference"`
		Counterparty string `json:"counterparty"`
	}
	f := struct {
		CompanyBankID  string `json:"company_bank_id"`
		StatementNo    string `json:"statement_no"`
		StatementDate  string `json:"statement_date"`
		OpeningBalance string `json:"opening_balance"`
		ClosingBalance string `json:"closing_balance"`
		Lines          []line `json:"lines"`
	}{bank, no, date.Format("2006-01-02"), opening, closing, []line{}}
	for _, l := range lines {
		f.Lines = append(f.Lines, line{date.Format("2006-01-02"), l[0], l[1], l[2]})
	}
	b, _ := json.Marshal(f)
	return b
}

func TestJourneyA_BOQToBankReconciliationToGL(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")

	// Two partial deliveries.
	_, j1 := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("500")})
	_, j2 := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("8")})

	// Invoice 1: cement billed 945 vs PO 940 (0.53% < 2% tolerance): MATCHED,
	// the 2,500 difference goes to purchase price variance on the cost code.
	inv1, m1 := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "ABC/2026/0417", InvoiceDate: today(), DueDate: today().AddDate(0, 0, 30),
		Subtotal: dec("1486500"), TaxAmount: dec("222975"), Total: dec("1709475"),
		Lines: []InvoiceLine{{1, dec("12"), dec("84500")}, {2, dec("500"), dec("945")}}})
	if m1 != "MATCHED" {
		t.Fatalf("invoice 1 match = %s", m1)
	}
	j3, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv1, "")
	must(t, "approve inv1", err)
	inv2, m2 := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "ABC/2026/0431", InvoiceDate: today(), DueDate: today().AddDate(0, 0, 30),
		Subtotal: dec("676000"), TaxAmount: dec("101400"), Total: dec("777400"), Lines: []InvoiceLine{{1, dec("8"), dec("84500")}}})
	if m2 != "MATCHED" {
		t.Fatalf("invoice 2 match = %s", m2)
	}
	j4, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv2, "")
	must(t, "approve inv2", err)
	w.financePost(t, j1, j2, j3, j4)

	// Payments: both above the dual-approval threshold.
	pay := func(inv string, amount string) (string, string) {
		id, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec(amount)}})
		must(t, "prepare payment", err)
		must(t, "submit payment", f.svc.SubmitPayment(f.ctx, c.treasury, id))
		st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, id)
		must(t, "approve 1", err)
		if st != "PARTIALLY_APPROVED" {
			t.Fatalf("first approval status %s", st)
		}
		st, err = f.svc.ApprovePayment(f.ctx, c.cfo, id)
		must(t, "approve 2", err)
		if st != "APPROVED" {
			t.Fatalf("second approval status %s", st)
		}
		jid, err := f.svc.ReleasePayment(f.ctx, c.treasury2, id) // never the preparer
		must(t, "release", err)
		d, _ := f.svc.GetP2PDoc(f.ctx, c.treasury, "payment_instruction", id)
		return d.Number, jid
	}
	pay1, j5 := pay(inv1, "1709475")
	pay2, j6 := pay(inv2, "777400")
	w.financePost(t, j5, j6)

	// Bank statement: both payments, a customer receipt and a bank charge.
	// Imported by the statement officer, independent of both payments.
	st, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "CBE-2026-10-001", today(), "50000000", "47812600",
		[3]string{"-1709475", "TRF " + pay1 + " ABC STEEL", "ABC STEEL PLC"},
		[3]string{"300000", "CUSTOMER RECEIPT IPC-07", "MINISTRY OF ROADS"},
		[3]string{"-777400", pay2 + "/ABC", "ABC STEEL PLC"},
		[3]string{"-525", "SERVICE CHARGE", "CBE"}))
	must(t, "import", err)
	rec, err := f.svc.AutoReconcile(f.ctx, c.accountant, st)
	must(t, "reconcile", err)
	if len(rec.Matched) != 2 || len(rec.Unmatched) != 2 {
		t.Fatalf("reconciliation: %+v", rec)
	}
	t.Logf("reconciliation: matched %d, unmatched %+v", len(rec.Matched), rec.Unmatched)
	w.financePost(t, rec.Matched[0].JournalID, rec.Matched[1].JournalID)

	// Every subledger reconciles to the GL to the cent.
	recon, err := f.svc.GLReconciliation(f.ctx, c.controller, f.entity)
	must(t, "gl recon", err)
	for _, r := range recon {
		t.Logf("recon %-45s subledger %15s gl %15s diff %s unposted/unmatched %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
		if !r.Difference.IsZero() {
			t.Errorf("reconciliation break: %+v", r)
		}
	}
	want := map[string]string{"GRNI (goods received not invoiced)": "0", "Accounts payable": "0", "Payments in transit: CBE Operating": "0",
		"Bank (reconciled movements): CBE Operating": "-2486875"}
	for _, r := range recon {
		if w, ok := want[r.Check]; ok && !r.Subledger.Equal(dec(w)) {
			t.Errorf("%s subledger = %s, want %s", r.Check, r.Subledger, w)
		}
	}
	// Project cost report: budget, commitment, actuals (incl. price variance).
	rep, err := f.svc.ProjectCostReport(f.ctx, c.pm, f.project)
	must(t, "cost report", err)
	if len(rep) != 1 {
		t.Fatalf("cost report rows: %+v", rep)
	}
	r := rep[0]
	t.Logf("cost %s: budget %s committed %s received %s invoiced %s actual %s other %s available %s",
		r.CostCode, r.Budget, r.Committed, r.Received, r.Invoiced, r.ActualPosted, r.ActualOther, r.Available)
	for name, got := range map[string]decimal.Decimal{"budget": r.Budget, "committed": r.Committed, "received": r.Received,
		"invoiced": r.Invoiced, "actual_posted": r.ActualPosted, "actual_other": r.ActualOther, "available": r.Available} {
		exp := map[string]string{"budget": "12100000", "committed": "2160000", "received": "2160000", "invoiced": "2162500",
			"actual_posted": "2162500", "actual_other": "2500", "available": "9937500"}[name]
		if !got.Equal(dec(exp)) {
			t.Errorf("cost report %s = %s, want %s", name, got, exp)
		}
	}
	// Documents end in their terminal states; every step left audit + outbox.
	for _, id := range []string{inv1, inv2} {
		if d, _ := f.svc.GetP2PDoc(f.ctx, c.apSup, "supplier_invoice", id); d.Status != "APPROVED" {
			t.Errorf("invoice %s is %s", id, d.Status)
		}
	}
	var settled, events, audits int
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM payment_instructions WHERE status = 'SETTLED'`).Scan(&settled)
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type LIKE 'p2p.%' OR event_type LIKE 'supplier.%' OR event_type LIKE 'boq.%'
			OR event_type LIKE 'pr.%' OR event_type LIKE 'rfq.%' OR event_type LIKE 'po.%' OR event_type LIKE 'grn.%' OR event_type LIKE 'ap.%'
			OR event_type LIKE 'payment.%' OR event_type LIKE 'bank.%' OR event_type LIKE 'company_bank_account.%'`).Scan(&events)
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action LIKE 'grn.%' OR action LIKE 'ap.%' OR action LIKE 'payment.%' OR action LIKE 'bank.%'`).Scan(&audits)
	})
	if settled != 2 || events < 40 || audits < 20 {
		t.Errorf("settled=%d outbox events=%d audit entries=%d", settled, events, audits)
	}
	t.Logf("settled payments %d, P2P outbox events %d, audit entries (receipt..bank) %d", settled, events, audits)
}
