package httpapi

// Journey B over HTTP: every step is a real request with a token for the
// person who would do it, against PostgreSQL. The figures are those of
// docs/testing/E2E_JOURNEY_B.md.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func decOf(t *testing.T, v any) decimal.Decimal {
	t.Helper()
	d, err := decimal.NewFromString(fmt.Sprint(v))
	if err != nil {
		t.Fatalf("not a number: %v", v)
	}
	return d
}

func TestAPIJourneyB_ContractToCash(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	controller, cfo := a.tok("u-controller", nil, false, "controller"), a.tok("u-cfo", nil, true, "cfo")
	finMgr, treasury := a.tok("u-finance-manager", nil, true, "finance_manager"), a.tok("u-treasury", nil, true, "treasury_officer")
	bankOfficer := a.tok("u-bank-officer", nil, false, "bank_statement_officer")
	arClerk, arSup := a.tok("u-ar-clerk", nil, false, "ar_clerk"), a.tok("u-ar-supervisor", nil, false, "ar_supervisor")
	commercial, commercialMFA := a.tok("u-commercial", P, false, "commercial_manager"), a.tok("u-commercial", P, true, "commercial_manager")
	qs, siteEng := a.tok("u-qs", P, false, "quantity_surveyor"), a.tok("u-site-engineer", P, false, "site_engineer")
	otherQS := a.tok("u-qs-2", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, false, "quantity_surveyor")
	today := time.Now().UTC().Format("2006-01-02")
	in30 := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")

	// Receivable accounts (operator setup).
	if err := a.db.AdminStore.WithTenant(a.db.Ctx, a.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, x := range []struct{ code, typ string }{{"1100", "ASSET"}, {"1150", "ASSET"}, {"2200", "LIABILITY"}, {"2300", "LIABILITY"}, {"4000", "REVENUE"}} {
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

	// Policy, customer, company bank account.
	pol := a.id("POST", "/v1/contract-policies", controller, map[string]any{"legal_entity_id": a.entity, "vat_rate": "0.15", "vat_base": "GROSS_LESS_ADVANCE",
		"ar_account_id": a.accounts["1100"], "retention_account_id": a.accounts["1150"], "advance_account_id": a.accounts["2200"],
		"revenue_account_id": a.accounts["4000"], "vat_output_account_id": a.accounts["2300"]})
	a.call(200, "POST", "/v1/contract-policies/"+pol+"/approve", cfo, nil)
	cust := a.id("POST", "/v1/customers", arClerk, map[string]any{"legal_entity_id": a.entity, "code": "ERA", "name": "Ethiopian Roads Administration", "tax_id": "TIN-ERA"})
	a.call(200, "POST", "/v1/customers/"+cust+"/approve", finMgr, nil)
	bank := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Operating", "account_number": "1000999888777",
		"currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)

	// Contract: commercial manager records and submits, CFO approves with MFA.
	ctr := a.id("POST", "/v1/contracts", commercial, map[string]any{"project_id": a.project, "customer_id": cust, "title": "Adama-Awash road section 2",
		"client_reference": "ERA/CW/2026/014", "signed_on": "2026-10-01", "retention_pct": "0.05", "advance_amount": "1000000", "advance_recovery_pct": "0.20",
		"lines": []map[string]any{
			{"line_no": 1, "description": "Bulk excavation", "unit": "m3", "quantity": "10000", "rate": "350"},
			{"line_no": 2, "description": "Concrete C30", "unit": "m3", "quantity": "1200", "rate": "6500"},
			{"line_no": 3, "description": "Reinforcement steel", "unit": "t", "quantity": "120", "rate": "98000"}}})
	a.call(200, "POST", "/v1/contracts/"+ctr+"/submit", commercial, nil)
	if st, _ := a.do("POST", "/v1/contracts/"+ctr+"/approve", a.tok("u-cfo", nil, false, "cfo"), nil); st != 401 {
		t.Errorf("contract approval without fresh MFA: %d, want 401", st)
	}
	a.call(200, "POST", "/v1/contracts/"+ctr+"/approve", cfo, nil)
	// Another project's QS cannot see or measure the contract.
	if st, _ := a.do("GET", "/v1/p2p/contract/"+ctr, otherQS, nil); st != 404 {
		t.Errorf("other-project QS reads the contract: %d", st)
	}
	if st, _ := a.do("POST", "/v1/contracts/"+ctr+"/measurements", otherQS, map[string]any{"period_end": "2026-10-15", "lines": []map[string]any{{"contract_line_no": 1, "quantity": "1"}}}); st != 404 {
		t.Errorf("other-project QS measures the contract: %d", st)
	}

	// The bank statement with the three receipts.
	a.call(201, "POST", "/v1/bank-statements", bankOfficer, map[string]any{"company_bank_id": bank, "statement_no": "CBE-B-001", "statement_date": today,
		"opening_balance": "10000000", "closing_balance": "17691000", "lines": []map[string]any{
			{"booking_date": today, "amount": "1000000", "reference": "ERA ADVANCE", "counterparty": "ERA"},
			{"booking_date": today, "amount": "4691000", "reference": "ERA IPC 1", "counterparty": "ERA"},
			{"booking_date": today, "amount": "2000000", "reference": "ERA PART IPC 2", "counterparty": "ERA"}}})
	moneyIn := map[string]string{}
	for _, it := range a.call(200, "GET", "/v1/p2p/money_in?status=UNAPPLIED", arClerk, nil)["items"].([]any) {
		m := it.(map[string]any)
		moneyIn[strings.SplitN(m["label"].(string), " — ", 2)[0]] = m["id"].(string)
	}
	if len(moneyIn) != 3 {
		t.Fatalf("money in: %v", moneyIn)
	}
	var journals []string
	receive := func(line string, alloc map[string]any) {
		t.Helper()
		r := a.id("POST", "/v1/receipts", arClerk, map[string]any{"statement_line_id": moneyIn[line], "allocations": []map[string]any{alloc}})
		if st, _ := a.do("POST", "/v1/receipts/"+r+"/confirm", arClerk, nil); st != 403 {
			t.Errorf("receipt confirmed by the AR clerk who recorded it: %d", st)
		}
		journals = append(journals, a.call(200, "POST", "/v1/receipts/"+r+"/confirm", arSup, nil)["journal_id"].(string))
	}
	receive("ERA ADVANCE", map[string]any{"contract_id": ctr, "amount": "1000000"})

	// Measurement, IPC, invoice, receipt.
	cycle := func(period string, q [3]string, ref, wantDue, receiptLine, receiptAmount string) {
		t.Helper()
		var lines []map[string]any
		for i, x := range q {
			lines = append(lines, map[string]any{"contract_line_no": i + 1, "quantity": x})
		}
		ms := a.id("POST", "/v1/contracts/"+ctr+"/measurements", qs, map[string]any{"period_end": period, "lines": lines})
		a.call(200, "POST", "/v1/measurements/"+ms+"/submit", qs, nil)
		a.call(200, "POST", "/v1/measurements/"+ms+"/verify", siteEng, nil)
		ipc := a.id("POST", "/v1/contracts/"+ctr+"/ipcs", qs, map[string]any{"period_end": period})
		a.call(200, "POST", "/v1/ipcs/"+ipc+"/submit", qs, nil)
		cert := map[string]any{"certificate_ref": ref, "certificate_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
		if st, _ := a.do("POST", "/v1/ipcs/"+ipc+"/certify", commercial, cert); st != 401 {
			t.Errorf("IPC certification without fresh MFA: %d, want 401", st)
		}
		a.call(200, "POST", "/v1/ipcs/"+ipc+"/certify", commercialMFA, cert)
		d := a.call(200, "GET", "/v1/p2p/ipc/"+ipc, commercial, nil)["detail"].(map[string]any)
		if got := decOf(t, d["amount_due"]); !got.Equal(decimal.RequireFromString(wantDue)) {
			t.Errorf("IPC %s amount due %s, want %s", ref, got, wantDue)
		}
		inv := a.id("POST", "/v1/ipcs/"+ipc+"/invoice", arClerk, map[string]any{"invoice_date": today, "due_date": in30})
		// An AI assistant holding the supervisor's role cannot approve.
		now := time.Now()
		aiTok, err := testVerifier.Sign(Claims{Subject: "u-ar-assistant", TenantID: a.tenant, Roles: []string{"ar_supervisor"}, IssuedAt: now.Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", Kind: "ai", TokenID: uuid.NewString()})
		if err != nil {
			t.Fatal(err)
		}
		if st, out := a.do("POST", "/v1/customer-invoices/"+inv+"/approve", aiTok, nil); st != 403 {
			t.Errorf("AI principal approves a customer invoice: %d %v", st, out)
		}
		journals = append(journals, a.call(200, "POST", "/v1/customer-invoices/"+inv+"/approve", arSup, nil)["journal_id"].(string))
		receive(receiptLine, map[string]any{"invoice_id": inv, "amount": receiptAmount})
	}
	cycle("2026-10-15", [3]string{"4000", "300", "20"}, "ERA-IPC-01", "4691000", "ERA IPC 1", "4691000")
	cycle("2026-10-20", [3]string{"3000", "200", "10"}, "ERA-IPC-02", "3663000", "ERA PART IPC 2", "2000000")

	// Finance approves and posts the AR journals.
	for _, r := range a.call(200, "POST", "/v1/journals/approve-batch", finMgr, map[string]any{"journal_ids": journals})["results"].([]any) {
		if !r.(map[string]any)["ok"].(bool) {
			t.Fatalf("approve: %v", r)
		}
	}
	for _, r := range a.call(200, "POST", "/v1/journals/post-batch", controller, map[string]any{"journal_ids": journals})["results"].([]any) {
		if !r.(map[string]any)["ok"].(bool) {
			t.Fatalf("post: %v", r)
		}
	}

	// Position, reconciliation, profitability.
	pos := a.call(200, "GET", "/v1/contracts/"+ctr+"/position", commercial, nil)
	for k, want := range map[string]string{"contract_value": "23060000", "certified_gross": "8640000", "retention_held": "432000", "invoiced_total": "8354000",
		"received": "6691000", "receivable_open": "1663000"} {
		if got := decOf(t, pos[k]); !got.Equal(decimal.RequireFromString(want)) {
			t.Errorf("position %s: %s, want %s", k, got, want)
		}
	}
	if st, _ := a.do("GET", "/v1/contracts/"+ctr+"/position", otherQS, nil); st != 404 {
		t.Errorf("other-project QS reads the contract position: %d", st)
	}
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/ar-reconciliation", controller, nil)["checks"].([]any) {
		m := c.(map[string]any)
		t.Logf("AR recon %v: subledger %v gl %v difference %v", m["check"], m["subledger"], m["gl"], m["difference"])
		if strings.HasPrefix(m["check"].(string), "Unapplied") {
			if !decOf(t, m["subledger"]).IsZero() {
				t.Errorf("unapplied money in: %v", m)
			}
		} else if !decOf(t, m["difference"]).IsZero() {
			t.Errorf("does not reconcile: %v", m)
		}
	}
	if st, _ := a.do("GET", "/v1/entities/"+a.entity+"/ar-reconciliation", commercial, nil); st != 403 {
		t.Errorf("project-scoped commercial manager reads the entity AR reconciliation: %d", st)
	}
	prof := a.call(200, "GET", "/v1/projects/"+a.project+"/profitability", controller, nil)
	if !decOf(t, prof["revenue_posted"]).Equal(decimal.RequireFromString("8640000")) {
		t.Errorf("profitability: %v", prof)
	}
	// Receipts are entity-level documents: hidden from project roles.
	if items := a.call(200, "GET", "/v1/p2p/customer_receipt", commercial, nil)["items"].([]any); len(items) != 0 {
		t.Errorf("project role lists %d customer receipts", len(items))
	}
}
