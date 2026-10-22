package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

// TestConsoleBrowserJourneyB drives Journey B (contract to cash) through the
// web console in a real Chromium, one browser context per person. Master
// data and the bank statement are seeded through the API; every commercial
// and receivables step is done in the UI. The outcome is then verified
// independently through the API. Skipped (never passed) without node and
// Playwright, exactly like TestConsoleBrowserJourneyA.
func TestConsoleBrowserJourneyB(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the browser journey was not run")
	}
	pw := os.Getenv("SERK_PLAYWRIGHT")
	if pw == "" {
		if out, err := exec.Command("npm", "root", "-g").Output(); err == nil {
			pw = filepath.Join(strings.TrimSpace(string(out)), "playwright")
		}
	}
	if _, err := os.Stat(filepath.Join(pw, "package.json")); err != nil {
		t.Skipf("playwright module not found at %q: the browser journey was not run", pw)
	}
	script, err := filepath.Abs("../../e2e/console_journey_b.mjs")
	if err != nil {
		t.Fatal(err)
	}

	a := newP2PAPI(t)
	h := New(Config{Verifier: testVerifier, Kernel: a.svc, Store: a.db.Router, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		RatePerMinute: 100000, Abuse: AbuseConfig{PreAuthPerMinute: 1000000, MaxInFlight: 1024}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	a.srv = srv
	P := []string{a.project}

	// Seed through the API: accounts, contract policy, customer, company bank
	// account and the bank statement with the advance and the IPC payment.
	if err := a.db.AdminStore.WithTenant(a.db.Ctx, a.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, x := range []struct{ code, name, typ string }{{"1100", "Accounts receivable", "ASSET"}, {"1150", "Retention receivable", "ASSET"},
			{"2200", "Advances from customers", "LIABILITY"}, {"2300", "VAT output", "LIABILITY"}, {"4000", "Contract revenue", "REVENUE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: a.tenant, LegalEntityID: a.entity, Code: x.code, Name: x.name, Type: ledger.AccountType(x.typ), Active: true})
			if err != nil {
				return err
			}
			a.accounts[x.code] = id
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	controller, cfo := a.tok("u-controller-seed", nil, true, "controller"), a.tok("u-cfo-seed", nil, true, "cfo")
	pol := a.id("POST", "/v1/contract-policies", controller, map[string]any{"legal_entity_id": a.entity, "vat_rate": "0.15", "vat_base": "GROSS_LESS_ADVANCE",
		"ar_account_id": a.accounts["1100"], "retention_account_id": a.accounts["1150"], "advance_account_id": a.accounts["2200"],
		"revenue_account_id": a.accounts["4000"], "vat_output_account_id": a.accounts["2300"]})
	a.call(200, "POST", "/v1/contract-policies/"+pol+"/approve", cfo, nil)
	cust := a.id("POST", "/v1/customers", a.tok("u-ar-seed", nil, false, "ar_clerk"), map[string]any{"legal_entity_id": a.entity, "code": "ERA",
		"name": "Ethiopian Roads Administration", "tax_id": "TIN-ERA"})
	a.call(200, "POST", "/v1/customers/"+cust+"/approve", a.tok("u-finance-seed", nil, true, "finance_manager"), nil)
	bank := a.id("POST", "/v1/company-bank-accounts", a.tok("u-treasury-seed", nil, true, "treasury_officer"), map[string]any{"legal_entity_id": a.entity,
		"name": "CBE Operating", "account_number": "1000999888777", "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)
	today := time.Now().UTC().Format("2006-01-02")
	a.call(201, "POST", "/v1/bank-statements", a.tok("u-bank-officer", nil, false, "bank_statement_officer"), map[string]any{"company_bank_id": bank,
		"statement_no": "CBE-B-001", "statement_date": today, "opening_balance": "0", "closing_balance": "5691000", "lines": []map[string]any{
			{"booking_date": today, "amount": "1000000", "reference": "ERA ADVANCE", "counterparty": "ERA"},
			{"booking_date": today, "amount": "4691000", "reference": "ERA IPC 1", "counterparty": "ERA"}}})

	tokens := map[string]string{
		"commercial": a.tok("u-commercial", P, true, "commercial_manager"), "commercialPhone": a.tok("u-commercial", P, true, "commercial_manager"),
		"cfo": a.tok("u-cfo", nil, true, "cfo"), "qs": a.tok("u-qs", P, false, "quantity_surveyor"),
		"otherQS": a.tok("u-qs-2", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, false, "quantity_surveyor"),
		"siteEng": a.tok("u-site-engineer", P, false, "site_engineer"), "arClerk": a.tok("u-ar-clerk", nil, false, "ar_clerk"),
		"arSup": a.tok("u-ar-supervisor", nil, false, "ar_supervisor"), "finMgr": a.tok("u-finance-manager", nil, true, "finance_manager"),
		"controller": a.tok("u-controller", nil, false, "controller"), "controllerDark": a.tok("u-controller", nil, false, "controller"),
	}
	dir := t.TempDir()
	fx, _ := json.Marshal(map[string]any{"tokens": tokens, "entity": a.entity, "project": a.project})
	fixture := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixture, fx, 0o600); err != nil {
		t.Fatal(err)
	}
	shots := os.Getenv("SERK_E2E_SHOTS_B")
	if shots == "" {
		shots = filepath.Join(dir, "shots")
	}
	if err := os.MkdirAll(shots, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, script)
	cmd.Env = append(os.Environ(), "SERK_URL="+srv.URL, "SERK_FIXTURE="+fixture, "SERK_SHOTS="+shots, "SERK_PLAYWRIGHT="+pw)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	t.Logf("browser journey B (%s):\n%s", time.Since(start).Round(time.Second), out)
	if err != nil {
		t.Fatalf("browser journey B failed: %v (screenshots in %s)", err, shots)
	}

	// Independent verification through the API of what the UI did.
	ctl := a.tok("u-controller-check", nil, false, "controller")
	if n := len(a.call(200, "GET", "/v1/p2p/ipc?status=INVOICED", ctl, nil)["items"].([]any)); n != 1 {
		t.Errorf("invoiced IPCs after the UI journey: %d, want 1", n)
	}
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/ar-reconciliation", ctl, nil)["checks"].([]any) {
		m := c.(map[string]any)
		if !strings.HasPrefix(m["check"].(string), "Unapplied") && m["difference"] != "0" {
			t.Errorf("AR reconciliation break after the UI journey: %v", m)
		}
		if strings.HasPrefix(m["check"].(string), "Unapplied") && m["subledger"] != "0" {
			t.Errorf("money left unapplied after the UI journey: %v", m)
		}
	}
	if drafts := a.call(200, "GET", "/v1/journals?status=DRAFT&source_prefix=AR_", ctl, nil)["journals"].([]any); len(drafts) != 0 {
		t.Errorf("%d AR journals left unposted", len(drafts))
	}
	ctrs := a.call(200, "GET", "/v1/p2p/contract?status=ACTIVE", ctl, nil)["items"].([]any)
	if len(ctrs) != 1 {
		t.Fatalf("active contracts: %d", len(ctrs))
	}
	pos := a.call(200, "GET", "/v1/contracts/"+ctrs[0].(map[string]any)["id"].(string)+"/position", ctl, nil)
	if pos["receivable_open"] != "0" || pos["retention_held"] != "265500" || pos["advance_recovered"] != "1000000" {
		t.Errorf("contract position after the UI journey: %v", pos)
	}
}
