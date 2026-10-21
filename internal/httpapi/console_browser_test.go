package httpapi

import (
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
)

// TestConsoleBrowserJourneyA drives Journey A through the web console in a
// real Chromium (Playwright), one browser context per person, against this
// server and a disposable PostgreSQL. Master data is seeded through the API;
// every procure-to-pay step is done by clicking through the UI. Afterwards
// the outcome is verified independently through the API.
//
// Requires node and the playwright package (SERK_PLAYWRIGHT=<path to the
// playwright module>, default: `npm root -g`/playwright). Without them the
// test is SKIPPED, never reported as passed.
func TestConsoleBrowserJourneyA(t *testing.T) {
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
	script, err := filepath.Abs("../../e2e/console_journey_a.mjs")
	if err != nil {
		t.Fatal(err)
	}

	a := newP2PAPI(t)
	// One browser drives fifteen people from one address: limits sized for that.
	h := New(Config{Verifier: testVerifier, Kernel: a.svc, Store: a.db.Router, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		RatePerMinute: 100000, Abuse: AbuseConfig{PreAuthPerMinute: 1000000, MaxInFlight: 1024}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	a.srv = srv

	P := []string{a.project}
	// Master data and the approved BOQ, through the API (not part of the UI journey).
	controller, cfo := a.tok("u-controller-seed", nil, true, "controller"), a.tok("u-cfo-seed", nil, true, "cfo")
	buyer, procMgr := a.tok("u-buyer-seed", P, false, "procurement_officer"), a.tok("u-proc-manager-seed", P, false, "procurement_manager")
	finMgr, treasury := a.tok("u-finance-seed", nil, true, "finance_manager"), a.tok("u-treasury-seed", nil, true, "treasury_officer")
	pol := a.id("POST", "/v1/p2p/policies", controller, map[string]any{"legal_entity_id": a.entity, "price_tolerance_pct": "0.02", "over_receipt_pct": "0.05",
		"vat_rate": "0.15", "high_value_po_threshold": "5000000", "dual_payment_threshold": "500000", "grni_account_id": a.accounts["2100"],
		"ap_account_id": a.accounts["2000"], "vat_input_account_id": a.accounts["1300"], "ppv_account_id": a.accounts["5100"]})
	a.call(200, "POST", "/v1/p2p/policies/"+pol+"/approve", cfo, nil)
	var sup [3]string
	for i, code := range []string{"ABC-STEEL", "HABESHA-CEMENT", "SAFARI-BUILD"} {
		sup[i] = a.id("POST", "/v1/suppliers", buyer, map[string]any{"legal_entity_id": a.entity, "code": code, "name": code + " PLC", "tax_id": "TIN-UI-" + code})
		a.call(200, "POST", "/v1/suppliers/"+sup[i]+"/approve", procMgr, nil)
	}
	sb := a.id("POST", "/v1/suppliers/"+sup[0]+"/bank-accounts", buyer, map[string]any{"bank_name": "Commercial Bank of Ethiopia",
		"account_name": "ABC Steel PLC", "account_number": "1000123456789", "currency": "ETB"})
	a.call(200, "POST", "/v1/supplier-bank-accounts/"+sb+"/approve", finMgr, nil)
	bank := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Operating",
		"account_number": "1000999888777", "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)
	est, com := a.tok("u-estimator", P, false, "estimator"), a.tok("u-commercial", P, false, "commercial_manager")
	boq := a.id("POST", "/v1/boqs", est, map[string]any{"project_id": a.project, "description": "Tender BOQ rev A", "items": []map[string]any{
		{"item_no": "3.1", "description": "Reinforcement steel", "unit": "t", "quantity": "120", "rate": "85000", "cost_code_id": a.costCode},
		{"item_no": "3.2", "description": "OPC cement 50kg", "unit": "bag", "quantity": "2000", "rate": "950", "cost_code_id": a.costCode}}})
	a.call(200, "POST", "/v1/boqs/"+boq+"/submit", est, nil)
	a.call(200, "POST", "/v1/boqs/"+boq+"/approve", com, nil)

	// The people who use the console (one token, and one browser context, each).
	tokens := map[string]string{
		"siteEng": a.tok("u-site-engineer", P, false, "site_engineer"), "pm": a.tok("u-pm", P, false, "project_manager"),
		"pmMobile": a.tok("u-pm", P, false, "project_manager"), "buyer": a.tok("u-buyer", P, false, "procurement_officer"),
		"procMgr": a.tok("u-proc-manager", P, false, "procurement_manager"), "store": a.tok("u-storekeeper", P, false, "storekeeper"),
		"apClerk": a.tok("u-ap-clerk", P, false, "ap_clerk"), "apDual": a.tok("u-ap-clerk", P, false, "ap_clerk", "ap_supervisor"),
		"apSup": a.tok("u-ap-supervisor", P, false, "ap_supervisor"), "finMgr": a.tok("u-finance-manager", nil, true, "finance_manager"),
		"controller": a.tok("u-controller", nil, false, "controller"), "cfo": a.tok("u-cfo", nil, true, "cfo"),
		"treasury": a.tok("u-treasury", nil, true, "treasury_officer"), "treasury2": a.tok("u-treasury-2", nil, true, "treasury_officer"),
		"bankOfficer": a.tok("u-bank-officer", nil, false, "bank_statement_officer"), "accountant": a.tok("u-accountant", nil, false, "accountant"),
	}
	dir := t.TempDir()
	fx, _ := json.Marshal(map[string]any{"tokens": tokens, "entity": a.entity, "project": a.project, "bank": bank})
	fixture := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixture, fx, 0o600); err != nil {
		t.Fatal(err)
	}
	shots := os.Getenv("SERK_E2E_SHOTS")
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
	t.Logf("browser journey (%s):\n%s", time.Since(start).Round(time.Second), out)
	if err != nil {
		t.Fatalf("browser journey failed: %v (screenshots in %s)", err, shots)
	}

	// Independent verification through the API of what the UI did.
	ctl := a.tok("u-controller-check", nil, false, "controller")
	settled := a.call(200, "GET", "/v1/p2p/payment_instruction?status=SETTLED", ctl, nil)["items"].([]any)
	if len(settled) != 2 {
		t.Errorf("settled payments after the UI journey: %d, want 2", len(settled))
	}
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/p2p-reconciliation", ctl, nil)["checks"].([]any) {
		if m := c.(map[string]any); m["difference"] != "0" {
			t.Errorf("reconciliation break after the UI journey: %v", m)
		}
	}
	if drafts := a.call(200, "GET", "/v1/journals?status=DRAFT&source_prefix=P2P_", ctl, nil)["journals"].([]any); len(drafts) != 0 {
		t.Errorf("%d P2P journals left unposted", len(drafts))
	}
}
