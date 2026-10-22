package httpapi

// Independent review 5 probes for IA-040-01 at the HTTP boundary.
// "held:" = control holds; t.Errorf "OPEN:" = it does not; "info:" = observation.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestR5_H1_ExistenceVariantsAndTenantWideRoutes(t *testing.T) {
	a := newP2PAPI(t)
	var logs bytes.Buffer
	srv := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: a.svc, Store: a.db.Router, RatePerMinute: 10000,
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}))
	defer srv.Close()
	a.srv = srv
	P := []string{a.project}
	controller, cfo := a.tok("u-controller", nil, true, "controller"), a.tok("u-cfo", nil, true, "cfo")
	buyer, procMgr := a.tok("u-buyer", P, false, "procurement_officer"), a.tok("u-proc-manager", P, false, "procurement_manager")
	finMgr, treasury := a.tok("u-finance-manager", nil, true, "finance_manager"), a.tok("u-treasury", nil, true, "treasury_officer")
	const supAcct, coAcct, coAcct2 = "3000123456789", "3000999888777", "3000555444333"

	pol := a.id("POST", "/v1/p2p/policies", controller, map[string]any{"legal_entity_id": a.entity, "price_tolerance_pct": "0.02", "over_receipt_pct": "0.05",
		"vat_rate": "0.15", "high_value_po_threshold": "5000000", "dual_payment_threshold": "500000", "grni_account_id": a.accounts["2100"],
		"ap_account_id": a.accounts["2000"], "vat_input_account_id": a.accounts["1300"], "ppv_account_id": a.accounts["5100"]})
	pol2 := a.id("POST", "/v1/p2p/policies", controller, map[string]any{"legal_entity_id": a.entity, "price_tolerance_pct": "0.02", "over_receipt_pct": "0.05",
		"vat_rate": "0.15", "high_value_po_threshold": "5000000", "dual_payment_threshold": "500000", "grni_account_id": a.accounts["2100"],
		"ap_account_id": a.accounts["2000"], "vat_input_account_id": a.accounts["1300"], "ppv_account_id": a.accounts["5100"]})
	a.call(200, "POST", "/v1/p2p/policies/"+pol+"/approve", cfo, nil)
	sup := a.id("POST", "/v1/suppliers", buyer, map[string]any{"legal_entity_id": a.entity, "code": "ABC-STEEL", "name": "ABC Steel PLC", "tax_id": "TIN-R5"})
	a.call(200, "POST", "/v1/suppliers/"+sup+"/approve", procMgr, nil)
	sb := a.id("POST", "/v1/suppliers/"+sup+"/bank-accounts", buyer, map[string]any{"bank_name": "CBE", "account_name": "ABC Steel PLC",
		"account_number": supAcct, "currency": "ETB"})
	a.call(200, "POST", "/v1/supplier-bank-accounts/"+sb+"/approve", finMgr, nil)
	bank := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Operating",
		"account_number": coAcct, "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)
	pending := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Payroll",
		"account_number": coAcct2, "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})

	const random = "00000000-0000-4000-8000-0000000000bb"
	pm := a.tok("u-pm", P, false, "project_manager")
	scopedCFO := a.tok("u-cfo-s", P, true, "cfo")
	scopedFM := a.tok("u-fm-s", P, true, "finance_manager")
	purpose := map[string]any{"purpose": "Independent review 5: call-back verification"}
	pair := func(name, method, pathReal, pathRandom, tok string, body any) {
		t.Helper()
		s1, b1 := a.do(method, pathReal, tok, body)
		s2, b2 := a.do(method, pathRandom, tok, body)
		j1, _ := json.Marshal(b1)
		j2, _ := json.Marshal(b2)
		if s1 != s2 || string(j1) != string(j2) {
			t.Errorf("OPEN: %s: out-of-scope %d %s vs nonexistent %d %s", name, s1, j1, s2, j2)
			return
		}
		t.Logf("held: %-44s out-of-scope == nonexistent: %d %s", name, s1, j1)
	}
	pair("GET policy (pm)", "GET", "/v1/p2p/p2p_policy/"+pol, "/v1/p2p/p2p_policy/"+random, pm, nil)
	pair("GET company bank (scoped cfo)", "GET", "/v1/p2p/company_bank_account/"+bank, "/v1/p2p/company_bank_account/"+random, scopedCFO, nil)
	pair("GET supplier bank (pm)", "GET", "/v1/p2p/supplier_bank_account/"+sb, "/v1/p2p/supplier_bank_account/"+random, pm, nil)
	pair("reveal company bank (scoped fm)", "POST", "/v1/p2p/company_bank_account/"+bank+"/reveal-bank-details",
		"/v1/p2p/company_bank_account/"+random+"/reveal-bank-details", scopedFM, purpose)
	pair("reveal supplier bank (scoped fm)", "POST", "/v1/p2p/supplier_bank_account/"+sb+"/reveal-bank-details",
		"/v1/p2p/supplier_bank_account/"+random+"/reveal-bank-details", scopedFM, purpose)
	pair("approve pending company bank (scoped cfo)", "POST", "/v1/company-bank-accounts/"+pending+"/approve", "/v1/company-bank-accounts/"+random+"/approve", scopedCFO, nil)
	pair("approve policy (scoped cfo)", "POST", "/v1/p2p/policies/"+pol2+"/approve", "/v1/p2p/policies/"+random+"/approve", scopedCFO, nil)

	// Id and type variants.
	up := strings.ToUpper(bank)
	for _, v := range []struct{ name, path string }{
		{"uppercase id", "/v1/p2p/company_bank_account/" + up},
		{"braced id", "/v1/p2p/company_bank_account/%7B" + bank + "%7D"},
		{"no-hyphen id", "/v1/p2p/company_bank_account/" + strings.ReplaceAll(bank, "-", "")},
		{"urn id", "/v1/p2p/company_bank_account/urn:uuid:" + bank},
		{"type upper", "/v1/p2p/COMPANY_BANK_ACCOUNT/" + bank},
		{"type bank_statement", "/v1/p2p/bank_statement/" + bank},
	} {
		s1, b1 := a.do("GET", v.path, cfo, nil)
		s2, b2 := a.do("GET", v.path, scopedCFO, nil)
		j1, _ := json.Marshal(b1)
		j2, _ := json.Marshal(b2)
		t.Logf("%-20s tenant-wide cfo -> %d %.160s | scoped cfo -> %d %.120s", v.name, s1, j1, s2, j2)
		if s2 == 200 {
			t.Errorf("OPEN: %s readable by scoped cfo", v.name)
		}
		if strings.HasSuffix(v.name, " id") && (s1 != 404 || s2 != 404) {
			t.Errorf("OPEN: non-canonical %s answered %d/%d, want 404", v.name, s1, s2)
		}
		if strings.Contains(string(j1), coAcct) {
			t.Errorf("OPEN: %s leaks the number", v.name)
		}
	}

	// Reveal response headers.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/p2p/company_bank_account/"+bank+"/reveal-bank-details", strings.NewReader(`{"purpose":"Independent review 5: call-back verification"}`))
	req.Header.Set("Authorization", "Bearer "+cfo)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 && resp.Header.Get("Cache-Control") == "no-store" {
		t.Logf("held: reveal 200 with Cache-Control: %s", resp.Header.Get("Cache-Control"))
	} else {
		t.Errorf("OPEN: reveal %d Cache-Control=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	// Unknown JSON fields / oversized purpose in the reveal body.
	st, body := a.do("POST", "/v1/p2p/company_bank_account/"+bank+"/reveal-bank-details", cfo, map[string]any{"purpose": strings.Repeat("p", 70000)})
	t.Logf("info: reveal with a 70 kB purpose -> %d %.120v", st, body)

	// Tenant-wide routes that use Has(scope.tenant_wide) instead of ScopeOf.
	sAcct := a.tok("u-acct-s", P, false, "accountant")
	sCtrl := a.tok("u-ctrl-s", P, false, "controller")
	sBank := a.tok("u-bank-s", P, false, "bank_statement_officer")
	st, body = a.do("GET", "/v1/journals", sAcct, nil)
	t.Logf("scoped accountant GET /v1/journals -> %d (%d journals)", st, func() int { l, _ := body["journals"].([]any); return len(l) }())
	if st == 200 {
		t.Errorf("OPEN: project-restricted accountant gets the tenant-wide journal worklist (200)")
	}
	st, body = a.do("GET", "/v1/entities/"+a.entity+"/p2p-reconciliation", sCtrl, nil)
	if st == 200 {
		t.Errorf("OPEN: project-restricted controller gets entity P2P reconciliation (200): %.200v", body)
	} else {
		t.Logf("held: scoped controller reconciliation -> %d", st)
	}
	stmt := fmt.Sprintf(`{"company_bank_id":%q,"statement_no":"R5-H1","statement_date":%q,"opening_balance":"100","closing_balance":"100","lines":[]}`,
		bank, time.Now().Format("2006-01-02"))
	st, body = a.do("POST", "/v1/bank-statements", sBank, stmt)
	if st == 201 {
		t.Errorf("OPEN: project-restricted statement officer imports a statement on an entity-level account it cannot read (201)")
	} else {
		t.Logf("scoped statement import -> %d %v", st, body)
	}
	st, body = a.do("GET", "/v1/p2p/company_bank_account/"+bank, sBank, nil)
	t.Logf("      same officer reading that account -> %d", st)
	who := a.call(200, "GET", "/v1/identity/me", sAcct, nil)
	t.Logf("info: /v1/identity/me for scoped accountant: tenant_wide=%v project_ids=%v", who["tenant_wide"], who["project_ids"])

	// Server log: no numbers.
	time.Sleep(50 * time.Millisecond)
	for _, n := range []string{supAcct, coAcct, coAcct2} {
		if strings.Contains(logs.String(), n) {
			t.Errorf("OPEN: server log contains a full account number")
		}
	}
	t.Logf("server log: %d bytes, %d lines; no full account numbers found unless reported above", logs.Len(), strings.Count(logs.String(), "\n"))
}
