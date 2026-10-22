package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// IA-040-01 at the HTTP boundary: known-id reads by project-restricted
// tokens, masking in every response and error, the audited reveal, and no
// account number in the server log.
func TestAPI_IA04001_DocumentScopeAndBankMasking(t *testing.T) {
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
	const supAcct, coAcct = "2000123456789", "2000999888777"

	pol := a.id("POST", "/v1/p2p/policies", controller, map[string]any{"legal_entity_id": a.entity, "price_tolerance_pct": "0.02", "over_receipt_pct": "0.05",
		"vat_rate": "0.15", "high_value_po_threshold": "5000000", "dual_payment_threshold": "500000", "grni_account_id": a.accounts["2100"],
		"ap_account_id": a.accounts["2000"], "vat_input_account_id": a.accounts["1300"], "ppv_account_id": a.accounts["5100"]})
	a.call(200, "POST", "/v1/p2p/policies/"+pol+"/approve", cfo, nil)
	sup := a.id("POST", "/v1/suppliers", buyer, map[string]any{"legal_entity_id": a.entity, "code": "ABC-STEEL", "name": "ABC Steel PLC", "tax_id": "TIN-IA"})
	a.call(200, "POST", "/v1/suppliers/"+sup+"/approve", procMgr, nil)
	sb := a.id("POST", "/v1/suppliers/"+sup+"/bank-accounts", buyer, map[string]any{"bank_name": "CBE", "account_name": "ABC Steel PLC",
		"account_number": supAcct, "currency": "ETB"})
	a.call(200, "POST", "/v1/supplier-bank-accounts/"+sb+"/approve", finMgr, nil)
	bank := a.id("POST", "/v1/company-bank-accounts", treasury, map[string]any{"legal_entity_id": a.entity, "name": "CBE Operating",
		"account_number": coAcct, "currency": "ETB", "gl_account_id": a.accounts["1000"], "clearing_account_id": a.accounts["1050"]})
	a.call(200, "POST", "/v1/company-bank-accounts/"+bank+"/approve", cfo, nil)

	noLeak := func(what string, body any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		for _, n := range []string{supAcct, coAcct} {
			if strings.Contains(string(raw), n) {
				t.Errorf("EXPOSED: %s contains full account number %s", what, n)
			}
		}
	}
	// Known-id reads by project-restricted people: 404, same as a random id.
	restricted := map[string]string{
		"project manager": a.tok("u-pm", P, false, "project_manager"), "site engineer": a.tok("u-se", P, false, "site_engineer"),
		"storekeeper": a.tok("u-store", P, false, "storekeeper"), "other-project manager": a.tok("u-pm2", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, false, "project_manager"),
		"project-restricted auditor": a.tok("u-analyst", P, false, "auditor"),
	}
	_, random := a.do("GET", "/v1/p2p/p2p_policy/00000000-0000-4000-8000-000000000000", restricted["project manager"], nil)
	for who, tok := range restricted {
		for typ, id := range map[string]string{"p2p_policy": pol, "company_bank_account": bank, "supplier_bank_account": sb} {
			st, body := a.do("GET", "/v1/p2p/"+typ+"/"+id, tok, nil)
			noLeak(who+" "+typ+" response", body)
			if st != 404 {
				t.Errorf("EXPOSED: %s GET %s by id: %d", who, typ, st)
				continue
			}
			if b, _ := json.Marshal(body); string(b) != func() string { r, _ := json.Marshal(random); return string(r) }() {
				t.Errorf("%s: out-of-scope response differs from a nonexistent id: %s", who, b)
			}
			if items := a.call(200, "GET", "/v1/p2p/"+typ, tok, nil)["items"].([]any); len(items) != 0 {
				t.Errorf("%s lists %d %s", who, len(items), typ)
			}
		}
	}
	// Authorised readers get masked numbers only.
	for what, path := range map[string]string{"supplier bank (finance)": "/v1/p2p/supplier_bank_account/" + sb,
		"company bank (finance)": "/v1/p2p/company_bank_account/" + bank} {
		body := a.call(200, "GET", path, finMgr, nil)
		noLeak(what, body)
		if !strings.Contains(func() string { b, _ := json.Marshal(body); return string(b) }(), "****") {
			t.Errorf("%s: no masked number in %v", what, body)
		}
	}
	noLeak("supplier bank (buyer)", a.call(200, "GET", "/v1/p2p/supplier_bank_account/"+sb, buyer, nil))
	noLeak("supplier bank list", a.call(200, "GET", "/v1/p2p/supplier_bank_account", finMgr, nil))
	// A rejected account number is not echoed in the error.
	st, body := a.do("POST", "/v1/suppliers/"+sup+"/bank-accounts", buyer, map[string]any{"bank_name": "CBE", "account_name": "x",
		"account_number": supAcct, "currency": "ETB"}) // duplicate
	noLeak("duplicate-account error", body)
	t.Logf("duplicate supplier account rejected: %d %v", st, body)

	purpose := map[string]any{"purpose": "Call-back verification of new payee details"}
	// Reveal: refused without the permission, without fresh MFA, out of scope.
	if st, _ := a.do("POST", "/v1/p2p/supplier_bank_account/"+sb+"/reveal-bank-details", buyer, purpose); st != 403 {
		t.Errorf("reveal by procurement officer: %d", st)
	}
	if st, _ := a.do("POST", "/v1/p2p/supplier_bank_account/"+sb+"/reveal-bank-details", a.tok("u-finance-manager", nil, false, "finance_manager"), purpose); st != 401 {
		t.Errorf("reveal without fresh MFA: %d", st)
	}
	if st, _ := a.do("POST", "/v1/p2p/company_bank_account/"+bank+"/reveal-bank-details", a.tok("u-fm2", P, true, "finance_manager"), purpose); st != 404 {
		t.Errorf("project-restricted reveal of a company account: %d", st)
	}
	got := a.call(200, "POST", "/v1/p2p/supplier_bank_account/"+sb+"/reveal-bank-details", finMgr, purpose)
	if got["account_number"] != supAcct {
		t.Errorf("reveal returned %v", got)
	}
	// The server log carries neither account numbers nor bearer tokens.
	time.Sleep(50 * time.Millisecond)
	for _, n := range []string{supAcct, coAcct, finMgr, "Bearer "} {
		if strings.Contains(logs.String(), n) {
			t.Errorf("EXPOSED: server log contains %q", n[:min(len(n), 12)])
		}
	}
	_ = io.Discard
	_ = http.StatusOK
}
