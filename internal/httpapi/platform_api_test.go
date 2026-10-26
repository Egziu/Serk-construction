package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/serk-group/serk-construction/internal/aiphrase"
)

// Platform routes end to end: settings, rules (maker/checker through the
// API), notifications, intelligence, assistant, export budget, staging
// companies.
func TestAPIPlatform(t *testing.T) {
	a := newP2PAPI(t)
	owner, wfAdmin, secAdmin := a.token("u-process-owner", "process_owner"), a.token("u-workflow-admin", "workflow_admin"), a.tok("u-security-admin", nil, true, "security_admin")
	pm := a.tok("u-pm", []string{a.project}, false, "project_manager")
	siteEng := a.tok("u-site-engineer", []string{a.project}, false, "site_engineer")
	auditor := a.tok("u-auditor", nil, false, "auditor")

	// Settings.
	cur := a.call(200, "GET", "/v1/tenant/settings", pm, nil)
	if cur["display_name"] != "api-test" || cur["version"].(float64) != 0 {
		t.Fatalf("defaults %v", cur)
	}
	a.call(403, "PUT", "/v1/tenant/settings", pm, map[string]any{"display_name": "Senselet Construction PLC", "short_code": "senselet", "country": "ET", "timezone": "Africa/Addis_Ababa", "locale": "en", "export_daily_limit": 2})
	saved := a.call(200, "PUT", "/v1/tenant/settings", secAdmin, map[string]any{"display_name": "Senselet Construction PLC", "short_code": "senselet", "letterhead_name": "SENSELET CONSTRUCTION PLC",
		"country": "ET", "timezone": "Africa/Addis_Ababa", "locale": "en", "export_daily_limit": 2})
	if saved["short_code"] != "senselet" || saved["version"].(float64) != 1 {
		t.Fatalf("saved %v", saved)
	}
	a.call(409, "PUT", "/v1/tenant/settings", secAdmin, map[string]any{"display_name": "Stale", "short_code": "senselet", "country": "ET", "timezone": "UTC", "locale": "en", "export_daily_limit": 2, "version": 0})

	// Export budget of 2: third export refused with 429 and security told.
	src := "/v1/p2p/supplier"
	for i := 0; i < 2; i++ {
		if resp, _ := a.raw(exportPath(src, "xlsx", "Suppliers"), auditor); resp.StatusCode != 200 {
			t.Fatalf("export %d: %d", i, resp.StatusCode)
		}
	}
	resp, body := a.raw(exportPath(src, "xlsx", "Suppliers"), auditor)
	if resp.StatusCode != 429 || !strings.Contains(string(body), "export_budget") || !strings.Contains(string(body), "security has been notified") {
		t.Fatalf("third export: %d %s", resp.StatusCode, body)
	}
	ns := a.call(200, "GET", "/v1/notifications", secAdmin, nil)
	if ns["unread"].(float64) != 1 {
		t.Fatalf("security notifications %v", ns)
	}
	nid := ns["items"].([]any)[0].(map[string]any)["id"].(string)
	a.call(200, "POST", "/v1/notifications/"+nid+"/read", secAdmin, nil)
	a.call(404, "POST", "/v1/notifications/"+nid+"/read", pm, nil)
	// The letterhead now comes from the company settings.
	resp, body = a.raw(exportPath(src, "pdf", "Suppliers"), pm)
	if resp.StatusCode != 200 {
		t.Fatalf("pm export: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "SENSELET CONSTRUCTION PLC") && !strings.Contains(string(body), "Confidential") {
		// Content streams are compressed; the Info dictionary carries the author.
		if !strings.Contains(string(body), "/Author (SENSELET CONSTRUCTION PLC)") {
			t.Fatal("letterhead not taken from the company settings")
		}
	}

	// Rules through the API.
	cat := a.call(200, "GET", "/v1/automation/catalogue", owner, nil)
	if len(cat["conditions"].([]any)) < 9 {
		t.Fatalf("catalogue %v", cat)
	}
	rule := a.call(201, "POST", "/v1/automation/rules", owner, map[string]any{"code": "PO-OVERDUE", "name": "Overdue POs",
		"body": map[string]any{"when": map[string]any{"kind": "po_overdue"}, "then": map[string]any{"notify_role": "procurement_manager", "severity": "warn"}}})
	rid := rule["id"].(string)
	a.call(422, "POST", "/v1/automation/rules", owner, map[string]any{"code": "BAD", "name": "Bad",
		"body": map[string]any{"when": map[string]any{"kind": "po_overdue"}, "then": map[string]any{"notify_role": "procurement_manager", "severity": "warn", "approve": true}}})
	a.call(403, "POST", "/v1/automation/rules/"+rid+"/activate", owner, nil) // no activate permission
	a.call(403, "POST", "/v1/automation/rules/"+rid+"/activate", pm, nil)
	// An author who also holds the activate permission is still refused (maker/checker).
	both := a.token("u-process-owner", "process_owner", "workflow_admin")
	a.call(409, "POST", "/v1/automation/rules/"+rid+"/activate", both, nil)
	act := a.call(200, "POST", "/v1/automation/rules/"+rid+"/activate", wfAdmin, nil)
	if act["status"] != "ACTIVE" {
		t.Fatalf("activate %v", act)
	}
	a.call(422, "POST", "/v1/automation/rules/"+rid+"/retire", wfAdmin, map[string]any{"reason": "no"})
	list := a.call(200, "GET", "/v1/automation/rules?status=ACTIVE", auditor, nil)
	if len(list["items"].([]any)) != 1 {
		t.Fatalf("list %v", list)
	}
	a.call(403, "GET", "/v1/automation/rules", siteEng, nil)

	// Intelligence and assistant.
	pf := a.call(200, "GET", "/v1/intelligence/portfolio", pm, nil)
	if len(pf["projects"].([]any)) != 1 {
		t.Fatalf("portfolio %v", pf)
	}
	risk := a.call(200, "GET", "/v1/intelligence/projects/"+a.project+"/risks", pm, nil)
	if risk["overall"] != "unknown" || risk["algorithm"] == "" {
		t.Fatalf("risks %v", risk)
	}
	a.call(403, "GET", "/v1/intelligence/projects/"+a.project+"/risks", siteEng, nil)
	a.call(403, "GET", "/v1/intelligence/cash?entity="+a.entity, pm, nil)
	a.call(200, "GET", "/v1/intelligence/cash?entity="+a.entity, auditor, nil)
	a.call(200, "GET", "/v1/intelligence/controls?entity="+a.entity, auditor, nil)
	ans := a.call(200, "POST", "/v1/assistant/ask", pm, map[string]any{"question": "Which projects are over budget?"})
	if ans["intent"] != "cost_risk" || ans["phrased_by_model"] != false {
		t.Fatalf("answer %v", ans)
	}
	a.call(403, "POST", "/v1/assistant/ask", siteEng, map[string]any{"question": "anything"})
	a.call(422, "POST", "/v1/assistant/ask", pm, map[string]any{"question": ""})
	// Unknown fields are refused (no hidden tool parameters).
	a.call(400, "POST", "/v1/assistant/ask", pm, map[string]any{"question": "x", "tool": "pay"})
}

// The staging sign-in offers several synthetic companies; a token is bound
// to the chosen one.
func TestStagingLoginCompanies(t *testing.T) {
	h := stagingServer(&StagingLogin{Passphrase: []byte("a-long-staging-passphrase"), Signer: testVerifier, Tenant: "5e4c0000-0000-4000-8000-00000000de30", Projects: []string{"p1"},
		Companies: []StagingCompany{{ID: "5e4c0000-0000-4000-8000-00000000de30", Name: "SERK Demo", Projects: []string{"p1"}}, {ID: "5e4c0000-0000-4000-8000-00000000de31", Name: "Senselet Construction PLC", Projects: []string{"p2"}}}})
	r := httptest.NewRequest("GET", "/staging/personas", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out struct {
		Vendor    string           `json:"vendor"`
		Companies []StagingCompany `json:"companies"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Vendor != "SERK Construction OS" || len(out.Companies) != 2 {
		t.Fatalf("%s", w.Body)
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/staging/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w = post(`{"passphrase":"a-long-staging-passphrase","persona":"u-pm","company":"5e4c0000-0000-4000-8000-00000000de31"}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var tok struct{ Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	p, err := testVerifier.Verify(tok.Token, time.Now())
	if err != nil || p.TenantID != "5e4c0000-0000-4000-8000-00000000de31" || len(p.ProjectIDs) != 1 || p.ProjectIDs[0] != "p2" {
		t.Fatalf("%+v %v", p, err)
	}
	if w := post(`{"passphrase":"a-long-staging-passphrase","persona":"u-pm","company":"nope"}`); w.Code != 422 {
		t.Fatalf("unknown company: %d", w.Code)
	}
}

// The phrasing adapter speaks the chat-completions protocol, sends only the
// facts, and refuses non-https endpoints.
func TestAIPhraserAdapter(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Rephrased."}}]}`))
	}))
	defer srv.Close()
	if _, err := aiphrase.New(aiphrase.Config{Endpoint: "http://model.example/v1", Model: "m"}); err == nil {
		t.Fatal("plain http endpoint accepted")
	}
	c, err := aiphrase.New(aiphrase.Config{Endpoint: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/v1/chat/completions", APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	text, err := c.Phrase(t.Context(), "Which projects are over budget?", map[string]any{"text": "None of the 2 projects."})
	if err != nil || text != "Rephrased." {
		t.Fatalf("%q %v", text, err)
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 2 || !strings.Contains(msgs[1].(map[string]any)["content"].(string), "None of the 2 projects") || got["tools"] != nil {
		t.Fatalf("request %v", got)
	}
}
