package httpapi

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func (e *env) raw(path, token string) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func exportPath(src, format, title string) string {
	return "/v1/export?" + url.Values{"src": {src}, "format": {format}, "title": {title}}.Encode()
}

// Posted journals appear in the trial balance, which balances and exports in
// all three formats with the entity's name as letterhead. Exports pass the
// same authorisation as the read they render.
func TestAPIReportsAndExports(t *testing.T) {
	a := newP2PAPI(t)
	prep, appr, ctrl := a.token("prep", "accountant"), a.token("appr", "finance_manager"), a.token("ctrl", "controller")
	auditor := a.tok("u-auditor", nil, false, "auditor")
	for i, key := range []string{"tb-1", "tb-2"} {
		id := a.id("POST", "/v1/journals", prep, a.journalBody(key, "250.00"))
		a.call(200, "POST", "/v1/journals/"+id+"/approve", appr, nil)
		a.call(200, "POST", "/v1/journals/"+id+"/post", ctrl, nil)
		_ = i
	}
	tb := a.call(200, "GET", "/v1/reports/trial-balance?entity="+a.entity+"&as_of=2026-12-31", auditor, nil)
	if tb["balanced"] != true || tb["total_debit"] != "500" {
		t.Fatalf("trial balance %v", tb)
	}
	// Before the entries' date nothing is posted.
	if early := a.call(200, "GET", "/v1/reports/trial-balance?entity="+a.entity+"&as_of=2026-10-14", auditor, nil); early["total_debit"] != "0" {
		t.Fatalf("as-of filter: %v", early)
	}
	a.call(200, "GET", "/v1/reports/ap-aging?entity="+a.entity, auditor, nil)
	a.call(200, "GET", "/v1/reports/ar-aging?entity="+a.entity, auditor, nil)
	// Project-scoped people cannot see cross-project reports.
	siteEng := a.tok("u-site-engineer", []string{a.project}, false, "site_engineer")
	a.call(403, "GET", "/v1/reports/ap-aging?entity="+a.entity, siteEng, nil)
	a.call(403, "GET", "/v1/reports/trial-balance?entity="+a.entity, siteEng, nil)
	a.call(422, "GET", "/v1/reports/trial-balance?entity=nope", auditor, nil)

	src := "/v1/reports/trial-balance?entity=" + a.entity + "&as_of=2026-12-31"
	for _, f := range []string{"pdf", "docx", "xlsx"} {
		resp, body := a.raw(exportPath(src, f, "Trial balance"), auditor)
		if resp.StatusCode != 200 {
			t.Fatalf("%s export: %d %s", f, resp.StatusCode, body)
		}
		cd := resp.Header.Get("Content-Disposition")
		if !strings.HasPrefix(cd, `attachment; filename="serk-et-trial-balance-`) || !strings.HasSuffix(cd, "."+f+`"`) {
			t.Errorf("%s disposition %q", f, cd)
		}
		switch f {
		case "pdf":
			if !bytes.HasPrefix(body, []byte("%PDF-")) {
				t.Error("not a PDF")
			}
		default:
			zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			found := false
			for _, zf := range zr.File {
				if zf.Name == "docProps/app.xml" {
					rc, _ := zf.Open()
					x, _ := io.ReadAll(rc)
					found = strings.Contains(string(x), "<Company>SERK ET</Company>")
				}
			}
			if !found {
				t.Errorf("%s lacks the company letterhead", f)
			}
		}
	}
	// The read's refusal passes through: no export of what one may not read.
	resp, _ := a.raw(exportPath(src, "pdf", "x"), siteEng)
	if resp.StatusCode != 403 {
		t.Errorf("out-of-scope export: %d", resp.StatusCode)
	}
	if resp, _ := a.raw(exportPath(src, "pdf", "x"), ""); resp.StatusCode != 401 {
		t.Errorf("anonymous export: %d", resp.StatusCode)
	}
	for _, bad := range []string{"/v1/identity/me", "/v1/export?src=/v1/journals", "https://evil.example/v1/p2p/supplier", "//evil.example/v1/p2p/x",
		"/v1/p2p/../identity/me", "/healthz"} {
		if resp, b := a.raw(exportPath(bad, "pdf", "x"), auditor); resp.StatusCode != 422 {
			t.Errorf("src %q: %d %s", bad, resp.StatusCode, b)
		}
	}
	if resp, _ := a.raw(exportPath(src, "exe", "x"), auditor); resp.StatusCode != 422 {
		t.Errorf("format exe: %d", resp.StatusCode)
	}
	// A list export.
	if resp, body := a.raw(exportPath("/v1/p2p/supplier", "xlsx", "Suppliers"), auditor); resp.StatusCode != 200 || len(body) < 500 {
		t.Errorf("list export: %d", resp.StatusCode)
	}
}
