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

// TestConsoleBrowserSite drives site operations (migration 0037) through the
// web console in a real Chromium: device registration with step-up, a diary
// recorded and submitted by the site engineer, approved by the project
// manager from the worklist, and the device revoked. The outcome is verified
// through the API. Skipped when node or playwright is not installed.
func TestConsoleBrowserSite(t *testing.T) {
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
	script, err := filepath.Abs("../../e2e/console_site.mjs")
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
	tokens := map[string]string{"eng": a.tok("u-site-eng", P, true, "site_engineer"), "pm": a.tok("u-pm", P, false, "project_manager"),
		"pmPhone": a.tok("u-pm", P, false, "project_manager")}
	dir := t.TempDir()
	fx, _ := json.Marshal(map[string]any{"tokens": tokens, "entity": a.entity, "project": a.project})
	fixture := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixture, fx, 0o600); err != nil {
		t.Fatal(err)
	}
	shots := os.Getenv("SERK_E2E_SHOTS_SITE")
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
	t.Logf("browser site journey (%s):\n%s", time.Since(start).Round(time.Second), out)
	if err != nil {
		t.Fatalf("browser site journey failed: %v (screenshots in %s)", err, shots)
	}
	pmCheck := a.tok("u-pm-check", P, false, "project_manager")
	if l := a.call(200, "GET", "/v1/p2p/site_diary?status=APPROVED", pmCheck, nil); len(l["items"].([]any)) != 1 {
		t.Errorf("approved diaries after the UI journey: %v", l)
	}
	devs := a.call(200, "GET", "/v1/site/devices", a.tok("u-site-eng", P, false, "site_engineer"), nil)
	if items := devs["items"].([]any); len(items) != 1 || items[0].(map[string]any)["status"] != "REVOKED" {
		t.Errorf("devices after the UI journey: %v", devs)
	}
}
