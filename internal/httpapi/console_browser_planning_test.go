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

// TestConsoleBrowserPlanning drives planning (migration 0027) through the web
// console in a real Chromium: the planner builds the textbook network in the
// schedule form, submits it, the project manager approves the baseline, the
// planner reports progress, the project manager approves it, and earned value
// is read on the EVM page. The outcome is verified through the API. Skipped
// (never passed) without node and Playwright.
func TestConsoleBrowserPlanning(t *testing.T) {
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
	script, err := filepath.Abs("../../e2e/console_planning.mjs")
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
	estimator, commercial := a.tok("u-estimator", P, false, "estimator"), a.tok("u-commercial", P, false, "commercial_manager")
	boq := a.id("POST", "/v1/boqs", estimator, map[string]any{"project_id": a.project, "description": "Tender BOQ rev A", "items": []map[string]any{
		{"item_no": "3.1", "description": "Reinforcement steel", "unit": "t", "quantity": "120", "rate": "85000", "cost_code_id": a.costCode}}})
	a.call(200, "POST", "/v1/boqs/"+boq+"/submit", estimator, nil)
	a.call(200, "POST", "/v1/boqs/"+boq+"/approve", commercial, map[string]any{"reason": "priced to tender"})
	tokens := map[string]string{"planner": a.tok("u-planner", P, false, "planner"), "pm": a.tok("u-pm", P, false, "project_manager"),
		"pmPhone": a.tok("u-pm", P, false, "project_manager")}
	dir := t.TempDir()
	fx, _ := json.Marshal(map[string]any{"tokens": tokens, "entity": a.entity, "project": a.project})
	fixture := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixture, fx, 0o600); err != nil {
		t.Fatal(err)
	}
	shots := os.Getenv("SERK_E2E_SHOTS_PLANNING")
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
	t.Logf("browser planning journey (%s):\n%s", time.Since(start).Round(time.Second), out)
	if err != nil {
		t.Fatalf("browser planning journey failed: %v (screenshots in %s)", err, shots)
	}
	ev := a.call(200, "GET", "/v1/projects/"+a.project+"/evm?status_date=2026-10-14", a.tok("u-pm-check", P, false, "project_manager"), nil)
	if ev["pv"] != "4700000" || ev["ev"] != "3850000" || ev["spi"] != "0.8191" {
		t.Errorf("earned value after the UI journey: %v", ev)
	}
}
