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

// TestConsoleBrowserJourneyC drives Journey C (stock valuation) through the
// web console in a real Chromium, one browser context per person. A confirmed
// goods receipt posted to inventory is seeded through the kernel; every stock
// step is done in the UI; the outcome is verified through the API. Skipped
// (never passed) without node and Playwright.
func TestConsoleBrowserJourneyC(t *testing.T) {
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
	script, err := filepath.Abs("../../e2e/console_journey_c.mjs")
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
	if err := a.db.AdminStore.WithTenant(a.db.Ctx, a.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, x := range []struct{ code, name, typ string }{{"1200", "Inventory", "ASSET"}, {"5200", "Stock count variance", "EXPENSE"}} {
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
	grn, jGRN := a.seedInventoryGRN(t)
	// The goods receipt journal is posted before the journey (finance step of Journey A).
	for _, path := range []string{"/v1/journals/approve-batch", "/v1/journals/post-batch"} {
		tok := map[string]string{"/v1/journals/approve-batch": a.tok("u-fm-seed", nil, true, "finance_manager"), "/v1/journals/post-batch": a.tok("u-ctl-seed", nil, false, "controller")}[path]
		a.call(200, "POST", path, tok, map[string]any{"journal_ids": []string{jGRN}})
	}
	tokens := map[string]string{
		"buyer": a.tok("u-buyer", P, false, "procurement_officer"), "finMgr": a.tok("u-finance-manager", nil, true, "finance_manager"),
		"procMgr": a.tok("u-proc-manager", P, false, "procurement_manager"), "store": a.tok("u-storekeeper", P, false, "storekeeper"),
		"storePhone": a.tok("u-storekeeper", P, false, "storekeeper"), "siteEng": a.tok("u-site-engineer", P, false, "site_engineer"),
		"invCtl": a.tok("u-inventory-controller", nil, false, "inventory_controller"), "controller": a.tok("u-controller", nil, false, "controller"),
	}
	dir := t.TempDir()
	fx, _ := json.Marshal(map[string]any{"tokens": tokens, "entity": a.entity, "project": a.project, "grn": grn})
	fixture := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(fixture, fx, 0o600); err != nil {
		t.Fatal(err)
	}
	shots := os.Getenv("SERK_E2E_SHOTS_C")
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
	t.Logf("browser journey C (%s):\n%s", time.Since(start).Round(time.Second), out)
	if err != nil {
		t.Fatalf("browser journey C failed: %v (screenshots in %s)", err, shots)
	}

	// Independent verification through the API.
	ctl := a.tok("u-controller-check", nil, false, "controller")
	lines := a.call(200, "GET", "/v1/entities/"+a.entity+"/stock-on-hand", ctl, nil)["lines"].([]any)
	if len(lines) != 1 || lines[0].(map[string]any)["qty"] != "6.5" || lines[0].(map[string]any)["value"] != "549250" {
		t.Errorf("stock on hand after the UI journey: %v", lines)
	}
	for _, c := range a.call(200, "GET", "/v1/entities/"+a.entity+"/stock-reconciliation", ctl, nil)["checks"].([]any) {
		m := c.(map[string]any)
		if !strings.HasPrefix(m["check"].(string), "Received") && m["difference"] != "0" {
			t.Errorf("stock reconciliation break after the UI journey: %v", m)
		}
	}
	if drafts := a.call(200, "GET", "/v1/journals?status=DRAFT&source_prefix=STK_", ctl, nil)["journals"].([]any); len(drafts) != 0 {
		t.Errorf("%d stock journals left unposted", len(drafts))
	}
}
