package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/obs"
)

// scrape parses the text exposition into series -> value and name -> sum.
func scrape(t *testing.T, reg *obs.Registry) (map[string]float64, map[string]float64) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := reg.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	series, byName := map[string]float64{}, map[string]float64{}
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			t.Fatalf("bad exposition line %q", line)
		}
		s := line[:i]
		series[s] = v
		name := s
		if j := strings.IndexByte(s, '{'); j >= 0 {
			name = s[:j]
		}
		if !strings.HasSuffix(name, "_bucket") {
			byName[name] += v
		}
	}
	return series, byName
}

type alertRule struct {
	name, expr string
	evaluated  bool // marked "drill: evaluated" in the rules file
}

func loadAlertRules(t *testing.T) []alertRule {
	t.Helper()
	b, err := os.ReadFile("../../deploy/observability/prometheus-alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	var rules []alertRule
	alertRe := regexp.MustCompile(`^\s*- alert: (\w+)\s*(# drill: (evaluated|not evaluated))?`)
	exprRe := regexp.MustCompile(`^\s*expr: (.*)$`)
	for _, line := range strings.Split(string(b), "\n") {
		if m := alertRe.FindStringSubmatch(line); m != nil {
			rules = append(rules, alertRule{name: m[1], evaluated: m[3] == "evaluated"})
			continue
		}
		if m := exprRe.FindStringSubmatch(line); m != nil && len(rules) > 0 {
			rules[len(rules)-1].expr = strings.TrimSpace(m[1])
		}
	}
	return rules
}

var (
	gaugeExpr    = regexp.MustCompile(`^(serk_[a-z_]+) (>|>=|==) ([0-9.]+)$`)
	increaseExpr = regexp.MustCompile(`^increase\((serk_[a-z_]+)\[[0-9]+[smh]\]\) (>|>=|==) ([0-9.]+)$`)
)

func cmp(v float64, op string, th float64) bool {
	switch op {
	case ">":
		return v > th
	case ">=":
		return v >= th
	}
	return v == th
}

// firing evaluates the simple rules against a scrape (and, for increase(),
// the delta from a baseline scrape).
func firing(t *testing.T, rules []alertRule, base, now map[string]float64) []string {
	t.Helper()
	var out []string
	for _, r := range rules {
		if !r.evaluated {
			continue
		}
		if m := gaugeExpr.FindStringSubmatch(r.expr); m != nil {
			th, _ := strconv.ParseFloat(m[3], 64)
			if v, ok := now[m[1]]; ok && cmp(v, m[2], th) {
				out = append(out, r.name)
			}
			continue
		}
		if m := increaseExpr.FindStringSubmatch(r.expr); m != nil {
			th, _ := strconv.ParseFloat(m[3], 64)
			if cmp(now[m[1]]-base[m[1]], m[2], th) {
				out = append(out, r.name)
			}
			continue
		}
		t.Fatalf("rule %s is marked 'drill: evaluated' but its expression is not evaluable here: %q", r.name, r.expr)
	}
	sort.Strings(out)
	return out
}

// GATEA-11 alert drill. A dedicated database gives a clean baseline; real
// failures are then induced (as the operator/superuser would see them happen)
// and the rules in deploy/observability/prometheus-alerts.yml are evaluated
// against the scraped metrics. Prometheus/Alertmanager routing itself is not
// part of this drill (not available in this environment).
func TestAlertDrill_InducedFailuresFireTheRightAlerts(t *testing.T) {
	adminDSN := os.Getenv("SERK_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("SERK_TEST_ADMIN_DSN not set")
	}
	ctx := context.Background()
	// Fresh database for this drill.
	dbName := "serk_drill_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	admin0, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin0.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin0.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, dbName)
		_, _ = admin0.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
		_ = admin0.Close(ctx)
	})
	u, _ := url.Parse(adminDSN)
	u.Path = "/" + dbName
	t.Setenv("SERK_TEST_ADMIN_DSN", u.String())

	e := newEnv(t)
	reg := obs.NewRegistry()
	monPool, err := pgxpool.New(ctx, e.db.LoginRole(t, "serk_monitor"))
	if err != nil {
		t.Fatal(err)
	}
	reg.Collect(obs.DBHealth{Pool: monPool}.Collector())
	srv := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router, Metrics: reg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: 1000, Abuse: AbuseConfig{AuthFailuresPerMinute: 1000}}))
	t.Cleanup(srv.Close)
	e.srv = srv
	rules := loadAlertRules(t)

	// Healthy baseline: a normal journal lifecycle produces outbox events
	// (no relay runs here, so they stay pending but young).
	prep, appr := e.token("u-prep", "accountant"), e.token("u-appr", "finance_manager")
	code, out := e.do("POST", "/v1/journals", prep, e.journalBody("drill-1", "250.00"))
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	jid := out["id"].(string)
	if code, out := e.do("POST", "/v1/journals", prep, e.journalBody("drill-1b", "250.00")); code != 201 && code != 200 {
		t.Fatalf("create 1b: %d %v", code, out)
	}
	base, baseByName := scrape(t, reg)
	_ = base
	if f := firing(t, rules, baseByName, baseByName); len(f) != 0 {
		t.Fatalf("alerts firing on a healthy baseline: %v", f)
	}
	if baseByName["serk_db_health_up"] != 1 {
		t.Fatalf("monitor login cannot read health: %v", baseByName)
	}

	su := e.db.Admin // schema owner/superuser: the out-of-band actor
	exec := func(what, q string, args ...any) {
		t.Helper()
		if _, err := su.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	// 1. Relay stuck for an hour (time passage simulated by backdating).
	exec("replica role", `SET session_replication_role = replica`)
	exec("backdate outbox", `UPDATE outbox SET created_at = now() - interval '1 hour' WHERE tenant_id = $1::uuid`, e.tenant)
	// 2. One event exhausted its retries.
	exec("dead letter", `UPDATE outbox SET dead_at = now(), attempts = 10 WHERE id = (SELECT min(id) FROM outbox WHERE tenant_id = $1::uuid)`, e.tenant)
	// 3. Out-of-band ledger change: an unbalanced POSTED journal.
	exec("plant line", `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency)
		VALUES ($1::uuid,$2::uuid,$3::uuid,99,$4::uuid,'DEBIT',1,'ETB')`, jid, e.tenant, e.entity, e.accounts["5000"])
	exec("force posted", `UPDATE journals SET status='POSTED', approved_by='x', approved_at=now(), posted_by='y', posted_at=now() WHERE id=$1::uuid`, jid)
	// 4. Audit log truncated behind the head.
	exec("truncate audit tail", `DELETE FROM audit_log WHERE seq = (SELECT max(seq) FROM audit_log WHERE tenant_id = $1::uuid)`, e.tenant)
	exec("replica role off", `SET session_replication_role = origin`)
	// 5. The tenant's approval key deactivated (tampering or a botched
	//    rotation): the API's next approval is refused BY THE DATABASE.
	code2, out2 := e.do("POST", "/v1/journals", prep, e.journalBody("drill-2", "250.00"))
	if code2 != 201 && code2 != 200 {
		t.Fatalf("create 2: %d %v", code2, out2)
	}
	exec("deactivate key", `UPDATE approval_keys SET active = false WHERE tenant_id = $1::uuid`, e.tenant)
	if code, out := e.do("POST", "/v1/journals/"+out2["id"].(string)+"/approve", appr, nil); code != 409 {
		t.Fatalf("approval with a deactivated key: %d %v", code, out)
	}
	exec("reactivate key", `UPDATE approval_keys SET active = true WHERE tenant_id = $1::uuid`, e.tenant)
	// 6. Credential stuffing: 25 invalid tokens.
	for i := 0; i < 25; i++ {
		req, _ := http.NewRequest("GET", srv.URL+"/v1/workflow/tasks", nil)
		req.Header.Set("Authorization", "Bearer not-a-token-"+strconv.Itoa(i))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	// 7. A revoked session is presented.
	victim := e.tokenAt("u-leaver", "jti-drill", time.Now().Add(-time.Minute), "accountant")
	if code, _ := e.do("POST", "/v1/identity/logout", victim, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := e.do("GET", "/v1/workflow/tasks", victim, nil); code != 401 {
		t.Fatalf("revoked session: %d", code)
	}

	_, nowByName := scrape(t, reg)
	got := firing(t, rules, baseByName, nowByName)
	want := []string{"SerkApprovalRefusedAtDatabase", "SerkAuditChainMismatch", "SerkAuthFailureSpike", "SerkLedgerIntegrityViolation",
		"SerkOutboxDeadLetters", "SerkOutboxLagCritical", "SerkOutboxLagHigh", "SerkRevokedSessionUsed"}
	t.Logf("metrics after inducing failures: ledger_violations=%v audit_mismatches=%v outbox_lag_s=%.0f dead_letters=%v authority_refusals=%v auth_failures=%v revoked_uses=%v",
		nowByName["serk_ledger_integrity_violations"], nowByName["serk_audit_head_mismatches"], nowByName["serk_outbox_oldest_pending_age_seconds"],
		nowByName["serk_outbox_dead_letters"], nowByName["serk_db_authority_refusals_total"], nowByName["serk_auth_failures_total"], nowByName["serk_revoked_session_uses_total"])
	t.Logf("alerts firing: %v", got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("firing alerts = %v\nwant           %v", got, want)
	}

	// 8. Fail-safe: when health cannot be read, the scrape says so and the
	//    blind-monitoring alert fires (no data must not look healthy).
	monPool.Close()
	_, blind := scrape(t, reg)
	if fb := firing(t, rules, nowByName, blind); !contains(fb, "SerkDBHealthScrapeFailing") {
		t.Fatalf("health scrape failure not alerted: %v (up=%v)", fb, blind["serk_db_health_up"])
	}
	t.Logf("monitor pool closed: serk_db_health_up=%v -> SerkDBHealthScrapeFailing fires", blind["serk_db_health_up"])
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Request telemetry: counters by route pattern (bounded cardinality: the id
// is never a label), latency histogram, and W3C trace context continuation.
func TestRequestTelemetryAndTraceContext(t *testing.T) {
	e := newEnv(t)
	reg := obs.NewRegistry()
	var logs bytes.Buffer
	srv := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router, Metrics: reg,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)), RatePerMinute: 100}))
	t.Cleanup(srv.Close)
	e.srv = srv
	tok := e.token("u-prep", "accountant")
	for i := 0; i < 3; i++ {
		e.do("GET", "/v1/journals/"+uuid.NewString(), tok, nil)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/v1/workflow/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tp := resp.Header.Get("traceparent"); !strings.HasPrefix(tp, "00-4bf92f3577b34da6a3ce929d0e0e4736-") {
		t.Errorf("trace not continued: %q", tp)
	}
	series, _ := scrape(t, reg)
	if v := series[`serk_http_requests_total{route="GET /v1/journals/{id}",method="GET",code="404"}`]; v != 3 {
		t.Errorf("route-pattern counter = %v; series: %v", v, keys(series, "serk_http_requests_total"))
	}
	if v := series[`serk_http_request_duration_seconds_count{route="GET /v1/journals/{id}"}`]; v != 3 {
		t.Errorf("latency histogram count = %v", v)
	}
	if !strings.Contains(logs.String(), `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`) || !strings.Contains(logs.String(), `"sub":"u-prep"`) {
		t.Errorf("log lines lack trace_id/sub: %s", logs.String())
	}
	if strings.Contains(logs.String(), tok) {
		t.Error("bearer token written to logs")
	}
}

func keys(m map[string]float64, prefix string) []string {
	var out []string
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
