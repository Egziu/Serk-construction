package httpapi

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/obs"
	"github.com/serk-group/serk-construction/internal/store/postgres"
)

// Distributed abuse limits (migration 0029): two API replicas sharing one
// database-backed store enforce one limit between them. Each test uses a
// fresh HMAC key, so counters from other runs never collide.

func abuseKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// sharedReplicas starts n API servers over the same kernel and abuse store.
func sharedReplicas(t *testing.T, e *env, store AbuseStore, key []byte, n, rate int, abuse AbuseConfig) ([]*httptest.Server, *obs.Registry) {
	t.Helper()
	abuse.Shared, abuse.KeySecret = store, key
	reg := obs.NewRegistry()
	var out []*httptest.Server
	for i := 0; i < n; i++ {
		srv := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router, Metrics: reg,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: rate, Abuse: abuse}))
		t.Cleanup(srv.Close)
		out = append(out, srv)
	}
	return out, reg
}

func statusOf(t *testing.T, srv *httptest.Server, token string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/journals/"+uuid.NewString(), nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func abuseStore(t *testing.T, e *env) (postgres.AbuseStore, *pgxpool.Pool) {
	t.Helper()
	pool, err := pgxpool.New(e.db.Ctx, e.db.LoginRole(t, "serk_abuse"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return postgres.AbuseStore{Pool: pool}, pool
}

func TestSharedAbuse_LockoutAndBudgetsSpanReplicas(t *testing.T) {
	e := newEnv(t)
	store, _ := abuseStore(t, e)
	good := e.token("u-reader", "accountant")

	// 1. Invalid credentials: 4 per minute with lockout. Two failures on each
	// replica reach the limit together; both replicas then refuse even a
	// valid token. Per-process limiters would have allowed 4 per replica.
	rs, _ := sharedReplicas(t, e, store, abuseKey(t), 2, 1000, AbuseConfig{AuthFailuresPerMinute: 4, PreAuthPerMinute: 1000})
	for i := 0; i < 2; i++ {
		for _, r := range rs {
			if st := statusOf(t, r, "junk."+uuid.NewString()); st != 401 && st != 429 {
				t.Fatalf("bad token: %d", st)
			}
		}
	}
	for i, r := range rs {
		if st := statusOf(t, r, good); st != 429 {
			t.Errorf("replica %d after 4 failures spread over 2 replicas: %d, want 429 (lockout shared)", i, st)
		}
	}
	// Control: the same traffic against per-process replicas is not locked
	// out (this is the defect the shared store closes).
	var local []*httptest.Server
	for i := 0; i < 2; i++ {
		srv := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: 1000, Abuse: AbuseConfig{AuthFailuresPerMinute: 4, PreAuthPerMinute: 1000}}))
		t.Cleanup(srv.Close)
		local = append(local, srv)
	}
	for i := 0; i < 2; i++ {
		for _, r := range local {
			statusOf(t, r, "junk."+uuid.NewString())
		}
	}
	if st := statusOf(t, local[0], good); st == 429 {
		t.Errorf("control: per-process replicas locked out after 2 failures each (%d); the shared test does not discriminate", st)
	}

	// 2. Pre-authentication budget: 6 per minute per client across replicas.
	rs, _ = sharedReplicas(t, e, store, abuseKey(t), 3, 1000, AbuseConfig{AuthFailuresPerMinute: 1000, PreAuthPerMinute: 6})
	for i := 0; i < 6; i++ {
		if st := statusOf(t, rs[i%3], good); st == 429 {
			t.Fatalf("request %d of 6 refused", i+1)
		}
	}
	for i, r := range rs {
		if st := statusOf(t, r, good); st != 429 {
			t.Errorf("replica %d, 7th+ request of a 6/min budget spread over 3 replicas: %d, want 429", i, st)
		}
	}

	// 3. Per-principal budget: 4 per minute across replicas.
	rs, _ = sharedReplicas(t, e, store, abuseKey(t), 2, 4, AbuseConfig{AuthFailuresPerMinute: 1000, PreAuthPerMinute: 1000})
	codes := []int{}
	for i := 0; i < 6; i++ {
		codes = append(codes, statusOf(t, rs[i%2], good))
	}
	refused := 0
	for _, c := range codes {
		if c == 429 {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("principal budget 4/min over 2 replicas, 6 requests: %v (want exactly 2 refused)", codes)
	}
}

// The counters hold only HMAC digests: no client address or user id is stored.
func TestSharedAbuse_StoresDigestsOnly(t *testing.T) {
	e := newEnv(t)
	store, _ := abuseStore(t, e)
	rs, _ := sharedReplicas(t, e, store, abuseKey(t), 1, 1000, AbuseConfig{AuthFailuresPerMinute: 3, PreAuthPerMinute: 1000})
	statusOf(t, rs[0], e.token("u-digest-probe", "accountant"))
	statusOf(t, rs[0], "junk")
	var leaks, rows int
	if err := e.db.Admin.QueryRow(e.db.Ctx, `SELECT count(*) FILTER (WHERE position('127.0.0.1'::bytea IN key_hash) > 0 OR position('u-digest-probe'::bytea IN key_hash) > 0), count(*)
		FROM abuse_counters WHERE octet_length(key_hash) = 32`).Scan(&leaks, &rows); err != nil {
		t.Fatal(err)
	}
	if rows == 0 || leaks != 0 {
		t.Errorf("abuse_counters: %d digest rows, %d containing a raw key", rows, leaks)
	}
}

// The abuse login executes the two counter functions and nothing else; the
// tenant role cannot reach them.
func TestSharedAbuse_RolePrivileges(t *testing.T) {
	e := newEnv(t)
	_, pool := abuseStore(t, e)
	ctx := e.db.Ctx
	for _, q := range []string{
		`SELECT count(*) FROM abuse_counters`,
		`DELETE FROM abuse_counters`,
		`SELECT count(*) FROM journals`,
		`SELECT count(*) FROM approval_keys`,
		`SELECT abuse_hit('preauth', '\x00'::bytea, 1, 60, 0)`, // key is not 32 bytes
		`SELECT abuse_hit('preauth', decode(repeat('ab', 32), 'hex'), 0, 60, 0)`,
		`SELECT abuse_hit('PREAUTH; DROP', decode(repeat('ab', 32), 'hex'), 1, 60, 0)`,
		`CREATE TABLE abuse_probe(x int)`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil {
			t.Errorf("abuse login: %q accepted", q)
		}
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT abuse_hit('preauth', decode(repeat('cd', 32), 'hex'), 2, 60, 0)`).Scan(&ok); err != nil || !ok {
		t.Errorf("abuse login cannot count: %v %v", ok, err)
	}
	var tenantCan, healthCan bool
	if err := e.db.Admin.QueryRow(ctx, `SELECT has_function_privilege('serk_app', 'abuse_hit(text,bytea,integer,integer,integer)', 'EXECUTE'),
		has_function_privilege('serk_health', 'abuse_blocked(text,bytea)', 'EXECUTE')`).Scan(&tenantCan, &healthCan); err != nil {
		t.Fatal(err)
	}
	if tenantCan || healthCan {
		t.Errorf("abuse functions executable by serk_app=%v serk_health=%v", tenantCan, healthCan)
	}
}

type failingStore struct{ calls atomic.Int64 }

func (f *failingStore) Hit(context.Context, string, []byte, int, time.Duration, time.Duration) (bool, error) {
	f.calls.Add(1)
	return false, errors.New("store down")
}

func (f *failingStore) Blocked(context.Context, string, []byte) (bool, error) {
	f.calls.Add(1)
	return false, errors.New("store down")
}

// A failing store neither opens the door nor closes it: each replica falls
// back to its own limits and the failure is counted for alerting.
func TestSharedAbuse_StoreFailureFallsBackToLocalLimits(t *testing.T) {
	e := newEnv(t)
	fs := &failingStore{}
	rs, reg := sharedReplicas(t, e, fs, abuseKey(t), 1, 1000, AbuseConfig{AuthFailuresPerMinute: 3, PreAuthPerMinute: 1000})
	good := e.token("u-reader", "accountant")
	if st := statusOf(t, rs[0], good); st == 429 || st == 503 {
		t.Fatalf("a store outage refused a normal request: %d", st)
	}
	for i := 0; i < 3; i++ {
		statusOf(t, rs[0], "junk")
	}
	if st := statusOf(t, rs[0], good); st != 429 {
		t.Errorf("after 3 failures with the store down: %d, want 429 from the local limiter", st)
	}
	var b strings.Builder
	if _, err := reg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	if fs.calls.Load() == 0 || !strings.Contains(b.String(), `serk_abuse_store_errors_total{scope="auth_failure"}`) {
		t.Errorf("store failures not counted (calls %d):\n%s", fs.calls.Load(), b.String())
	}
}
