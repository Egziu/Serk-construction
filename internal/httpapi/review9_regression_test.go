package httpapi

// Independent review 9 probes of migration 0029 (shared abuse limits).
// "OPEN:" (t.Errorf) = a defect observed; "held:" / "info:" (t.Logf).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/store/postgres"
)

func r9status(t *testing.T, srv *httptest.Server, token, xff string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/journals/"+uuid.NewString(), nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func r9pool(t *testing.T, e *env, maxConns int) (postgres.AbuseStore, *pgxpool.Pool) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(e.db.LoginRole(t, "serk_abuse"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = int32(maxConns)
	pool, err := pgxpool.NewWithConfig(e.db.Ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return postgres.AbuseStore{Pool: pool}, pool
}

func TestR9_AbuseClientKeys(t *testing.T) {
	e := newEnv(t)
	store, _ := r9pool(t, e, 8)
	good := e.token("u-reader", "accountant")
	proxy := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

	// No trusted proxy: a client-supplied X-Forwarded-For is ignored.
	rs, _ := sharedReplicas(t, e, store, abuseKey(t), 1, 1000, AbuseConfig{AuthFailuresPerMinute: 3, PreAuthPerMinute: 1000})
	for i := 0; i < 3; i++ {
		r9status(t, rs[0], "junk", fmt.Sprintf("203.0.113.%d", i+1))
	}
	if st := r9status(t, rs[0], good, "203.0.113.200"); st == 429 {
		t.Logf("held: without trusted proxies, rotating X-Forwarded-For does not evade the lockout (good token -> %d)", st)
	} else {
		t.Errorf("OPEN: rotating X-Forwarded-For without trusted proxies evaded the lockout: %d", st)
	}

	// Behind a trusted proxy: one IPv4 address is locked out ...
	rs, _ = sharedReplicas(t, e, store, abuseKey(t), 2, 1000, AbuseConfig{AuthFailuresPerMinute: 3, PreAuthPerMinute: 1000, TrustedProxies: proxy})
	for i := 0; i < 3; i++ {
		r9status(t, rs[i%2], "junk", "198.51.100.7")
	}
	st4 := r9status(t, rs[0], good, "198.51.100.7")
	// ... and the same for one IPv6 address,
	for i := 0; i < 3; i++ {
		r9status(t, rs[i%2], "junk", "2001:db8:7:1::1")
	}
	st6 := r9status(t, rs[1], good, "2001:db8:7:1::1")
	t.Logf("held: through the trusted proxy, after 3 failures: IPv4 client -> %d, IPv6 client -> %d", st4, st6)

	// ... but every other address of the same /64 is a new client.
	var before, after int64
	if err := e.db.Admin.QueryRow(e.db.Ctx, `SELECT count(*) FROM abuse_counters`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	limited := 0
	for i := 0; i < 60; i++ {
		if r9status(t, rs[i%2], "junk."+uuid.NewString(), fmt.Sprintf("2001:db8:7:1::%x", 0x100+i)) == 429 {
			limited++
		}
	}
	stAfter := r9status(t, rs[0], good, "2001:db8:7:1::ffff")
	if err := e.db.Admin.QueryRow(e.db.Ctx, `SELECT count(*) FROM abuse_counters`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	t.Logf("60 invalid tokens from 60 addresses of 2001:db8:7:1::/64 (limit 3 per minute with lockout): %d answered 429; a valid token from the same /64 -> %d; abuse_counters rows %d -> %d",
		limited, stAfter, before, after)
	if limited == 0 && stAfter != 429 {
		t.Errorf("OPEN: the per-client limits are keyed by the full IPv6 address: 60 failures from one /64 were never limited (the lockout is per /128), and each address added counter rows (%d -> %d)", before, after)
	}
	// IPv4-mapped and textual variants canonicalise to one key.
	ks := map[string]bool{}
	for _, s := range []string{"198.51.100.7", "::ffff:198.51.100.7", "::FFFF:c633:6407"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		r.Header.Set("X-Forwarded-For", s)
		ks[clientIP(r, proxy).String()] = true
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "fe80::1%eth0")
	z1 := clientIP(r, proxy).String()
	r.Header.Set("X-Forwarded-For", "fe80::1%eth1")
	z2 := clientIP(r, proxy).String()
	t.Logf("info: IPv4 / IPv4-mapped variants -> %d key(s) %v; zoned addresses -> %q and %q", len(ks), ks, z1, z2)
}

// The 250 ms timeout under load: shared calls run before the in-flight
// semaphore and queue on the abuse pool; timed-out calls fall back to each
// replica's local limiter.
func TestR9_AbuseFallbackUnderLoad(t *testing.T) {
	e := newEnv(t)
	run := func(maxConns, replicas, n int) (allowed, errs int64, lat []time.Duration) {
		store, _ := r9pool(t, e, maxConns)
		key := abuseKey(t)
		var errCount atomic.Int64
		ls := make([]*sharedLimiter, replicas)
		for i := range ls {
			ls[i] = newSharedLimiter(store, key, "auth_failure", 5, time.Minute, 5*time.Minute, func(string) { errCount.Add(1) })
		}
		var ok atomic.Int64
		var mu sync.Mutex
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				t0 := time.Now()
				if ls[i%replicas].hit("198.51.100.77") {
					ok.Add(1)
				}
				mu.Lock()
				lat = append(lat, time.Since(t0))
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return ok.Load(), errCount.Load(), lat
	}
	for _, c := range []struct{ conns, replicas, n int }{{32, 4, 40}, {4, 4, 400}, {4, 10, 1000}, {4, 20, 6000}} {
		allowed, errs, lat := run(c.conns, c.replicas, c.n)
		t.Logf("pool %d conns, %d replicas, %d concurrent auth failures from one client (limit 5 + lockout): allowed %d; shared-store errors/timeouts %d; latency p50 %s p99 %s max %s",
			c.conns, c.replicas, c.n, allowed, errs, lat[len(lat)/2].Round(time.Millisecond), lat[len(lat)*99/100].Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
		switch {
		case allowed > 5 && errs == 0:
			t.Errorf("OPEN: %d auth failures allowed against a shared limit of 5 with a healthy store", allowed)
		case allowed > 5*int64(c.replicas):
			t.Errorf("OPEN: %d auth failures allowed, beyond even %d per-replica limits", allowed, c.replicas)
		case allowed > 5:
			// R9-I4 (open, ADR 0014): with the store timing out, replicas fall
			// back to their local limits as designed.
			t.Logf("R9-I4 (open): %d allowed against 5 while %d store calls timed out (documented fallback, bounded by %d x 5)", allowed, errs, c.replicas)
		}
	}
	// Direct contention on one counter row.
	store, _ := r9pool(t, e, 64)
	k := make([]byte, 32)
	copy(k, []byte(uuid.NewString()))
	var lat []time.Duration
	var mu sync.Mutex
	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				t0 := time.Now()
				_, _ = store.Hit(ctx, "preauth", k, 1_000_000, time.Minute, 0)
				cancel()
				mu.Lock()
				lat = append(lat, time.Since(t0))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	t.Logf("info: 64 connections x 20 abuse_hit on one key: p50 %s p99 %s max %s", lat[len(lat)/2].Round(time.Millisecond), lat[len(lat)*99/100].Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
}
