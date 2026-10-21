package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Pre-authentication abuse controls (SC-13). They run before any token
// parsing or signature verification, so floods of junk tokens cost almost
// nothing and cannot consume database connections.
//
// In multi-replica deployments these in-process limits complement, and do
// not replace, edge limits (reverse proxy / WAF) documented in deploy/.

// AbuseConfig tunes the controls. Zero values take safe defaults.
type AbuseConfig struct {
	PreAuthPerMinute      int           // requests per client IP per minute (default 600)
	AuthFailuresPerMinute int           // invalid credentials per IP before lockout (default 20)
	AuthFailureBlock      time.Duration // lockout duration (default 5m)
	MaxInFlight           int           // concurrent authenticated requests (default 256)
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is
	// honoured. A header from any other peer is ignored (no spoofing).
	TrustedProxies []netip.Prefix
}

func (c *AbuseConfig) defaults() {
	if c.PreAuthPerMinute == 0 {
		c.PreAuthPerMinute = 600
	}
	if c.AuthFailuresPerMinute == 0 {
		c.AuthFailuresPerMinute = 20
	}
	if c.AuthFailureBlock == 0 {
		c.AuthFailureBlock = 5 * time.Minute
	}
	if c.MaxInFlight == 0 {
		c.MaxInFlight = 256
	}
}

// clientIP returns the client address: the peer, or — only when the peer is
// a trusted proxy — the right-most address in X-Forwarded-For that is not
// itself a trusted proxy.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return peer
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer // malformed chain: fall back to the proxy itself
		}
		a = a.Unmap()
		if !isTrusted(a) {
			return a
		}
	}
	return peer
}

// windowLimiter is a fixed-window counter per key with optional lockout.
type windowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	block   time.Duration
	entries map[string]*windowEntry
	now     func() time.Time
}

type windowEntry struct {
	count        int
	windowEnd    time.Time
	blockedUntil time.Time
}

func newWindowLimiter(limit int, window, block time.Duration) *windowLimiter {
	return &windowLimiter{limit: limit, window: window, block: block, entries: map[string]*windowEntry{}, now: time.Now}
}

// blocked reports whether key is currently locked out.
func (l *windowLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	return e != nil && l.now().Before(e.blockedUntil)
}

// hit counts one event; it returns false when the key is over its limit. A
// limiter with a lockout starts it when the limit is reached.
func (l *windowLimiter) hit(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil || now.After(e.windowEnd) {
		if len(l.entries) > 50_000 {
			l.sweepLocked(now)
		}
		if e == nil {
			e = &windowEntry{}
			l.entries[key] = e
		}
		e.count, e.windowEnd = 0, now.Add(l.window)
	}
	if now.Before(e.blockedUntil) {
		return false
	}
	e.count++
	// With a lockout, the limit-th event starts it, so the next request is
	// refused before any token work is done.
	if l.block > 0 && e.count >= l.limit {
		e.blockedUntil = now.Add(l.block)
	}
	return e.count <= l.limit
}

// sweepLocked drops entries whose window and lockout have both expired.
func (l *windowLimiter) sweepLocked(now time.Time) {
	for k, e := range l.entries {
		if now.After(e.windowEnd) && now.After(e.blockedUntil) {
			delete(l.entries, k)
		}
	}
}
