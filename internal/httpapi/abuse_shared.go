package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

// Distributed abuse limits (order item "distributed abuse protection"; SC-13
// residual). With one process per replica, N replicas allowed N times each
// limit and a lockout on one replica did not apply on the others. When
// AbuseConfig.Shared is set, every limit is counted in shared storage
// (migration 0029: abuse_hit / abuse_blocked, on the database clock) under an
// HMAC of the client key, so no raw IP address or user id is stored.
//
// Failure mode: each event is also counted in the local limiter. If the shared
// store fails or times out, the decision falls back to the local limiter (the
// pre-0029 per-replica limits) and serk_abuse_store_errors_total is
// incremented. Falling back to "allow everything" would turn a database
// incident into an open door; falling back to "refuse everything" would turn
// it into a full outage for every client. Per-replica limits are the bounded
// middle and are alerted on.

// AbuseStore is shared counter storage for abuse limits.
type AbuseStore interface {
	// Hit counts one event for key in scope and reports whether the key is
	// within limit. With block > 0 the limit-th event starts a lockout.
	Hit(ctx context.Context, scope string, key []byte, limit int, window, block time.Duration) (bool, error)
	// Blocked reports whether key is locked out in scope.
	Blocked(ctx context.Context, scope string, key []byte) (bool, error)
}

// limiter is satisfied by the in-process windowLimiter and by sharedLimiter.
type limiter interface {
	hit(key string) bool
	blocked(key string) bool
}

type sharedLimiter struct {
	store   AbuseStore
	scope   string
	secret  []byte
	limit   int
	window  time.Duration
	block   time.Duration
	local   *windowLimiter
	timeout time.Duration
	onError func(scope string)
}

func newSharedLimiter(store AbuseStore, secret []byte, scope string, limit int, window, block time.Duration, onError func(string)) *sharedLimiter {
	return &sharedLimiter{store: store, scope: scope, secret: secret, limit: limit, window: window, block: block,
		local: newWindowLimiter(limit, window, block), timeout: 250 * time.Millisecond, onError: onError}
}

// digest keys the counter by HMAC-SHA256(secret, scope || 0 || key).
func (l *sharedLimiter) digest(key string) []byte {
	m := hmac.New(sha256.New, l.secret)
	m.Write([]byte(l.scope))
	m.Write([]byte{0})
	m.Write([]byte(key))
	return m.Sum(nil)
}

func (l *sharedLimiter) hit(key string) bool {
	localOK := l.local.hit(key)
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()
	ok, err := l.store.Hit(ctx, l.scope, l.digest(key), l.limit, l.window, l.block)
	if err != nil {
		l.onError(l.scope)
		return localOK
	}
	return ok && localOK
}

func (l *sharedLimiter) blocked(key string) bool {
	if l.local.blocked(key) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()
	b, err := l.store.Blocked(ctx, l.scope, l.digest(key))
	if err != nil {
		l.onError(l.scope)
		return false // the local limiter, consulted above, decides
	}
	return b
}
