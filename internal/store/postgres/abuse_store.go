package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AbuseStore keeps the API's abuse counters in the database (migration 0029)
// so every replica enforces one limit. Pool is a dedicated login in role
// serk_abuse, which may execute abuse_hit and abuse_blocked and nothing else;
// it never sees tenant data.
type AbuseStore struct{ Pool *pgxpool.Pool }

// Hit implements httpapi.AbuseStore.
func (s AbuseStore) Hit(ctx context.Context, scope string, key []byte, limit int, window, block time.Duration) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT abuse_hit($1, $2, $3, $4, $5)`, scope, key, limit,
		int(window/time.Second), int(block/time.Second)).Scan(&ok)
	return ok, err
}

// Blocked implements httpapi.AbuseStore.
func (s AbuseStore) Blocked(ctx context.Context, scope string, key []byte) (bool, error) {
	var b bool
	err := s.Pool.QueryRow(ctx, `SELECT abuse_blocked($1, $2)`, scope, key).Scan(&b)
	return b, err
}
