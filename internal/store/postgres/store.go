package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors surfaced by the store. Database constraint failures are translated
// so callers never need to inspect SQLSTATE.
var (
	ErrNotFound            = errors.New("store: not found")
	ErrIdempotencyConflict = errors.New("store: idempotency key reused with a different command")
	ErrVersionConflict     = errors.New("store: concurrent modification")
	ErrInvariant           = errors.New("store: database invariant violated")
	ErrTenantContext       = errors.New("store: tenant context missing or invalid")
)

// Store wraps one connection pool authenticated as one database role. In
// production a Router holds one Store per tenant (each as that tenant's
// role); a Store opened directly is for the operator/bootstrap path.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL with a 16-connection pool.
func Open(ctx context.Context, dsn string) (*Store, error) { return openStore(ctx, dsn, 16) }

func openStore(ctx context.Context, dsn string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = maxConns
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	// Every session starts with no tenant; the only way to see rows is an
	// explicit WithTenant transaction.
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SELECT set_config('app.tenant_id', '', false)`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks liveness.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// bindTenant marks the transaction with the tenant (SET LOCAL, for
// diagnostics only — authorization no longer reads it) and verifies the
// connection's database identity. A mapped role serving another tenant is a
// routing defect and fails closed. An unmapped session (operator/superuser
// bootstrap) is allowed; RLS shows an unmapped non-superuser nothing.
func bindTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var dbTenant *string
	if err := tx.QueryRow(ctx, `SELECT set_config('app.tenant_id', $1, true), current_tenant()::text`, tenantID).Scan(new(string), &dbTenant); err != nil {
		return err
	}
	if dbTenant != nil && *dbTenant != tenantID {
		return fmt.Errorf("%w: connection belongs to a different tenant", ErrTenantContext)
	}
	return nil
}

// WithTenant runs fn inside a transaction bound to a tenant.
func (s *Store) WithTenant(ctx context.Context, tenantID string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if _, err := uuid.Parse(tenantID); err != nil {
		return fmt.Errorf("%w: %q", ErrTenantContext, tenantID)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if err := bindTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		return translate(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return translate(err)
	}
	return nil
}

// BeginTenant opens a tenant-bound transaction the caller must commit or
// roll back. Used by the workflow engine's workers and by concurrency tests
// that need to hold a transaction open at a precise point.
func (s *Store) BeginTenant(ctx context.Context, tenantID string) (pgx.Tx, error) {
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, fmt.Errorf("%w: %q", ErrTenantContext, tenantID)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	if err := bindTenant(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// Translate exposes the error translation for callers that manage their own
// transactions (BeginTenant).
func Translate(err error) error { return translate(err) }

// translate maps PostgreSQL errors to store errors.
func translate(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505": // unique_violation
		if pgErr.ConstraintName == "journals_tenant_id_idempotency_key_key" {
			return ErrIdempotencyConflict
		}
		return fmt.Errorf("%w: %s", ErrInvariant, pgErr.ConstraintName)
	case "23514", "23000", "23503", "23P01": // check, integrity, fk, exclusion
		return fmt.Errorf("%w: %s", ErrInvariant, pgErr.Message)
	case "40P01", "40001": // deadlock / serialization: safe to retry
		return fmt.Errorf("%w: %s", ErrVersionConflict, pgErr.Message)
	case "42501": // insufficient_privilege
		return fmt.Errorf("%w: privilege: %s", ErrInvariant, pgErr.Message)
	}
	return err
}

// newID returns a fresh v4 UUID string.
func newID() string { return uuid.NewString() }
