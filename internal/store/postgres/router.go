package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantDB is what the kernel needs from storage: a transaction bound to one
// tenant's database identity. Router (production) and Store (a single pool,
// used for operator bootstrap and tests) implement it.
type TenantDB interface {
	WithTenant(ctx context.Context, tenantID string, fn func(ctx context.Context, tx pgx.Tx) error) error
	BeginTenant(ctx context.Context, tenantID string) (pgx.Tx, error)
	Ping(ctx context.Context) error
}

// RoleName is the PostgreSQL login role of a tenant (SC-04).
func RoleName(tenantID string) (string, error) {
	u, err := uuid.Parse(tenantID)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrTenantContext, tenantID)
	}
	return "serk_t_" + strings.ReplaceAll(u.String(), "-", ""), nil
}

// CredentialProvider yields the DSN a tenant's pool connects with.
type CredentialProvider interface {
	TenantDSN(ctx context.Context, tenantID string) (string, error)
}

// DerivedCredentials connects every tenant to the shared database with its
// own role. The password is HMAC-SHA256(secret, "serk-tenant-db:"+tenant), so
// the application holds one secret instead of N passwords; leaking one
// tenant's DB password does not reveal another's.
type DerivedCredentials struct {
	// BaseDSN is a postgres:// URL without user info, e.g.
	// postgres://db.internal:5432/serk?sslmode=verify-full
	BaseDSN string
	Secret  []byte
}

// TenantPassword derives a tenant role's password.
func TenantPassword(secret []byte, tenantID string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("serk-tenant-db:" + tenantID))
	return hex.EncodeToString(m.Sum(nil))
}

// TenantDSN implements CredentialProvider.
func (d DerivedCredentials) TenantDSN(_ context.Context, tenantID string) (string, error) {
	if len(d.Secret) < 32 {
		return "", errors.New("postgres: tenant credential secret must be at least 32 bytes")
	}
	role, err := RoleName(tenantID)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(d.BaseDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", fmt.Errorf("postgres: base DSN must be a postgres:// URL")
	}
	if u.User != nil {
		return "", errors.New("postgres: base DSN must not contain user information")
	}
	u.User = url.UserPassword(role, TenantPassword(d.Secret, tenantID))
	return u.String(), nil
}

// DedicatedCredentials routes listed tenants to their own databases
// (DEDICATED_DB tier) and everyone else to Fallback.
type DedicatedCredentials struct {
	DSNs     map[string]string // tenant id -> full DSN incl. the tenant's role
	Fallback CredentialProvider
}

// TenantDSN implements CredentialProvider.
func (d DedicatedCredentials) TenantDSN(ctx context.Context, tenantID string) (string, error) {
	if dsn, ok := d.DSNs[tenantID]; ok {
		return dsn, nil
	}
	if d.Fallback == nil {
		return "", fmt.Errorf("%w: no database route for tenant", ErrTenantContext)
	}
	return d.Fallback.TenantDSN(ctx, tenantID)
}

// Router keeps one small pool per active tenant, each authenticated as that
// tenant's role, and evicts idle pools. It never shares a connection between
// tenants, so no session state can leak across them.
type Router struct {
	creds       CredentialProvider
	health      *pgxpool.Pool
	maxConns    int32
	maxPools    int
	idleTimeout time.Duration

	mu    sync.Mutex
	pools map[string]*routedPool
}

type routedPool struct {
	store    *Store
	lastUsed time.Time
	inUse    int
}

// RouterConfig configures a Router.
type RouterConfig struct {
	Credentials CredentialProvider
	// HealthDSN connects as a role with no table privileges, for readiness.
	HealthDSN         string
	MaxConnsPerTenant int32
	MaxPools          int
	IdleTimeout       time.Duration
}

// NewRouter builds a router.
func NewRouter(ctx context.Context, cfg RouterConfig) (*Router, error) {
	if cfg.Credentials == nil {
		return nil, errors.New("postgres: router needs a credential provider")
	}
	if cfg.MaxConnsPerTenant == 0 {
		cfg.MaxConnsPerTenant = 4
	}
	if cfg.MaxPools == 0 {
		cfg.MaxPools = 200
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	r := &Router{creds: cfg.Credentials, maxConns: cfg.MaxConnsPerTenant, maxPools: cfg.MaxPools, idleTimeout: cfg.IdleTimeout, pools: map[string]*routedPool{}}
	if cfg.HealthDSN != "" {
		hp, err := pgxpool.New(ctx, cfg.HealthDSN)
		if err != nil {
			return nil, err
		}
		r.health = hp
	}
	return r, nil
}

func (r *Router) acquire(ctx context.Context, tenantID string) (*Store, func(), error) {
	if _, err := uuid.Parse(tenantID); err != nil {
		return nil, nil, fmt.Errorf("%w: %q", ErrTenantContext, tenantID)
	}
	r.mu.Lock()
	p, ok := r.pools[tenantID]
	if ok {
		p.inUse++
		p.lastUsed = time.Now()
		r.mu.Unlock()
		return p.store, r.releaser(tenantID), nil
	}
	r.evictLocked()
	r.mu.Unlock()

	dsn, err := r.creds.TenantDSN(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	st, err := openStore(ctx, dsn, r.maxConns)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot open tenant database session", ErrTenantContext)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.pools[tenantID]; ok { // lost a race: keep the first
		st.Close()
		existing.inUse++
		existing.lastUsed = time.Now()
		return existing.store, r.releaser(tenantID), nil
	}
	r.pools[tenantID] = &routedPool{store: st, lastUsed: time.Now(), inUse: 1}
	return st, r.releaser(tenantID), nil
}

func (r *Router) releaser(tenantID string) func() {
	return func() {
		r.mu.Lock()
		if p, ok := r.pools[tenantID]; ok {
			p.inUse--
			p.lastUsed = time.Now()
		}
		r.mu.Unlock()
	}
}

// evictLocked closes idle pools past the idle timeout, and the least
// recently used idle pool when over capacity.
func (r *Router) evictLocked() {
	now := time.Now()
	for id, p := range r.pools {
		if p.inUse == 0 && now.Sub(p.lastUsed) > r.idleTimeout {
			p.store.Close()
			delete(r.pools, id)
		}
	}
	for len(r.pools) >= r.maxPools {
		var lru string
		for id, p := range r.pools {
			if p.inUse == 0 && (lru == "" || p.lastUsed.Before(r.pools[lru].lastUsed)) {
				lru = id
			}
		}
		if lru == "" {
			return // every pool busy: allow temporary overshoot rather than block
		}
		r.pools[lru].store.Close()
		delete(r.pools, lru)
	}
}

// WithTenant implements TenantDB.
func (r *Router) WithTenant(ctx context.Context, tenantID string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	st, release, err := r.acquire(ctx, tenantID)
	if err != nil {
		return err
	}
	defer release()
	return st.WithTenant(ctx, tenantID, fn)
}

// BeginTenant implements TenantDB. The pool stays referenced until the
// transaction ends.
func (r *Router) BeginTenant(ctx context.Context, tenantID string) (pgx.Tx, error) {
	st, release, err := r.acquire(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	tx, err := st.BeginTenant(ctx, tenantID)
	if err != nil {
		release()
		return nil, err
	}
	return &releasingTx{Tx: tx, release: release}, nil
}

// Ping checks readiness through the privilege-less health role.
func (r *Router) Ping(ctx context.Context) error {
	if r.health == nil {
		return errors.New("postgres: no health DSN configured")
	}
	return r.health.Ping(ctx)
}

// Close closes every pool.
func (r *Router) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, p := range r.pools {
		p.store.Close()
		delete(r.pools, id)
	}
	if r.health != nil {
		r.health.Close()
	}
}

// PoolCount reports open tenant pools (for metrics and tests).
func (r *Router) PoolCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pools)
}

type releasingTx struct {
	pgx.Tx
	once    sync.Once
	release func()
}

func (t *releasingTx) Commit(ctx context.Context) error {
	err := t.Tx.Commit(ctx)
	t.once.Do(t.release)
	return err
}

func (t *releasingTx) Rollback(ctx context.Context) error {
	err := t.Tx.Rollback(ctx)
	t.once.Do(t.release)
	return err
}

// ---------------------------------------------------------------------------
// Provisioning (operator path, schema-owner connection)
// ---------------------------------------------------------------------------

// ProvisionTenant creates the tenant row, its LOGIN role (member of serk_app,
// no other memberships, no BYPASSRLS) and the role mapping, idempotently.
// It must run with a role that has CREATEROLE and owns the schema.
func ProvisionTenant(ctx context.Context, admin *pgx.Conn, tenantID, name, password string) error {
	role, err := RoleName(tenantID)
	if err != nil {
		return err
	}
	if len(password) < 32 {
		return errors.New("postgres: tenant role password must be at least 32 characters")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
		return err
	}
	var lit string
	if err := tx.QueryRow(ctx, `SELECT quote_literal($1)`, password).Scan(&lit); err != nil {
		return err
	}
	// role is derived from a parsed UUID (hex only), so it is a safe identifier.
	if !exists {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %s IN ROLE serk_app`, role, lit)); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s PASSWORD %s`, role, lit)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenants(id, name) VALUES ($1::uuid, $2) ON CONFLICT (id) DO NOTHING`, tenantID, name); err != nil {
		return err
	}
	var mapped bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_db_roles WHERE tenant_id=$1::uuid)`, tenantID).Scan(&mapped); err != nil {
		return err
	}
	if !mapped {
		if _, err := tx.Exec(ctx, `SELECT provision_tenant_role($1::uuid, $2)`, tenantID, role); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
