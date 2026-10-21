// Package testdb provisions PostgreSQL integration-test environments with the
// production tenancy model: per-tenant LOGIN roles routed by a Router.
//
// Requires SERK_TEST_ADMIN_DSN (schema owner with CREATEROLE, e.g. the
// postgres superuser of a disposable cluster). Tests skip without it.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
)

// Secret is the tenant-credential derivation secret used by tests only.
var Secret = []byte("serk-test-tenant-credential-secret-0123456789")

// Env is a migrated database plus an application router.
type Env struct {
	Ctx        context.Context
	AdminDSN   string
	BaseDSN    string
	Admin      *pgx.Conn
	AdminStore *postgres.Store
	Router     *postgres.Router

	mu    sync.Mutex
	roles []string
}

// Setup migrates the database and builds a router with derived credentials.
func Setup(t *testing.T) *Env {
	t.Helper()
	adminDSN := os.Getenv("SERK_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("SERK_TEST_ADMIN_DSN not set; skipping PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })
	if _, err := postgres.Migrate(ctx, admin); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	u.User = nil
	e := &Env{Ctx: ctx, AdminDSN: adminDSN, BaseDSN: u.String(), Admin: admin}
	// Registered before the router so it runs after the router closes (LIFO).
	t.Cleanup(e.dropRoles)
	e.AdminStore, err = postgres.Open(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.AdminStore.Close)
	e.Router, err = postgres.NewRouter(ctx, postgres.RouterConfig{
		Credentials: postgres.DerivedCredentials{BaseDSN: e.BaseDSN, Secret: Secret},
		HealthDSN:   adminDSN,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Router.Close)
	return e
}

// ProvisionTenant creates the tenant, its database role and mapping.
func (e *Env) ProvisionTenant(t *testing.T, tenantID, name string) {
	t.Helper()
	if err := postgres.ProvisionTenant(e.Ctx, e.Admin, tenantID, name, postgres.TenantPassword(Secret, tenantID)); err != nil {
		t.Fatalf("provision tenant: %v", err)
	}
	role, _ := postgres.RoleName(tenantID)
	e.mu.Lock()
	e.roles = append(e.roles, role)
	e.mu.Unlock()
}

// TenantDSN is the DSN of a tenant's own database role (for hostile-SQL tests).
func (e *Env) TenantDSN(t *testing.T, tenantID string) string {
	t.Helper()
	dsn, err := postgres.DerivedCredentials{BaseDSN: e.BaseDSN, Secret: Secret}.TenantDSN(e.Ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return dsn
}

// dropRoles removes the cluster-global roles a test created.
func (e *Env) dropRoles() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.roles {
		// Sessions of a dropped role are terminated first so DROP ROLE succeeds.
		_, _ = e.Admin.Exec(e.Ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1`, r)
		_, _ = e.Admin.Exec(e.Ctx, `DROP ROLE IF EXISTS `+r)
	}
}

// LoginRole creates a temporary LOGIN role that is a member of group and
// returns its DSN (dropped at cleanup).
func (e *Env) LoginRole(t *testing.T, group string) string {
	t.Helper()
	name := "serk_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	pw := strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := e.Admin.Exec(e.Ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER INHERIT PASSWORD '%s' IN ROLE %s`, name, pw, pgx.Identifier{group}.Sanitize())); err != nil {
		t.Fatalf("create login role: %v", err)
	}
	e.mu.Lock()
	e.roles = append(e.roles, name)
	e.mu.Unlock()
	u, _ := url.Parse(e.BaseDSN)
	u.User = url.UserPassword(name, pw)
	return u.String()
}
