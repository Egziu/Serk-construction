package kernel

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// SC-04: tenant isolation must hold against an attacker holding tenant A's
// database credential (stolen password, or SQL injection inside A's
// session). The attacker connects directly as A's role and tries every
// known way to reach tenant B.
func TestSC04_CompromisedTenantCredentialCannotReachOtherTenant(t *testing.T) {
	f := newFixture(t)
	// Give tenant B (f.tenant2) data in every tenant-scoped table we probe.
	outsiderPost := auth.Principal{UserID: "u-b-post", TenantID: f.tenant2, Roles: []string{"controller"}}
	var bEntity string
	var bAccts []string
	_ = f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT id::text FROM legal_entities`).Scan(&bEntity)
		rows, _ := tx.Query(ctx, `SELECT id::text FROM accounts WHERE code IN ('5000','1000') ORDER BY code DESC`)
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			bAccts = append(bAccts, id)
		}
		rows.Close()
		return nil
	})
	bj := ledger.Journal{LegalEntityID: bEntity, FunctionalCurrency: "ETB", BusinessEventAt: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		Description: "tenant B secret", SourceType: "MANUAL", IdempotencyKey: key("b"), Lines: []ledger.Line{
			{LineNo: 1, AccountID: bAccts[0], Side: ledger.Debit, Amount: money.MustNew("999.00", "ETB")},
			{LineNo: 2, AccountID: bAccts[1], Side: ledger.Credit, Amount: money.MustNew("999.00", "ETB")}}}
	bPrep := auth.Principal{UserID: "u-b-prep", TenantID: f.tenant2, Roles: []string{"accountant"}}
	bAppr := auth.Principal{UserID: "u-b-appr", TenantID: f.tenant2, Roles: []string{"finance_manager"}}
	res, err := f.svc.CreateJournal(f.ctx, bPrep, bj)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.svc.ApproveJournal(f.ctx, bAppr, res.JournalID)
	if err := f.svc.PostJournal(f.ctx, outsiderPost, res.JournalID); err != nil {
		t.Fatal(err)
	}

	// The attacker: a raw session as tenant A's own database role.
	att, err := pgx.Connect(f.ctx, f.db.TenantDSN(t, f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close(f.ctx)
	roleB, _ := postgres.RoleName(f.tenant2)

	countB := func(label string) {
		t.Helper()
		for _, tbl := range []string{"tenants", "legal_entities", "accounts", "journals", "journal_lines", "fiscal_periods", "fx_snapshots", "audit_log", "outbox", "fiscal_period_closes"} {
			col := "tenant_id"
			if tbl == "tenants" {
				col = "id"
			}
			var n int
			if err := att.QueryRow(f.ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1::uuid`, tbl, col), f.tenant2).Scan(&n); err != nil {
				t.Fatalf("%s: %s: %v", label, tbl, err)
			}
			if n != 0 {
				t.Fatalf("SC-04 [%s]: tenant A's credential sees %d row(s) of tenant B in %s", label, n, tbl)
			}
		}
	}

	countB("plain")
	// 1. The 0.1.0 attack: rewrite the tenant GUC.
	if _, err := att.Exec(f.ctx, `SELECT set_config('app.tenant_id', $1, false)`, f.tenant2); err != nil {
		t.Fatal(err)
	}
	countB("after set_config(app.tenant_id = B)")
	// 2. Become B's role.
	if _, err := att.Exec(f.ctx, `SET ROLE `+roleB); err == nil {
		t.Fatal("SC-04: tenant A's session switched to tenant B's role")
	}
	// 3. Become the privilege group (session_user is unchanged).
	if _, err := att.Exec(f.ctx, `SET ROLE serk_app`); err != nil {
		t.Fatalf("SET ROLE serk_app: %v", err)
	}
	countB("after SET ROLE serk_app")
	_, _ = att.Exec(f.ctx, `RESET ROLE`)
	// 4. Change the session user.
	if _, err := att.Exec(f.ctx, `SET SESSION AUTHORIZATION `+roleB); err == nil {
		t.Fatal("SC-04: SET SESSION AUTHORIZATION succeeded")
	}
	// 5. Read or rewrite the identity mapping.
	if _, err := att.Exec(f.ctx, `SELECT * FROM tenant_db_roles`); err == nil {
		t.Fatal("SC-04: tenant role can read the identity mapping")
	}
	if _, err := att.Exec(f.ctx, `SELECT provision_tenant_role($1::uuid, $2)`, f.tenant2, "serk_t_"+uuid.New().String()[:8]); err == nil {
		t.Fatal("SC-04: tenant role can call provisioning")
	}
	// 6. Write into B.
	if _, err := att.Exec(f.ctx, `INSERT INTO accounts(tenant_id,legal_entity_id,code,name,type) VALUES ($1::uuid,$2::uuid,'9999','x','ASSET')`, f.tenant2, bEntity); err == nil {
		t.Fatal("SC-04: tenant A wrote a row into tenant B")
	}
	// 7. Probe B's audit chain through a definer function.
	if _, err := att.Exec(f.ctx, `SELECT audit_log_verify($1::uuid)`, f.tenant2); err == nil {
		t.Fatal("SC-04: tenant A verified tenant B's audit chain")
	}
	// 8. Plant objects (functions/tables) for privilege escalation.
	if _, err := att.Exec(f.ctx, `CREATE FUNCTION public.evil() RETURNS int LANGUAGE sql AS 'SELECT 1'`); err == nil {
		t.Fatal("SC-04: tenant role can create objects in the schema")
	}
	// 9. Its own data remains fully usable.
	var mine int
	if err := att.QueryRow(f.ctx, `SELECT count(*) FROM journals`).Scan(&mine); err != nil || mine != 0 {
		// tenant A has no journals in this test; the point is the query works
		t.Fatalf("own-tenant query: %d %v", mine, err)
	}
	var who string
	_ = att.QueryRow(f.ctx, `SELECT current_tenant()::text`).Scan(&who)
	if who != f.tenant {
		t.Fatalf("current_tenant() = %s, want %s", who, f.tenant)
	}
}

// SC-04: the retired shared login (0.1.0's serk_api) sees nothing even after
// setting the GUC, and a misrouted pool fails closed.
func TestSC04_SharedLoginRetiredAndMisroutingFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.lifecycle(t, f.balanced(key("shared")))
	u, _ := url.Parse(f.db.BaseDSN)
	u.User = url.User("serk_api")
	shared, err := pgx.Connect(f.ctx, u.String())
	if err == nil {
		defer shared.Close(f.ctx)
		_, _ = shared.Exec(f.ctx, `SELECT set_config('app.tenant_id', $1, false)`, f.tenant)
		var n int
		if err := shared.QueryRow(f.ctx, `SELECT count(*) FROM journals`).Scan(&n); err == nil && n != 0 {
			t.Fatalf("SC-04: shared serk_api login still reads %d journal(s) via the GUC", n)
		}
	}
	// A router whose credentials send tenant B's requests to A's role.
	wrong := misroute{to: f.db.TenantDSN(t, f.tenant)}
	r, err := postgres.NewRouter(f.ctx, postgres.RouterConfig{Credentials: wrong})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error { return nil })
	if !errors.Is(err, postgres.ErrTenantContext) {
		t.Fatalf("SC-04: misrouted pool was used: %v", err)
	}
}

type misroute struct{ to string }

func (m misroute) TenantDSN(context.Context, string) (string, error) { return m.to, nil }

// SC-04 DEDICATED_DB tier: a tenant routed to its own database writes there
// and nowhere else, through the same kernel code path.
func TestSC04_DedicatedDatabaseTier(t *testing.T) {
	shared := testdb.Setup(t)
	dbName := "serk_ded_" + uuid.NewString()[:8]
	if _, err := shared.Admin.Exec(shared.Ctx, `CREATE DATABASE `+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = shared.Admin.Exec(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, dbName)
		_, _ = shared.Admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+dbName)
	})
	dedAdminURL, _ := url.Parse(shared.AdminDSN)
	dedAdminURL.Path = "/" + dbName
	dedAdmin, err := pgx.Connect(shared.Ctx, dedAdminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dedAdmin.Close(shared.Ctx)
	if _, err := postgres.Migrate(shared.Ctx, dedAdmin); err != nil {
		t.Fatal(err)
	}
	tenant := uuid.NewString()
	// Provision in the dedicated database (the role is cluster-global).
	if err := postgres.ProvisionTenant(shared.Ctx, dedAdmin, tenant, "dedicated", postgres.TenantPassword(testdb.Secret, tenant)); err != nil {
		t.Fatal(err)
	}
	role, _ := postgres.RoleName(tenant)
	t.Cleanup(func() { _, _ = shared.Admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role) })
	dedTenantURL, _ := url.Parse(shared.BaseDSN)
	dedTenantURL.Path = "/" + dbName
	dsn, _ := postgres.DerivedCredentials{BaseDSN: dedTenantURL.String(), Secret: testdb.Secret}.TenantDSN(shared.Ctx, tenant)
	router, err := postgres.NewRouter(shared.Ctx, postgres.RouterConfig{Credentials: postgres.DedicatedCredentials{
		DSNs: map[string]string{tenant: dsn}, Fallback: postgres.DerivedCredentials{BaseDSN: shared.BaseDSN, Secret: testdb.Secret}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	dedStore, _ := postgres.Open(shared.Ctx, dedAdminURL.String())
	defer dedStore.Close()
	var le, a1, a2 string
	err = dedStore.WithTenant(shared.Ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if le, err = postgres.CreateLegalEntity(ctx, tx, tenant, "Dedicated PLC", "ET", "ETB", ""); err != nil {
			return err
		}
		if _, err = postgres.CreateFiscalPeriod(ctx, tx, tenant, le, "FY26", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
			return err
		}
		if a1, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: tenant, LegalEntityID: le, Code: "5000", Name: "E", Type: ledger.Expense, Active: true}); err != nil {
			return err
		}
		a2, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: tenant, LegalEntityID: le, Code: "1000", Name: "C", Type: ledger.Asset, Active: true})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := New(router, auth.NewAuthorizer(nil, true))
	prep := auth.Principal{UserID: "d-prep", TenantID: tenant, Roles: []string{"accountant"}}
	_, err = svc.CreateJournal(shared.Ctx, prep, ledger.Journal{LegalEntityID: le, FunctionalCurrency: "ETB", BusinessEventAt: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		Description: "dedicated tier", SourceType: "MANUAL", IdempotencyKey: "ded-1", Lines: []ledger.Line{
			{LineNo: 1, AccountID: a1, Side: ledger.Debit, Amount: money.MustNew("10.00", "ETB")},
			{LineNo: 2, AccountID: a2, Side: ledger.Credit, Amount: money.MustNew("10.00", "ETB")}}})
	if err != nil {
		t.Fatal(err)
	}
	var inDed, inShared int
	_ = dedAdmin.QueryRow(shared.Ctx, `SELECT count(*) FROM journals WHERE tenant_id=$1::uuid`, tenant).Scan(&inDed)
	_ = shared.Admin.QueryRow(shared.Ctx, `SELECT count(*) FROM journals WHERE tenant_id=$1::uuid`, tenant).Scan(&inShared)
	if inDed != 1 || inShared != 0 {
		t.Fatalf("dedicated tier routing: dedicated=%d shared=%d", inDed, inShared)
	}
}
