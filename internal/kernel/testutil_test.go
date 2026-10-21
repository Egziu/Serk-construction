package kernel

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// Integration tests need a real PostgreSQL. Set:
//   SERK_TEST_ADMIN_DSN  — schema owner (runs migrations and bootstrap)
//   SERK_TEST_APP_DSN    — application role (RLS enforced)
// Tests are skipped when the admin DSN is absent.

type fixture struct {
	ctx      context.Context
	svc      *Service
	app      *postgres.Store
	admin    *pgx.Conn
	tenant   string
	tenant2  string
	entity   string
	project  string
	accounts map[string]string // code -> id
	prep     auth.Principal
	appr     auth.Principal
	post     auth.Principal
	ctrl     auth.Principal // controller: post + reverse
	treasury auth.Principal // FX maker
	cfo      auth.Principal // FX exception checker, period reopen (MFA)
	outsider auth.Principal // tenant 2
	fxPolicy string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	adminDSN := os.Getenv("SERK_TEST_ADMIN_DSN")
	appDSN := os.Getenv("SERK_TEST_APP_DSN")
	if adminDSN == "" || appDSN == "" {
		t.Skip("SERK_TEST_ADMIN_DSN / SERK_TEST_APP_DSN not set; skipping PostgreSQL integration tests")
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
	app, err := postgres.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("app connect: %v", err)
	}
	t.Cleanup(app.Close)

	f := &fixture{ctx: ctx, app: app, admin: admin, accounts: map[string]string{}}
	f.svc = New(app, auth.NewAuthorizer(nil, true))
	f.tenant, f.tenant2 = uuid.NewString(), uuid.NewString()

	// Bootstrap both tenants through the admin connection using the same
	// tenant-scoped transaction discipline as the application.
	adminStore := adminStoreFor(t, adminDSN)
	for _, tid := range []string{f.tenant, f.tenant2} {
		tid := tid
		err := adminStore.WithTenant(ctx, tid, func(ctx context.Context, tx pgx.Tx) error {
			if err := postgres.CreateTenant(ctx, tx, tid, "tenant-"+tid[:8]); err != nil {
				return err
			}
			le, err := postgres.CreateLegalEntity(ctx, tx, tid, "SERK ETHIOPIA PLC", "ET", "ETB", "USD")
			if err != nil {
				return err
			}
			pr, err := postgres.CreateProject(ctx, tx, tid, le, "P-001", "Mekelle Ring Road", "ETB")
			if err != nil {
				return err
			}
			if _, err := postgres.CreateFiscalPeriod(ctx, tx, tid, le, "FY2026-Q4", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
				return err
			}
			for _, a := range []struct{ code, name, typ string }{
				{"1000", "Cash at Bank", "ASSET"}, {"1200", "Inventory", "ASSET"}, {"1300", "VAT Input", "ASSET"},
				{"2000", "Accounts Payable", "LIABILITY"}, {"5000", "Materials Expense", "EXPENSE"},
			} {
				id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: tid, LegalEntityID: le, Code: a.code, Name: a.name, Type: ledger.AccountType(a.typ), Active: true})
				if err != nil {
					return err
				}
				if tid == f.tenant {
					f.accounts[a.code] = id
				}
			}
			if tid == f.tenant {
				f.entity, f.project = le, pr
			}
			return nil
		})
		if err != nil {
			t.Fatalf("bootstrap tenant: %v", err)
		}
	}
	f.prep = auth.Principal{UserID: "u-preparer", TenantID: f.tenant, Roles: []string{"accountant"}}
	f.appr = auth.Principal{UserID: "u-approver", TenantID: f.tenant, Roles: []string{"finance_manager"}}
	f.post = auth.Principal{UserID: "u-poster", TenantID: f.tenant, Roles: []string{"controller"}}
	f.ctrl = f.post
	f.treasury = auth.Principal{UserID: "u-treasury", TenantID: f.tenant, Roles: []string{"treasury_officer"}}
	f.cfo = auth.Principal{UserID: "u-cfo", TenantID: f.tenant, Roles: []string{"cfo"}, MFA: true, AuthTime: time.Now()}
	f.outsider = auth.Principal{UserID: "u-outsider", TenantID: f.tenant2, Roles: []string{"accountant", "finance_manager", "controller", "auditor", "cfo", "treasury_officer"}}
	return f
}

// docHash is a well-formed source document hash.
const docHash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// setupFX registers and approves the NBE source and a TRANSACTION policy for
// the fixture entity, each through the real maker/checker commands.
func (f *fixture) setupFX(t *testing.T, pol fx.Policy) string {
	t.Helper()
	if err := f.svc.RegisterFXSource(f.ctx, f.treasury, postgres.FXSource{SourceID: "NBE", SourceType: "CENTRAL_BANK",
		Description: "National Bank of Ethiopia reference rate", RequiresDocumentHash: true, MaxVariance: decimal.RequireFromString("0.05")}); err != nil {
		t.Fatalf("register source: %v", err)
	}
	if err := f.svc.ApproveFXSource(f.ctx, f.appr, "NBE"); err != nil {
		t.Fatalf("approve source: %v", err)
	}
	if pol.RateType == "" {
		pol = fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 30 * 24 * time.Hour, AllowInverse: true}
	}
	p, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, pol)
	if err != nil {
		t.Fatalf("propose policy: %v", err)
	}
	if err := f.svc.DecideFXPolicy(f.ctx, f.appr, p.ID, true, "standard NBE official policy"); err != nil {
		t.Fatalf("approve policy: %v", err)
	}
	f.fxPolicy = p.ID
	return p.ID
}

// snapshot records a rate (maker = treasury) and optionally has it approved
// (checker = finance manager).
func (f *fixture) snapshot(t *testing.T, base, quote money.Currency, rate string, effective time.Time, approve bool) string {
	t.Helper()
	id, err := f.svc.RecordFXSnapshot(f.ctx, f.treasury, fx.Snapshot{SourceID: "NBE", SourceType: "CENTRAL_BANK", BaseCurrency: base, QuoteCurrency: quote,
		Rate: decimal.RequireFromString(rate), RateType: fx.RateOfficial, EffectiveFromUTC: effective, PublishedAtUTC: effective.Add(6 * time.Hour),
		SourceDocumentHash: docHash})
	if err != nil {
		t.Fatalf("record snapshot: %v", err)
	}
	if approve {
		if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.appr, id, ""); err != nil {
			t.Fatalf("approve snapshot: %v", err)
		}
	}
	return id
}

// fxLine builds a USD-denominated line converted at rate.
func fxLine(account string, side ledger.Side, usd, etb, snap string) ledger.Line {
	m := money.MustNew(usd, "USD")
	return ledger.Line{AccountID: account, Side: side, Amount: money.MustNew(etb, "ETB"), TxnAmount: &m, FXSnapshotID: snap}
}

func adminStoreFor(t *testing.T, dsn string) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("admin store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func (f *fixture) journal(key string, lines ...ledger.Line) ledger.Journal {
	for i := range lines {
		lines[i].LineNo = i + 1
	}
	return ledger.Journal{
		LegalEntityID: f.entity, ProjectID: f.project, FunctionalCurrency: "ETB",
		BusinessEventAt: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC), Description: "Cement delivery — Dangote 50kg x 200",
		SourceType: "MANUAL", IdempotencyKey: key, Lines: lines,
	}
}

func (f *fixture) balanced(key string) ledger.Journal {
	return f.journal(key,
		ledger.Line{AccountID: f.accounts["1200"], Side: ledger.Debit, Amount: money.MustNew("100000.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1300"], Side: ledger.Debit, Amount: money.MustNew("15000.00", "ETB")},
		ledger.Line{AccountID: f.accounts["2000"], Side: ledger.Credit, Amount: money.MustNew("115000.00", "ETB")},
	)
}

// lifecycle drives create → approve → post with proper SoD and returns the id.
func (f *fixture) lifecycle(t *testing.T, j ledger.Journal) string {
	t.Helper()
	res, err := f.svc.CreateJournal(f.ctx, f.prep, j)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, res.JournalID); err != nil {
		t.Fatalf("post: %v", err)
	}
	return res.JournalID
}

func key(prefix string) string { return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8]) }
