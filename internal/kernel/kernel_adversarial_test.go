package kernel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// These tests encode the findings of the independent adversarial review.

func (f *fixture) approvedSnapshot(t *testing.T, base, quote money.Currency, rate string) string {
	t.Helper()
	fxm := auth.Principal{UserID: "u-fx", TenantID: f.tenant, Roles: []string{"finance_manager"}}
	id, err := f.svc.RecordFXSnapshot(f.ctx, fxm, fx.Snapshot{SourceID: "NBE", SourceType: "CENTRAL_BANK", BaseCurrency: base, QuoteCurrency: quote,
		Rate: decimal.RequireFromString(rate), RateType: fx.RateOfficial, EffectiveFromUTC: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		PublishedAtUTC: time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC), SourceDocumentHash: "sha256:t"}, true)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFXLineMustReconcileToApprovedSnapshotOfRightPair(t *testing.T) {
	f := newFixture(t)
	fxm := auth.Principal{UserID: "u-fx", TenantID: f.tenant, Roles: []string{"finance_manager"}}
	pending, _ := f.svc.RecordFXSnapshot(f.ctx, fxm, fx.Snapshot{SourceID: "X", SourceType: "PROVIDER", BaseCurrency: "CNY", QuoteCurrency: "KES",
		Rate: decimal.NewFromInt(1), RateType: fx.RateOfficial, EffectiveFromUTC: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		PublishedAtUTC: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), SourceDocumentHash: "h"}, false)
	usdEtb := f.approvedSnapshot(t, "USD", "ETB", "57.25")
	kesUsd := f.approvedSnapshot(t, "KES", "USD", "0.0077")
	usd := money.MustNew("1000.00", "USD")

	mk := func(amount string, snap string) ledger.Journal {
		return f.journal(key("fxl"),
			ledger.Line{AccountID: f.accounts["5000"], Side: ledger.Debit, Amount: money.MustNew(amount, "ETB"), TxnAmount: &usd, FXSnapshotID: snap},
			ledger.Line{AccountID: f.accounts["2000"], Side: ledger.Credit, Amount: money.MustNew(amount, "ETB")},
		)
	}
	cases := map[string]ledger.Journal{
		"pending snapshot":          mk("1.00", pending),
		"wrong pair":                mk("7.70", kesUsd),
		"amount does not reconcile": mk("57251.00", usdEtb), // 1000 x 57.25 = 57250.00
		"unknown snapshot":          mk("57250.00", "00000000-0000-0000-0000-000000000001"),
	}
	for name, j := range cases {
		if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrLineRejected) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	id := f.lifecycle(t, mk("57250.00", usdEtb))
	rec, _ := f.svc.GetJournal(f.ctx, f.prep, id)
	if rec.Lines[0].AppliedRate.String() != "57.25" {
		t.Fatalf("applied rate not bound: %s", rec.Lines[0].AppliedRate)
	}
	// Raw SQL cannot sneak an unreconciled or pending-snapshot line in either.
	const ins = `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency,txn_amount,txn_currency,fx_snapshot_id,applied_rate)
		VALUES ($1::uuid,$2::uuid,$3::uuid,1,$4::uuid,'DEBIT',$5::numeric,'ETB',1000,'USD',$6::uuid,$7::numeric)`
	for name, c := range map[string]struct {
		amount, snap, rate string
	}{
		"pending snapshot": {"1000", pending, "1"},
		"wrong amount":     {"1", usdEtb, "57.25"},
		"wrong rate":       {"1000", usdEtb, "1"},
		"wrong pair":       {"7.70", kesUsd, "0.0077"},
	} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			var jid string
			if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by)
				VALUES ($1::uuid,$2::uuid,'ETB','2026-10-15','raw','MANUAL',$3,'h','a') RETURNING id::text`, f.tenant, f.entity, key("rawfx")).Scan(&jid); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, ins, jid, f.tenant, f.entity, f.accounts["5000"], c.amount, c.snap, c.rate)
			return err
		})
		if !errors.Is(err, postgres.ErrInvariant) {
			t.Fatalf("raw %s line accepted: %v", name, err)
		}
	}
	// An approved snapshot referenced by a line cannot be withdrawn.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return postgres.SetFXSnapshotApproval(ctx, tx, usdEtb, fx.StatusDisputed, "u-fx")
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("referenced snapshot withdrawn: %v", err)
	}
}

func TestJournalBoundToLegalEntity(t *testing.T) {
	f := newFixture(t)
	// Journal currency must be the entity's functional currency (FK).
	j := f.balanced(key("cur"))
	j.FunctionalCurrency = "USD"
	for i := range j.Lines {
		j.Lines[i].Amount, _ = money.New(j.Lines[i].Amount.Amount(), "USD", money.RoundHalfEven)
	}
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("USD journal on ETB entity accepted: %v", err)
	}
	// A second entity (KES) with an inactive account and a USD-only account.
	var le2, inactive, usdOnly, kesAcct string
	adminStore := adminStoreFor(t, "postgres://postgres@/serk_construction_test?host=/tmp&port=5433")
	_ = adminStore
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if le2, err = postgres.CreateLegalEntity(ctx, tx, f.tenant, "SERK KENYA LTD", "KE", "KES", ""); err != nil {
			return err
		}
		if inactive, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: le2, Code: "1000", Name: "x", Type: ledger.Asset, Active: false}); err != nil {
			return err
		}
		if kesAcct, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: le2, Code: "2000", Name: "y", Type: ledger.Liability, Active: true}); err != nil {
			return err
		}
		usdOnly, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: "1050", Name: "USD bank", Type: ledger.Asset, Currency: "USD", Active: true})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Account of another entity (same tenant) is rejected in Go and by the composite FK.
	j = f.balanced(key("xent"))
	j.Lines[0].AccountID = kesAcct
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("cross-entity account accepted: %v", err)
	}
	_ = inactive
	// Inactive account rejected.
	j2 := ledger.Journal{LegalEntityID: le2, FunctionalCurrency: "KES", BusinessEventAt: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		Description: "x", SourceType: "MANUAL", IdempotencyKey: key("inact"), Lines: []ledger.Line{
			{LineNo: 1, AccountID: inactive, Side: ledger.Debit, Amount: money.MustNew("10", "KES")},
			{LineNo: 2, AccountID: kesAcct, Side: ledger.Credit, Amount: money.MustNew("10", "KES")}}}
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j2); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("inactive account accepted: %v", err)
	}
	// USD-only account refuses an ETB-only line but accepts a USD transaction.
	j = f.balanced(key("usdonly"))
	j.Lines[0].AccountID = usdOnly
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("currency-restricted account accepted ETB line: %v", err)
	}
	snap := f.approvedSnapshot(t, "USD", "ETB", "50")
	usd := money.MustNew("100.00", "USD")
	j = f.journal(key("usdok"),
		ledger.Line{AccountID: usdOnly, Side: ledger.Debit, Amount: money.MustNew("5000.00", "ETB"), TxnAmount: &usd, FXSnapshotID: snap},
		ledger.Line{AccountID: f.accounts["2000"], Side: ledger.Credit, Amount: money.MustNew("5000.00", "ETB")})
	f.lifecycle(t, j)
	// Reference data referenced by lines is frozen; entity currency frozen.
	for name, stmt := range map[string]string{
		"account type":    `UPDATE accounts SET type='ASSET' WHERE id=$1::uuid`,
		"account code":    `UPDATE accounts SET code='9999' WHERE id=$1::uuid`,
		"entity currency": `UPDATE legal_entities SET functional_currency='USD' WHERE id=$2::uuid`,
		"account delete":  `DELETE FROM accounts WHERE id=$1::uuid`,
	} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt, f.accounts["2000"], f.entity)
			return err
		})
		if err == nil {
			t.Fatalf("%s mutated: %s", name, stmt)
		}
	}
}

func TestApprovedContentIsFrozen(t *testing.T) {
	f := newFixture(t)
	res, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("frz")))
	// Draft lines may still be corrected (business as usual).
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE journal_lines SET memo='draft edit' WHERE journal_id=$1::uuid`, res.JournalID)
		return err
	})
	if err != nil {
		t.Fatalf("draft edit refused: %v", err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE journal_lines SET amount = amount * 10 WHERE journal_id=$1::uuid`,
		`UPDATE journal_lines SET account_id=$2::uuid WHERE journal_id=$1::uuid AND line_no=1`,
		`UPDATE journals SET description='after approval' WHERE id=$1::uuid`,
		`DELETE FROM journal_lines WHERE journal_id=$1::uuid`,
	} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt, res.JournalID, f.accounts["1000"])
			return err
		})
		if err == nil {
			t.Fatalf("approved journal mutated: %s", stmt)
		}
	}
}

func TestReversedLinkCannotBeForged(t *testing.T) {
	f := newFixture(t)
	orig := f.lifecycle(t, f.balanced(key("forge")))
	other := f.lifecycle(t, f.balanced(key("forge2")))
	approvedOnly, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("forge3")))
	_ = f.svc.ApproveJournal(f.ctx, f.appr, approvedOnly.JournalID)
	for name, target := range map[string]string{"unrelated posted": other, "approved not posted": approvedOnly.JournalID, "self": orig} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE journals SET status='REVERSED', reversed_by=$2::uuid WHERE id=$1::uuid`, orig, target)
			return err
		})
		if !errors.Is(err, postgres.ErrInvariant) {
			t.Fatalf("forged reversal link (%s) accepted: %v", name, err)
		}
	}
	// A reversal journal whose lines do not mirror the original is refused at post.
	res, _ := f.svc.ReverseJournal(f.ctx, f.ctrl, orig, key("rv"), "x", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		// tamper the draft reversal (allowed while DRAFT) so it no longer mirrors
		_, err := tx.Exec(ctx, `UPDATE journal_lines SET amount = 1 WHERE journal_id=$1::uuid`, res.JournalID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Go detects the content change at post time (hash) even before the DB mirror check.
	_ = f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID)
	if err := f.svc.PostJournal(f.ctx, auth.Principal{UserID: "u-poster-2", TenantID: f.tenant, Roles: []string{"controller"}}, res.JournalID); err == nil {
		t.Fatal("tampered reversal posted")
	}
}

func TestProjectRestrictionCoversLines(t *testing.T) {
	f := newFixture(t)
	j := f.balanced(key("lineproj"))
	j.ProjectID = ""
	j.Lines[0].ProjectID = f.project
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, ledger.ErrBadLine) {
		t.Fatalf("line-level project on unscoped journal accepted: %v", err)
	}
}

func TestConcurrentIdenticalCreatesAreIdempotent(t *testing.T) {
	f := newFixture(t)
	j := f.balanced(key("par"))
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.svc.CreateJournal(f.ctx, f.prep, j)
			if err != nil {
				errs <- err
				return
			}
			ids <- res.JournalID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent identical create failed: %v", err)
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("expected one journal, got %d", len(seen))
	}
	// Another user replaying the same key is not handed this journal.
	other := auth.Principal{UserID: "u-other", TenantID: f.tenant, Roles: []string{"accountant"}}
	if _, err := f.svc.CreateJournal(f.ctx, other, j); !errors.Is(err, postgres.ErrIdempotencyConflict) {
		t.Fatalf("cross-user replay accepted: %v", err)
	}
}

func TestAuditChainLinearUnderConcurrency(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				if _, err := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("cc"))); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		broken, err := postgres.VerifyAuditChain(ctx, tx, f.tenant)
		if err != nil || broken != 0 {
			t.Fatalf("chain broken at %d (%v)", broken, err)
		}
		var forks, n int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT prev_hash FROM audit_log GROUP BY prev_hash HAVING count(*)>1) x`).Scan(&forks)
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n)
		if forks != 0 || n < 80 {
			t.Fatalf("forks=%d rows=%d", forks, n)
		}
		// App role has no access to the chain head.
		if _, err := tx.Exec(ctx, `UPDATE audit_heads SET head_hash='x'`); err == nil {
			t.Fatal("audit_heads writable by app role")
		}
		return nil
	})
}

func TestOutboxAndPeriodsCannotBeTamperedByAppRole(t *testing.T) {
	f := newFixture(t)
	f.lifecycle(t, f.balanced(key("ob")))
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET published_at=now()`)
		return err
	})
	if err == nil {
		t.Fatal("app role suppressed outbox events")
	}
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='LOCKED' WHERE name='FY2026-Q4'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='OPEN' WHERE name='FY2026-Q4'`)
		return err
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("LOCKED period reopened: %v", err)
	}
}
