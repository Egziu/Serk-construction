package kernel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// These tests encode the findings of the independent adversarial review.

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
	f.setupFX(t, fx.Policy{})
	snap := f.snapshot(t, "USD", "ETB", "50", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), true)
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
	// Since 0002 the app role cannot change line amounts at all, even on a
	// DRAFT (only memo is updatable), so the reversal cannot be made to stop
	// mirroring its original.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE journal_lines SET amount = 1 WHERE journal_id=$1::uuid`, res.JournalID)
		return err
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("draft reversal amount tampered: %v", err)
	}
	// The untampered reversal posts and links correctly.
	_ = f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID)
	if err := f.svc.PostJournal(f.ctx, auth.Principal{UserID: "u-poster-2", TenantID: f.tenant, Roles: []string{"controller"}}, res.JournalID); err != nil {
		t.Fatalf("valid reversal refused: %v", err)
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
	for _, l := range j.Lines {
		if !l.AppliedRate.IsZero() || l.FXPolicyID != "" {
			t.Fatalf("CreateJournal mutated the caller's lines: %+v", l)
		}
	}
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
