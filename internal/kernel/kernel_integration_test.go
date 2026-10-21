package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

func TestHappyPathPostsAndBalancesAccounts(t *testing.T) {
	f := newFixture(t)
	id := f.lifecycle(t, f.balanced(key("ok")))

	rec, err := f.svc.GetJournal(f.ctx, f.prep, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != ledger.StatusPosted || rec.ApprovedBy != "u-approver" || rec.PostedBy != "u-poster" || rec.Version != 3 {
		t.Fatalf("unexpected record %+v", rec)
	}
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		ap, err := postgres.AccountBalance(ctx, tx, f.accounts["2000"], "ETB")
		if err != nil {
			t.Fatal(err)
		}
		if ap.AmountString() != "-115000.00" {
			t.Fatalf("AP balance %s", ap)
		}
		rows, err := tx.Query(ctx, `SELECT event_type FROM outbox WHERE aggregate_id=$1 AND published_at IS NULL`, id)
		if err != nil {
			t.Fatal(err)
		}
		types := map[string]int{}
		for rows.Next() {
			var et string
			_ = rows.Scan(&et)
			types[et]++
		}
		rows.Close()
		if types["journal.created"] != 1 || types["journal.approved"] != 1 || types["journal.posted"] != 1 {
			t.Fatalf("outbox events for journal: %v", types)
		}
		broken, err := postgres.VerifyAuditChain(ctx, tx, f.tenant)
		if err != nil || broken != 0 {
			t.Fatalf("audit chain broken at %d (%v)", broken, err)
		}
		return nil
	})
}

func TestUnbalancedRejectedInGoAndInDatabase(t *testing.T) {
	f := newFixture(t)
	j := f.journal(key("unbal"),
		ledger.Line{AccountID: f.accounts["5000"], Side: ledger.Debit, Amount: money.MustNew("100.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1000"], Side: ledger.Credit, Amount: money.MustNew("99.99", "ETB")},
	)
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, ledger.ErrUnbalanced) {
		t.Fatalf("Go validation missed unbalanced journal: %v", err)
	}

	// Adversarial: bypass the Go domain entirely and drive raw SQL as the app
	// role. The database must still refuse to COMMIT an unbalanced POSTED journal.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var jid string
		if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by)
			VALUES ($1::uuid,$2::uuid,'ETB','2026-10-15','raw','MANUAL',$3,'h','a') RETURNING id::text`, f.tenant, f.entity, key("raw")).Scan(&jid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency) VALUES
			($1::uuid,$2::uuid,$5::uuid,1,$3::uuid,'DEBIT',100,'ETB'),($1::uuid,$2::uuid,$5::uuid,2,$4::uuid,'CREDIT',99.99,'ETB')`, jid, f.tenant, f.accounts["5000"], f.accounts["1000"], f.entity); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED',approved_by='b',approved_at=now() WHERE id=$1::uuid`, jid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE journals SET status='POSTED',posted_by='c',posted_at=now() WHERE id=$1::uuid`, jid)
		return err
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("database accepted an unbalanced posted journal: %v", err)
	}
}

func TestSegregationOfDuties(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("sod")))
	if err != nil {
		t.Fatal(err)
	}
	// Preparer with an approver role still cannot approve their own work.
	selfApprover := auth.Principal{UserID: "u-preparer", TenantID: f.tenant, Roles: []string{"accountant", "finance_manager"}}
	if err := f.svc.ApproveJournal(f.ctx, selfApprover, res.JournalID); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("self-approval allowed: %v", err)
	}
	// Posting before approval is an illegal transition even for a controller.
	if err := f.svc.PostJournal(f.ctx, f.post, res.JournalID); !errors.Is(err, ledger.ErrBadTransition) {
		t.Fatalf("post without approval allowed: %v", err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID); err != nil {
		t.Fatal(err)
	}
	// Approver who also holds the controller role may not post under strict SoD.
	approverPoster := auth.Principal{UserID: "u-approver", TenantID: f.tenant, Roles: []string{"finance_manager", "controller"}}
	if err := f.svc.PostJournal(f.ctx, approverPoster, res.JournalID); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("approver posting allowed: %v", err)
	}
	// Accountant lacks journal.post entirely.
	if err := f.svc.PostJournal(f.ctx, f.prep, res.JournalID); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("accountant posting allowed: %v", err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, res.JournalID); err != nil {
		t.Fatal(err)
	}
}

func TestTenantIsolation(t *testing.T) {
	f := newFixture(t)
	id := f.lifecycle(t, f.balanced(key("iso")))

	// Tenant 2 (with every role) cannot see, approve, post or reverse tenant 1's journal.
	if _, err := f.svc.GetJournal(f.ctx, f.outsider, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read leaked: %v", err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.outsider, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
	if _, err := f.svc.ReverseJournal(f.ctx, f.outsider, id, key("x"), "steal", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant reverse: %v", err)
	}
	// Adversarial raw SQL as the app role under tenant 2: zero rows, and an
	// INSERT claiming tenant 1 is rejected by the RLS WITH CHECK.
	err := f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM journal_lines WHERE journal_id=$1::uuid`, id).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS leaked %d lines", n)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1::uuid`, f.tenant).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS leaked %d audit rows", n)
		}
		_, err := tx.Exec(ctx, `INSERT INTO accounts(tenant_id,legal_entity_id,code,name,type) VALUES ($1::uuid,$2::uuid,'9999','smuggled','ASSET')`, f.tenant, f.entity)
		return err
	})
	if err == nil {
		t.Fatal("RLS allowed writing a row into another tenant")
	}
	// A journal referencing another tenant's account must fail the composite FK.
	j := f.balanced(key("xacct"))
	_ = f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM accounts WHERE code='1000'`).Scan(&j.Lines[0].AccountID)
	})
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("journal line pointing at a foreign-tenant account accepted: %v", err)
	}
}

func TestPostedJournalIsImmutable(t *testing.T) {
	f := newFixture(t)
	id := f.lifecycle(t, f.balanced(key("imm")))
	for _, stmt := range []string{
		`UPDATE journal_lines SET amount = amount + 1 WHERE journal_id=$1::uuid`,
		`DELETE FROM journal_lines WHERE journal_id=$1::uuid`,
		`UPDATE journals SET description='tampered' WHERE id=$1::uuid`,
		`UPDATE journals SET status='DRAFT' WHERE id=$1::uuid`,
		`UPDATE journals SET business_event_at='2020-01-01' WHERE id=$1::uuid`,
		`DELETE FROM journals WHERE id=$1::uuid`,
	} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt, id)
			return err
		})
		if err == nil {
			t.Fatalf("statement mutated a posted journal: %s", stmt)
		}
	}
	// Audit log is append-only too.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_log SET payload='{}' WHERE aggregate_id=$1`, id)
		return err
	})
	if err == nil {
		t.Fatal("audit_log row was modified")
	}
}

func TestIdempotentReplayAndConflict(t *testing.T) {
	f := newFixture(t)
	k := key("idem")
	j := f.balanced(k)
	a, err := f.svc.CreateJournal(f.ctx, f.prep, j)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.svc.CreateJournal(f.ctx, f.prep, j) // offline client retries the same command
	if err != nil {
		t.Fatal(err)
	}
	if !b.Replayed || b.JournalID != a.JournalID {
		t.Fatalf("replay created a second journal: %+v %+v", a, b)
	}
	j.Description = "same key, different payload"
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, j); !errors.Is(err, postgres.ErrIdempotencyConflict) {
		t.Fatalf("key reuse with different payload accepted: %v", err)
	}
	// Exactly one audit record and one outbox event for the create.
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE aggregate_id=$1 AND action='journal.create'`, a.JournalID).Scan(&n)
		if n != 1 {
			t.Fatalf("expected 1 create audit row, got %d", n)
		}
		return nil
	})
}

func TestReversalFlow(t *testing.T) {
	f := newFixture(t)
	orig := f.lifecycle(t, f.balanced(key("rev")))
	when := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if _, err := f.svc.ReverseJournal(f.ctx, f.ctrl, orig, key("revk0"), "no date", time.Time{}); !errors.Is(err, ledger.ErrBadLine) {
		t.Fatalf("reversal without event date accepted: %v", err)
	}
	rk := key("revk")
	res, err := f.svc.ReverseJournal(f.ctx, f.ctrl, orig, rk, "duplicate supplier invoice", when)
	if err != nil {
		t.Fatal(err)
	}
	// Identical retry is an idempotent replay, not a conflict.
	if again, err := f.svc.ReverseJournal(f.ctx, f.ctrl, orig, rk, "duplicate supplier invoice", when); err != nil || !again.Replayed || again.JournalID != res.JournalID {
		t.Fatalf("reversal replay: %+v %v", again, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	// The reversal is a normal draft: the controller who created it cannot approve it.
	ctrlApprover := auth.Principal{UserID: "u-poster", TenantID: f.tenant, Roles: []string{"controller", "finance_manager"}}
	if err := f.svc.ApproveJournal(f.ctx, ctrlApprover, res.JournalID); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("reversal self-approval allowed: %v", err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID); err != nil {
		t.Fatal(err)
	}
	poster2 := auth.Principal{UserID: "u-poster-2", TenantID: f.tenant, Roles: []string{"controller"}}
	if err := f.svc.PostJournal(f.ctx, poster2, res.JournalID); err != nil {
		t.Fatal(err)
	}
	o, _ := f.svc.GetJournal(f.ctx, f.prep, orig)
	r, _ := f.svc.GetJournal(f.ctx, f.prep, res.JournalID)
	if o.Status != ledger.StatusReversed || o.ReversedBy != res.JournalID || r.ReversalOf != orig || r.Status != ledger.StatusPosted {
		t.Fatalf("links wrong: orig %s/%s rev %s/%s", o.Status, o.ReversedBy, r.Status, r.ReversalOf)
	}
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, code := range []string{"1200", "1300", "2000"} {
			bal, _ := postgres.AccountBalance(ctx, tx, f.accounts[code], "ETB")
			if !bal.IsZero() {
				t.Fatalf("account %s net %s after reversal", code, bal)
			}
		}
		return nil
	})
	// A second reversal of the same original must fail.
	if _, err := f.svc.ReverseJournal(f.ctx, f.ctrl, orig, key("revk2"), "again", when); !errors.Is(err, ledger.ErrNotPosted) && !errors.Is(err, ledger.ErrAlreadyReversed) {
		t.Fatalf("double reversal accepted: %v", err)
	}
}

func TestClosedPeriodBlocksPosting(t *testing.T) {
	f := newFixture(t)
	period := f.period(t)
	// A raw close without an actor is refused by the database.
	if err := f.rawExec(`UPDATE fiscal_periods SET status='CLOSED' WHERE id=$1::uuid`, period); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("anonymous raw close accepted: %v", err)
	}
	// Closing with an approved-but-unposted journal in the period is refused.
	pending, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("pending")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, pending.JournalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClosePeriod(f.ctx, f.ctrl, period, false); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("closed over an approved, unposted journal: %v", err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, pending.JournalID); err != nil {
		t.Fatal(err)
	}
	// Close records the trial balance; posting into the closed period fails.
	res, err := f.svc.ClosePeriod(f.ctx, f.ctrl, period, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Action != "CLOSE" || res.Record.JournalCount != 1 || res.Record.TBDebits != "115000.000000" || res.Record.TBDebits != res.Record.TBCredits {
		t.Fatalf("closing TB record: %+v", res.Record)
	}
	late, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("late")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, late.JournalID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, late.JournalID); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("posted into closed period: %v", err)
	}
	// Reopen needs period.reopen, MFA step-up, a reason, and a person other than the closer.
	noMFA := f.cfo
	noMFA.MFA = false
	if err := f.svc.ReopenPeriod(f.ctx, noMFA, period, "late supplier invoice"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("reopen without MFA: %v", err)
	}
	if err := f.svc.ReopenPeriod(f.ctx, f.cfo, period, "x"); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("reopen without reason: %v", err)
	}
	closerAsCFO := auth.Principal{UserID: f.ctrl.UserID, TenantID: f.tenant, Roles: []string{"cfo"}, MFA: true, AuthTime: time.Now()}
	if err := f.svc.ReopenPeriod(f.ctx, closerAsCFO, period, "late supplier invoice"); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("closer reopened own period: %v", err)
	}
	if err := f.svc.ReopenPeriod(f.ctx, f.cfo, period, "late supplier invoice"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, late.JournalID); err != nil {
		t.Fatal(err)
	}
	// LOCKED is terminal.
	if _, err := f.svc.ClosePeriod(f.ctx, f.ctrl, period, true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ReopenPeriod(f.ctx, f.cfo, period, "attempt after lock"); err == nil {
		t.Fatal("LOCKED period reopened")
	}
	// Event outside any period.
	j := f.balanced(key("noperiod"))
	j.BusinessEventAt = time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	out, _ := f.svc.CreateJournal(f.ctx, f.prep, j)
	_ = f.svc.ApproveJournal(f.ctx, f.appr, out.JournalID)
	if err := f.svc.PostJournal(f.ctx, f.post, out.JournalID); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("posted without a fiscal period: %v", err)
	}
}

func TestProjectAttributeRestriction(t *testing.T) {
	f := newFixture(t)
	id := f.lifecycle(t, f.balanced(key("abac")))
	pm := auth.Principal{UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{"00000000-0000-0000-0000-000000000000"}}
	if _, err := f.svc.GetJournal(f.ctx, pm, id); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("project restriction bypassed: %v", err)
	}
	pm.ProjectIDs = []string{f.project}
	if _, err := f.svc.GetJournal(f.ctx, pm, id); err != nil {
		t.Fatal(err)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	f := newFixture(t)
	res, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("occ")))
	// Simulate a stale version: approve with the wrong expected version via the repo.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return postgres.ApproveJournal(ctx, tx, res.JournalID, "u-approver", 99)
	})
	if !errors.Is(err, postgres.ErrVersionConflict) {
		t.Fatalf("stale version accepted: %v", err)
	}
}
