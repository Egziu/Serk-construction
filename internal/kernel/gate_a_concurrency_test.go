package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/fx"
)

// SC-08: controlled two-session interleavings at READ COMMITTED. One side
// holds an open transaction at a precise point; the other runs the real
// kernel command in a goroutine. We assert (1) the second side BLOCKS on the
// lock instead of reading stale state, and (2) the final committed state is
// one a serial execution could have produced.

const blockWindow = 400 * time.Millisecond

type outcome struct{ err error }

func async(fn func() error) <-chan outcome {
	ch := make(chan outcome, 1)
	go func() { ch <- outcome{fn()} }()
	return ch
}

func mustBlock(t *testing.T, ch <-chan outcome, what string) {
	t.Helper()
	select {
	case o := <-ch:
		t.Fatalf("SC-08: %s did not wait for the concurrent transaction (returned %v)", what, o.err)
	case <-time.After(blockWindow):
	}
}

func await(t *testing.T, ch <-chan outcome) error {
	t.Helper()
	select {
	case o := <-ch:
		return o.err
	case <-time.After(10 * time.Second):
		t.Fatal("SC-08: blocked command never completed (possible deadlock)")
		return nil
	}
}

// Order 1a: the close command holds the period row lock when a journal in
// that period becomes approved and its post starts. The post must wait. When
// the close then runs its checks (fresh snapshot, after the lock), it sees
// the approved journal and refuses; the post then proceeds. Serial order:
// approve -> close (refused) -> post.
func TestSC08_PostWaitsForInFlightCloseThenRefuses(t *testing.T) {
	f := newFixture(t)
	period := f.period(t)
	j, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("race1")))
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	closeTx, err := f.app.BeginTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTx.Rollback(ctx) //nolint:errcheck
	if _, err := postgres.GetFiscalPeriod(ctx, closeTx, period, true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, j.JournalID); err != nil {
		t.Fatal(err)
	}
	post := async(func() error { return f.svc.PostJournal(f.ctx, f.post, j.JournalID) })
	mustBlock(t, post, "PostJournal during an in-flight period close")
	closeErr := postgres.CloseFiscalPeriod(ctx, closeTx, period, f.ctrl.UserID, false)
	if closeErr == nil {
		if err := closeTx.Commit(ctx); err != nil {
			closeErr = postgres.Translate(err)
		}
	} else {
		_ = closeTx.Rollback(ctx)
	}
	postErr := await(t, post)
	status := f.periodStatus(t, period)
	jt := f.totals(t, j.JournalID)
	t.Logf("close err=%v | post err=%v | period=%s journal=%s", closeErr, postErr, status, jt.status)
	switch {
	case closeErr == nil && status == "CLOSED":
		if postErr == nil || jt.status == "POSTED" {
			t.Fatalf("SC-08: journal posted into a period that closed first (post err %v)", postErr)
		}
	case closeErr != nil && status == "OPEN":
		if postErr != nil || jt.status != "POSTED" {
			t.Fatalf("SC-08: unexpected post outcome after refused close: %v %s", postErr, jt.status)
		}
	default:
		t.Fatalf("SC-08: non-serial outcome close=%v status=%s post=%v", closeErr, status, postErr)
	}
}

// Order 1b: the exact audit race. A close has updated the period row and not
// yet committed when a post of an already-approved journal starts. Before
// the fix the post read the old OPEN version and committed. Now it must wait
// for the close and then refuse. (The close session runs as the schema owner
// with session_replication_role=replica solely to bypass the pending-journal
// prerequisite, isolating the lock behaviour under test.)
func TestSC08_PostBlockedByUncommittedCloseIsRefused(t *testing.T) {
	f := newFixture(t)
	period := f.period(t)
	j, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("race1b")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, j.JournalID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	tx, err := f.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='CLOSED', closed_by='closer', closed_at=now() WHERE id=$1::uuid`, period); err != nil {
		t.Fatal(err)
	}
	post := async(func() error { return f.svc.PostJournal(f.ctx, f.post, j.JournalID) })
	mustBlock(t, post, "PostJournal while the period row is being closed")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = await(t, post)
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("SC-08: post committed into a period closed concurrently: %v", err)
	}
	t.Logf("post after concurrent close -> %v", err)
	if s := f.totals(t, j.JournalID).status; s != "APPROVED" {
		t.Fatalf("journal status %s", s)
	}
}

// Order 2: a post is in flight (holds the period share lock); the close must
// wait, then run its checks and closing TB with the posted journal visible.
func TestSC08_CloseWaitsForInFlightPostAndIncludesIt(t *testing.T) {
	f := newFixture(t)
	period := f.period(t)
	j, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("race2")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, j.JournalID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	postTx, err := f.app.BeginTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer postTx.Rollback(ctx) //nolint:errcheck
	rec, err := postgres.GetJournal(ctx, postTx, j.JournalID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorizeIn(ctx, postTx, f.post, "journal.post", "journal", j.JournalID, ""); err != nil {
		t.Fatal(err)
	}
	if err := postgres.PostJournal(ctx, postTx, j.JournalID, f.post.UserID, rec.Version); err != nil {
		t.Fatal(err)
	}
	closing := async(func() error { _, err := f.svc.ClosePeriod(f.ctx, f.ctrl, period, false); return err })
	mustBlock(t, closing, "ClosePeriod while a post holds the period")
	if err := postTx.Commit(ctx); err != nil {
		t.Fatal(postgres.Translate(err))
	}
	if err := await(t, closing); err != nil {
		t.Fatalf("close after post: %v", err)
	}
	_, _ = f.svc.GetJournal(f.ctx, f.prep, j.JournalID)
	var tb postgres.PeriodCloseRecord
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		tb, err = postgres.LatestPeriodClose(ctx, tx, period)
		return err
	})
	if tb.JournalCount != 1 || tb.TBDebits != "115000.000000" {
		t.Fatalf("SC-08: closing TB excluded the concurrently posted journal: %+v", tb)
	}
	t.Logf("closing TB after waiting: %+v", tb)
}

// FX order 1: a withdrawal is in flight; a journal line using the rate must
// wait and then be refused.
func TestSC08_LineInsertWaitsForInFlightFXWithdrawal(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{})
	snap := f.snapshot(t, "USD", "ETB", "57.25", day(10, 5), true)
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	tx, err := f.app.BeginTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := f.authorizeIn(ctx, tx, f.appr, "fx.snapshot.withdraw", "fx_snapshot", snap, ""); err != nil {
		t.Fatal(err)
	}
	if err := postgres.DecideFXSnapshot(ctx, tx, snap, postgres.FXDecision{From: fx.StatusApproved, To: fx.StatusDisputed, By: f.appr.UserID, Reason: "publication error"}); err != nil {
		t.Fatal(err)
	}
	create := async(func() error {
		_, err := f.svc.CreateJournal(f.ctx, f.prep, f.usdJournal(key("fxrace1"), "100.00", "5725.00", snap))
		return err
	})
	mustBlock(t, create, "CreateJournal using a rate being withdrawn")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = await(t, create)
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("SC-08: line committed against a withdrawn rate: %v", err)
	}
	t.Logf("create after concurrent withdrawal -> %v", err)
	if n := f.linesReferencing(t, snap); n != 0 {
		t.Fatalf("SC-08: %d line(s) reference the withdrawn rate", n)
	}
}

// FX order 2: a line insert is in flight; the withdrawal must wait and then
// be refused because the rate is now referenced.
func TestSC08_FXWithdrawalWaitsForInFlightLineAndRefuses(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{})
	snap := f.snapshot(t, "USD", "ETB", "57.25", day(10, 5), true)
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	tx, err := f.app.BeginTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	j := f.usdJournal(key("fxrace2"), "100.00", "5725.00", snap)
	j.TenantID, j.CreatedBy = f.tenant, f.prep.UserID
	if _, _, err := postgres.CreateJournal(ctx, tx, j); err != nil {
		t.Fatal(err)
	}
	withdraw := async(func() error { return f.svc.WithdrawFXSnapshot(f.ctx, f.appr, snap, "publication error") })
	mustBlock(t, withdraw, "WithdrawFXSnapshot while a line referencing it is uncommitted")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = await(t, withdraw)
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("SC-08: referenced rate withdrawn: %v", err)
	}
	t.Logf("withdraw after concurrent line insert -> %v", err)
}

func (f *fixture) periodStatus(t *testing.T, id string) string {
	t.Helper()
	var s string
	if err := f.admin.QueryRow(f.ctx, `SELECT status FROM fiscal_periods WHERE id=$1::uuid`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) linesReferencing(t *testing.T, snap string) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM journal_lines WHERE fx_snapshot_id=$1::uuid`, snap).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// FX order 2, raw path: the kernel's withdraw takes FOR UPDATE first, which
// alone would serialise. A raw UPDATE (as a compromised app session would
// issue) takes only a NO KEY UPDATE lock, which does NOT conflict with the
// FK key-share lock of the pending line; the database must still serialise
// it via the snapshot share lock taken by the line validation trigger.
func TestSC08_RawFXWithdrawalWaitsForInFlightLine(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{})
	snap := f.snapshot(t, "USD", "ETB", "57.25", day(10, 5), true)
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	tx, err := f.app.BeginTenant(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	j := f.usdJournal(key("fxrace3"), "100.00", "5725.00", snap)
	j.TenantID, j.CreatedBy = f.tenant, f.prep.UserID
	if _, _, err := postgres.CreateJournal(ctx, tx, j); err != nil {
		t.Fatal(err)
	}
	withdraw := async(func() error {
		return f.rawAs(f.appr, "fx.snapshot.withdraw", "fx_snapshot", snap, "",
			`UPDATE fx_snapshots SET approval_status='DISPUTED', decision_reason='raw withdrawal' WHERE snapshot_id=$1::uuid`, snap)
	})
	mustBlock(t, withdraw, "raw UPDATE withdrawing a rate referenced by an uncommitted line")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := await(t, withdraw); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("SC-08: referenced rate withdrawn by raw SQL: %v", err)
	}
}
