package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// GATEA-07 (server side): revocation is effective immediately, inside the
// approval transaction, for exactly the intended tokens, and the tenant login
// cannot undo or backdate it.

func TestSessions_RevocationKillsOldTokensIncludingInFlightApprovals(t *testing.T) {
	f := newFixture(t)
	admin := auth.Principal{Kind: auth.KindHuman, UserID: "u-secadmin", TenantID: f.tenant, Roles: []string{"security_admin"}, IssuedAt: time.Now().Add(-time.Minute)}
	old := f.appr
	old.IssuedAt, old.SessionID = time.Now().Add(-10*time.Minute), "sess-old"

	res, err := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("sess")))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CheckSession(f.ctx, old); err != nil {
		t.Fatalf("valid session refused: %v", err)
	}
	cutoff, err := f.svc.RevokeSessions(f.ctx, admin, old.UserID, "role removed: finance_manager")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := f.svc.CheckSession(f.ctx, old); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("revoked session still accepted: %v", err)
	}
	// The API middleware is bypassed here on purpose: the approval itself
	// re-checks inside its transaction.
	if err := f.svc.ApproveJournal(f.ctx, old, res.JournalID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("approval with a revoked session: %v", err)
	}
	// A token without iat cannot prove it is newer than the cut-off.
	noIat := f.appr
	if err := f.svc.CheckSession(f.ctx, noIat); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("token without iat accepted after a subject revocation: %v", err)
	}
	// A token issued after the cut-off (re-authentication) works again.
	fresh := f.appr
	fresh.IssuedAt = cutoff.Add(2 * time.Second).Truncate(time.Second)
	if err := f.svc.ApproveJournal(f.ctx, fresh, res.JournalID); err != nil {
		t.Fatalf("approval after re-authentication: %v", err)
	}
	// Other people and the other tenant are unaffected.
	other := f.post
	other.IssuedAt = time.Now().Add(-time.Hour)
	if err := f.svc.CheckSession(f.ctx, other); err != nil {
		t.Fatalf("unrelated subject refused: %v", err)
	}
	sameNameOtherTenant := f.outsider
	sameNameOtherTenant.UserID = old.UserID
	if err := f.svc.CheckSession(f.ctx, sameNameOtherTenant); err != nil {
		t.Fatalf("revocation leaked into another tenant: %v", err)
	}
	// Audited and emitted.
	var audits, events int
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='identity.sessions_revoked' AND aggregate_id=$1`, old.UserID).Scan(&audits)
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE event_type='identity.sessions_revoked.v1' AND aggregate_id=$1`, old.UserID).Scan(&events)
	})
	if audits != 1 || events != 1 {
		t.Errorf("revocation audit/outbox = %d/%d, want 1/1", audits, events)
	}
}

func TestSessions_WhoMayRevokeAndLogout(t *testing.T) {
	f := newFixture(t)
	me := f.prep
	me.IssuedAt, me.SessionID = time.Now().Add(-time.Minute), "sess-a"
	// Revoking someone else needs identity.revoke_sessions; the CFO lacks it.
	if _, err := f.svc.RevokeSessions(f.ctx, f.cfo, f.appr.UserID, "attempted by cfo"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cfo revoked another user's sessions: %v", err)
	}
	if _, err := f.svc.RevokeSessions(f.ctx, f.cfo, f.appr.UserID, "x"); err == nil {
		t.Fatal("reason shorter than 3 characters accepted")
	}
	// Logout kills only this token.
	if err := f.svc.Logout(f.ctx, me); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if err := f.svc.CheckSession(f.ctx, me); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("logged-out token still accepted: %v", err)
	}
	if err := f.svc.Logout(f.ctx, me); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("a revoked token could act again: %v", err)
	}
	other := me
	other.SessionID = "sess-b"
	if err := f.svc.CheckSession(f.ctx, other); err != nil {
		t.Fatalf("logout of one session killed another: %v", err)
	}
	// "Log out everywhere" needs no special permission.
	if _, err := f.svc.RevokeSessions(f.ctx, other, other.UserID, "lost laptop"); err != nil {
		t.Fatalf("self revoke: %v", err)
	}
	if err := f.svc.CheckSession(f.ctx, other); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("self revoke ineffective: %v", err)
	}
	noJti := f.post
	if err := f.svc.Logout(f.ctx, noJti); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("logout without jti: %v", err)
	}
}

func TestSessions_TenantLoginCannotUndoOrBackdateRevocations(t *testing.T) {
	f := newFixture(t)
	admin := auth.Principal{Kind: auth.KindHuman, UserID: "u-secadmin", TenantID: f.tenant, Roles: []string{"security_admin"}}
	if _, err := f.svc.RevokeSessions(f.ctx, admin, "u-terminated", "employment ended"); err != nil {
		t.Fatal(err)
	}
	for name, stmt := range map[string]string{
		"delete a revocation":          `DELETE FROM session_revocations`,
		"move a cut-off into the past": `UPDATE session_revocations SET revoked_before = '2000-01-01'`,
		"truncate the revocation list": `TRUNCATE session_revocations`,
	} {
		denied(t, name, f.rawExec(stmt))
	}
	// Backdating at insert is overwritten with database time.
	if err := f.rawExec(`INSERT INTO session_revocations (subject, reason, revoked_by, revoked_before) VALUES ('u-x', 'probe', 'u-x', '2000-01-01')`); err != nil {
		t.Fatal(err)
	}
	var age time.Duration
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var ts time.Time
		err := tx.QueryRow(ctx, `SELECT revoked_before FROM session_revocations WHERE subject='u-x'`).Scan(&ts)
		age = time.Since(ts)
		return err
	})
	if age > time.Minute {
		t.Errorf("client-supplied revoked_before kept (age %s)", age)
	}
	// Cross-tenant: tenant 2 neither sees nor can write tenant 1's list.
	var n int
	_ = f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM session_revocations`).Scan(&n)
	})
	if n != 0 {
		t.Errorf("tenant 2 sees %d foreign revocations", n)
	}
	err := f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO session_revocations (tenant_id, subject, reason, revoked_by) VALUES ($1, 'u-approver', 'cross-tenant', 'x')`, f.tenant)
		return err
	})
	denied(t, "insert a revocation into another tenant", err)
}
