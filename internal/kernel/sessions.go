package kernel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// ErrSessionRevoked: the presented token was revoked (logout, termination,
// role removal). The caller must authenticate again.
var ErrSessionRevoked = errors.New("kernel: session revoked")

// ErrInvalidInput: a command argument failed validation.
var ErrInvalidInput = errors.New("kernel: invalid input")

// CheckSession refuses a principal whose token appears on the tenant's shared
// revocation list. It is called by the API on every authenticated request; the
// same check runs again inside every approval transaction (authorize), so a
// revocation also stops a command that had already passed the middleware.
// Any database error is returned as-is: callers must fail closed.
func (s *Service) CheckSession(ctx context.Context, p auth.Principal) error {
	if p.TenantID == "" || p.UserID == "" {
		return auth.ErrUnauthenticated
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return checkSessionTx(ctx, tx, p)
	})
}

func checkSessionTx(ctx context.Context, tx pgx.Tx, p auth.Principal) error {
	var iat *time.Time
	if !p.IssuedAt.IsZero() {
		t := p.IssuedAt
		iat = &t
	}
	var jti *string
	if p.SessionID != "" {
		jti = &p.SessionID
	}
	var revoked bool
	if err := tx.QueryRow(ctx, `SELECT session_is_revoked($1, $2, $3)`, p.UserID, jti, iat).Scan(&revoked); err != nil {
		return fmt.Errorf("kernel: session check: %w", err)
	}
	if revoked {
		return ErrSessionRevoked
	}
	return nil
}

// RevokeSessions kills every token of subject issued up to now (database
// time). A principal may always revoke its own sessions ("log out
// everywhere"); revoking someone else's requires identity.revoke_sessions.
// It returns the effective cut-off.
func (s *Service) RevokeSessions(ctx context.Context, p auth.Principal, subject, reason string) (time.Time, error) {
	subject, reason = strings.TrimSpace(subject), strings.TrimSpace(reason)
	if subject == "" || len(reason) < 3 {
		return time.Time{}, fmt.Errorf("%w: subject and a reason (3+ characters) are required", ErrInvalidInput)
	}
	if subject != p.UserID {
		if err := s.authz.Require(p, auth.PermIdentityRevoke, p.TenantID); err != nil {
			return time.Time{}, err
		}
	}
	var cutoff time.Time
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSessionTx(ctx, tx, p); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO session_revocations (subject, reason, revoked_by) VALUES ($1, $2, $3) RETURNING revoked_before`,
			subject, reason, p.UserID).Scan(&cutoff); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "identity.sessions_revoked", "identity_subject", subject, "identity.sessions_revoked.v1",
			map[string]any{"subject": subject, "revoked_before": cutoff, "reason": reason})
	})
	return cutoff, err
}

// Logout revokes exactly the presented token. Tokens without a jti cannot be
// revoked individually; the caller must use RevokeSessions for itself.
func (s *Service) Logout(ctx context.Context, p auth.Principal) error {
	if p.SessionID == "" {
		return fmt.Errorf("%w: token has no jti; revoke all own sessions instead", ErrInvalidInput)
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSessionTx(ctx, tx, p); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO session_revocations (subject, token_id, reason, revoked_by) VALUES ($1, $2, 'logout', $1)`,
			p.UserID, p.SessionID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "identity.logout", "identity_subject", p.UserID, "identity.logout.v1",
			map[string]any{"subject": p.UserID})
	})
}
