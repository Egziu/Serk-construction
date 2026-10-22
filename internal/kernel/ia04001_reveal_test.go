package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

func TestIA04001_PrivilegedRevealIsPermissionedFreshAndAudited(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	purpose := "Call-back verification of new payee details against the supplier letter"
	// No permission (procurement, treasury, site roles).
	for _, p := range []auth.Principal{c.buyer, c.siteEng, c.treasury} {
		if _, err := f.svc.RevealBankAccount(f.ctx, p, "supplier_bank_account", w.supBank, purpose); !errors.Is(err, auth.ErrForbidden) {
			t.Errorf("%s revealed bank details: %v", p.UserID, err)
		}
	}
	// Permission but no fresh MFA.
	stale := c.finMgr
	stale.AuthTime = time.Now().Add(-2 * time.Hour)
	if _, err := f.svc.RevealBankAccount(f.ctx, stale, "supplier_bank_account", w.supBank, purpose); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Errorf("reveal without fresh MFA: %v", err)
	}
	// Permission and MFA but no stated purpose.
	if _, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, "x"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("reveal without purpose: %v", err)
	}
	// Project-restricted holder of the permission: entity-level account not found.
	scoped := c.finMgr
	scoped.ProjectIDs = []string{f.project}
	if _, err := f.svc.RevealBankAccount(f.ctx, scoped, "company_bank_account", w.bank, purpose); !errors.Is(err, ErrNotFound) {
		t.Errorf("project-restricted reveal of a company account: %v", err)
	}
	// Legitimate reveal returns the number and leaves an audit record without it.
	got, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, purpose)
	must(t, "reveal", err)
	if got.AccountNumber != iaSupplierAcct {
		t.Fatalf("revealed %q", got.AccountNumber)
	}
	var n int
	var payload string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'bank.details.reveal' AND actor_id = 'u-finance-manager'`).Scan(&n)
		return tx.QueryRow(ctx, `SELECT COALESCE(string_agg(payload::text, ' '), '') FROM outbox`).Scan(&payload)
	})
	if n != 1 {
		t.Errorf("reveal audit records: %d, want 1", n)
	}
	if strings.Contains(payload, iaSupplierAcct) || strings.Contains(payload, iaCompanyAcct) {
		t.Errorf("EXPOSED: an outbox event carries a full account number")
	}
}
