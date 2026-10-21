package kernel

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// ErrClosePrerequisite is returned when a period cannot be closed yet.
var ErrClosePrerequisite = errors.New("kernel: period close prerequisite failed")

// ClosePeriodResult reports the immutable closing trial-balance record.
type ClosePeriodResult struct {
	PeriodID string
	Record   postgres.PeriodCloseRecord
}

// ClosePeriod closes (or locks) a fiscal period. The period row is locked
// FIRST, so in-flight postings finish and later ones wait and then see the
// closed period (SC-08). Prerequisites: no ledger integrity violations, an
// intact audit chain, and (enforced by the database) no approved-but-unposted
// journals in the period. The database records the closing trial balance.
func (s *Service) ClosePeriod(ctx context.Context, p auth.Principal, periodID string, lock bool) (ClosePeriodResult, error) {
	if err := s.authz.Require(p, auth.PermPeriodClose, p.TenantID); err != nil {
		return ClosePeriodResult{}, err
	}
	var res ClosePeriodResult
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		per, err := postgres.GetFiscalPeriod(ctx, tx, periodID, true)
		if err != nil {
			return err
		}
		if per.Status == "LOCKED" || (per.Status == "CLOSED" && !lock) {
			return fmt.Errorf("%w: period is already %s", ErrClosePrerequisite, per.Status)
		}
		violations, err := postgres.LedgerIntegrityScan(ctx, tx)
		if err != nil {
			return err
		}
		if len(violations) > 0 {
			return fmt.Errorf("%w: %d ledger integrity violation(s), first: %s %s", ErrClosePrerequisite, len(violations), violations[0].Rule, violations[0].Detail)
		}
		if broken, err := postgres.VerifyAuditChain(ctx, tx, p.TenantID); err != nil {
			return err
		} else if broken != 0 {
			return fmt.Errorf("%w: audit chain broken at %d", ErrClosePrerequisite, broken)
		}
		if err := postgres.CloseFiscalPeriod(ctx, tx, periodID, p.UserID, lock); err != nil {
			return err
		}
		rec, err := postgres.LatestPeriodClose(ctx, tx, periodID)
		if err != nil {
			return err
		}
		res = ClosePeriodResult{PeriodID: periodID, Record: rec}
		ev := "period.closed"
		if lock {
			ev = "period.locked"
		}
		return s.record(ctx, tx, p, "period.close", "fiscal_period", periodID, ev, map[string]any{
			"period_id": periodID, "name": per.Name, "action": rec.Action, "journal_count": rec.JournalCount,
			"tb_debits": rec.TBDebits, "tb_credits": rec.TBCredits, "tb_hash": rec.TBHash})
	})
	return res, err
}

// ReopenPeriod reopens a CLOSED period. Requires period.reopen, a recent MFA
// and a reason; the database forbids the closer from reopening.
func (s *Service) ReopenPeriod(ctx context.Context, p auth.Principal, periodID, reason string) error {
	if err := s.authz.Require(p, auth.PermPeriodReopen, p.TenantID); err != nil {
		return err
	}
	if err := s.authz.RequireStepUp(p); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		per, err := postgres.GetFiscalPeriod(ctx, tx, periodID, true)
		if err != nil {
			return err
		}
		if per.ClosedBy == p.UserID {
			return fmt.Errorf("%w: the user who closed a period cannot reopen it", auth.ErrSoD)
		}
		if err := postgres.ReopenFiscalPeriod(ctx, tx, periodID, p.UserID, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "period.reopen", "fiscal_period", periodID, "period.reopened",
			map[string]any{"period_id": periodID, "name": per.Name, "reason": reason, "previously_closed_by": per.ClosedBy})
	})
}
