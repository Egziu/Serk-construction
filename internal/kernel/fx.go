package kernel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/money"
)

// FX commands (SC-02, SC-03, SC-07). Makers record; a different checker
// decides. Every command writes audit + outbox in its own transaction.

// ErrReasonRequired is returned when a decision lacks a justification.
var ErrReasonRequired = errors.New("kernel: a reason of at least 5 characters is required")

func requireReason(r string) error {
	if len(strings.TrimSpace(r)) < 5 {
		return ErrReasonRequired
	}
	return nil
}

// RegisterFXSource proposes a rate source (maker).
func (s *Service) RegisterFXSource(ctx context.Context, p auth.Principal, src postgres.FXSource) error {
	if err := s.authz.Require(p, auth.PermFXManage, p.TenantID); err != nil {
		return err
	}
	src.TenantID, src.CreatedBy = p.TenantID, p.UserID
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := postgres.InsertFXSource(ctx, tx, src); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "fx.source.register", "fx_source", src.SourceID, "fx.source.registered",
			map[string]any{"source_id": src.SourceID, "source_type": src.SourceType, "max_variance": src.MaxVariance.String()})
	})
}

// ApproveFXSource trusts a source (checker ≠ maker).
func (s *Service) ApproveFXSource(ctx context.Context, p auth.Principal, sourceID string) error {
	if err := s.authz.Require(p, auth.PermFXApprove, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		src, err := postgres.GetFXSource(ctx, tx, sourceID, true)
		if err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, src.CreatedBy, "FX source"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "fx.source.approve", "fx_source", sourceID, ""); err != nil {
			return err
		}
		if err := postgres.SetFXSourceStatus(ctx, tx, sourceID, "PENDING", "APPROVED", p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "fx.source.approve", "fx_source", sourceID, "fx.source.approved",
			map[string]any{"source_id": sourceID, "approved_by": p.UserID, "created_by": src.CreatedBy})
	})
}

// ProposeFXPolicy creates the next version of an entity's FX policy (maker).
func (s *Service) ProposeFXPolicy(ctx context.Context, p auth.Principal, legalEntityID, purpose string, pol fx.Policy) (postgres.FXPolicy, error) {
	if err := s.authz.Require(p, auth.PermFXManage, p.TenantID); err != nil {
		return postgres.FXPolicy{}, err
	}
	if err := pol.Validate(); err != nil {
		return postgres.FXPolicy{}, err
	}
	var out postgres.FXPolicy
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.InsertFXPolicy(ctx, tx, postgres.FXPolicy{TenantID: p.TenantID, LegalEntityID: legalEntityID, Purpose: purpose,
			Policy: pol, CreatedBy: p.UserID})
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "fx.policy.propose", "fx_policy", out.ID, "fx.policy.proposed",
			map[string]any{"policy_id": out.ID, "legal_entity_id": legalEntityID, "purpose": purpose, "version": out.Version,
				"rate_type": pol.RateType, "sources": pol.SourcePriority, "max_staleness_s": pol.MaxStaleness.Seconds(), "allow_inverse": pol.AllowInverse})
	})
	return out, err
}

// DecideFXPolicy approves or rejects a proposed policy (checker ≠ maker).
// Approval atomically retires the previously approved version.
func (s *Service) DecideFXPolicy(ctx context.Context, p auth.Principal, policyID string, approve bool, reason string) error {
	if err := s.authz.Require(p, auth.PermFXPolicyApprove, p.TenantID); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		pol, err := postgres.GetFXPolicy(ctx, tx, policyID, true)
		if err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, pol.CreatedBy, "FX policy"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "fx.policy.decide", "fx_policy", policyID, ""); err != nil {
			return err
		}
		if err := postgres.DecideFXPolicy(ctx, tx, pol, approve, p.UserID); err != nil {
			return err
		}
		action, ev := "fx.policy.reject", "fx.policy.rejected"
		if approve {
			action, ev = "fx.policy.approve", "fx.policy.approved"
		}
		return s.record(ctx, tx, p, action, "fx_policy", policyID, ev,
			map[string]any{"policy_id": policyID, "version": pol.Version, "decided_by": p.UserID, "reason": reason})
	})
}

// RecordFXSnapshot stores a new observation; it is always PENDING (maker).
func (s *Service) RecordFXSnapshot(ctx context.Context, p auth.Principal, snap fx.Snapshot) (string, error) {
	if err := s.authz.Require(p, auth.PermFXManage, p.TenantID); err != nil {
		return "", err
	}
	snap.TenantID = p.TenantID
	snap.CreatedBy = p.UserID
	var id string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertFXSnapshot(ctx, tx, snap)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "fx.snapshot.record", "fx_snapshot", id, "fx.snapshot.recorded", map[string]any{
			"snapshot_id": id, "source_id": snap.SourceID, "pair": string(snap.BaseCurrency) + "/" + string(snap.QuoteCurrency),
			"rate": snap.Rate.String(), "rate_type": snap.RateType, "effective_from_utc": snap.EffectiveFromUTC, "status": fx.StatusPending})
	})
	return id, err
}

// FXDecisionResult reports an approval outcome.
type FXDecisionResult struct {
	Deviation         *decimal.Decimal // |new/prev − 1| when a previous rate exists
	VarianceException bool
}

// ApproveFXSnapshot is the checker decision on a PENDING rate. The approver
// may not be the maker. A rate outside the source's variance tolerance
// requires fx.approve_exception and a recent MFA (step-up).
func (s *Service) ApproveFXSnapshot(ctx context.Context, p auth.Principal, id, reason string) (FXDecisionResult, error) {
	if err := s.authz.Require(p, auth.PermFXApprove, p.TenantID); err != nil {
		return FXDecisionResult{}, err
	}
	var res FXDecisionResult
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := refuseIfMandatory(ctx, tx, "fx_snapshot"); err != nil {
			return err
		}
		var err error
		res, err = s.approveFXSnapshotTx(ctx, tx, p, id, reason)
		return err
	})
	return res, err
}

func (s *Service) approveFXSnapshotTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id, reason string) (FXDecisionResult, error) {
	if err := s.authz.Require(p, auth.PermFXApprove, p.TenantID); err != nil {
		return FXDecisionResult{}, err
	}
	var res FXDecisionResult
	err := func() error {
		snap, err := postgres.GetFXSnapshot(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, snap.CreatedBy, "FX rate"); err != nil {
			return err
		}
		if snap.ApprovalStatus != fx.StatusPending {
			return fmt.Errorf("%w: snapshot is %s", fx.ErrSnapshotState, snap.ApprovalStatus)
		}
		src, err := postgres.GetFXSource(ctx, tx, snap.SourceID, false)
		if err != nil {
			return err
		}
		if src.Status != "APPROVED" {
			return fmt.Errorf("%w: source %s is %s", fx.ErrSnapshotState, src.SourceID, src.Status)
		}
		prev, ok, err := postgres.PreviousApprovedRate(ctx, tx, snap)
		if err != nil {
			return err
		}
		if ok {
			dev := snap.Rate.Div(prev).Sub(decimal.NewFromInt(1)).Abs().Round(6)
			res.Deviation = &dev
			if dev.GreaterThan(src.MaxVariance) {
				if err := s.authz.Require(p, auth.PermFXApproveExcept, p.TenantID); err != nil {
					return fmt.Errorf("rate deviates %s from the previous approved rate (tolerance %s): %w", dev, src.MaxVariance, err)
				}
				if err := s.authz.RequireStepUp(p); err != nil {
					return err
				}
				if err := requireReason(reason); err != nil {
					return fmt.Errorf("variance exception: %w", err)
				}
				res.VarianceException = true
			}
		}
		if err := s.authorize(ctx, tx, p, "fx.snapshot.approve", "fx_snapshot", id, ""); err != nil {
			return err
		}
		if err := postgres.DecideFXSnapshot(ctx, tx, id, postgres.FXDecision{From: fx.StatusPending, To: fx.StatusApproved, By: p.UserID,
			Reason: reason, VarianceException: res.VarianceException, ApproverMFA: res.VarianceException && p.MFA}); err != nil {
			return err
		}
		payload := map[string]any{"snapshot_id": id, "approved_by": p.UserID, "created_by": snap.CreatedBy, "variance_exception": res.VarianceException,
			"rate": snap.Rate.String(), "pair": string(snap.BaseCurrency) + "/" + string(snap.QuoteCurrency)}
		if res.Deviation != nil {
			payload["deviation"] = res.Deviation.String()
		}
		return s.record(ctx, tx, p, "fx.snapshot.approve", "fx_snapshot", id, "fx.snapshot.approved", payload)
	}()
	return res, err
}

// RejectFXSnapshot is the checker rejecting a PENDING rate.
func (s *Service) RejectFXSnapshot(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.decideNegative(ctx, p, id, reason, fx.StatusPending, fx.StatusRejected, "fx.snapshot.reject", "fx.snapshot.rejected")
}

// WithdrawFXSnapshot disputes an APPROVED rate that no line references yet.
func (s *Service) WithdrawFXSnapshot(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.decideNegative(ctx, p, id, reason, fx.StatusApproved, fx.StatusDisputed, "fx.snapshot.withdraw", "fx.snapshot.withdrawn")
}

func (s *Service) decideNegative(ctx context.Context, p auth.Principal, id, reason string, from, to fx.ApprovalStatus, action, event string) error {
	if err := s.authz.Require(p, auth.PermFXApprove, p.TenantID); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return s.decideNegativeTx(ctx, tx, p, id, reason, from, to, action, event)
	})
}

func (s *Service) decideNegativeTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id, reason string, from, to fx.ApprovalStatus, action, event string) error {
	if err := s.authz.Require(p, auth.PermFXApprove, p.TenantID); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	{
		snap, err := postgres.GetFXSnapshot(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if to == fx.StatusRejected {
			if err := auth.CheckMakerChecker(p, snap.CreatedBy, "FX rate"); err != nil {
				return err
			}
		}
		if snap.ApprovalStatus != from {
			return fmt.Errorf("%w: snapshot is %s", fx.ErrSnapshotState, snap.ApprovalStatus)
		}
		act := "fx.snapshot.reject"
		if to == fx.StatusDisputed {
			act = "fx.snapshot.withdraw"
		}
		if err := s.authorize(ctx, tx, p, act, "fx_snapshot", id, ""); err != nil {
			return err
		}
		if err := postgres.DecideFXSnapshot(ctx, tx, id, postgres.FXDecision{From: from, To: to, By: p.UserID, Reason: reason}); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "fx_snapshot", id, event, map[string]any{"snapshot_id": id, "by": p.UserID, "reason": reason})
	}
}

// ConvertRequest describes an FX conversion query.
type ConvertRequest struct {
	Amount money.Money
	Target money.Currency
	// EventAt is the business event time. Required.
	EventAt time.Time
	// LegalEntityID selects the entity's approved policy. When set, the
	// result is exactly what a journal line for that entity must use.
	LegalEntityID string
	Purpose       string
	// Policy is used only when LegalEntityID is empty (advisory what-if).
	Policy          fx.Policy
	KnowledgeCutoff time.Time
	Rounding        money.RoundingPolicy
}

// ConvertResult is a conversion with its policy binding.
type ConvertResult struct {
	fx.Conversion
	PolicyID      string
	PolicyVersion int
	Binding       bool // true when produced under the entity's approved policy
}

// Convert selects a rate and converts. Read-only.
func (s *Service) Convert(ctx context.Context, p auth.Principal, req ConvertRequest) (ConvertResult, error) {
	if err := s.authz.Require(p, auth.PermFXRead, p.TenantID); err != nil {
		return ConvertResult{}, err
	}
	if req.EventAt.IsZero() {
		return ConvertResult{}, fmt.Errorf("%w: business_event_at is required", fx.ErrPolicyInvalid)
	}
	if req.Purpose == "" {
		req.Purpose = postgres.PurposeTransaction
	}
	var out ConvertResult
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var sel fx.Selection
		if req.LegalEntityID != "" {
			var pol postgres.FXPolicy
			var err error
			sel, pol, err = postgres.SelectFXForEntity(ctx, tx, req.LegalEntityID, req.Purpose, req.Amount.Currency(), req.Target, req.EventAt)
			if err != nil {
				return err
			}
			out.PolicyID, out.PolicyVersion, out.Binding = pol.ID, pol.Version, true
			req.Rounding = money.RoundHalfEven // the journal write path reconciles with HALF_EVEN
		} else {
			cands, err := postgres.ListEligibleFXSnapshots(ctx, tx, req.Amount.Currency(), req.Target, req.EventAt)
			if err != nil {
				return err
			}
			if req.KnowledgeCutoff.IsZero() {
				if req.KnowledgeCutoff, err = postgres.DBNow(ctx, tx); err != nil {
					return err
				}
			}
			if sel, err = fx.Select(cands, req.Amount.Currency(), req.Target, req.EventAt, req.KnowledgeCutoff, req.Policy); err != nil {
				return err
			}
		}
		conv, err := fx.Convert(req.Amount, req.Target, sel, req.Rounding)
		out.Conversion = conv
		return err
	})
	return out, err
}
