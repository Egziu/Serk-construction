// Package kernel is the application service layer of the financial kernel.
// Every public method is a deterministic domain command (LAW 02): it
// authorises the principal, validates the domain object, commits an ACID
// transaction, and writes the audit record and outbox event inside that same
// transaction.
package kernel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// Service executes kernel commands.
type Service struct {
	store *postgres.Store
	authz *auth.Authorizer
	now   func() time.Time
}

// New builds a Service.
func New(store *postgres.Store, authz *auth.Authorizer) *Service {
	return &Service{store: store, authz: authz, now: func() time.Time { return time.Now().UTC() }}
}

// RequestID is carried in context for audit correlation.
type ctxKey int

const requestIDKey ctxKey = 1

// WithRequestID annotates a context with a request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func requestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// ErrNotFound is returned for journals outside the principal's tenant too, so
// existence is never leaked across tenants.
var ErrNotFound = postgres.ErrNotFound

// CreateJournalResult reports the outcome of a create command.
type CreateJournalResult struct {
	JournalID string
	Replayed  bool
}

// CreateJournal validates and stores a DRAFT journal under the principal's tenant.
func (s *Service) CreateJournal(ctx context.Context, p auth.Principal, j ledger.Journal) (CreateJournalResult, error) {
	j.TenantID = p.TenantID // the tenant is always the caller's; never trusted from the payload
	j.CreatedBy = p.UserID
	if err := s.authz.RequireProject(p, auth.PermJournalCreate, j.TenantID, j.ProjectID); err != nil {
		return CreateJournalResult{}, err
	}
	if err := j.Validate(); err != nil {
		return CreateJournalResult{}, err
	}
	var res CreateJournalResult
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		id, replayed, err := postgres.CreateJournal(ctx, tx, j)
		if err != nil {
			return err
		}
		res = CreateJournalResult{JournalID: id, Replayed: replayed}
		if replayed {
			return nil // nothing changed; no audit/outbox for an idempotent replay
		}
		d, c, _ := j.Totals()
		payload := map[string]any{"journal_id": id, "lines": len(j.Lines), "debits": d, "credits": c, "idempotency_key": j.IdempotencyKey}
		if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "journal.create",
			AggregateType: "journal", AggregateID: id, RequestID: requestID(ctx), Payload: payload}); err != nil {
			return err
		}
		return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "journal", AggregateID: id, EventType: "journal.created", Payload: payload})
	})
	return res, err
}

// GetJournal returns a journal visible to the principal.
func (s *Service) GetJournal(ctx context.Context, p auth.Principal, id string) (postgres.JournalRecord, error) {
	if err := s.authz.Require(p, auth.PermJournalRead, p.TenantID); err != nil {
		return postgres.JournalRecord{}, err
	}
	var rec postgres.JournalRecord
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		rec, err = postgres.GetJournal(ctx, tx, id, false)
		if err != nil {
			return err
		}
		return s.authz.RequireProject(p, auth.PermJournalRead, rec.TenantID, rec.ProjectID)
	})
	return rec, err
}

// ApproveJournal moves DRAFT -> APPROVED enforcing SoD.
func (s *Service) ApproveJournal(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalApprove, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rec, err := postgres.GetJournal(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := s.authz.RequireProject(p, auth.PermJournalApprove, rec.TenantID, rec.ProjectID); err != nil {
			return err
		}
		if !ledger.CanTransition(rec.Status, ledger.StatusApproved) {
			return fmt.Errorf("%w: %s -> APPROVED", ledger.ErrBadTransition, rec.Status)
		}
		if err := s.authz.CheckSoDApprove(p, auth.JournalActors{CreatedBy: rec.CreatedBy}); err != nil {
			return err
		}
		if err := postgres.ApproveJournal(ctx, tx, id, p.UserID, rec.Version); err != nil {
			return err
		}
		payload := map[string]any{"journal_id": id, "approved_by": p.UserID, "created_by": rec.CreatedBy}
		if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "journal.approve",
			AggregateType: "journal", AggregateID: id, RequestID: requestID(ctx), Payload: payload}); err != nil {
			return err
		}
		return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "journal", AggregateID: id, EventType: "journal.approved", Payload: payload})
	})
}

// PostJournal moves APPROVED -> POSTED enforcing SoD and the balance
// invariant (checked in Go, then again by the database at commit).
func (s *Service) PostJournal(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalPost, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rec, err := postgres.GetJournal(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if err := s.authz.RequireProject(p, auth.PermJournalPost, rec.TenantID, rec.ProjectID); err != nil {
			return err
		}
		if !ledger.CanTransition(rec.Status, ledger.StatusPosted) {
			return fmt.Errorf("%w: %s -> POSTED", ledger.ErrBadTransition, rec.Status)
		}
		if err := s.authz.CheckSoDPost(p, auth.JournalActors{CreatedBy: rec.CreatedBy, ApprovedBy: rec.ApprovedBy}); err != nil {
			return err
		}
		if err := rec.Journal.Validate(); err != nil { // re-validate stored lines before posting
			return err
		}
		// What the approver saw must be what posts: the stored command hash
		// is recomputed from the stored lines (the DB also freezes them).
		if postgres.CommandHash(rec.Journal) != rec.CommandHash {
			return fmt.Errorf("%w: journal content changed after creation", ledger.ErrBadTransition)
		}
		if err := postgres.PostJournal(ctx, tx, id, p.UserID, rec.Version); err != nil {
			return err
		}
		d, c, _ := rec.Journal.Totals()
		payload := map[string]any{"journal_id": id, "posted_by": p.UserID, "business_event_at": rec.BusinessEventAt,
			"debits": d, "credits": c, "reversal_of": rec.ReversalOf}
		if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "journal.post",
			AggregateType: "journal", AggregateID: id, RequestID: requestID(ctx), Payload: payload}); err != nil {
			return err
		}
		return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "journal", AggregateID: id, EventType: "journal.posted", Payload: payload})
	})
}

// ReverseJournal creates the DRAFT compensating journal for a POSTED journal.
// It then follows the normal approve/post path, which marks the original
// REVERSED atomically when the reversal posts.
func (s *Service) ReverseJournal(ctx context.Context, p auth.Principal, originalID, idempotencyKey, reason string, eventAt time.Time) (CreateJournalResult, error) {
	if err := s.authz.Require(p, auth.PermJournalReverse, p.TenantID); err != nil {
		return CreateJournalResult{}, err
	}
	var res CreateJournalResult
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		orig, err := postgres.GetJournal(ctx, tx, originalID, true)
		if err != nil {
			return err
		}
		if err := s.authz.RequireProject(p, auth.PermJournalReverse, orig.TenantID, orig.ProjectID); err != nil {
			return err
		}
		if eventAt.IsZero() {
			// A server-chosen default would make identical retries hash
			// differently and defeat idempotency; the client states the date.
			return fmt.Errorf("%w: reversal business_event_at is required", ledger.ErrBadLine)
		}
		rev, err := orig.Journal.Reversal("", idempotencyKey, p.UserID, eventAt.UTC(), reason)
		if err != nil {
			return err
		}
		id, replayed, err := postgres.CreateJournal(ctx, tx, rev)
		if err != nil {
			return err
		}
		res = CreateJournalResult{JournalID: id, Replayed: replayed}
		if replayed {
			return nil
		}
		payload := map[string]any{"journal_id": id, "reversal_of": originalID, "reason": reason}
		if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "journal.reverse",
			AggregateType: "journal", AggregateID: id, RequestID: requestID(ctx), Payload: payload}); err != nil {
			return err
		}
		return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "journal", AggregateID: id, EventType: "journal.reversal_created", Payload: payload})
	})
	return res, err
}

// ConvertRequest describes an FX conversion query.
type ConvertRequest struct {
	Amount          money.Money
	Target          money.Currency
	EventAt         time.Time
	KnowledgeCutoff time.Time
	Policy          fx.Policy
	Rounding        money.RoundingPolicy
}

// Convert selects the authoritative snapshot and converts. Read-only; the
// result is advisory until bound to a posted journal line.
func (s *Service) Convert(ctx context.Context, p auth.Principal, req ConvertRequest) (fx.Conversion, error) {
	if err := s.authz.Require(p, auth.PermFXRead, p.TenantID); err != nil {
		return fx.Conversion{}, err
	}
	if req.EventAt.IsZero() {
		req.EventAt = s.now()
	}
	var conv fx.Conversion
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		cands, err := postgres.ListFXSnapshots(ctx, tx, req.Amount.Currency(), req.Target, req.EventAt)
		if err != nil {
			return err
		}
		sel, err := fx.Select(cands, req.Amount.Currency(), req.Target, req.EventAt, req.KnowledgeCutoff, req.Policy)
		if err != nil {
			return err
		}
		conv, err = fx.Convert(req.Amount, req.Target, sel, req.Rounding)
		return err
	})
	return conv, err
}

// RecordFXSnapshot stores a new observation (PENDING unless the principal
// may manage FX and asks for immediate approval).
func (s *Service) RecordFXSnapshot(ctx context.Context, p auth.Principal, snap fx.Snapshot, approve bool) (string, error) {
	if err := s.authz.Require(p, auth.PermFXManage, p.TenantID); err != nil {
		return "", err
	}
	snap.TenantID = p.TenantID
	snap.CreatedBy = p.UserID
	if approve {
		snap.ApprovalStatus = fx.StatusApproved
	} else {
		snap.ApprovalStatus = fx.StatusPending
	}
	var id string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertFXSnapshot(ctx, tx, snap)
		if err != nil {
			return err
		}
		payload := map[string]any{"snapshot_id": id, "pair": string(snap.BaseCurrency) + "/" + string(snap.QuoteCurrency), "rate": snap.Rate.String(), "status": snap.ApprovalStatus}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "fx.snapshot.record",
			AggregateType: "fx_snapshot", AggregateID: id, RequestID: requestID(ctx), Payload: payload})
	})
	return id, err
}

// IsAuthError reports whether err is an authorization failure.
func IsAuthError(err error) bool {
	return errors.Is(err, auth.ErrForbidden) || errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrTenantMismatch) || errors.Is(err, auth.ErrSoD)
}
