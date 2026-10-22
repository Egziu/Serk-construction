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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

// Service executes kernel commands.
type Service struct {
	store  postgres.TenantDB
	authz  *auth.Authorizer
	now    func() time.Time
	signer *attest.Signer
}

// UseApprovalSigner configures the approval attestation signer. Without it
// every sensitive transition fails closed (the database requires a verified
// attestation for each).
func (s *Service) UseApprovalSigner(signer attest.Signer) *Service {
	s.signer = &signer
	return s
}

// ErrApprovalSigning: no signer configured, or the subject vanished.
var ErrApprovalSigning = errors.New("kernel: approval attestation unavailable")

// authorize issues a signed, single-use attestation that p — whose token,
// permissions, scope and MFA the caller has already verified — authorises
// action on the subject in its current content, and has PostgreSQL verify
// and record it in this transaction. Sensitive database transitions are
// refused without it (GATEA-APPROVAL-01).
func (s *Service) authorize(ctx context.Context, tx pgx.Tx, p auth.Principal, action, subjectType, subjectID, actx string) error {
	if s.signer == nil {
		return fmt.Errorf("%w: no signer configured", ErrApprovalSigning)
	}
	// Decisions are made by people. AI and service principals may prepare
	// and submit drafts only (governed AI; enforced again in SQL by 0019).
	if p.Kind != auth.KindHuman && !auth.IsDraftAction(action) {
		return fmt.Errorf("%w: %s is a decision reserved to human principals (the identity provider did not assert this principal is human); AI and service principals may only prepare drafts", auth.ErrForbidden, action)
	}
	// A revoked session signs nothing, even if the request passed the API
	// middleware before the revocation committed.
	if err := checkSessionTx(ctx, tx, p); err != nil {
		return err
	}
	hash, err := postgres.SubjectHash(ctx, tx, subjectType, subjectID)
	if err != nil {
		return err
	}
	if hash == "" {
		return ErrNotFound
	}
	perms := make([]string, 0, 8)
	for _, perm := range s.authz.Permissions(p) {
		perms = append(perms, string(perm))
	}
	// Platform-derived marker (never grantable by a role): the identity
	// provider asserted this principal is a person. The database requires it
	// for payment approval and release (0014, review 3 M2).
	if p.Kind == auth.KindHuman {
		perms = append(perms, auth.ReservedPermissionPrefix+"human")
	}
	var authTime int64
	if !p.AuthTime.IsZero() {
		authTime = p.AuthTime.Unix()
	}
	a, err := s.signer.Sign(attest.Claims{Tenant: p.TenantID, Actor: p.UserID, Action: action, SubjectType: subjectType,
		SubjectID: subjectID, SubjectHash: hash, Context: actx, Perms: perms, MFA: p.MFA && authTime > 0, AuthTime: authTime})
	if err != nil {
		return err
	}
	return postgres.Authorize(ctx, tx, a.JSON())
}

// New builds a Service.
func New(store postgres.TenantDB, authz *auth.Authorizer) *Service {
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
		payload := map[string]any{"journal_id": id, "project_id": j.ProjectID, "lines": len(j.Lines), "debits": d, "credits": c, "idempotency_key": j.IdempotencyKey}
		return s.record(ctx, tx, p, "journal.create", "journal", id, "journal.created", payload)
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
		if s.authz.RequireProject(p, auth.PermJournalRead, rec.TenantID, rec.ProjectID) != nil {
			return ErrNotFound // out of scope looks like absence (review 5, F5)
		}
		return nil
	})
	return rec, err
}

// ApproveJournal moves DRAFT -> APPROVED enforcing SoD. When a mandatory
// journal workflow is published the direct path is refused; approval then
// happens only as the effect of a workflow step.
func (s *Service) ApproveJournal(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalApprove, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := refuseIfMandatory(ctx, tx, "journal"); err != nil {
			return err
		}
		return s.approveJournalTx(ctx, tx, p, id)
	})
}

func (s *Service) approveJournalTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalApprove, p.TenantID); err != nil {
		return err
	}
	rec, err := postgres.GetJournal(ctx, tx, id, true)
	if err != nil {
		return err
	}
	if err := s.authz.RequireProject(p, auth.PermJournalApprove, rec.TenantID, rec.ProjectID); err != nil {
		return ErrNotFound // permission was checked first; this is scope (review 5, F5)
	}
	if !ledger.CanTransition(rec.Status, ledger.StatusApproved) {
		return fmt.Errorf("%w: %s -> APPROVED", ledger.ErrBadTransition, rec.Status)
	}
	if err := s.authz.CheckSoDApprove(p, auth.JournalActors{CreatedBy: rec.CreatedBy}); err != nil {
		return err
	}
	// The approver approves the journal as it was created: lines added since
	// the command was accepted are refused (the attestation then binds this
	// exact content in the database).
	if postgres.CommandHash(rec.Journal) != rec.CommandHash {
		return fmt.Errorf("%w: journal content changed after creation", ledger.ErrBadTransition)
	}

	if err := s.authorize(ctx, tx, p, "journal.approve", "journal", id, ""); err != nil {
		return err
	}
	if err := postgres.ApproveJournal(ctx, tx, id, p.UserID, rec.Version); err != nil {
		return err
	}
	payload := map[string]any{"journal_id": id, "project_id": rec.ProjectID, "approved_by": p.UserID, "created_by": rec.CreatedBy}
	return s.record(ctx, tx, p, "journal.approve", "journal", id, "journal.approved", payload)
}

// PostJournal moves APPROVED -> POSTED enforcing SoD and the balance
// invariant (checked in Go, then again by the database at commit).
func (s *Service) PostJournal(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalPost, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := refuseIfMandatory(ctx, tx, "journal"); err != nil {
			return err
		}
		return s.postJournalTx(ctx, tx, p, id)
	})
}

func (s *Service) postJournalTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id string) error {
	if err := s.authz.Require(p, auth.PermJournalPost, p.TenantID); err != nil {
		return err
	}
	rec, err := postgres.GetJournal(ctx, tx, id, true)
	if err != nil {
		return err
	}
	if err := s.authz.RequireProject(p, auth.PermJournalPost, rec.TenantID, rec.ProjectID); err != nil {
		return ErrNotFound // permission was checked first; this is scope (review 5, F5)
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
	if err := s.authorize(ctx, tx, p, "journal.post", "journal", id, ""); err != nil {
		return err
	}
	if err := postgres.PostJournal(ctx, tx, id, p.UserID, rec.Version); err != nil {
		return err
	}
	d, c, _ := rec.Journal.Totals()
	payload := map[string]any{"journal_id": id, "project_id": rec.ProjectID, "posted_by": p.UserID, "business_event_at": rec.BusinessEventAt,
		"debits": d, "credits": c, "reversal_of": rec.ReversalOf}
	return s.record(ctx, tx, p, "journal.post", "journal", id, "journal.posted", payload)
}

// cancelJournalTx cancels a DRAFT or APPROVED journal. It is the
// compensation a rejected journal workflow may run; it never moves value.
// Either journal.approve or journal.post suffices: both finance checkers may
// stop a journal they decline to approve or post.
func (s *Service) cancelJournalTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id, reason string) error {
	perm := auth.PermJournalApprove
	if !s.authz.Has(p, perm) {
		perm = auth.PermJournalPost
	}
	if err := s.authz.Require(p, perm, p.TenantID); err != nil {
		return err
	}
	rec, err := postgres.GetJournal(ctx, tx, id, true)
	if err != nil {
		return err
	}
	if err := s.authz.RequireProject(p, perm, rec.TenantID, rec.ProjectID); err != nil {
		return err
	}
	if !ledger.CanTransition(rec.Status, ledger.StatusCancelled) {
		return fmt.Errorf("%w: %s -> CANCELLED", ledger.ErrBadTransition, rec.Status)
	}
	if err := s.authorize(ctx, tx, p, "journal.cancel", "journal", id, ""); err != nil {
		return err
	}
	if err := postgres.CancelJournal(ctx, tx, id, rec.Version); err != nil {
		return err
	}
	return s.record(ctx, tx, p, "journal.cancel", "journal", id, "journal.cancelled",
		map[string]any{"journal_id": id, "project_id": rec.ProjectID, "cancelled_by": p.UserID, "reason": reason, "previous_status": rec.Status})
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
		// Subledger journals are corrected at their document, never reversed:
		// a reversal would leave the document and the ledger disagreeing
		// (review 6, R6-F4; also refused in SQL by 0020).
		if st := string(orig.SourceType); strings.HasPrefix(st, "P2P_") || strings.HasPrefix(st, "AR_") || strings.HasPrefix(st, "STK_") {
			return fmt.Errorf("%w: %s journals are not reversed; correct the source document instead", ErrInvalidInput, st)
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
		payload := map[string]any{"journal_id": id, "project_id": orig.ProjectID, "reversal_of": originalID, "reason": reason}
		return s.record(ctx, tx, p, "journal.reverse", "journal", id, "journal.reversal_created", payload)
	})
	return res, err
}

// IsAuthError reports whether err is an authorization failure.
func IsAuthError(err error) bool {
	return errors.Is(err, auth.ErrForbidden) || errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrTenantMismatch) ||
		errors.Is(err, auth.ErrSoD) || errors.Is(err, auth.ErrStepUpRequired)
}

// record writes the audit entry and the outbox event of a command in the
// caller's transaction. Every state-changing command uses it, so audit and
// integration events can never diverge (SC-07).
func (s *Service) record(ctx context.Context, tx pgx.Tx, p auth.Principal, action, aggType, aggID, eventType string, payload map[string]any) error {
	if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: action,
		AggregateType: aggType, AggregateID: aggID, RequestID: requestID(ctx), Payload: payload}); err != nil {
		return err
	}
	return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: aggType, AggregateID: aggID,
		EventType: eventType, SchemaVersion: 1, Payload: payload})
}
