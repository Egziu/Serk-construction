package kernel

// Retention release (migration 0023). Retention deducted on certificates is
// held in retention receivable until the client certifies its release:
//
//	AR clerk records a DRAFT release on an ACTIVE contract with the client's
//	release certificate (reference + SHA-256 of the signed file) -> a
//	commercial manager approves it (different person, human, fresh MFA) ->
//	AR_RETENTION journal (Dr AR / Cr retention receivable) -> the customer
//	pays it through a receipt allocated to the release.

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// RetentionReleaseInput is what the AR clerk records; every other figure is
// taken from the contract by the database.
type RetentionReleaseInput struct {
	Amount            decimal.Decimal
	ReleaseDate       time.Time
	Milestone         string // TAKING_OVER, DEFECTS_LIABILITY_END or NEGOTIATED
	CertificateRef    string
	CertificateSHA256 string
}

// RecordRetentionRelease records a DRAFT retention release on a contract.
func (s *Service) RecordRetentionRelease(ctx context.Context, p auth.Principal, contractID string, in RetentionReleaseInput) (string, error) {
	in.CertificateSHA256 = strings.ToLower(strings.TrimSpace(in.CertificateSHA256))
	if b, err := hex.DecodeString(in.CertificateSHA256); err != nil || len(b) != 32 || len(strings.TrimSpace(in.CertificateRef)) < 3 {
		return "", fmt.Errorf("%w: a retention release records the client's release certificate reference and the SHA-256 of the signed certificate", ErrInvalidInput)
	}
	switch in.Milestone {
	case "TAKING_OVER", "DEFECTS_LIABILITY_END", "NEGOTIATED":
	default:
		return "", fmt.Errorf("%w: milestone is TAKING_OVER, DEFECTS_LIABILITY_END or NEGOTIATED", ErrInvalidInput)
	}
	if !in.Amount.IsPositive() {
		return "", fmt.Errorf("%w: a retention release is a positive amount", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermARRetentionCreate, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARRetentionCreate, "contract", contractID)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "ACTIVE"); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "RTR")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO retention_releases(legal_entity_id, project_id, contract_id, customer_id, policy_id, number,
			release_date, currency, amount, milestone, certificate_ref, certificate_sha256, created_by)
			SELECT c.legal_entity_id, c.project_id, c.id, c.customer_id, c.policy_id, $2, $3, c.currency, $4, $5, $6, $7, $8
			  FROM contracts c WHERE c.id = $1::uuid RETURNING id::text`,
			contractID, num, in.ReleaseDate, in.Amount, in.Milestone, strings.TrimSpace(in.CertificateRef), in.CertificateSHA256, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "ar.retention.create", "retention_release", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.retention.create", "retention_release", id, "ar.retention_release_recorded",
			map[string]any{"retention_release_id": id, "contract_id": contractID, "number": num, "amount": in.Amount.String(), "milestone": in.Milestone,
				"certificate_ref": in.CertificateRef})
	})
	return id, err
}

// ApproveRetentionRelease approves a DRAFT release (different person, fresh
// MFA) and generates its AR_RETENTION journal.
func (s *Service) ApproveRetentionRelease(ctx context.Context, p auth.Principal, id string) (string, error) {
	if err := s.authz.RequireStepUp(p); err != nil {
		return "", err
	}
	var jid string
	err := s.p2pTx(ctx, p, auth.PermARRetentionApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARRetentionApprove, "retention_release", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "retention release"); err != nil {
			return err
		}
		var entity, ccy, num string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, number, release_date FROM retention_releases WHERE id = $1::uuid`, id).Scan(
			&entity, &ccy, &num, &date); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.retention.approve", "retention_release", id, "APPROVED"); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "AR_RETENTION", id, entity, ccy, "Retention release "+num, date)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE retention_releases SET status = 'APPROVED', approved_by = $2, journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.retention.approve", "retention_release", id, "ar.retention_release_approved",
			map[string]any{"retention_release_id": id, "journal_id": jid})
	})
	return jid, err
}

// CancelRetentionRelease withdraws a DRAFT release with a reason.
func (s *Service) CancelRetentionRelease(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	perm := auth.PermARRetentionCreate
	if !s.authz.Has(p, perm) {
		perm = auth.PermARRetentionApprove
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "retention_release", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.retention.cancel", "retention_release", id, "CANCELLED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE retention_releases SET status = 'CANCELLED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.retention.cancel", "retention_release", id, "ar.retention_release_cancelled",
			map[string]any{"retention_release_id": id, "reason": reason})
	})
}
