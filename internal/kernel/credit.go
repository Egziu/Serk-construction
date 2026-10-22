package kernel

// Customer credit notes (migration 0022, JB-CREDIT-NOTE): the only way to
// reduce what an approved customer invoice bills. The invoice and its
// AR_INVOICE journal are never edited or reversed.
//
//	AR clerk issues a DRAFT credit note against an APPROVED invoice (net
//	amount and reason only; the database takes everything else from the
//	invoice and computes the VAT) -> a commercial manager, a different
//	person with fresh MFA, approves it and its AR_CREDIT journal is generated
//	(Dr revenue on the project, Dr VAT output; Cr AR) -> finance approves and
//	a controller posts the journal. A draft may be cancelled with a reason.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// IssueCreditNote creates a DRAFT credit note of netAmount (before VAT)
// against an approved customer invoice.
func (s *Service) IssueCreditNote(ctx context.Context, p auth.Principal, invoiceID string, netAmount decimal.Decimal, creditDate time.Time, reason string) (string, error) {
	if err := requireReason(reason); err != nil {
		return "", err
	}
	if !netAmount.IsPositive() {
		return "", fmt.Errorf("%w: a credit note is a positive amount", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermARCreditCreate, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARCreditCreate, "customer_invoice", invoiceID)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "APPROVED"); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "CRN")
		if err != nil {
			return err
		}
		// The trigger overwrites every copied field from the invoice; they are
		// given here only to satisfy NOT NULL.
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO customer_credit_notes(legal_entity_id, project_id, contract_id, customer_id, invoice_id,
			policy_id, number, credit_date, currency, net_amount, reason, created_by)
			SELECT i.legal_entity_id, i.project_id, i.contract_id, i.customer_id, i.id, i.policy_id, $2, $3, i.currency, $4, $5, $6
			  FROM customer_invoices i WHERE i.id = $1::uuid RETURNING id::text`, invoiceID, num, creditDate, netAmount, strings.TrimSpace(reason), p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "ar.credit.create", "customer_credit_note", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.credit.create", "customer_credit_note", id, "ar.credit_issued",
			map[string]any{"credit_note_id": id, "invoice_id": invoiceID, "number": num, "net_amount": netAmount.String(), "reason": reason})
	})
	return id, err
}

// ApproveCreditNote approves a DRAFT credit note (a different person, fresh
// MFA) and generates its AR_CREDIT journal.
func (s *Service) ApproveCreditNote(ctx context.Context, p auth.Principal, id string) (string, error) {
	if err := s.authz.RequireStepUp(p); err != nil {
		return "", err
	}
	var jid string
	err := s.p2pTx(ctx, p, auth.PermARCreditApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARCreditApprove, "customer_credit_note", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "credit note"); err != nil {
			return err
		}
		var entity, ccy, num string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, number, credit_date FROM customer_credit_notes WHERE id = $1::uuid`, id).Scan(
			&entity, &ccy, &num, &date); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.credit.approve", "customer_credit_note", id, "APPROVED"); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "AR_CREDIT", id, entity, ccy, "Customer credit note "+num, date)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE customer_credit_notes SET status = 'APPROVED', approved_by = $2, journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.credit.approve", "customer_credit_note", id, "ar.credit_approved", map[string]any{"credit_note_id": id, "journal_id": jid})
	})
	return jid, err
}

// CancelCreditNote withdraws a DRAFT credit note with a reason (the issuer or
// an approver).
func (s *Service) CancelCreditNote(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	perm := auth.PermARCreditCreate
	if !s.authz.Has(p, perm) {
		perm = auth.PermARCreditApprove
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "customer_credit_note", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.credit.cancel", "customer_credit_note", id, "CANCELLED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE customer_credit_notes SET status = 'CANCELLED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.credit.cancel", "customer_credit_note", id, "ar.credit_cancelled", map[string]any{"credit_note_id": id, "reason": reason})
	})
}
