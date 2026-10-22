package kernel

// Contract variations / change orders (migration 0026, GATEB-06). A
// commercial manager records the client's variation order (reference and
// SHA-256 of the signed instruction) with new priced lines and quantity
// changes, and submits it; the CFO approves it with fresh MFA (a different
// person, a human). Approval adds the new lines to the contract; quantity
// changes raise or lower each line's effective quantity, which caps
// measurement. The database prices every line.

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// VariationLine is one line of a variation: NEW adds a contract line (with
// its rate); CHANGE adds QtyDelta (negative for an omission) to an existing
// line, at the contract rate.
type VariationLine struct {
	LineNo      int             `json:"line_no"`
	Kind        string          `json:"kind"`
	BOQItemID   string          `json:"boq_item_id,omitempty"`
	Description string          `json:"description"`
	Unit        string          `json:"unit"`
	QtyDelta    decimal.Decimal `json:"qty_delta"`
	Rate        decimal.Decimal `json:"rate"`
}

// VariationInput is a variation order on an active contract.
type VariationInput struct {
	Title                   string          `json:"title"`
	Reason                  string          `json:"reason"`
	ClientInstructionRef    string          `json:"client_instruction_ref"`
	ClientInstructionSHA256 string          `json:"client_instruction_sha256"`
	Lines                   []VariationLine `json:"lines"`
}

// CreateVariation records a DRAFT variation with its lines.
func (s *Service) CreateVariation(ctx context.Context, p auth.Principal, contractID string, in VariationInput) (string, error) {
	in.ClientInstructionSHA256 = strings.ToLower(strings.TrimSpace(in.ClientInstructionSHA256))
	if b, err := hex.DecodeString(in.ClientInstructionSHA256); err != nil || len(b) != 32 || len(strings.TrimSpace(in.ClientInstructionRef)) < 3 {
		return "", fmt.Errorf("%w: a variation records the client's instruction reference and the SHA-256 of the signed instruction", ErrInvalidInput)
	}
	if len(in.Lines) == 0 {
		return "", fmt.Errorf("%w: a variation has at least one line", ErrInvalidInput)
	}
	for _, l := range in.Lines {
		if l.Kind != "NEW" && l.Kind != "CHANGE" {
			return "", fmt.Errorf("%w: variation line %d: kind is NEW or CHANGE", ErrInvalidInput, l.LineNo)
		}
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermContractManage, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermContractManage, "contract", contractID)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "ACTIVE"); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "VO")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO contract_variations(contract_id, number, title, reason, client_instruction_ref,
			client_instruction_sha256, created_by) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
			contractID, num, strings.TrimSpace(in.Title), strings.TrimSpace(in.Reason), strings.TrimSpace(in.ClientInstructionRef), in.ClientInstructionSHA256, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, l := range in.Lines {
			var boq *string
			if l.BOQItemID != "" {
				boq = &l.BOQItemID
			}
			// For CHANGE lines the database takes rate, unit and BOQ link
			// from the contract line; placeholders satisfy NOT NULL.
			unit, desc := l.Unit, l.Description
			if l.Kind == "CHANGE" && unit == "" {
				unit = "x"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO variation_lines(variation_id, line_no, kind, boq_item_id, description, unit, qty_delta, rate)
				VALUES ($1::uuid, $2, $3, $4::uuid, $5, $6, $7, $8)`, id, l.LineNo, l.Kind, boq, desc, unit, l.QtyDelta, l.Rate); err != nil {
				return err
			}
		}
		if err := s.authorize(ctx, tx, p, "contract.variation.create", "contract_variation", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "contract.variation.create", "contract_variation", id, "contract.variation_recorded",
			map[string]any{"variation_id": id, "contract_id": contractID, "number": num, "client_instruction_ref": in.ClientInstructionRef})
	})
	return id, err
}

// SubmitVariation submits the author's DRAFT variation for approval.
func (s *Service) SubmitVariation(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermContractManage, "contract_variation", "contract_variations", id, "contract.variation.submit", "contract.variation_submitted")
}

// DecideVariation approves (fresh MFA; the new lines join the contract) or
// rejects (with a reason) a submitted variation.
func (s *Service) DecideVariation(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if approve {
		if err := s.authz.RequireStepUp(p); err != nil {
			return err
		}
	} else if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermContractApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermContractApprove, "contract_variation", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "variation"); err != nil {
			return err
		}
		action, next := "contract.variation.approve", "APPROVED"
		if !approve {
			action, next = "contract.variation.reject", "REJECTED"
		}
		if err := s.authorize(ctx, tx, p, action, "contract_variation", id, next); err != nil {
			return err
		}
		if !approve {
			if err := postgres.Exec1(ctx, tx, `UPDATE contract_variations SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
				return err
			}
			return s.record(ctx, tx, p, action, "contract_variation", id, "contract.variation_rejected", map[string]any{"variation_id": id, "reason": reason})
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE contract_variations SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		// The new lines join the contract exactly as approved.
		if _, err := tx.Exec(ctx, `INSERT INTO contract_lines(contract_id, line_no, boq_item_id, description, unit, quantity, rate)
			SELECT v.contract_id, l.line_no, l.boq_item_id, l.description, l.unit, l.qty_delta, l.rate
			  FROM variation_lines l JOIN contract_variations v ON v.id = l.variation_id
			 WHERE v.id = $1::uuid AND l.kind = 'NEW' ORDER BY l.line_no`, id); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "contract_variation", id, "contract.variation_approved", map[string]any{"variation_id": id})
	})
}

// CancelVariation withdraws a DRAFT or SUBMITTED variation (commercial staff), with a reason.
func (s *Service) CancelVariation(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermContractManage, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermContractManage, "contract_variation", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT", "SUBMITTED"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "contract.variation.cancel", "contract_variation", id, "CANCELLED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE contract_variations SET status = 'CANCELLED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "contract.variation.cancel", "contract_variation", id, "contract.variation_cancelled", map[string]any{"variation_id": id, "reason": reason})
	})
}
