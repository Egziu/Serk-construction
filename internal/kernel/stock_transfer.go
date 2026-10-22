package kernel

// Stock transfers between warehouses (migration 0025, JC-TRANSFER): the
// storekeeper requests, an inventory controller (different person, human)
// approves, and the database moves quantity and cost from one warehouse to
// the other (FIFO layers keep their cost and order). No journal: the item's
// inventory account is the same on both sides.

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

// StockTransferInput moves a quantity of one item between two warehouses.
type StockTransferInput struct {
	StockItemID     string          `json:"stock_item_id"`
	FromWarehouseID string          `json:"from_warehouse_id"`
	ToWarehouseID   string          `json:"to_warehouse_id"`
	Quantity        decimal.Decimal `json:"quantity"`
	TransferDate    time.Time       `json:"-"`
	Note            string          `json:"note,omitempty"`
}

// CreateStockTransfer records a DRAFT transfer. The requester must see both
// warehouses.
func (s *Service) CreateStockTransfer(ctx context.Context, p auth.Principal, in StockTransferInput) (string, error) {
	if err := stockDate(in.TransferDate); err != nil {
		return "", err
	}
	if !in.Quantity.IsPositive() || in.FromWarehouseID == in.ToWarehouseID {
		return "", fmt.Errorf("%w: a transfer moves a positive quantity between two different warehouses", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermStockTransfer, func(ctx context.Context, tx pgx.Tx) error {
		for _, w := range []string{in.FromWarehouseID, in.ToWarehouseID} {
			if _, err := s.visibleDoc(ctx, tx, p, "warehouse", w, false); err != nil {
				return err
			}
		}
		num, err := postgres.NextNumber(ctx, tx, "STR")
		if err != nil {
			return err
		}
		var note *string
		if strings.TrimSpace(in.Note) != "" {
			note = &in.Note
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO stock_transfers(legal_entity_id, number, stock_item_id, from_warehouse_id, to_warehouse_id,
			quantity, transfer_date, note, currency, created_by)
			SELECT w.legal_entity_id, $1, $3::uuid, w.id, $4::uuid, $5, $6, $7, le.functional_currency, $8
			  FROM warehouses w JOIN legal_entities le ON le.id = w.legal_entity_id WHERE w.id = $2::uuid RETURNING id::text`,
			num, in.FromWarehouseID, in.StockItemID, in.ToWarehouseID, in.Quantity, in.TransferDate, note, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "stock.transfer.create", "stock_transfer", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.transfer.create", "stock_transfer", id, "stock.transfer_requested", map[string]any{"stock_transfer_id": id, "number": num})
	})
	return id, err
}

// ApproveStockTransfer approves a DRAFT transfer; the database moves the stock at cost.
func (s *Service) ApproveStockTransfer(ctx context.Context, p auth.Principal, id string) error {
	return s.p2pTx(ctx, p, auth.PermStockTransferApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermStockTransferApprove, "stock_transfer", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "stock transfer"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.transfer.approve", "stock_transfer", id, "APPROVED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_transfers SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.transfer.approve", "stock_transfer", id, "stock.transferred", map[string]any{"stock_transfer_id": id})
	})
}

// RejectStockTransfer (approver) or CancelStockTransfer (preparer) closes a DRAFT transfer.
func (s *Service) RejectStockTransfer(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.closeStockTransfer(ctx, p, auth.PermStockTransferApprove, id, "REJECTED", "stock.transfer.reject", reason)
}

// CancelStockTransfer withdraws the preparer's own DRAFT transfer.
func (s *Service) CancelStockTransfer(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.closeStockTransfer(ctx, p, auth.PermStockTransfer, id, "CANCELLED", "stock.transfer.cancel", reason)
}

func (s *Service) closeStockTransfer(ctx context.Context, p auth.Principal, perm auth.Permission, id, next, action, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "stock_transfer", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if next == "CANCELLED" && d.CreatedBy != p.UserID {
			return fmt.Errorf("%w: only the preparer cancels a transfer", auth.ErrForbidden)
		}
		if err := s.authorize(ctx, tx, p, action, "stock_transfer", id, next); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_transfers SET status = $2, decision_reason = $3 WHERE id = $1::uuid`, id, next, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "stock_transfer", id, "stock.transfer_"+strings.ToLower(next), map[string]any{"stock_transfer_id": id, "reason": reason})
	})
}
