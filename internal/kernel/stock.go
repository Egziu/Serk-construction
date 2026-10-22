package kernel

// Journey C: stock valuation (migration 0021, ADR 0012).
//
// stock item (procurement officer creates, finance manager approves) ->
// put-away of a confirmed goods receipt line into a warehouse (storekeeper)
// -> issue to a project cost code (storekeeper prepares; site engineer or
// project manager approves: the database values it FIFO or WAC and the
// STK_ISSUE journal is generated) -> count (storekeeper records; finance
// manager approves: STK_ADJUST journal) -> inventory-to-GL reconciliation.

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

// StockItemInput is a stock item master record.
type StockItemInput struct {
	LegalEntityID      string `json:"legal_entity_id"`
	Code               string `json:"code"`
	Name               string `json:"name"`
	Unit               string `json:"unit"`
	ValuationMethod    string `json:"valuation_method"` // FIFO | WAC
	InventoryAccountID string `json:"inventory_account_id"`
}

// CreateStockItem records a PENDING stock item.
func (s *Service) CreateStockItem(ctx context.Context, p auth.Principal, in StockItemInput) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermStockItemManage, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO stock_items(legal_entity_id, code, name, unit, valuation_method, inventory_account_id, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid, $7) RETURNING id::text`, in.LegalEntityID, strings.ToUpper(strings.TrimSpace(in.Code)),
			strings.TrimSpace(in.Name), strings.TrimSpace(in.Unit), strings.ToUpper(strings.TrimSpace(in.ValuationMethod)), in.InventoryAccountID, p.UserID)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.item.create", "stock_item", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.item.create", "stock_item", id, "stock.item_created", map[string]any{"stock_item_id": id, "code": in.Code})
	})
	return id, err
}

// ApproveStockItem activates a stock item (maker/checker).
func (s *Service) ApproveStockItem(ctx context.Context, p auth.Principal, id string) error {
	return s.p2pTx(ctx, p, auth.PermStockItemApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermStockItemApprove, "stock_item", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "stock item"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.item.approve", "stock_item", id, "ACTIVE"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_items SET status = 'ACTIVE', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.item.approve", "stock_item", id, "stock.item_approved", map[string]any{"stock_item_id": id})
	})
}

// CreateWarehouse records a warehouse: central (no project) or a project store.
func (s *Service) CreateWarehouse(ctx context.Context, p auth.Principal, entity, projectID, code, name string) (string, error) {
	if projectID != "" {
		if err := s.authz.RequireProject(p, auth.PermWarehouseManage, p.TenantID, projectID); err != nil {
			return "", err
		}
	} else if !s.tenantWide(p) {
		return "", fmt.Errorf("%w: a central warehouse needs tenant-wide scope", auth.ErrForbidden)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermWarehouseManage, func(ctx context.Context, tx pgx.Tx) error {
		var proj *string
		if projectID != "" {
			proj = &projectID
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO warehouses(legal_entity_id, project_id, code, name, created_by) VALUES ($1::uuid, $2::uuid, $3, $4, $5) RETURNING id::text`,
			entity, proj, strings.ToUpper(strings.TrimSpace(code)), strings.TrimSpace(name), p.UserID)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "warehouse.create", "warehouse", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "warehouse.create", "warehouse", id, "stock.warehouse_created", map[string]any{"warehouse_id": id, "code": code})
	})
	return id, err
}

// PutAway moves quantity of a confirmed goods receipt line into a warehouse.
// Its value is the receipt's (the GRN journal already debited inventory).
func (s *Service) PutAway(ctx context.Context, p auth.Principal, grnID string, poLineNo int, itemID, warehouseID string, qty decimal.Decimal) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermStockReceive, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.visibleDoc(ctx, tx, p, "grn", grnID, false); err != nil {
			return err
		}
		if _, err := s.visibleDoc(ctx, tx, p, "warehouse", warehouseID, false); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "STR")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO stock_receipts(legal_entity_id, number, grn_id, po_line_no, stock_item_id, warehouse_id, quantity, currency, created_by)
			SELECT o.legal_entity_id, $1, g.id, $3, $4::uuid, $5::uuid, $6, o.currency, $7
			  FROM grns g JOIN purchase_orders o ON o.id = g.po_id WHERE g.id = $2::uuid RETURNING id::text`, num, grnID, poLineNo, itemID, warehouseID, qty, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "stock.receipt.create", "stock_receipt", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.receipt.create", "stock_receipt", id, "stock.put_away",
			map[string]any{"stock_receipt_id": id, "grn_id": grnID, "po_line_no": poLineNo, "quantity": qty.String()})
	})
	return id, err
}

// StockIssueInput is a request to issue stock to a project cost code.
type StockIssueInput struct {
	WarehouseID      string          `json:"warehouse_id"`
	StockItemID      string          `json:"stock_item_id"`
	ProjectID        string          `json:"project_id"`
	CostCodeID       string          `json:"cost_code_id"`
	ExpenseAccountID string          `json:"expense_account_id"`
	Quantity         decimal.Decimal `json:"quantity"`
	IssueDate        time.Time       `json:"-"`
	Note             string          `json:"note,omitempty"`
}

// CreateStockIssue records a DRAFT issue.
func (s *Service) CreateStockIssue(ctx context.Context, p auth.Principal, in StockIssueInput) (string, error) {
	if err := s.authz.RequireProject(p, auth.PermStockIssue, p.TenantID, in.ProjectID); err != nil {
		return "", err
	}
	if err := stockDate(in.IssueDate); err != nil {
		return "", err
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermStockIssue, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.visibleDoc(ctx, tx, p, "warehouse", in.WarehouseID, false); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "SIS")
		if err != nil {
			return err
		}
		var note *string
		if strings.TrimSpace(in.Note) != "" {
			note = &in.Note
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO stock_issues(legal_entity_id, number, warehouse_id, stock_item_id, project_id, cost_code_id,
			expense_account_id, quantity, issue_date, note, currency, created_by)
			SELECT w.legal_entity_id, $1, w.id, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7, $8, $9, le.functional_currency, $10
			  FROM warehouses w JOIN legal_entities le ON le.id = w.legal_entity_id WHERE w.id = $2::uuid RETURNING id::text`,
			num, in.WarehouseID, in.StockItemID, in.ProjectID, in.CostCodeID, in.ExpenseAccountID, in.Quantity, in.IssueDate, note, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "stock.issue.create", "stock_issue", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.issue.create", "stock_issue", id, "stock.issue_requested", map[string]any{"stock_issue_id": id, "number": num})
	})
	return id, err
}

// ApproveStockIssue approves a DRAFT issue: the database values it (FIFO or
// WAC) and the STK_ISSUE journal is generated for finance to approve and post.
func (s *Service) ApproveStockIssue(ctx context.Context, p auth.Principal, id string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermStockIssueApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermStockIssueApprove, "stock_issue", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "stock issue"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.issue.approve", "stock_issue", id, "APPROVED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_issues SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		jid, err = s.stockJournal(ctx, tx, p, "STK_ISSUE", "stock_issues", "issue_date", id)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.issue.approve", "stock_issue", id, "stock.issued", map[string]any{"stock_issue_id": id, "journal_id": jid})
	})
	return jid, err
}

// RejectStockIssue (approver) or CancelStockIssue (preparer) closes a DRAFT issue.
func (s *Service) RejectStockIssue(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.closeStockIssue(ctx, p, auth.PermStockIssueApprove, id, "REJECTED", "stock.issue.reject", reason)
}

// CancelStockIssue withdraws the preparer's own DRAFT issue.
func (s *Service) CancelStockIssue(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.closeStockIssue(ctx, p, auth.PermStockIssue, id, "CANCELLED", "stock.issue.cancel", reason)
}

func (s *Service) closeStockIssue(ctx context.Context, p auth.Principal, perm auth.Permission, id, next, action, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "stock_issue", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if next == "CANCELLED" && d.CreatedBy != p.UserID {
			return fmt.Errorf("%w: only the preparer cancels an issue", auth.ErrForbidden)
		}
		if err := s.authorize(ctx, tx, p, action, "stock_issue", id, next); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_issues SET status = $2, decision_reason = $3 WHERE id = $1::uuid`, id, next, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "stock_issue", id, "stock.issue_"+strings.ToLower(next), map[string]any{"stock_issue_id": id, "reason": reason})
	})
}

// StockCountInput is a physical count of one item in one warehouse.
type StockCountInput struct {
	WarehouseID       string          `json:"warehouse_id"`
	StockItemID       string          `json:"stock_item_id"`
	CountedQty        decimal.Decimal `json:"counted_qty"`
	VarianceAccountID string          `json:"variance_account_id"`
	CountDate         time.Time       `json:"-"`
	Note              string          `json:"note,omitempty"`
}

// CreateStockCount records a DRAFT count; the book quantity and the
// difference are taken by the database.
func (s *Service) CreateStockCount(ctx context.Context, p auth.Principal, in StockCountInput) (string, error) {
	if err := stockDate(in.CountDate); err != nil {
		return "", err
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermStockCount, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.visibleDoc(ctx, tx, p, "warehouse", in.WarehouseID, false); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "SCT")
		if err != nil {
			return err
		}
		var note *string
		if strings.TrimSpace(in.Note) != "" {
			note = &in.Note
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO stock_counts(legal_entity_id, number, warehouse_id, stock_item_id, counted_qty, variance_account_id,
			count_date, note, currency, created_by)
			SELECT w.legal_entity_id, $1, w.id, $3::uuid, $4, $5::uuid, $6, $7, le.functional_currency, $8
			  FROM warehouses w JOIN legal_entities le ON le.id = w.legal_entity_id WHERE w.id = $2::uuid RETURNING id::text`,
			num, in.WarehouseID, in.StockItemID, in.CountedQty, in.VarianceAccountID, in.CountDate, note, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "stock.count.create", "stock_count", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.count.create", "stock_count", id, "stock.counted", map[string]any{"stock_count_id": id, "number": num})
	})
	return id, err
}

// ApproveStockCount adjusts the books to the count (stale counts are refused)
// and generates the STK_ADJUST journal.
func (s *Service) ApproveStockCount(ctx context.Context, p auth.Principal, id string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermStockAdjustApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermStockAdjustApprove, "stock_count", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "stock count"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.count.approve", "stock_count", id, "APPROVED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_counts SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		jid, err = s.stockJournal(ctx, tx, p, "STK_ADJUST", "stock_counts", "count_date", id)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.count.approve", "stock_count", id, "stock.adjusted", map[string]any{"stock_count_id": id, "journal_id": jid})
	})
	return jid, err
}

// RejectStockCount rejects a DRAFT count with a reason.
func (s *Service) RejectStockCount(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermStockAdjustApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermStockAdjustApprove, "stock_count", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "stock.count.reject", "stock_count", id, "REJECTED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE stock_counts SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "stock.count.reject", "stock_count", id, "stock.count_rejected", map[string]any{"stock_count_id": id, "reason": reason})
	})
}

// stockJournal generates the document's journal (when it has value) and
// attaches it in the approving transaction.
func (s *Service) stockJournal(ctx context.Context, tx pgx.Tx, p auth.Principal, doc, table, dateCol, id string) (string, error) {
	var entity, ccy, num string
	var amount decimal.Decimal
	var date time.Time
	if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, number, amount, `+dateCol+` FROM `+table+` WHERE id = $1::uuid`, id).Scan(
		&entity, &ccy, &num, &amount, &date); err != nil {
		return "", err
	}
	if !amount.IsPositive() {
		return "", nil // nothing to post (a count difference worth less than the currency's minor unit)
	}
	jid, err := s.subledgerJournal(ctx, tx, p, doc, id, entity, ccy, map[string]string{"STK_ISSUE": "Stock issue ", "STK_ADJUST": "Stock count adjustment "}[doc]+num, date)
	if err != nil {
		return "", err
	}
	if err := postgres.Exec1(ctx, tx, `UPDATE `+table+` SET journal_id = $2::uuid WHERE id = $1::uuid`, id, jid); err != nil {
		return "", err
	}
	return jid, nil
}

// StockOnHand lists quantities and values the principal may see: every
// warehouse for tenant-wide principals, project stores of their projects
// otherwise.
func (s *Service) StockOnHand(ctx context.Context, p auth.Principal, entity string) ([]postgres.StockLine, error) {
	var out []postgres.StockLine
	err := s.p2pTx(ctx, p, auth.PermP2PRead, func(ctx context.Context, tx pgx.Tx) error {
		all, err := postgres.StockOnHand(ctx, tx, entity)
		if err != nil {
			return err
		}
		out = []postgres.StockLine{}
		for _, l := range all {
			if s.canSee(p, "warehouse", l.ProjectID) {
				out = append(out, l)
			}
		}
		return nil
	})
	return out, err
}

// StockReconciliation compares inventory with the GL (tenant-wide finance).
func (s *Service) StockReconciliation(ctx context.Context, p auth.Principal, entity string) ([]postgres.ReconCheck, error) {
	if err := s.authz.Require(p, auth.PermJournalRead, p.TenantID); err != nil {
		return nil, err
	}
	if !s.tenantWide(p) {
		return nil, fmt.Errorf("%w: reconciliation needs tenant-wide scope", auth.ErrForbidden)
	}
	var out []postgres.ReconCheck
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.StockReconciliation(ctx, tx, entity)
		return err
	})
	return out, err
}

// stockDate refuses a missing or future document date (R7-F3); the database
// also requires an open fiscal period, at recording and at approval.
func stockDate(d time.Time) error {
	if d.IsZero() || d.After(time.Now().UTC()) {
		return fmt.Errorf("%w: a stock document is dated today or earlier, in an open period", ErrInvalidInput)
	}
	return nil
}

// DesignatePOLineItem names the stock item of an inventory purchase-order
// line that was raised without one (R8-F8). It is procurement's decision
// (po.manage, human), made once and before anything is put away; the
// storekeeper never chooses the item.
func (s *Service) DesignatePOLineItem(ctx context.Context, p auth.Principal, poID string, lineNo int, itemID string) error {
	return s.p2pTx(ctx, p, auth.PermPOManage, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermPOManage, "purchase_order", poID); err != nil {
			return err
		}
		if _, err := s.visibleDoc(ctx, tx, p, "stock_item", itemID, false); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "po.line.designate", "purchase_order", poID, "DESIGNATE"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE po_lines SET stock_item_id = $3::uuid WHERE po_id = $1::uuid AND line_no = $2`, poID, lineNo, itemID); err != nil {
			return mapNoRows(err)
		}
		return s.record(ctx, tx, p, "po.line.designate", "purchase_order", poID, "po.line_designated",
			map[string]any{"po_id": poID, "line_no": lineNo, "stock_item_id": itemID})
	})
}
