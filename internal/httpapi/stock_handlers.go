package httpapi

// Journey C routes: stock valuation (ADR 0012). Thin adapters over the
// kernel; valuation, authorization and separation of duties live below.

import (
	"context"
	"net/http"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func (s *Server) registerStock() {
	m := s.mux
	k := func() *kernel.Service { return s.cfg.Kernel }
	decide := func(fn func(context.Context, auth.Principal, string, decisionBody) (any, error)) http.Handler {
		return s.authed(s.p2pDecision(fn))
	}
	m.Handle("POST /v1/stock-items", s.authed(s.createStockItem))
	m.Handle("POST /v1/stock-items/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().ApproveStockItem(ctx, p, id)
	}))
	m.Handle("POST /v1/warehouses", s.authed(s.createWarehouse))
	m.Handle("POST /v1/goods-receipts/{id}/put-away", s.authed(s.putAway))
	m.Handle("POST /v1/stock-issues", s.authed(s.createStockIssue))
	m.Handle("POST /v1/stock-issues/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := k().ApproveStockIssue(ctx, p, id)
		return map[string]any{"id": id, "journal_id": jid}, err
	}))
	m.Handle("POST /v1/stock-issues/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().RejectStockIssue(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/stock-issues/{id}/cancel", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().CancelStockIssue(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/stock-counts", s.authed(s.createStockCount))
	m.Handle("POST /v1/stock-counts/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := k().ApproveStockCount(ctx, p, id)
		return map[string]any{"id": id, "journal_id": jid}, err
	}))
	m.Handle("POST /v1/stock-counts/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().RejectStockCount(ctx, p, id, b.Reason)
	}))
	// Transfers (0025).
	m.Handle("POST /v1/stock-transfers", s.authed(s.createStockTransfer))
	m.Handle("POST /v1/stock-transfers/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().ApproveStockTransfer(ctx, p, id)
	}))
	m.Handle("POST /v1/stock-transfers/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().RejectStockTransfer(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/stock-transfers/{id}/cancel", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().CancelStockTransfer(ctx, p, id, b.Reason)
	}))
	m.Handle("GET /v1/entities/{id}/stock-on-hand", s.authed(s.stockOnHand))
	m.Handle("GET /v1/entities/{id}/stock-reconciliation", s.authed(s.stockRecon))
}

func validIDs(w http.ResponseWriter, ids ...string) bool {
	for _, id := range ids {
		if !canonicalUUID(id) {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "ids must be canonical UUIDs")
			return false
		}
	}
	return true
}

func (s *Server) createStockItem(w http.ResponseWriter, r *http.Request) {
	var b kernel.StockItemInput
	if !decode(w, r, &b) || !validIDs(w, b.LegalEntityID, b.InventoryAccountID) {
		return
	}
	id, err := s.cfg.Kernel.CreateStockItem(r.Context(), principalFrom(r.Context()), b)
	s.created(w, id, err)
}

func (s *Server) createWarehouse(w http.ResponseWriter, r *http.Request) {
	var b struct {
		LegalEntityID string `json:"legal_entity_id"`
		ProjectID     string `json:"project_id"`
		Code          string `json:"code"`
		Name          string `json:"name"`
	}
	if !decode(w, r, &b) || !validIDs(w, b.LegalEntityID) || (b.ProjectID != "" && !validIDs(w, b.ProjectID)) {
		return
	}
	id, err := s.cfg.Kernel.CreateWarehouse(r.Context(), principalFrom(r.Context()), b.LegalEntityID, b.ProjectID, b.Code, b.Name)
	s.created(w, id, err)
}

func (s *Server) putAway(w http.ResponseWriter, r *http.Request) {
	grn, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		POLineNo    int             `json:"po_line_no"`
		StockItemID string          `json:"stock_item_id"`
		WarehouseID string          `json:"warehouse_id"`
		Quantity    decimal.Decimal `json:"quantity"`
	}
	if !decode(w, r, &b) || !validIDs(w, b.StockItemID, b.WarehouseID) {
		return
	}
	id, err := s.cfg.Kernel.PutAway(r.Context(), principalFrom(r.Context()), grn, b.POLineNo, b.StockItemID, b.WarehouseID, b.Quantity)
	s.created(w, id, err)
}

func (s *Server) createStockIssue(w http.ResponseWriter, r *http.Request) {
	var b struct {
		kernel.StockIssueInput
		IssueDate day `json:"issue_date"`
	}
	if !decode(w, r, &b) || !validIDs(w, b.WarehouseID, b.StockItemID, b.ProjectID, b.CostCodeID, b.ExpenseAccountID) {
		return
	}
	b.StockIssueInput.IssueDate = b.IssueDate.Time
	id, err := s.cfg.Kernel.CreateStockIssue(r.Context(), principalFrom(r.Context()), b.StockIssueInput)
	s.created(w, id, err)
}

func (s *Server) createStockCount(w http.ResponseWriter, r *http.Request) {
	var b struct {
		kernel.StockCountInput
		CountDate day `json:"count_date"`
	}
	if !decode(w, r, &b) || !validIDs(w, b.WarehouseID, b.StockItemID, b.VarianceAccountID) {
		return
	}
	b.StockCountInput.CountDate = b.CountDate.Time
	id, err := s.cfg.Kernel.CreateStockCount(r.Context(), principalFrom(r.Context()), b.StockCountInput)
	s.created(w, id, err)
}

func (s *Server) createStockTransfer(w http.ResponseWriter, r *http.Request) {
	var b struct {
		kernel.StockTransferInput
		TransferDate day `json:"transfer_date"`
	}
	if !decode(w, r, &b) || !validIDs(w, b.StockItemID, b.FromWarehouseID, b.ToWarehouseID) {
		return
	}
	b.StockTransferInput.TransferDate = b.TransferDate.Time
	id, err := s.cfg.Kernel.CreateStockTransfer(r.Context(), principalFrom(r.Context()), b.StockTransferInput)
	s.created(w, id, err)
}

func (s *Server) stockOnHand(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.StockOnHand(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": out})
}

func (s *Server) stockRecon(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.StockReconciliation(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if out == nil {
		out = []postgres.ReconCheck{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": out})
}
