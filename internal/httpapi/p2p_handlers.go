package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Journey A HTTP surface. Every route is authenticated (s.authed); the kernel
// re-checks permission, project scope and SoD, and PostgreSQL enforces the
// rest under a per-action attestation.

// day is a calendar date in JSON ("2026-10-22").
type day struct{ time.Time }

func (d *day) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("date %q must be YYYY-MM-DD", s)
	}
	d.Time = t
	return nil
}

func (s *Server) registerP2P() {
	m := s.mux
	// Policy and master data.
	m.Handle("POST /v1/p2p/policies", s.authed(s.createP2PPolicy))
	m.Handle("POST /v1/p2p/policies/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecideP2PPolicy(ctx, p, id, true)
	})))
	m.Handle("POST /v1/p2p/policies/{id}/reject", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecideP2PPolicy(ctx, p, id, false)
	})))
	m.Handle("POST /v1/suppliers", s.authed(s.createSupplier))
	m.Handle("POST /v1/suppliers/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.ApproveSupplier(ctx, p, id)
	})))
	m.Handle("POST /v1/suppliers/{id}/block", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.BlockSupplier(ctx, p, id, b.Reason)
	})))
	m.Handle("POST /v1/suppliers/{id}/bank-accounts", s.authed(s.addSupplierBank))
	m.Handle("POST /v1/supplier-bank-accounts/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.ApproveSupplierBankAccount(ctx, p, id)
	})))
	m.Handle("POST /v1/company-bank-accounts", s.authed(s.registerCompanyBank))
	m.Handle("POST /v1/company-bank-accounts/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.ApproveCompanyBankAccount(ctx, p, id)
	})))
	// BOQ, requisitions, RFQ, PO.
	m.Handle("POST /v1/boqs", s.authed(s.createBOQ))
	m.Handle("POST /v1/boqs/{id}/submit", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.SubmitBOQ(ctx, p, id)
	})))
	m.Handle("POST /v1/boqs/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecideBOQ(ctx, p, id, true, b.Reason)
	})))
	m.Handle("POST /v1/boqs/{id}/reject", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecideBOQ(ctx, p, id, false, b.Reason)
	})))
	m.Handle("POST /v1/requisitions", s.authed(s.createPR))
	m.Handle("POST /v1/requisitions/{id}/submit", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.SubmitPR(ctx, p, id)
	})))
	m.Handle("POST /v1/requisitions/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecidePR(ctx, p, id, true, b.Reason)
	})))
	m.Handle("POST /v1/requisitions/{id}/reject", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.DecidePR(ctx, p, id, false, b.Reason)
	})))
	m.Handle("POST /v1/rfqs", s.authed(s.createRFQ))
	m.Handle("POST /v1/rfqs/{id}/issue", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.IssueRFQ(ctx, p, id)
	})))
	m.Handle("POST /v1/rfqs/{id}/quotes", s.authed(s.recordQuote))
	m.Handle("POST /v1/quotes/{id}/evaluate", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.EvaluateQuote(ctx, p, id, b.Compliant, b.Note)
	})))
	m.Handle("POST /v1/rfqs/{id}/award", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		if _, err := uuid.Parse(b.QuoteID); err != nil {
			return nil, fmt.Errorf("%w: quote_id required", kernel.ErrInvalidInput)
		}
		return nil, s.cfg.Kernel.AwardRFQ(ctx, p, id, b.QuoteID, b.Reason)
	})))
	m.Handle("POST /v1/purchase-orders", s.authed(s.createPO))
	m.Handle("POST /v1/purchase-orders/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.ApprovePO(ctx, p, id, b.Reason)
	})))
	// Receipts, invoices, payments, bank.
	m.Handle("POST /v1/goods-receipts", s.authed(s.createGRN))
	m.Handle("POST /v1/goods-receipts/{id}/submit", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.SubmitGRN(ctx, p, id)
	})))
	m.Handle("POST /v1/goods-receipts/{id}/confirm", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := s.cfg.Kernel.ConfirmGRN(ctx, p, id)
		return map[string]any{"journal_id": jid}, err
	})))
	m.Handle("POST /v1/invoices", s.authed(s.enterInvoice))
	m.Handle("POST /v1/invoices/{id}/submit", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		st, err := s.cfg.Kernel.SubmitInvoice(ctx, p, id)
		return map[string]any{"match_status": st}, err
	})))
	m.Handle("POST /v1/invoices/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		jid, err := s.cfg.Kernel.ApproveInvoice(ctx, p, id, b.Reason)
		return map[string]any{"journal_id": jid}, err
	})))
	m.Handle("POST /v1/invoices/{id}/reject", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.RejectInvoice(ctx, p, id, b.Reason)
	})))
	m.Handle("POST /v1/payments", s.authed(s.preparePayment))
	m.Handle("POST /v1/payments/{id}/submit", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, s.cfg.Kernel.SubmitPayment(ctx, p, id)
	})))
	m.Handle("POST /v1/payments/{id}/approve", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		st, err := s.cfg.Kernel.ApprovePayment(ctx, p, id)
		return map[string]any{"status": st}, err
	})))
	m.Handle("POST /v1/payments/{id}/release", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := s.cfg.Kernel.ReleasePayment(ctx, p, id)
		return map[string]any{"journal_id": jid}, err
	})))
	m.Handle("POST /v1/payments/{id}/cancel", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, s.cfg.Kernel.CancelPayment(ctx, p, id, b.Reason)
	})))
	m.Handle("POST /v1/bank-statements", s.authed(s.importStatement))
	m.Handle("POST /v1/bank-statements/{id}/reconcile", s.authed(s.p2pDecision(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return s.cfg.Kernel.AutoReconcile(ctx, p, id)
	})))
	// Finance batches, reads and reports.
	m.Handle("POST /v1/journals/approve-batch", s.authed(s.journalBatch(true)))
	m.Handle("POST /v1/journals/post-batch", s.authed(s.journalBatch(false)))
	m.Handle("GET /v1/journals", s.authed(s.listJournals))
	m.Handle("GET /v1/p2p/{type}", s.authed(s.listP2P))
	m.Handle("GET /v1/p2p/{type}/{id}", s.authed(s.getP2P))
	m.Handle("POST /v1/p2p/{type}/{id}/reveal-bank-details", s.authed(s.revealBank))
	m.Handle("GET /v1/projects/{id}/cost-report", s.authed(s.costReport))
	m.Handle("GET /v1/projects/{id}/cost-codes", s.authed(s.costCodes))
	m.Handle("GET /v1/p2p-reference", s.authed(s.p2pReference))
	m.Handle("GET /v1/identity/me", s.authed(s.whoami))
	m.Handle("GET /v1/entities/{id}/p2p-reconciliation", s.authed(s.p2pRecon))
}

// decisionBody is the optional body of a transition.
type decisionBody struct {
	Reason    string `json:"reason"`
	Note      string `json:"note"`
	Compliant bool   `json:"compliant"`
	QuoteID   string `json:"quote_id"`
}

// p2pDecision wraps a transition on /{id}: validates the id, reads an
// optional JSON body, runs fn and answers 200 with fn's result.
func (s *Server) p2pDecision(fn func(context.Context, auth.Principal, string, decisionBody) (any, error)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !canonicalUUID(id) {
			writeErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		var b decisionBody
		if r.ContentLength != 0 && !decode(w, r, &b) {
			return
		}
		out, err := fn(r.Context(), principalFrom(r.Context()), id, b)
		if err != nil {
			s.fail(w, err)
			return
		}
		if out == nil {
			out = map[string]any{"id": id, "ok": true}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) created(w http.ResponseWriter, id string, err error) {
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) createP2PPolicy(w http.ResponseWriter, r *http.Request) {
	var b postgres.P2PPolicy
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.ProposeP2PPolicy(r.Context(), principalFrom(r.Context()), b)
	s.created(w, id, err)
}

func (s *Server) createSupplier(w http.ResponseWriter, r *http.Request) {
	var b struct {
		LegalEntityID string `json:"legal_entity_id"`
		Code          string `json:"code"`
		Name          string `json:"name"`
		TaxID         string `json:"tax_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.CreateSupplier(r.Context(), principalFrom(r.Context()), b.LegalEntityID, b.Code, b.Name, b.TaxID)
	s.created(w, id, err)
}

func (s *Server) addSupplierBank(w http.ResponseWriter, r *http.Request) {
	var b struct {
		BankName      string `json:"bank_name"`
		AccountName   string `json:"account_name"`
		AccountNumber string `json:"account_number"`
		Currency      string `json:"currency"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.AddSupplierBankAccount(r.Context(), principalFrom(r.Context()), r.PathValue("id"), b.BankName, b.AccountName, b.AccountNumber, b.Currency)
	s.created(w, id, err)
}

func (s *Server) registerCompanyBank(w http.ResponseWriter, r *http.Request) {
	var b struct {
		LegalEntityID     string `json:"legal_entity_id"`
		Name              string `json:"name"`
		AccountNumber     string `json:"account_number"`
		Currency          string `json:"currency"`
		GLAccountID       string `json:"gl_account_id"`
		ClearingAccountID string `json:"clearing_account_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.RegisterCompanyBankAccount(r.Context(), principalFrom(r.Context()), b.LegalEntityID, b.Name, b.AccountNumber, b.Currency, b.GLAccountID, b.ClearingAccountID)
	s.created(w, id, err)
}

func (s *Server) createBOQ(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ProjectID   string           `json:"project_id"`
		Description string           `json:"description"`
		Items       []kernel.BOQItem `json:"items"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.CreateBOQ(r.Context(), principalFrom(r.Context()), b.ProjectID, b.Description, b.Items)
	s.created(w, id, err)
}

func (s *Server) createPR(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ProjectID     string          `json:"project_id"`
		Justification string          `json:"justification"`
		NeededBy      *day            `json:"needed_by"`
		Lines         []kernel.PRLine `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	var nb *time.Time
	if b.NeededBy != nil {
		nb = &b.NeededBy.Time
	}
	id, err := s.cfg.Kernel.CreatePR(r.Context(), principalFrom(r.Context()), b.ProjectID, b.Justification, nb, b.Lines)
	s.created(w, id, err)
}

func (s *Server) createRFQ(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PRID               string    `json:"pr_id"`
		DueAt              time.Time `json:"due_at"`
		MinSuppliers       int       `json:"min_suppliers"`
		SingleSourceReason string    `json:"single_source_reason"`
		SupplierIDs        []string  `json:"supplier_ids"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.CreateRFQ(r.Context(), principalFrom(r.Context()), b.PRID, b.DueAt, b.MinSuppliers, b.SingleSourceReason, b.SupplierIDs)
	s.created(w, id, err)
}

func (s *Server) recordQuote(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SupplierID        string             `json:"supplier_id"`
		ValidUntil        day                `json:"valid_until"`
		SupplierReference string             `json:"supplier_reference"`
		Lines             []kernel.QuoteLine `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.RecordQuote(r.Context(), principalFrom(r.Context()), r.PathValue("id"), b.SupplierID, b.ValidUntil.Time, b.SupplierReference, b.Lines)
	s.created(w, id, err)
}

func (s *Server) createPO(w http.ResponseWriter, r *http.Request) {
	var b struct {
		RFQID    string            `json:"rfq_id"`
		Accounts map[string]string `json:"accounts"` // requisition line number -> GL account id
	}
	if !decode(w, r, &b) {
		return
	}
	acc := map[int]string{}
	for k, v := range b.Accounts {
		n, err := strconv.Atoi(k)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "accounts keys are requisition line numbers")
			return
		}
		acc[n] = v
	}
	id, err := s.cfg.Kernel.CreatePOFromAward(r.Context(), principalFrom(r.Context()), b.RFQID, acc)
	s.created(w, id, err)
}

func (s *Server) createGRN(w http.ResponseWriter, r *http.Request) {
	var b struct {
		POID         string           `json:"po_id"`
		ReceivedOn   day              `json:"received_on"`
		DeliveryNote string           `json:"delivery_note"`
		Lines        []kernel.GRNLine `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.CreateGRN(r.Context(), principalFrom(r.Context()), b.POID, b.ReceivedOn.Time, b.DeliveryNote, b.Lines)
	s.created(w, id, err)
}

func (s *Server) enterInvoice(w http.ResponseWriter, r *http.Request) {
	var b struct {
		POID          string               `json:"po_id"`
		InvoiceNumber string               `json:"invoice_number"`
		InvoiceDate   day                  `json:"invoice_date"`
		DueDate       day                  `json:"due_date"`
		Subtotal      decimal.Decimal      `json:"subtotal"`
		TaxAmount     decimal.Decimal      `json:"tax_amount"`
		Total         decimal.Decimal      `json:"total"`
		Lines         []kernel.InvoiceLine `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.EnterInvoice(r.Context(), principalFrom(r.Context()), kernel.InvoiceInput{POID: b.POID, InvoiceNumber: b.InvoiceNumber,
		InvoiceDate: b.InvoiceDate.Time, DueDate: b.DueDate.Time, Subtotal: b.Subtotal, TaxAmount: b.TaxAmount, Total: b.Total, Lines: b.Lines})
	s.created(w, id, err)
}

func (s *Server) preparePayment(w http.ResponseWriter, r *http.Request) {
	var b struct {
		LegalEntityID  string              `json:"legal_entity_id"`
		SupplierID     string              `json:"supplier_id"`
		SupplierBankID string              `json:"supplier_bank_id"`
		CompanyBankID  string              `json:"company_bank_id"`
		ValueDate      day                 `json:"value_date"`
		Allocations    []kernel.Allocation `json:"allocations"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.PreparePayment(r.Context(), principalFrom(r.Context()), b.LegalEntityID, b.SupplierID, b.SupplierBankID, b.CompanyBankID, b.ValueDate.Time, b.Allocations)
	s.created(w, id, err)
}

// importStatement: the request body IS the statement file. The kernel parses
// it and attests both the SHA-256 of these exact bytes and the digest of the
// parsed content; the database re-derives the latter from the stored rows.
func (s *Server) importStatement(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "statement too large")
		return
	}
	id, err := s.cfg.Kernel.ImportBankStatement(r.Context(), principalFrom(r.Context()), raw)
	s.created(w, id, err)
}

func (s *Server) journalBatch(approve bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			JournalIDs []string `json:"journal_ids"`
		}
		if !decode(w, r, &b) {
			return
		}
		if len(b.JournalIDs) == 0 || len(b.JournalIDs) > 200 {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "journal_ids: 1 to 200 ids")
			return
		}
		p := principalFrom(r.Context())
		var res []kernel.BatchResult
		if approve {
			res = s.cfg.Kernel.ApproveJournals(r.Context(), p, b.JournalIDs)
		} else {
			res = s.cfg.Kernel.PostJournals(r.Context(), p, b.JournalIDs)
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": res})
	}
}

func (s *Server) listJournals(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.ListJournals(r.Context(), principalFrom(r.Context()), r.URL.Query().Get("status"), r.URL.Query().Get("source_prefix"), 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	if out == nil {
		out = []postgres.JournalSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"journals": out})
}

func (s *Server) listP2P(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.ListP2PDocs(r.Context(), principalFrom(r.Context()), r.PathValue("type"), r.URL.Query().Get("status"), 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	if out == nil {
		out = []postgres.DocSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// canonicalUUID accepts a path id only in the canonical lowercase,
// hyphenated form. Other spellings that uuid.Parse accepts (urn:uuid:,
// braces, upper case, no hyphens) are answered 404 before the kernel
// (review 5, F9).
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

func (s *Server) getP2P(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonicalUUID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	d, err := s.cfg.Kernel.GetP2PDoc(r.Context(), principalFrom(r.Context()), r.PathValue("type"), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) costReport(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.ProjectCostReport(r.Context(), principalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cost_codes": out})
}

func (s *Server) p2pRecon(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.GLReconciliation(r.Context(), principalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": out})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Kernel.Whoami(principalFrom(r.Context())))
}

func (s *Server) p2pReference(w http.ResponseWriter, r *http.Request) {
	ref, err := s.cfg.Kernel.P2PReference(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ref)
}

func (s *Server) costCodes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonicalUUID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	out, err := s.cfg.Kernel.ProjectCostCodes(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cost_codes": out})
}

// revealBank returns a full bank account number to a privileged, MFA-fresh
// caller who states a purpose (IA-040-01). The response is never cached.
func (s *Server) revealBank(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonicalUUID(id) {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	var b struct {
		Purpose string `json:"purpose"`
	}
	if !decode(w, r, &b) {
		return
	}
	out, err := s.cfg.Kernel.RevealBankAccount(r.Context(), principalFrom(r.Context()), r.PathValue("type"), id, b.Purpose)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
