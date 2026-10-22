package httpapi

// Journey B routes: contract to cash (ADR 0011). Every route is a thin
// adapter over one kernel command; authorization, separation of duties,
// visibility and every figure are decided by the kernel and the database.

import (
	"context"
	"net/http"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func (s *Server) registerAR() {
	m := s.mux
	k := func() *kernel.Service { return s.cfg.Kernel }
	decide := func(fn func(context.Context, auth.Principal, string, decisionBody) (any, error)) http.Handler {
		return s.authed(s.p2pDecision(fn))
	}
	// Contract policy and customers.
	m.Handle("POST /v1/contract-policies", s.authed(s.createContractPolicy))
	m.Handle("POST /v1/contract-policies/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideContractPolicy(ctx, p, id, true)
	}))
	m.Handle("POST /v1/contract-policies/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideContractPolicy(ctx, p, id, false)
	}))
	m.Handle("POST /v1/customers", s.authed(s.createCustomer))
	m.Handle("POST /v1/customers/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().ApproveCustomer(ctx, p, id)
	}))
	// Contracts.
	m.Handle("POST /v1/contracts", s.authed(s.createContract))
	m.Handle("POST /v1/contracts/{id}/submit", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().SubmitContract(ctx, p, id)
	}))
	m.Handle("POST /v1/contracts/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideContract(ctx, p, id, true, b.Reason)
	}))
	m.Handle("POST /v1/contracts/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideContract(ctx, p, id, false, b.Reason)
	}))
	m.Handle("GET /v1/contracts/{id}/position", s.authed(s.contractPosition))
	// Measurements.
	m.Handle("POST /v1/contracts/{id}/measurements", s.authed(s.createMeasurement))
	m.Handle("POST /v1/measurements/{id}/submit", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().SubmitMeasurement(ctx, p, id)
	}))
	m.Handle("POST /v1/measurements/{id}/verify", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideMeasurement(ctx, p, id, true, "")
	}))
	m.Handle("POST /v1/measurements/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideMeasurement(ctx, p, id, false, b.Reason)
	}))
	// Interim payment certificates.
	m.Handle("POST /v1/contracts/{id}/ipcs", s.authed(s.prepareIPC))
	m.Handle("POST /v1/ipcs/{id}/submit", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().SubmitIPC(ctx, p, id)
	}))
	m.Handle("POST /v1/ipcs/{id}/certify", s.authed(s.certifyIPC))
	m.Handle("POST /v1/ipcs/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().RejectIPC(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/ipcs/{id}/cancel", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().CancelIPC(ctx, p, id, b.Reason)
	}))
	// Customer invoices and receipts.
	m.Handle("POST /v1/ipcs/{id}/invoice", s.authed(s.issueCustomerInvoice))
	m.Handle("POST /v1/customer-invoices/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := k().ApproveCustomerInvoice(ctx, p, id)
		return map[string]any{"id": id, "journal_id": jid}, err
	}))
	m.Handle("POST /v1/receipts", s.authed(s.recordReceipt))
	m.Handle("POST /v1/receipts/{id}/confirm", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		jid, err := k().ConfirmReceipt(ctx, p, id)
		return map[string]any{"id": id, "journal_id": jid}, err
	}))
	// Reports.
	m.Handle("GET /v1/entities/{id}/ar-reconciliation", s.authed(s.arRecon))
	m.Handle("GET /v1/projects/{id}/profitability", s.authed(s.profitability))
}

func (s *Server) createContractPolicy(w http.ResponseWriter, r *http.Request) {
	var b kernel.ContractPolicy
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.ProposeContractPolicy(r.Context(), principalFrom(r.Context()), b)
	s.created(w, id, err)
}

func (s *Server) createCustomer(w http.ResponseWriter, r *http.Request) {
	var b struct {
		LegalEntityID string `json:"legal_entity_id"`
		Code          string `json:"code"`
		Name          string `json:"name"`
		TaxID         string `json:"tax_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	id, err := s.cfg.Kernel.CreateCustomer(r.Context(), principalFrom(r.Context()), b.LegalEntityID, b.Code, b.Name, b.TaxID)
	s.created(w, id, err)
}

func (s *Server) createContract(w http.ResponseWriter, r *http.Request) {
	var b struct {
		kernel.ContractInput
		SignedOn day `json:"signed_on"`
	}
	if !decode(w, r, &b) {
		return
	}
	b.ContractInput.SignedOn = b.SignedOn.Time
	id, err := s.cfg.Kernel.CreateContract(r.Context(), principalFrom(r.Context()), b.ContractInput)
	s.created(w, id, err)
}

func (s *Server) createMeasurement(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		PeriodEnd day                      `json:"period_end"`
		Lines     []kernel.MeasurementLine `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	mid, err := s.cfg.Kernel.CreateMeasurement(r.Context(), principalFrom(r.Context()), id, b.PeriodEnd.Time, b.Lines)
	s.created(w, mid, err)
}

func (s *Server) prepareIPC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		PeriodEnd day `json:"period_end"`
	}
	if !decode(w, r, &b) {
		return
	}
	ipc, err := s.cfg.Kernel.PrepareIPC(r.Context(), principalFrom(r.Context()), id, b.PeriodEnd.Time)
	s.created(w, ipc, err)
}

func (s *Server) certifyIPC(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		CertificateRef    string `json:"certificate_ref"`
		CertificateSHA256 string `json:"certificate_sha256"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := s.cfg.Kernel.CertifyIPC(r.Context(), principalFrom(r.Context()), id, b.CertificateRef, b.CertificateSHA256); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "ok": true})
}

func (s *Server) issueCustomerInvoice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		InvoiceDate day `json:"invoice_date"`
		DueDate     day `json:"due_date"`
	}
	if !decode(w, r, &b) {
		return
	}
	inv, err := s.cfg.Kernel.IssueCustomerInvoice(r.Context(), principalFrom(r.Context()), id, b.InvoiceDate.Time, b.DueDate.Time)
	s.created(w, inv, err)
}

func (s *Server) recordReceipt(w http.ResponseWriter, r *http.Request) {
	var b struct {
		StatementLineID string                     `json:"statement_line_id"`
		Allocations     []kernel.ReceiptAllocation `json:"allocations"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !canonicalUUID(b.StatementLineID) {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "statement_line_id must be a canonical UUID")
		return
	}
	id, err := s.cfg.Kernel.RecordReceipt(r.Context(), principalFrom(r.Context()), b.StatementLineID, b.Allocations)
	s.created(w, id, err)
}

func (s *Server) contractPosition(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.ContractPosition(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) arRecon(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.ARReconciliation(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if out == nil {
		out = []postgres.ReconCheck{} // no contract policy yet: [] not null
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": out})
}

func (s *Server) profitability(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.ProjectProfitability(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
