package kernel

// Journey B: contract to cash (migration 0018, ADR 0011).
//
// customer + contract (maker: commercial manager; checker: CFO with MFA) ->
// measurement (quantity surveyor) verified by a site engineer -> IPC computed
// by the database (quantity surveyor prepares, commercial manager certifies
// with MFA and the client's certificate) -> customer invoice (AR clerk issues,
// AR supervisor approves: AR journal) -> receipt from a money-in statement
// line (AR clerk allocates, AR supervisor confirms: receipt journal) ->
// finance approves and posts the journals.
//
// As in Journey A, every command signs exactly one attestation for one
// transition and the database enforces the numbers and the separation.

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

// ContractPolicy is the AR configuration of a legal entity.
type ContractPolicy struct {
	LegalEntityID      string          `json:"legal_entity_id"`
	VATRate            decimal.Decimal `json:"vat_rate"`
	VATBase            string          `json:"vat_base"` // GROSS | GROSS_LESS_ADVANCE
	ARAccountID        string          `json:"ar_account_id"`
	RetentionAccountID string          `json:"retention_account_id"`
	AdvanceAccountID   string          `json:"advance_account_id"`
	RevenueAccountID   string          `json:"revenue_account_id"`
	VATOutputAccountID string          `json:"vat_output_account_id"`
}

// ProposeContractPolicy creates a DRAFT contract policy (next version).
func (s *Service) ProposeContractPolicy(ctx context.Context, p auth.Principal, cp ContractPolicy) (string, error) {
	if cp.VATBase == "" {
		cp.VATBase = "GROSS_LESS_ADVANCE"
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermContractPolicyManage, func(ctx context.Context, tx pgx.Tx) error {
		if !s.tenantWide(p) {
			return fmt.Errorf("%w: contract policies need tenant-wide scope", auth.ErrForbidden)
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO contract_policies(legal_entity_id, version, currency, vat_rate, vat_base, ar_account_id,
			retention_account_id, advance_account_id, revenue_account_id, vat_output_account_id, created_by)
			SELECT $1::uuid, COALESCE(max(version), 0) + 1, (SELECT functional_currency FROM legal_entities WHERE id = $1::uuid), $2, $3,
			       $4::uuid, $5::uuid, $6::uuid, $7::uuid, $8::uuid, $9 FROM contract_policies WHERE legal_entity_id = $1::uuid RETURNING id::text`,
			cp.LegalEntityID, cp.VATRate, cp.VATBase, cp.ARAccountID, cp.RetentionAccountID, cp.AdvanceAccountID, cp.RevenueAccountID, cp.VATOutputAccountID, p.UserID)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "contract.policy.create", "contract_policy", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "contract.policy.propose", "contract_policy", id, "contract.policy.proposed", map[string]any{"policy_id": id})
	})
	return id, err
}

// DecideContractPolicy approves (retiring the predecessor) or rejects.
func (s *Service) DecideContractPolicy(ctx context.Context, p auth.Principal, id string, approve bool) error {
	return s.p2pTx(ctx, p, auth.PermContractPolicyApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermContractPolicyApprove, "contract_policy", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "contract policy"); err != nil {
			return err
		}
		next := map[bool]string{true: "APPROVED", false: "REJECTED"}[approve]
		if err := s.authorize(ctx, tx, p, "contract.policy.decide", "contract_policy", id, next); err != nil {
			return err
		}
		if approve {
			if _, err := tx.Exec(ctx, `UPDATE contract_policies SET status = 'RETIRED' WHERE status = 'APPROVED' AND id <> $1::uuid
				AND legal_entity_id = (SELECT legal_entity_id FROM contract_policies WHERE id = $1::uuid)`, id); err != nil {
				return err
			}
			err = postgres.Exec1(ctx, tx, `UPDATE contract_policies SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE contract_policies SET status = 'REJECTED' WHERE id = $1::uuid`, id)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "contract.policy.decide", "contract_policy", id, "contract.policy."+strings.ToLower(next), map[string]any{"policy_id": id})
	})
}

// CreateCustomer creates a PENDING customer (attested creator).
func (s *Service) CreateCustomer(ctx context.Context, p auth.Principal, entity, code, name, taxID string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermCustomerManage, func(ctx context.Context, tx pgx.Tx) error {
		var tax *string
		if strings.TrimSpace(taxID) != "" {
			tax = &taxID
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO customers(legal_entity_id, code, name, tax_id, created_by) VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
			entity, strings.ToUpper(strings.TrimSpace(code)), strings.TrimSpace(name), tax, p.UserID)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "customer.create", "customer", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "customer.create", "customer", id, "customer.created", map[string]any{"customer_id": id, "code": code})
	})
	return id, err
}

// ApproveCustomer activates a customer (maker/checker).
func (s *Service) ApproveCustomer(ctx context.Context, p auth.Principal, id string) error {
	return s.p2pTx(ctx, p, auth.PermCustomerApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermCustomerApprove, "customer", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING", "BLOCKED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "customer"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "customer.approve", "customer", id, "ACTIVE"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE customers SET status = 'ACTIVE', approved_by = $2, blocked_reason = NULL WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "customer.approve", "customer", id, "customer.approved", map[string]any{"customer_id": id})
	})
}

// ContractLine is one priced line of a contract (optionally linked to the
// project's approved BOQ item it delivers).
type ContractLine struct {
	LineNo      int             `json:"line_no"`
	BOQItemID   string          `json:"boq_item_id,omitempty"`
	Description string          `json:"description"`
	Unit        string          `json:"unit"`
	Quantity    decimal.Decimal `json:"quantity"`
	Rate        decimal.Decimal `json:"rate"`
}

// ContractInput is a client contract as signed.
type ContractInput struct {
	ProjectID          string          `json:"project_id"`
	CustomerID         string          `json:"customer_id"`
	Title              string          `json:"title"`
	ClientReference    string          `json:"client_reference"`
	SignedOn           time.Time       `json:"-"`
	RetentionPct       decimal.Decimal `json:"retention_pct"`
	AdvanceAmount      decimal.Decimal `json:"advance_amount"`
	AdvanceRecoveryPct decimal.Decimal `json:"advance_recovery_pct"`
	Lines              []ContractLine  `json:"lines"`
}

// CreateContract records a DRAFT client contract.
func (s *Service) CreateContract(ctx context.Context, p auth.Principal, in ContractInput) (string, error) {
	if len(in.Lines) == 0 {
		return "", fmt.Errorf("%w: a contract has at least one line", ErrInvalidInput)
	}
	if err := s.authz.RequireProject(p, auth.PermContractManage, p.TenantID, in.ProjectID); err != nil {
		return "", err
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermContractManage, func(ctx context.Context, tx pgx.Tx) error {
		num, err := postgres.NextNumber(ctx, tx, "CTR")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO contracts(legal_entity_id, project_id, customer_id, number, title, client_reference, signed_on,
			currency, retention_pct, advance_amount, advance_recovery_pct, created_by)
			SELECT pr.legal_entity_id, pr.id, $2::uuid, $3, $4, $5, $6, le.functional_currency, $7, $8, $9, $10
			  FROM projects pr JOIN legal_entities le ON le.id = pr.legal_entity_id WHERE pr.id = $1::uuid RETURNING id::text`,
			in.ProjectID, in.CustomerID, num, strings.TrimSpace(in.Title), strings.TrimSpace(in.ClientReference), in.SignedOn,
			in.RetentionPct, in.AdvanceAmount, in.AdvanceRecoveryPct, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, l := range in.Lines {
			var boq *string
			if l.BOQItemID != "" {
				boq = &l.BOQItemID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO contract_lines(contract_id, line_no, boq_item_id, description, unit, quantity, rate) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7)`,
				id, l.LineNo, boq, l.Description, l.Unit, l.Quantity, l.Rate); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "contract.create", "contract", id, "contract.created", map[string]any{"contract_id": id, "number": num})
	})
	return id, err
}

// SubmitContract submits a DRAFT contract for approval (its author only).
func (s *Service) SubmitContract(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermContractManage, "contract", "contracts", id, "contract.submit", "contract.submitted")
}

// DecideContract activates (MFA) or rejects a submitted contract.
func (s *Service) DecideContract(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if approve {
		if err := s.authz.RequireStepUp(p); err != nil {
			return err
		}
	} else if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermContractApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermContractApprove, "contract", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "contract"); err != nil {
			return err
		}
		next := map[bool]string{true: "ACTIVE", false: "REJECTED"}[approve]
		if err := s.authorize(ctx, tx, p, "contract.decide", "contract", id, next); err != nil {
			return err
		}
		if approve {
			err = postgres.Exec1(ctx, tx, `UPDATE contracts SET status = 'ACTIVE', approved_by = $2, decision_reason = NULLIF($3, '') WHERE id = $1::uuid`, id, p.UserID, reason)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE contracts SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, reason)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "contract.decide", "contract", id, "contract."+strings.ToLower(next), map[string]any{"contract_id": id})
	})
}

// MeasurementLine is a quantity measured on site for a contract line.
type MeasurementLine struct {
	ContractLineNo int             `json:"contract_line_no"`
	Quantity       decimal.Decimal `json:"quantity"`
	Location       string          `json:"location,omitempty"`
}

// CreateMeasurement records a DRAFT measurement sheet for a period.
func (s *Service) CreateMeasurement(ctx context.Context, p auth.Principal, contractID string, periodEnd time.Time, lines []MeasurementLine) (string, error) {
	if len(lines) == 0 {
		return "", fmt.Errorf("%w: a measurement has at least one line", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermMeasureCreate, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermMeasureCreate, "contract", contractID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "MS")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO measurements(contract_id, number, period_end, created_by) VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
			contractID, num, periodEnd, p.UserID)
		if err != nil {
			return err
		}
		for _, l := range lines {
			var loc *string
			if strings.TrimSpace(l.Location) != "" {
				loc = &l.Location
			}
			if _, err := tx.Exec(ctx, `INSERT INTO measurement_lines(measurement_id, contract_line_no, quantity, location) VALUES ($1::uuid, $2, $3, $4)`,
				id, l.ContractLineNo, l.Quantity, loc); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "measure.create", "measurement", id, "measurement.created", map[string]any{"measurement_id": id, "contract_id": contractID})
	})
	return id, err
}

// SubmitMeasurement submits a DRAFT measurement (its author only).
func (s *Service) SubmitMeasurement(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermMeasureCreate, "measurement", "measurements", id, "measure.submit", "measurement.submitted")
}

// DecideMeasurement verifies (cumulative quantities checked against the
// contract by the database) or rejects a submitted measurement.
func (s *Service) DecideMeasurement(ctx context.Context, p auth.Principal, id string, verify bool, reason string) error {
	if !verify {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermMeasureVerify, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermMeasureVerify, "measurement", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "measurement"); err != nil {
			return err
		}
		next := map[bool]string{true: "VERIFIED", false: "REJECTED"}[verify]
		if err := s.authorize(ctx, tx, p, "measure.verify", "measurement", id, next); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE measurements SET status = $2, verified_by = $3, decision_reason = NULLIF($4, '') WHERE id = $1::uuid`,
			id, next, p.UserID, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "measure.verify", "measurement", id, "measurement."+strings.ToLower(next), map[string]any{"measurement_id": id})
	})
}

// PrepareIPC creates a DRAFT interim payment certificate. Every amount is
// computed by the database from cumulative verified measurements, previous
// certificates, the contract terms and the contract policy.
func (s *Service) PrepareIPC(ctx context.Context, p auth.Principal, contractID string, periodEnd time.Time) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermIPCPrepare, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermIPCPrepare, "contract", contractID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "IPC")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO ipcs(contract_id, number, seq, period_end, currency, policy_id, created_by)
			SELECT c.id, $2, 1, $3, c.currency, c.policy_id, $4 FROM contracts c WHERE c.id = $1::uuid RETURNING id::text`, contractID, num, periodEnd, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		return s.record(ctx, tx, p, "ipc.prepare", "ipc", id, "ipc.prepared", map[string]any{"ipc_id": id, "contract_id": contractID, "number": num})
	})
	return id, err
}

// SubmitIPC submits a DRAFT IPC (its preparer only).
func (s *Service) SubmitIPC(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermIPCPrepare, "ipc", "ipcs", id, "ipc.submit", "ipc.submitted")
}

// CertifyIPC records the certification of a submitted IPC: a different
// person from the preparer, with fresh MFA, recording the client's
// certificate reference and the SHA-256 of the signed certificate file.
func (s *Service) CertifyIPC(ctx context.Context, p auth.Principal, id, certificateRef, certificateSHA256 string) error {
	if err := s.authz.RequireStepUp(p); err != nil {
		return err
	}
	certificateSHA256 = strings.ToLower(strings.TrimSpace(certificateSHA256))
	if b, err := hex.DecodeString(certificateSHA256); err != nil || len(b) != 32 || len(strings.TrimSpace(certificateRef)) < 3 {
		return fmt.Errorf("%w: certification needs the client's certificate reference and the SHA-256 of the signed certificate", ErrInvalidInput)
	}
	return s.p2pTx(ctx, p, auth.PermIPCCertify, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermIPCCertify, "ipc", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "IPC"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ipc.certify", "ipc", id, "CERTIFIED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE ipcs SET status = 'CERTIFIED', certified_by = $2, certificate_ref = $3, certificate_sha256 = $4 WHERE id = $1::uuid`,
			id, p.UserID, strings.TrimSpace(certificateRef), certificateSHA256); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ipc.certify", "ipc", id, "ipc.certified", map[string]any{"ipc_id": id, "certificate_ref": certificateRef})
	})
}

// RejectIPC rejects a submitted IPC; CancelIPC withdraws a draft or
// submitted one (e.g. when it became stale).
func (s *Service) RejectIPC(ctx context.Context, p auth.Principal, id, reason string) error {
	return s.closeIPC(ctx, p, auth.PermIPCCertify, id, "REJECTED", "ipc.certify", reason, "SUBMITTED")
}

// CancelIPC withdraws a DRAFT or SUBMITTED IPC.
func (s *Service) CancelIPC(ctx context.Context, p auth.Principal, id, reason string) error {
	perm := auth.PermIPCPrepare
	if !s.authz.Has(p, perm) {
		perm = auth.PermIPCCertify
	}
	return s.closeIPC(ctx, p, perm, id, "CANCELLED", "ipc.cancel", reason, "DRAFT", "SUBMITTED")
}

func (s *Service) closeIPC(ctx context.Context, p auth.Principal, perm auth.Permission, id, next, action, reason string, from ...string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "ipc", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, from...); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, action, "ipc", id, next); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE ipcs SET status = $2, decision_reason = $3 WHERE id = $1::uuid`, id, next, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "ipc", id, "ipc."+strings.ToLower(next), map[string]any{"ipc_id": id, "reason": reason})
	})
}

// IssueCustomerInvoice creates the DRAFT customer invoice of a certified IPC
// (all amounts are the certificate's).
func (s *Service) IssueCustomerInvoice(ctx context.Context, p auth.Principal, ipcID string, invoiceDate, dueDate time.Time) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermARInvoiceCreate, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermARInvoiceCreate, "ipc", ipcID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "CINV")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO customer_invoices(legal_entity_id, project_id, contract_id, customer_id, ipc_id, policy_id, number,
			invoice_date, due_date, currency, created_by)
			SELECT c.legal_entity_id, c.project_id, c.id, c.customer_id, i.id, i.policy_id, $2, $3, $4, i.currency, $5
			  FROM ipcs i JOIN contracts c ON c.id = i.contract_id WHERE i.id = $1::uuid RETURNING id::text`, ipcID, num, invoiceDate, dueDate, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		if err := s.authorize(ctx, tx, p, "ar.invoice.create", "customer_invoice", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.invoice.create", "customer_invoice", id, "ar.invoice_issued", map[string]any{"invoice_id": id, "ipc_id": ipcID, "number": num})
	})
	return id, err
}

// ApproveCustomerInvoice approves a DRAFT customer invoice, generates its AR
// journal and marks the IPC invoiced.
func (s *Service) ApproveCustomerInvoice(ctx context.Context, p auth.Principal, id string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermARInvoiceApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARInvoiceApprove, "customer_invoice", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "customer invoice"); err != nil {
			return err
		}
		var entity, ccy, num, ipc string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, number, invoice_date, ipc_id::text FROM customer_invoices WHERE id = $1::uuid`, id).Scan(
			&entity, &ccy, &num, &date, &ipc); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.invoice.approve", "customer_invoice", id, "APPROVED"); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "AR_INVOICE", id, entity, ccy, "Customer invoice "+num, date)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE customer_invoices SET status = 'APPROVED', approved_by = $2, journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE ipcs SET status = 'INVOICED' WHERE id = $1::uuid`, ipc); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.invoice.approve", "customer_invoice", id, "ar.invoice_approved", map[string]any{"invoice_id": id, "journal_id": jid})
	})
	return jid, err
}

// ReceiptAllocation applies part of a receipt to one customer invoice or to
// one contract's advance.
type ReceiptAllocation struct {
	InvoiceID  string          `json:"invoice_id,omitempty"`
	ContractID string          `json:"contract_id,omitempty"`
	Amount     decimal.Decimal `json:"amount"`
}

// RecordReceipt records a DRAFT receipt for a money-in statement line with
// its allocations. The amount is the statement line's.
func (s *Service) RecordReceipt(ctx context.Context, p auth.Principal, statementLineID string, allocs []ReceiptAllocation) (string, error) {
	if len(allocs) == 0 {
		return "", fmt.Errorf("%w: a receipt is allocated to at least one invoice or contract advance", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermARReceiptCreate, func(ctx context.Context, tx pgx.Tx) error {
		if !s.tenantWide(p) {
			return fmt.Errorf("%w: receipts need tenant-wide scope", auth.ErrForbidden)
		}
		num, err := postgres.NextNumber(ctx, tx, "RCPT")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO customer_receipts(legal_entity_id, number, statement_line_id, company_bank_id, receipt_date, currency, created_by)
			SELECT b.legal_entity_id, $2, l.id, b.id, l.booking_date, b.currency, $3
			  FROM bank_statement_lines l JOIN bank_statements st ON st.id = l.statement_id JOIN company_bank_accounts b ON b.id = st.company_bank_id
			 WHERE l.id = $1::uuid RETURNING id::text`, statementLineID, num, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for i, a := range allocs {
			var inv, ctr *string
			if a.InvoiceID != "" {
				inv = &allocs[i].InvoiceID
			}
			if a.ContractID != "" {
				ctr = &allocs[i].ContractID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO receipt_allocations(receipt_id, line_no, invoice_id, contract_id, amount) VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5)`,
				id, i+1, inv, ctr, a.Amount); err != nil {
				return err
			}
		}
		// The whole amount received is applied (the database checks it again
		// at confirmation): an unapplied remainder would leave cash without a
		// receivable to clear.
		var amount, applied decimal.Decimal
		if err := tx.QueryRow(ctx, `SELECT r.amount, COALESCE((SELECT sum(a.amount) FROM receipt_allocations a WHERE a.receipt_id = r.id), 0)
			FROM customer_receipts r WHERE r.id = $1::uuid`, id).Scan(&amount, &applied); err != nil {
			return err
		}
		if !amount.Equal(applied) {
			return fmt.Errorf("%w: allocations (%s) must equal the amount received (%s)", ErrInvalidInput, applied, amount)
		}
		if err := s.authorize(ctx, tx, p, "ar.receipt.create", "customer_receipt", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.receipt.create", "customer_receipt", id, "ar.receipt_recorded", map[string]any{"receipt_id": id, "allocations": len(allocs)})
	})
	return id, err
}

// ConfirmReceipt confirms a DRAFT receipt (different person, independent of
// the statement import) and generates the receipt journal.
func (s *Service) ConfirmReceipt(ctx context.Context, p auth.Principal, id string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermARReceiptConfirm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermARReceiptConfirm, "customer_receipt", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "receipt"); err != nil {
			return err
		}
		var entity, ccy, num string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, number, receipt_date FROM customer_receipts WHERE id = $1::uuid`, id).Scan(&entity, &ccy, &num, &date); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ar.receipt.confirm", "customer_receipt", id, "CONFIRMED"); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "AR_RECEIPT", id, entity, ccy, "Customer receipt "+num, date)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE customer_receipts SET status = 'CONFIRMED', confirmed_by = $2, journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ar.receipt.confirm", "customer_receipt", id, "ar.receipt_confirmed", map[string]any{"receipt_id": id, "journal_id": jid})
	})
	return jid, err
}

// ContractPosition reports a contract's commercial position.
func (s *Service) ContractPosition(ctx context.Context, p auth.Principal, contractID string) (postgres.ContractPosition, error) {
	var out postgres.ContractPosition
	err := s.p2pTx(ctx, p, auth.PermP2PRead, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermP2PRead, "contract", contractID); err != nil {
			return err
		}
		var err error
		out, err = postgres.GetContractPosition(ctx, tx, contractID)
		return err
	})
	return out, err
}

// ARReconciliation compares the receivable subledgers with the GL.
func (s *Service) ARReconciliation(ctx context.Context, p auth.Principal, entity string) ([]postgres.ReconCheck, error) {
	if err := s.authz.Require(p, auth.PermJournalRead, p.TenantID); err != nil {
		return nil, err
	}
	if !s.tenantWide(p) {
		return nil, fmt.Errorf("%w: reconciliation needs tenant-wide scope", auth.ErrForbidden)
	}
	var out []postgres.ReconCheck
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ARReconciliation(ctx, tx, entity)
		return err
	})
	return out, err
}

// ProjectProfitability reports posted revenue, cost and margin of a project.
func (s *Service) ProjectProfitability(ctx context.Context, p auth.Principal, project string) (postgres.Profitability, error) {
	if err := s.authz.RequireProject(p, auth.PermJournalRead, p.TenantID, project); err != nil {
		return postgres.Profitability{}, err
	}
	var out postgres.Profitability
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ProjectProfitability(ctx, tx, project)
		return err
	})
	return out, err
}
