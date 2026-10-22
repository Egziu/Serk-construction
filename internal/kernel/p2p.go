package kernel

// Journey A: procure-to-pay (migration 0013, ADR 0009).
//
// Every command: authorise the caller (permission + project scope), sign
// exactly one attestation for exactly one transition, let the database
// enforce the state machine, the numbers and the separation of duties, and
// record audit + outbox in the same transaction. Subledger documents generate
// DRAFT journals from the database's own expected lines; finance approves and
// posts them through the ordinary attested journal commands.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// ErrBudgetExceeded: the document does not fit the approved budget.
var ErrBudgetExceeded = errors.New("kernel: approved budget exceeded")

// Doc is re-exported for callers.
type Doc = postgres.Doc

// p2pTx runs fn in the caller's tenant transaction after the permission check.
func (s *Service) p2pTx(ctx context.Context, p auth.Principal, perm auth.Permission, fn func(ctx context.Context, tx pgx.Tx) error) error {
	if err := s.authz.Require(p, perm, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, fn)
}

// docProject returns the project a document belongs to ("" for entity-level
// documents) so project scope (SC-05) applies to every P2P document.
func docProject(ctx context.Context, tx pgx.Tx, docType, id string) (string, error) {
	var q string
	switch docType {
	case "boq_version", "purchase_requisition", "purchase_order":
		q = map[string]string{"boq_version": "boq_versions", "purchase_requisition": "purchase_requisitions", "purchase_order": "purchase_orders"}[docType]
		q = `SELECT project_id::text FROM ` + q + ` WHERE id = $1::uuid`
	case "rfq":
		q = `SELECT r.project_id::text FROM rfqs q JOIN purchase_requisitions r ON r.id = q.pr_id WHERE q.id = $1::uuid`
	case "rfq_quote":
		q = `SELECT r.project_id::text FROM rfq_quotes x JOIN rfqs q ON q.id = x.rfq_id JOIN purchase_requisitions r ON r.id = q.pr_id WHERE x.id = $1::uuid`
	case "grn":
		q = `SELECT o.project_id::text FROM grns g JOIN purchase_orders o ON o.id = g.po_id WHERE g.id = $1::uuid`
	case "supplier_invoice":
		q = `SELECT o.project_id::text FROM supplier_invoices i JOIN purchase_orders o ON o.id = i.po_id WHERE i.id = $1::uuid`
	default:
		return "", nil
	}
	var pid string
	err := tx.QueryRow(ctx, q, id).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return pid, err
}

// loadDoc locks a document and enforces the principal's project scope for perm.
func (s *Service) loadDoc(ctx context.Context, tx pgx.Tx, p auth.Principal, perm auth.Permission, docType, id string) (postgres.Doc, error) {
	// perm was checked by p2pTx; visibility is the one policy in docscope.go.
	return s.visibleDoc(ctx, tx, p, docType, id, true)
}

func requireStatus(d postgres.Doc, want ...string) error {
	for _, w := range want {
		if d.Status == w {
			return nil
		}
	}
	return fmt.Errorf("%w: document is %s", ledger.ErrBadTransition, d.Status)
}

// GetP2PDoc returns a P2P document visible to the principal, as a
// reader-safe projection (bank account numbers masked; IA-040-01).
func (s *Service) GetP2PDoc(ctx context.Context, p auth.Principal, docType, id string) (postgres.Doc, error) {
	var d postgres.Doc
	err := s.p2pTx(ctx, p, auth.PermP2PRead, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if d, err = s.visibleDoc(ctx, tx, p, docType, id, false); err != nil {
			return err
		}
		d.Detail, err = projectDoc(docType, d.Detail)
		return err
	})
	return d, err
}

// subledgerJournal creates the DRAFT journal of a document from the
// database's expected lines. The database binds it to the document when the
// document transition is written (p2p_assert_journal).
func (s *Service) subledgerJournal(ctx context.Context, tx pgx.Tx, p auth.Principal, doc, docID, entity, ccy, description string, date time.Time) (string, error) {
	exp, err := postgres.ExpectedLines(ctx, tx, doc, docID)
	if err != nil {
		return "", err
	}
	j := ledger.Journal{TenantID: p.TenantID, LegalEntityID: entity, FunctionalCurrency: money.Currency(ccy),
		BusinessEventAt: date, Description: description, SourceType: doc, SourceRef: docID,
		IdempotencyKey: "p2p:" + doc + ":" + docID, CreatedBy: p.UserID}
	for _, l := range exp {
		// A document belongs to one project; the journal is scoped to it
		// (ledger rule: a line's project equals the journal's).
		if l.ProjectID != "" {
			if j.ProjectID != "" && j.ProjectID != l.ProjectID {
				return "", fmt.Errorf("%w: %s %s spans several projects", ErrInvalidInput, doc, docID)
			}
			j.ProjectID = l.ProjectID
		}
	}
	for i, l := range exp {
		amt, err := money.New(l.Amount, money.Currency(ccy), money.DefaultRounding)
		if err != nil {
			return "", err
		}
		j.Lines = append(j.Lines, ledger.Line{LineNo: i + 1, AccountID: l.AccountID, Side: ledger.Side(l.Side), Amount: amt,
			ProjectID: l.ProjectID, CostCodeID: l.CostCodeID})
	}
	id, replayed, err := postgres.CreateJournal(ctx, tx, j)
	if err != nil {
		return "", err
	}
	if !replayed {
		if err := s.record(ctx, tx, p, "journal.create", "journal", id, "journal.created",
			map[string]any{"journal_id": id, "source_type": doc, "source_ref": docID, "lines": len(j.Lines)}); err != nil {
			return "", err
		}
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// ProposeP2PPolicy creates a DRAFT policy version for an entity.
func (s *Service) ProposeP2PPolicy(ctx context.Context, p auth.Principal, pol postgres.P2PPolicy) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermP2PPolicyManage, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO p2p_policies(legal_entity_id, version, currency, price_tolerance_pct, over_receipt_pct, vat_rate,
			high_value_po_threshold, dual_payment_threshold, grni_account_id, ap_account_id, vat_input_account_id, ppv_account_id, created_by,
			dual_payment_window_days)
			SELECT $1::uuid, COALESCE(max(version), 0) + 1, (SELECT functional_currency FROM legal_entities WHERE id = $1::uuid), $2, $3, $4, $5, $6,
			       $7::uuid, $8::uuid, $9::uuid, $10::uuid, $11, COALESCE(NULLIF($12::int, 0), 30) FROM p2p_policies WHERE legal_entity_id = $1::uuid RETURNING id::text`,
			pol.LegalEntityID, pol.PriceTolerancePct, pol.OverReceiptPct, pol.VATRate, pol.HighValuePOThreshold, pol.DualPaymentThreshold,
			pol.GRNIAccountID, pol.APAccountID, pol.VATInputAccountID, pol.PPVAccountID, p.UserID, pol.DualPaymentWindowDays)
		if err != nil {
			return err
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "p2p.policy.create", "p2p_policy", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "p2p.policy.propose", "p2p_policy", id, "p2p.policy.proposed", map[string]any{"policy_id": id, "legal_entity_id": pol.LegalEntityID})
	})
	return id, err
}

// DecideP2PPolicy approves (retiring the previous version) or rejects.
func (s *Service) DecideP2PPolicy(ctx context.Context, p auth.Principal, id string, approve bool) error {
	return s.p2pTx(ctx, p, auth.PermP2PPolicyApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermP2PPolicyApprove, "p2p_policy", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "P2P policy"); err != nil {
			return err
		}
		outcome := map[bool]string{true: "APPROVED", false: "REJECTED"}[approve]
		if err := s.authorize(ctx, tx, p, "p2p.policy.decide", "p2p_policy", id, outcome); err != nil {
			return err
		}
		if approve {
			if _, err := tx.Exec(ctx, `UPDATE p2p_policies SET status = 'RETIRED' WHERE status = 'APPROVED'
				AND legal_entity_id = (SELECT legal_entity_id FROM p2p_policies WHERE id = $1::uuid)`, id); err != nil {
				return err
			}
			err = postgres.Exec1(ctx, tx, `UPDATE p2p_policies SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE p2p_policies SET status = 'REJECTED' WHERE id = $1::uuid`, id)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "p2p.policy.decide", "p2p_policy", id, "p2p.policy."+strings.ToLower(outcome), map[string]any{"policy_id": id})
	})
}

// ---------------------------------------------------------------------------
// Suppliers and bank accounts
// ---------------------------------------------------------------------------

// CreateSupplier registers a PENDING supplier.
func (s *Service) CreateSupplier(ctx context.Context, p auth.Principal, entity, code, name, taxID string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermSupplierManage, func(ctx context.Context, tx pgx.Tx) error {
		var tax *string
		if taxID != "" {
			tax = &taxID
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO suppliers(legal_entity_id, code, name, tax_id, created_by) VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
			entity, strings.ToUpper(strings.TrimSpace(code)), strings.TrimSpace(name), tax, p.UserID)
		if err != nil {
			return err
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "supplier.create", "supplier", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "supplier.create", "supplier", id, "supplier.created", map[string]any{"supplier_id": id, "code": code})
	})
	return id, err
}

// ApproveSupplier activates a supplier (maker/checker).
func (s *Service) ApproveSupplier(ctx context.Context, p auth.Principal, id string) error {
	return s.p2pTx(ctx, p, auth.PermSupplierApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermSupplierApprove, "supplier", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING", "BLOCKED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "supplier"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "supplier.approve", "supplier", id, "ACTIVE"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE suppliers SET status = 'ACTIVE', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "supplier.approve", "supplier", id, "supplier.activated", map[string]any{"supplier_id": id})
	})
}

// BlockSupplier stops all further business with a supplier.
func (s *Service) BlockSupplier(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermSupplierApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermSupplierApprove, "supplier", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "ACTIVE"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "supplier.block", "supplier", id, "BLOCKED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE suppliers SET status = 'BLOCKED', blocked_reason = $2 WHERE id = $1::uuid`, id, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "supplier.block", "supplier", id, "supplier.blocked", map[string]any{"supplier_id": id, "reason": reason})
	})
}

// AddSupplierBankAccount records new bank details, PENDING a second person.
func (s *Service) AddSupplierBankAccount(ctx context.Context, p auth.Principal, supplierID, bank, accountName, accountNumber, ccy string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermSupplierManage, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO supplier_bank_accounts(supplier_id, bank_name, account_name, account_number, currency, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6) RETURNING id::text`, supplierID, bank, accountName, strings.ToUpper(strings.ReplaceAll(accountNumber, " ", "")), ccy, p.UserID)
		if err != nil {
			return err
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "supplier.bank.create", "supplier_bank_account", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "supplier.bank.add", "supplier_bank_account", id, "supplier.bank_account.added",
			map[string]any{"supplier_id": supplierID, "bank_account_id": id, "account_last4": last4(accountNumber)})
	})
	return id, err
}

func last4(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) <= 4 {
		return s
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}

// ApproveSupplierBankAccount approves bank details (second person, MFA).
func (s *Service) ApproveSupplierBankAccount(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.RequireStepUp(p); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermSupplierBankApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermSupplierBankApprove, "supplier_bank_account", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "supplier bank account"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "supplier.bank.approve", "supplier_bank_account", id, "APPROVED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE supplier_bank_accounts SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "supplier.bank.approve", "supplier_bank_account", id, "supplier.bank_account.approved", map[string]any{"bank_account_id": id})
	})
}

// RegisterCompanyBankAccount records one of the entity's own bank accounts.
func (s *Service) RegisterCompanyBankAccount(ctx context.Context, p auth.Principal, entity, name, number, ccy, glAccount, clearingAccount string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermBankAcctManage, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO company_bank_accounts(legal_entity_id, name, account_number, currency, gl_account_id, clearing_account_id, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6::uuid, $7) RETURNING id::text`, entity, name, number, ccy, glAccount, clearingAccount, p.UserID)
		if err != nil {
			return err
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "bankacct.create", "company_bank_account", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "bankacct.register", "company_bank_account", id, "company_bank_account.registered", map[string]any{"bank_account_id": id})
	})
	return id, err
}

// ApproveCompanyBankAccount activates it (second person, MFA).
func (s *Service) ApproveCompanyBankAccount(ctx context.Context, p auth.Principal, id string) error {
	if err := s.authz.RequireStepUp(p); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermBankAcctApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermBankAcctApprove, "company_bank_account", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "company bank account"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "bankacct.approve", "company_bank_account", id, "ACTIVE"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE company_bank_accounts SET status = 'ACTIVE', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "bankacct.approve", "company_bank_account", id, "company_bank_account.activated", map[string]any{"bank_account_id": id})
	})
}

// ---------------------------------------------------------------------------
// BOQ
// ---------------------------------------------------------------------------

// BOQItem is one bill-of-quantities line.
type BOQItem struct {
	ItemNo      string          `json:"item_no"`
	Description string          `json:"description"`
	Unit        string          `json:"unit"`
	Quantity    decimal.Decimal `json:"quantity"`
	Rate        decimal.Decimal `json:"rate"`
	CostCodeID  string          `json:"cost_code_id"`
}

// CreateBOQ creates a DRAFT BOQ version with its items.
func (s *Service) CreateBOQ(ctx context.Context, p auth.Principal, projectID, description string, items []BOQItem) (string, error) {
	if err := s.authz.RequireProject(p, auth.PermBOQManage, p.TenantID, projectID); err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", fmt.Errorf("%w: a BOQ needs items", ErrInvalidInput)
	}
	var id string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO boq_versions(legal_entity_id, project_id, version, currency, description, created_by)
			SELECT pr.legal_entity_id, pr.id, COALESCE((SELECT max(version) FROM boq_versions WHERE project_id = pr.id), 0) + 1,
			       le.functional_currency, $2, $3
			  FROM projects pr JOIN legal_entities le ON le.id = pr.legal_entity_id WHERE pr.id = $1::uuid RETURNING id::text`,
			projectID, description, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, it := range items {
			if _, err := tx.Exec(ctx, `INSERT INTO boq_items(version_id, item_no, description, unit, quantity, rate, cost_code_id)
				VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid)`, id, it.ItemNo, it.Description, it.Unit, it.Quantity, it.Rate, it.CostCodeID); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "boq.create", "boq_version", id, "boq.created", map[string]any{"boq_version_id": id, "project_id": projectID, "items": len(items)})
	})
	return id, err
}

func mapNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// SubmitBOQ is the estimator's attested submission.
func (s *Service) SubmitBOQ(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermBOQManage, "boq_version", "boq_versions", id, "boq.submit", "boq.submitted")
}

// submitDoc is the common maker submission: only the creator, attested.
func (s *Service) submitDoc(ctx context.Context, p auth.Principal, perm auth.Permission, docType, table, id, action, event string) error {
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, docType, id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if d.CreatedBy != p.UserID {
			return fmt.Errorf("%w: only the author submits a %s", auth.ErrForbidden, docType)
		}
		if err := s.authorize(ctx, tx, p, action, docType, id, ""); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE `+table+` SET status = 'SUBMITTED' WHERE id = $1::uuid`, id); err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, docType, id, event, map[string]any{"id": id})
	})
}

// DecideBOQ approves (superseding the previous baseline) or rejects.
func (s *Service) DecideBOQ(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if !approve {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermBOQApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermBOQApprove, "boq_version", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "BOQ"); err != nil {
			return err
		}
		outcome := map[bool]string{true: "APPROVED", false: "REJECTED"}[approve]
		if err := s.authorize(ctx, tx, p, "boq.decide", "boq_version", id, outcome); err != nil {
			return err
		}
		if approve {
			if _, err := tx.Exec(ctx, `UPDATE boq_versions SET status = 'SUPERSEDED' WHERE status = 'APPROVED'
				AND project_id = (SELECT project_id FROM boq_versions WHERE id = $1::uuid)`, id); err != nil {
				return err
			}
			err = postgres.Exec1(ctx, tx, `UPDATE boq_versions SET status = 'APPROVED', approved_by = $2, decision_reason = NULLIF($3, '') WHERE id = $1::uuid`, id, p.UserID, reason)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE boq_versions SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, reason)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "boq.decide", "boq_version", id, "boq."+strings.ToLower(outcome), map[string]any{"boq_version_id": id, "reason": reason})
	})
}

// ---------------------------------------------------------------------------
// Purchase requisitions
// ---------------------------------------------------------------------------

// PRLine is one requisition line.
type PRLine struct {
	LineNo       int             `json:"line_no"`
	BOQItemID    string          `json:"boq_item_id,omitempty"`
	CostCodeID   string          `json:"cost_code_id"`
	Description  string          `json:"description"`
	Unit         string          `json:"unit"`
	Quantity     decimal.Decimal `json:"quantity"`
	EstUnitPrice decimal.Decimal `json:"est_unit_price"`
}

// CreatePR creates a DRAFT requisition.
func (s *Service) CreatePR(ctx context.Context, p auth.Principal, projectID, justification string, neededBy *time.Time, lines []PRLine) (string, error) {
	if err := s.authz.RequireProject(p, auth.PermPRCreate, p.TenantID, projectID); err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("%w: a requisition needs lines", ErrInvalidInput)
	}
	var id string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		num, err := postgres.NextNumber(ctx, tx, "PR")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO purchase_requisitions(legal_entity_id, project_id, number, currency, justification, needed_by, requested_by)
			SELECT pr.legal_entity_id, pr.id, $2, le.functional_currency, $3, $4, $5
			  FROM projects pr JOIN legal_entities le ON le.id = pr.legal_entity_id WHERE pr.id = $1::uuid RETURNING id::text`,
			projectID, num, justification, neededBy, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, l := range lines {
			var boq *string
			if l.BOQItemID != "" {
				boq = &l.BOQItemID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pr_lines(pr_id, line_no, boq_item_id, cost_code_id, description, unit, quantity, est_unit_price)
				VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6, $7, $8)`, id, l.LineNo, boq, l.CostCodeID, l.Description, l.Unit, l.Quantity, l.EstUnitPrice); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "pr.create", "purchase_requisition", id, "pr.created", map[string]any{"pr_id": id, "number": num, "project_id": projectID})
	})
	return id, err
}

// SubmitPR is the requester's attested submission.
func (s *Service) SubmitPR(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermPRCreate, "purchase_requisition", "purchase_requisitions", id, "pr.submit", "pr.submitted")
}

// DecidePR approves (budget-checked by the database) or rejects.
func (s *Service) DecidePR(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if !approve {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermPRApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermPRApprove, "purchase_requisition", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "requisition"); err != nil {
			return err
		}
		if approve {
			short, err := postgres.BudgetShortfall(ctx, tx, id, "")
			if err != nil {
				return err
			}
			if short != "" {
				return fmt.Errorf("%w: %s", ErrBudgetExceeded, short)
			}
		}
		outcome := map[bool]string{true: "APPROVED", false: "REJECTED"}[approve]
		if err := s.authorize(ctx, tx, p, "pr.decide", "purchase_requisition", id, outcome); err != nil {
			return err
		}
		if approve {
			err = postgres.Exec1(ctx, tx, `UPDATE purchase_requisitions SET status = 'APPROVED', approved_by = $2, decision_reason = NULLIF($3, '') WHERE id = $1::uuid`, id, p.UserID, reason)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE purchase_requisitions SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, reason)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "pr.decide", "purchase_requisition", id, "pr."+strings.ToLower(outcome), map[string]any{"pr_id": id, "reason": reason})
	})
}

// ---------------------------------------------------------------------------
// RFQ
// ---------------------------------------------------------------------------

// CreateRFQ drafts an RFQ for an approved requisition and invites suppliers.
func (s *Service) CreateRFQ(ctx context.Context, p auth.Principal, prID string, dueAt time.Time, minSuppliers int, singleSourceReason string, supplierIDs []string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermRFQManage, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermRFQManage, "purchase_requisition", prID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "RFQ")
		if err != nil {
			return err
		}
		if minSuppliers == 0 {
			minSuppliers = 3
		}
		var ssr *string
		if singleSourceReason != "" {
			ssr = &singleSourceReason
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO rfqs(pr_id, number, due_at, min_suppliers, single_source_reason, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6) RETURNING id::text`, prID, num, dueAt, minSuppliers, ssr, p.UserID)
		if err != nil {
			return err
		}
		for _, sup := range supplierIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO rfq_suppliers(rfq_id, supplier_id) VALUES ($1::uuid, $2::uuid)`, id, sup); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "rfq.create", "rfq", id, "rfq.created", map[string]any{"rfq_id": id, "number": num, "pr_id": prID, "invited": len(supplierIDs)})
	})
	return id, err
}

// IssueRFQ is the buyer's attested issue to the invited suppliers.
func (s *Service) IssueRFQ(ctx context.Context, p auth.Principal, id string) error {
	return s.p2pTx(ctx, p, auth.PermRFQManage, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermRFQManage, "rfq", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if d.CreatedBy != p.UserID {
			return fmt.Errorf("%w: only the author issues an RFQ", auth.ErrForbidden)
		}
		if err := s.authorize(ctx, tx, p, "rfq.issue", "rfq", id, ""); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE rfqs SET status = 'ISSUED' WHERE id = $1::uuid`, id); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "rfq.issue", "rfq", id, "rfq.issued", map[string]any{"rfq_id": id})
	})
}

// QuoteLine is a supplier's price for a requisition line.
type QuoteLine struct {
	PRLineNo  int             `json:"pr_line_no"`
	UnitPrice decimal.Decimal `json:"unit_price"`
}

// RecordQuote records a supplier quote received for an issued RFQ.
func (s *Service) RecordQuote(ctx context.Context, p auth.Principal, rfqID, supplierID string, validUntil time.Time, supplierRef string, lines []QuoteLine) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermRFQManage, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermRFQManage, "rfq", rfqID); err != nil {
			return err
		}
		var ref *string
		if supplierRef != "" {
			ref = &supplierRef
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO rfq_quotes(rfq_id, supplier_id, currency, valid_until, supplier_reference, received_by)
			SELECT $1::uuid, $2::uuid, r.currency, $3, $4, $5 FROM rfqs q JOIN purchase_requisitions r ON r.id = q.pr_id WHERE q.id = $1::uuid RETURNING id::text`,
			rfqID, supplierID, validUntil, ref, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, l := range lines {
			if _, err := tx.Exec(ctx, `INSERT INTO rfq_quote_lines(quote_id, pr_line_no, unit_price) VALUES ($1::uuid, $2, $3)`, id, l.PRLineNo, l.UnitPrice); err != nil {
				return err
			}
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "rfq.quote.record", "rfq_quote", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "rfq.quote", "rfq_quote", id, "rfq.quote_received", map[string]any{"rfq_id": rfqID, "quote_id": id, "supplier_id": supplierID})
	})
	return id, err
}

// EvaluateQuote records the technical evaluation (not by the person who
// received the quote).
func (s *Service) EvaluateQuote(ctx context.Context, p auth.Principal, quoteID string, compliant bool, note string) error {
	return s.p2pTx(ctx, p, auth.PermRFQEvaluate, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermRFQEvaluate, "rfq_quote", quoteID)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "PENDING"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "quote"); err != nil {
			return err
		}
		outcome := map[bool]string{true: "COMPLIANT", false: "NON_COMPLIANT"}[compliant]
		if err := s.authorize(ctx, tx, p, "rfq.evaluate", "rfq_quote", quoteID, outcome); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE rfq_quotes SET technical_status = $2, technical_note = NULLIF($3, ''), evaluated_by = $4 WHERE id = $1::uuid`,
			quoteID, outcome, note, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "rfq.evaluate", "rfq_quote", quoteID, "rfq.quote_evaluated", map[string]any{"quote_id": quoteID, "result": outcome})
	})
}

// AwardRFQ awards a compliant quote (reason required unless it is the lowest).
func (s *Service) AwardRFQ(ctx context.Context, p auth.Principal, rfqID, quoteID, reason string) error {
	return s.p2pTx(ctx, p, auth.PermRFQAward, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermRFQAward, "rfq", rfqID)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "ISSUED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "RFQ"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "rfq.award", "rfq", rfqID, quoteID); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE rfqs SET status = 'AWARDED', awarded_quote_id = $2::uuid, awarded_by = $3, award_reason = NULLIF($4, '') WHERE id = $1::uuid`,
			rfqID, quoteID, p.UserID, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "rfq.award", "rfq", rfqID, "rfq.awarded", map[string]any{"rfq_id": rfqID, "quote_id": quoteID, "reason": reason})
	})
}

// ---------------------------------------------------------------------------
// Purchase orders
// ---------------------------------------------------------------------------

// CreatePOFromAward raises a DRAFT PO from an awarded RFQ. accounts maps each
// requisition line number to the GL account it is costed to (expense or
// inventory); price, quantity and cost code come from the award.
func (s *Service) CreatePOFromAward(ctx context.Context, p auth.Principal, rfqID string, accounts map[int]string) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermPOManage, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermPOManage, "rfq", rfqID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "PO")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO purchase_orders(legal_entity_id, project_id, number, rfq_id, quote_id, supplier_id, currency, created_by)
			SELECT r.legal_entity_id, r.project_id, $2, q.id, qt.id, qt.supplier_id, qt.currency, $3
			  FROM rfqs q JOIN purchase_requisitions r ON r.id = q.pr_id JOIN rfq_quotes qt ON qt.id = q.awarded_quote_id
			 WHERE q.id = $1::uuid RETURNING id::text`, rfqID, num, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		rows, err := tx.Query(ctx, `SELECT pl.line_no FROM pr_lines pl JOIN rfqs q ON q.pr_id = pl.pr_id WHERE q.id = $1::uuid ORDER BY pl.line_no`, rfqID)
		if err != nil {
			return err
		}
		var lineNos []int
		for rows.Next() {
			var n int
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return err
			}
			lineNos = append(lineNos, n)
		}
		rows.Close()
		for _, n := range lineNos {
			acct, ok := accounts[n]
			if !ok {
				return fmt.Errorf("%w: no GL account given for requisition line %d", ErrInvalidInput, n)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO po_lines(po_id, line_no, legal_entity_id, cost_code_id, account_id, description, unit, quantity, unit_price)
				SELECT $1::uuid, pl.line_no, o.legal_entity_id, pl.cost_code_id, $3::uuid, pl.description, pl.unit, pl.quantity, ql.unit_price
				  FROM purchase_orders o JOIN rfqs q ON q.id = o.rfq_id JOIN pr_lines pl ON pl.pr_id = q.pr_id AND pl.line_no = $2
				  JOIN rfq_quote_lines ql ON ql.quote_id = o.quote_id AND ql.pr_line_no = pl.line_no
				 WHERE o.id = $1::uuid`, id, n, acct); err != nil {
				return err
			}
		}
		// The creator is bound by an attestation over the created content,
		// consumed by the database at commit (0014, review 3 H1).
		if err := s.authorize(ctx, tx, p, "po.create", "purchase_order", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "po.create", "purchase_order", id, "po.created", map[string]any{"po_id": id, "number": num, "rfq_id": rfqID})
	})
	return id, err
}

// ApprovePO approves a PO. Over budget, the approver must hold
// budget.override, have a recent MFA and give a reason; high-value POs need
// approval.high_value with MFA (both enforced by the database).
func (s *Service) ApprovePO(ctx context.Context, p auth.Principal, id, overrideReason string) error {
	return s.p2pTx(ctx, p, auth.PermPOApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermPOApprove, "purchase_order", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "purchase order"); err != nil {
			return err
		}
		short, err := postgres.BudgetShortfall(ctx, tx, "", id)
		if err != nil {
			return err
		}
		outcome := "APPROVED"
		if short != "" {
			if overrideReason == "" || !s.authz.Has(p, auth.PermBudgetOverride) {
				return fmt.Errorf("%w: %s", ErrBudgetExceeded, short)
			}
			if err := s.authz.RequireStepUp(p); err != nil {
				return err
			}
			outcome = "APPROVED_OVER_BUDGET"
			if _, err := tx.Exec(ctx, `UPDATE purchase_orders SET budget_override_reason = $2 WHERE id = $1::uuid`, id, overrideReason); err != nil {
				return err
			}
		}
		if err := s.authorize(ctx, tx, p, "po.approve", "purchase_order", id, outcome); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE purchase_orders SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "po.approve", "purchase_order", id, "po.approved", map[string]any{"po_id": id, "over_budget": short != "", "budget_note": short})
	})
}

// ---------------------------------------------------------------------------
// Goods receipts
// ---------------------------------------------------------------------------

// GRNLine is a received quantity for a PO line.
type GRNLine struct {
	POLineNo    int             `json:"po_line_no"`
	QtyReceived decimal.Decimal `json:"qty_received"`
	Note        string          `json:"note,omitempty"`
}

// CreateGRN records a DRAFT goods receipt.
func (s *Service) CreateGRN(ctx context.Context, p auth.Principal, poID string, receivedOn time.Time, deliveryNote string, lines []GRNLine) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermGRNCreate, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermGRNCreate, "purchase_order", poID); err != nil {
			return err
		}
		num, err := postgres.NextNumber(ctx, tx, "GRN")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO grns(po_id, number, received_on, delivery_note_ref, created_by) VALUES ($1::uuid, $2, $3, $4, $5) RETURNING id::text`,
			poID, num, receivedOn, deliveryNote, p.UserID)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if _, err := tx.Exec(ctx, `INSERT INTO grn_lines(grn_id, po_line_no, qty_received, note) VALUES ($1::uuid, $2, $3, NULLIF($4, ''))`, id, l.POLineNo, l.QtyReceived, l.Note); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "grn.create", "grn", id, "grn.created", map[string]any{"grn_id": id, "number": num, "po_id": poID})
	})
	return id, err
}

// SubmitGRN is the storekeeper's attested submission.
func (s *Service) SubmitGRN(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermGRNCreate, "grn", "grns", id, "grn.submit", "grn.submitted")
}

// ConfirmGRN confirms a receipt (second person) and generates its accrual
// journal (Dr cost/inventory, Cr GRNI) as DRAFT for finance.
func (s *Service) ConfirmGRN(ctx context.Context, p auth.Principal, id string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermGRNConfirm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermGRNConfirm, "grn", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "goods receipt"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "grn.confirm", "grn", id, "CONFIRMED"); err != nil {
			return err
		}
		var entity, ccy, num string
		var on time.Time
		if err := tx.QueryRow(ctx, `SELECT o.legal_entity_id::text, o.currency, g.number, g.received_on FROM grns g JOIN purchase_orders o ON o.id = g.po_id WHERE g.id = $1::uuid`, id).
			Scan(&entity, &ccy, &num, &on); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "P2P_GRN", id, entity, ccy, "Goods receipt "+num, on)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE grns SET status = 'CONFIRMED', confirmed_by = $2, journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "grn.confirm", "grn", id, "grn.confirmed", map[string]any{"grn_id": id, "journal_id": jid})
	})
	return jid, err
}

// ---------------------------------------------------------------------------
// Supplier invoices
// ---------------------------------------------------------------------------

// InvoiceInput is a supplier invoice as keyed by AP.
type InvoiceInput struct {
	POID          string          `json:"po_id"`
	InvoiceNumber string          `json:"invoice_number"`
	InvoiceDate   time.Time       `json:"invoice_date"`
	DueDate       time.Time       `json:"due_date"`
	Subtotal      decimal.Decimal `json:"subtotal"`
	TaxAmount     decimal.Decimal `json:"tax_amount"`
	Total         decimal.Decimal `json:"total"`
	Lines         []InvoiceLine   `json:"lines"`
}

// InvoiceLine is an invoiced quantity and price for a PO line.
type InvoiceLine struct {
	POLineNo  int             `json:"po_line_no"`
	Quantity  decimal.Decimal `json:"quantity"`
	UnitPrice decimal.Decimal `json:"unit_price"`
}

// EnterInvoice records a DRAFT invoice.
func (s *Service) EnterInvoice(ctx context.Context, p auth.Principal, in InvoiceInput) (string, error) {
	var id string
	err := s.p2pTx(ctx, p, auth.PermAPEnter, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := s.loadDoc(ctx, tx, p, auth.PermAPEnter, "purchase_order", in.POID); err != nil {
			return err
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO supplier_invoices(supplier_id, po_id, invoice_number, invoice_date, due_date, currency, subtotal, tax_amount, total, entered_by)
			SELECT o.supplier_id, o.id, $2, $3, $4, o.currency, $5, $6, $7, $8 FROM purchase_orders o WHERE o.id = $1::uuid RETURNING id::text`,
			in.POID, in.InvoiceNumber, in.InvoiceDate, in.DueDate, in.Subtotal, in.TaxAmount, in.Total, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, l := range in.Lines {
			if _, err := tx.Exec(ctx, `INSERT INTO invoice_lines(invoice_id, po_line_no, quantity, unit_price) VALUES ($1::uuid, $2, $3, $4)`, id, l.POLineNo, l.Quantity, l.UnitPrice); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "ap.enter", "supplier_invoice", id, "ap.invoice_entered", map[string]any{"invoice_id": id, "po_id": in.POID, "total": in.Total})
	})
	return id, err
}

// SubmitInvoice submits for 3-way matching; returns MATCHED or EXCEPTION.
func (s *Service) SubmitInvoice(ctx context.Context, p auth.Principal, id string) (string, error) {
	if err := s.submitDoc(ctx, p, auth.PermAPEnter, "supplier_invoice", "supplier_invoices", id, "ap.submit", "ap.invoice_submitted"); err != nil {
		return "", err
	}
	var st string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT match_status FROM supplier_invoices WHERE id = $1::uuid`, id).Scan(&st)
	})
	return st, err
}

// ApproveInvoice approves a matched invoice (or, with ap.approve_exception,
// MFA and a reason, a match exception) and generates its AP journal.
func (s *Service) ApproveInvoice(ctx context.Context, p auth.Principal, id, exceptionReason string) (string, error) {
	var jid string
	err := s.p2pTx(ctx, p, auth.PermAPApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermAPApprove, "supplier_invoice", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "invoice"); err != nil {
			return err
		}
		var match, entity, ccy, num string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT i.match_status, o.legal_entity_id::text, i.currency, i.invoice_number, i.invoice_date
			FROM supplier_invoices i JOIN purchase_orders o ON o.id = i.po_id WHERE i.id = $1::uuid`, id).Scan(&match, &entity, &ccy, &num, &date); err != nil {
			return err
		}
		if match == "EXCEPTION" {
			if !s.authz.Has(p, auth.PermAPApproveException) {
				return fmt.Errorf("%w: the invoice is a match exception; approval needs ap.approve_exception", auth.ErrForbidden)
			}
			if err := s.authz.RequireStepUp(p); err != nil {
				return err
			}
			if len(strings.TrimSpace(exceptionReason)) < 20 {
				return fmt.Errorf("%w: approving a match exception needs a reason of 20+ characters", ErrInvalidInput)
			}
		}
		if err := s.authorize(ctx, tx, p, "ap.approve", "supplier_invoice", id, match); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "P2P_INVOICE", id, entity, ccy, "Supplier invoice "+num, date)
		if err != nil {
			return err
		}
		if match != "EXCEPTION" {
			exceptionReason = ""
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE supplier_invoices SET status = 'APPROVED', approved_by = $2, exception_reason = NULLIF($3, ''), journal_id = $4::uuid WHERE id = $1::uuid`,
			id, p.UserID, exceptionReason, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ap.approve", "supplier_invoice", id, "ap.invoice_approved", map[string]any{"invoice_id": id, "match": match, "journal_id": jid})
	})
	return jid, err
}

// RejectInvoice rejects a submitted invoice.
func (s *Service) RejectInvoice(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermAPApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermAPApprove, "supplier_invoice", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "ap.reject", "supplier_invoice", id, ""); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE supplier_invoices SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "ap.reject", "supplier_invoice", id, "ap.invoice_rejected", map[string]any{"invoice_id": id, "reason": reason})
	})
}

// ---------------------------------------------------------------------------
// Payments (instructions only: nothing here moves money)
// ---------------------------------------------------------------------------

// Allocation pays an amount of one approved invoice.
type Allocation struct {
	InvoiceID string          `json:"invoice_id"`
	Amount    decimal.Decimal `json:"amount"`
}

// PreparePayment drafts a payment instruction for approved invoices.
func (s *Service) PreparePayment(ctx context.Context, p auth.Principal, entity, supplierID, supplierBankID, companyBankID string, valueDate time.Time, allocs []Allocation) (string, error) {
	if len(allocs) == 0 {
		return "", fmt.Errorf("%w: a payment pays at least one invoice", ErrInvalidInput)
	}
	total := decimal.Zero
	for _, a := range allocs {
		total = total.Add(a.Amount)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermPaymentPrepare, func(ctx context.Context, tx pgx.Tx) error {
		if !s.authz.Has(p, auth.PermScopeTenantWide) {
			return fmt.Errorf("%w: payments are entity-level and need tenant-wide scope", auth.ErrForbidden)
		}
		num, err := postgres.NextNumber(ctx, tx, "PAY")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO payment_instructions(legal_entity_id, number, supplier_id, supplier_bank_id, bank_snapshot, company_bank_id, currency, amount, value_date, created_by)
			SELECT $1::uuid, $2, $3::uuid, $4::uuid, '', $5::uuid, b.currency, $6, $7, $8 FROM company_bank_accounts b WHERE b.id = $5::uuid RETURNING id::text`,
			entity, num, supplierID, supplierBankID, companyBankID, total, valueDate, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, a := range allocs {
			if _, err := tx.Exec(ctx, `INSERT INTO payment_allocations(payment_id, invoice_id, amount) VALUES ($1::uuid, $2::uuid, $3)`, id, a.InvoiceID, a.Amount); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "payment.prepare", "payment_instruction", id, "payment.prepared", map[string]any{"payment_id": id, "number": num, "amount": total})
	})
	return id, err
}

// SubmitPayment is the preparer's attested submission.
func (s *Service) SubmitPayment(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermPaymentPrepare, "payment_instruction", "payment_instructions", id, "payment.submit", "payment.submitted")
}

// ApprovePayment records one human approval (MFA). Below the policy's dual
// threshold one approval suffices; at or above it, two different approvers.
// Returns the resulting status.
func (s *Service) ApprovePayment(ctx context.Context, p auth.Principal, id string) (string, error) {
	if err := s.authz.RequireStepUp(p); err != nil {
		return "", err
	}
	var next string
	err := s.p2pTx(ctx, p, auth.PermPaymentApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermPaymentApprove, "payment_instruction", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED", "PARTIALLY_APPROVED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "payment"); err != nil {
			return err
		}
		var dual bool
		var first string
		// The database's own definition (amount, invoice total, supplier
		// exposure within the policy window; migration 0016).
		if err := tx.QueryRow(ctx, `SELECT p2p_payment_needs_dual_id($1::uuid), COALESCE(approved_by, '') FROM payment_instructions WHERE id = $1::uuid`,
			id).Scan(&dual, &first); err != nil {
			return err
		}
		if d.Status == "PARTIALLY_APPROVED" {
			if first == p.UserID {
				return fmt.Errorf("%w: the second approval must come from a different person", auth.ErrSoD)
			}
			next = "APPROVED"
			if err := s.authorize(ctx, tx, p, "payment.approve", "payment_instruction", id, next); err != nil {
				return err
			}
			err = postgres.Exec1(ctx, tx, `UPDATE payment_instructions SET status = 'APPROVED', second_approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			next = map[bool]string{true: "PARTIALLY_APPROVED", false: "APPROVED"}[dual]
			if err := s.authorize(ctx, tx, p, "payment.approve", "payment_instruction", id, next); err != nil {
				return err
			}
			err = postgres.Exec1(ctx, tx, `UPDATE payment_instructions SET status = $2, approved_by = $3 WHERE id = $1::uuid`, id, next, p.UserID)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "payment.approve", "payment_instruction", id, "payment.approved", map[string]any{"payment_id": id, "status": next})
	})
	return next, err
}

// ReleasePayment marks an approved instruction as released to the bank (MFA)
// and generates Dr AP / Cr payments-in-transit. No money moves here: the bank
// transfer itself is outside this system and is recognised on reconciliation.
func (s *Service) ReleasePayment(ctx context.Context, p auth.Principal, id string) (string, error) {
	if err := s.authz.RequireStepUp(p); err != nil {
		return "", err
	}
	var jid string
	err := s.p2pTx(ctx, p, auth.PermPaymentRelease, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermPaymentRelease, "payment_instruction", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "APPROVED"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "payment.release", "payment_instruction", id, "RELEASED"); err != nil {
			return err
		}
		var entity, ccy string
		var vd time.Time
		if err := tx.QueryRow(ctx, `SELECT legal_entity_id::text, currency, value_date FROM payment_instructions WHERE id = $1::uuid`, id).Scan(&entity, &ccy, &vd); err != nil {
			return err
		}
		jid, err = s.subledgerJournal(ctx, tx, p, "P2P_PAYMENT", id, entity, ccy, "Payment "+d.Number, vd)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE payment_instructions SET status = 'RELEASED', released_by = $2, release_journal_id = $3::uuid WHERE id = $1::uuid`, id, p.UserID, jid); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "payment.release", "payment_instruction", id, "payment.released", map[string]any{"payment_id": id, "journal_id": jid})
	})
	return jid, err
}

// CancelPayment cancels an instruction that has not been released.
func (s *Service) CancelPayment(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	perm := auth.PermPaymentPrepare
	if !s.authz.Has(p, perm) {
		perm = auth.PermPaymentApprove
	}
	return s.p2pTx(ctx, p, perm, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, perm, "payment_instruction", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT", "SUBMITTED", "PARTIALLY_APPROVED", "APPROVED"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "payment.cancel", "payment_instruction", id, ""); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE payment_instructions SET status = 'CANCELLED', cancel_reason = $2 WHERE id = $1::uuid`, id, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "payment.cancel", "payment_instruction", id, "payment.cancelled", map[string]any{"payment_id": id, "reason": reason})
	})
}

// ---------------------------------------------------------------------------
// Bank statements and reconciliation
// ---------------------------------------------------------------------------

// StatementLine is one line of an imported bank statement.
type StatementLine struct {
	BookingDate  time.Time       `json:"booking_date"`
	Amount       decimal.Decimal `json:"amount"` // negative = money out
	Reference    string          `json:"reference"`
	Counterparty string          `json:"counterparty"`
}

// StatementInput is a statement parsed from its file. It is produced only by
// ParseStatement: lines are never accepted separately from the file bytes.
type StatementInput struct {
	CompanyBankID  string          `json:"company_bank_id"`
	StatementNo    string          `json:"statement_no"`
	StatementDate  time.Time       `json:"-"`
	OpeningBalance decimal.Decimal `json:"opening_balance"`
	ClosingBalance decimal.Decimal `json:"closing_balance"`
	Lines          []StatementLine `json:"-"`
	SourceSHA256   string          `json:"-"`
}

// statementFile is the SERK statement interchange format (JSON).
type statementFile struct {
	CompanyBankID  string          `json:"company_bank_id"`
	StatementNo    string          `json:"statement_no"`
	StatementDate  string          `json:"statement_date"`
	OpeningBalance decimal.Decimal `json:"opening_balance"`
	ClosingBalance decimal.Decimal `json:"closing_balance"`
	Lines          []struct {
		BookingDate  string          `json:"booking_date"`
		Amount       decimal.Decimal `json:"amount"`
		Reference    string          `json:"reference"`
		Counterparty string          `json:"counterparty"`
	} `json:"lines"`
}

const maxStatementLines = 5000

// ParseStatement parses a statement file strictly (unknown fields, trailing
// data, bad dates and more than 6 decimals are refused) and records the
// SHA-256 of the exact bytes.
func ParseStatement(raw []byte) (StatementInput, error) {
	var in StatementInput
	if len(raw) == 0 {
		return in, fmt.Errorf("%w: the statement file is empty", ErrInvalidInput)
	}
	if err := noDuplicateKeys(raw); err != nil {
		return in, fmt.Errorf("%w: statement file: %v", ErrInvalidInput, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f statementFile
	if err := dec.Decode(&f); err != nil {
		return in, fmt.Errorf("%w: statement file: %v", ErrInvalidInput, err)
	}
	if dec.More() {
		return in, fmt.Errorf("%w: statement file has trailing data", ErrInvalidInput)
	}
	if _, err := uuid.Parse(f.CompanyBankID); err != nil {
		return in, fmt.Errorf("%w: company_bank_id must be a bank account id", ErrInvalidInput)
	}
	if strings.TrimSpace(f.StatementNo) == "" || len(f.Lines) > maxStatementLines {
		return in, fmt.Errorf("%w: statement_no is required and a statement has at most %d lines", ErrInvalidInput, maxStatementLines)
	}
	date := func(v, what string) (time.Time, error) {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return t, fmt.Errorf("%w: %s %q must be YYYY-MM-DD", ErrInvalidInput, what, v)
		}
		return t, nil
	}
	limit := decimal.New(1, 18) // numeric(24,6): at most 18 integer digits
	six := func(d decimal.Decimal, what string) error {
		if d.Exponent() < -6 && !d.Equal(d.Round(6)) {
			return fmt.Errorf("%w: %s has more than 6 decimal places", ErrInvalidInput, what)
		}
		if d.Abs().GreaterThanOrEqual(limit) {
			return fmt.Errorf("%w: %s is out of range", ErrInvalidInput, what)
		}
		return nil
	}
	clean := func(v, what string) error {
		if strings.ContainsRune(v, 0) || !utf8.ValidString(v) || len(v) > 500 {
			return fmt.Errorf("%w: %s must be valid text of at most 500 bytes", ErrInvalidInput, what)
		}
		return nil
	}
	if err := clean(f.StatementNo, "statement_no"); err != nil {
		return in, err
	}
	var err error
	if in.StatementDate, err = date(f.StatementDate, "statement_date"); err != nil {
		return in, err
	}
	if err := six(f.OpeningBalance, "opening_balance"); err != nil {
		return in, err
	}
	if err := six(f.ClosingBalance, "closing_balance"); err != nil {
		return in, err
	}
	in.CompanyBankID, in.StatementNo = f.CompanyBankID, f.StatementNo
	in.OpeningBalance, in.ClosingBalance = f.OpeningBalance, f.ClosingBalance
	for i, l := range f.Lines {
		bd, err := date(l.BookingDate, fmt.Sprintf("line %d booking_date", i+1))
		if err != nil {
			return in, err
		}
		if err := six(l.Amount, fmt.Sprintf("line %d amount", i+1)); err != nil {
			return in, err
		}
		if l.Amount.IsZero() {
			return in, fmt.Errorf("%w: line %d amount is zero", ErrInvalidInput, i+1)
		}
		if err := clean(l.Reference, fmt.Sprintf("line %d reference", i+1)); err != nil {
			return in, err
		}
		if err := clean(l.Counterparty, fmt.Sprintf("line %d counterparty", i+1)); err != nil {
			return in, err
		}
		in.Lines = append(in.Lines, StatementLine{BookingDate: bd, Amount: l.Amount, Reference: l.Reference, Counterparty: l.Counterparty})
	}
	sum := sha256.Sum256(raw)
	in.SourceSHA256 = hex.EncodeToString(sum[:])
	return in, nil
}

// noDuplicateKeys refuses JSON objects that repeat a key: the statement must
// have one meaning, not "last value wins".
func noDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // next string token in an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, key: true})
			case '[':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top != nil && top.obj {
			if top.key {
				k, _ := tok.(string)
				if top.keys[k] {
					return fmt.Errorf("duplicate key %q", k)
				}
				top.keys[k] = true
				top.key = false
			} else {
				top.key = true
			}
		}
	}
}

// ContentDigest is the canonical digest of a parsed statement. The database
// computes the same digest from the stored rows (p2p_statement_digest) and
// refuses the import at commit unless it equals the attested one, so the
// stored lines are exactly the lines parsed from the attested file.
func (in StatementInput) ContentDigest() string {
	hx := func(v string) string { return hex.EncodeToString([]byte(v)) }
	var b strings.Builder
	b.WriteString(strings.Join([]string{"v1", in.CompanyBankID, hx(in.StatementNo), in.StatementDate.Format("2006-01-02"),
		in.OpeningBalance.StringFixed(6), in.ClosingBalance.StringFixed(6), in.SourceSHA256}, "|"))
	for i, l := range in.Lines {
		b.WriteString("\n")
		b.WriteString(strings.Join([]string{strconv.Itoa(i + 1), l.BookingDate.Format("2006-01-02"), l.Amount.StringFixed(6), hx(l.Reference), hx(l.Counterparty)}, "|"))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ImportBankStatement parses and stores a statement file. The attestation
// names the SHA-256 of the file and, in its context, the digest of the parsed
// content; the importer must be independent of every payment the statement
// later settles (enforced by the database at reconciliation).
func (s *Service) ImportBankStatement(ctx context.Context, p auth.Principal, raw []byte) (string, error) {
	in, err := ParseStatement(raw)
	if err != nil {
		return "", err
	}
	var id string
	err = s.p2pTx(ctx, p, auth.PermBankImport, func(ctx context.Context, tx pgx.Tx) error {
		if !s.authz.Has(p, auth.PermScopeTenantWide) {
			return fmt.Errorf("%w: bank statements need tenant-wide scope", auth.ErrForbidden)
		}
		if err := s.authorize(ctx, tx, p, "bank.import", "bank_statement_source", in.SourceSHA256, in.CompanyBankID+"|"+in.ContentDigest()); err != nil {
			return err
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO bank_statements(company_bank_id, statement_no, statement_date, opening_balance, closing_balance, source_sha256, imported_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7) RETURNING id::text`, in.CompanyBankID, in.StatementNo, in.StatementDate, in.OpeningBalance, in.ClosingBalance, in.SourceSHA256, p.UserID)
		if err != nil {
			return err
		}
		for i, l := range in.Lines {
			if _, err := tx.Exec(ctx, `INSERT INTO bank_statement_lines(statement_id, line_no, booking_date, amount, reference, counterparty) VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
				id, i+1, l.BookingDate, l.Amount, l.Reference, l.Counterparty); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, p, "bank.import", "bank_statement", id, "bank.statement_imported",
			map[string]any{"statement_id": id, "lines": len(in.Lines), "sha256": in.SourceSHA256})
	})
	return id, err
}

// ReconcileResult reports an automatic reconciliation run.
type ReconcileResult struct {
	Matched   []ReconMatch `json:"matched"`
	Unmatched []ReconMiss  `json:"unmatched"`
}

// ReconMatch is a statement line reconciled to a payment.
type ReconMatch struct {
	LineNo    int    `json:"line_no"`
	PaymentID string `json:"payment_id"`
	Payment   string `json:"payment_number"`
	JournalID string `json:"journal_id"`
}

// ReconMiss is a line left for manual investigation, with the reason.
type ReconMiss struct {
	LineNo int             `json:"line_no"`
	Amount decimal.Decimal `json:"amount"`
	Reason string          `json:"reason"`
}

// AutoReconcile proposes matches by rule (released payment from this
// account, same amount out, reference contains the payment number, exactly
// one candidate) and commits each under the reconciler's own attestation:
// automation finds, a person is accountable. Each line is its own
// transaction so one failure does not block the rest.
func (s *Service) AutoReconcile(ctx context.Context, p auth.Principal, statementID string) (ReconcileResult, error) {
	var res ReconcileResult
	if err := s.authz.Require(p, auth.PermBankReconcile, p.TenantID); err != nil {
		return res, err
	}
	if !s.authz.Has(p, auth.PermScopeTenantWide) {
		return res, fmt.Errorf("%w: reconciliation needs tenant-wide scope", auth.ErrForbidden)
	}
	type line struct {
		id     string
		no     int
		amount decimal.Decimal
		cands  []string
	}
	var lines []line
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT l.id::text, l.line_no, l.amount,
			  ARRAY(SELECT p.id::text FROM payment_instructions p
			         WHERE p.company_bank_id = s.company_bank_id AND p.status = 'RELEASED' AND p.amount = -l.amount
			           AND position(upper(p.number) IN upper(l.reference)) > 0)
			FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
			WHERE l.statement_id = $1::uuid AND l.status = 'UNMATCHED' ORDER BY l.line_no`, statementID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l line
			if err := rows.Scan(&l.id, &l.no, &l.amount, &l.cands); err != nil {
				return err
			}
			lines = append(lines, l)
		}
		return rows.Err()
	})
	if err != nil {
		return res, err
	}
	for _, l := range lines {
		switch {
		case l.amount.IsPositive():
			res.Unmatched = append(res.Unmatched, ReconMiss{l.no, l.amount, "money in: receipts are reconciled in Journey B"})
			continue
		case len(l.cands) == 0:
			res.Unmatched = append(res.Unmatched, ReconMiss{l.no, l.amount, "no released payment with this amount and reference"})
			continue
		case len(l.cands) > 1:
			res.Unmatched = append(res.Unmatched, ReconMiss{l.no, l.amount, "ambiguous: several released payments match"})
			continue
		}
		m, err := s.reconcileLine(ctx, p, l.id, l.cands[0])
		if err != nil {
			res.Unmatched = append(res.Unmatched, ReconMiss{l.no, l.amount, consoleError(err)})
			continue
		}
		m.LineNo = l.no
		res.Matched = append(res.Matched, m)
	}
	return res, nil
}

func (s *Service) reconcileLine(ctx context.Context, p auth.Principal, lineID, paymentID string) (ReconMatch, error) {
	var m ReconMatch
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var entity, ccy, num, releasedBy string
		var date time.Time
		if err := tx.QueryRow(ctx, `SELECT b.legal_entity_id::text, b.currency, l.booking_date, p.number, COALESCE(p.released_by, '')
			FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id JOIN company_bank_accounts b ON b.id = s.company_bank_id
			JOIN payment_instructions p ON p.id = $2::uuid WHERE l.id = $1::uuid FOR UPDATE OF l, p`, lineID, paymentID).Scan(&entity, &ccy, &date, &num, &releasedBy); err != nil {
			return mapNoRows(err)
		}
		if releasedBy == p.UserID {
			return fmt.Errorf("%w: the person who released a payment cannot reconcile it", auth.ErrSoD)
		}
		if err := s.authorize(ctx, tx, p, "bank.reconcile", "bank_statement_line", lineID, paymentID); err != nil {
			return err
		}
		// The settlement journal needs the line's payment link to compute;
		// link first (inside the same statement as MATCHED would be refused
		// without the journal), so build the journal from the expected
		// lines of the line+payment pair.
		jid, err := s.settlementJournal(ctx, tx, p, lineID, entity, ccy, "Bank settlement "+num, date)
		if err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE bank_statement_lines SET status = 'MATCHED', payment_id = $2::uuid, matched_by = $3, journal_id = $4::uuid WHERE id = $1::uuid`,
			lineID, paymentID, p.UserID, jid); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE payment_instructions SET status = 'SETTLED' WHERE id = $1::uuid`, paymentID); err != nil {
			return err
		}
		m = ReconMatch{PaymentID: paymentID, Payment: num, JournalID: jid}
		return s.record(ctx, tx, p, "bank.reconcile", "bank_statement_line", lineID, "bank.line_reconciled",
			map[string]any{"line_id": lineID, "payment_id": paymentID, "journal_id": jid})
	})
	return m, err
}

// settlementJournal: the settlement's accounting depends only on the
// statement line and its bank account (Dr clearing, Cr bank).
func (s *Service) settlementJournal(ctx context.Context, tx pgx.Tx, p auth.Principal, lineID, entity, ccy, desc string, date time.Time) (string, error) {
	return s.subledgerJournal(ctx, tx, p, "P2P_SETTLEMENT", lineID, entity, ccy, desc, date)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// ProjectCostReport returns budget, commitments and actuals per cost code.
func (s *Service) ProjectCostReport(ctx context.Context, p auth.Principal, projectID string) ([]postgres.CostPosition, error) {
	if err := s.authz.RequireProject(p, auth.PermP2PRead, p.TenantID, projectID); err != nil {
		return nil, err
	}
	var out []postgres.CostPosition
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ProjectCostReport(ctx, tx, projectID)
		return err
	})
	return out, err
}

// GLReconciliation compares the P2P subledgers with the general ledger.
func (s *Service) GLReconciliation(ctx context.Context, p auth.Principal, entityID string) ([]postgres.ReconCheck, error) {
	if err := s.authz.Require(p, auth.PermJournalRead, p.TenantID); err != nil {
		return nil, err
	}
	if !s.authz.Has(p, auth.PermScopeTenantWide) {
		return nil, fmt.Errorf("%w: reconciliation needs tenant-wide scope", auth.ErrForbidden)
	}
	var out []postgres.ReconCheck
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.GLReconciliation(ctx, tx, entityID)
		return err
	})
	return out, err
}

// BatchResult reports a batch journal command per journal.
type BatchResult struct {
	JournalID string `json:"journal_id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// ApproveJournals approves several DRAFT journals, each in its own attested
// transaction (a failure does not undo the others).
func (s *Service) ApproveJournals(ctx context.Context, p auth.Principal, ids []string) []BatchResult {
	return s.batch(ids, func(id string) error { return s.ApproveJournal(ctx, p, id) })
}

// PostJournals posts several APPROVED journals, each in its own attested transaction.
func (s *Service) PostJournals(ctx context.Context, p auth.Principal, ids []string) []BatchResult {
	return s.batch(ids, func(id string) error { return s.PostJournal(ctx, p, id) })
}

func (s *Service) batch(ids []string, fn func(string) error) []BatchResult {
	out := make([]BatchResult, 0, len(ids))
	for _, id := range ids {
		if err := fn(id); err != nil {
			out = append(out, BatchResult{JournalID: id, Error: consoleError(err)})
			continue
		}
		out = append(out, BatchResult{JournalID: id, OK: true})
	}
	return out
}

// ListP2PDocs lists documents of a type visible to the principal (project
// scope applied per row; entity-level documents need tenant-wide scope,
// except supplier master data which every P2P reader may see).
func (s *Service) ListP2PDocs(ctx context.Context, p auth.Principal, docType, status string, limit int) ([]postgres.DocSummary, error) {
	var out []postgres.DocSummary
	err := s.p2pTx(ctx, p, auth.PermP2PRead, func(ctx context.Context, tx pgx.Tx) error {
		scope := s.listScope(p, docType) // the same policy as detail reads (docscope.go)
		var err error
		out, err = postgres.ListDocs(ctx, tx, docType, status, scope, limit)
		return err
	})
	return out, err
}

// ListJournals lists journals for finance worklists (tenant-wide readers).
func (s *Service) ListJournals(ctx context.Context, p auth.Principal, status, sourcePrefix string, limit int) ([]postgres.JournalSummary, error) {
	if err := s.authz.Require(p, auth.PermJournalRead, p.TenantID); err != nil {
		return nil, err
	}
	if !s.authz.Has(p, auth.PermScopeTenantWide) {
		return nil, fmt.Errorf("%w: journal worklists need tenant-wide scope", auth.ErrForbidden)
	}
	var out []postgres.JournalSummary
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ListJournals(ctx, tx, status, sourcePrefix, limit)
		return err
	})
	return out, err
}

// Identity describes the caller for the console: what it shows is display
// only; every command is re-authorized by the kernel and the database.
type Identity struct {
	UserID      string            `json:"user_id"`
	TenantID    string            `json:"tenant_id"`
	Roles       []string          `json:"roles"`
	ProjectIDs  []string          `json:"project_ids"`
	TenantWide  bool              `json:"tenant_wide"`
	MFA         bool              `json:"mfa"`
	Permissions []auth.Permission `json:"permissions"`
}

// Whoami returns the caller's identity and effective permissions.
func (s *Service) Whoami(p auth.Principal) Identity {
	id := Identity{UserID: p.UserID, TenantID: p.TenantID, Roles: p.Roles, ProjectIDs: p.ProjectIDs,
		TenantWide: s.authz.Has(p, auth.PermScopeTenantWide), MFA: p.MFA, Permissions: s.authz.Permissions(p)}
	if id.Roles == nil {
		id.Roles = []string{}
	}
	if id.ProjectIDs == nil {
		id.ProjectIDs = []string{}
	}
	return id
}

// Reference is the form reference data visible to the caller.
type Reference struct {
	LegalEntities []postgres.RefItem `json:"legal_entities"`
	Projects      []postgres.RefItem `json:"projects"`
	Accounts      []postgres.RefItem `json:"accounts"`
}

// P2PReference returns entities, the projects in the caller's scope and GL
// accounts.
func (s *Service) P2PReference(ctx context.Context, p auth.Principal) (Reference, error) {
	var ref Reference
	err := s.p2pTx(ctx, p, auth.PermP2PRead, func(ctx context.Context, tx pgx.Tx) error {
		ents, projs, accts, err := postgres.ReferenceData(ctx, tx)
		if err != nil {
			return err
		}
		scope := s.authz.ScopeOf(p)
		ref = Reference{LegalEntities: ents, Accounts: accts, Projects: []postgres.RefItem{}}
		for _, pr := range projs {
			if scope.Allows(pr.ID) {
				ref.Projects = append(ref.Projects, pr)
			}
		}
		return nil
	})
	return ref, err
}

// ProjectCostCodes lists the active cost codes of a project in scope.
func (s *Service) ProjectCostCodes(ctx context.Context, p auth.Principal, projectID string) ([]postgres.RefItem, error) {
	if err := s.authz.RequireProject(p, auth.PermP2PRead, p.TenantID, projectID); err != nil {
		return nil, err
	}
	var out []postgres.RefItem
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ProjectCostCodes(ctx, tx, projectID)
		return err
	})
	return out, err
}
