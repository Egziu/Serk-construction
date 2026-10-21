package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// Procure-to-pay data access (migration 0013). The database computes every
// amount, budget position and match result and enforces the state machines;
// these functions insert drafts, request transitions and read results.

// P2PPolicy is an entity's procure-to-pay policy.
type P2PPolicy struct {
	ID                   string          `json:"id"`
	LegalEntityID        string          `json:"legal_entity_id"`
	Version              int             `json:"version"`
	Currency             string          `json:"currency"`
	PriceTolerancePct    decimal.Decimal `json:"price_tolerance_pct"`
	OverReceiptPct       decimal.Decimal `json:"over_receipt_pct"`
	VATRate              decimal.Decimal `json:"vat_rate"`
	HighValuePOThreshold decimal.Decimal `json:"high_value_po_threshold"`
	DualPaymentThreshold decimal.Decimal `json:"dual_payment_threshold"`
	GRNIAccountID        string          `json:"grni_account_id"`
	APAccountID          string          `json:"ap_account_id"`
	VATInputAccountID    string          `json:"vat_input_account_id"`
	PPVAccountID         string          `json:"ppv_account_id"`
	Status               string          `json:"status"`
	CreatedBy            string          `json:"created_by"`
	ApprovedBy           string          `json:"approved_by,omitempty"`
}

// Doc is the common header of a P2P document as returned to callers.
type Doc struct {
	ID        string          `json:"id"`
	Number    string          `json:"number,omitempty"`
	Status    string          `json:"status"`
	CreatedBy string          `json:"created_by"`
	Detail    json.RawMessage `json:"detail"` // the row (and children) as stored, from the database
}

// P2PTable maps a document type to its table and creator column.
var p2pTables = map[string]struct{ table, creator, children string }{
	"p2p_policy":            {"p2p_policies", "created_by", ""},
	"supplier":              {"suppliers", "created_by", ""},
	"supplier_bank_account": {"supplier_bank_accounts", "created_by", ""},
	"company_bank_account":  {"company_bank_accounts", "created_by", ""},
	"boq_version":           {"boq_versions", "created_by", ""},
	"purchase_requisition":  {"purchase_requisitions", "requested_by", ""},
	"rfq":                   {"rfqs", "created_by", ""},
	"rfq_quote":             {"rfq_quotes", "received_by", ""},
	"purchase_order":        {"purchase_orders", "created_by", ""},
	"grn":                   {"grns", "created_by", ""},
	"supplier_invoice":      {"supplier_invoices", "entered_by", ""},
	"payment_instruction":   {"payment_instructions", "created_by", ""},
}

// ErrUnknownDocType is returned for an unsupported document type.
var ErrUnknownDocType = errors.New("p2p: unknown document type")

// GetDoc returns a document with its children, as canonical JSON produced by
// the database (the same content the approval subject hash covers).
func GetDoc(ctx context.Context, tx pgx.Tx, docType, id string, lock bool) (Doc, error) {
	t, ok := p2pTables[docType]
	if !ok {
		return Doc{}, ErrUnknownDocType
	}
	q := `SELECT id::text, COALESCE(to_jsonb(x)->>'number', ''), COALESCE(to_jsonb(x)->>'status', to_jsonb(x)->>'technical_status'), ` + t.creator + `, p2p_subject_text($1, $2)
	        FROM ` + t.table + ` x WHERE id = $2::uuid`
	if lock {
		q += ` FOR UPDATE`
	}
	var d Doc
	var detail *string
	err := tx.QueryRow(ctx, q, docType, id).Scan(&d.ID, &d.Number, &d.Status, &d.CreatedBy, &detail)
	if errors.Is(err, pgx.ErrNoRows) {
		return Doc{}, ErrNotFound
	}
	if err != nil {
		return Doc{}, err
	}
	if detail != nil {
		d.Detail = json.RawMessage(*detail)
	}
	return d, nil
}

// NextNumber returns the next document number (PREFIX-YYYY-000001).
func NextNumber(ctx context.Context, tx pgx.Tx, prefix string) (string, error) {
	var n string
	err := tx.QueryRow(ctx, `SELECT p2p_next_number($1)`, prefix).Scan(&n)
	return n, err
}

// InsertReturningID runs an INSERT ... RETURNING id::text.
func InsertReturningID(ctx context.Context, tx pgx.Tx, sql string, args ...any) (string, error) {
	var id string
	err := tx.QueryRow(ctx, sql, args...).Scan(&id)
	return id, err
}

// Exec1 runs a statement that must affect exactly one row.
func Exec1(ctx context.Context, tx pgx.Tx, sql string, args ...any) error {
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrVersionConflict
	}
	return nil
}

// ExpectedLine is one line of a document's accounting as the database
// computes it (p2p_expected_lines).
type ExpectedLine struct {
	AccountID  string
	Side       string
	Amount     decimal.Decimal
	ProjectID  string
	CostCodeID string
}

// ExpectedLines returns the accounting the database requires for a document.
func ExpectedLines(ctx context.Context, tx pgx.Tx, doc, id string) ([]ExpectedLine, error) {
	rows, err := tx.Query(ctx, `SELECT account_id::text, side, amount, COALESCE(project_id::text, ''), COALESCE(cost_code_id::text, '')
		FROM p2p_expected_lines($1, $2::uuid) ORDER BY side DESC, account_id, project_id, cost_code_id`, doc, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExpectedLine
	for rows.Next() {
		var l ExpectedLine
		if err := rows.Scan(&l.AccountID, &l.Side, &l.Amount, &l.ProjectID, &l.CostCodeID); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// CostPosition is the budget position of one cost code.
type CostPosition struct {
	CostCodeID   string          `json:"cost_code_id"`
	CostCode     string          `json:"cost_code"`
	Budget       decimal.Decimal `json:"budget"`
	Committed    decimal.Decimal `json:"committed"`
	Reserved     decimal.Decimal `json:"reserved"`
	Received     decimal.Decimal `json:"received"`
	Invoiced     decimal.Decimal `json:"invoiced"`
	ActualPosted decimal.Decimal `json:"actual_posted"`
	ActualOther  decimal.Decimal `json:"actual_other"`
	Available    decimal.Decimal `json:"available"`
}

// ProjectCostReport returns the per-cost-code budget/commitment/actual report.
func ProjectCostReport(ctx context.Context, tx pgx.Tx, projectID string) ([]CostPosition, error) {
	rows, err := tx.Query(ctx, `SELECT cost_code_id::text, cost_code, budget, committed, reserved, received, invoiced, actual_posted, actual_other, available
		FROM p2p_project_cost_report($1::uuid)`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CostPosition
	for rows.Next() {
		var c CostPosition
		if err := rows.Scan(&c.CostCodeID, &c.CostCode, &c.Budget, &c.Committed, &c.Reserved, &c.Received, &c.Invoiced, &c.ActualPosted, &c.ActualOther, &c.Available); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReconCheck is one subledger-to-GL reconciliation line.
type ReconCheck struct {
	Check      string          `json:"check"`
	Subledger  decimal.Decimal `json:"subledger"`
	GL         decimal.Decimal `json:"gl"`
	Difference decimal.Decimal `json:"difference"`
	Unposted   int64           `json:"unposted_or_unmatched"`
}

// GLReconciliation returns the subledger-to-GL checks of an entity.
func GLReconciliation(ctx context.Context, tx pgx.Tx, entityID string) ([]ReconCheck, error) {
	rows, err := tx.Query(ctx, `SELECT check_name, subledger, gl, difference, unposted_documents FROM p2p_gl_reconciliation($1::uuid)`, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReconCheck
	for rows.Next() {
		var c ReconCheck
		if err := rows.Scan(&c.Check, &c.Subledger, &c.GL, &c.Difference, &c.Unposted); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// BudgetShortfall returns "" when the document fits the available budget,
// otherwise the database's description of the first shortfall.
func BudgetShortfall(ctx context.Context, tx pgx.Tx, prID, poID string) (string, error) {
	var s *string
	var pr, po *string
	if prID != "" {
		pr = &prID
	}
	if poID != "" {
		po = &poID
	}
	if err := tx.QueryRow(ctx, `SELECT p2p_assert_budget($1::uuid, $2::uuid)`, pr, po).Scan(&s); err != nil {
		return "", err
	}
	if s == nil {
		return "", nil
	}
	return *s, nil
}

// DBDate returns the database's current date (documents are dated by the
// database clock, never the client's).
func DBDate(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var d time.Time
	err := tx.QueryRow(ctx, `SELECT current_date::timestamptz`).Scan(&d)
	return d, err
}
