package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// TrialBalanceRow is one account's posted debits and credits to a date.
type TrialBalanceRow struct {
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	AccountType string          `json:"account_type"`
	Debit       decimal.Decimal `json:"debit"`
	Credit      decimal.Decimal `json:"credit"`
	Balance     decimal.Decimal `json:"balance"` // debit - credit
}

// TrialBalance sums posted journal lines (status POSTED or REVERSED, as the
// reconciliations do) dated up to and including asOf, for every account of
// the entity. Read-only; row-level security applies.
func TrialBalance(ctx context.Context, tx pgx.Tx, entityID string, asOf time.Time) ([]TrialBalanceRow, error) {
	rows, err := tx.Query(ctx, `
		WITH t AS (
		  SELECT l.account_id,
		         COALESCE(sum(l.amount) FILTER (WHERE l.side = 'DEBIT'), 0)  AS dr,
		         COALESCE(sum(l.amount) FILTER (WHERE l.side = 'CREDIT'), 0) AS cr
		    FROM journal_lines l JOIN journals j ON j.tenant_id = l.tenant_id AND j.id = l.journal_id
		   WHERE j.legal_entity_id = $1::uuid AND j.status IN ('POSTED', 'REVERSED') AND j.business_event_at < ($2::date + 1)
		   GROUP BY l.account_id)
		SELECT a.code, a.name, a.type, COALESCE(t.dr, 0), COALESCE(t.cr, 0)
		  FROM accounts a LEFT JOIN t ON t.account_id = a.id
		 WHERE a.legal_entity_id = $1::uuid
		 ORDER BY a.code`, entityID, asOf)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrialBalanceRow
	for rows.Next() {
		var r TrialBalanceRow
		if err := rows.Scan(&r.AccountCode, &r.AccountName, &r.AccountType, &r.Debit, &r.Credit); err != nil {
			return nil, err
		}
		r.Balance = r.Debit.Sub(r.Credit)
		out = append(out, r)
	}
	return out, rows.Err()
}

// OpenItem is an approved invoice with an amount still open at a date.
type OpenItem struct {
	Party       string          `json:"party"`
	Document    string          `json:"document"`
	InvoiceDate time.Time       `json:"invoice_date"`
	DueDate     time.Time       `json:"due_date"`
	Currency    string          `json:"currency"`
	Total       decimal.Decimal `json:"total"`
	Open        decimal.Decimal `json:"open"`
}

// PayablesOpen lists approved supplier invoices of the entity dated up to
// asOf, less payments released or settled.
func PayablesOpen(ctx context.Context, tx pgx.Tx, entityID string, asOf time.Time) ([]OpenItem, error) {
	return openItems(ctx, tx, `
		SELECT s.name, i.invoice_number, i.invoice_date, i.due_date, i.currency, i.total,
		       i.total - COALESCE((SELECT sum(a.amount) FROM payment_allocations a
		                             JOIN payment_instructions p ON p.tenant_id = a.tenant_id AND p.id = a.payment_id
		                            WHERE a.invoice_id = i.id AND p.status IN ('RELEASED', 'SETTLED') AND p.value_date <= $2::date), 0)
		  FROM supplier_invoices i
		  JOIN suppliers s ON s.tenant_id = i.tenant_id AND s.id = i.supplier_id
		  JOIN purchase_orders po ON po.tenant_id = i.tenant_id AND po.id = i.po_id
		 WHERE po.legal_entity_id = $1::uuid AND i.status = 'APPROVED' AND i.invoice_date <= $2::date
		 ORDER BY i.due_date, s.name, i.invoice_number`, entityID, asOf)
}

// ReceivablesOpen lists approved customer invoices of the entity dated up to
// asOf, less confirmed receipts and approved credit notes.
func ReceivablesOpen(ctx context.Context, tx pgx.Tx, entityID string, asOf time.Time) ([]OpenItem, error) {
	return openItems(ctx, tx, `
		SELECT c.name, i.number, i.invoice_date, i.due_date, i.currency, i.total,
		       i.total - COALESCE((SELECT sum(a.amount) FROM receipt_allocations a
		                             JOIN customer_receipts r ON r.tenant_id = a.tenant_id AND r.id = a.receipt_id
		                            WHERE a.invoice_id = i.id AND r.status = 'CONFIRMED' AND r.receipt_date <= $2::date), 0)
		               - COALESCE((SELECT sum(n.total) FROM customer_credit_notes n
		                            WHERE n.invoice_id = i.id AND n.status = 'APPROVED' AND n.credit_date <= $2::date), 0)
		  FROM customer_invoices i
		  JOIN customers c ON c.tenant_id = i.tenant_id AND c.id = i.customer_id
		 WHERE i.legal_entity_id = $1::uuid AND i.status = 'APPROVED' AND i.invoice_date <= $2::date
		 ORDER BY i.due_date, c.name, i.number`, entityID, asOf)
}

func openItems(ctx context.Context, tx pgx.Tx, sql, entityID string, asOf time.Time) ([]OpenItem, error) {
	rows, err := tx.Query(ctx, sql, entityID, asOf)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenItem
	for rows.Next() {
		var r OpenItem
		if err := rows.Scan(&r.Party, &r.Document, &r.InvoiceDate, &r.DueDate, &r.Currency, &r.Total, &r.Open); err != nil {
			return nil, err
		}
		if r.Open.IsPositive() {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}
