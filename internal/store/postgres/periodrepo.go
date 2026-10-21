package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// FiscalPeriod is an accounting period of one legal entity.
type FiscalPeriod struct {
	ID            string
	TenantID      string
	LegalEntityID string
	Name          string
	StartsOn      time.Time
	EndsOn        time.Time
	Status        string
	ClosedBy      string
}

// GetFiscalPeriod loads a period. forUpdate takes the row lock FIRST, so that
// in-flight postings (which share-lock the period) finish before the caller
// computes anything (SC-08).
func GetFiscalPeriod(ctx context.Context, tx pgx.Tx, id string, forUpdate bool) (FiscalPeriod, error) {
	q := `SELECT id::text, tenant_id::text, legal_entity_id::text, name, starts_on, ends_on, status, COALESCE(closed_by,'')
		FROM fiscal_periods WHERE id=$1::uuid`
	if forUpdate {
		q += " FOR UPDATE"
	}
	var p FiscalPeriod
	err := tx.QueryRow(ctx, q, id).Scan(&p.ID, &p.TenantID, &p.LegalEntityID, &p.Name, &p.StartsOn, &p.EndsOn, &p.Status, &p.ClosedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return FiscalPeriod{}, ErrNotFound
	}
	return p, err
}

// CloseFiscalPeriod moves OPEN -> CLOSED (or LOCKED). The database trigger
// refuses while approved-but-unposted journals exist and records the closing
// trial balance.
func CloseFiscalPeriod(ctx context.Context, tx pgx.Tx, id, by string, lock bool) error {
	to := "CLOSED"
	if lock {
		to = "LOCKED"
	}
	tag, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status=$2, closed_by=$3 WHERE id=$1::uuid AND status IN ('OPEN','CLOSED')`, id, to, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ReopenFiscalPeriod moves CLOSED -> OPEN with a reason; the database
// enforces that the reopener is not the closer.
func ReopenFiscalPeriod(ctx context.Context, tx pgx.Tx, id, by, reason string) error {
	tag, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='OPEN', reopened_by=$2, reopen_reason=$3 WHERE id=$1::uuid AND status='CLOSED'`, id, by, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// PeriodCloseRecord is an immutable close/lock/reopen record.
type PeriodCloseRecord struct {
	Action       string
	Actor        string
	JournalCount int
	TBDebits     string
	TBCredits    string
	TBHash       string
	RecordedAt   time.Time
}

// LatestPeriodClose returns the most recent close/reopen record of a period.
func LatestPeriodClose(ctx context.Context, tx pgx.Tx, periodID string) (PeriodCloseRecord, error) {
	var r PeriodCloseRecord
	err := tx.QueryRow(ctx, `SELECT action, actor, journal_count, tb_debits::text, tb_credits::text, tb_hash, recorded_at
		FROM fiscal_period_closes WHERE period_id=$1::uuid ORDER BY id DESC LIMIT 1`, periodID).
		Scan(&r.Action, &r.Actor, &r.JournalCount, &r.TBDebits, &r.TBCredits, &r.TBHash, &r.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PeriodCloseRecord{}, ErrNotFound
	}
	return r, err
}

// IntegrityViolation is one finding of the forensic ledger scan.
type IntegrityViolation struct {
	Rule      string
	JournalID string
	Detail    string
}

// LedgerIntegrityScan runs ledger_integrity_scan() for the current tenant.
func LedgerIntegrityScan(ctx context.Context, tx pgx.Tx) ([]IntegrityViolation, error) {
	rows, err := tx.Query(ctx, `SELECT rule, journal_id::text, detail FROM ledger_integrity_scan()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntegrityViolation
	for rows.Next() {
		var v IntegrityViolation
		if err := rows.Scan(&v.Rule, &v.JournalID, &v.Detail); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
