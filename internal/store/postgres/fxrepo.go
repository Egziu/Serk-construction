package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// FX persistence under maker/checker control (SC-02, SC-03). Every function
// runs inside a tenant-bound transaction; the database triggers in migration
// 0002 re-enforce each rule, so these are the fast, explainable first line.

// PurposeTransaction is the FX policy purpose for ordinary postings.
const PurposeTransaction = "TRANSACTION"

// ErrNoFXPolicy is returned when an entity has no approved FX policy for a
// purpose. Foreign-currency postings fail closed.
var ErrNoFXPolicy = errors.New("fx: no approved FX policy for this legal entity and purpose")

// DBNow returns the transaction timestamp: the authoritative knowledge cutoff
// used by both the Go selection and the database eligibility check.
func DBNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var t time.Time
	err := tx.QueryRow(ctx, `SELECT now()`).Scan(&t)
	return t, err
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// FXSource is a registered rate source.
type FXSource struct {
	TenantID             string
	SourceID             string
	SourceType           string
	Description          string
	RequiresDocumentHash bool
	MaxVariance          decimal.Decimal
	Status               string
	CreatedBy            string
	ApprovedBy           string
}

// InsertFXSource registers a source as PENDING.
func InsertFXSource(ctx context.Context, tx pgx.Tx, s FXSource) error {
	if s.MaxVariance.IsZero() {
		s.MaxVariance = decimal.RequireFromString("0.05")
	}
	_, err := tx.Exec(ctx, `INSERT INTO fx_sources(tenant_id,source_id,source_type,description,requires_document_hash,max_variance,created_by)
		VALUES ($1::uuid,$2,$3,$4,$5,$6::numeric,$7)`,
		s.TenantID, s.SourceID, s.SourceType, s.Description, s.RequiresDocumentHash, s.MaxVariance.String(), s.CreatedBy)
	return err
}

// GetFXSource loads a source; lock takes a row lock for a decision.
func GetFXSource(ctx context.Context, tx pgx.Tx, sourceID string, lock bool) (FXSource, error) {
	q := `SELECT tenant_id::text, source_id, source_type, description, requires_document_hash, max_variance::text, status, created_by, COALESCE(approved_by,'')
		FROM fx_sources WHERE source_id=$1`
	if lock {
		q += " FOR UPDATE"
	}
	var s FXSource
	var mv string
	err := tx.QueryRow(ctx, q, sourceID).Scan(&s.TenantID, &s.SourceID, &s.SourceType, &s.Description, &s.RequiresDocumentHash, &mv, &s.Status, &s.CreatedBy, &s.ApprovedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return FXSource{}, ErrNotFound
	}
	if err != nil {
		return FXSource{}, err
	}
	s.MaxVariance, err = decimal.NewFromString(mv)
	return s, err
}

// SetFXSourceStatus records an approval or retirement.
func SetFXSourceStatus(ctx context.Context, tx pgx.Tx, sourceID, from, to, by string) error {
	tag, err := tx.Exec(ctx, `UPDATE fx_sources SET status=$3,
		approved_by=CASE WHEN $3='APPROVED' THEN $4 ELSE approved_by END,
		approved_at=CASE WHEN $3='APPROVED' THEN now() ELSE approved_at END
		WHERE source_id=$1 AND status=$2`, sourceID, from, to, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

// FXPolicy is a versioned, approved selection policy for one legal entity
// and purpose.
type FXPolicy struct {
	ID            string
	TenantID      string
	LegalEntityID string
	Purpose       string
	Version       int
	Policy        fx.Policy
	Status        string
	CreatedBy     string
	ApprovedBy    string
}

// InsertFXPolicy proposes the next version of an entity's policy.
func InsertFXPolicy(ctx context.Context, tx pgx.Tx, p FXPolicy) (FXPolicy, error) {
	if err := p.Policy.Validate(); err != nil {
		return FXPolicy{}, err
	}
	if p.ID == "" {
		p.ID = newID()
	}
	err := tx.QueryRow(ctx, `INSERT INTO fx_policies(id,tenant_id,legal_entity_id,purpose,version,rate_type,source_priority,max_staleness,allow_inverse,created_by)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,
		        (SELECT COALESCE(MAX(version),0)+1 FROM fx_policies WHERE legal_entity_id=$3::uuid AND purpose=$4),
		        $5,$6,make_interval(secs => $7),$8,$9)
		RETURNING version`,
		p.ID, p.TenantID, p.LegalEntityID, p.Purpose, string(p.Policy.RateType), p.Policy.SourcePriority,
		p.Policy.MaxStaleness.Seconds(), p.Policy.AllowInverse, p.CreatedBy).Scan(&p.Version)
	p.Status = "PENDING"
	return p, err
}

const fxPolicyCols = `id::text, tenant_id::text, legal_entity_id::text, purpose, version, rate_type, source_priority,
	extract(epoch FROM max_staleness)::bigint, allow_inverse, status, created_by, COALESCE(approved_by,'')`

func scanFXPolicy(row pgx.Row) (FXPolicy, error) {
	var p FXPolicy
	var rt string
	var secs int64
	err := row.Scan(&p.ID, &p.TenantID, &p.LegalEntityID, &p.Purpose, &p.Version, &rt, &p.Policy.SourcePriority,
		&secs, &p.Policy.AllowInverse, &p.Status, &p.CreatedBy, &p.ApprovedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return FXPolicy{}, ErrNotFound
	}
	p.Policy.RateType = fx.RateType(rt)
	p.Policy.MaxStaleness = time.Duration(secs) * time.Second
	return p, err
}

// GetFXPolicy loads a policy by id; lock takes a row lock.
func GetFXPolicy(ctx context.Context, tx pgx.Tx, id string, lock bool) (FXPolicy, error) {
	q := `SELECT ` + fxPolicyCols + ` FROM fx_policies WHERE id=$1::uuid`
	if lock {
		q += " FOR UPDATE"
	}
	return scanFXPolicy(tx.QueryRow(ctx, q, id))
}

// ApprovedFXPolicy returns the entity's single approved policy for a purpose.
func ApprovedFXPolicy(ctx context.Context, tx pgx.Tx, legalEntityID, purpose string) (FXPolicy, error) {
	p, err := scanFXPolicy(tx.QueryRow(ctx, `SELECT `+fxPolicyCols+` FROM fx_policies
		WHERE legal_entity_id=$1::uuid AND purpose=$2 AND status='APPROVED'`, legalEntityID, purpose))
	if errors.Is(err, ErrNotFound) {
		return FXPolicy{}, ErrNoFXPolicy
	}
	return p, err
}

// DecideFXPolicy approves (retiring the previously approved version in the
// same transaction) or rejects a PENDING policy.
func DecideFXPolicy(ctx context.Context, tx pgx.Tx, p FXPolicy, approve bool, by string) error {
	if approve {
		if _, err := tx.Exec(ctx, `UPDATE fx_policies SET status='RETIRED'
			WHERE legal_entity_id=$1::uuid AND purpose=$2 AND status='APPROVED'`, p.LegalEntityID, p.Purpose); err != nil {
			return err
		}
	}
	to := "REJECTED"
	if approve {
		to = "APPROVED"
	}
	tag, err := tx.Exec(ctx, `UPDATE fx_policies SET status=$2,
		approved_by=CASE WHEN $2='APPROVED' THEN $3 ELSE NULL END, approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE NULL END
		WHERE id=$1::uuid AND status='PENDING'`, p.ID, to, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

// FXSnapshotRecord is a snapshot with its decision record.
type FXSnapshotRecord struct {
	fx.Snapshot
	ApprovedBy        string
	RejectedBy        string
	DecisionReason    string
	DecidedAt         *time.Time
	VarianceException bool
	ApproverMFA       bool
	Legacy            bool
}

// InsertFXSnapshot records an observation. Snapshots are always born
// PENDING; approval is a separate maker/checker decision (SC-03).
func InsertFXSnapshot(ctx context.Context, tx pgx.Tx, s fx.Snapshot) (string, error) {
	if s.SnapshotID == "" {
		s.SnapshotID = newID()
	}
	if s.CapturedAtUTC.IsZero() {
		s.CapturedAtUTC = time.Now().UTC()
	}
	if s.AlgorithmVersion == "" {
		s.AlgorithmVersion = fx.AlgorithmVersion
	}
	s.ApprovalStatus = fx.StatusPending
	if err := s.Validate(); err != nil {
		return "", err
	}
	var be *time.Time
	if !s.BusinessEventAtUTC.IsZero() {
		t := s.BusinessEventAtUTC
		be = &t
	}
	_, err := tx.Exec(ctx, `INSERT INTO fx_snapshots(snapshot_id,tenant_id,source_id,source_type,base_currency,quote_currency,rate,rate_type,
		effective_from_utc,published_at_utc,captured_at_utc,business_event_at_utc,source_document_hash,algorithm_version,approval_status,created_by)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,'PENDING',$15)`,
		s.SnapshotID, s.TenantID, s.SourceID, s.SourceType, string(s.BaseCurrency), string(s.QuoteCurrency), s.Rate.String(), string(s.RateType),
		s.EffectiveFromUTC, s.PublishedAtUTC, s.CapturedAtUTC, be, s.SourceDocumentHash, s.AlgorithmVersion, s.CreatedBy)
	return s.SnapshotID, err
}

const fxSnapshotCols = `snapshot_id::text, tenant_id::text, source_id, source_type, base_currency, quote_currency, rate::text, rate_type,
	effective_from_utc, published_at_utc, captured_at_utc, business_event_at_utc, source_document_hash, algorithm_version, approval_status, created_by,
	COALESCE(approved_by,''), COALESCE(rejected_by,''), COALESCE(decision_reason,''), decided_at, variance_exception, approver_mfa, legacy_self_approved`

func scanFXSnapshot(row pgx.Row) (FXSnapshotRecord, error) {
	var r FXSnapshotRecord
	var rate, b, q, rt, st string
	var be *time.Time
	err := row.Scan(&r.SnapshotID, &r.TenantID, &r.SourceID, &r.SourceType, &b, &q, &rate, &rt,
		&r.EffectiveFromUTC, &r.PublishedAtUTC, &r.CapturedAtUTC, &be, &r.SourceDocumentHash, &r.AlgorithmVersion, &st, &r.CreatedBy,
		&r.ApprovedBy, &r.RejectedBy, &r.DecisionReason, &r.DecidedAt, &r.VarianceException, &r.ApproverMFA, &r.Legacy)
	if errors.Is(err, pgx.ErrNoRows) {
		return FXSnapshotRecord{}, ErrNotFound
	}
	if err != nil {
		return FXSnapshotRecord{}, err
	}
	r.BaseCurrency, r.QuoteCurrency = money.Currency(b), money.Currency(q)
	r.RateType, r.ApprovalStatus = fx.RateType(rt), fx.ApprovalStatus(st)
	if be != nil {
		r.BusinessEventAtUTC = *be
	}
	r.Rate, err = decimal.NewFromString(rate)
	return r, err
}

// GetFXSnapshot loads one snapshot; lock takes a row lock for a decision.
func GetFXSnapshot(ctx context.Context, tx pgx.Tx, id string, lock bool) (FXSnapshotRecord, error) {
	q := `SELECT ` + fxSnapshotCols + ` FROM fx_snapshots WHERE snapshot_id=$1::uuid`
	if lock {
		q += " FOR UPDATE"
	}
	return scanFXSnapshot(tx.QueryRow(ctx, q, id))
}

// PreviousApprovedRate returns the latest earlier approved rate of the same
// series (pair, source, rate type), used for the variance gate.
func PreviousApprovedRate(ctx context.Context, tx pgx.Tx, s FXSnapshotRecord) (decimal.Decimal, bool, error) {
	var r string
	err := tx.QueryRow(ctx, `SELECT rate::text FROM fx_snapshots
		WHERE base_currency=$1 AND quote_currency=$2 AND source_id=$3 AND rate_type=$4 AND approval_status='APPROVED'
		  AND effective_from_utc < $5 AND snapshot_id <> $6::uuid
		ORDER BY effective_from_utc DESC LIMIT 1`,
		string(s.BaseCurrency), string(s.QuoteCurrency), s.SourceID, string(s.RateType), s.EffectiveFromUTC, s.SnapshotID).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return decimal.Zero, false, nil
	}
	if err != nil {
		return decimal.Zero, false, err
	}
	d, err := decimal.NewFromString(r)
	return d, true, err
}

// FXDecision is a checker's decision on a snapshot.
type FXDecision struct {
	From              fx.ApprovalStatus
	To                fx.ApprovalStatus
	By                string
	Reason            string
	VarianceException bool
	ApproverMFA       bool
}

// DecideFXSnapshot applies an approval, rejection or withdrawal. The update
// is conditional on the expected current status (no lost decisions).
func DecideFXSnapshot(ctx context.Context, tx pgx.Tx, id string, d FXDecision) error {
	var approvedBy, rejectedBy *string
	switch d.To {
	case fx.StatusApproved:
		approvedBy = &d.By
	case fx.StatusRejected:
		rejectedBy = &d.By
	}
	var tag interface{ RowsAffected() int64 }
	var err error
	if d.To == fx.StatusDisputed {
		// Withdrawal keeps the original approval record and adds a reason.
		tag, err = tx.Exec(ctx, `UPDATE fx_snapshots SET approval_status='DISPUTED', decision_reason=$3
			WHERE snapshot_id=$1::uuid AND approval_status=$2`, id, string(d.From), d.Reason)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE fx_snapshots SET approval_status=$3, approved_by=$4, rejected_by=$5, decided_at=now(),
			decision_reason=NULLIF($6,''), variance_exception=$7, approver_mfa=$8
			WHERE snapshot_id=$1::uuid AND approval_status=$2`,
			id, string(d.From), string(d.To), approvedBy, rejectedBy, d.Reason, d.VarianceException, d.ApproverMFA)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ListEligibleFXSnapshots returns candidate snapshots for a pair (either
// orientation) effective on or before `until`, excluding legacy
// self-approved rows and rows from sources that are not currently trusted.
// Policy selection (rate type, priority, staleness, cutoff, inverse) is then
// applied by pkg/fx.Select.
func ListEligibleFXSnapshots(ctx context.Context, tx pgx.Tx, base, quote money.Currency, until time.Time) ([]fx.Snapshot, error) {
	rows, err := tx.Query(ctx, `SELECT `+fxSnapshotCols+` FROM fx_snapshots s
		WHERE ((base_currency=$1 AND quote_currency=$2) OR (base_currency=$2 AND quote_currency=$1)) AND effective_from_utc <= $3
		  AND NOT legacy_self_approved
		  AND EXISTS (SELECT 1 FROM fx_sources src WHERE src.source_id = s.source_id AND src.status = 'APPROVED')
		ORDER BY effective_from_utc DESC LIMIT 500`, string(base), string(quote), until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fx.Snapshot
	for rows.Next() {
		r, err := scanFXSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r.Snapshot)
	}
	return out, rows.Err()
}

// SelectFXForEntity applies the entity's approved policy for a purpose to the
// eligible candidates, with the database transaction time as the knowledge
// cutoff. This is the single selection used by both /fx/convert and the
// journal write path.
func SelectFXForEntity(ctx context.Context, tx pgx.Tx, legalEntityID, purpose string, from, to money.Currency, eventAt time.Time) (fx.Selection, FXPolicy, error) {
	pol, err := ApprovedFXPolicy(ctx, tx, legalEntityID, purpose)
	if err != nil {
		return fx.Selection{}, FXPolicy{}, err
	}
	cutoff, err := DBNow(ctx, tx)
	if err != nil {
		return fx.Selection{}, FXPolicy{}, err
	}
	cands, err := ListEligibleFXSnapshots(ctx, tx, from, to, eventAt)
	if err != nil {
		return fx.Selection{}, FXPolicy{}, err
	}
	sel, err := fx.Select(cands, from, to, eventAt, cutoff, pol.Policy)
	return sel, pol, err
}

// fxBinder binds foreign-currency journal lines to the policy-selected rate.
type fxBinder struct {
	cache map[money.Currency]struct {
		sel fx.Selection
		pol FXPolicy
	}
}

func (b *fxBinder) bindLine(ctx context.Context, tx pgx.Tx, j *ledger.Journal, l *ledger.Line) error {
	if l.FXSnapshotID == "" {
		return fmt.Errorf("%w: line %d: fx_snapshot_id is required for a foreign-currency line (obtain it from /v1/fx/convert with legal_entity_id)", ErrLineRejected, l.LineNo)
	}
	cur := l.TxnAmount.Currency()
	if b.cache == nil {
		b.cache = map[money.Currency]struct {
			sel fx.Selection
			pol FXPolicy
		}{}
	}
	c, ok := b.cache[cur]
	if !ok {
		sel, pol, err := SelectFXForEntity(ctx, tx, j.LegalEntityID, PurposeTransaction, cur, j.FunctionalCurrency, j.BusinessEventAt)
		if err != nil {
			return fmt.Errorf("%w: line %d: %w", ErrLineRejected, l.LineNo, err)
		}
		c.sel, c.pol = sel, pol
		b.cache[cur] = c
	}
	if c.sel.Snapshot.SnapshotID != l.FXSnapshotID {
		return fmt.Errorf("%w: line %d: snapshot %s is not the rate selected by FX policy v%d for this event (expected %s)",
			ErrLineRejected, l.LineNo, l.FXSnapshotID, c.pol.Version, c.sel.Snapshot.SnapshotID)
	}
	expect, err := money.New(l.TxnAmount.Amount().Mul(c.sel.AppliedRate), j.FunctionalCurrency, money.RoundHalfEven)
	if err != nil {
		return err
	}
	if !expect.Equal(l.Amount) {
		return fmt.Errorf("%w: line %d amount %s does not reconcile to %s x %s = %s", ErrLineRejected, l.LineNo, l.Amount, l.TxnAmount, c.sel.AppliedRate, expect)
	}
	l.AppliedRate = c.sel.AppliedRate
	l.FXPolicyID, l.FXPolicyVersion = c.pol.ID, c.pol.Version
	return nil
}
