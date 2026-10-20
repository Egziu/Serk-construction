package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// ---------------------------------------------------------------------------
// Organisation bootstrap
// ---------------------------------------------------------------------------

// CreateTenant inserts a tenant. It must run under WithTenant(newTenantID)
// because the tenants policy only admits the current tenant's own row.
func CreateTenant(ctx context.Context, tx pgx.Tx, id, name string) error {
	_, err := tx.Exec(ctx, `INSERT INTO tenants(id,name) VALUES ($1::uuid,$2)`, id, name)
	return err
}

// CreateLegalEntity inserts a legal entity for the current tenant.
func CreateLegalEntity(ctx context.Context, tx pgx.Tx, tenantID, name, country string, functional, presentation money.Currency) (string, error) {
	if !money.IsKnown(functional) {
		return "", fmt.Errorf("unknown functional currency %q", functional)
	}
	id := newID()
	var pres *string
	if presentation != "" {
		p := string(presentation)
		pres = &p
	}
	_, err := tx.Exec(ctx, `INSERT INTO legal_entities(id,tenant_id,name,country,functional_currency,presentation_currency)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6)`, id, tenantID, name, country, string(functional), pres)
	return id, err
}

// CreateProject inserts a project.
func CreateProject(ctx context.Context, tx pgx.Tx, tenantID, legalEntityID, code, name string, contractCur money.Currency) (string, error) {
	id := newID()
	var cc *string
	if contractCur != "" {
		c := string(contractCur)
		cc = &c
	}
	_, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,legal_entity_id,code,name,contract_currency)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6)`, id, tenantID, legalEntityID, code, name, cc)
	return id, err
}

// CreateAccount inserts a chart-of-accounts entry.
func CreateAccount(ctx context.Context, tx pgx.Tx, a ledger.Account) (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	id := a.ID
	if id == "" {
		id = newID()
	}
	var cur *string
	if a.Currency != "" {
		c := string(a.Currency)
		cur = &c
	}
	_, err := tx.Exec(ctx, `INSERT INTO accounts(id,tenant_id,legal_entity_id,code,name,type,currency,active)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8)`, id, a.TenantID, a.LegalEntityID, a.Code, a.Name, string(a.Type), cur, a.Active)
	return id, err
}

// CreateFiscalPeriod inserts an OPEN period.
func CreateFiscalPeriod(ctx context.Context, tx pgx.Tx, tenantID, legalEntityID, name string, start, end time.Time) (string, error) {
	id := newID()
	_, err := tx.Exec(ctx, `INSERT INTO fiscal_periods(id,tenant_id,legal_entity_id,name,starts_on,ends_on)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::date,$6::date)`, id, tenantID, legalEntityID, name, start, end)
	return id, err
}

// SetFiscalPeriodStatus moves a period between OPEN/CLOSED/LOCKED.
func SetFiscalPeriodStatus(ctx context.Context, tx pgx.Tx, id, status, by string) error {
	tag, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status=$2, closed_by=CASE WHEN $2='OPEN' THEN NULL ELSE $3 END,
		closed_at=CASE WHEN $2='OPEN' THEN NULL ELSE now() END WHERE id=$1::uuid`, id, status, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// FX snapshots
// ---------------------------------------------------------------------------

// InsertFXSnapshot stores an observation. ID is generated when empty.
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
	if s.ApprovalStatus == "" {
		s.ApprovalStatus = fx.StatusPending
	}
	if err := s.Validate(); err != nil {
		return "", err
	}
	var be *time.Time
	if !s.BusinessEventAtUTC.IsZero() {
		t := s.BusinessEventAtUTC
		be = &t
	}
	var approvedBy *string
	if s.ApprovalStatus == fx.StatusApproved {
		approvedBy = &s.CreatedBy
	}
	_, err := tx.Exec(ctx, `INSERT INTO fx_snapshots(snapshot_id,tenant_id,source_id,source_type,base_currency,quote_currency,rate,rate_type,
		effective_from_utc,published_at_utc,captured_at_utc,business_event_at_utc,source_document_hash,algorithm_version,approval_status,approved_by,created_by)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7::numeric,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		s.SnapshotID, s.TenantID, s.SourceID, s.SourceType, string(s.BaseCurrency), string(s.QuoteCurrency), s.Rate.String(), string(s.RateType),
		s.EffectiveFromUTC, s.PublishedAtUTC, s.CapturedAtUTC, be, s.SourceDocumentHash, s.AlgorithmVersion, string(s.ApprovalStatus), approvedBy, s.CreatedBy)
	return s.SnapshotID, err
}

// SetFXSnapshotApproval changes only the approval state of a snapshot.
func SetFXSnapshotApproval(ctx context.Context, tx pgx.Tx, id string, status fx.ApprovalStatus, by string) error {
	tag, err := tx.Exec(ctx, `UPDATE fx_snapshots SET approval_status=$2, approved_by=CASE WHEN $2='APPROVED' THEN $3 ELSE approved_by END WHERE snapshot_id=$1::uuid`, id, string(status), by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListFXSnapshots returns all snapshots for a pair in either orientation,
// effective on or before `until`. Selection policy is applied by pkg/fx.
func ListFXSnapshots(ctx context.Context, tx pgx.Tx, base, quote money.Currency, until time.Time) ([]fx.Snapshot, error) {
	rows, err := tx.Query(ctx, `SELECT snapshot_id::text, tenant_id::text, source_id, source_type, base_currency, quote_currency, rate::text, rate_type,
		effective_from_utc, published_at_utc, captured_at_utc, business_event_at_utc, source_document_hash, algorithm_version, approval_status, created_by
		FROM fx_snapshots
		WHERE ((base_currency=$1 AND quote_currency=$2) OR (base_currency=$2 AND quote_currency=$1)) AND effective_from_utc <= $3
		ORDER BY effective_from_utc DESC LIMIT 500`, string(base), string(quote), until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fx.Snapshot
	for rows.Next() {
		var s fx.Snapshot
		var rate string
		var be *time.Time
		var b, q, rt, st string
		if err := rows.Scan(&s.SnapshotID, &s.TenantID, &s.SourceID, &s.SourceType, &b, &q, &rate, &rt,
			&s.EffectiveFromUTC, &s.PublishedAtUTC, &s.CapturedAtUTC, &be, &s.SourceDocumentHash, &s.AlgorithmVersion, &st, &s.CreatedBy); err != nil {
			return nil, err
		}
		s.BaseCurrency, s.QuoteCurrency = money.Currency(b), money.Currency(q)
		s.RateType, s.ApprovalStatus = fx.RateType(rt), fx.ApprovalStatus(st)
		if s.Rate, err = decimal.NewFromString(rate); err != nil {
			return nil, err
		}
		if be != nil {
			s.BusinessEventAtUTC = *be
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Journals
// ---------------------------------------------------------------------------

// CommandHash returns the canonical SHA-256 of a journal command so that an
// idempotency key cannot be silently reused for a different payload.
func CommandHash(j ledger.Journal) string {
	type line struct {
		N, A, S, Amt, Cur, Txn, TxnCur, Snap, P, C, M string
	}
	type cmd struct {
		By, LE, P, Cur, Ev, Desc, ST, SR, RevOf string
		L                                       []line
	}
	// CreatedBy is part of the command: another user replaying the same key
	// must not be handed this journal as "their" replay.
	c := cmd{By: j.CreatedBy, LE: j.LegalEntityID, P: j.ProjectID, Cur: string(j.FunctionalCurrency), Ev: j.BusinessEventAt.UTC().Format(time.RFC3339Nano),
		Desc: j.Description, ST: j.SourceType, SR: j.SourceRef, RevOf: j.ReversalOf}
	for _, l := range j.Lines {
		ln := line{N: fmt.Sprint(l.LineNo), A: l.AccountID, S: string(l.Side), Amt: l.Amount.AmountString(), Cur: string(l.Amount.Currency()),
			Snap: l.FXSnapshotID, P: l.ProjectID, C: l.CostCodeID, M: l.Memo}
		if l.TxnAmount != nil {
			ln.Txn, ln.TxnCur = l.TxnAmount.AmountString(), string(l.TxnAmount.Currency())
		}
		c.L = append(c.L, ln)
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GetFXSnapshot loads one snapshot by id.
func GetFXSnapshot(ctx context.Context, tx pgx.Tx, id string) (fx.Snapshot, error) {
	var s fx.Snapshot
	var rate, b, q, rt, st string
	var be *time.Time
	err := tx.QueryRow(ctx, `SELECT snapshot_id::text, tenant_id::text, source_id, source_type, base_currency, quote_currency, rate::text, rate_type,
		effective_from_utc, published_at_utc, captured_at_utc, business_event_at_utc, source_document_hash, algorithm_version, approval_status, created_by
		FROM fx_snapshots WHERE snapshot_id=$1::uuid`, id).Scan(&s.SnapshotID, &s.TenantID, &s.SourceID, &s.SourceType, &b, &q, &rate, &rt,
		&s.EffectiveFromUTC, &s.PublishedAtUTC, &s.CapturedAtUTC, &be, &s.SourceDocumentHash, &s.AlgorithmVersion, &st, &s.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return fx.Snapshot{}, ErrNotFound
	}
	if err != nil {
		return fx.Snapshot{}, err
	}
	s.BaseCurrency, s.QuoteCurrency = money.Currency(b), money.Currency(q)
	s.RateType, s.ApprovalStatus = fx.RateType(rt), fx.ApprovalStatus(st)
	if s.Rate, err = decimal.NewFromString(rate); err != nil {
		return fx.Snapshot{}, err
	}
	if be != nil {
		s.BusinessEventAtUTC = *be
	}
	return s, nil
}

// GetAccount loads an account.
func GetAccount(ctx context.Context, tx pgx.Tx, id string) (ledger.Account, error) {
	var a ledger.Account
	var cur *string
	var typ string
	err := tx.QueryRow(ctx, `SELECT id::text, tenant_id::text, legal_entity_id::text, code, name, type, currency, active FROM accounts WHERE id=$1::uuid`, id).
		Scan(&a.ID, &a.TenantID, &a.LegalEntityID, &a.Code, &a.Name, &typ, &cur, &a.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return ledger.Account{}, ErrNotFound
	}
	if err != nil {
		return ledger.Account{}, err
	}
	a.Type = ledger.AccountType(typ)
	if cur != nil {
		a.Currency = money.Currency(*cur)
	}
	return a, nil
}

// ErrLineRejected wraps a line-level validation failure found against stored
// reference data (account, snapshot). It is a validation error, not a bug.
var ErrLineRejected = errors.New("ledger: line rejected")

// bindLines resolves every line against stored accounts and FX snapshots:
// account exists in the journal's entity and is active, its currency
// restriction holds, the snapshot is APPROVED and of the right pair, and the
// functional amount equals round_half_even(txn_amount × rate). On success the
// applied rate is written into the line (LAW 06 provenance).
func bindLines(ctx context.Context, tx pgx.Tx, j *ledger.Journal) error {
	for i := range j.Lines {
		l := &j.Lines[i]
		acct, err := GetAccount(ctx, tx, l.AccountID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: line %d account not found", ErrLineRejected, l.LineNo)
			}
			return err
		}
		if acct.LegalEntityID != j.LegalEntityID {
			return fmt.Errorf("%w: line %d account belongs to another legal entity", ErrLineRejected, l.LineNo)
		}
		if !acct.Active {
			return fmt.Errorf("%w: line %d account %s is inactive", ErrLineRejected, l.LineNo, acct.Code)
		}
		if acct.Currency != "" && acct.Currency != j.FunctionalCurrency {
			if l.TxnAmount == nil || l.TxnAmount.Currency() != acct.Currency {
				return fmt.Errorf("%w: line %d account %s only accepts %s transactions", ErrLineRejected, l.LineNo, acct.Code, acct.Currency)
			}
		}
		if l.TxnAmount == nil {
			l.AppliedRate = decimal.Zero
			continue
		}
		snap, err := GetFXSnapshot(ctx, tx, l.FXSnapshotID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: line %d fx snapshot not found", ErrLineRejected, l.LineNo)
			}
			return err
		}
		if snap.ApprovalStatus != fx.StatusApproved {
			return fmt.Errorf("%w: line %d fx snapshot %s is %s, not APPROVED", ErrLineRejected, l.LineNo, snap.SnapshotID, snap.ApprovalStatus)
		}
		var rate decimal.Decimal
		switch {
		case snap.BaseCurrency == l.TxnAmount.Currency() && snap.QuoteCurrency == j.FunctionalCurrency:
			rate = snap.Rate
		case snap.BaseCurrency == j.FunctionalCurrency && snap.QuoteCurrency == l.TxnAmount.Currency():
			rate = decimal.NewFromInt(1).DivRound(snap.Rate, 12)
		default:
			return fmt.Errorf("%w: line %d snapshot pair %s/%s does not convert %s->%s", ErrLineRejected, l.LineNo,
				snap.BaseCurrency, snap.QuoteCurrency, l.TxnAmount.Currency(), j.FunctionalCurrency)
		}
		expect, err := money.New(l.TxnAmount.Amount().Mul(rate), j.FunctionalCurrency, money.RoundHalfEven)
		if err != nil {
			return err
		}
		if !expect.Equal(l.Amount) {
			return fmt.Errorf("%w: line %d amount %s does not reconcile to %s x %s = %s", ErrLineRejected, l.LineNo, l.Amount, l.TxnAmount, rate, expect)
		}
		l.AppliedRate = rate
	}
	return nil
}

// CreateJournal validates the journal against stored reference data and
// inserts it as DRAFT with its lines. If the idempotency key was already used
// with the same command, the existing id is returned with replayed=true; a
// different command under the same key is a conflict. The check is atomic
// under the unique index, so concurrent identical retries never conflict.
func CreateJournal(ctx context.Context, tx pgx.Tx, j ledger.Journal) (id string, replayed bool, err error) {
	j.Status = ledger.StatusDraft
	if err = j.Validate(); err != nil {
		return "", false, err
	}
	hash := CommandHash(j)

	id = j.ID
	if id == "" {
		id = newID()
	}
	var project, srcRef, revOf *string
	if j.ProjectID != "" {
		project = &j.ProjectID
	}
	if j.SourceRef != "" {
		srcRef = &j.SourceRef
	}
	if j.ReversalOf != "" {
		revOf = &j.ReversalOf
	}
	// Reserve the idempotency key first; ON CONFLICT makes the decision atomic.
	var inserted string
	err = tx.QueryRow(ctx, `INSERT INTO journals(id,tenant_id,legal_entity_id,project_id,functional_currency,status,business_event_at,description,
		source_type,source_ref,idempotency_key,command_hash,created_by,reversal_of)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,'DRAFT',$6,$7,$8,$9,$10,$11,$12,$13::uuid)
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING id::text`,
		id, j.TenantID, j.LegalEntityID, project, string(j.FunctionalCurrency), j.BusinessEventAt.UTC(), j.Description,
		j.SourceType, srcRef, j.IdempotencyKey, hash, j.CreatedBy, revOf).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingID, existingHash string
		if err := tx.QueryRow(ctx, `SELECT id::text, command_hash FROM journals WHERE idempotency_key=$1`, j.IdempotencyKey).Scan(&existingID, &existingHash); err != nil {
			return "", false, err
		}
		if existingHash != hash {
			return "", false, ErrIdempotencyConflict
		}
		return existingID, true, nil
	}
	if err != nil {
		return "", false, err
	}
	if err := bindLines(ctx, tx, &j); err != nil {
		return "", false, err
	}
	batch := &pgx.Batch{}
	for _, l := range j.Lines {
		var txnAmt, txnCur, snap, rate, lp, cc, memo *string
		if l.TxnAmount != nil {
			a, c, r := l.TxnAmount.AmountString(), string(l.TxnAmount.Currency()), l.AppliedRate.String()
			txnAmt, txnCur, rate = &a, &c, &r
		}
		if l.FXSnapshotID != "" {
			snap = &l.FXSnapshotID
		}
		if l.ProjectID != "" {
			lp = &l.ProjectID
		}
		if l.CostCodeID != "" {
			cc = &l.CostCodeID
		}
		if l.Memo != "" {
			memo = &l.Memo
		}
		batch.Queue(`INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency,txn_amount,txn_currency,fx_snapshot_id,applied_rate,project_id,cost_code_id,memo)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7::numeric,$8,$9::numeric,$10,$11::uuid,$12::numeric,$13::uuid,$14::uuid,$15)`,
			id, j.TenantID, j.LegalEntityID, l.LineNo, l.AccountID, string(l.Side), l.Amount.AmountString(), string(l.Amount.Currency()), txnAmt, txnCur, snap, rate, lp, cc, memo)
	}
	br := tx.SendBatch(ctx, batch)
	for range j.Lines {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return "", false, err
		}
	}
	if err := br.Close(); err != nil {
		return "", false, err
	}
	return id, false, nil
}

// JournalRecord is a journal with its persistence metadata.
type JournalRecord struct {
	ledger.Journal
	CommandHash string
	Version     int
	CreatedAt   time.Time
	ApprovedAt  *time.Time
	PostedAt    *time.Time
}

// GetJournal loads a journal with lines. forUpdate takes a row lock.
func GetJournal(ctx context.Context, tx pgx.Tx, id string, forUpdate bool) (JournalRecord, error) {
	q := `SELECT id::text, tenant_id::text, legal_entity_id::text, COALESCE(project_id::text,''), functional_currency, status, business_event_at,
		description, source_type, COALESCE(source_ref,''), idempotency_key, created_by, created_at, COALESCE(approved_by,''), approved_at,
		COALESCE(posted_by,''), posted_at, COALESCE(reversal_of::text,''), COALESCE(reversed_by::text,''), version, command_hash
		FROM journals WHERE id=$1::uuid`
	if forUpdate {
		q += " FOR UPDATE"
	}
	var r JournalRecord
	var cur string
	var st string
	err := tx.QueryRow(ctx, q, id).Scan(&r.ID, &r.TenantID, &r.LegalEntityID, &r.ProjectID, &cur, &st, &r.BusinessEventAt,
		&r.Description, &r.SourceType, &r.SourceRef, &r.IdempotencyKey, &r.CreatedBy, &r.CreatedAt, &r.ApprovedBy, &r.ApprovedAt,
		&r.PostedBy, &r.PostedAt, &r.ReversalOf, &r.ReversedBy, &r.Version, &r.CommandHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return JournalRecord{}, ErrNotFound
	}
	if err != nil {
		return JournalRecord{}, err
	}
	r.FunctionalCurrency, r.Status = money.Currency(cur), ledger.Status(st)

	rows, err := tx.Query(ctx, `SELECT line_no, account_id::text, side, amount::text, currency, txn_amount::text, txn_currency,
		COALESCE(fx_snapshot_id::text,''), COALESCE(applied_rate::text,'0'), COALESCE(project_id::text,''), COALESCE(cost_code_id::text,''), COALESCE(memo,'')
		FROM journal_lines WHERE journal_id=$1::uuid ORDER BY line_no`, id)
	if err != nil {
		return JournalRecord{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var l ledger.Line
		var side, amt, lcur, rate string
		var txnAmt, txnCur *string
		if err := rows.Scan(&l.LineNo, &l.AccountID, &side, &amt, &lcur, &txnAmt, &txnCur, &l.FXSnapshotID, &rate, &l.ProjectID, &l.CostCodeID, &l.Memo); err != nil {
			return JournalRecord{}, err
		}
		if l.AppliedRate, err = decimal.NewFromString(rate); err != nil {
			return JournalRecord{}, err
		}
		l.Side = ledger.Side(side)
		if l.Amount, err = money.Parse(amt, money.Currency(lcur), money.DefaultRounding); err != nil {
			return JournalRecord{}, err
		}
		if txnAmt != nil && txnCur != nil {
			m, err := money.Parse(*txnAmt, money.Currency(*txnCur), money.DefaultRounding)
			if err != nil {
				return JournalRecord{}, err
			}
			l.TxnAmount = &m
		}
		r.Lines = append(r.Lines, l)
	}
	return r, rows.Err()
}

// ApproveJournal moves DRAFT -> APPROVED with optimistic concurrency.
func ApproveJournal(ctx context.Context, tx pgx.Tx, id, by string, expectedVersion int) error {
	tag, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by=$2, approved_at=now() WHERE id=$1::uuid AND version=$3`, id, by, expectedVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// PostJournal moves APPROVED -> POSTED. If the journal is a reversal, the
// original is atomically marked REVERSED in the same transaction.
func PostJournal(ctx context.Context, tx pgx.Tx, id, by string, expectedVersion int) error {
	var revOf *string
	if err := tx.QueryRow(ctx, `SELECT reversal_of::text FROM journals WHERE id=$1::uuid FOR UPDATE`, id).Scan(&revOf); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if revOf != nil {
		// Lock the original and ensure it is still reversible.
		var st string
		var reversedBy *string
		if err := tx.QueryRow(ctx, `SELECT status, reversed_by::text FROM journals WHERE id=$1::uuid FOR UPDATE`, *revOf).Scan(&st, &reversedBy); err != nil {
			return fmt.Errorf("original journal: %w", err)
		}
		if st != string(ledger.StatusPosted) || reversedBy != nil {
			return fmt.Errorf("%w: original journal %s is %s and cannot be reversed", ErrInvariant, *revOf, st)
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE journals SET status='POSTED', posted_by=$2, posted_at=now() WHERE id=$1::uuid AND version=$3`, id, by, expectedVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	if revOf != nil {
		if _, err := tx.Exec(ctx, `UPDATE journals SET status='REVERSED', reversed_by=$2::uuid WHERE id=$1::uuid`, *revOf, id); err != nil {
			return err
		}
	}
	return nil
}

// CancelJournal moves DRAFT/APPROVED -> CANCELLED.
func CancelJournal(ctx context.Context, tx pgx.Tx, id string, expectedVersion int) error {
	tag, err := tx.Exec(ctx, `UPDATE journals SET status='CANCELLED' WHERE id=$1::uuid AND version=$2`, id, expectedVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// AccountBalance returns the net posted balance (debits − credits) of an
// account in its functional currency.
func AccountBalance(ctx context.Context, tx pgx.Tx, accountID string, cur money.Currency) (money.Money, error) {
	var s string
	err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(CASE WHEN l.side='DEBIT' THEN l.amount ELSE -l.amount END),0)::text
		FROM journal_lines l JOIN journals j ON j.id=l.journal_id
		WHERE l.account_id=$1::uuid AND l.currency=$2 AND j.status IN ('POSTED','REVERSED')`, accountID, string(cur)).Scan(&s)
	if err != nil {
		return money.Money{}, err
	}
	return money.Parse(s, cur, money.DefaultRounding)
}

// ---------------------------------------------------------------------------
// Audit log and outbox
// ---------------------------------------------------------------------------

// AuditEntry is one append-only audit record.
type AuditEntry struct {
	TenantID      string
	ActorID       string
	Action        string
	AggregateType string
	AggregateID   string
	RequestID     string
	Payload       any
}

// Audit appends to the hash-chained audit log. Hashing happens in the
// database trigger so it cannot be skipped by any code path.
func Audit(ctx context.Context, tx pgx.Tx, e AuditEntry) error {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	var rid *string
	if e.RequestID != "" {
		rid = &e.RequestID
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(tenant_id,actor_id,action,aggregate_type,aggregate_id,request_id,payload)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::jsonb)`, e.TenantID, e.ActorID, e.Action, e.AggregateType, e.AggregateID, rid, string(payload))
	return err
}

// VerifyAuditChain returns the first broken sequence number (-1 when the
// head row disagrees with the log), or 0 if intact.
func VerifyAuditChain(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	var seq *int64
	if err := tx.QueryRow(ctx, `SELECT audit_log_verify($1::uuid)`, tenantID).Scan(&seq); err != nil {
		return 0, err
	}
	if seq == nil {
		return 0, nil
	}
	return *seq, nil
}

// OutboxEvent is a domain event written in the same transaction as the
// state change it describes.
type OutboxEvent struct {
	TenantID      string
	AggregateType string
	AggregateID   string
	EventType     string
	SchemaVersion int
	Payload       any
}

// Outbox appends an event for asynchronous delivery.
func Outbox(ctx context.Context, tx pgx.Tx, e OutboxEvent) error {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = 1
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox(tenant_id,aggregate_type,aggregate_id,event_type,schema_version,payload)
		VALUES ($1::uuid,$2,$3,$4,$5,$6::jsonb)`, e.TenantID, e.AggregateType, e.AggregateID, e.EventType, e.SchemaVersion, string(payload))
	return err
}

// PendingOutbox claims unpublished events for the current tenant, oldest
// first. It requires the serk_publisher role (row locks need UPDATE); the
// API role cannot call it.
func PendingOutbox(ctx context.Context, tx pgx.Tx, limit int) ([]OutboxRow, error) {
	rows, err := tx.Query(ctx, `SELECT id, event_id::text, aggregate_type, aggregate_id, event_type, schema_version, payload::text, created_at
		FROM outbox WHERE published_at IS NULL ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(&r.ID, &r.EventID, &r.AggregateType, &r.AggregateID, &r.EventType, &r.SchemaVersion, &r.Payload, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OutboxRow is a stored outbox event.
type OutboxRow struct {
	ID            int64
	EventID       string
	AggregateType string
	AggregateID   string
	EventType     string
	SchemaVersion int
	Payload       string
	CreatedAt     time.Time
}

// MarkPublished records successful delivery.
func MarkPublished(ctx context.Context, tx pgx.Tx, id int64) error {
	_, err := tx.Exec(ctx, `UPDATE outbox SET published_at=now(), attempts=attempts+1 WHERE id=$1`, id)
	return err
}
