// Package ledger is the deterministic accounting domain of the SERK
// Construction financial kernel (Pillar 2).
//
// It defines accounts, journals and the posting state machine, and enforces
// the invariants of LAW 03 in pure Go so they can be unit-tested without a
// database. The PostgreSQL store enforces the same invariants again at the
// transaction boundary (defense in depth).
package ledger

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

// AccountType is the five-way classification driving normal balances.
type AccountType string

const (
	Asset     AccountType = "ASSET"
	Liability AccountType = "LIABILITY"
	Equity    AccountType = "EQUITY"
	Revenue   AccountType = "REVENUE"
	Expense   AccountType = "EXPENSE"
)

// Side of a ledger entry.
type Side string

const (
	Debit  Side = "DEBIT"
	Credit Side = "CREDIT"
)

// NormalBalance returns the side on which the account type normally carries
// its balance.
func (t AccountType) NormalBalance() (Side, error) {
	switch t {
	case Asset, Expense:
		return Debit, nil
	case Liability, Equity, Revenue:
		return Credit, nil
	}
	return "", fmt.Errorf("ledger: unknown account type %q", t)
}

// Account is a chart-of-accounts entry owned by a tenant and legal entity.
type Account struct {
	ID            string
	TenantID      string
	LegalEntityID string
	Code          string
	Name          string
	Type          AccountType
	// Currency restricts postings to a single currency when set (e.g. a
	// USD bank account). Empty means the entity's functional currency.
	Currency money.Currency
	Active   bool
}

// Validate checks the account definition.
func (a Account) Validate() error {
	switch {
	case a.TenantID == "":
		return errors.New("ledger: account tenant required")
	case a.LegalEntityID == "":
		return errors.New("ledger: account legal entity required")
	case strings.TrimSpace(a.Code) == "":
		return errors.New("ledger: account code required")
	case strings.TrimSpace(a.Name) == "":
		return errors.New("ledger: account name required")
	}
	if _, err := a.Type.NormalBalance(); err != nil {
		return err
	}
	if a.Currency != "" && !money.IsKnown(a.Currency) {
		return fmt.Errorf("ledger: account currency %q unknown", a.Currency)
	}
	return nil
}

// Status is the journal lifecycle state.
//
//	DRAFT ──approve──▶ APPROVED ──post──▶ POSTED ──reverse──▶ REVERSED
//	  │                    │
//	  └──────cancel────────┘──▶ CANCELLED
//
// POSTED and REVERSED are terminal for the original record: posted lines are
// never edited; a reversal is a new POSTED journal that references the
// original (LAW 03).
type Status string

const (
	StatusDraft     Status = "DRAFT"
	StatusApproved  Status = "APPROVED"
	StatusPosted    Status = "POSTED"
	StatusReversed  Status = "REVERSED"
	StatusCancelled Status = "CANCELLED"
)

// CanTransition reports whether from→to is a legal state change.
func CanTransition(from, to Status) bool {
	switch from {
	case StatusDraft:
		return to == StatusApproved || to == StatusCancelled
	case StatusApproved:
		return to == StatusPosted || to == StatusCancelled
	case StatusPosted:
		return to == StatusReversed
	}
	return false
}

// Line is one side of a double entry. Amounts are in the legal entity's
// functional currency. When the originating transaction was in another
// currency, TxnAmount and FXSnapshotID record the provenance (LAW 06).
type Line struct {
	LineNo       int
	AccountID    string
	Side         Side
	Amount       money.Money  // functional currency, always positive
	TxnAmount    *money.Money // original transaction-currency amount, optional
	FXSnapshotID string       // required when TxnAmount is set
	// AppliedRate (functional units per one transaction unit) is set by the
	// kernel from the referenced snapshot, never by the client; it is stored
	// with the line so the amount is reproducible (LAW 06).
	AppliedRate decimal.Decimal
	// FXPolicyID / FXPolicyVersion identify the approved entity FX policy
	// under which the snapshot was selected (SC-02); set by the kernel.
	FXPolicyID      string
	FXPolicyVersion int
	ProjectID       string // project dimension (required for project-scoped journals)
	CostCodeID      string // WBS / cost code dimension, optional
	Memo            string
}

// Journal is a set of lines that must balance.
type Journal struct {
	ID                 string
	TenantID           string
	LegalEntityID      string
	ProjectID          string // optional project scope
	FunctionalCurrency money.Currency
	Status             Status
	// BusinessEventAt is the accounting date of the event (not server time).
	BusinessEventAt time.Time
	Description     string
	SourceType      string // e.g. MANUAL, AP_INVOICE, PAYROLL
	SourceRef       string
	// IdempotencyKey makes command replay safe (LAW 05: offline-prepared
	// commands are committed exactly once by the server).
	IdempotencyKey string
	Lines          []Line
	// Workflow actors, used for segregation of duties.
	CreatedBy  string
	ApprovedBy string
	PostedBy   string
	// ReversalOf references the original journal for reversing entries.
	ReversalOf string
	ReversedBy string
}

// Validation errors.
var (
	ErrUnbalanced            = errors.New("ledger: journal does not balance")
	ErrTooFewLines           = errors.New("ledger: a journal needs at least two lines")
	ErrBadLine               = errors.New("ledger: invalid line")
	ErrBadTransition         = errors.New("ledger: illegal status transition")
	ErrNotPosted             = errors.New("ledger: journal is not posted")
	ErrAlreadyReversed       = errors.New("ledger: journal already reversed")
	ErrMissingIdempotencyKey = errors.New("ledger: idempotency key required")
)

// Totals returns the debit and credit sums.
func (j Journal) Totals() (debits, credits money.Money, err error) {
	debits, err = money.Zero(j.FunctionalCurrency)
	if err != nil {
		return
	}
	credits = debits
	for _, l := range j.Lines {
		switch l.Side {
		case Debit:
			debits, err = debits.Add(l.Amount)
		case Credit:
			credits, err = credits.Add(l.Amount)
		default:
			err = fmt.Errorf("%w: line %d has side %q", ErrBadLine, l.LineNo, l.Side)
		}
		if err != nil {
			return
		}
	}
	return
}

// Validate enforces every structural invariant of a journal. It does not
// check account existence or period status — those need the store.
func (j Journal) Validate() error {
	switch {
	case j.TenantID == "":
		return errors.New("ledger: tenant required")
	case j.LegalEntityID == "":
		return errors.New("ledger: legal entity required")
	case !money.IsKnown(j.FunctionalCurrency):
		return fmt.Errorf("ledger: functional currency %q unknown", j.FunctionalCurrency)
	case j.BusinessEventAt.IsZero():
		return errors.New("ledger: business event time required")
	case strings.TrimSpace(j.IdempotencyKey) == "":
		return ErrMissingIdempotencyKey
	case len(j.IdempotencyKey) > 128:
		return errors.New("ledger: idempotency key too long")
	case strings.TrimSpace(j.Description) == "":
		return errors.New("ledger: description required")
	case len(j.Lines) < 2:
		return ErrTooFewLines
	case len(j.Lines) > 10_000:
		return errors.New("ledger: too many lines")
	case j.CreatedBy == "":
		return errors.New("ledger: created_by required")
	}
	seen := map[int]bool{}
	for i, l := range j.Lines {
		if l.LineNo != i+1 {
			return fmt.Errorf("%w: line numbers must be contiguous from 1 (got %d at index %d)", ErrBadLine, l.LineNo, i)
		}
		if seen[l.LineNo] {
			return fmt.Errorf("%w: duplicate line %d", ErrBadLine, l.LineNo)
		}
		seen[l.LineNo] = true
		if l.AccountID == "" {
			return fmt.Errorf("%w: line %d has no account", ErrBadLine, l.LineNo)
		}
		if l.Side != Debit && l.Side != Credit {
			return fmt.Errorf("%w: line %d side %q", ErrBadLine, l.LineNo, l.Side)
		}
		if !l.Amount.IsValid() || !l.Amount.IsPositive() {
			return fmt.Errorf("%w: line %d amount must be positive", ErrBadLine, l.LineNo)
		}
		if l.Amount.Currency() != j.FunctionalCurrency {
			return fmt.Errorf("%w: line %d currency %s differs from functional %s", ErrBadLine, l.LineNo, l.Amount.Currency(), j.FunctionalCurrency)
		}
		if l.TxnAmount != nil {
			if !l.TxnAmount.IsValid() || l.TxnAmount.Currency() == j.FunctionalCurrency {
				return fmt.Errorf("%w: line %d transaction amount must be in a foreign currency", ErrBadLine, l.LineNo)
			}
			if l.FXSnapshotID == "" {
				return fmt.Errorf("%w: line %d foreign amount without fx snapshot (LAW 06)", ErrBadLine, l.LineNo)
			}
		}
		if l.CostCodeID != "" && j.ProjectID == "" {
			return fmt.Errorf("%w: line %d has a cost code but the journal has no project", ErrBadLine, l.LineNo)
		}
		// A line's project dimension must equal the journal's project: project
		// authorisation is decided once, on the header, and cannot be
		// bypassed by tagging lines with another project.
		if l.ProjectID != "" && l.ProjectID != j.ProjectID {
			return fmt.Errorf("%w: line %d project %s differs from journal project %q", ErrBadLine, l.LineNo, l.ProjectID, j.ProjectID)
		}
	}
	d, c, err := j.Totals()
	if err != nil {
		return err
	}
	if !d.Equal(c) {
		return fmt.Errorf("%w: debits %s credits %s", ErrUnbalanced, d, c)
	}
	return nil
}

// Transition applies a status change, enforcing the state machine.
func (j *Journal) Transition(to Status) error {
	if !CanTransition(j.Status, to) {
		return fmt.Errorf("%w: %s -> %s", ErrBadTransition, j.Status, to)
	}
	j.Status = to
	return nil
}

// Reversal builds the compensating journal for a posted journal: every line
// is mirrored on the opposite side with the same amounts, so the original
// history is preserved and the net effect is nil (LAW 03).
func (j Journal) Reversal(newID, idempotencyKey, createdBy string, eventAt time.Time, reason string) (Journal, error) {
	if j.Status != StatusPosted {
		return Journal{}, ErrNotPosted
	}
	if j.ReversedBy != "" {
		return Journal{}, ErrAlreadyReversed
	}
	if strings.TrimSpace(reason) == "" {
		return Journal{}, errors.New("ledger: reversal reason required")
	}
	r := Journal{
		ID: newID, TenantID: j.TenantID, LegalEntityID: j.LegalEntityID, ProjectID: j.ProjectID,
		FunctionalCurrency: j.FunctionalCurrency, Status: StatusDraft, BusinessEventAt: eventAt,
		Description: "REVERSAL of " + j.ID + ": " + reason, SourceType: "REVERSAL", SourceRef: j.ID,
		IdempotencyKey: idempotencyKey, CreatedBy: createdBy, ReversalOf: j.ID,
	}
	for _, l := range j.Lines {
		m := l
		if l.Side == Debit {
			m.Side = Credit
		} else {
			m.Side = Debit
		}
		r.Lines = append(r.Lines, m)
	}
	return r, r.Validate()
}
