package ledger

import (
	"errors"
	"testing"
	"time"

	"github.com/serk-group/serk-construction/pkg/money"
)

func sample() Journal {
	return Journal{
		ID: "j1", TenantID: "t1", LegalEntityID: "le1", FunctionalCurrency: "ETB", Status: StatusDraft,
		BusinessEventAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Description: "Cement purchase",
		SourceType: "MANUAL", IdempotencyKey: "cmd-001", CreatedBy: "u-prep",
		Lines: []Line{
			{LineNo: 1, AccountID: "a-inventory", Side: Debit, Amount: money.MustNew("1150.00", "ETB")},
			{LineNo: 2, AccountID: "a-vat-input", Side: Debit, Amount: money.MustNew("172.50", "ETB")},
			{LineNo: 3, AccountID: "a-ap", Side: Credit, Amount: money.MustNew("1322.50", "ETB")},
		},
	}
}

func TestValidJournal(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUnbalancedRejected(t *testing.T) {
	j := sample()
	j.Lines[2].Amount = money.MustNew("1322.51", "ETB")
	if err := j.Validate(); !errors.Is(err, ErrUnbalanced) {
		t.Fatalf("want ErrUnbalanced got %v", err)
	}
}

func TestLineRules(t *testing.T) {
	j := sample()
	j.Lines = j.Lines[:1]
	if err := j.Validate(); !errors.Is(err, ErrTooFewLines) {
		t.Fatalf("want too few lines got %v", err)
	}

	j = sample()
	j.Lines[0].Amount = money.MustNew("-1150.00", "ETB")
	if err := j.Validate(); !errors.Is(err, ErrBadLine) {
		t.Fatalf("negative line accepted: %v", err)
	}

	j = sample()
	j.Lines[0].Amount = money.MustNew("1150.00", "USD")
	if err := j.Validate(); !errors.Is(err, ErrBadLine) {
		t.Fatalf("foreign functional amount accepted: %v", err)
	}

	j = sample()
	usd := money.MustNew("20.00", "USD")
	j.Lines[0].TxnAmount = &usd
	if err := j.Validate(); !errors.Is(err, ErrBadLine) {
		t.Fatalf("foreign amount without snapshot accepted: %v", err)
	}
	j.Lines[0].FXSnapshotID = "snap-1"
	if err := j.Validate(); err != nil {
		t.Fatalf("valid fx line rejected: %v", err)
	}

	j = sample()
	j.Lines[1].LineNo = 5
	if err := j.Validate(); !errors.Is(err, ErrBadLine) {
		t.Fatalf("non-contiguous line numbers accepted: %v", err)
	}

	j = sample()
	j.IdempotencyKey = " "
	if err := j.Validate(); !errors.Is(err, ErrMissingIdempotencyKey) {
		t.Fatalf("missing idempotency key accepted: %v", err)
	}

	j = sample()
	j.ProjectID = "p1"
	j.Lines[0].ProjectID = "p2"
	if err := j.Validate(); !errors.Is(err, ErrBadLine) {
		t.Fatalf("cross-project line accepted: %v", err)
	}
}

func TestStateMachine(t *testing.T) {
	j := sample()
	if err := j.Transition(StatusPosted); !errors.Is(err, ErrBadTransition) {
		t.Fatal("draft -> posted must be illegal (approval skipped)")
	}
	if err := j.Transition(StatusApproved); err != nil {
		t.Fatal(err)
	}
	if err := j.Transition(StatusDraft); !errors.Is(err, ErrBadTransition) {
		t.Fatal("approved -> draft must be illegal")
	}
	if err := j.Transition(StatusPosted); err != nil {
		t.Fatal(err)
	}
	for _, to := range []Status{StatusDraft, StatusApproved, StatusCancelled, StatusPosted} {
		if err := j.Transition(to); !errors.Is(err, ErrBadTransition) {
			t.Fatalf("posted -> %s must be illegal", to)
		}
	}
	if err := j.Transition(StatusReversed); err != nil {
		t.Fatal(err)
	}
	if CanTransition(StatusReversed, StatusPosted) || CanTransition(StatusCancelled, StatusApproved) {
		t.Fatal("terminal states must not transition")
	}
}

func TestReversalMirrorsLines(t *testing.T) {
	j := sample()
	_ = j.Transition(StatusApproved)
	_ = j.Transition(StatusPosted)
	r, err := j.Reversal("j2", "cmd-002", "u-rev", j.BusinessEventAt.AddDate(0, 0, 1), "wrong supplier")
	if err != nil {
		t.Fatal(err)
	}
	if r.ReversalOf != "j1" || r.Status != StatusDraft || len(r.Lines) != 3 {
		t.Fatalf("bad reversal %+v", r)
	}
	for i := range j.Lines {
		if r.Lines[i].Side == j.Lines[i].Side || !r.Lines[i].Amount.Equal(j.Lines[i].Amount) {
			t.Fatalf("line %d not mirrored", i)
		}
	}
	// Net effect of original + reversal is zero per account.
	net := map[string]money.Money{}
	for _, l := range append(append([]Line{}, j.Lines...), r.Lines...) {
		cur := net[l.AccountID]
		if !cur.IsValid() {
			cur, _ = money.Zero("ETB")
		}
		if l.Side == Debit {
			cur, _ = cur.Add(l.Amount)
		} else {
			cur, _ = cur.Sub(l.Amount)
		}
		net[l.AccountID] = cur
	}
	for acct, v := range net {
		if !v.IsZero() {
			t.Fatalf("account %s net %s after reversal", acct, v)
		}
	}
	// Cannot reverse a draft, nor reverse twice.
	d := sample()
	if _, err := d.Reversal("x", "k", "u", time.Now(), "r"); !errors.Is(err, ErrNotPosted) {
		t.Fatal("reversing draft allowed")
	}
	j.ReversedBy = "j2"
	if _, err := j.Reversal("j3", "cmd-003", "u", time.Now(), "again"); !errors.Is(err, ErrAlreadyReversed) {
		t.Fatal("double reversal allowed")
	}
	if _, err := sample().Reversal("x", "k", "u", time.Now(), ""); err == nil {
		t.Fatal("empty reason allowed")
	}
}

func TestAccountValidate(t *testing.T) {
	a := Account{ID: "a", TenantID: "t", LegalEntityID: "le", Code: "1000", Name: "Cash", Type: Asset, Active: true}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.Type = "WEIRD"
	if err := a.Validate(); err == nil {
		t.Fatal("bad type accepted")
	}
	a.Type = Asset
	a.Currency = "XXX"
	if err := a.Validate(); err == nil {
		t.Fatal("unknown currency accepted")
	}
	for _, c := range []struct {
		t AccountType
		s Side
	}{{Asset, Debit}, {Expense, Debit}, {Liability, Credit}, {Equity, Credit}, {Revenue, Credit}} {
		s, _ := c.t.NormalBalance()
		if s != c.s {
			t.Fatalf("%s normal balance %s", c.t, s)
		}
	}
}
