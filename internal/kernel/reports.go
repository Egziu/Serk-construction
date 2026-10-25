package kernel

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Financial reports. All are read-only and need tenant-wide scope: they
// aggregate across projects, so a project-scoped person could otherwise
// infer other projects' figures.

// TrialBalance is the entity's posted trial balance at a date.
type TrialBalance struct {
	AsOf        string                     `json:"as_of"`
	Rows        []postgres.TrialBalanceRow `json:"accounts"`
	TotalDebit  decimal.Decimal            `json:"total_debit"`
	TotalCredit decimal.Decimal            `json:"total_credit"`
	Difference  decimal.Decimal            `json:"difference"`
	Balanced    bool                       `json:"balanced"`
}

// Aging is an open-item aging by due date.
type Aging struct {
	AsOf    string       `json:"as_of"`
	Items   []AgingItem  `json:"items"`
	Parties []AgingTotal `json:"by_party"`
	Total   AgingTotal   `json:"total"`
}

// AgingItem is one open invoice with its bucket.
type AgingItem struct {
	Party       string          `json:"party"`
	Document    string          `json:"document"`
	InvoiceDate string          `json:"invoice_date"`
	DueDate     string          `json:"due_date"`
	Currency    string          `json:"currency"`
	DaysOverdue int             `json:"days_overdue"`
	Open        decimal.Decimal `json:"open"`
}

// AgingTotal is open amounts per bucket.
type AgingTotal struct {
	Party  string          `json:"party"`
	NotDue decimal.Decimal `json:"not_due"`
	D1to30 decimal.Decimal `json:"d1_30"`
	D31to6 decimal.Decimal `json:"d31_60"`
	D61to9 decimal.Decimal `json:"d61_90"`
	Over90 decimal.Decimal `json:"over_90"`
	Open   decimal.Decimal `json:"open"`
}

func (t *AgingTotal) add(days int, v decimal.Decimal) {
	switch {
	case days <= 0:
		t.NotDue = t.NotDue.Add(v)
	case days <= 30:
		t.D1to30 = t.D1to30.Add(v)
	case days <= 60:
		t.D31to6 = t.D31to6.Add(v)
	case days <= 90:
		t.D61to9 = t.D61to9.Add(v)
	default:
		t.Over90 = t.Over90.Add(v)
	}
	t.Open = t.Open.Add(v)
}

func (s *Service) reportScope(p auth.Principal, perm auth.Permission) error {
	if err := s.authz.Require(p, perm, p.TenantID); err != nil {
		return err
	}
	if !s.tenantWide(p) {
		return fmt.Errorf("%w: this report needs tenant-wide scope", auth.ErrForbidden)
	}
	return nil
}

// TrialBalanceReport returns the trial balance of an entity at asOf.
func (s *Service) TrialBalanceReport(ctx context.Context, p auth.Principal, entityID string, asOf time.Time) (TrialBalance, error) {
	if err := s.reportScope(p, auth.PermJournalRead); err != nil {
		return TrialBalance{}, err
	}
	out := TrialBalance{AsOf: asOf.Format("2006-01-02")}
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out.Rows, err = postgres.TrialBalance(ctx, tx, entityID, asOf)
		return err
	})
	for _, r := range out.Rows {
		out.TotalDebit = out.TotalDebit.Add(r.Debit)
		out.TotalCredit = out.TotalCredit.Add(r.Credit)
	}
	out.Difference = out.TotalDebit.Sub(out.TotalCredit)
	out.Balanced = out.Difference.IsZero()
	return out, err
}

// PayablesAging ages approved supplier invoices still open at asOf.
func (s *Service) PayablesAging(ctx context.Context, p auth.Principal, entityID string, asOf time.Time) (Aging, error) {
	return s.aging(ctx, p, entityID, asOf, postgres.PayablesOpen)
}

// ReceivablesAging ages approved customer invoices still open at asOf.
func (s *Service) ReceivablesAging(ctx context.Context, p auth.Principal, entityID string, asOf time.Time) (Aging, error) {
	return s.aging(ctx, p, entityID, asOf, postgres.ReceivablesOpen)
}

func (s *Service) aging(ctx context.Context, p auth.Principal, entityID string, asOf time.Time,
	q func(context.Context, pgx.Tx, string, time.Time) ([]postgres.OpenItem, error)) (Aging, error) {
	if err := s.reportScope(p, auth.PermP2PRead); err != nil {
		return Aging{}, err
	}
	var items []postgres.OpenItem
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		items, err = q(ctx, tx, entityID, asOf)
		return err
	})
	if err != nil {
		return Aging{}, err
	}
	out := Aging{AsOf: asOf.Format("2006-01-02"), Total: AgingTotal{Party: "Total"}, Items: []AgingItem{}, Parties: []AgingTotal{}}
	idx := map[string]int{}
	day := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	for _, it := range items {
		due := time.Date(it.DueDate.Year(), it.DueDate.Month(), it.DueDate.Day(), 0, 0, 0, 0, time.UTC)
		days := int(day.Sub(due).Hours() / 24)
		out.Items = append(out.Items, AgingItem{Party: it.Party, Document: it.Document, InvoiceDate: it.InvoiceDate.Format("2006-01-02"),
			DueDate: it.DueDate.Format("2006-01-02"), Currency: it.Currency, DaysOverdue: max(days, 0), Open: it.Open})
		i, ok := idx[it.Party]
		if !ok {
			i = len(out.Parties)
			idx[it.Party] = i
			out.Parties = append(out.Parties, AgingTotal{Party: it.Party})
		}
		out.Parties[i].add(days, it.Open)
		out.Total.add(days, it.Open)
	}
	return out, nil
}
