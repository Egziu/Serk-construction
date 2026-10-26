// Package automation defines the customer-configurable rule language of SERK
// Construction OS: what a rule may watch and what it may do.
//
// A rule watches a condition from a fixed catalogue (documents waiting too
// long, invoices falling due, budgets nearly consumed, schedules slipping,
// unusual data access, …) and, when it matches, raises a notification to a
// role or a person. That is the whole action set: a rule informs and
// escalates; it never approves, posts, pays, releases or changes a document.
// Decisions stay with people and are re-verified by the database.
package automation

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

// Kind names a condition in the catalogue.
type Kind string

const (
	// DocumentStale: documents of Subject in Status for more than Hours.
	DocumentStale Kind = "document_stale"
	// InvoiceDue: approved supplier invoices due within Days (or overdue).
	InvoiceDue Kind = "invoice_due"
	// ReceivableOverdue: approved customer invoices overdue by more than Days.
	ReceivableOverdue Kind = "receivable_overdue"
	// POOverdue: approved purchase orders past needed_by and still open.
	POOverdue Kind = "po_overdue"
	// BudgetThreshold: a cost code whose consumed share of budget is at least Percent.
	BudgetThreshold Kind = "budget_threshold"
	// StockBelow: a stock item whose on-hand quantity is at or below Quantity.
	StockBelow Kind = "stock_below"
	// ScheduleRisk: a project whose SPI is below Ratio.
	ScheduleRisk Kind = "schedule_risk"
	// CostRisk: a project whose CPI is below Ratio.
	CostRisk Kind = "cost_risk"
	// ExportVolume: a person who exported more than Count files in 24 hours.
	ExportVolume Kind = "export_volume"
)

// Kinds lists the catalogue in display order.
var Kinds = []Kind{DocumentStale, InvoiceDue, ReceivableOverdue, POOverdue, BudgetThreshold, StockBelow, ScheduleRisk, CostRisk, ExportVolume}

// Describe explains a kind and its parameters for the console.
func Describe(k Kind) string {
	switch k {
	case DocumentStale:
		return "Documents of a type that have waited in a status longer than a number of hours (subject, status, hours)."
	case InvoiceDue:
		return "Approved supplier invoices due within a number of days, including overdue ones (days)."
	case ReceivableOverdue:
		return "Approved customer invoices overdue by more than a number of days (days)."
	case POOverdue:
		return "Approved purchase orders past their needed-by date that are still open."
	case BudgetThreshold:
		return "Cost codes whose committed plus actual cost reaches a percentage of budget (percent)."
	case StockBelow:
		return "A stock item whose quantity on hand is at or below a level (item_code, quantity)."
	case ScheduleRisk:
		return "Projects with a baseline whose schedule performance index is below a ratio (ratio)."
	case CostRisk:
		return "Projects with a baseline whose cost performance index is below a ratio (ratio)."
	case ExportVolume:
		return "A person who exported more than a number of files in the last 24 hours (count). Addressed to security."
	}
	return ""
}

// Condition is the "when" of a rule.
type Condition struct {
	Kind     Kind            `json:"kind"`
	Subject  string          `json:"subject,omitempty"`
	Status   string          `json:"status,omitempty"`
	Hours    int             `json:"hours,omitempty"`
	Days     int             `json:"days,omitempty"`
	Percent  int             `json:"percent,omitempty"`
	Count    int             `json:"count,omitempty"`
	ItemCode string          `json:"item_code,omitempty"`
	Quantity decimal.Decimal `json:"quantity,omitempty"`
	Ratio    decimal.Decimal `json:"ratio,omitempty"`
}

// Action is the "then" of a rule: who is told and how loudly.
type Action struct {
	NotifyRole string `json:"notify_role,omitempty"`
	NotifyUser string `json:"notify_user,omitempty"`
	Severity   string `json:"severity"` // info | warn | critical
	Title      string `json:"title,omitempty"`
}

// Rule is a validated rule body.
type Rule struct {
	When Condition `json:"when"`
	Then Action    `json:"then"`
}

// ErrInvalid wraps validation failures.
var ErrInvalid = errors.New("automation: invalid rule")

var (
	subjectRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)
	statusRe  = regexp.MustCompile(`^[A-Z][A-Z_]{2,40}$`)
	roleRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)
	userRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,120}$`)
	itemRe    = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{1,30}$`)
)

// Parse decodes and validates a rule body. Unknown fields are refused so a
// typo cannot silently disable a condition.
func Parse(body []byte) (Rule, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var r Rule
	if err := dec.Decode(&r); err != nil {
		return Rule{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return Rule{}, fmt.Errorf("%w: trailing content", ErrInvalid)
	}
	return r, r.Validate()
}

// Validate checks the rule against the catalogue.
func (r Rule) Validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrInvalid}, a...)...) }
	c := r.When
	switch c.Kind {
	case DocumentStale:
		if !subjectRe.MatchString(c.Subject) || !statusRe.MatchString(c.Status) {
			return bad("document_stale needs a subject type and a status")
		}
		if c.Hours < 1 || c.Hours > 24*365 {
			return bad("hours must be 1..8760")
		}
	case InvoiceDue:
		if c.Days < 0 || c.Days > 365 {
			return bad("days must be 0..365")
		}
	case ReceivableOverdue:
		if c.Days < 0 || c.Days > 3650 {
			return bad("days must be 0..3650")
		}
	case POOverdue:
	case BudgetThreshold:
		if c.Percent < 1 || c.Percent > 1000 {
			return bad("percent must be 1..1000")
		}
	case StockBelow:
		if !itemRe.MatchString(c.ItemCode) || c.Quantity.IsNegative() {
			return bad("stock_below needs an item_code and a non-negative quantity")
		}
	case ScheduleRisk, CostRisk:
		if !c.Ratio.IsPositive() || c.Ratio.GreaterThan(decimal.NewFromInt(10)) {
			return bad("ratio must be between 0 and 10")
		}
	case ExportVolume:
		if c.Count < 1 || c.Count > 100000 {
			return bad("count must be 1..100000")
		}
	default:
		return bad("unknown condition kind %q", c.Kind)
	}
	a := r.Then
	switch {
	case a.NotifyRole == "" && a.NotifyUser == "":
		return bad("then needs notify_role or notify_user")
	case a.NotifyRole != "" && !roleRe.MatchString(a.NotifyRole):
		return bad("notify_role is not a role name")
	case a.NotifyUser != "" && !userRe.MatchString(a.NotifyUser):
		return bad("notify_user is not a user id")
	}
	switch a.Severity {
	case "info", "warn", "critical":
	default:
		return bad("severity must be info, warn or critical")
	}
	if len(a.Title) > 200 {
		return bad("title is at most 200 characters")
	}
	return nil
}

// Finding is one match of a rule: a subject that needs a person's attention.
type Finding struct {
	SubjectType string
	SubjectID   string
	ProjectID   string
	Title       string
	Body        string
	Href        string
	// Key distinguishes recurrences; the dedupe key is rule + subject + Key.
	Key string
}

// DedupeKey is the notification key for a finding of a rule.
func DedupeKey(ruleCode string, f Finding) string {
	k := ruleCode + ":" + f.SubjectType + ":" + f.SubjectID
	if f.Key != "" {
		k += ":" + f.Key
	}
	return k
}

// Horizon is the time window a condition looks at, for display.
func (c Condition) Horizon(now time.Time) string {
	switch c.Kind {
	case DocumentStale:
		return fmt.Sprintf("waiting since before %s", now.Add(-time.Duration(c.Hours)*time.Hour).Format("2 Jan 15:04"))
	case InvoiceDue:
		return fmt.Sprintf("due by %s", now.AddDate(0, 0, c.Days).Format("2 Jan 2006"))
	case ReceivableOverdue:
		return fmt.Sprintf("overdue more than %d days", c.Days)
	case ExportVolume:
		return "last 24 hours"
	}
	return "now"
}
