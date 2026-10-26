package kernel

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/automation"
)

// Platform (0038): tenant portal settings, notifications, automation rules
// and the automation worker. The worker is an observer: it reads documents
// through the same scoped queries a person would, and writes notifications
// and risk snapshots only. It holds no approval permission and signs nothing.

// SystemAutomationActor is the audit identity of the automation worker.
const SystemAutomationActor = "system:automation"

// AutomationAlgorithm versions the evaluator so recorded findings can be
// interpreted later.
const AutomationAlgorithm = "automation/1"

// ---------------------------------------------------------------- settings

// TenantSettings returns the company's portal settings (defaults when none
// were saved yet). Any authenticated member may read them.
func (s *Service) TenantSettings(ctx context.Context, p auth.Principal) (postgres.TenantSettings, error) {
	var out postgres.TenantSettings
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.GetTenantSettings(ctx, tx)
		if errors.Is(err, postgres.ErrNotFound) {
			out = postgres.TenantSettings{TenantID: p.TenantID, Country: "ET", Timezone: "Africa/Addis_Ababa", Locale: "en", ExportDailyLimit: 200}
			return tx.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1::uuid`, p.TenantID).Scan(&out.DisplayName)
		}
		return err
	})
	return out, err
}

var shortCodeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// SaveTenantSettings creates or updates the settings (tenant.settings.manage,
// tenant-wide, optimistic locking on version).
func (s *Service) SaveTenantSettings(ctx context.Context, p auth.Principal, in postgres.TenantSettings) (postgres.TenantSettings, error) {
	if err := s.authz.Require(p, auth.PermTenantSettingsManage, p.TenantID); err != nil {
		return postgres.TenantSettings{}, err
	}
	if !s.tenantWide(p) {
		return postgres.TenantSettings{}, fmt.Errorf("%w: company settings need tenant-wide scope", auth.ErrForbidden)
	}
	in.DisplayName, in.ShortCode = strings.TrimSpace(in.DisplayName), strings.ToLower(strings.TrimSpace(in.ShortCode))
	in.LetterheadName = strings.TrimSpace(in.LetterheadName)
	switch {
	case len(in.DisplayName) < 2 || len(in.DisplayName) > 120:
		return postgres.TenantSettings{}, fmt.Errorf("%w: display name is 2..120 characters", ErrInvalidInput)
	case !shortCodeRe.MatchString(in.ShortCode):
		return postgres.TenantSettings{}, fmt.Errorf("%w: short code is 2..32 lowercase letters, digits or hyphens", ErrInvalidInput)
	case len(in.LetterheadName) > 160:
		return postgres.TenantSettings{}, fmt.Errorf("%w: letterhead name is at most 160 characters", ErrInvalidInput)
	case len(in.Country) != 2:
		return postgres.TenantSettings{}, fmt.Errorf("%w: country is a 2-letter code", ErrInvalidInput)
	case in.ExportDailyLimit < 1 || in.ExportDailyLimit > 100000:
		return postgres.TenantSettings{}, fmt.Errorf("%w: export daily limit is 1..100000", ErrInvalidInput)
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil || in.Timezone == "" {
		return postgres.TenantSettings{}, fmt.Errorf("%w: unknown time zone", ErrInvalidInput)
	}
	switch in.Locale {
	case "en", "am", "ti":
	default:
		return postgres.TenantSettings{}, fmt.Errorf("%w: locale must be en, am or ti", ErrInvalidInput)
	}
	in.Country = strings.ToUpper(in.Country)
	var out postgres.TenantSettings
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.UpsertTenantSettings(ctx, tx, in, p.UserID)
		if err != nil {
			return err
		}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "tenant.settings.save", AggregateType: "tenant_settings",
			AggregateID: p.TenantID, RequestID: requestID(ctx), Payload: map[string]any{"display_name": out.DisplayName, "short_code": out.ShortCode, "version": out.Version}})
	})
	return out, err
}

// ----------------------------------------------------------- notifications

// Notifications lists the person's open notifications (their user id or any
// of their roles), limited to the projects they may see.
func (s *Service) Notifications(ctx context.Context, p auth.Principal, includeResolved bool, limit int) ([]postgres.Notification, error) {
	scope := s.authz.ScopeOf(p)
	var out []postgres.Notification
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ListNotifications(ctx, tx, p.UserID, p.Roles, postgres.ListScope{TenantWide: scope.TenantWide, Projects: p.ProjectIDs}, includeResolved, limit)
		return err
	})
	return out, err
}

// MarkNotificationRead marks one of the person's notifications read.
func (s *Service) MarkNotificationRead(ctx context.Context, p auth.Principal, id string) error {
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		ok, err := postgres.MarkNotificationRead(ctx, tx, id, p.UserID, p.Roles)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		return nil
	})
}

// Notify records a notification from a system control (security, exports).
// It is not reachable from the API.
func (s *Service) notify(ctx context.Context, tx pgx.Tx, n postgres.Notification) error {
	if n.CreatedBy == "" {
		n.CreatedBy = SystemAutomationActor
	}
	_, err := postgres.InsertNotification(ctx, tx, n)
	return err
}

// ---------------------------------------------------------- automation rules

var ruleCodeRe = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{1,39}$`)

// RuleInput is a proposed rule.
type RuleInput struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Body        []byte `json:"body"`
}

func validateRuleInput(in RuleInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if !ruleCodeRe.MatchString(in.Code) {
		return fmt.Errorf("%w: rule code is 2..40 upper-case letters, digits, _ or -", ErrInvalidInput)
	}
	if len(in.Name) < 2 || len(in.Name) > 120 || len(in.Description) > 2000 {
		return fmt.Errorf("%w: name is 2..120 characters, description at most 2000", ErrInvalidInput)
	}
	if _, err := automation.Parse(in.Body); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return nil
}

// ProposeRule creates a DRAFT rule (automation.manage).
func (s *Service) ProposeRule(ctx context.Context, p auth.Principal, in RuleInput) (postgres.AutomationRule, error) {
	if err := s.authz.Require(p, auth.PermAutomationManage, p.TenantID); err != nil {
		return postgres.AutomationRule{}, err
	}
	if err := validateRuleInput(in); err != nil {
		return postgres.AutomationRule{}, err
	}
	var out postgres.AutomationRule
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.InsertRule(ctx, tx, in.Code, strings.TrimSpace(in.Name), in.Description, in.Body, p.UserID)
		if err != nil {
			return err
		}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "automation.rule.propose", AggregateType: "automation_rule",
			AggregateID: out.ID, RequestID: requestID(ctx), Payload: map[string]any{"code": out.Code}})
	})
	return out, err
}

// UpdateRule changes a DRAFT rule (automation.manage).
func (s *Service) UpdateRule(ctx context.Context, p auth.Principal, id string, in RuleInput) (postgres.AutomationRule, error) {
	if err := s.authz.Require(p, auth.PermAutomationManage, p.TenantID); err != nil {
		return postgres.AutomationRule{}, err
	}
	in.Code = "X-UPDATE" // the code never changes on update
	if err := validateRuleInput(in); err != nil {
		return postgres.AutomationRule{}, err
	}
	var out postgres.AutomationRule
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.UpdateDraftRule(ctx, tx, id, strings.TrimSpace(in.Name), in.Description, in.Body)
		if err != nil {
			return err
		}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "automation.rule.update", AggregateType: "automation_rule",
			AggregateID: out.ID, RequestID: requestID(ctx), Payload: map[string]any{"version": out.Version}})
	})
	return out, err
}

// DecideRule activates (approve=true) or retires a rule. Activation needs
// automation.activate and a person other than the author (maker/checker,
// enforced again by the database); retirement needs either permission.
func (s *Service) DecideRule(ctx context.Context, p auth.Principal, id string, activate bool, reason string) (postgres.AutomationRule, error) {
	if activate {
		if err := s.authz.Require(p, auth.PermAutomationActivate, p.TenantID); err != nil {
			return postgres.AutomationRule{}, err
		}
	} else if s.authz.Require(p, auth.PermAutomationActivate, p.TenantID) != nil {
		if err := s.authz.Require(p, auth.PermAutomationManage, p.TenantID); err != nil {
			return postgres.AutomationRule{}, err
		}
	}
	if !activate && len(strings.TrimSpace(reason)) < 5 {
		return postgres.AutomationRule{}, fmt.Errorf("%w: a reason of at least 5 characters is required", ErrInvalidInput)
	}
	var out postgres.AutomationRule
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := postgres.GetRule(ctx, tx, id)
		if err != nil {
			return err
		}
		if activate {
			if cur.CreatedBy == p.UserID {
				return fmt.Errorf("%w: a rule is activated by someone other than its author", auth.ErrSoD)
			}
			if _, err := automation.Parse(cur.Body); err != nil {
				return fmt.Errorf("%w: stored rule no longer validates: %v", ErrInvalidInput, err)
			}
			out, err = postgres.ActivateRule(ctx, tx, id, p.UserID)
		} else {
			out, err = postgres.RetireRule(ctx, tx, id, p.UserID, strings.TrimSpace(reason))
		}
		if err != nil {
			return err
		}
		action := "automation.rule.activate"
		if !activate {
			action = "automation.rule.retire"
		}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: action, AggregateType: "automation_rule",
			AggregateID: out.ID, RequestID: requestID(ctx), Payload: map[string]any{"code": out.Code, "reason": reason}})
	})
	return out, err
}

// ListRules lists rules for anyone who may read workflows or manage automation.
func (s *Service) ListRules(ctx context.Context, p auth.Principal, status string) ([]postgres.AutomationRule, error) {
	if s.authz.Require(p, auth.PermAutomationManage, p.TenantID) != nil && s.authz.Require(p, auth.PermAutomationActivate, p.TenantID) != nil {
		if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
			return nil, err
		}
	}
	var out []postgres.AutomationRule
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ListRules(ctx, tx, status)
		return err
	})
	return out, err
}

// RuleCatalogue describes the conditions a rule may use.
func RuleCatalogue() []map[string]string {
	out := make([]map[string]string, 0, len(automation.Kinds))
	for _, k := range automation.Kinds {
		out = append(out, map[string]string{"kind": string(k), "description": automation.Describe(k)})
	}
	return out
}

// ------------------------------------------------------------- the worker

// AutomationResult summarises one pass.
type AutomationResult struct {
	Rules, Findings, Notified, Resolved, Snapshots int
}

// RunAutomation evaluates every ACTIVE rule of a tenant and records one risk
// snapshot per project. Each rule runs in its own savepoint; a failing rule
// is skipped and retried next pass.
func (s *Service) RunAutomation(ctx context.Context, tenantID string) (AutomationResult, error) {
	var res AutomationResult
	var first error
	sys := auth.Principal{Kind: auth.KindService, UserID: SystemAutomationActor, TenantID: tenantID}
	err := s.store.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '20s'`); err != nil {
			return err
		}
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		rules, err := postgres.ListRules(ctx, tx, "ACTIVE")
		if err != nil {
			return err
		}
		for _, r := range rules {
			sp, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			n, notified, resolved, err := s.evaluateRule(ctx, sp, sys, r, now)
			if err != nil {
				_ = sp.Rollback(ctx)
				if first == nil {
					first = fmt.Errorf("rule %s: %w", r.Code, err)
				}
				continue
			}
			if err := sp.Commit(ctx); err != nil {
				return err
			}
			res.Rules++
			res.Findings += n
			res.Notified += notified
			res.Resolved += resolved
		}
		// Risk snapshots for trend history.
		projects, err := postgres.Projects(ctx, tx)
		if err != nil {
			return err
		}
		for _, pr := range projects {
			sp, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			assessment, err := s.assessProject(ctx, sp, pr, now)
			if err == nil {
				err = postgres.InsertRiskSnapshot(ctx, sp, pr.ID, assessment.Overall, assessment.Algorithm, assessment.Findings)
			}
			if err != nil {
				_ = sp.Rollback(ctx)
				if first == nil {
					first = fmt.Errorf("snapshot %s: %w", pr.Code, err)
				}
				continue
			}
			if err := sp.Commit(ctx); err != nil {
				return err
			}
			res.Snapshots++
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, first
}

// RunDueAutomation runs every tenant the scheduler reports.
func (s *Service) RunDueAutomation(ctx context.Context, due TenantLister) (AutomationResult, error) {
	tenants, err := due(ctx)
	if err != nil {
		return AutomationResult{}, err
	}
	var total AutomationResult
	var first error
	for _, t := range tenants {
		r, err := s.RunAutomation(ctx, t)
		total.Rules += r.Rules
		total.Findings += r.Findings
		total.Notified += r.Notified
		total.Resolved += r.Resolved
		total.Snapshots += r.Snapshots
		if err != nil && first == nil {
			first = fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return total, first
}

func (s *Service) evaluateRule(ctx context.Context, tx pgx.Tx, sys auth.Principal, r postgres.AutomationRule, now time.Time) (findings, notified, resolved int, err error) {
	rule, err := automation.Parse(r.Body)
	if err != nil {
		return 0, 0, 0, err
	}
	found, err := s.findings(ctx, tx, rule.When, now)
	if err != nil {
		return 0, 0, 0, err
	}
	keys := make([]string, 0, len(found))
	for _, f := range found {
		key := automation.DedupeKey(r.Code, f)
		keys = append(keys, key)
		title := f.Title
		if rule.Then.Title != "" {
			title = rule.Then.Title + ": " + f.Title
		}
		ins, err := postgres.InsertNotification(ctx, tx, postgres.Notification{RecipientUser: rule.Then.NotifyUser, RecipientRole: rule.Then.NotifyRole,
			Kind: "automation." + string(rule.When.Kind), Severity: rule.Then.Severity, Title: title, Body: f.Body, SubjectType: f.SubjectType, SubjectID: f.SubjectID,
			ProjectID: f.ProjectID, Href: f.Href, RuleID: r.ID, DedupeKey: key, CreatedBy: sys.UserID})
		if err != nil {
			return 0, 0, 0, err
		}
		if ins {
			notified++
		}
	}
	resolved, err = postgres.ResolveRuleNotifications(ctx, tx, r.ID, keys)
	if err != nil {
		return 0, 0, 0, err
	}
	if err := postgres.RecordRuleRun(ctx, tx, r.ID, len(found)); err != nil {
		return 0, 0, 0, err
	}
	return len(found), notified, resolved, nil
}

// findings evaluates a condition against the tenant's data.
func (s *Service) findings(ctx context.Context, tx pgx.Tx, c automation.Condition, now time.Time) ([]automation.Finding, error) {
	all := postgres.ListScope{TenantWide: true}
	var out []automation.Finding
	switch c.Kind {
	case automation.DocumentStale:
		if !docTypes[c.Subject] {
			return nil, fmt.Errorf("%w: unknown subject %q", ErrInvalidInput, c.Subject)
		}
		docs, err := postgres.ListDocs(ctx, tx, c.Subject, c.Status, all, 500)
		if err != nil {
			return nil, err
		}
		cut := now.Add(-time.Duration(c.Hours) * time.Hour)
		for _, d := range docs {
			if d.CreatedAt.Before(cut) {
				ref := d.Number
				if ref == "" {
					ref = d.ID[:8]
				}
				out = append(out, automation.Finding{SubjectType: c.Subject, SubjectID: d.ID, ProjectID: d.ProjectID,
					Title: fmt.Sprintf("%s %s has waited in %s since %s", words(c.Subject), ref, d.Status, d.CreatedAt.Format("2 Jan")),
					Body:  d.Label, Href: "#/doc/" + c.Subject + "/" + d.ID})
			}
		}
	case automation.InvoiceDue:
		entities, err := entityIDs(ctx, tx)
		if err != nil {
			return nil, err
		}
		for _, e := range entities {
			items, err := postgres.PayablesOpen(ctx, tx, e, now.AddDate(0, 0, 365))
			if err != nil {
				return nil, err
			}
			limit := now.AddDate(0, 0, c.Days)
			for _, it := range items {
				if !it.DueDate.After(limit) {
					state := "due " + it.DueDate.Format("2 Jan")
					if it.DueDate.Before(now.Truncate(24 * time.Hour)) {
						state = "overdue since " + it.DueDate.Format("2 Jan")
					}
					out = append(out, automation.Finding{SubjectType: "supplier_invoice", SubjectID: it.Document, Key: it.DueDate.Format("2006-01-02"),
						Title: fmt.Sprintf("Invoice %s from %s: %s %s %s", it.Document, it.Party, money2(it.Open), it.Currency, state),
						Href:  "#/aging/ap"})
				}
			}
		}
	case automation.ReceivableOverdue:
		entities, err := entityIDs(ctx, tx)
		if err != nil {
			return nil, err
		}
		for _, e := range entities {
			items, err := postgres.ReceivablesOpen(ctx, tx, e, now)
			if err != nil {
				return nil, err
			}
			for _, it := range items {
				days := int(now.Sub(it.DueDate).Hours() / 24)
				if days > c.Days {
					out = append(out, automation.Finding{SubjectType: "customer_invoice", SubjectID: it.Document,
						Title: fmt.Sprintf("Customer invoice %s (%s): %s %s overdue by %d days", it.Document, it.Party, money2(it.Open), it.Currency, days), Href: "#/aging/ar"})
				}
			}
		}
	case automation.POOverdue:
		pos, err := postgres.OverduePOs(ctx, tx, now)
		if err != nil {
			return nil, err
		}
		for _, po := range pos {
			out = append(out, automation.Finding{SubjectType: "purchase_order", SubjectID: po.ID, ProjectID: po.ProjectID,
				Title: fmt.Sprintf("Purchase order %s (%s) was needed by %s and is still open", po.Number, po.Supplier, po.NeededBy.Format("2 Jan")),
				Body:  "Total " + money2(po.Total), Href: "#/doc/purchase_order/" + po.ID})
		}
	case automation.BudgetThreshold:
		projects, err := postgres.Projects(ctx, tx)
		if err != nil {
			return nil, err
		}
		pct := decimal.NewFromInt(int64(c.Percent)).Div(decimal.NewFromInt(100))
		for _, pr := range projects {
			rows, err := postgres.ProjectCostReport(ctx, tx, pr.ID)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				if !row.Budget.IsPositive() {
					continue
				}
				used := row.Budget.Sub(row.Available)
				if used.GreaterThanOrEqual(row.Budget.Mul(pct)) {
					share := used.Div(row.Budget).Mul(decimal.NewFromInt(100)).Round(1)
					out = append(out, automation.Finding{SubjectType: "cost_code", SubjectID: row.CostCodeID, ProjectID: pr.ID, Key: fmt.Sprint(c.Percent),
						Title: fmt.Sprintf("%s %s: %s%% of budget %s consumed (committed %s, actual %s)", pr.Code, row.CostCode, share, money2(row.Budget), money2(row.Committed), money2(row.ActualPosted)),
						Href:  "#/cost"})
				}
			}
		}
	case automation.StockBelow:
		lvl, err := postgres.StockLevelOf(ctx, tx, c.ItemCode)
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if lvl.Qty.LessThanOrEqual(c.Quantity) {
			out = append(out, automation.Finding{SubjectType: "stock_item", SubjectID: lvl.ItemID,
				Title: fmt.Sprintf("Stock of %s %s is %s %s (level %s)", lvl.ItemCode, lvl.ItemName, lvl.Qty.String(), lvl.Unit, c.Quantity.String()), Href: "#/stock"})
		}
	case automation.ScheduleRisk, automation.CostRisk:
		projects, err := postgres.Projects(ctx, tx)
		if err != nil {
			return nil, err
		}
		for _, pr := range projects {
			r, err := postgres.ScheduleEVM(ctx, tx, pr.ID, now)
			if errors.Is(err, postgres.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			idx, label := r.SPI, "SPI"
			if c.Kind == automation.CostRisk {
				idx, label = r.CPI, "CPI"
			}
			if idx != nil && idx.LessThan(c.Ratio) {
				out = append(out, automation.Finding{SubjectType: "project", SubjectID: pr.ID, ProjectID: pr.ID, Key: c.Ratio.String(),
					Title: fmt.Sprintf("%s %s: %s %s is below %s", pr.Code, pr.Name, label, idx.Round(3).String(), c.Ratio.String()), Href: "#/evm"})
			}
		}
	case automation.ExportVolume:
		counts, err := postgres.ExportCounts(ctx, tx)
		if err != nil {
			return nil, err
		}
		for u, n := range counts {
			if n > c.Count {
				out = append(out, automation.Finding{SubjectType: "user", SubjectID: u, Key: now.Format("2006-01-02"),
					Title: fmt.Sprintf("%s exported %d files in the last 24 hours (limit %d)", u, n, c.Count), Body: "Review whether this is expected bulk reporting or data extraction.", Href: "#/settings"})
			}
		}
	default:
		return nil, fmt.Errorf("%w: unsupported kind %q", ErrInvalidInput, c.Kind)
	}
	return out, nil
}

func entityIDs(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id::text FROM legal_entities ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func words(k string) string {
	k = strings.ReplaceAll(k, "_", " ")
	if k == "" {
		return k
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

func money2(d decimal.Decimal) string {
	s := d.StringFixed(2)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	ip, fp, _ := strings.Cut(s, ".")
	var b strings.Builder
	for i, r := range ip {
		if i > 0 && (len(ip)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := b.String() + "." + fp
	if neg {
		out = "-" + out
	}
	return out
}

// --------------------------------------------------------- export budget

// ErrExportBudget is returned when the person's daily export budget is spent.
var ErrExportBudget = errors.New("kernel: daily export budget exhausted")

// RecordExport counts an export against the person's daily budget (tenant
// setting, default 200). Over budget: the export is refused, recorded, and
// security is notified once per person and day.
func (s *Service) RecordExport(ctx context.Context, p auth.Principal, subject string, bytes int64) error {
	var over error
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		limit := 200
		if st, err := postgres.GetTenantSettings(ctx, tx); err == nil {
			limit = st.ExportDailyLimit
		} else if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		n, err := postgres.RecordAccess(ctx, tx, p.UserID, "export", subject, bytes)
		if err != nil {
			return err
		}
		if n <= limit {
			return nil
		}
		// The refusal is recorded (event, notification, audit) and committed;
		// the error is returned after the commit.
		day := time.Now().UTC().Format("2006-01-02")
		if err := s.notify(ctx, tx, postgres.Notification{RecipientRole: "security_admin", Kind: "security.export_budget", Severity: "critical",
			Title: fmt.Sprintf("%s reached the daily export limit (%d)", p.UserID, limit), Body: "Further exports by this person are refused until tomorrow (UTC). Review whether this is expected.",
			SubjectType: "user", SubjectID: p.UserID, Href: "#/settings", DedupeKey: "security:export_budget:" + p.UserID + ":" + day}); err != nil {
			return err
		}
		if err := postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: "security.export_budget_exceeded", AggregateType: "user",
			AggregateID: p.UserID, RequestID: requestID(ctx), Payload: map[string]any{"count": n, "limit": limit, "subject": subject}}); err != nil {
			return err
		}
		over = fmt.Errorf("%w (%d of %d today)", ErrExportBudget, n, limit)
		return nil
	})
	if err != nil {
		return err
	}
	return over
}
