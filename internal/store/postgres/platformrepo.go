package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// Platform (0038): tenant settings, notifications, automation rules, risk
// snapshots, data-access events.

// TenantSettings is the construction company's portal configuration.
type TenantSettings struct {
	TenantID         string    `json:"tenant_id"`
	DisplayName      string    `json:"display_name"`
	ShortCode        string    `json:"short_code"`
	LetterheadName   string    `json:"letterhead_name"`
	Country          string    `json:"country"`
	Timezone         string    `json:"timezone"`
	Locale           string    `json:"locale"`
	ExportDailyLimit int       `json:"export_daily_limit"`
	ThemeAccent      string    `json:"theme_accent"`
	Version          int       `json:"version"`
	UpdatedBy        string    `json:"updated_by"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GetTenantSettings returns the row, or ErrNotFound when none was created.
func GetTenantSettings(ctx context.Context, tx pgx.Tx) (TenantSettings, error) {
	var s TenantSettings
	err := tx.QueryRow(ctx, `SELECT tenant_id::text, display_name, short_code, letterhead_name, country, timezone, locale, export_daily_limit, theme_accent, version, updated_by, updated_at
		FROM tenant_settings WHERE tenant_id = current_tenant()`).Scan(&s.TenantID, &s.DisplayName, &s.ShortCode, &s.LetterheadName, &s.Country, &s.Timezone, &s.Locale,
		&s.ExportDailyLimit, &s.ThemeAccent, &s.Version, &s.UpdatedBy, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// UpsertTenantSettings creates or updates the row with optimistic locking on
// version (0 = create).
func UpsertTenantSettings(ctx context.Context, tx pgx.Tx, s TenantSettings, by string) (TenantSettings, error) {
	var out TenantSettings
	err := tx.QueryRow(ctx, `INSERT INTO tenant_settings (display_name, short_code, letterhead_name, country, timezone, locale, export_daily_limit, theme_accent, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id) DO UPDATE SET display_name = EXCLUDED.display_name, short_code = EXCLUDED.short_code, letterhead_name = EXCLUDED.letterhead_name,
		  country = EXCLUDED.country, timezone = EXCLUDED.timezone, locale = EXCLUDED.locale, export_daily_limit = EXCLUDED.export_daily_limit,
		  theme_accent = EXCLUDED.theme_accent, version = tenant_settings.version + 1, updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE tenant_settings.version = $10
		RETURNING tenant_id::text, display_name, short_code, letterhead_name, country, timezone, locale, export_daily_limit, theme_accent, version, updated_by, updated_at`,
		s.DisplayName, s.ShortCode, s.LetterheadName, s.Country, s.Timezone, s.Locale, s.ExportDailyLimit, s.ThemeAccent, by, s.Version).Scan(
		&out.TenantID, &out.DisplayName, &out.ShortCode, &out.LetterheadName, &out.Country, &out.Timezone, &out.Locale, &out.ExportDailyLimit, &out.ThemeAccent,
		&out.Version, &out.UpdatedBy, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrConflict
	}
	return out, err
}

// ErrConflict is an optimistic-locking failure.
var ErrConflict = errors.New("store: the record changed since it was read")

// Notification is a message to a person or a role.
type Notification struct {
	ID            string     `json:"id"`
	RecipientUser string     `json:"recipient_user,omitempty"`
	RecipientRole string     `json:"recipient_role,omitempty"`
	Kind          string     `json:"kind"`
	Severity      string     `json:"severity"`
	Title         string     `json:"title"`
	Body          string     `json:"body,omitempty"`
	SubjectType   string     `json:"subject_type,omitempty"`
	SubjectID     string     `json:"subject_id,omitempty"`
	ProjectID     string     `json:"project_id,omitempty"`
	Href          string     `json:"href,omitempty"`
	RuleID        string     `json:"rule_id,omitempty"`
	DedupeKey     string     `json:"-"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ReadAt        *time.Time `json:"read_at,omitempty"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
}

// InsertNotification records a notification unless one with the same
// dedupe key is already open; it reports whether a row was inserted.
func InsertNotification(ctx context.Context, tx pgx.Tx, n Notification) (bool, error) {
	var ru, rr, pid, rid *string
	if n.RecipientUser != "" {
		ru = &n.RecipientUser
	}
	if n.RecipientRole != "" {
		rr = &n.RecipientRole
	}
	if n.ProjectID != "" {
		pid = &n.ProjectID
	}
	if n.RuleID != "" {
		rid = &n.RuleID
	}
	tag, err := tx.Exec(ctx, `INSERT INTO notifications (recipient_user, recipient_role, kind, severity, title, body, subject_type, subject_id, project_id, href, rule_id, dedupe_key, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid, $10, $11::uuid, $12, $13) ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
		ru, rr, n.Kind, n.Severity, n.Title, n.Body, n.SubjectType, n.SubjectID, pid, n.Href, rid, n.DedupeKey, n.CreatedBy)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ListNotifications returns open (or all) notifications addressed to the
// user or any of the roles, limited to the projects visible to them.
func ListNotifications(ctx context.Context, tx pgx.Tx, user string, roles []string, scope ListScope, includeResolved bool, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(recipient_user, ''), COALESCE(recipient_role, ''), kind, severity, title, body, subject_type, subject_id,
			COALESCE(project_id::text, ''), href, COALESCE(rule_id::text, ''), created_by, created_at, read_at, resolved_at
		FROM notifications
		WHERE (recipient_user = $1 OR recipient_role = ANY($2::text[]))
		  AND ($3 OR resolved_at IS NULL)
		  AND ($4 OR project_id IS NULL OR project_id::text = ANY($5::text[]))
		ORDER BY created_at DESC LIMIT $6`, user, roles, includeResolved, scope.TenantWide, scope.Projects, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.RecipientUser, &n.RecipientRole, &n.Kind, &n.Severity, &n.Title, &n.Body, &n.SubjectType, &n.SubjectID, &n.ProjectID,
			&n.Href, &n.RuleID, &n.CreatedBy, &n.CreatedAt, &n.ReadAt, &n.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkNotificationRead sets read_at for a notification the user may see.
func MarkNotificationRead(ctx context.Context, tx pgx.Tx, id, user string, roles []string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE notifications SET read_at = COALESCE(read_at, now()) WHERE id = $1::uuid AND (recipient_user = $2 OR recipient_role = ANY($3::text[]))`, id, user, roles)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ResolveRuleNotifications closes the rule's open notifications whose key is
// not among the current findings; returns how many were resolved.
func ResolveRuleNotifications(ctx context.Context, tx pgx.Tx, ruleID string, currentKeys []string) (int, error) {
	tag, err := tx.Exec(ctx, `UPDATE notifications SET resolved_at = now() WHERE rule_id = $1::uuid AND resolved_at IS NULL AND NOT (dedupe_key = ANY($2::text[]))`, ruleID, currentKeys)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// AutomationRule is a stored rule.
type AutomationRule struct {
	ID              string          `json:"id"`
	Code            string          `json:"code"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	Body            json.RawMessage `json:"body"`
	Status          string          `json:"status"`
	Version         int             `json:"version"`
	CreatedBy       string          `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	ActivatedBy     string          `json:"activated_by,omitempty"`
	ActivatedAt     *time.Time      `json:"activated_at,omitempty"`
	RetiredBy       string          `json:"retired_by,omitempty"`
	RetiredAt       *time.Time      `json:"retired_at,omitempty"`
	RetireReason    string          `json:"retire_reason,omitempty"`
	LastRunAt       *time.Time      `json:"last_run_at,omitempty"`
	LastRunFindings int             `json:"last_run_findings"`
}

const ruleCols = `id::text, code, name, description, body, status, version, created_by, created_at, COALESCE(activated_by, ''), activated_at,
	COALESCE(retired_by, ''), retired_at, COALESCE(retire_reason, ''), last_run_at, last_run_findings`

func scanRule(row pgx.Row) (AutomationRule, error) {
	var r AutomationRule
	err := row.Scan(&r.ID, &r.Code, &r.Name, &r.Description, &r.Body, &r.Status, &r.Version, &r.CreatedBy, &r.CreatedAt, &r.ActivatedBy, &r.ActivatedAt,
		&r.RetiredBy, &r.RetiredAt, &r.RetireReason, &r.LastRunAt, &r.LastRunFindings)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// InsertRule creates a DRAFT rule.
func InsertRule(ctx context.Context, tx pgx.Tx, code, name, description string, body []byte, by string) (AutomationRule, error) {
	return scanRule(tx.QueryRow(ctx, `INSERT INTO automation_rules (code, name, description, body, created_by) VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING `+ruleCols,
		code, name, description, string(body), by))
}

// UpdateDraftRule changes a DRAFT rule's content (the trigger refuses others).
func UpdateDraftRule(ctx context.Context, tx pgx.Tx, id, name, description string, body []byte) (AutomationRule, error) {
	return scanRule(tx.QueryRow(ctx, `UPDATE automation_rules SET name = $2, description = $3, body = $4::jsonb, version = version + 1
		WHERE id = $1::uuid AND status = 'DRAFT' RETURNING `+ruleCols, id, name, description, string(body)))
}

// GetRule loads one rule.
func GetRule(ctx context.Context, tx pgx.Tx, id string) (AutomationRule, error) {
	return scanRule(tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM automation_rules WHERE id = $1::uuid`, id))
}

// ListRules lists rules, optionally by status.
func ListRules(ctx context.Context, tx pgx.Tx, status string) ([]AutomationRule, error) {
	rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM automation_rules WHERE $1 = '' OR status = $1 ORDER BY status, code`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AutomationRule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActivateRule moves DRAFT -> ACTIVE (the constraint refuses the author).
func ActivateRule(ctx context.Context, tx pgx.Tx, id, by string) (AutomationRule, error) {
	return scanRule(tx.QueryRow(ctx, `UPDATE automation_rules SET status = 'ACTIVE', activated_by = $2, activated_at = now()
		WHERE id = $1::uuid AND status = 'DRAFT' RETURNING `+ruleCols, id, by))
}

// RetireRule moves DRAFT or ACTIVE -> RETIRED.
func RetireRule(ctx context.Context, tx pgx.Tx, id, by, reason string) (AutomationRule, error) {
	return scanRule(tx.QueryRow(ctx, `UPDATE automation_rules SET status = 'RETIRED', retired_by = $2, retired_at = now(), retire_reason = $3
		WHERE id = $1::uuid AND status <> 'RETIRED' RETURNING `+ruleCols, id, by, reason))
}

// RecordRuleRun stamps the last evaluation.
func RecordRuleRun(ctx context.Context, tx pgx.Tx, id string, findings int) error {
	_, err := tx.Exec(ctx, `UPDATE automation_rules SET last_run_at = now(), last_run_findings = $2 WHERE id = $1::uuid`, id, findings)
	return err
}

// DueAutomationTenants lists tenants with active rules (scheduler login).
func DueAutomationTenants(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}, max int) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT t::text FROM automation_due_tenants($1) AS t`, max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- condition queries -------------------------------------------------

// ProjectRef is a project's identity.
type ProjectRef struct {
	ID, Code, Name, EntityID string
}

// Projects lists the tenant's projects.
func Projects(ctx context.Context, tx pgx.Tx) ([]ProjectRef, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, code, name, legal_entity_id::text FROM projects ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectRef
	for rows.Next() {
		var p ProjectRef
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.EntityID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OverduePO is an approved purchase order past its requisition's needed-by.
type OverduePO struct {
	ID, Number, ProjectID, Supplier string
	NeededBy                        time.Time
	Total                           decimal.Decimal
}

// OverduePOs lists approved purchase orders whose requisition needed the
// goods before asOf and that are not closed.
func OverduePOs(ctx context.Context, tx pgx.Tx, asOf time.Time) ([]OverduePO, error) {
	rows, err := tx.Query(ctx, `SELECT po.id::text, po.number, po.project_id::text, s.name, pr.needed_by, po.total
		FROM purchase_orders po
		JOIN rfqs r ON r.tenant_id = po.tenant_id AND r.id = po.rfq_id
		JOIN purchase_requisitions pr ON pr.tenant_id = r.tenant_id AND pr.id = r.pr_id
		JOIN suppliers s ON s.tenant_id = po.tenant_id AND s.id = po.supplier_id
		WHERE po.status = 'APPROVED' AND pr.needed_by IS NOT NULL AND pr.needed_by < $1::date
		ORDER BY pr.needed_by`, asOf)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OverduePO
	for rows.Next() {
		var o OverduePO
		if err := rows.Scan(&o.ID, &o.Number, &o.ProjectID, &o.Supplier, &o.NeededBy, &o.Total); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// StockLevel is an item's total on-hand quantity.
type StockLevel struct {
	ItemID, ItemCode, ItemName, Unit string
	Qty                              decimal.Decimal
}

// StockLevelOf sums an item's quantity across warehouses.
func StockLevelOf(ctx context.Context, tx pgx.Tx, itemCode string) (StockLevel, error) {
	var l StockLevel
	err := tx.QueryRow(ctx, `SELECT i.id::text, i.code, i.name, i.unit, COALESCE(sum(b.qty), 0)
		FROM stock_items i LEFT JOIN stock_balances b ON b.tenant_id = i.tenant_id AND b.stock_item_id = i.id
		WHERE i.code = $1 GROUP BY i.id, i.code, i.name, i.unit`, itemCode).Scan(&l.ItemID, &l.ItemCode, &l.ItemName, &l.Unit, &l.Qty)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

// ExportCounts counts exports per user in the last 24 hours.
func ExportCounts(ctx context.Context, tx pgx.Tx) (map[string]int, error) {
	rows, err := tx.Query(ctx, `SELECT user_id, count(*) FROM data_access_events WHERE kind = 'export' AND occurred_at > now() - interval '24 hours' GROUP BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var u string
		var n int
		if err := rows.Scan(&u, &n); err != nil {
			return nil, err
		}
		out[u] = n
	}
	return out, rows.Err()
}

// RecordAccess appends a data-access event and returns the user's count of
// that kind today (UTC), including this one.
func RecordAccess(ctx context.Context, tx pgx.Tx, user, kind, subject string, bytes int64) (int, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO data_access_events (user_id, kind, subject, bytes) VALUES ($1, $2, $3, $4)`, user, kind, subject, bytes); err != nil {
		return 0, err
	}
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM data_access_events WHERE user_id = $1 AND kind = $2 AND occurred_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, user, kind).Scan(&n)
	return n, err
}

// InsertRiskSnapshot stores a computed risk assessment.
func InsertRiskSnapshot(ctx context.Context, tx pgx.Tx, projectID, overall, algorithm string, findings any) error {
	b, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO risk_snapshots (project_id, overall, findings, algorithm) VALUES ($1::uuid, $2, $3::jsonb, $4)`, projectID, overall, string(b), algorithm)
	return err
}

// RiskHistory returns the overall level per snapshot, newest first.
type RiskPoint struct {
	At      time.Time `json:"at"`
	Overall string    `json:"overall"`
}

// RiskHistoryOf lists a project's snapshot levels.
func RiskHistoryOf(ctx context.Context, tx pgx.Tx, projectID string, limit int) ([]RiskPoint, error) {
	rows, err := tx.Query(ctx, `SELECT computed_at, overall FROM risk_snapshots WHERE project_id = $1::uuid ORDER BY computed_at DESC LIMIT $2`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RiskPoint{}
	for rows.Next() {
		var p RiskPoint
		if err := rows.Scan(&p.At, &p.Overall); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// BankCash sums posted balances of the GL accounts behind active company
// bank accounts of an entity (debit balance = cash held).
func BankCash(ctx context.Context, tx pgx.Tx, entityID string) (decimal.Decimal, int, error) {
	var cash decimal.Decimal
	var n int
	err := tx.QueryRow(ctx, `SELECT COALESCE(sum(CASE WHEN l.side = 'DEBIT' THEN l.amount ELSE -l.amount END), 0), count(DISTINCT b.id)
		FROM company_bank_accounts b
		LEFT JOIN journal_lines l ON l.tenant_id = b.tenant_id AND l.account_id = b.gl_account_id
		LEFT JOIN journals j ON j.tenant_id = l.tenant_id AND j.id = l.journal_id AND j.status IN ('POSTED', 'REVERSED')
		WHERE b.legal_entity_id = $1::uuid AND b.status = 'ACTIVE' AND (j.id IS NOT NULL OR l.journal_id IS NULL)`, entityID).Scan(&cash, &n)
	return cash, n, err
}

// DuplicateInvoiceNumber is two supplier invoices of one supplier with the
// same normalised number.
type DuplicateInvoiceNumber struct {
	Supplier, Number string
	IDs              []string
}

// DuplicateSupplierInvoices finds repeated invoice numbers per supplier.
func DuplicateSupplierInvoices(ctx context.Context, tx pgx.Tx) ([]DuplicateInvoiceNumber, error) {
	rows, err := tx.Query(ctx, `SELECT s.name, i.normalized_number, array_agg(i.id::text ORDER BY i.created_at)
		FROM supplier_invoices i JOIN suppliers s ON s.tenant_id = i.tenant_id AND s.id = i.supplier_id
		WHERE i.status <> 'REJECTED' AND i.normalized_number <> ''
		GROUP BY s.name, i.supplier_id, i.normalized_number HAVING count(*) > 1 ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DuplicateInvoiceNumber
	for rows.Next() {
		var d DuplicateInvoiceNumber
		if err := rows.Scan(&d.Supplier, &d.Number, &d.IDs); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// NearThresholdPayment is a payment just under the dual-approval threshold.
type NearThresholdPayment struct {
	ID, Number, Supplier string
	Amount, Threshold    decimal.Decimal
	ValueDate            time.Time
}

// PaymentsJustBelowDualThreshold lists payments of the last days whose amount
// is within pct percent below the entity's dual-approval threshold.
func PaymentsJustBelowDualThreshold(ctx context.Context, tx pgx.Tx, entityID string, days, pct int) ([]NearThresholdPayment, error) {
	rows, err := tx.Query(ctx, `SELECT p.id::text, p.number, s.name, p.amount, pol.dual_payment_threshold, p.value_date
		FROM payment_instructions p
		JOIN suppliers s ON s.tenant_id = p.tenant_id AND s.id = p.supplier_id
		JOIN p2p_policies pol ON pol.tenant_id = p.tenant_id AND pol.id = p.policy_id
		WHERE p.legal_entity_id = $1::uuid AND p.status NOT IN ('CANCELLED') AND p.created_at > now() - make_interval(days => $2::int)
		  AND p.amount < pol.dual_payment_threshold AND p.amount >= pol.dual_payment_threshold * (1 - $3::numeric / 100)
		ORDER BY p.created_at DESC`, entityID, days, pct)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NearThresholdPayment
	for rows.Next() {
		var n NearThresholdPayment
		if err := rows.Scan(&n.ID, &n.Number, &n.Supplier, &n.Amount, &n.Threshold, &n.ValueDate); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// RecentActivity counts documents created in the last days by type.
type RecentActivity struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// RecentActivityCounts summarises what was created recently.
func RecentActivityCounts(ctx context.Context, tx pgx.Tx, days int) ([]RecentActivity, error) {
	rows, err := tx.Query(ctx, `
		SELECT t, n FROM (
		  SELECT 'purchase_requisition' AS t, count(*) AS n FROM purchase_requisitions WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'purchase_order', count(*) FROM purchase_orders WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'grn', count(*) FROM grns WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'supplier_invoice', count(*) FROM supplier_invoices WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'payment_instruction', count(*) FROM payment_instructions WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'ipc', count(*) FROM ipcs WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'customer_invoice', count(*) FROM customer_invoices WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'contract_variation', count(*) FROM contract_variations WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'site_diary', count(*) FROM site_diaries WHERE created_at > now() - make_interval(days => $1::int)
		  UNION ALL SELECT 'journal', count(*) FROM journals WHERE created_at > now() - make_interval(days => $1::int)
		) x WHERE n > 0 ORDER BY n DESC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentActivity{}
	for rows.Next() {
		var a RecentActivity
		if err := rows.Scan(&a.Type, &a.Count); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
