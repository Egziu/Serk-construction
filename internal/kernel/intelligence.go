package kernel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Intelligence: deterministic, explainable assessments computed from the
// same authorised data the screens show. Every figure carries its formula,
// its evidence and what is missing. Nothing here predicts with a model:
// there is no history of outcomes to train or evaluate one on yet, and a
// forecast that cannot be evaluated is not a forecast. Risk snapshots
// (0038) record these assessments so that, once outcomes exist, a model can
// be compared against this baseline before it is trusted.

// IntelligenceAlgorithm versions the assessment.
const IntelligenceAlgorithm = "risk-rules/1"

// Finding is one assessed risk.
type Finding struct {
	Area      string            `json:"area"`  // schedule | cost | procurement | cash | controls
	Level     string            `json:"level"` // low | medium | high | unknown
	Title     string            `json:"title"`
	Metric    string            `json:"metric,omitempty"`
	Value     string            `json:"value,omitempty"`
	Threshold string            `json:"threshold,omitempty"`
	Formula   string            `json:"formula,omitempty"`
	Evidence  []Evidence        `json:"evidence,omitempty"`
	Missing   []string          `json:"missing,omitempty"`
	Advice    string            `json:"advice,omitempty"`
	Amounts   map[string]string `json:"amounts,omitempty"`
}

// Evidence links a finding to its records.
type Evidence struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

// Assessment is a project's risk picture.
type Assessment struct {
	ProjectID  string               `json:"project_id"`
	Code       string               `json:"code"`
	Name       string               `json:"name"`
	Overall    string               `json:"overall"`
	Findings   []Finding            `json:"findings"`
	Forecast   *Forecast            `json:"forecast,omitempty"`
	ComputedAt time.Time            `json:"computed_at"`
	Algorithm  string               `json:"algorithm"`
	DataAsOf   string               `json:"data_as_of"`
	History    []postgres.RiskPoint `json:"history,omitempty"`
}

// Forecast is the earned-value forecast of final cost.
type Forecast struct {
	BAC, PV, EV, AC decimal.Decimal  `json:"-"`
	Bac             string           `json:"bac"`
	Pv              string           `json:"pv"`
	Ev              string           `json:"ev"`
	Ac              string           `json:"ac"`
	SPI, CPI        *decimal.Decimal `json:"-"`
	Spi             string           `json:"spi"`
	Cpi             string           `json:"cpi"`
	EAC             string           `json:"eac"`
	ETC             string           `json:"etc"`
	VAC             string           `json:"vac"`
	PercentComplete string           `json:"percent_complete"`
	Method          string           `json:"method"`
	Assumptions     []string         `json:"assumptions"`
	ProgressDate    string           `json:"progress_date,omitempty"`
}

var (
	spiWarn, spiBad = decimal.RequireFromString("0.95"), decimal.RequireFromString("0.85")
	cpiWarn, cpiBad = decimal.RequireFromString("0.95"), decimal.RequireFromString("0.85")
	budgetWarn      = decimal.RequireFromString("0.85")
	budgetBad       = decimal.RequireFromString("1.00")
)

func worse(a, b string) string {
	rank := map[string]int{"low": 0, "unknown": 1, "medium": 2, "high": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// ProjectRisks assesses one project for a person who may see it.
func (s *Service) ProjectRisks(ctx context.Context, p auth.Principal, projectID string) (Assessment, error) {
	if err := s.authz.RequireProject(p, auth.PermIntelligenceRead, p.TenantID, projectID); err != nil {
		return Assessment{}, err
	}
	var out Assessment
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '10s'`); err != nil {
			return err
		}
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		var pr postgres.ProjectRef
		if err := tx.QueryRow(ctx, `SELECT id::text, code, name, legal_entity_id::text FROM projects WHERE id = $1::uuid`, projectID).Scan(&pr.ID, &pr.Code, &pr.Name, &pr.EntityID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		out, err = s.assessProject(ctx, tx, pr, now)
		if err != nil {
			return err
		}
		out.History, err = postgres.RiskHistoryOf(ctx, tx, projectID, 30)
		return err
	})
	return out, err
}

// PortfolioRisks assesses every project the person may see.
func (s *Service) PortfolioRisks(ctx context.Context, p auth.Principal) ([]Assessment, error) {
	if err := s.authz.Require(p, auth.PermIntelligenceRead, p.TenantID); err != nil {
		return nil, err
	}
	scope := s.authz.ScopeOf(p)
	var out []Assessment
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '15s'`); err != nil {
			return err
		}
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		projects, err := postgres.Projects(ctx, tx)
		if err != nil {
			return err
		}
		out = []Assessment{}
		for _, pr := range projects {
			if !scope.TenantWide && !contains(p.ProjectIDs, pr.ID) {
				continue
			}
			a, err := s.assessProject(ctx, tx, pr, now)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		rank := map[string]int{"high": 0, "medium": 1, "unknown": 2, "low": 3}
		return rank[out[i].Overall] < rank[out[j].Overall]
	})
	return out, err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// assessProject computes the findings inside an open tenant transaction.
func (s *Service) assessProject(ctx context.Context, tx pgx.Tx, pr postgres.ProjectRef, now time.Time) (Assessment, error) {
	a := Assessment{ProjectID: pr.ID, Code: pr.Code, Name: pr.Name, Overall: "low", ComputedAt: now, Algorithm: IntelligenceAlgorithm, DataAsOf: now.Format("2006-01-02 15:04 MST")}
	evmHref := "#/evm"
	// --- schedule and cost performance (earned value) ---------------------
	r, err := postgres.ScheduleEVM(ctx, tx, pr.ID, now)
	switch {
	case errors.Is(err, postgres.ErrNotFound):
		a.Findings = append(a.Findings, Finding{Area: "schedule", Level: "unknown", Title: "No approved baseline schedule",
			Missing: []string{"an approved (BASELINE) schedule version"}, Advice: "Submit and approve a baseline schedule; schedule and cost performance cannot be measured without one.",
			Evidence: []Evidence{{"Schedules", "#/list/schedule_version"}}})
	case err != nil:
		return a, err
	default:
		fc := forecastFrom(r.BAC, r.PV, r.EV, r.AC)
		f := &fc
		if r.ProgressDate != nil {
			f.ProgressDate = r.ProgressDate.Format("2006-01-02")
		}
		// The database's indices are authoritative when it reports them.
		if r.SPI != nil {
			f.SPI, f.Spi = r.SPI, r.SPI.Round(3).String()
		}
		if r.CPI != nil {
			f.CPI, f.Cpi = r.CPI, r.CPI.Round(3).String()
		}
		// Schedule.
		sched := Finding{Area: "schedule", Metric: "SPI", Formula: "SPI = EV / PV (earned value over planned value at the status date)", Evidence: []Evidence{{"Earned value", evmHref}}}
		switch {
		case r.ProgressDate == nil:
			sched.Level, sched.Title = "unknown", "No approved progress report yet"
			sched.Missing = []string{"an approved progress report"}
			sched.Advice = "Record and approve progress; until then earned value is zero and performance cannot be judged."
		case r.SPI == nil:
			sched.Level, sched.Title = "unknown", "Schedule performance not defined (no planned value yet)"
			sched.Missing = []string{"planned value at the status date (the baseline may not have started)"}
		case r.SPI.LessThan(spiBad):
			sched.Level, sched.Title, sched.Value, sched.Threshold = "high", "Seriously behind the baseline", r.SPI.Round(3).String(), "below "+spiBad.String()
			sched.Advice = "Review the critical path with the planner; consider a recovery schedule and confirm resource availability."
		case r.SPI.LessThan(spiWarn):
			sched.Level, sched.Title, sched.Value, sched.Threshold = "medium", "Behind the baseline", r.SPI.Round(3).String(), "below "+spiWarn.String()
			sched.Advice = "Check which critical activities slipped and whether they can be recovered without added cost."
		default:
			sched.Level, sched.Title, sched.Value, sched.Threshold = "low", "On or ahead of the baseline", r.SPI.Round(3).String(), "at least "+spiWarn.String()
		}
		sched.Amounts = map[string]string{"planned_value": money2(r.PV), "earned_value": money2(r.EV), "schedule_variance": money2(r.SV)}
		a.Findings = append(a.Findings, sched)
		// Cost efficiency and forecast.
		cost := Finding{Area: "cost", Metric: "CPI", Formula: "CPI = EV / AC; EAC = BAC / CPI; ETC = EAC − AC; VAC = BAC − EAC", Evidence: []Evidence{{"Earned value", evmHref}}}
		switch {
		case f.CPI == nil:
			cost.Level, cost.Title = "unknown", "Cost performance not defined (no posted actual cost against earned value)"
			cost.Missing = []string{"posted actual cost on the project", "earned value above zero"}
		default:
			cost.Value, cost.Amounts = f.Cpi, map[string]string{"bac": f.Bac, "eac": f.EAC, "vac": f.VAC, "cost_variance": money2(r.CV)}
			switch {
			case f.CPI.LessThan(cpiBad):
				cost.Level, cost.Title, cost.Threshold = "high", "Forecast final cost well above budget", "below "+cpiBad.String()
				cost.Advice = "Identify the cost codes driving the overrun (cost report) and agree corrective action before further commitments."
			case f.CPI.LessThan(cpiWarn):
				cost.Level, cost.Title, cost.Threshold = "medium", "Forecast final cost above budget", "below "+cpiWarn.String()
				cost.Advice = "Review price variances and unplanned quantities on the busiest cost codes."
			default:
				cost.Level, cost.Title, cost.Threshold = "low", "Cost efficiency on or better than plan", "at least "+cpiWarn.String()
			}
		}
		a.Findings = append(a.Findings, cost)
		a.Forecast = f
	}
	// --- budget consumption (commitments and actuals vs approved BOQ) --------
	rows, err := postgres.ProjectCostReport(ctx, tx, pr.ID)
	if err != nil {
		return a, err
	}
	var budget, used, committed, actual decimal.Decimal
	var hot []string
	for _, row := range rows {
		budget = budget.Add(row.Budget)
		used = used.Add(row.Budget.Sub(row.Available))
		committed = committed.Add(row.Committed)
		actual = actual.Add(row.ActualPosted)
		if row.Budget.IsPositive() && row.Budget.Sub(row.Available).GreaterThanOrEqual(row.Budget.Mul(budgetWarn)) {
			hot = append(hot, row.CostCode)
		}
	}
	b := Finding{Area: "cost", Metric: "budget consumed", Formula: "consumed = budget − available, where available already nets commitments against invoiced and posted cost (no double counting)",
		Evidence: []Evidence{{"Cost report", "#/cost"}, {"BOQ", "#/list/boq_version"}}, Amounts: map[string]string{"budget": money2(budget), "consumed": money2(used), "committed": money2(committed), "actual_posted": money2(actual)}}
	switch {
	case !budget.IsPositive():
		b.Level, b.Title, b.Missing = "unknown", "No approved budget (BOQ)", []string{"an approved BOQ version with priced items"}
		b.Advice = "Approve a BOQ so commitments can be checked against a budget."
	default:
		share := used.Div(budget)
		b.Value = share.Mul(decimal.NewFromInt(100)).Round(1).String() + "%"
		switch {
		case share.GreaterThanOrEqual(budgetBad):
			b.Level, b.Title, b.Threshold = "high", "Budget fully consumed or exceeded", "100%"
			b.Advice = "Further purchases on exhausted cost codes are refused by the budget gate; a budget revision needs approval."
		case share.GreaterThanOrEqual(budgetWarn):
			b.Level, b.Title, b.Threshold = "medium", "Budget nearly consumed", "85%"
			b.Advice = "Cost codes near their limit: " + strings.Join(hot, ", ") + "."
		default:
			b.Level, b.Title, b.Threshold = "low", "Budget consumption within plan", "85%"
		}
	}
	a.Findings = append(a.Findings, b)
	// --- procurement: overdue purchase orders --------------------------------
	pos, err := postgres.OverduePOs(ctx, tx, now)
	if err != nil {
		return a, err
	}
	var overdueVal decimal.Decimal
	var ev []Evidence
	n := 0
	for _, po := range pos {
		if po.ProjectID != pr.ID {
			continue
		}
		n++
		overdueVal = overdueVal.Add(po.Total)
		if len(ev) < 5 {
			ev = append(ev, Evidence{po.Number + " · " + po.Supplier, "#/doc/purchase_order/" + po.ID})
		}
	}
	proc := Finding{Area: "procurement", Metric: "overdue purchase orders", Value: fmt.Sprint(n), Formula: "approved purchase orders whose requisition needed the goods before today and that are not closed",
		Evidence: ev, Amounts: map[string]string{"overdue_value": money2(overdueVal)}}
	switch {
	case n == 0:
		proc.Level, proc.Title = "low", "No overdue deliveries"
	case n <= 2:
		proc.Level, proc.Title = "medium", fmt.Sprintf("%d purchase order(s) overdue", n)
		proc.Advice = "Confirm revised delivery dates with the suppliers and check the affected activities' float."
	default:
		proc.Level, proc.Title = "high", fmt.Sprintf("%d purchase orders overdue", n)
		proc.Advice = "Escalate with procurement; several deliveries are late and may be delaying critical work."
	}
	a.Findings = append(a.Findings, proc)
	for _, f := range a.Findings {
		a.Overall = worse(a.Overall, f.Level)
	}
	return a, nil
}

// CashOutlook is the entity's near-term cash picture.
type CashOutlook struct {
	EntityID     string            `json:"entity_id"`
	AsOf         string            `json:"as_of"`
	CashHeld     string            `json:"cash_held"`
	BankAccounts int               `json:"bank_accounts"`
	Payables     map[string]string `json:"payables_due"`    // 30 | 60 | 90 | overdue
	Receivables  map[string]string `json:"receivables_due"` // 30 | 60 | 90 | overdue
	Net90        string            `json:"net_90"`
	Level        string            `json:"level"`
	Formula      string            `json:"formula"`
	Assumptions  []string          `json:"assumptions"`
	Missing      []string          `json:"missing,omitempty"`
}

// CashOutlookOf computes the 90-day cash requirement of an entity from
// approved invoices (tenant-wide scope).
func (s *Service) CashOutlookOf(ctx context.Context, p auth.Principal, entityID string) (CashOutlook, error) {
	if err := s.reportScope(p, auth.PermIntelligenceRead); err != nil {
		return CashOutlook{}, err
	}
	var out CashOutlook
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		out, err = cashOutlook(ctx, tx, entityID, now)
		return err
	})
	return out, err
}

func cashOutlook(ctx context.Context, tx pgx.Tx, entityID string, now time.Time) (CashOutlook, error) {
	out := CashOutlook{EntityID: entityID, AsOf: now.Format("2006-01-02"), Payables: map[string]string{}, Receivables: map[string]string{},
		Formula: "net 90 = cash held + receivables due within 90 days − payables due within 90 days (overdue items counted as due now)",
		Assumptions: []string{"Only approved supplier and customer invoices count; draft and submitted documents do not.", "Receivables are assumed collected by their due date; retention and advances are excluded.",
			"Cash held is the posted ledger balance of active company bank accounts, not a live bank balance.", "Payroll, taxes and non-invoice obligations are not yet recorded in the system."}}
	cash, n, err := postgres.BankCash(ctx, tx, entityID)
	if err != nil {
		return out, err
	}
	out.CashHeld, out.BankAccounts = money2(cash), n
	if n == 0 {
		out.Missing = append(out.Missing, "an active company bank account linked to a ledger account")
	}
	ap, err := postgres.PayablesOpen(ctx, tx, entityID, now.AddDate(0, 0, 90))
	if err != nil {
		return out, err
	}
	ar, err := postgres.ReceivablesOpen(ctx, tx, entityID, now.AddDate(0, 0, 90))
	if err != nil {
		return out, err
	}
	bucket := func(items []postgres.OpenItem, m map[string]string) decimal.Decimal {
		var d30, d60, d90, over, total decimal.Decimal
		for _, it := range items {
			days := int(it.DueDate.Sub(now).Hours() / 24)
			switch {
			case days < 0:
				over = over.Add(it.Open)
			case days <= 30:
				d30 = d30.Add(it.Open)
			case days <= 60:
				d60 = d60.Add(it.Open)
			default:
				d90 = d90.Add(it.Open)
			}
			total = total.Add(it.Open)
		}
		m["overdue"], m["30"], m["60"], m["90"], m["total"] = money2(over), money2(d30), money2(d60), money2(d90), money2(total)
		return total
	}
	apT := bucket(ap, out.Payables)
	arT := bucket(ar, out.Receivables)
	net := cash.Add(arT).Sub(apT)
	out.Net90 = money2(net)
	switch {
	case net.IsNegative():
		out.Level = "high"
	case apT.IsPositive() && net.LessThan(apT.Div(decimal.NewFromInt(4))):
		out.Level = "medium"
	default:
		out.Level = "low"
	}
	return out, nil
}

// ControlFinding is a control-anomaly flag for review (never an accusation).
type ControlFinding struct {
	Kind     string     `json:"kind"`
	Level    string     `json:"level"`
	Title    string     `json:"title"`
	Detail   string     `json:"detail"`
	Evidence []Evidence `json:"evidence"`
}

// ControlAnomalies lists transactions that deserve a second look
// (tenant-wide; auditors, finance, security).
func (s *Service) ControlAnomalies(ctx context.Context, p auth.Principal, entityID string) ([]ControlFinding, error) {
	if err := s.reportScope(p, auth.PermIntelligenceRead); err != nil {
		return nil, err
	}
	out := []ControlFinding{}
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		dups, err := postgres.DuplicateSupplierInvoices(ctx, tx)
		if err != nil {
			return err
		}
		for _, d := range dups {
			ev := make([]Evidence, 0, len(d.IDs))
			for _, id := range d.IDs {
				ev = append(ev, Evidence{"Invoice " + id[:8], "#/doc/supplier_invoice/" + id})
			}
			out = append(out, ControlFinding{Kind: "duplicate_invoice_number", Level: "high", Title: fmt.Sprintf("Invoice number %s appears %d times for %s", d.Number, len(d.IDs), d.Supplier),
				Detail: "The same supplier invoice number was entered more than once. Confirm it is not the same invoice paid twice.", Evidence: ev})
		}
		near, err := postgres.PaymentsJustBelowDualThreshold(ctx, tx, entityID, 30, 5)
		if err != nil {
			return err
		}
		for _, n := range near {
			out = append(out, ControlFinding{Kind: "payment_near_threshold", Level: "medium",
				Title:    fmt.Sprintf("Payment %s to %s is %s, just under the dual-approval threshold %s", n.Number, n.Supplier, money2(n.Amount), money2(n.Threshold)),
				Detail:   "Payments within 5% below the threshold in the last 30 days are listed so a reviewer can rule out splitting. The supplier-exposure window still aggregates them.",
				Evidence: []Evidence{{"Payment " + n.Number, "#/doc/payment_instruction/" + n.ID}}})
		}
		return nil
	})
	return out, err
}

// ------------------------------------------------------------- assistant

// Answer is the assistant's reply: text, structured facts and provenance.
type Answer struct {
	Question    string     `json:"question"`
	Intent      string     `json:"intent"`
	Text        string     `json:"text"`
	Facts       any        `json:"facts,omitempty"`
	Sources     []Evidence `json:"sources"`
	Freshness   string     `json:"freshness"`
	Assumptions []string   `json:"assumptions,omitempty"`
	Missing     []string   `json:"missing,omitempty"`
	Phrased     bool       `json:"phrased_by_model"`
}

// Phraser optionally rewrites a deterministic answer in natural language.
// It receives only the facts the person is allowed to see and may not add
// to them; the kernel checks that every number in its text comes from them.
type Phraser interface {
	Phrase(ctx context.Context, question string, facts any) (string, error)
}

// UsePhraser installs an optional language model for phrasing.
func (s *Service) UsePhraser(p Phraser) *Service { s.phraser = p; return s }

// Ask answers a question from computed facts. Unknown questions get the list
// of what can be asked; nothing is invented.
func (s *Service) Ask(ctx context.Context, p auth.Principal, question string) (Answer, error) {
	if err := s.authz.Require(p, auth.PermIntelligenceRead, p.TenantID); err != nil {
		return Answer{}, err
	}
	q := strings.ToLower(strings.TrimSpace(question))
	if len(q) == 0 || len(q) > 500 {
		return Answer{}, fmt.Errorf("%w: a question is 1..500 characters", ErrInvalidInput)
	}
	ans := Answer{Question: question, Freshness: time.Now().UTC().Format("2006-01-02 15:04 UTC")}
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(q, w) {
				return true
			}
		}
		return false
	}
	var err error
	switch {
	case has("over budget", "overrun", "overspend", "budget"):
		ans.Intent = "cost_risk"
		err = s.answerPortfolio(ctx, p, &ans, "cost", "over budget or close to it")
	case has("delay", "behind", "late activit", "critical", "schedule", "milestone"):
		ans.Intent = "schedule_risk"
		err = s.answerPortfolio(ctx, p, &ans, "schedule", "behind their baseline")
	case has("not been delivered", "undelivered", "overdue purchase", "overdue po", "delivery", "deliveries", "purchase order"):
		ans.Intent = "procurement"
		err = s.answerPortfolio(ctx, p, &ans, "procurement", "waiting on overdue deliveries")
	case has("invoice") && has("await", "pending", "approval", "approve", "waiting"):
		ans.Intent = "invoices_awaiting"
		err = s.answerQueue(ctx, p, &ans, "supplier_invoice", "SUBMITTED", "supplier invoices awaiting approval")
	case has("requisition") && has("await", "pending", "approval", "approve", "waiting"):
		ans.Intent = "requisitions_awaiting"
		err = s.answerQueue(ctx, p, &ans, "purchase_requisition", "SUBMITTED", "requisitions awaiting approval")
	case has("cash", "90 days", "liquidity", "money will we need", "payables due", "receivable"):
		ans.Intent = "cash"
		err = s.answerCash(ctx, p, &ans)
	case has("margin", "profit"):
		ans.Intent = "margin"
		err = s.answerMargins(ctx, p, &ans)
	case has("changed", "last week", "what happened", "recent"):
		ans.Intent = "recent_activity"
		err = s.answerRecent(ctx, p, &ans)
	case has("duplicate", "anomal", "fraud", "suspicious", "control"):
		ans.Intent = "controls"
		err = s.answerControls(ctx, p, &ans)
	case has("safety", "incident", "quality", "defect", "rfi", "drawing", "payroll", "equipment"):
		ans.Intent = "not_available"
		ans.Text = "Safety, quality, RFIs, drawings, payroll and equipment are not yet part of this system, so there is no data to answer from. They are on the roadmap (docs/BACKLOG.md)."
		ans.Missing = []string{"the module itself"}
	default:
		ans.Intent = "help"
		ans.Text = "I answer from the company's own records. Try: which projects are over budget; which activities are behind schedule; which purchase orders have not been delivered; " +
			"which invoices are awaiting approval; what is the cash requirement for the next 90 days; which projects have deteriorating margins; what changed last week; are there duplicate invoices."
	}
	if err != nil {
		return Answer{}, err
	}
	if s.phraser != nil && ans.Intent != "help" && ans.Intent != "not_available" {
		if text, err := s.phraser.Phrase(ctx, question, ans); err == nil && numbersComeFrom(text, ans) {
			ans.Text, ans.Phrased = text, true
		}
	}
	return ans, nil
}

func (s *Service) answerPortfolio(ctx context.Context, p auth.Principal, ans *Answer, area, phrase string) error {
	all, err := s.PortfolioRisks(ctx, p)
	if err != nil {
		return err
	}
	type hit struct {
		Project string   `json:"project"`
		Level   string   `json:"level"`
		Finding string   `json:"finding"`
		Value   string   `json:"value,omitempty"`
		Advice  string   `json:"advice,omitempty"`
		Missing []string `json:"missing,omitempty"`
	}
	var hits []hit
	var unknown []string
	for _, a := range all {
		for _, f := range a.Findings {
			if f.Area != area {
				continue
			}
			switch f.Level {
			case "medium", "high":
				hits = append(hits, hit{Project: a.Code + " " + a.Name, Level: f.Level, Finding: f.Title, Value: f.Value, Advice: f.Advice})
				ans.Sources = append(ans.Sources, Evidence{a.Code + ": " + f.Title, "#/risk/" + a.ProjectID})
			case "unknown":
				unknown = append(unknown, a.Code+" ("+strings.Join(f.Missing, "; ")+")")
			}
		}
	}
	ans.Facts = hits
	switch {
	case len(all) == 0:
		ans.Text = "You have no projects in view."
	case len(hits) == 0:
		ans.Text = fmt.Sprintf("None of the %d project(s) you can see are %s.", len(all), phrase)
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%d of %d project(s) are %s:\n", len(hits), len(all), phrase)
		for _, h := range hits {
			fmt.Fprintf(&b, "• %s — %s (%s)", h.Project, h.Finding, h.Level)
			if h.Value != "" {
				fmt.Fprintf(&b, ", value %s", h.Value)
			}
			if h.Advice != "" {
				fmt.Fprintf(&b, ". %s", h.Advice)
			}
			b.WriteString("\n")
		}
		ans.Text = strings.TrimSpace(b.String())
	}
	if len(unknown) > 0 {
		ans.Missing = append(ans.Missing, "cannot be assessed: "+strings.Join(unknown, "; "))
	}
	ans.Assumptions = []string{"Assessed by " + IntelligenceAlgorithm + " from approved baselines, posted ledger cost and approved purchase orders."}
	return nil
}

func (s *Service) answerQueue(ctx context.Context, p auth.Principal, ans *Answer, docType, status, phrase string) error {
	docs, err := s.ListP2PDocs(ctx, p, docType, status, 200)
	if err != nil {
		return err
	}
	var total decimal.Decimal
	for _, d := range docs {
		total = total.Add(d.Amount)
		if len(ans.Sources) < 10 {
			ans.Sources = append(ans.Sources, Evidence{d.Number + " " + d.Label, "#/doc/" + docType + "/" + d.ID})
		}
	}
	ans.Facts = map[string]any{"count": len(docs), "total": money2(total), "items": docs}
	if len(docs) == 0 {
		ans.Text = "There are no " + phrase + "."
	} else {
		ans.Text = fmt.Sprintf("%d %s, totalling %s.", len(docs), phrase, money2(total))
	}
	ans.Sources = append(ans.Sources, Evidence{"Open the list", "#/list/" + docType + "/" + status})
	return nil
}

func (s *Service) answerCash(ctx context.Context, p auth.Principal, ans *Answer) error {
	if !s.tenantWide(p) {
		ans.Text = "The cash outlook covers the whole company and needs a tenant-wide finance role."
		ans.Missing = []string{"tenant-wide scope"}
		return nil
	}
	var entities []string
	if err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		entities, err = entityIDs(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	var outs []CashOutlook
	var b strings.Builder
	for _, e := range entities {
		o, err := s.CashOutlookOf(ctx, p, e)
		if err != nil {
			return err
		}
		outs = append(outs, o)
		fmt.Fprintf(&b, "Cash held %s; payables due within 90 days %s (overdue %s); receivables due within 90 days %s (overdue %s); net position %s (%s risk).\n",
			o.CashHeld, o.Payables["total"], o.Payables["overdue"], o.Receivables["total"], o.Receivables["overdue"], o.Net90, o.Level)
		ans.Assumptions = o.Assumptions
		ans.Missing = append(ans.Missing, o.Missing...)
	}
	ans.Facts = outs
	ans.Text = strings.TrimSpace(b.String())
	ans.Sources = []Evidence{{"Payables aging", "#/aging/ap"}, {"Receivables aging", "#/aging/ar"}, {"Trial balance", "#/tb"}}
	return nil
}

func (s *Service) answerMargins(ctx context.Context, p auth.Principal, ans *Answer) error {
	all, err := s.PortfolioRisks(ctx, p)
	if err != nil {
		return err
	}
	type row struct {
		Project string `json:"project"`
		Revenue string `json:"revenue_posted"`
		Cost    string `json:"cost_posted"`
		Margin  string `json:"margin"`
		CPI     string `json:"cpi,omitempty"`
		EAC     string `json:"eac,omitempty"`
	}
	var rows []row
	var b strings.Builder
	for _, a := range all {
		pr, err := s.ProjectProfitability(ctx, p, a.ProjectID)
		if err != nil {
			return err
		}
		r := row{Project: a.Code + " " + a.Name, Revenue: money2(pr.RevenuePosted), Cost: money2(pr.CostPosted), Margin: money2(pr.Margin)}
		if a.Forecast != nil {
			r.CPI, r.EAC = a.Forecast.Cpi, a.Forecast.EAC
		}
		rows = append(rows, r)
		fmt.Fprintf(&b, "• %s: posted revenue %s, posted cost %s, margin %s", r.Project, r.Revenue, r.Cost, r.Margin)
		if r.CPI != "" {
			fmt.Fprintf(&b, "; CPI %s, forecast final cost %s", r.CPI, r.EAC)
		}
		b.WriteString("\n")
		ans.Sources = append(ans.Sources, Evidence{a.Code + " risks", "#/risk/" + a.ProjectID})
	}
	ans.Facts = rows
	ans.Text = strings.TrimSpace(b.String())
	if ans.Text == "" {
		ans.Text = "You have no projects in view."
	}
	ans.Assumptions = []string{"Margin is posted revenue less posted cost (ledger), not forecast profit.", "Forecast final cost uses EAC = BAC / CPI where a baseline and progress exist."}
	return nil
}

func (s *Service) answerRecent(ctx context.Context, p auth.Principal, ans *Answer) error {
	if !s.tenantWide(p) {
		ans.Text = "Recent activity across the company needs a tenant-wide role; your project lists show your own projects' documents."
		return nil
	}
	var acts []postgres.RecentActivity
	if err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		acts, err = postgres.RecentActivityCounts(ctx, tx, 7)
		return err
	}); err != nil {
		return err
	}
	ans.Facts = acts
	if len(acts) == 0 {
		ans.Text = "Nothing was created in the last 7 days."
		return nil
	}
	var parts []string
	for _, a := range acts {
		parts = append(parts, fmt.Sprintf("%d %s", a.Count, strings.ReplaceAll(a.Type, "_", " ")))
	}
	ans.Text = "Created in the last 7 days: " + strings.Join(parts, ", ") + "."
	ans.Sources = []Evidence{{"My work", "#/home"}}
	return nil
}

func (s *Service) answerControls(ctx context.Context, p auth.Principal, ans *Answer) error {
	if !s.tenantWide(p) {
		ans.Text = "Control reviews cover the whole company and need a tenant-wide role."
		return nil
	}
	var entities []string
	if err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		entities, err = entityIDs(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	var all []ControlFinding
	for _, e := range entities {
		f, err := s.ControlAnomalies(ctx, p, e)
		if err != nil {
			return err
		}
		all = append(all, f...)
	}
	ans.Facts = all
	if len(all) == 0 {
		ans.Text = "No duplicate invoice numbers and no payments just under the dual-approval threshold were found."
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "%d item(s) for review:\n", len(all))
		for _, f := range all {
			fmt.Fprintf(&b, "• %s\n", f.Title)
			ans.Sources = append(ans.Sources, f.Evidence...)
		}
		ans.Text = strings.TrimSpace(b.String())
	}
	ans.Assumptions = []string{"These are flags for a reviewer, not findings of fraud."}
	ans.Sources = append(ans.Sources, Evidence{"Control review", "#/risk"})
	return nil
}

// numbersComeFrom checks that every digit run in text appears in the
// deterministic answer or its facts (a model may rephrase, never invent).
func numbersComeFrom(text string, a Answer) bool {
	src := a.Text + " " + fmt.Sprint(a.Facts)
	srcNums := map[string]bool{}
	for _, n := range digitRuns(src) {
		srcNums[n] = true
	}
	for _, n := range digitRuns(text) {
		if !srcNums[n] {
			return false
		}
	}
	return true
}

func digitRuns(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur += string(r)
			continue
		}
		if cur != "" {
			out = append(out, strings.TrimLeft(cur, "0"))
			cur = ""
		}
	}
	if cur != "" {
		out = append(out, strings.TrimLeft(cur, "0"))
	}
	return out
}

// forecastFrom computes the earned-value indices and the forecast of final
// cost. Indices are left undefined (nil) rather than derived from a zero
// denominator or from no actual cost.
func forecastFrom(bac, pv, ev, ac decimal.Decimal) Forecast {
	f := Forecast{BAC: bac, PV: pv, EV: ev, AC: ac, Bac: money2(bac), Pv: money2(pv), Ev: money2(ev), Ac: money2(ac),
		Assumptions: []string{"Actual cost is the posted ledger cost on the project at baseline prices (SC-09).", "Future work performs at the cost efficiency observed so far.",
			"Approved variations change BAC only through a new baseline."}}
	if pv.IsPositive() {
		spi := ev.Div(pv).Round(6)
		f.SPI, f.Spi = &spi, spi.Round(3).String()
	}
	if bac.IsPositive() {
		f.PercentComplete = ev.Div(bac).Mul(decimal.NewFromInt(100)).Round(1).String() + "%"
	}
	if ac.IsPositive() && ev.IsPositive() {
		cpi := ev.Div(ac).Round(6)
		f.CPI, f.Cpi = &cpi, cpi.Round(3).String()
		eac := bac.Div(cpi)
		f.EAC, f.ETC, f.VAC = money2(eac), money2(eac.Sub(ac)), money2(bac.Sub(eac))
		f.Method = "EAC = BAC / CPI (performance to date continues)"
	} else {
		f.Method = "not computable: CPI undefined (no posted actual cost against earned value)"
	}
	return f
}
