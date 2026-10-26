package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func platformCast(f *fixture) (owner, wfAdmin, secAdmin, apSup auth.Principal) {
	mk := func(id string, roles ...string) auth.Principal {
		return auth.Principal{Kind: auth.KindHuman, UserID: id, TenantID: f.tenant, Roles: roles, IssuedAt: time.Now().Add(-time.Minute), MFA: true, AuthTime: time.Now()}
	}
	return mk("u-process-owner", "process_owner"), mk("u-workflow-admin", "workflow_admin"), mk("u-security-admin", "security_admin"), mk("u-ap-supervisor", "ap_supervisor")
}

const staleRule = `{"when":{"kind":"document_stale","subject":"supplier_invoice","status":"SUBMITTED","hours":1},"then":{"notify_role":"ap_supervisor","severity":"warn","title":"Invoice waiting"}}`

// Rules are maker/checker, frozen once active, tenant-isolated; the worker
// notifies on a match once, resolves when the condition clears, and never
// changes the document.
func TestPlatform_RulesLifecycleAndWorker(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	owner, wfAdmin, _, _ := platformCast(f)
	apSup := c.apSup // project-scoped, like a real AP supervisor

	// Lifecycle.
	_, err := f.svc.ProposeRule(f.ctx, apSup, RuleInput{Code: "X", Name: "x", Body: []byte(staleRule)})
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("AP supervisor proposing a rule: %v", err)
	}
	_, err = f.svc.ProposeRule(f.ctx, owner, RuleInput{Code: "AP-STALE", Name: "Stale invoices", Body: []byte(`{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"info","approve":true}}`)})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("rule with an action outside the catalogue accepted: %v", err)
	}
	rule, err := f.svc.ProposeRule(f.ctx, owner, RuleInput{Code: "AP-STALE", Name: "Stale invoices", Body: []byte(staleRule)})
	must(t, "propose", err)
	if _, err := f.svc.DecideRule(f.ctx, owner, rule.ID, true, ""); !errors.Is(err, auth.ErrForbidden) && !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("author activating own rule: %v", err)
	}
	ownerAdmin := owner
	ownerAdmin.Roles = []string{"process_owner", "workflow_admin"}
	if _, err := f.svc.DecideRule(f.ctx, ownerAdmin, rule.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("author with both roles activating own rule: %v", err)
	}
	active, err := f.svc.DecideRule(f.ctx, wfAdmin, rule.ID, true, "")
	must(t, "activate", err)
	if active.Status != "ACTIVE" || active.ActivatedBy != wfAdmin.UserID {
		t.Fatalf("%+v", active)
	}
	if _, err := f.svc.UpdateRule(f.ctx, owner, rule.ID, RuleInput{Name: "changed", Body: []byte(staleRule)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("editing an active rule: %v", err)
	}
	// The database refuses a direct body change of an active rule too.
	err = f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE automation_rules SET body = '{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"info"}}' WHERE id = $1::uuid`, rule.ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("direct body change of an active rule: %v", err)
	}

	// Worker: nothing stale yet.
	res, err := f.svc.RunAutomation(f.ctx, f.tenant)
	must(t, "run", err)
	if res.Rules != 1 || res.Findings != 0 || res.Snapshots < 1 {
		t.Fatalf("first run %+v", res)
	}
	// A submitted invoice older than an hour (backdated directly, as time would).
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("5")})
	inv, _ := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "INV-STALE-1", InvoiceDate: today(), DueDate: today(), Subtotal: dec("422500"), TaxAmount: dec("63375"), Total: dec("485875"),
		Lines: []InvoiceLine{{1, dec("5"), dec("84500")}}})
	// Backdating is a test-only superuser act (the guards refuse it to every
	// application role, as they should).
	backdate(t, f, `UPDATE supplier_invoices SET created_at = now() - interval '3 hours' WHERE id = $1::uuid`, inv)
	res, err = f.svc.RunAutomation(f.ctx, f.tenant)
	must(t, "run 2", err)
	if res.Findings != 1 || res.Notified != 1 {
		t.Fatalf("second run %+v", res)
	}
	// Idempotent: a third run adds nothing.
	res, err = f.svc.RunAutomation(f.ctx, f.tenant)
	must(t, "run 3", err)
	if res.Findings != 1 || res.Notified != 0 || res.Resolved != 0 {
		t.Fatalf("third run %+v", res)
	}
	// The AP supervisor sees it; the site engineer (no role match) does not;
	// another tenant sees nothing.
	ns, err := f.svc.Notifications(f.ctx, apSup, false, 50)
	must(t, "notifications", err)
	if len(ns) != 1 || ns[0].Kind != "automation.document_stale" || !strings.Contains(ns[0].Title, "INV-STALE-1") || ns[0].ProjectID != f.project || ns[0].Href != "#/doc/supplier_invoice/"+inv {
		t.Fatalf("supervisor notifications %+v", ns)
	}
	if ns, _ := f.svc.Notifications(f.ctx, c.siteEng, false, 50); len(ns) != 0 {
		t.Fatalf("site engineer sees %+v", ns)
	}
	if ns, _ := f.svc.Notifications(f.ctx, f.outsider, false, 50); len(ns) != 0 {
		t.Fatalf("outsider sees %+v", ns)
	}
	must(t, "read", f.svc.MarkNotificationRead(f.ctx, apSup, ns[0].ID))
	if err := f.svc.MarkNotificationRead(f.ctx, c.siteEng, ns[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("site engineer marking another's notification: %v", err)
	}
	// The invoice itself is untouched: still SUBMITTED, decided by a person.
	var status string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM supplier_invoices WHERE id = $1::uuid`, inv).Scan(&status)
	})
	if status != "SUBMITTED" {
		t.Fatalf("automation changed the invoice to %s", status)
	}
	_, err = f.svc.ApproveInvoice(f.ctx, c.apSup, inv, "")
	must(t, "approve invoice", err)
	res, err = f.svc.RunAutomation(f.ctx, f.tenant)
	must(t, "run 4", err)
	if res.Findings != 0 || res.Resolved != 1 {
		t.Fatalf("after approval %+v", res)
	}
	if ns, _ := f.svc.Notifications(f.ctx, apSup, false, 50); len(ns) != 0 {
		t.Fatalf("resolved notification still open: %+v", ns)
	}
	// Retire needs a reason; retired rules do not run.
	if _, err := f.svc.DecideRule(f.ctx, wfAdmin, rule.ID, false, "no"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("retire without reason: %v", err)
	}
	_, err = f.svc.DecideRule(f.ctx, wfAdmin, rule.ID, false, "Replaced by a 24-hour rule")
	must(t, "retire", err)
	res, _ = f.svc.RunAutomation(f.ctx, f.tenant)
	if res.Rules != 0 {
		t.Fatalf("retired rule ran: %+v", res)
	}
	t.Logf("held: maker/checker, frozen body, notify-only worker, dedupe, resolution, tenant isolation")
}

// Tenant settings: permission, validation, optimistic locking, isolation.
func TestPlatform_TenantSettings(t *testing.T) {
	f := newFixture(t)
	owner, _, secAdmin, _ := platformCast(f)
	cur, err := f.svc.TenantSettings(f.ctx, owner)
	must(t, "defaults", err)
	if cur.Version != 0 || cur.DisplayName == "" || cur.ExportDailyLimit != 200 {
		t.Fatalf("defaults %+v", cur)
	}
	in := postgres.TenantSettings{DisplayName: "Senselet Construction PLC", ShortCode: "Senselet", LetterheadName: "SENSELET CONSTRUCTION PLC", Country: "et", Timezone: "Africa/Addis_Ababa", Locale: "ti", ExportDailyLimit: 50}
	if _, err := f.svc.SaveTenantSettings(f.ctx, owner, in); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("process owner saving settings: %v", err)
	}
	bad := in
	bad.Timezone = "Mars/Olympus"
	if _, err := f.svc.SaveTenantSettings(f.ctx, secAdmin, bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad timezone: %v", err)
	}
	saved, err := f.svc.SaveTenantSettings(f.ctx, secAdmin, in)
	must(t, "save", err)
	if saved.ShortCode != "senselet" || saved.Country != "ET" || saved.Version != 1 {
		t.Fatalf("%+v", saved)
	}
	stale := saved
	stale.Version = 0
	stale.DisplayName = "Stale write"
	if _, err := f.svc.SaveTenantSettings(f.ctx, secAdmin, stale); !errors.Is(err, postgres.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if got, _ := f.svc.TenantSettings(f.ctx, f.outsider); got.ShortCode == "senselet" {
		t.Fatal("another tenant reads these settings")
	}
}

// Export budget: counted per person and day, refused when spent, security
// notified once, all of it committed even though the export is refused.
func TestPlatform_ExportBudget(t *testing.T) {
	f := newFixture(t)
	_, _, secAdmin, _ := platformCast(f)
	_, err := f.svc.SaveTenantSettings(f.ctx, secAdmin, postgres.TenantSettings{DisplayName: "Budget Co", ShortCode: "budget", Country: "ET", Timezone: "UTC", Locale: "en", ExportDailyLimit: 3})
	must(t, "settings", err)
	for i := 0; i < 3; i++ {
		must(t, "export within budget", f.svc.RecordExport(f.ctx, f.appr, "/v1/p2p/supplier", 100))
	}
	err = f.svc.RecordExport(f.ctx, f.appr, "/v1/p2p/supplier", 100)
	if !errors.Is(err, ErrExportBudget) {
		t.Fatalf("fourth export: %v", err)
	}
	if err := f.svc.RecordExport(f.ctx, f.appr, "/v1/p2p/supplier", 100); !errors.Is(err, ErrExportBudget) {
		t.Fatalf("fifth export: %v", err)
	}
	must(t, "another person is unaffected", f.svc.RecordExport(f.ctx, f.prep, "/v1/p2p/supplier", 100))
	ns, err := f.svc.Notifications(f.ctx, secAdmin, false, 10)
	must(t, "security notifications", err)
	if len(ns) != 1 || ns[0].Kind != "security.export_budget" || !strings.Contains(ns[0].Title, f.appr.UserID) {
		t.Fatalf("security notifications %+v", ns)
	}
	var events int
	_ = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM data_access_events WHERE tenant_id = $1::uuid AND user_id = $2`, f.tenant, f.appr.UserID).Scan(&events)
	if events != 5 {
		t.Fatalf("recorded events %d (refusals must be recorded too)", events)
	}
	var audited int
	_ = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM audit_log WHERE tenant_id = $1::uuid AND action = 'security.export_budget_exceeded'`, f.tenant).Scan(&audited)
	if audited != 2 {
		t.Fatalf("audit entries %d", audited)
	}
}

// Intelligence: findings carry formulas, evidence and missing data; EVM
// forecast formulas hold; indices are never derived from zero denominators;
// the assistant answers from the same facts and refuses to invent.
func TestPlatform_IntelligenceAndAssistant(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	// Without a baseline: unknown, with what is missing stated.
	a, err := f.svc.ProjectRisks(f.ctx, c.pm, f.project)
	must(t, "risks", err)
	var sched, budget *Finding
	for i := range a.Findings {
		switch {
		case a.Findings[i].Area == "schedule":
			sched = &a.Findings[i]
		case a.Findings[i].Metric == "budget consumed":
			budget = &a.Findings[i]
		}
	}
	if sched == nil || sched.Level != "unknown" || len(sched.Missing) == 0 || a.Forecast != nil {
		t.Fatalf("no-baseline assessment %+v", a)
	}
	if budget == nil || budget.Level != "unknown" {
		t.Fatalf("no-BOQ budget finding %+v", budget)
	}
	if a.Overall != "unknown" {
		t.Fatalf("overall %s", a.Overall)
	}
	// Outsider and out-of-scope people get nothing.
	if _, err := f.svc.ProjectRisks(f.ctx, f.outsider, f.project); err == nil {
		t.Fatal("outsider assessed another tenant's project")
	}
	other := c.pm
	other.ProjectIDs = []string{"11111111-1111-4111-8111-111111111111"}
	if _, err := f.svc.ProjectRisks(f.ctx, other, f.project); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("out-of-scope PM: %v", err)
	}
	// With a budget and commitments: budget consumption is measured and
	// procurement is assessed; an overdue PO raises the level.
	w.approvedBOQ(t)
	pr, _, po := w.awardedPO(t, "20", "500")
	backdate(t, f, `UPDATE purchase_requisitions SET needed_by = current_date - 10 WHERE id = $1::uuid`, pr)
	a, err = f.svc.ProjectRisks(f.ctx, c.pm, f.project)
	must(t, "risks 2", err)
	var proc *Finding
	for i := range a.Findings {
		if a.Findings[i].Area == "procurement" {
			proc = &a.Findings[i]
		}
		if a.Findings[i].Metric == "budget consumed" && a.Findings[i].Level == "unknown" {
			t.Fatalf("budget still unknown with an approved BOQ: %+v", a.Findings[i])
		}
	}
	if proc == nil || proc.Level != "medium" || proc.Value != "1" || len(proc.Evidence) != 1 || !strings.HasSuffix(proc.Evidence[0].Href, po) {
		t.Fatalf("procurement finding %+v", proc)
	}
	// Assistant: deterministic answers with sources; help for the unknown.
	ans, err := f.svc.Ask(f.ctx, c.pm, "Which purchase orders have not been delivered?")
	must(t, "ask", err)
	if ans.Intent != "procurement" || !strings.Contains(ans.Text, "1 of 1 project") || len(ans.Sources) == 0 {
		t.Fatalf("answer %+v", ans)
	}
	ans, err = f.svc.Ask(f.ctx, c.pm, "Which invoices are awaiting approval?")
	must(t, "ask queue", err)
	if ans.Intent != "invoices_awaiting" || !strings.Contains(ans.Text, "no supplier invoices") {
		t.Fatalf("queue answer %+v", ans)
	}
	ans, err = f.svc.Ask(f.ctx, c.pm, "Which safety incidents are unresolved?")
	must(t, "ask safety", err)
	if ans.Intent != "not_available" || len(ans.Missing) == 0 {
		t.Fatalf("safety answer %+v", ans)
	}
	ans, err = f.svc.Ask(f.ctx, c.pm, "tell me a joke")
	must(t, "ask help", err)
	if ans.Intent != "help" {
		t.Fatalf("help answer %+v", ans)
	}
	if _, err := f.svc.Ask(f.ctx, c.siteEng, "which projects are over budget?"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("site engineer asking: %v", err)
	}
	// Cash outlook needs tenant-wide scope and states its assumptions.
	if _, err := f.svc.CashOutlookOf(f.ctx, c.pm, f.entity); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("PM cash outlook: %v", err)
	}
	cash, err := f.svc.CashOutlookOf(f.ctx, c.cfo, f.entity)
	must(t, "cash", err)
	if cash.Payables["total"] != "0.00" || len(cash.Assumptions) < 3 || cash.Formula == "" {
		t.Fatalf("cash %+v", cash)
	}
	// A phraser that invents a number is ignored; one that only rephrases is used.
	f.svc.UsePhraser(fakePhraser{text: "There are 7 overdue orders worth 9,999,999."})
	ans, _ = f.svc.Ask(f.ctx, c.pm, "Which purchase orders have not been delivered?")
	if ans.Phrased {
		t.Fatal("a phrasing with invented numbers was accepted")
	}
	f.svc.UsePhraser(fakePhraser{text: "One of your 1 projects is waiting on an overdue delivery."})
	ans, _ = f.svc.Ask(f.ctx, c.pm, "Which purchase orders have not been delivered?")
	if !ans.Phrased || !strings.HasPrefix(ans.Text, "One of your") {
		t.Fatalf("faithful phrasing rejected: %+v", ans)
	}
	f.svc.UsePhraser(nil)
	// EVM forecast formulas on a worked example.
	fc := forecastFrom(dec("1000"), dec("400"), dec("300"), dec("375"))
	if fc.Cpi != "0.8" || fc.EAC != "1,250.00" || fc.ETC != "875.00" || fc.VAC != "-250.00" || fc.PercentComplete != "30%" {
		t.Fatalf("forecast %+v", fc)
	}
	t.Logf("held: unknown with missing data, scope, deterministic answers, phrasing guard, EAC/ETC/VAC formulas")
}

type fakePhraser struct{ text string }

func (p fakePhraser) Phrase(context.Context, string, any) (string, error) { return p.text, nil }

// backdate runs a superuser statement with triggers bypassed, to simulate
// the passage of time. Application roles cannot do this (the guards refuse
// changes to created_at and needed_by).
func backdate(t *testing.T, f *fixture, sql string, args ...any) {
	t.Helper()
	if f.super == nil {
		t.Skip("no superuser connection (SERK_TEST_SUPERUSER_DSN) to simulate time")
	}
	tx, err := f.super.Begin(f.ctx)
	must(t, "super begin", err)
	defer tx.Rollback(f.ctx) //nolint:errcheck
	_, err = tx.Exec(f.ctx, `SET LOCAL session_replication_role = replica`)
	must(t, "replica role", err)
	_, err = tx.Exec(f.ctx, sql, args...)
	must(t, "backdate", err)
	must(t, "super commit", tx.Commit(f.ctx))
}
