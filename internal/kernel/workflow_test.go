package kernel

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
	"github.com/serk-group/serk-construction/pkg/workflow"
)

// Controlled-approval workflow engine. The property under test throughout:
// automation routes, reminds, escalates and executes — it never authorizes.

const journalPostingDef = `{
  "key": "journal.posting", "title": "Journal approval and posting", "subject": "journal", "mandatory": true,
  "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "Finance review", "permission": "journal.approve",
     "distinct_from": ["initiator", "subject.creator"], "sla": "24h", "escalate_to": "approval.high_value",
     "expire_after": "168h", "effect": "journal.approve"},
    {"id": "executive", "title": "Executive sign-off", "permission": "approval.high_value", "approvals": 2,
     "require_mfa": true, "when": [{"amount_gte": "1000000.00", "currency": "ETB"}],
     "distinct_from": ["initiator", "subject.creator", "step:review"]},
    {"id": "post", "title": "Controller posts", "permission": "journal.post",
     "distinct_from": ["initiator", "subject.creator", "step:review", "step:executive"], "effect": "journal.post"}
  ],
  "on_reject": "journal.cancel"
}`

const periodCloseDef = `{
  "key": "period.close", "title": "Fiscal period close", "subject": "fiscal_period", "mandatory": true,
  "start_permission": "journal.read",
  "steps": [
    {"id": "close", "title": "Controller closes", "permission": "period.close", "distinct_from": ["initiator", "subject.creator"], "effect": "period.close"}
  ]
}`

type wfActors struct {
	owner, cfo2, admin, ctrl2 auth.Principal
}

func (f *fixture) wfActors() wfActors {
	return wfActors{
		owner: auth.Principal{Kind: auth.KindHuman, UserID: "u-process-owner", TenantID: f.tenant, Roles: []string{"process_owner"}},
		cfo2:  auth.Principal{Kind: auth.KindHuman, UserID: "u-cfo-2", TenantID: f.tenant, Roles: []string{"cfo"}, MFA: true, AuthTime: time.Now()},
		admin: auth.Principal{Kind: auth.KindHuman, UserID: "u-wf-admin", TenantID: f.tenant, Roles: []string{"workflow_admin"}},
		ctrl2: auth.Principal{Kind: auth.KindHuman, UserID: "u-controller-2", TenantID: f.tenant, Roles: []string{"controller"}},
	}
}

// publish proposes (process owner) and publishes (CFO, MFA) a definition.
func (f *fixture) publish(t *testing.T, body string) postgres.WorkflowDefinitionRow {
	t.Helper()
	a := f.wfActors()
	d, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(body))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, d.ID, true, ""); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return d
}

func (f *fixture) draftJournal(t *testing.T, j ledger.Journal) string {
	t.Helper()
	res, err := f.svc.CreateJournal(f.ctx, f.prep, j)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return res.JournalID
}

func (f *fixture) bigJournal(k string) ledger.Journal {
	return f.journal(k,
		ledger.Line{AccountID: f.accounts["1200"], Side: ledger.Debit, Amount: money.MustNew("1000000.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1300"], Side: ledger.Debit, Amount: money.MustNew("150000.00", "ETB")},
		ledger.Line{AccountID: f.accounts["2000"], Side: ledger.Credit, Amount: money.MustNew("1150000.00", "ETB")},
	)
}

func (f *fixture) journalStatus(t *testing.T, id string) string {
	t.Helper()
	return f.totals(t, id).status
}

func historyKinds(d InstanceDetail) string {
	var k []string
	for _, h := range d.History {
		k = append(k, h.Kind)
	}
	return strings.Join(k, ",")
}

// backdate moves an instance's deadlines into the past, as the operator,
// with triggers disabled for this one statement: a simulated clock for
// timer tests (deadlines are otherwise derived by the database only).
func (f *fixture) backdate(t *testing.T, instanceID, column string) {
	t.Helper()
	ctx := f.ctx
	if _, err := f.super.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	defer f.super.Exec(ctx, `SET session_replication_role = origin`) //nolint:errcheck
	if _, err := f.super.Exec(ctx, `UPDATE workflow_instances SET `+column+` = now() - interval '1 minute' WHERE id=$1::uuid`, instanceID); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflow_MandatoryJournalWorkflowReplacesDirectPath(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-small")))

	// The direct API path is closed…
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("direct approve under a mandatory workflow: %v", err)
	}
	// …and so is the database path, even for the application role.
	err := f.rawAs(f.appr, "journal.approve", "journal", jid, "", `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
	if err == nil || !strings.Contains(err.Error(), "requires its mandatory approval workflow") {
		t.Fatalf("raw approve under a mandatory workflow: %v", err)
	}

	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Route) != 2 || w.Route[0].ID != "review" || w.Route[1].ID != "post" || w.SLADueAt == nil || w.ExpiresAt == nil {
		t.Fatalf("small journal route %+v", w.Route)
	}
	if _, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid); err == nil {
		t.Fatal("second ACTIVE workflow for the same subject")
	}

	// The preparer cannot decide (no permission); the approver sees the task.
	if _, err := f.svc.DecideWorkflow(f.ctx, f.prep, w.ID, true, ""); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("preparer decided: %v", err)
	}
	tasks, err := f.svc.ListWorkflowTasks(f.ctx, f.appr)
	if err != nil || len(tasks) != 1 || tasks[0].Step != "review" || tasks[0].Amount != "115000.00" {
		t.Fatalf("approver tasks %+v %v", tasks, err)
	}
	if tasks, _ := f.svc.ListWorkflowTasks(f.ctx, f.post); len(tasks) != 0 {
		t.Fatalf("poster sees a task before review: %+v", tasks)
	}

	r, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, "")
	if err != nil || r.EffectExecuted != "journal.approve" || !r.StepCompleted {
		t.Fatalf("review: %+v %v", r, err)
	}
	if st := f.journalStatus(t, jid); st != "APPROVED" {
		t.Fatalf("journal %s after review", st)
	}
	r, err = f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, "")
	if err != nil || r.EffectExecuted != "journal.post" || r.Instance.Status != "COMPLETED" {
		t.Fatalf("post: %+v %v", r, err)
	}
	if st := f.journalStatus(t, jid); st != "POSTED" {
		t.Fatalf("journal %s after post step", st)
	}
	d, err := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := historyKinds(d); got != "STARTED,DECIDED,EFFECT,STEP_COMPLETED,DECIDED,EFFECT,STEP_COMPLETED,COMPLETED" {
		t.Fatalf("history %s", got)
	}
	var events int
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE aggregate_id=$1 AND event_type IN ('workflow.started','workflow.task_opened','workflow.decided','workflow.completed')`, w.ID).Scan(&events)
	})
	if events != 6 { // started, 2× task_opened, 2× decided, completed
		t.Fatalf("workflow outbox events %d", events)
	}
}

func TestWorkflow_HighValueNeedsQuorumOfDistinctExecutivesWithMFA(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	a := f.wfActors()
	jid := f.draftJournal(t, f.bigJournal(key("wf-big")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Route) != 3 || w.Route[1].ID != "executive" || w.Route[1].Approvals != 2 || !strings.Contains(w.Route[1].Reason, "≥ threshold 1000000.00 ETB") {
		t.Fatalf("big journal route %+v", w.Route)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	// The review approver may not also sign off as executive.
	both := auth.Principal{Kind: auth.KindHuman, UserID: f.appr.UserID, TenantID: f.tenant, Roles: []string{"finance_manager", "cfo"}, MFA: true, AuthTime: time.Now()}
	if _, err := f.svc.DecideWorkflow(f.ctx, both, w.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("review approver signed off as executive: %v", err)
	}
	// The database refuses a decision on an MFA step that does not record MFA
	// (the flag is asserted by the application: this catches code paths that
	// forget the check, not a compromised application — see THREAT_MODEL).
	staleCFO := f.cfo
	staleCFO.AuthTime = time.Now().Add(-time.Hour)
	err = f.rawAs(staleCFO, "workflow.decide", "workflow_instance", w.ID, "1:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,mfa) VALUES ($1::uuid,$2::uuid,1,'executive','u-cfo','APPROVE',true)`,
		f.tenant, w.ID)
	if err == nil || !strings.Contains(err.Error(), "multi-factor") {
		t.Fatalf("database accepted an executive decision without MFA: %v", err)
	}
	stale := f.cfo
	stale.AuthTime = time.Now().Add(-time.Hour)
	if _, err := f.svc.DecideWorkflow(f.ctx, stale, w.ID, true, ""); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("executive step without fresh MFA: %v", err)
	}
	r, err := f.svc.DecideWorkflow(f.ctx, f.cfo, w.ID, true, "")
	if err != nil || r.StepCompleted || r.Approvals != 1 || r.Needed != 2 {
		t.Fatalf("first executive: %+v %v", r, err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.cfo, w.ID, true, ""); !errors.Is(err, ErrWorkflowState) {
		t.Fatalf("same executive counted twice: %v", err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, ""); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("poster decided before the executive quorum: %v", err)
	}
	if r, err = f.svc.DecideWorkflow(f.ctx, a.cfo2, w.ID, true, ""); err != nil || !r.StepCompleted {
		t.Fatalf("second executive: %+v %v", r, err)
	}
	// Neither executive may post (step:executive exclusion) — and the
	// database computes the same exclusion independently.
	cfoPoster := auth.Principal{Kind: auth.KindHuman, UserID: a.cfo2.UserID, TenantID: f.tenant, Roles: []string{"controller"}}
	if _, err := f.svc.DecideWorkflow(f.ctx, cfoPoster, w.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("executive posted: %v", err)
	}
	err = f.rawAs(cfoPoster, "workflow.decide", "workflow_instance", w.ID, "2:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,2,'post',$3,'APPROVE')`,
		f.tenant, w.ID, a.cfo2.UserID)
	if err == nil || !strings.Contains(err.Error(), "segregation of duties") {
		t.Fatalf("database accepted an excluded decision: %v", err)
	}
	if r, err = f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, ""); err != nil || r.Instance.Status != "COMPLETED" {
		t.Fatalf("post: %+v %v", r, err)
	}
	if st := f.journalStatus(t, jid); st != "POSTED" {
		t.Fatalf("journal %s", st)
	}
}

// The database refuses a forged approval trail written directly by the
// application role (compromised application code).
func TestWorkflow_DatabaseRefusesForgedTrail(t *testing.T) {
	f := newFixture(t)
	def := f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-forge")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	prepApprover := auth.Principal{Kind: auth.KindHuman, UserID: f.prep.UserID, TenantID: f.tenant, Roles: []string{"accountant", "finance_manager"}}
	attacks := map[string]struct {
		sql  string
		args []any
		want string
	}{
		"effect before quorum": {`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by)
			VALUES ($1::uuid,$2::uuid,0,'journal.approve','journal',$3::uuid,'u-approver')`, []any{f.tenant, w.ID, jid}, "quorum"},
		"skip a step":               {`UPDATE workflow_instances SET current_step=1 WHERE id=$1::uuid`, []any{w.ID}, "quorum"},
		"complete without steps":    {`UPDATE workflow_instances SET status='COMPLETED', current_step=2 WHERE id=$1::uuid`, []any{w.ID}, "one step at a time"},
		"rewrite the route":         {`UPDATE workflow_instances SET route='[{"id":"post","permission":"journal.post","approvals":1,"effect":"journal.post"}]' WHERE id=$1::uuid`, []any{w.ID}, "privilege"},
		"push the deadline":         {`UPDATE workflow_instances SET expires_at=now()+interval '10 years' WHERE id=$1::uuid`, []any{w.ID}, "privilege"},
		"escalate early":            {`UPDATE workflow_instances SET escalated_at=now() WHERE id=$1::uuid`, []any{w.ID}, "after its SLA"},
		"expire early":              {`UPDATE workflow_instances SET status='EXPIRED' WHERE id=$1::uuid`, []any{w.ID}, "after its deadline"},
		"reject without a decision": {`UPDATE workflow_instances SET status='REJECTED' WHERE id=$1::uuid`, []any{w.ID}, "REJECT decision"},
		"decide a later step": {`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,1,'post','u-poster','APPROVE')`,
			[]any{f.tenant, w.ID}, "open step"},
		"preparer approves": {`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'review',$3,'APPROVE')`,
			[]any{f.tenant, w.ID, f.prep.UserID}, "segregation of duties"},
		"edit a published definition": {`UPDATE workflow_definitions SET body = body || '{"mandatory": false}' WHERE id=$1::uuid`, []any{def.ID}, "privilege"},
		"delete history":              {`DELETE FROM workflow_history WHERE instance_id=$1::uuid`, []any{w.ID}, "privilege"},
	}
	// Decision attacks run with a genuine attestation so that they reach the
	// deeper guards (open step, segregation of duties).
	attested := map[string]struct {
		p    auth.Principal
		actx string
	}{"decide a later step": {f.post, "1:APPROVE"}, "preparer approves": {prepApprover, "0:APPROVE"},
		// 0010 binds an effect to its executor's verified decision; with that
		// evidence present the quorum guard is still what refuses it.
		"effect before quorum": {f.appr, "0:APPROVE"}}
	for name, a := range attacks {
		var err error
		if as, ok := attested[name]; ok {
			err = f.rawAs(as.p, "workflow.decide", "workflow_instance", w.ID, as.actx, a.sql, a.args...)
		} else {
			err = f.rawExec(a.sql, a.args...)
		}
		if err == nil || !strings.Contains(err.Error(), a.want) {
			t.Errorf("%s: %v (want %q)", name, err, a.want)
		}
	}
	// A genuine approval in one transaction cannot be reused to approve the
	// journal in another: the gate requires the effect in the SAME transaction.
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	j2 := f.draftJournal(t, f.balanced(key("wf-forge-2")))
	err = f.rawAs(f.appr, "journal.approve", "journal", j2, "", `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, j2)
	if err == nil || !strings.Contains(err.Error(), "mandatory approval workflow") {
		t.Fatalf("approval without its own effect: %v", err)
	}
	// Even the schema owner cannot retire a published definition directly or
	// insert a self-published one.
	if _, err := f.admin.Exec(f.ctx, `UPDATE workflow_definitions SET status='RETIRED' WHERE id=$1::uuid`, def.ID); err == nil {
		t.Fatal("schema owner retired a published definition directly")
	}
	_, err = f.admin.Exec(f.ctx, `INSERT INTO workflow_definitions(tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by,status,decided_by)
		SELECT tenant_id,key,99,subject,mandatory,body,body_hash,proposed_by,'PUBLISHED',proposed_by FROM workflow_definitions WHERE id=$1::uuid`, def.ID)
	if err == nil {
		t.Fatal("self-published definition inserted")
	}
}

func TestWorkflow_RejectionRunsCompensationAsTheRejector(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-reject")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, false, ""); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("reject without reason: %v", err)
	}
	r, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, false, "supplier invoice not attached")
	if err != nil || r.Instance.Status != "REJECTED" || r.EffectExecuted != "journal.cancel" {
		t.Fatalf("reject: %+v %v", r, err)
	}
	if st := f.journalStatus(t, jid); st != "CANCELLED" {
		t.Fatalf("journal %s after rejection", st)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, ""); !errors.Is(err, ErrWorkflowState) {
		t.Fatalf("decision on a rejected workflow: %v", err)
	}
}

// An effect the kernel refuses rolls the decision back, is counted on the
// instance and stays visible in the console until it can succeed.
func TestWorkflow_EffectFailureRollsBackAndIsRecorded(t *testing.T) {
	f := newFixture(t)
	f.publish(t, periodCloseDef)
	a := f.wfActors()
	per := f.period(t)
	// An approved-but-unposted journal blocks the close (database prerequisite).
	jid := f.draftJournal(t, f.balanced(key("wf-close-blocker")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("direct close under a mandatory workflow: %v", err)
	}
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "period.close", per)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, ""); err == nil || !strings.Contains(err.Error(), "awaiting posting") {
		t.Fatalf("close with an unposted journal: %v", err)
	}
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if d.Instance.EffectFailures != 1 || d.Instance.Status != "ACTIVE" || len(d.Decisions) != 0 || historyKinds(d) != "STARTED,EFFECT_FAILED" {
		t.Fatalf("after failed effect: failures=%d status=%s decisions=%d history=%s", d.Instance.EffectFailures, d.Instance.Status, len(d.Decisions), historyKinds(d))
	}
	tasks, _ := f.svc.ListWorkflowTasks(f.ctx, f.post)
	if len(tasks) != 1 || tasks[0].FailedTries != 1 || !strings.Contains(tasks[0].LastError, "awaiting posting") {
		t.Fatalf("console task %+v", tasks)
	}
	if err := f.svc.PostJournal(f.ctx, a.ctrl2, jid); err != nil {
		t.Fatal(err)
	}
	r, err := f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, "")
	if err != nil || r.Instance.Status != "COMPLETED" {
		t.Fatalf("retry close: %+v %v", r, err)
	}
	if st := f.periodStatus(t, per); st != "CLOSED" {
		t.Fatalf("period %s", st)
	}
	// Reopening (CFO, MFA, reason) does not leave a reusable approval behind:
	// the earlier close effect belongs to an earlier transaction, so neither
	// the direct path nor a raw update can close the period again.
	if err := f.svc.ReopenPeriod(f.ctx, f.cfo, per, "late supplier invoice to accrue"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("direct re-close: %v", err)
	}
	err = f.rawAs(f.post, "period.close", "fiscal_period", per, "CLOSED", `UPDATE fiscal_periods SET status='CLOSED', closed_by=$2 WHERE id=$1::uuid`, per, f.post.UserID)
	if err == nil || !strings.Contains(err.Error(), "mandatory approval workflow") {
		t.Fatalf("raw re-close reusing an old effect: %v", err)
	}
	w2, err := f.svc.StartWorkflow(f.ctx, f.prep, "period.close", per)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, w2.ID, true, ""); err != nil {
		t.Fatalf("re-close through a new workflow: %v", err)
	}
	// Locking a closed period is not workflow-gated.
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, true); err != nil {
		t.Fatalf("lock closed period: %v", err)
	}
}

func TestWorkflow_SubjectChangedAfterStartIsRefused(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-change")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.addBalancedLines(jid); err != nil { // lines slipped in after routing
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); !errors.Is(err, ErrSubjectChanged) {
		t.Fatalf("decision on a changed subject: %v", err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal %s", st)
	}
	// Generic check, defense in depth: every routed subject is otherwise
	// immutable in the database, so simulate drift by changing a period
	// boundary with triggers bypassed (operator/replication path).
	f.publish(t, periodCloseDef)
	per := f.period(t)
	pw, err := f.svc.StartWorkflow(f.ctx, f.prep, "period.close", per)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(f.ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = f.super.Exec(f.ctx, `UPDATE fiscal_periods SET ends_on = ends_on + 1 WHERE id=$1::uuid`, per)
	f.super.Exec(f.ctx, `SET session_replication_role = origin`) //nolint:errcheck
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, pw.ID, true, ""); !errors.Is(err, ErrSubjectChanged) {
		t.Fatalf("close after the period changed: %v", err)
	}
}

// Timers are durable (state in the database; a fresh service instance —
// a restarted worker — picks them up), idempotent, and never authorize.
func TestWorkflow_TimersEscalateOnceAndExpire(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-timer")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(f.app, auth.NewAuthorizer(nil, true))
	// The scheduler login learns which tenants have due work — and nothing else.
	sched, err := pgx.Connect(f.ctx, f.db.LoginRole(t, "serk_scheduler"))
	if err != nil {
		t.Fatal(err)
	}
	defer sched.Close(f.ctx)
	// Other tests' tenants may also have due work in a shared test database;
	// this test drives only its own tenant through the scheduler's list.
	lister := func(ctx context.Context) ([]string, error) {
		due, err := postgres.DueWorkflowTenants(ctx, sched, 10000)
		if err != nil || !slices.Contains(due, f.tenant) {
			return nil, err
		}
		return []string{f.tenant}, nil
	}
	if _, err := sched.Exec(f.ctx, `SELECT count(*) FROM workflow_instances`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("scheduler login read workflow instances: %v", err)
	}
	if res, err := restarted.RunDueWorkflowTimers(f.ctx, lister); err != nil || res != (TimerResult{}) {
		t.Fatalf("nothing due yet: %+v %v", res, err)
	}
	f.backdate(t, w.ID, "sla_due_at")
	if due, err := postgres.DueWorkflowTenants(f.ctx, sched, 10000); err != nil || !slices.Contains(due, f.tenant) {
		t.Fatalf("due tenants %v %v", due, err)
	}
	if res, err := restarted.RunDueWorkflowTimers(f.ctx, lister); err != nil || res.Escalated != 1 {
		t.Fatalf("escalation: %+v %v", res, err)
	}
	if res, _ := restarted.RunWorkflowTimers(f.ctx, f.tenant, 0); res.Escalated != 0 {
		t.Fatal("escalated twice")
	}
	tasks, _ := f.svc.ListWorkflowTasks(f.ctx, f.appr)
	if len(tasks) != 1 || !tasks[0].Escalated || !tasks[0].Overdue {
		t.Fatalf("overdue task %+v", tasks)
	}
	f.backdate(t, w.ID, "expires_at")
	if res, err := restarted.RunWorkflowTimers(f.ctx, f.tenant, 0); err != nil || res.Expired != 1 {
		t.Fatalf("expiry: %+v %v", res, err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("expiry changed the subject: %s", st)
	}
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if d.Instance.Status != "EXPIRED" || historyKinds(d) != "STARTED,ESCALATED,EXPIRED" {
		t.Fatalf("expired instance %s %s", d.Instance.Status, historyKinds(d))
	}
	for _, h := range d.History[1:] {
		if h.Actor != SystemTimerActor {
			t.Fatalf("timer event by %s", h.Actor)
		}
	}
	// The subject is released for a new workflow.
	if _, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid); err != nil {
		t.Fatalf("restart after expiry: %v", err)
	}
	m, err := f.svc.WorkflowMetrics(f.ctx, f.cfo, time.Now().Add(-time.Hour))
	if err != nil || m.Started != 2 || m.Expired != 1 || m.Active != 1 || m.Escalated != 1 || m.ExceptionRate == nil || *m.ExceptionRate != 0.5 {
		t.Fatalf("metrics %+v %v", m, err)
	}
}

func TestWorkflow_DefinitionGovernance(t *testing.T) {
	f := newFixture(t)
	a := f.wfActors()
	if _, err := f.svc.ProposeWorkflowDefinition(f.ctx, f.cfo, []byte(journalPostingDef)); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("publisher proposed: %v", err)
	}
	unsafe := strings.Replace(journalPostingDef, `"permission": "journal.post",`, `"permission": "journal.create",`, 1)
	if _, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(unsafe)); !errors.Is(err, workflow.ErrInvalid) {
		t.Fatalf("unsafe definition proposed: %v", err)
	}
	v1, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(journalPostingDef))
	if err != nil {
		t.Fatal(err)
	}
	noMFA := f.cfo
	noMFA.MFA = false
	if err := f.svc.DecideWorkflowDefinition(f.ctx, noMFA, v1.ID, true, ""); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("publish without MFA: %v", err)
	}
	selfPublisher := auth.Principal{Kind: auth.KindHuman, UserID: a.owner.UserID, TenantID: f.tenant, Roles: []string{"process_owner", "cfo"}, MFA: true, AuthTime: time.Now()}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, selfPublisher, v1.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("author published own definition: %v", err)
	}

	// Dry run of the draft against a real subject creates nothing.
	jid := f.draftJournal(t, f.bigJournal(key("wf-sim")))
	sim, err := f.svc.SimulateWorkflow(f.ctx, f.appr, v1.ID, jid)
	if err != nil || len(sim) != 3 || sim[1].Approvals != 2 {
		t.Fatalf("simulation %+v %v", sim, err)
	}
	if list, _ := f.svc.ListWorkflowInstances(f.ctx, f.cfo, postgres.InstanceFilter{}); len(list) != 0 {
		t.Fatal("simulation created an instance")
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, v1.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	w1, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	// v2 lowers nothing silently: it is a new reviewed version, and the
	// running instance keeps the route frozen at its start.
	v2body := strings.Replace(journalPostingDef, `"amount_gte": "1000000.00"`, `"amount_gte": "5000000.00"`, 1)
	v2, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(v2body))
	if err != nil || v2.Version != 2 {
		t.Fatalf("v2 %+v %v", v2, err)
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, v2.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	defs, _ := f.svc.ListWorkflowDefinitions(f.ctx, f.cfo)
	status := map[int]string{}
	for _, d := range defs {
		status[d.Version] = d.Status
	}
	if status[1] != "RETIRED" || status[2] != "PUBLISHED" {
		t.Fatalf("versions %+v", status)
	}
	// An instance of the superseded version can no longer act (it might be
	// weaker than the version now in force): cancel and restart under v2,
	// whose route is computed afresh.
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w1.ID, true, ""); !errors.Is(err, ErrWorkflowState) {
		t.Fatalf("superseded instance acted: %v", err)
	}
	if err := f.svc.CancelWorkflow(f.ctx, a.admin, w1.ID, "definition superseded by v2"); err != nil {
		t.Fatal(err)
	}
	w2, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil || w2.DefinitionVersion != 2 || len(w2.Route) != 2 {
		t.Fatalf("restart under v2: %+v %v", w2, err)
	}
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w1.ID)
	if d.Instance.DefinitionVersion != 1 || len(d.Instance.Route) != 3 || d.Instance.Status != "CANCELLED" {
		t.Fatalf("history of the superseded instance changed: v%d %s", d.Instance.DefinitionVersion, d.Instance.Status)
	}
	// A second mandatory definition for the same subject is refused.
	other := strings.Replace(journalPostingDef, `"key": "journal.posting"`, `"key": "journal.posting_alt"`, 1)
	alt, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(other))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, alt.ID, true, ""); err == nil {
		t.Fatal("two mandatory workflows for one subject")
	}
}

// Two people racing to complete the same step: exactly one effect runs.
func TestWorkflow_ConcurrentDecisionsExecuteTheEffectOnce(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	a := f.wfActors()
	jid := f.draftJournal(t, f.balanced(key("wf-race")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, p := range []auth.Principal{f.post, a.ctrl2} {
		wg.Add(1)
		go func(i int, p auth.Principal) {
			defer wg.Done()
			_, errs[i] = f.svc.DecideWorkflow(f.ctx, p, w.ID, true, "")
		}(i, p)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrWorkflowState) {
			t.Fatalf("loser error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d winners (%v)", ok, errs)
	}
	var effects int
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM workflow_effects WHERE instance_id=$1::uuid AND action='journal.post'`, w.ID).Scan(&effects)
	})
	if effects != 1 || f.journalStatus(t, jid) != "POSTED" {
		t.Fatalf("effects %d status %s", effects, f.journalStatus(t, jid))
	}
}

// Workflow data is tenant-isolated like everything else.
func TestWorkflow_TenantIsolation(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("wf-iso")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetWorkflowInstance(f.ctx, f.outsider, w.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider read instance: %v", err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.outsider, w.ID, true, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outsider decided: %v", err)
	}
	// The other tenant has no mandatory workflow: its direct path is open.
	if tasks, _ := f.svc.ListWorkflowTasks(f.ctx, f.outsider); len(tasks) != 0 {
		t.Fatalf("outsider sees tasks %+v", tasks)
	}
}

const fxRateDef = `{
  "key": "fx.rate", "title": "FX rate approval", "subject": "fx_snapshot", "mandatory": true,
  "start_permission": "fx.manage",
  "steps": [
    {"id": "check", "title": "Independent rate check", "permission": "fx.approve",
     "distinct_from": ["initiator", "subject.creator"], "effect": "fx.approve"}
  ],
  "on_reject": "fx.reject"
}`

// The workflow cannot widen what the approver may do: an out-of-tolerance
// rate still needs fx.approve_exception + fresh MFA + a reason from the
// person deciding, exactly as on the direct path.
func TestWorkflow_FXApprovalKeepsVarianceControls(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{})
	f.snapshot(t, "USD", "ETB", "57.25", day(10, 7), true)
	f.publish(t, fxRateDef)
	jump := f.snapshot(t, "USD", "ETB", "62.98", day(10, 8), false)
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.cfo, jump, "devaluation"); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("direct FX approval under a mandatory workflow: %v", err)
	}
	w, err := f.svc.StartWorkflow(f.ctx, f.treasury, "fx.rate", jump)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, "looks right"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("ordinary checker approved an out-of-tolerance rate via workflow: %v", err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.cfo, w.ID, true, ""); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("exception without reason via workflow: %v", err)
	}
	r, err := f.svc.DecideWorkflow(f.ctx, f.cfo, w.ID, true, "NBE devaluation notice 2026/10")
	if err != nil || r.Instance.Status != "COMPLETED" || r.EffectExecuted != "fx.approve" {
		t.Fatalf("CFO exception approval: %+v %v", r, err)
	}
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if d.Instance.EffectFailures != 2 {
		t.Fatalf("refused effects not counted: %d", d.Instance.EffectFailures)
	}
	var exc bool
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT variance_exception FROM fx_snapshots WHERE snapshot_id=$1::uuid`, jump).Scan(&exc)
	})
	if !exc {
		t.Fatal("variance exception not recorded on the rate")
	}
	// Rejection runs fx.reject as the rejecting checker.
	r2 := f.snapshot(t, "USD", "ETB", "57.30", day(10, 9), false)
	w2, err := f.svc.StartWorkflow(f.ctx, f.treasury, "fx.rate", r2)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := f.svc.DecideWorkflow(f.ctx, f.appr, w2.ID, false, "typo in source document"); err != nil || res.EffectExecuted != "fx.reject" {
		t.Fatalf("reject: %+v %v", res, err)
	}
}
