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

// Regression tests for the independent review of the workflow engine
// (2026-10-21, findings R1–R9). Each reproduced an exploit against commit
// e2c19a5; each must now be refused.

const strictDef = `{
  "key": "journal.strict", "title": "Strict", "subject": "journal", "mandatory": true,
  "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "r", "permission": "journal.approve", "approvals": 2,
     "distinct_from": ["initiator", "subject.creator"], "effect": "journal.approve"},
    {"id": "exec", "title": "e", "permission": "approval.high_value", "approvals": 2, "require_mfa": true,
     "distinct_from": ["initiator", "subject.creator", "step:review"]},
    {"id": "post", "title": "p", "permission": "journal.post",
     "distinct_from": ["initiator", "subject.creator", "step:review", "step:exec"], "effect": "journal.post"}
  ],
  "on_reject": "journal.cancel"
}`

const lenientDef = `{
  "key": "journal.fasttrack", "title": "Fast track", "subject": "journal", "mandatory": false,
  "start_permission": "journal.create",
  "steps": [
    {"id": "aa", "title": "a", "permission": "journal.approve", "distinct_from": ["subject.creator"], "effect": "journal.approve"},
    {"id": "pp", "title": "p", "permission": "journal.post", "distinct_from": ["subject.creator", "step:aa"], "effect": "journal.post"}
  ]
}`

// R1: an optional definition must not satisfy (or bypass) a mandatory one —
// neither through the API nor by using an instance started earlier.
func TestReview_R1_OptionalDefinitionCannotBypassMandatory(t *testing.T) {
	f := newFixture(t)
	f.publish(t, lenientDef)
	jid := f.draftJournal(t, f.balanced(key("r1")))
	early, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.fasttrack", jid) // started before the mandatory one exists
	if err != nil {
		t.Fatal(err)
	}
	f.publish(t, strictDef)
	j2 := f.draftJournal(t, f.balanced(key("r1b")))
	if _, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.fasttrack", j2); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("optional workflow started under a mandatory one: %v", err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, early.ID, true, ""); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("pre-existing optional instance acted under a mandatory one: %v", err)
	}
	// And in SQL: an effect row from the optional instance cannot be written.
	err = f.rawAs(f.appr, "workflow.decide", "workflow_instance", early.ID, "0:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'aa','u-approver','APPROVE')`, f.tenant, early.ID)
	if err == nil || !strings.Contains(err.Error(), "mandatory workflow governs") {
		t.Fatalf("database accepted a decision on a non-governing instance: %v", err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal %s", st)
	}
}

// R2: application code cannot start an instance whose route or facts differ
// from the definition and the subject.
func TestReview_R2_ForgedRouteOrFactsRefused(t *testing.T) {
	f := newFixture(t)
	def := f.publish(t, strictDef)
	jid := f.draftJournal(t, f.balanced(key("r2")))
	ins := func(facts, route string) error {
		// A correctly attested initiator: route and facts are still checked.
		return f.rawAs(f.prep, "workflow.start", "journal", jid, def.ID, `INSERT INTO workflow_instances(tenant_id,definition_id,subject_type,subject_id,facts,route,initiated_by)
			VALUES ($1::uuid,$2::uuid,'journal',$3::uuid,$4::jsonb,$5::jsonb,'u-preparer')`, f.tenant, def.ID, jid, facts, route)
	}
	goodFacts := `{"amount":"115000.00","currency":"ETB","project_id":"` + f.project + `","created_by":"u-preparer","fingerprint":"x"}`
	weakRoute := `[{"id":"review","permission":"journal.approve","approvals":1,"distinct_from":[],"effect":"journal.approve"},
	              {"id":"post","permission":"journal.post","approvals":1,"distinct_from":[],"effect":"journal.post"}]`
	if err := ins(goodFacts, weakRoute); err == nil || !strings.Contains(err.Error(), "does not match definition") {
		t.Fatalf("weakened route accepted: %v", err)
	}
	forgedFacts := strings.Replace(goodFacts, `"created_by":"u-preparer"`, `"created_by":"nobody"`, 1)
	if err := ins(forgedFacts, weakRoute); err == nil || !strings.Contains(err.Error(), "facts do not match") {
		t.Fatalf("forged facts accepted: %v", err)
	}
	smallAmount := strings.Replace(goodFacts, `"115000.00"`, `"1.00"`, 1)
	if err := ins(smallAmount, weakRoute); err == nil || !strings.Contains(err.Error(), "facts do not match") {
		t.Fatalf("understated amount accepted: %v", err)
	}
	// The genuine route (as the kernel computes it) is accepted.
	if _, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.strict", jid); err != nil {
		t.Fatalf("genuine start refused: %v", err)
	}
}

// R3: a published definition cannot be retired by a direct UPDATE.
func TestReview_R3_DirectRetirementRefused(t *testing.T) {
	f := newFixture(t)
	def := f.publish(t, strictDef)
	err := f.rawExec(`UPDATE workflow_definitions SET status='RETIRED' WHERE id=$1::uuid`, def.ID)
	if err == nil || !strings.Contains(err.Error(), "permission denied") { // no UPDATE privilege at all since RV-6
		t.Fatalf("direct retirement: %v", err)
	}
	if _, err := f.admin.Exec(f.ctx, `UPDATE workflow_definitions SET status='RETIRED' WHERE id=$1::uuid`, def.ID); err == nil {
		t.Fatal("schema owner retired a published definition directly")
	}
	jid := f.draftJournal(t, f.balanced(key("r3")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); !errors.Is(err, ErrWorkflowRequired) {
		t.Fatalf("direct approve: %v", err)
	}
}

// R4: rejection at the post step, expiry or cancellation must not strand an
// APPROVED journal: it can be cancelled by the rejecting controller, or
// routed again from where it stands — keeping the earlier approver excluded.
func TestReview_R4_ApprovedJournalIsNeverStranded(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	f.publish(t, periodCloseDef)
	a := f.wfActors()

	// (a) the controller rejects at the post step: compensation cancels.
	jid := f.draftJournal(t, f.balanced(key("r4a")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	r, err := f.svc.DecideWorkflow(f.ctx, f.post, w.ID, false, "wrong cost centre, redo")
	if err != nil || r.EffectExecuted != "journal.cancel" || f.journalStatus(t, jid) != "CANCELLED" {
		t.Fatalf("reject at post: %+v %v %s", r, err, f.journalStatus(t, jid))
	}

	// (b) cancelled after review: the APPROVED journal is routed again from
	// the step after approval, and the earlier approver stays excluded.
	j2 := f.draftJournal(t, f.bigJournal(key("r4b")))
	w2, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", j2)
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w2.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelWorkflow(f.ctx, a.admin, w2.ID, "approver on leave, reroute"); err != nil {
		t.Fatal(err)
	}
	w3, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", j2)
	if err != nil || len(w3.Route) != 2 || w3.Route[0].ID != "executive" || w3.Route[1].ID != "post" {
		t.Fatalf("resume of an approved journal: %+v %v", w3.Route, err)
	}
	both := auth.Principal{UserID: f.appr.UserID, TenantID: f.tenant, Roles: []string{"cfo"}, MFA: true, AuthTime: time.Now()}
	if _, err := f.svc.DecideWorkflow(f.ctx, both, w3.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("earlier approver signed off after resume: %v", err)
	}
	for _, p := range []auth.Principal{f.cfo, a.cfo2, f.post} {
		if _, err := f.svc.DecideWorkflow(f.ctx, p, w3.ID, true, ""); err != nil {
			t.Fatalf("%s: %v", p.UserID, err)
		}
	}
	if st := f.journalStatus(t, j2); st != "POSTED" {
		t.Fatalf("resumed journal %s", st)
	}
	// Nothing approved-but-unposted remains: the period can close.
	pw, err := f.svc.StartWorkflow(f.ctx, f.prep, "period.close", f.period(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, pw.ID, true, ""); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// R5: an expired step cannot be decided even if the timer has not run yet.
func TestReview_R5_ExpiredStepCannotBeDecided(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("r5")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	f.backdate(t, w.ID, "expires_at")
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); !errors.Is(err, ErrWorkflowState) {
		t.Fatalf("decision after expiry: %v", err)
	}
	err := f.rawAs(f.appr, "workflow.decide", "workflow_instance", w.ID, "0:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'review','u-approver','APPROVE')`, f.tenant, w.ID)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("database accepted a decision after expiry: %v", err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal %s", st)
	}
}

// R6: an instance of a superseded (weaker) version cannot act.
func TestReview_R6_SupersededVersionCannotAct(t *testing.T) {
	f := newFixture(t)
	a := f.wfActors()
	f.publish(t, journalPostingDef) // v1: one reviewer
	jid := f.draftJournal(t, f.balanced(key("r6")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	tight := strings.Replace(strictDef, `"key": "journal.strict"`, `"key": "journal.posting"`, 1)
	d2, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(tight))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, d2.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); !errors.Is(err, ErrWorkflowState) {
		t.Fatalf("v1 instance acted after v2: %v", err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal %s", st)
	}
}

// R7: a quorum cannot include the maker — such definitions are refused.
func TestReview_R7_QuorumMustExcludeMaker(t *testing.T) {
	f := newFixture(t)
	a := f.wfActors()
	weak := `{
  "key": "journal.q", "title": "Q", "subject": "journal", "mandatory": true, "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "r", "permission": "journal.approve", "approvals": 2, "effect": "journal.approve"},
    {"id": "post", "title": "p", "permission": "journal.post", "effect": "journal.post"}
  ]}`
	if _, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(weak)); err == nil || !strings.Contains(err.Error(), `must list "subject.creator"`) {
		t.Fatalf("maker-inclusive quorum accepted: %v", err)
	}
}

// R8: a raw approval racing a mandatory version switch is still gated.
func TestReview_R8_GateHoldsDuringVersionSwitch(t *testing.T) {
	f := newFixture(t)
	a := f.wfActors()
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("r8")))
	v2body := strings.Replace(journalPostingDef, `"amount_gte": "1000000.00"`, `"amount_gte": "2000000.00"`, 1)
	v2, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(v2body))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := f.app.BeginTenant(f.ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.authorizeIn(f.ctx, pub, f.cfo, "workflow.decide_definition", "workflow_definition", v2.ID, "PUBLISHED"); err != nil {
		_ = pub.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err := postgres.DecideWorkflowDefinition(f.ctx, pub, v2.ID, "PUBLISHED", f.cfo.UserID, ""); err != nil {
		_ = pub.Rollback(f.ctx)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- f.rawAs(f.appr, "journal.approve", "journal", jid, "",
			`UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
	}()
	select {
	case err := <-done:
		_ = pub.Rollback(f.ctx)
		t.Fatalf("raw approve did not wait for the publish: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err := pub.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "mandatory approval workflow") {
		t.Fatalf("raw approve racing the publish: %v", err)
	}
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal %s", st)
	}
}

// R9: finished instances are fully immutable; end details only with the end.
func TestReview_R9_FinishedInstanceIsImmutable(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	a := f.wfActors()
	jid := f.draftJournal(t, f.balanced(key("r9")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err := f.rawExec(`UPDATE workflow_instances SET ended_by='someone', end_reason='pre-filled reason' WHERE id=$1::uuid`, w.ID); err == nil {
		t.Fatal("end details written on an ACTIVE instance")
	}
	if err := f.svc.CancelWorkflow(f.ctx, a.admin, w.ID, "duplicate submission"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE workflow_instances SET ended_by='someone-else', end_reason='rewritten later' WHERE id=$1::uuid`,
		`UPDATE workflow_instances SET last_error='x' WHERE id=$1::uuid`,
		`UPDATE workflow_instances SET effect_failures=effect_failures+1 WHERE id=$1::uuid`,
	} {
		if err := f.rawExec(stmt, w.ID); err == nil || !strings.Contains(err.Error(), "final") {
			t.Errorf("%s: %v", stmt, err)
		}
	}
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if d.Instance.EndedBy != a.admin.UserID || d.Instance.EndReason != "duplicate submission" {
		t.Fatalf("end details rewritten: %s %s", d.Instance.EndedBy, d.Instance.EndReason)
	}
}

// R11: console error text carries no SQLSTATE or identifiers; scoped users
// cannot probe instances or subjects outside their projects.
func TestReview_R11_ConsoleLeaksNothing(t *testing.T) {
	f := newFixture(t)
	f.publish(t, periodCloseDef)
	per := f.period(t)
	jid := f.draftJournal(t, f.balanced(key("r11")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); err != nil {
		t.Fatal(err)
	}
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "period.close", per)
	_, _ = f.svc.DecideWorkflow(f.ctx, f.post, w.ID, true, "")
	d, _ := f.svc.GetWorkflowInstance(f.ctx, f.cfo, w.ID)
	if d.Instance.LastError == "" || strings.Contains(d.Instance.LastError, "SQLSTATE") || uuidPattern.MatchString(d.Instance.LastError) {
		t.Fatalf("console error %q", d.Instance.LastError)
	}
	scoped := auth.Principal{UserID: "u-scoped", TenantID: f.tenant, Roles: []string{"controller"}, ProjectIDs: []string{"00000000-0000-0000-0000-000000000001"}}
	if _, err := f.svc.DecideWorkflow(f.ctx, scoped, w.ID, true, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope decision: %v", err)
	}
	var def string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT definition_id::text FROM workflow_instances WHERE id=$1::uuid`, w.ID).Scan(&def)
	})
	reader := auth.Principal{UserID: "u-reader", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{"00000000-0000-0000-0000-000000000001"}}
	if _, err := f.svc.SimulateWorkflow(f.ctx, reader, def, per); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope simulation: %v", err)
	}
}
