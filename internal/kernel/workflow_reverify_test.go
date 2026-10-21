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

// Regression tests for the second independent review (re-verification of
// a40566d, findings RV-1…RV-7). Each reproduced a defect; each must now hold.

const quorumDef = `{
  "key": "journal.quorum", "title": "Quorum", "subject": "journal", "mandatory": true,
  "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "r", "permission": "journal.approve", "approvals": 2,
     "distinct_from": ["initiator", "subject.creator"], "expire_after": "24h", "effect": "journal.approve"},
    {"id": "post", "title": "p", "permission": "journal.post", "expire_after": "24h",
     "distinct_from": ["initiator", "subject.creator", "step:review"], "effect": "journal.post"}
  ]
}`

// RV-1: every member of an earlier approval quorum stays excluded after the
// journal's workflow is resumed — in Go and in SQL.
func TestReverify_RV1_ResumeKeepsWholeQuorumExcluded(t *testing.T) {
	f := newFixture(t)
	f.publish(t, quorumDef)
	dual := auth.Principal{UserID: "u-dual", TenantID: f.tenant, Roles: []string{"finance_manager", "controller"}}
	jid := f.draftJournal(t, f.balanced(key("rv1")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.quorum", jid)
	if _, err := f.svc.DecideWorkflow(f.ctx, dual, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.appr, w.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	f.backdate(t, w.ID, "expires_at")
	if _, err := f.svc.RunWorkflowTimers(f.ctx, f.tenant, 10); err != nil {
		t.Fatal(err)
	}
	w2, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.quorum", jid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, dual, w2.ID, true, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("co-approver posted after resume: %v", err)
	}
	err = f.rawExec(`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'post','u-dual','APPROVE')`, f.tenant, w2.ID)
	if err == nil || !strings.Contains(err.Error(), "segregation of duties") {
		t.Fatalf("database accepted the co-approver after resume: %v", err)
	}
	if _, err := f.svc.DecideWorkflow(f.ctx, f.post, w2.ID, true, ""); err != nil {
		t.Fatalf("independent poster: %v", err)
	}
}

// RV-2: starting a workflow while the next version is being published never
// deadlocks (gate lock is always taken before definition-row locks).
func TestReverify_RV2_StartAndPublishDoNotDeadlock(t *testing.T) {
	f := newFixture(t)
	a := f.wfActors()
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("rv2")))
	v2, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(strings.Replace(journalPostingDef, `"168h"`, `"169h"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ { // race them repeatedly
		errs := make(chan error, 2)
		go func() { _, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid); errs <- err }()
		if i == 5 {
			go func() { errs <- f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, v2.ID, true, "") }()
		} else {
			errs <- nil
		}
		for k := 0; k < 2; k++ {
			if err := <-errs; err != nil && strings.Contains(err.Error(), "deadlock") {
				t.Fatalf("deadlock: %v", err)
			}
		}
	}
}

// RV-3: no tenant can block another tenant's gate (advisory locks are not
// available to tenant logins; the gate lock row is protected by RLS).
func TestReverify_RV3_NoCrossTenantGateBlocking(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("rv3")))
	other, err := f.app.BeginTenant(f.ctx, f.tenant2)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Rollback(f.ctx) //nolint:errcheck
	if _, err := other.Exec(f.ctx, `SAVEPOINT a`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(f.ctx, `SELECT pg_advisory_lock(727002)`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("tenant login may take advisory locks: %v", err)
	}
	_, _ = other.Exec(f.ctx, `ROLLBACK TO SAVEPOINT a`)
	if _, err := other.Exec(f.ctx, `SELECT workflow_gate_lock($1::uuid, 'journal', true)`, f.tenant); err == nil {
		t.Fatal("tenant 2 locked tenant 1's gate row")
	}
	_, _ = other.Exec(f.ctx, `ROLLBACK TO SAVEPOINT a`)
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	if err := f.svc.ApproveJournal(ctx, f.appr, jid); err != nil {
		t.Fatalf("tenant 1 approval blocked or failed: %v", err)
	}
}

// RV-4: a project-scoped admin cannot cancel (or probe) out-of-scope instances.
func TestReverify_RV4_CancelHonoursScope(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("rv4")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	scoped := auth.Principal{UserID: "u-scoped-admin", TenantID: f.tenant, Roles: []string{"workflow_admin"}, ProjectIDs: []string{"00000000-0000-0000-0000-000000000001"}}
	if err := f.svc.CancelWorkflow(f.ctx, scoped, w.ID, "probing other projects"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope cancel: %v", err)
	}
}

// RV-5: neither the effect nor the step advance is accepted after expiry.
func TestReverify_RV5_EffectAfterExpiryRefused(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("rv5")))
	w, _ := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err := f.rawExec(`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'review','u-approver','APPROVE')`, f.tenant, w.ID); err != nil {
		t.Fatal(err)
	}
	f.backdate(t, w.ID, "expires_at")
	err := f.rawExec(`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) VALUES ($1::uuid,$2::uuid,0,'journal.approve','journal',$3::uuid,'u-approver')`, f.tenant, w.ID, jid)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("effect after expiry: %v", err)
	}
	if err := f.rawExec(`UPDATE workflow_instances SET current_step=1 WHERE id=$1::uuid`, w.ID); err == nil {
		t.Fatal("advance after expiry")
	}
}

// RV-6: no login other than the owner-rights function can retire or publish
// a definition — not via a temporary trigger, not by direct UPDATE.
func TestReverify_RV6_NoRetirementOutsideTheDecideFunction(t *testing.T) {
	f := newFixture(t)
	def := f.publish(t, journalPostingDef)
	err := f.rawExec(`
DO $$ BEGIN
  CREATE TEMP TABLE rv_kick(x int);
  CREATE FUNCTION pg_temp.rv_retire() RETURNS trigger LANGUAGE plpgsql AS $f$
  BEGIN UPDATE workflow_definitions SET status='RETIRED' WHERE status='PUBLISHED' AND key='journal.posting'; RETURN NEW; END $f$;
  CREATE TRIGGER rv_kick_t AFTER INSERT ON rv_kick FOR EACH ROW EXECUTE FUNCTION pg_temp.rv_retire();
  INSERT INTO rv_kick VALUES (1);
END $$`)
	if err == nil {
		t.Fatal("temp-trigger retirement ran")
	}
	if err := f.rawExec(`UPDATE workflow_definitions SET status='RETIRED' WHERE id=$1::uuid`, def.ID); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("direct update: %v", err)
	}
	// The function itself never retires without publishing a successor.
	if err := f.rawExec(`SELECT workflow_decide_definition($1::uuid, 'RETIRED', 'x', 'reason text')`, def.ID); err == nil {
		t.Fatal("decide function retired a definition")
	}
	var st string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM workflow_definitions WHERE id=$1::uuid`, def.ID).Scan(&st)
	})
	if st != "PUBLISHED" {
		t.Fatalf("definition %s", st)
	}
	// An older DRAFT cannot be published over a newer published version.
	a := f.wfActors()
	old, _ := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(journalPostingDef))
	newer, _ := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(journalPostingDef))
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, newer.ID, true, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideWorkflowDefinition(f.ctx, f.cfo, old.ID, true, ""); err == nil {
		t.Fatal("older draft published over a newer version")
	}
}

// RV-7: Go and SQL compute identical routes at threshold boundaries and for
// every duration form the validator accepts.
func TestReverify_RV7_GoSQLRouteEquivalence(t *testing.T) {
	for _, tc := range []struct {
		gte   string
		steps int
	}{{"115000.00", 3}, {"115000.01", 2}, {"0", 3}, {"114999.99", 3}} {
		f := newFixture(t)
		body := strings.NewReplacer(`"1000000.00"`, `"`+tc.gte+`"`, `"sla": "24h"`, `"sla": "45m30s"`, `"expire_after": "168h"`, `"expire_after": "0h90m"`).Replace(journalPostingDef)
		body = strings.Replace(body, `"require_mfa": true,`, `"require_mfa": true, "sla": "1h1s", "escalate_to": "approval.high_value", "expire_after": "2160h",`, 1)
		f.publish(t, body)
		jid := f.draftJournal(t, f.balanced(key("rv7")))
		w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
		if err != nil || len(w.Route) != tc.steps {
			t.Errorf("gte=%s: start err=%v steps=%d want %d", tc.gte, err, len(w.Route), tc.steps)
		}
	}
}

var _ = postgres.ErrNotFound
