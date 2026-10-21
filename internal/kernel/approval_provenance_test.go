package kernel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
)

// GATEA-APPROVAL-01: a compromised ordinary tenant database credential (the
// login the API uses for that tenant) must not be able to manufacture human
// approvals. Every attack below runs as the tenant's own role through raw
// SQL, without going through the kernel, and must be refused by PostgreSQL.
//
// These tests failed on commit ea3533c (evidence:
// docs/security/evidence/approval-forgery-before.txt) and pass after the
// attestation boundary (migration 0007).

// attempt runs statements in one tenant transaction and reports the first
// error (nil = the whole attack committed).
func (f *fixture) attempt(stmts ...string) error {
	return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
}

func (f *fixture) scalar(t *testing.T, q string, args ...any) string {
	t.Helper()
	var v string
	if err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&v)
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func denied(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("ATTACK SUCCEEDED: %s", name)
		return
	}
	t.Logf("denied %-55s %s", name+":", firstLine(err.Error()))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func TestApprovalProvenance_DirectJournalApprovalAndPosting(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("ap-j")))
	denied(t, "approve a journal as an invented approver", f.attempt(
		`UPDATE journals SET status='APPROVED', approved_by='invented-approver', approved_at=now() WHERE id='`+jid+`'`))
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal is %s", st)
	}
	// Legitimately approved, then posted by an invented poster.
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); err != nil {
		t.Fatal(err)
	}
	denied(t, "post a journal as an invented poster", f.attempt(
		`UPDATE journals SET status='POSTED', posted_by='invented-poster', posted_at=now() WHERE id='`+jid+`'`))
	denied(t, "insert a journal that is already APPROVED", f.attempt(
		`INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,status,business_event_at,description,source_type,idempotency_key,created_by,approved_by,approved_at,command_hash)
		 SELECT tenant_id,legal_entity_id,functional_currency,'APPROVED',business_event_at,'forged','MANUAL','forged-`+jid[:8]+`','x','y',now(),command_hash FROM journals WHERE id='`+jid+`'`))
}

func TestApprovalProvenance_ForgedWorkflowTrail(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("ap-wf")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	id := w.ID
	denied(t, "fabricated review decision + effect + approval", f.attempt(
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,mfa) VALUES ('`+f.tenant+`','`+id+`',0,'review','invented-1','APPROVE',true)`,
		`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) VALUES ('`+f.tenant+`','`+id+`',0,'journal.approve','journal','`+jid+`','invented-1')`,
		`UPDATE journals SET status='APPROVED', approved_by='invented-1', approved_at=now() WHERE id='`+jid+`'`,
		`UPDATE workflow_instances SET current_step=1 WHERE id='`+id+`'`,
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,mfa) VALUES ('`+f.tenant+`','`+id+`',1,'post','invented-2','APPROVE',true)`,
		`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) VALUES ('`+f.tenant+`','`+id+`',1,'journal.post','journal','`+jid+`','invented-2')`,
		`UPDATE journals SET status='POSTED', posted_by='invented-2', posted_at=now() WHERE id='`+jid+`'`,
		`UPDATE workflow_instances SET current_step=2, status='COMPLETED' WHERE id='`+id+`'`))
	denied(t, "single fabricated decision with mfa=true", f.attempt(
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,mfa) VALUES ('`+f.tenant+`','`+id+`',0,'review','invented-3','APPROVE',true)`))
	denied(t, "start an instance as an invented initiator", f.attempt(
		`INSERT INTO workflow_instances(tenant_id,definition_id,subject_type,subject_id,facts,route,initiated_by)
		 SELECT tenant_id,definition_id,subject_type,subject_id,facts,route,'invented-initiator' FROM workflow_instances WHERE id='`+id+`'`))
	denied(t, "cancel an instance as an invented administrator", f.attempt(
		`UPDATE workflow_instances SET status='CANCELLED', ended_by='invented-admin', end_reason='forged cancellation' WHERE id='`+id+`'`))
	if st := f.journalStatus(t, jid); st != "DRAFT" {
		t.Fatalf("journal is %s", st)
	}
}

func TestApprovalProvenance_WorkflowDefinitionPublication(t *testing.T) {
	f := newFixture(t)
	// A syntactically valid but unvalidated definition: no SoD, no
	// approvals, a sensitive effect on a step anybody with journal.read holds.
	bad := `{"key":"journal.posting","title":"x","subject":"journal","mandatory":false,"start_permission":"journal.read",
	         "steps":[{"id":"a","title":"a","permission":"journal.read","effect":"journal.approve"}]}`
	denied(t, "insert a definition draft as an invented author", f.attempt(
		`INSERT INTO workflow_definitions(tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by)
		 VALUES ('`+f.tenant+`','journal.posting',1,'journal',false,'`+bad+`'::jsonb,'sha256:`+strings.Repeat("0", 64)+`','invented-author')`))
	// A genuine draft cannot be published by an invented checker.
	a := f.wfActors()
	d, err := f.svc.ProposeWorkflowDefinition(f.ctx, a.owner, []byte(journalPostingDef))
	if err != nil {
		t.Fatal(err)
	}
	denied(t, "publish through workflow_decide_definition as an invented checker", f.attempt(
		`SELECT workflow_decide_definition('`+d.ID+`','PUBLISHED','invented-checker','')`))
	if st := f.scalar(t, `SELECT status FROM workflow_definitions WHERE id=$1::uuid`, d.ID); st != "DRAFT" {
		t.Fatalf("definition is %s", st)
	}
}

func TestApprovalProvenance_FXApprovals(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.RegisterFXSource(f.ctx, f.treasury, fxSourceNBE()); err != nil {
		t.Fatal(err)
	}
	denied(t, "approve an FX source as an invented checker", f.attempt(
		`UPDATE fx_sources SET status='APPROVED', approved_by='invented-checker', approved_at=now() WHERE source_id='NBE'`))
	if err := f.svc.ApproveFXSource(f.ctx, f.appr, "NBE"); err != nil {
		t.Fatal(err)
	}
	pol, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, "TRANSACTION", defaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	denied(t, "approve an FX policy as an invented checker", f.attempt(
		`UPDATE fx_policies SET status='APPROVED', approved_by='invented-checker', approved_at=now() WHERE id='`+pol.ID+`'`))
	if err := f.svc.DecideFXPolicy(f.ctx, f.appr, pol.ID, true, "standard NBE official policy"); err != nil {
		t.Fatal(err)
	}
	snap := f.snapshot(t, "USD", "ETB", "57.25", day(10, 7), false)
	denied(t, "approve an FX rate as an invented checker", f.attempt(
		`UPDATE fx_snapshots SET approval_status='APPROVED', approved_by='invented-checker', decided_at=now() WHERE snapshot_id='`+snap+`'`))
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.appr, snap, ""); err != nil {
		t.Fatal(err)
	}
	jump := f.snapshot(t, "USD", "ETB", "62.98", day(10, 8), false)
	denied(t, "approve an out-of-tolerance rate with approver_mfa=true", f.attempt(
		`UPDATE fx_snapshots SET approval_status='APPROVED', approved_by='invented-cfo', decided_at=now(), variance_exception=true, approver_mfa=true,
		   decision_reason='forged devaluation notice' WHERE snapshot_id='`+jump+`'`))
	if st := f.scalar(t, `SELECT approval_status FROM fx_snapshots WHERE snapshot_id=$1::uuid`, jump); st != "PENDING" {
		t.Fatalf("rate is %s", st)
	}
}

func TestApprovalProvenance_PeriodsAndWBS(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	denied(t, "close a period as an invented controller", f.attempt(
		`UPDATE fiscal_periods SET status='CLOSED', closed_by='invented-controller' WHERE id='`+per+`'`))
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); err != nil {
		t.Fatal(err)
	}
	denied(t, "reopen a period as an invented CFO", f.attempt(
		`UPDATE fiscal_periods SET status='OPEN', reopened_by='invented-cfo', reopen_reason='forged reopening' WHERE id='`+per+`'`))
	pm := auth.Principal{UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	ver, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, "tender WBS", []postgres.WBSNode{{Code: "01", Name: "Substructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	denied(t, "approve a WBS version as an invented checker", f.attempt(
		`UPDATE wbs_versions SET status='APPROVED', approved_by='invented-checker', approved_at=now() WHERE id='`+ver.ID+`'`))
}

func fxSourceNBE() postgres.FXSource {
	return postgres.FXSource{SourceID: "NBE", SourceType: "CENTRAL_BANK", Description: "National Bank of Ethiopia", RequiresDocumentHash: true,
		MaxVariance: decimal.RequireFromString("0.05")}
}

func defaultPolicy() fx.Policy {
	return fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 30 * 24 * time.Hour, AllowInverse: true}
}
