package kernel

// Re-verification probes for migration 0010, written by the second
// independent reviewer (2026-10-21) and kept verbatim as regression tests.
// Each probe asserts the SECURE behaviour: "OPEN:" lines are gaps, "held:"
// lines are controls that resisted. On 32a220e: 7 OPEN (evidence:
// docs/security/evidence/independent-reverify-before.txt); 0012 closes them.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func rv(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("OPEN: %s", name)
		return
	}
	t.Logf("held: %s: %s", name, firstLine(err.Error()))
}

func (f *fixture) wbsDraft(t *testing.T, desc string) string {
	t.Helper()
	pm := auth.Principal{UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	v, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, desc, []postgres.WBSNode{{Code: "01", Name: "Substructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}

// Q1: fx_snapshots authority columns across the APPROVED->DISPUTED and
// PENDING->REJECTED transitions.
func TestIndependentReverify_Q1_FXSnapshotAuthorityOnTransition(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, defaultPolicy())
	snap := f.snapshot(t, "USD", "ETB", "120.50", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), true)
	t.Logf("before: %s", f.scalar(t, `SELECT format('approved_by=%s rejected_by=%s decided_at=%s mfa=%s exc=%s', approved_by, COALESCE(rejected_by,'NULL'), decided_at, approver_mfa, variance_exception) FROM fx_snapshots WHERE snapshot_id=$1::uuid`, snap))
	rv(t, "withdraw (genuine fx.snapshot.withdraw attestation) rewrites approved_by/rejected_by/decided_at/approver_mfa/variance_exception",
		f.rawAs(f.appr, "fx.snapshot.withdraw", "fx_snapshot", snap, "",
			`UPDATE fx_snapshots SET approval_status='DISPUTED', decision_reason='withdrawn by probe', approved_by='u-forged-approver',
			        rejected_by='u-forged-rejecter', decided_at='2001-01-01', approver_mfa=true, variance_exception=true WHERE snapshot_id=$1::uuid`, snap))
	t.Logf("after: %s", f.scalar(t, `SELECT format('status=%s approved_by=%s rejected_by=%s decided_at=%s mfa=%s exc=%s', approval_status, approved_by, COALESCE(rejected_by,'NULL'), decided_at, approver_mfa, variance_exception) FROM fx_snapshots WHERE snapshot_id=$1::uuid`, snap))

	snap2 := f.snapshot(t, "USD", "ETB", "121.00", time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), false)
	rv(t, "reject (genuine attestation) also sets approver_mfa=true/variance_exception=true on a REJECTED snapshot",
		f.rawAs(f.appr, "fx.snapshot.reject", "fx_snapshot", snap2, "",
			`UPDATE fx_snapshots SET approval_status='REJECTED', rejected_by='u-approver', decision_reason='rejected by probe', decided_at=now(),
			        approver_mfa=true, variance_exception=true WHERE snapshot_id=$1::uuid`, snap2))
	t.Logf("after reject: %s", f.scalar(t, `SELECT format('status=%s mfa=%s exc=%s', approval_status, approver_mfa, variance_exception) FROM fx_snapshots WHERE snapshot_id=$1::uuid`, snap2))
}

// Q1: workflow_instances end details on derived transitions.
func TestIndependentReverify_Q1_WorkflowInstanceEndedBy(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("rv2-wi")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	rv(t, "tenant login sets ended_by on an ACTIVE instance without ending it",
		f.rawExec(`UPDATE workflow_instances SET ended_by='u-forged' WHERE id=$1::uuid`, w.ID))
	rv(t, "tenant login cancels with an invented ended_by",
		f.rawExec(`UPDATE workflow_instances SET status='CANCELLED', ended_by='u-wf-admin', end_reason='forged cancel' WHERE id=$1::uuid`, w.ID))
}

// Q2: direct calls of approval_use forge consumption markers that other
// checks read (fiscal_period_close_record; journals REVERSED).
func TestIndependentReverify_Q2_Q3_ForgedConsumptionMarker(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	unrelated := f.draftJournal(t, f.balanced(key("rv2-unrel")))
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", unrelated, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT approval_use('journal.approve','journal',$1,NULL,ARRAY['journal.approve'],false,NULL,'fiscal_period:'||$2||':CLOSED')`, unrelated, per); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, f.post, "period.close", "fiscal_period", per, "CLOSED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='CLOSED', closed_by='u-poster' WHERE id=$1::uuid`, per)
		return err
	})
	t.Logf("close with pre-forged marker: err=%v", err)
	// (Adjusted after 0012: when the attack is refused no close record exists,
	// so the lookup must tolerate zero rows.)
	rec := f.scalar(t, `SELECT COALESCE((SELECT format('close actor=%s linked attestation: action=%s actor=%s subject=%s:%s', c.actor, a.action, a.actor, a.subject_type, a.subject_id)
		FROM fiscal_period_closes c JOIN approval_attestations a ON a.nonce=c.attestation WHERE c.period_id=$1::uuid ORDER BY c.id DESC LIMIT 1), 'no close record')`, per)
	t.Logf("close record: %s", rec)
	if err == nil && !strings.Contains(rec, "action=period.close") {
		t.Errorf("OPEN: close record linked to unrelated evidence via a forged consumption marker (%s)", rec)
	}

	// Close record writer cannot be reached at trigger depth 0 and the
	// tenant cannot create code that would run inside a trigger.
	rv(t, "direct call of fiscal_period_close_record (depth 0)",
		f.rawExec(`SELECT fiscal_period_close_record($1::uuid,'LOCKED','LOCK','u-cfo','x')`, per))
	rv(t, "tenant creates a function", f.rawExec(`CREATE FUNCTION public.zz_evil() RETURNS int LANGUAGE sql AS 'select 1'`))
	rv(t, "tenant creates a temp table", f.rawExec(`CREATE TEMP TABLE zz_t(x int)`))
	rv(t, "tenant disables a trigger", f.rawExec(`ALTER TABLE wbs_versions DISABLE TRIGGER wbs_versions_successor_check`))
	rv(t, "tenant inserts approval_consumptions directly", f.rawExec(`INSERT INTO approval_consumptions(nonce,tenant_id,txid,used_for) SELECT nonce,tenant_id,txid_current(),'x' FROM approval_attestations LIMIT 1`))
}

// Q2: journals REVERSED via a forged 'journal:<R>:POSTED' marker in a later
// transaction than the reversal's posting.
func TestIndependentReverify_Q2_ReversedViaForgedMarker(t *testing.T) {
	f := newFixture(t)
	j := f.lifecycle(t, f.balanced(key("rv2-orig")))
	res, err := f.svc.ReverseJournal(f.ctx, f.post, j, key("rv2-rev"), "probe reversal", time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	r := res.JournalID
	if err := f.svc.ApproveJournal(f.ctx, f.appr, r); err != nil {
		t.Fatal(err)
	}
	// Post R with a genuine posting attestation but without marking J (raw).
	if err := f.rawAs(f.post, "journal.post", "journal", r, "", `UPDATE journals SET status='POSTED', posted_by='u-poster' WHERE id=$1::uuid`, r); err != nil {
		t.Logf("raw post of reversal refused: %v (probe not applicable)", err)
		return
	}
	t.Logf("after tx1: J=%s R=%s", f.journalStatus(t, j), f.journalStatus(t, r))
	other := f.draftJournal(t, f.balanced(key("rv2-other")))
	rv(t, "J marked REVERSED in a later tx with a forged consumption marker (unrelated evidence)",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", other, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT approval_use('journal.approve','journal',$1,NULL,ARRAY['journal.approve'],false,NULL,'journal:'||$2||':POSTED')`, other, r); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE journals SET status='REVERSED', reversed_by=$2::uuid WHERE id=$1::uuid`, j, r)
			return err
		}))
	t.Logf("final: J=%s", f.journalStatus(t, j))
}

// Q2: single use across savepoints; live hash re-check for wbs_version.
func TestIndependentReverify_Q2_SavepointsAndLiveHash(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("rv2-sp")))
	cnt := ""
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", jid, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SAVEPOINT a`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by='u-approver' WHERE id=$1::uuid`, jid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT a`); err != nil {
			return err
		}
		// Second use after RELEASE: the consumption must survive the release.
		_, err := tx.Exec(ctx, `SELECT approval_use('journal.approve','journal',$1,'u-approver',ARRAY['journal.approve'],false,NULL,'again')`, jid)
		_ = tx.QueryRow(ctx, `SELECT count(*)::text FROM approval_consumptions WHERE txid=txid_current()`).Scan(&cnt)
		return err
	})
	rv(t, "evidence consumed inside a released savepoint is reused", err)

	// Rolled-back savepoint: evidence becomes usable again, but only the one
	// surviving transition happens.
	jid2 := f.draftJournal(t, f.balanced(key("rv2-sp2")))
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", jid2, ""); err != nil {
			return err
		}
		for _, s := range []string{`SAVEPOINT a`, `UPDATE journals SET status='APPROVED', approved_by='u-approver' WHERE id='` + jid2 + `'`, `ROLLBACK TO SAVEPOINT a`,
			`UPDATE journals SET status='APPROVED', approved_by='u-approver' WHERE id='` + jid2 + `'`} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT count(*)::text FROM approval_consumptions WHERE txid=txid_current()`).Scan(&cnt)
	})
	t.Logf("rollback-to-savepoint then reuse: err=%v consumptions=%s status=%s (expected: one effective approval)", err, cnt, f.journalStatus(t, jid2))

	// WBS: add a node after attestation, then approve.
	v := f.wbsDraft(t, "toctou WBS")
	rv(t, "wbs.decide APPROVED evidence still valid after a node was added in the same tx",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "wbs.decide", "wbs_version", v, "APPROVED"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO wbs_nodes(tenant_id,project_id,version_id,code,name) VALUES ($1::uuid,$3::uuid,$2::uuid,'99','Injected')`, f.tenant, v, f.project); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE wbs_versions SET status='APPROVED', approved_by='u-approver' WHERE id=$1::uuid`, v)
			return err
		}))

	// Cross-tenant: tenant 2 can neither see nor consume tenant 1 evidence.
	var seen string
	_ = f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*)::text FROM approval_consumptions`).Scan(&seen)
	})
	t.Logf("tenant2 sees %s approval_consumptions rows", seen)
}

// Q4: deferred successor checks.
func TestIndependentReverify_Q4_DeferredSuccessorChecks(t *testing.T) {
	f := newFixture(t)
	v1 := f.wbsDraft(t, "tender WBS")
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v1, true, "approved for tender"); err != nil {
		t.Fatal(err)
	}
	v2 := f.wbsDraft(t, "variation WBS")
	rv(t, "supersede v1, approve v2 inside a savepoint, roll the savepoint back, commit",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "wbs.decide", "wbs_version", v2, "APPROVED"); err != nil {
				return err
			}
			for _, s := range []string{
				`UPDATE wbs_versions SET status='SUPERSEDED' WHERE id='` + v1 + `'`,
				`SAVEPOINT s`,
				`UPDATE wbs_versions SET status='APPROVED', approved_by='u-approver' WHERE id='` + v2 + `'`,
				`ROLLBACK TO SAVEPOINT s`,
				`SET CONSTRAINTS wbs_versions_successor_check DEFERRED`,
			} {
				if _, err := tx.Exec(ctx, s); err != nil {
					return err
				}
			}
			return nil
		}))
	rv(t, "SET CONSTRAINTS ALL IMMEDIATE then supersede without approved successor",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "wbs.decide", "wbs_version", v2, "APPROVED"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE wbs_versions SET status='SUPERSEDED' WHERE id=$1::uuid`, v1)
			return err
		}))
	t.Logf("approved WBS versions: %s", f.scalar(t, `SELECT string_agg(id::text||'='||status, ',') FROM wbs_versions WHERE project_id=$1::uuid`, f.project))

	// FX policy: retire p1, approve p2 then attempt to undo p2 in the same tx.
	p1 := f.setupFX(t, defaultPolicy())
	p2, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, defaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	rv(t, "retire p1 + approve p2 + REJECT p2 in the same tx",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "fx.policy.decide", "fx_policy", p2.ID, "APPROVED"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE fx_policies SET status='RETIRED' WHERE id=$1::uuid`, p1); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE fx_policies SET status='APPROVED', approved_by='u-approver' WHERE id=$1::uuid`, p2.ID); err != nil {
				return err
			}
			if err := f.authorizeIn(ctx, tx, f.appr, "fx.policy.decide", "fx_policy", p2.ID, "REJECTED"); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE fx_policies SET status='REJECTED' WHERE id=$1::uuid`, p2.ID)
			return err
		}))
	t.Logf("policies: %s", f.scalar(t, `SELECT string_agg(version||'='||status, ',' ORDER BY version) FROM fx_policies WHERE legal_entity_id=$1::uuid AND purpose='TRANSACTION'`, f.entity))
}

// Q5: workflow history binding.
func TestIndependentReverify_Q5_WorkflowHistoryBinding(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("rv2-hist")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	rv(t, "COMPLETED history entry by an invented 'system:' actor, no evidence",
		f.rawExec(`INSERT INTO workflow_history(tenant_id,instance_id,kind,actor,step_index,detail) VALUES ($1::uuid,$2::uuid,'COMPLETED','system:kernel',2,'{"note":"forged"}')`, f.tenant, w.ID))
	rv(t, "DECIDED history entry for u-cfo with no evidence, actor spelled 'system:u-cfo'",
		f.rawExec(`INSERT INTO workflow_history(tenant_id,instance_id,kind,actor,step_index,detail) VALUES ($1::uuid,$2::uuid,'DECIDED','system:u-cfo',0,'{"decision":"APPROVE"}')`, f.tenant, w.ID))
	other := f.draftJournal(t, f.balanced(key("rv2-hist-other")))
	rv(t, "DECIDED history entry for u-approver on instance W using u-approver's evidence for an unrelated journal",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", other, ""); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO workflow_history(tenant_id,instance_id,kind,actor,step_index,detail) VALUES ($1::uuid,$2::uuid,'DECIDED','u-approver',0,'{"decision":"APPROVE"}')`, f.tenant, w.ID)
			return err
		}))
	t.Logf("history of W: %s", f.scalar(t, `SELECT string_agg(kind||'/'||actor, ', ' ORDER BY id) FROM workflow_history WHERE instance_id=$1::uuid`, w.ID))
}

// Q2/M2: body_hash column vs the attested SQL digest.
func TestIndependentReverify_Q2_DefinitionBodyHashColumn(t *testing.T) {
	f := newFixture(t)
	owner := f.wfActors().owner
	body := `{"key":"evil.def","subject":"journal","mandatory":false,"steps":[]}`
	rv(t, "definition inserted with the attested body but an arbitrary body_hash",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			d, err := postgres.WorkflowBodyDigest(ctx, tx, []byte(body))
			if err != nil {
				return err
			}
			if err := f.authorizeIn(ctx, tx, owner, "workflow.define", "workflow_definition_body", d, "evil.def"); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO workflow_definitions(tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by)
				VALUES ($1::uuid,'evil.def',7,'journal',false,$2::jsonb,'sha256:`+strings.Repeat("0", 64)+`',$3)`, f.tenant, body, owner.UserID)
			return err
		}))
	t.Logf("stored: %s", f.scalar(t, `SELECT COALESCE(string_agg(format('v%s body_hash=%s digest=%s', version, left(body_hash,15), left(workflow_body_digest(body),15)), ';'),'none') FROM workflow_definitions WHERE key='evil.def'`))
}

// Q6: numeric encodings of a signed attestation (fresh attestation per try).
func TestIndependentReverify_Q6_CanonicalNumberForms(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("rv2-num")))
	try := func(name string, mut func(raw string) string) {
		a := f.sign(t, f.tenant, attest.Claims{Actor: "u-approver", Action: "journal.approve", SubjectType: "journal", SubjectID: jid,
			SubjectHash: f.subjectHash(t, "journal", jid), Perms: []string{"journal.approve"}}, time.Now())
		raw := mut(a.JSON())
		var stored string
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := postgres.Authorize(ctx, tx, raw); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT format('ctx=%L perms=%s auth_time=%s', ctx, perms::text, COALESCE(auth_time::text,'NULL')) FROM approval_attestations WHERE nonce=$1::uuid`, a.Nonce).Scan(&stored)
		})
		t.Logf("%s: err=%v stored=%s", name, err, stored)
	}
	_ = json.Valid
	try("v as 1.0", func(r string) string { return strings.Replace(r, `"v":1,`, `"v":1.0,`, 1) })
	try("v as 1e0", func(r string) string { return strings.Replace(r, `"v":1,`, `"v":1e0,`, 1) })
	try("auth_time as -0", func(r string) string { return strings.Replace(r, `"auth_time":0,`, `"auth_time":-0,`, 1) })
	try("duplicate ctx key with a different first value", func(r string) string { return strings.Replace(r, `"ctx":""`, `"ctx":"CLOSED","ctx":""`, 1) })
	try("perms duplicated element", func(r string) string {
		return strings.Replace(r, `"perms":["journal.approve"]`, `"perms":["journal.approve","journal.approve"]`, 1)
	})
	try("unicode escape in actor", func(r string) string {
		return strings.Replace(r, `"actor":"u-approver"`, `"actor":"\u0075-approver"`, 1)
	})
}

// Q1: CLOSED -> LOCKED by a second person rewrites closed_by (by design?).
func TestIndependentReverify_Q1_LockRewritesClosedBy(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); err != nil {
		t.Fatal(err)
	}
	other := auth.Principal{UserID: "u-controller-2", TenantID: f.tenant, Roles: []string{"controller"}}
	_, err := f.svc.ClosePeriod(f.ctx, other, per, true)
	t.Logf("lock by second person: err=%v; period: %s; records: %s", err,
		f.scalar(t, `SELECT status||' closed_by='||closed_by FROM fiscal_periods WHERE id=$1::uuid`, per),
		f.scalar(t, `SELECT string_agg(action||'/'||actor, ', ' ORDER BY id) FROM fiscal_period_closes WHERE period_id=$1::uuid`, per))
}

// Q3/Q7: close, reopen, close again in ONE transaction (two consumptions with
// the same used_for 'fiscal_period:P:CLOSED').
func TestIndependentReverify_Q3_CloseReopenCloseOneTx(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, f.post, "period.close", "fiscal_period", per, "CLOSED"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='CLOSED', closed_by='u-poster' WHERE id=$1::uuid`, per); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, f.cfo, "period.reopen", "fiscal_period", per, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='OPEN', reopened_by='u-cfo', reopen_reason='late invoice received' WHERE id=$1::uuid`, per); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, f.post, "period.close", "fiscal_period", per, "CLOSED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='CLOSED', closed_by='u-poster' WHERE id=$1::uuid`, per)
		return err
	})
	t.Logf("close/reopen/close in one tx: err=%v", err)
}
