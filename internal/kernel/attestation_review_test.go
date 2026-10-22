package kernel

// Independent review of GATEA-APPROVAL-01 (2026-10-21). These probes were
// written by the independent reviewer; each asserts the SECURE behaviour. On
// commit b314922 they failed (9 x "GAP CONFIRMED", evidence in
// docs/security/evidence/independent-review-before.txt); migration 0010
// closes them. Kept verbatim as regression tests, plus targeted tests for the
// controls 0010 introduced.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func gap(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("GAP CONFIRMED: %s", name)
		return
	}
	t.Logf("covered: %s: %s", name, firstLine(err.Error()))
}

// Q1: authority columns rewritten by the tenant login alone, without any
// status change and without any attestation.
func TestIndependentReview_Q1_AuthorityColumnsWithoutStatusChange(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); err != nil {
		t.Fatal(err)
	}
	gap(t, "tenant login rewrites closed_by/closed_at of a CLOSED period",
		f.rawExec(`UPDATE fiscal_periods SET closed_by='u-someone-else', closed_at='2020-01-01' WHERE id=$1::uuid`, per))
	t.Logf("closed_by now: %s", f.scalar(t, `SELECT COALESCE(closed_by,'<null>') FROM fiscal_periods WHERE id=$1::uuid`, per))

	// Consequence: the closer can now reopen their own close (DB SoD check
	// compares against the rewritten closed_by). Signed as the API would for
	// a person who holds both period.close and period.reopen with fresh MFA.
	now := time.Now()
	c := attest.Claims{Actor: "u-poster", Action: "period.reopen", SubjectType: "fiscal_period", SubjectID: per,
		SubjectHash: f.subjectHash(t, "fiscal_period", per), Perms: []string{"period.close", "period.reopen"}, MFA: true, AuthTime: now.Unix()}
	a := f.sign(t, f.tenant, c, now)
	gap(t, "closer reopens own close after closed_by was rewritten (SoD bypass)",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := postgres.Authorize(ctx, tx, a.JSON()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='OPEN', reopened_by='u-poster', reopen_reason='self reopen after rewrite' WHERE id=$1::uuid`, per)
			return err
		}))

	gap(t, "tenant login inserts a forged fiscal_period_closes record (actor u-cfo, REOPEN)",
		f.rawExec(`INSERT INTO fiscal_period_closes(tenant_id,legal_entity_id,period_id,action,actor,reason,journal_count,tb_debits,tb_credits,tb_hash)
		           VALUES ($1::uuid,$2::uuid,$3::uuid,'REOPEN','u-cfo','forged evidence',0,0,0,'x')`, f.tenant, f.entity, per))

	// WBS: approver identity of an APPROVED version.
	pm := auth.Principal{Kind: auth.KindHuman, UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	v1, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, "tender WBS", []postgres.WBSNode{{Code: "01", Name: "Substructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v1.ID, true, "approved for tender"); err != nil {
		t.Fatal(err)
	}
	gap(t, "tenant login rewrites approved_by/approved_at of an APPROVED WBS version",
		f.rawExec(`UPDATE wbs_versions SET approved_by='u-forged-checker', approved_at='2020-01-01' WHERE id=$1::uuid`, v1.ID))
	t.Logf("wbs approved_by now: %s", f.scalar(t, `SELECT approved_by FROM wbs_versions WHERE id=$1::uuid`, v1.ID))

	// Journal: posting record of an APPROVED (not yet posted) journal.
	jid := f.draftJournal(t, f.balanced(key("rv-q1")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, jid); err != nil {
		t.Fatal(err)
	}
	gap(t, "tenant login writes posted_by/posted_at on an APPROVED journal (no status change)",
		f.rawExec(`UPDATE journals SET posted_by='u-forged-poster', posted_at='2020-01-01' WHERE id=$1::uuid`, jid))
}

// Q2: evidence registered once is matched by (tx, action, subject, actor)
// only; the subject hash is checked at registration, not at use.
func TestIndependentReview_Q2_InTransactionBinding(t *testing.T) {
	f := newFixture(t)

	// Content changed AFTER approval_authorize, inside the same transaction.
	jid := f.draftJournal(t, f.balanced(key("rv-toctou")))
	gap(t, "journal.approve evidence still valid after lines were added in the same tx",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", jid, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency) VALUES
				($1::uuid,$2::uuid,$3::uuid,98,$4::uuid,'DEBIT',777,'ETB'),($1::uuid,$2::uuid,$3::uuid,99,$5::uuid,'CREDIT',777,'ETB')`,
				jid, f.tenant, f.entity, f.accounts["5000"], f.accounts["1000"]); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
			return err
		}))
	t.Logf("journal status %s, lines %s", f.journalStatus(t, jid), f.scalar(t, `SELECT count(*)::text FROM journal_lines WHERE journal_id=$1::uuid`, jid))

	// WBS: a decision on v2 (here: a REJECT) is accepted as the successor
	// approval that supersedes v1.
	pm := auth.Principal{Kind: auth.KindHuman, UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	mk := func(desc string) string {
		v, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, desc, []postgres.WBSNode{{Code: "01", Name: "Substructure"}},
			[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
		if err != nil {
			t.Fatal(err)
		}
		return v.ID
	}
	v1 := mk("tender WBS")
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v1, true, "approved for tender"); err != nil {
		t.Fatal(err)
	}
	v2 := mk("variation WBS")
	gap(t, "WBS v1 SUPERSEDED while successor v2 is REJECTED (same wbs.decide evidence)",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "wbs.decide", "wbs_version", v2, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE wbs_versions SET status='SUPERSEDED' WHERE id=$1::uuid`, v1); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE wbs_versions SET status='REJECTED' WHERE id=$1::uuid`, v2)
			return err
		}))
	t.Logf("approved WBS versions for project: %s", f.scalar(t, `SELECT count(*)::text FROM wbs_versions WHERE project_id=$1::uuid AND status='APPROVED'`, f.project))

	// FX policy: same pattern.
	p1 := f.setupFX(t, defaultPolicy())
	p2, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, defaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	gap(t, "FX policy v1 RETIRED while successor v2 is REJECTED (same fx.policy.decide evidence)",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "fx.policy.decide", "fx_policy", p2.ID, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE fx_policies SET status='RETIRED' WHERE id=$1::uuid`, p1); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE fx_policies SET status='REJECTED' WHERE id=$1::uuid`, p2.ID)
			return err
		}))
	t.Logf("approved TRANSACTION policies for entity: %s", f.scalar(t, `SELECT count(*)::text FROM fx_policies WHERE legal_entity_id=$1::uuid AND purpose='TRANSACTION' AND status='APPROVED'`, f.entity))

	// Workflow definition: one workflow.define evidence (over a body hash)
	// admits several rows whose bodies are not that body.
	owner := f.wfActors().owner
	h := "sha256:" + strings.Repeat("ab", 32)
	gap(t, "one workflow.define evidence inserts two definitions whose body does not hash to body_hash",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, owner, "workflow.define", "workflow_definition_body", h, "evil.one"); err != nil {
				return err
			}
			for _, k := range []string{"evil.one", "evil.two"} {
				if _, err := tx.Exec(ctx, `INSERT INTO workflow_definitions(tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by)
					VALUES ($1::uuid,$2,1,'journal',true,jsonb_build_object('key',$2::text,'subject','journal','mandatory',true,'steps','[]'::jsonb),$3,$4)`,
					f.tenant, k, h, owner.UserID); err != nil {
					return err
				}
			}
			return nil
		}))
}

// Q3: the SQL verifier accepts a second parse of a signed canonical string
// (U+001F inside a field + a missing field dropped by concat_ws).
func TestIndependentReview_Q3_CanonicalAmbiguity(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("rv-canon")))
	a := f.sign(t, f.tenant, attest.Claims{Actor: "u-approver", Action: "journal.approve", SubjectType: "journal", SubjectID: jid,
		SubjectHash: f.subjectHash(t, "journal", jid), Perms: []string{"journal.approve"}}, time.Now())
	var m map[string]any
	if err := json.Unmarshal([]byte(a.JSON()), &m); err != nil {
		t.Fatal(err)
	}
	m["ctx"] = "\x1fjournal.approve"
	m["perms"] = []string{"0"}
	delete(m, "auth_time")
	alt, _ := json.Marshal(m)
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return postgres.Authorize(ctx, tx, string(alt))
	})
	if err == nil {
		row := f.scalar(t, `SELECT format('ctx=%L perms=%s auth_time=%s', ctx, perms::text, COALESCE(auth_time::text,'NULL')) FROM approval_attestations WHERE nonce=$1::uuid`, a.Nonce)
		t.Errorf("GAP CONFIRMED: re-parsed attestation accepted with the original signature; evidence row: %q", row)
	} else {
		t.Logf("covered: %s", firstLine(err.Error()))
	}
}

// Q5: expiry is compared with the transaction start time.
func TestIndependentReview_Q5_ExpiryUsesTransactionStart(t *testing.T) {
	f := newFixture(t)
	jid := f.draftJournal(t, f.balanced(key("rv-clock")))
	issued := time.Now().Add(-117 * time.Second) // default TTL 2 min: exp = now+3s
	a := f.sign(t, f.tenant, attest.Claims{Actor: "u-approver", Action: "journal.approve", SubjectType: "journal", SubjectID: jid,
		SubjectHash: f.subjectHash(t, "journal", jid), Perms: []string{"journal.approve"}}, issued)
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_sleep(5)`); err != nil {
			return err
		}
		if time.Now().Unix() < a.ExpiresAt {
			t.Fatalf("test timing: not yet expired")
		}
		if err := postgres.Authorize(ctx, tx, a.JSON()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
		return err
	})
	gap(t, "attestation accepted after its exp (wall clock) because now() is the tx start", err)
}

// Q1: INSERT directly in a non-initial status / with authority columns, as
// the tenant login without any attestation.
func TestIndependentReview_Q1_InsertInNonInitialStatus(t *testing.T) {
	f := newFixture(t)
	for name, stmt := range map[string]string{
		"journal born APPROVED": `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by,status,approved_by,approved_at)
			VALUES ('` + f.tenant + `','` + f.entity + `','ETB',now(),'x','MANUAL','rv-ins-1','h','a','APPROVED','b',now())`,
		"journal born DRAFT with posted_by": `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by,posted_by)
			VALUES ('` + f.tenant + `','` + f.entity + `','ETB',now(),'x','MANUAL','rv-ins-2','h','a','b')`,
		"period born CLOSED":                `INSERT INTO fiscal_periods(tenant_id,legal_entity_id,name,starts_on,ends_on,status,closed_by) VALUES ('` + f.tenant + `','` + f.entity + `','X','2030-01-01','2030-03-31','CLOSED','b')`,
		"period born OPEN with reopened_by": `INSERT INTO fiscal_periods(tenant_id,legal_entity_id,name,starts_on,ends_on,reopened_by) VALUES ('` + f.tenant + `','` + f.entity + `','Y','2031-01-01','2031-03-31','b')`,
		"fx source born APPROVED":           `INSERT INTO fx_sources(tenant_id,source_id,source_type,description,status,created_by,approved_by) VALUES ('` + f.tenant + `','EVIL','PROVIDER','x','APPROVED','a','b')`,
		"fx policy born APPROVED":           `INSERT INTO fx_policies(tenant_id,legal_entity_id,purpose,version,rate_type,source_priority,max_staleness,status,created_by,approved_by) VALUES ('` + f.tenant + `','` + f.entity + `','BUDGET',1,'BUDGET','{X}','1 day','APPROVED','a','b')`,
		"fx snapshot born APPROVED": `INSERT INTO fx_snapshots(tenant_id,source_id,source_type,base_currency,quote_currency,rate,rate_type,effective_from_utc,published_at_utc,source_document_hash,algorithm_version,approval_status,approved_by,created_by)
			VALUES ('` + f.tenant + `','NBE','CENTRAL_BANK','USD','ETB',1,'OFFICIAL',now()-interval '1 day',now()-interval '1 day','x','v','APPROVED','b','a')`,
		"wbs version born APPROVED": `INSERT INTO wbs_versions(tenant_id,legal_entity_id,project_id,version,status,description,created_by,approved_by) VALUES ('` + f.tenant + `','` + f.entity + `','` + f.project + `',99,'APPROVED','x','a','b')`,
		"workflow definition born PUBLISHED": `INSERT INTO workflow_definitions(tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by,status,decided_by)
			VALUES ('` + f.tenant + `','evil.def',1,'journal',false,'{"key":"evil.def","subject":"journal","mandatory":false}','sha256:` + strings.Repeat("0", 64) + `','a','PUBLISHED','b')`,
	} {
		gap(t, "tenant login: "+name, f.rawExec(stmt))
	}
}

// 0010 controls not directly exercised by the reviewer's probes.
func TestIndependentReview_HardeningControls(t *testing.T) {
	f := newFixture(t)

	// Single use: one journal.approve attestation cannot authorise two
	// transitions (approve, then re-approve after a forged demotion is
	// impossible anyway; here: the same evidence cannot be consumed twice).
	jid := f.draftJournal(t, f.balanced(key("h-single")))
	gap(t, "one attestation consumed twice",
		f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", jid, ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT approval_use('journal.approve','journal',$1,'u-approver',ARRAY['journal.approve'],false,NULL,'probe')`, jid); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by='u-approver' WHERE id=$1::uuid`, jid)
			return err
		}))

	// Close evidence does not authorise a LOCK (decision bound in ctx).
	per := f.period(t)
	gap(t, "period.close attested for CLOSED used to LOCK",
		f.rawAs(f.post, "period.close", "fiscal_period", per, "CLOSED", `UPDATE fiscal_periods SET status='LOCKED', closed_by=$2 WHERE id=$1::uuid`, per, f.post.UserID))

	// Approval timestamps are database time, not the caller's.
	jid2 := f.draftJournal(t, f.balanced(key("h-time")))
	if err := f.rawAs(f.appr, "journal.approve", "journal", jid2, "", `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at='2001-01-01' WHERE id=$1::uuid`, jid2); err != nil {
		t.Fatal(err)
	}
	if y := f.scalar(t, `SELECT extract(year FROM approved_at)::text FROM journals WHERE id=$1::uuid`, jid2); y == "2001" {
		t.Error("caller-supplied approved_at kept")
	}

	// Close records: no direct insert, no direct call of the writer.
	gap(t, "direct call of fiscal_period_close_record",
		f.rawExec(`SELECT fiscal_period_close_record($1::uuid, 'CLOSED', 'CLOSE', 'u-cfo', NULL)`, per))

	// Authority narration and effects need the actor's evidence.
	f.publish(t, journalPostingDef)
	jid3 := f.draftJournal(t, f.balanced(key("h-wf")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid3)
	if err != nil {
		t.Fatal(err)
	}
	gap(t, "forged DECIDED history entry",
		f.rawExec(`INSERT INTO workflow_history(tenant_id,instance_id,kind,actor,step_index,detail) VALUES ($1::uuid,$2::uuid,'DECIDED','u-cfo',0,'{}')`, f.tenant, w.ID))
	gap(t, "workflow effect without the executor's decision",
		f.rawExec(`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) VALUES ($1::uuid,$2::uuid,0,'journal.approve','journal',$3::uuid,'u-approver')`, f.tenant, w.ID, jid3))
	gap(t, "workflow effect with someone else's decision evidence",
		f.rawAs(f.post, "workflow.decide", "workflow_instance", w.ID, "0:APPROVE",
			`INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by) VALUES ($1::uuid,$2::uuid,0,'journal.approve','journal',$3::uuid,'u-approver')`, f.tenant, w.ID, jid3))

	// Strict shape: an extra field or a string-typed number is refused even
	// with an otherwise valid signature.
	jid4 := f.draftJournal(t, f.balanced(key("h-shape")))
	a := f.sign(t, f.tenant, attest.Claims{Actor: "u-approver", Action: "journal.approve", SubjectType: "journal", SubjectID: jid4,
		SubjectHash: f.subjectHash(t, "journal", jid4), Perms: []string{"journal.approve"}}, time.Now())
	for name, mutate := range map[string]func(map[string]any){
		"extra field":          func(m map[string]any) { m["role"] = "admin" },
		"iat as a string":      func(m map[string]any) { m["iat"] = fmt.Sprint(m["iat"]) },
		"mfa as a string":      func(m map[string]any) { m["mfa"] = "false" },
		"comma in permissions": func(m map[string]any) { m["perms"] = []string{"journal.approve,journal.post"} },
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(a.JSON()), &m)
		mutate(m)
		b, _ := json.Marshal(m)
		gap(t, "strict shape: "+name, f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return postgres.Authorize(ctx, tx, string(b))
		}))
	}
	if _, err := (attest.Signer{Master: []byte(strings.Repeat("k", 32))}).Sign(attest.Claims{Perms: []string{"a,b"}}); err == nil {
		t.Error("signer accepted a comma inside a permission")
	}
}

// M1 (deferred half): an attested APPROVE of v2 lets v1 be superseded only if
// v2 really is APPROVED when the transaction commits.
func TestIndependentReview_SupersedeNeedsApprovedSuccessorAtCommit(t *testing.T) {
	f := newFixture(t)
	pm := auth.Principal{Kind: auth.KindHuman, UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	mk := func(desc string) string {
		v, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, desc, []postgres.WBSNode{{Code: "01", Name: "Substructure"}},
			[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
		if err != nil {
			t.Fatal(err)
		}
		return v.ID
	}
	v1 := mk("tender WBS")
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v1, true, "approved for tender"); err != nil {
		t.Fatal(err)
	}
	v2 := mk("variation WBS")
	gap(t, "v1 superseded on an APPROVE attestation for v2 that is never carried out",
		f.rawAs(f.appr, "wbs.decide", "wbs_version", v2, "APPROVED", `UPDATE wbs_versions SET status='SUPERSEDED' WHERE id=$1::uuid`, v1))
	if n := f.scalar(t, `SELECT count(*)::text FROM wbs_versions WHERE project_id=$1::uuid AND status='APPROVED'`, f.project); n != "1" {
		t.Errorf("approved WBS versions = %s, want 1", n)
	}
	// The legitimate path still works.
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v2, true, "variation approved"); err != nil {
		t.Fatalf("legitimate supersede: %v", err)
	}
}
