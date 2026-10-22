package kernel

// Independent review 11 probes (commit de5810d), kept as regression tests
// after migration 0036. "OPEN:" = defect observed, "held:" = control worked.
// Synthetic data only. docs/security/INDEPENDENT_REVIEW_11_2026-10-22.md.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func r11open(t *testing.T, format string, a ...any) { t.Helper(); t.Errorf("OPEN: "+format, a...) }
func r11held(t *testing.T, format string, a ...any) { t.Helper(); t.Logf("held: "+format, a...) }

// r11Compromised models a compromised API: it decides with a forged
// principal (so the kernel's own scope checks pass) but sends the signer the
// scope markers of the REAL token, which the signer accepts because they are
// the token's own.
type r11Compromised struct {
	inner attest.Issuer
	authz *auth.Authorizer
	token auth.Principal
}

func (c r11Compromised) Issue(ctx context.Context, cl attest.Claims) (attest.Attestation, error) {
	real, err := c.authz.ScopeMarkers(c.token)
	if err != nil {
		return attest.Attestation{}, err
	}
	var perms []string
	for _, p := range cl.Perms {
		if strings.HasPrefix(p, "principal.scope:") || strings.HasPrefix(p, "principal.project:") {
			continue
		}
		perms = append(perms, p)
	}
	for _, m := range real {
		if strings.HasPrefix(m, "principal.scope:") || strings.HasPrefix(m, "principal.project:") {
			perms = append(perms, m)
		}
	}
	cl.Perms = perms
	return c.inner.Issue(ctx, cl)
}

// R10-F1 is closed only for the subject types serk_subject_project() maps.
// Journals, WBS versions and payment instructions are scoped by the kernel
// (project, project, tenant-wide) but return NULL there, so the database does
// no scope check: the signed token markers are ignored.
func TestR11_UnmappedSubjectScope(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	authz := auth.NewAuthorizer(nil, true)
	otherProject := uuid.NewString()

	// Tokens as the identity provider issued them.
	jTok := f.appr
	jTok.ProjectIDs, jTok.IssuedAt, jTok.SessionID = []string{otherProject}, time.Now().Add(-time.Minute), "jti-r11-j"
	wTok := jTok
	wTok.UserID, wTok.Roles, wTok.SessionID = "u-r11-wbs-approver", []string{"finance_manager"}, "jti-r11-w"
	pTok := c.finMgr
	pTok.ProjectIDs, pTok.SessionID = []string{f.project}, "jti-r11-p"
	pTok.MFA, pTok.AuthTime = true, time.Now()
	sock := r10startSigner(t, r10Verifier{"tok-j": jTok, "tok-w": wTok, "tok-p": pTok}, nil)
	remote := &attest.Remote{Socket: sock}
	honest := New(f.app, authz).UseApprovalSigner(remote).UseBankDataKeys(testdb.BankDataKeys)
	status := func(q, id string) string {
		var s string
		_ = r9raw(f, func(ctx context.Context, tx pgx.Tx) error { return tx.QueryRow(ctx, q, id).Scan(&s) })
		return s
	}

	// ---- journal (kernel: RequireProject(journal.approve, rec.ProjectID)) ----
	jid := f.draftJournal(t, f.balanced(key("r11j")))
	ctx := attest.WithBearer(f.ctx, "tok-j")
	if err := honest.ApproveJournal(ctx, jTok, jid); err == nil {
		r11open(t, "honest API approved an out-of-scope journal")
	} else {
		r11held(t, "journal: honest API, token scope %s…: refused (%v)", otherProject[:8], err)
	}
	forged := jTok
	forged.ProjectIDs = []string{f.project}
	bad := New(f.app, authz).UseApprovalSigner(r11Compromised{remote, authz, jTok}).UseBankDataKeys(testdb.BankDataKeys)
	err := bad.ApproveJournal(ctx, forged, jid)
	st := status(`SELECT status || ' by ' || COALESCE(approved_by, '') FROM journals WHERE id = $1::uuid`, jid)
	var perms string
	_ = r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(array_to_string(perms, ' '), '') FROM approval_attestations WHERE subject_id = $1 AND action = 'journal.approve'`, jid).Scan(&perms)
	})
	if err == nil && strings.HasPrefix(st, "APPROVED") {
		r11open(t, "journal of project %s… approved by a principal whose signed token scope is project %s… only: %s; attested perms: [%s]", f.project[:8], otherProject[:8], st, perms)
	} else {
		r11held(t, "journal: compromised API refused: %v (%s)", err, st)
	}

	// ---- payment instruction (kernel: tenant-wide scope only) ----
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, j1 := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("500")})
	inv, m := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "R11/0001", InvoiceDate: today(), DueDate: today().AddDate(0, 0, 30),
		Subtotal: dec("1486500"), TaxAmount: dec("222975"), Total: dec("1709475"),
		Lines: []InvoiceLine{{1, dec("12"), dec("84500")}, {2, dec("500"), dec("945")}}})
	if m != "MATCHED" {
		t.Fatalf("match %s", m)
	}
	j2, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv, "")
	must(t, "approve invoice", err)
	w.financePost(t, j1, j2)
	pay, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec("1709475")}})
	must(t, "prepare payment", err)
	must(t, "submit payment", f.svc.SubmitPayment(f.ctx, c.treasury, pay))
	ctx = attest.WithBearer(f.ctx, "tok-p")
	if _, err := honest.ApprovePayment(ctx, pTok, pay); err == nil {
		r11open(t, "honest API let a project-scoped finance manager approve a payment")
	} else {
		r11held(t, "payment: honest API, project-scoped token: refused (%v)", err)
	}
	forgedP := pTok
	forgedP.ProjectIDs = nil // tenant-wide in the API's eyes
	bad = New(f.app, authz).UseApprovalSigner(r11Compromised{remote, authz, pTok}).UseBankDataKeys(testdb.BankDataKeys)
	next, err := bad.ApprovePayment(ctx, forgedP, pay)
	st = status(`SELECT status || ' by ' || COALESCE(approved_by, '') FROM payment_instructions WHERE id = $1::uuid`, pay)
	_ = r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(array_to_string(perms, ' '), '') FROM approval_attestations WHERE subject_id = $1 AND action = 'payment.approve'`, pay).Scan(&perms)
	})
	if err == nil {
		r11open(t, "payment %s… approved (%s; row %s) by a finance manager whose signed token is restricted to project %s… (kernel policy: tenant-wide only); attested perms: [%s]", pay[:8], next, st, f.project[:8], perms)
	} else {
		r11held(t, "payment: compromised API refused: %v (%s)", err, st)
	}

	// ---- WBS version (kernel: RequireProject(wbs.approve, v.ProjectID)) ----
	planner := auth.Principal{Kind: auth.KindHuman, UserID: "u-r11-planner", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	v, _, err := f.svc.ProposeWBSVersion(f.ctx, planner, f.project, "Rev B WBS", []postgres.WBSNode{{Code: "01", Name: "Superstructure"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "Structural materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	must(t, "wbs propose", err)
	ctx = attest.WithBearer(f.ctx, "tok-w")
	if err := honest.DecideWBSVersion(ctx, wTok, v.ID, true, "approve rev B"); err == nil {
		r11open(t, "honest API approved an out-of-scope WBS version")
	} else {
		r11held(t, "wbs: honest API, token scope %s…: refused (%v)", otherProject[:8], err)
	}
	forgedW := wTok
	forgedW.ProjectIDs = []string{f.project}
	bad = New(f.app, authz).UseApprovalSigner(r11Compromised{remote, authz, wTok}).UseBankDataKeys(testdb.BankDataKeys)
	err = bad.DecideWBSVersion(ctx, forgedW, v.ID, true, "approve rev B")
	st = status(`SELECT status || ' by ' || COALESCE(approved_by, '') FROM wbs_versions WHERE id = $1::uuid`, v.ID)
	if err == nil && strings.HasPrefix(st, "APPROVED") {
		r11open(t, "WBS version of project %s… approved (previous version superseded) by a principal whose signed token scope is project %s… only: %s", f.project[:8], otherProject[:8], st)
	} else {
		r11held(t, "wbs: compromised API refused: %v (%s)", err, st)
	}

}

// Marker smuggling through the signer: variants of the reserved markers that
// the token does not grant must be refused; duplicates must not pass the
// database.
func TestR11_MarkerSmuggling(t *testing.T) {
	f := newFixture(t)
	tok := f.appr
	tok.ProjectIDs, tok.IssuedAt, tok.SessionID = []string{f.project}, time.Now().Add(-time.Minute), "jti-r11-s"
	sock := r10startSigner(t, r10Verifier{"tok": tok}, nil)
	remote := &attest.Remote{Socket: sock}
	ctx := attest.WithBearer(f.ctx, "tok")
	jid := f.draftJournal(t, f.balanced(key("r11s")))
	hash := f.subjectHash(t, "journal", jid)
	base := []string{"journal.approve", "principal.human", "principal.session:jti-r11-s", fmt.Sprintf("principal.iat:%d", tok.IssuedAt.Unix())}
	try := func(name string, extra ...string) (attest.Attestation, error) {
		return remote.Issue(ctx, attest.Claims{Tenant: f.tenant, Actor: tok.UserID, Action: "journal.approve", SubjectType: "journal", SubjectID: jid, SubjectHash: hash,
			Perms: append(append([]string{}, base...), extra...)})
	}
	for _, v := range []string{"principal.scope:tenant", "Principal.scope:tenant", "principal.scope:tenant ", " principal.scope:tenant", "principal.scope:TENANT",
		"principal.project:" + strings.ToUpper(f.project), "principal.project:" + f.project + " ", "principal.project:" + uuid.NewString(),
		"principal.session:other", "principal.iat:0"} {
		if _, err := try(v, v); err == nil {
			r11open(t, "signer signed smuggled marker %q", v)
		} else {
			r11held(t, "signer refused %q: %v", v, err)
		}
	}
	// Duplicate of the token's own session marker: signed (it is the token's),
	// the database must still refuse (exactly one of each).
	a, err := try("dup", "principal.session:jti-r11-s")
	if err != nil {
		r11held(t, "signer refused a duplicated session marker: %v", err)
		return
	}
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error { return postgres.Authorize(ctx, tx, a.JSON()) })
	if err == nil {
		r11open(t, "database accepted an attestation with a duplicated session marker")
	} else {
		r11held(t, "duplicated session marker signed by the signer but refused by the database: %v", err)
	}
	// Session/iat markers omitted: the signer must refuse.
	_, err = remote.Issue(ctx, attest.Claims{Tenant: f.tenant, Actor: tok.UserID, Action: "journal.approve", SubjectType: "journal", SubjectID: jid, SubjectHash: hash,
		Perms: []string{"journal.approve", "principal.human"}})
	if err == nil {
		r11open(t, "signer signed without session markers")
	} else {
		r11held(t, "signer refused claims without session markers: %v", err)
	}
	// Malformed project ids in the token.
	for _, ids := range [][]string{{""}, {"a,b"}, {"a\x1fb"}} {
		p := tok
		p.ProjectIDs = ids
		if _, err := auth.NewAuthorizer(nil, true).ScopeMarkers(p); err == nil {
			r11open(t, "ScopeMarkers accepted project ids %q", ids)
		} else {
			r11held(t, "ScopeMarkers refused project ids %q: %v", ids, err)
		}
	}
}

// R10-F3 rewrote only functions that already pinned search_path. The 48
// trigger/helper functions with NO pinned path run with the caller's path,
// where pg_temp is searched first. journals_workflow_gate() ->
// workflow_require_effect() reads workflow_definitions unqualified: with TEMP
// granted, an empty pg_temp.workflow_definitions hides the mandatory
// workflow and a single attested approval replaces the multi-step workflow.
func TestR11_TempShadowsUnpinnedWorkflowGate(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("r11wf")))
	// Control: without TEMP the raw path is refused.
	err := f.rawAs(f.appr, "journal.approve", "journal", jid, "", `UPDATE journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
	if err == nil || !strings.Contains(err.Error(), "mandatory approval workflow") {
		t.Fatalf("control: %v", err)
	}
	r11held(t, "control (no TEMP): raw approve refused: %v", err)

	role, _ := postgres.RoleName(f.tenant)
	var db string
	must(t, "db", f.super.QueryRow(f.ctx, `SELECT current_database()`).Scan(&db))
	_, err = f.super.Exec(f.ctx, fmt.Sprintf(`GRANT TEMP ON DATABASE %s TO %s`, pgx.Identifier{db}.Sanitize(), pgx.Identifier{role}.Sanitize()))
	must(t, "grant temp", err)
	defer f.super.Exec(f.ctx, fmt.Sprintf(`REVOKE TEMP ON DATABASE %s FROM %s`, pgx.Identifier{db}.Sanitize(), pgx.Identifier{role}.Sanitize()))

	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE workflow_definitions (LIKE public.workflow_definitions) ON COMMIT DROP`); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, f.appr, "journal.approve", "journal", jid, ""); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE public.journals SET status='APPROVED', approved_by='u-approver', approved_at=now() WHERE id=$1::uuid`, jid)
		return err
	})
	st := f.journalStatus(t, jid)
	var inst int
	_ = r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM workflow_instances WHERE subject_id = $1::uuid`, jid).Scan(&inst)
	})
	if err == nil && st == "APPROVED" {
		r11open(t, "with TEMP granted, journal %s… under the mandatory 'journal.posting' workflow was APPROVED directly (workflow instances for it: %d): pg_temp.workflow_definitions shadowed the table in unpinned workflow_require_effect()", jid[:8], inst)
	} else {
		r11held(t, "shadow refused: %v (status %s)", err, st)
	}
}

// The hmac: -> hkey: digest change is admitted only in a maintenance
// session. A tenant session attempting exactly that shape must be refused.
func TestR11_TenantRedigest(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	id, err := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "Awash Bank", "ABC Steel PLC", "2000 5555 66688", "ETB")
	must(t, "add", err)
	legacy := "hmac:" + strings.Repeat("cd", 32)
	must(t, "legacy digest", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE supplier_bank_accounts DISABLE TRIGGER USER`); err != nil {
			return err
		}
		defer tx.Exec(ctx, `ALTER TABLE supplier_bank_accounts ENABLE TRIGGER USER`)
		_, err := tx.Exec(ctx, `UPDATE supplier_bank_accounts SET account_digest = $2 WHERE id = $1::uuid`, id, legacy)
		return err
	}))
	chosen := "hkey:" + strings.Repeat("ef", 32)
	err = r9exec(f, `UPDATE supplier_bank_accounts SET account_digest = $2 WHERE id = $1::uuid`, id, chosen)
	var got string
	_ = r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT account_digest FROM supplier_bank_accounts WHERE id = $1::uuid`, id).Scan(&got)
	})
	if err == nil || got == chosen {
		r11open(t, "tenant session re-digested an encrypted row to a chosen hkey: value (%v, now %s)", err, got[:12])
	} else {
		r11held(t, "tenant hmac:->hkey: change refused: %v (digest still %s…)", err, got[:12])
	}
	var ms bool
	err = r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT serk_maintenance_session()`).Scan(&ms)
	})
	r11held(t, "tenant calling serk_maintenance_session(): value=%v err=%v", ms, err)
}

// R11-F1: the database posture check runs through the privilege-less health
// login in production (the harness now uses one too); it must succeed there.
func TestR11_PostureThroughHealthLogin(t *testing.T) {
	f := newFixture(t)
	if f.db.HealthDSN == f.db.AdminDSN {
		t.Skip("cluster has no serk_health role")
	}
	issues, err := f.app.Posture(f.ctx)
	if err != nil {
		r11open(t, "posture through the health login: %v", err)
		return
	}
	t.Logf("held: posture through %s: %d issue(s) on the test cluster", "serk_health_test", len(issues))
	for _, who := range []string{"serk_health", "serk_monitor"} {
		var ok bool
		must(t, who, f.super.QueryRow(f.ctx, `SELECT has_function_privilege($1, 'serk_object_owner()', 'EXECUTE')`, who).Scan(&ok))
		if !ok {
			r11open(t, "%s cannot execute serk_object_owner()", who)
		}
	}
}
