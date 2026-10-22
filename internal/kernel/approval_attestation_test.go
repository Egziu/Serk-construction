package kernel

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// GATEA-APPROVAL-01 (directive §2.3): the attestation itself cannot be
// replayed, substituted, stretched or forged, and SQL-level privilege
// tricks do not reach the key or the evidence.

// sign builds an attestation as the kernel would, letting a test alter it.
func (f *fixture) sign(t *testing.T, tenant string, c attest.Claims, now time.Time) attest.Attestation {
	t.Helper()
	c.Tenant = tenant
	// Models the platform signer for a person: the identity provider asserted
	// a human principal, so the signed perms carry the human marker (0019).
	if !slices.Contains(c.Perms, "principal.human") {
		c.Perms = append(append([]string{}, c.Perms...), "principal.human")
	}
	a, err := attest.Signer{Master: testdb.ApprovalMaster, Now: func() time.Time { return now }}.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) subjectHash(t *testing.T, typ, id string) string {
	t.Helper()
	var h string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		h, err = postgres.SubjectHash(ctx, tx, typ, id)
		return err
	})
	return h
}

// addBalancedLines appends a balanced pair of lines to a DRAFT journal, as
// the tenant login (journal_lines INSERT is an ordinary maker operation).
func (f *fixture) addBalancedLines(jid string) error {
	return f.rawExec(`INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency) VALUES
		($1::uuid,$2::uuid,$3::uuid,98,$4::uuid,'DEBIT',777,'ETB'),($1::uuid,$2::uuid,$3::uuid,99,$5::uuid,'CREDIT',777,'ETB')`,
		jid, f.tenant, f.entity, f.accounts["5000"], f.accounts["1000"])
}

// approveWith tries to approve journal jid as approver with attestation a.
func (f *fixture) approveWith(tenant string, a attest.Attestation, jid, approver string) error {
	return f.app.WithTenant(f.ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := postgres.Authorize(ctx, tx, a.JSON()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE journals SET status='APPROVED', approved_by=$2, approved_at=now() WHERE id=$1::uuid`, jid, approver)
		return err
	})
}

func TestAttestation_ReplaySubstitutionExpiryAndTampering(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	j1 := f.draftJournal(t, f.balanced(key("att-1")))
	j2 := f.draftJournal(t, f.balanced(key("att-2")))
	claims := func(jid string) attest.Claims {
		return attest.Claims{Actor: "u-approver", Action: "journal.approve", SubjectType: "journal", SubjectID: jid,
			SubjectHash: f.subjectHash(t, "journal", jid), Perms: []string{"journal.approve"}}
	}
	good := f.sign(t, f.tenant, claims(j1), now)

	// Substitution: an attestation for j1 cannot approve j2.
	denied(t, "attestation for journal A used on journal B", f.approveWith(f.tenant, good, j2, "u-approver"))
	// Actor substitution: the attested person must be the recorded approver.
	denied(t, "attestation for u-approver recorded as someone else", f.approveWith(f.tenant, good, j1, "u-somebody-else"))
	// Tampering: any change invalidates the signature.
	for name, mut := range map[string]func(*attest.Attestation){
		"actor changed":   func(a *attest.Attestation) { a.Actor = "u-mallory" },
		"perms widened":   func(a *attest.Attestation) { a.Perms = append(a.Perms, "journal.post") },
		"mfa flipped":     func(a *attest.Attestation) { a.MFA = true },
		"expiry extended": func(a *attest.Attestation) { a.ExpiresAt += 3600 },
		"signature junk":  func(a *attest.Attestation) { a.Sig = strings.Repeat("0", 64) },
	} {
		b := good
		b.Perms = append([]string(nil), good.Perms...)
		mut(&b)
		denied(t, "tampered attestation: "+name, f.approveWith(f.tenant, b, j1, "u-approver"))
	}
	// Wrong key: signed with another secret.
	other, _ := attest.Signer{Master: []byte("an-attacker-chosen-secret-0123456789abcdef")}.Sign(func() attest.Claims { c := claims(j1); c.Tenant = f.tenant; return c }())
	denied(t, "attestation signed with another secret", f.approveWith(f.tenant, other, j1, "u-approver"))
	// Tenant substitution: a valid attestation of tenant 1 used in tenant 2.
	denied(t, "tenant-1 attestation presented in a tenant-2 session", f.approveWith(f.tenant2, good, j1, "u-approver"))
	// Expired / too long-lived.
	old := f.sign(t, f.tenant, claims(j1), now.Add(-10*time.Minute))
	denied(t, "expired attestation", f.approveWith(f.tenant, old, j1, "u-approver"))
	// Content changed after signing: two balanced lines slipped into the
	// DRAFT after review invalidate the pending attestation.
	stale := f.sign(t, f.tenant, claims(j1), now)
	if err := f.addBalancedLines(j1); err != nil {
		t.Fatal(err)
	}
	denied(t, "attestation for content that has since changed", f.approveWith(f.tenant, stale, j1, "u-approver"))
	// Permission not held: a signature over perms without journal.approve.
	np := claims(j1)
	np.SubjectHash = f.subjectHash(t, "journal", j1)
	np.Perms = []string{"journal.read"}
	denied(t, "attestation of a person without journal.approve", f.approveWith(f.tenant, f.sign(t, f.tenant, np, now), j1, "u-approver"))

	// The genuine attestation works exactly once.
	fresh := claims(j1)
	fresh.SubjectHash = f.subjectHash(t, "journal", j1)
	ok := f.sign(t, f.tenant, fresh, now)
	if err := f.approveWith(f.tenant, ok, j1, "u-approver"); err != nil {
		t.Fatalf("genuine attestation refused: %v", err)
	}
	// Replay of the used attestation (on another subject or the same one).
	denied(t, "replay of a used attestation", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return postgres.Authorize(ctx, tx, ok.JSON())
	}))
	// The evidence is immutable and readable by the tenant.
	var n int
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM approval_attestations WHERE subject_id=$1 AND action='journal.approve'`, j1).Scan(&n)
	})
	if n != 1 {
		t.Fatalf("evidence rows %d", n)
	}
	denied(t, "rewrite attestation evidence", f.rawExec(`UPDATE approval_attestations SET actor='someone' WHERE subject_id=$1`, j1))
	denied(t, "insert attestation evidence directly", f.rawExec(`INSERT INTO approval_attestations SELECT * FROM approval_attestations LIMIT 1`))
}

// Step-up evidence comes from the signed, fresh auth_time — a boolean claim
// with a stale login is not MFA.
func TestAttestation_MFAFreshnessIsVerifiedInSQL(t *testing.T) {
	f := newFixture(t)
	per := f.period(t)
	if _, err := f.svc.ClosePeriod(f.ctx, f.post, per, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	reopen := func(authTime time.Time, mfa bool) error {
		c := attest.Claims{Actor: "u-cfo", Action: "period.reopen", SubjectType: "fiscal_period", SubjectID: per,
			SubjectHash: f.subjectHash(t, "fiscal_period", per), Perms: []string{"period.reopen"}, MFA: mfa, AuthTime: authTime.Unix()}
		a := f.sign(t, f.tenant, c, now)
		return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			if err := postgres.Authorize(ctx, tx, a.JSON()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE fiscal_periods SET status='OPEN', reopened_by='u-cfo', reopen_reason='late supplier invoice' WHERE id=$1::uuid`, per)
			return err
		})
	}
	denied(t, "reopen with mfa=true but a login 2 hours old", reopen(now.Add(-2*time.Hour), true))
	denied(t, "reopen without MFA", reopen(now, false))
	if err := reopen(now.Add(-time.Minute), true); err != nil {
		t.Fatalf("fresh MFA reopen refused: %v", err)
	}
}

// Privilege tricks with the tenant login cannot reach the key, the
// verifier's internals or the evidence.
func TestAttestation_TenantLoginCannotReachKeysOrEscalate(t *testing.T) {
	f := newFixture(t)
	for name, stmt := range map[string]string{
		"read verification keys":         `SELECT key FROM approval_keys`,
		"install a key":                  `SELECT approval_key_install('` + f.tenant + `', 'evil', '\x` + strings.Repeat("ab", 32) + `'::bytea)`,
		"become the schema owner":        `SET ROLE postgres`,
		"create an object in public":     `CREATE FUNCTION public.hmac(bytea, bytea, text) RETURNS bytea LANGUAGE sql AS 'SELECT $1'`,
		"create a temporary object":      `CREATE TEMP TABLE x(y int)`,
		"forge a session tenant via GUC": `SELECT set_config('app.tenant_id', '` + f.tenant2 + `', false); SELECT count(*) FROM approval_attestations WHERE tenant_id = '` + f.tenant2 + `' HAVING count(*) > 0`,
	} {
		err := f.rawExec(stmt)
		if name == "forge a session tenant via GUC" {
			// No error, but no foreign rows either (HAVING filters to none).
			var n int
			_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
				_, _ = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, f.tenant2)
				return tx.QueryRow(ctx, `SELECT count(*) FROM approval_attestations WHERE tenant_id = $1::uuid`, f.tenant2).Scan(&n)
			})
			if n != 0 {
				t.Errorf("GUC exposed another tenant's evidence")
			}
			continue
		}
		denied(t, name, err)
	}
}

// The legitimate path: two independent people, current MFA, correct scope,
// through the ordinary API commands — and the evidence they leave.
func TestAttestation_LegitimateTwoPersonFlowLeavesEvidence(t *testing.T) {
	f := newFixture(t)
	jid := f.lifecycle(t, f.balanced(key("att-legit")))
	type ev struct {
		Actor, Action string
		Perms         []string
	}
	var got []ev
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT actor, action, perms FROM approval_attestations WHERE subject_id=$1 ORDER BY recorded_at`, jid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.Actor, &e.Action, &e.Perms); err != nil {
				return err
			}
			got = append(got, e)
		}
		return rows.Err()
	})
	b, _ := json.Marshal(got)
	if len(got) != 2 || got[0].Actor != f.appr.UserID || got[0].Action != "journal.approve" || got[1].Actor != f.post.UserID || got[1].Action != "journal.post" {
		t.Fatalf("evidence %s", b)
	}
	if f.journalStatus(t, jid) != "POSTED" {
		t.Fatal("legitimate flow did not post")
	}
	// A service without a signer fails closed.
	unsigned := New(f.app, auth.NewAuthorizer(nil, true))
	j2 := f.draftJournal(t, f.balanced(key("att-unsigned")))
	if err := unsigned.ApproveJournal(f.ctx, f.appr, j2); err == nil {
		t.Fatal("approval without a configured signer")
	}
}

// A decision attestation authorises exactly one step and one outcome.
func TestAttestation_DecisionBoundToStepAndOutcome(t *testing.T) {
	f := newFixture(t)
	f.publish(t, journalPostingDef)
	jid := f.draftJournal(t, f.balanced(key("att-dec")))
	w, err := f.svc.StartWorkflow(f.ctx, f.prep, "journal.posting", jid)
	if err != nil {
		t.Fatal(err)
	}
	denied(t, "APPROVE attestation used to record a REJECT", f.rawAs(f.appr, "workflow.decide", "workflow_instance", w.ID, "0:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,reason) VALUES ($1::uuid,$2::uuid,0,'review','u-approver','REJECT','not what was attested')`,
		f.tenant, w.ID))
	denied(t, "step-1 attestation used for step 0", f.rawAs(f.appr, "workflow.decide", "workflow_instance", w.ID, "1:APPROVE",
		`INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision) VALUES ($1::uuid,$2::uuid,0,'review','u-approver','APPROVE')`,
		f.tenant, w.ID))
}
