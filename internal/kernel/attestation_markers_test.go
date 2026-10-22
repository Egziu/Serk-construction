package kernel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
)

// Migration 0035 (R10-F1/F2): the database itself, not only the signer,
// refuses an attestation without the session markers, for a revoked
// session, or for a project-mapped subject outside the attested scope. Each
// attestation below is correctly signed with the tenant's key, as a
// compromised signer path or a leaked key would produce it.
func TestAttestationMarkers_DatabaseEnforcesSessionAndScope(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Marker probe", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	hash := f.subjectHash(t, "purchase_requisition", pr)
	j := f.draftJournal(t, f.balanced(key("mk")))
	jhash := f.subjectHash(t, "journal", j)
	now := time.Now()
	sign := func(actor, action, typ, id, h string, perms ...string) attest.Attestation {
		a, err := attest.Signer{Master: testdb.ApprovalMaster, Now: func() time.Time { return now }}.Sign(attest.Claims{Tenant: f.tenant, Actor: actor, Action: action,
			SubjectType: typ, SubjectID: id, SubjectHash: h, Perms: append([]string{action, "principal.human"}, perms...)})
		must(t, "sign", err)
		return a
	}
	present := func(a attest.Attestation) error {
		return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return postgres.Authorize(ctx, tx, a.JSON())
		})
	}
	refused := func(name string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want refusal containing %q)", name, err, want)
		} else {
			t.Logf("refused: %-58s %s", name, want)
		}
	}
	accepted := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s refused: %v", name, err)
		} else {
			t.Logf("accepted: %s", name)
		}
	}
	other := "11111111-1111-4111-8111-111111111111"
	sess := []string{"principal.session:-", fmt.Sprintf("principal.iat:%d", now.Add(-time.Minute).Unix())}

	// Markers are mandatory and unique.
	refused("no session markers", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash, "principal.scope:tenant")), "missing session markers")
	refused("two session markers", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash,
		append([]string{"principal.scope:tenant", "principal.session:a"}, sess...)...)), "missing session markers")

	// Scope: the PR belongs to f.project.
	refused("project-mapped subject, another project's marker", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash,
		append([]string{"principal.project:" + other}, sess...)...)), "outside the attested scope")
	refused("project-mapped subject, no scope marker", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash, sess...)), "outside the attested scope")
	accepted("project-mapped subject, its own project's marker", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash,
		append([]string{"principal.project:" + f.project}, sess...)...)))
	accepted("project-mapped subject, tenant scope", present(sign("u-pm", "pr.approve", "purchase_requisition", pr, hash,
		append([]string{"principal.scope:tenant"}, sess...)...)))
	// R11-F2: journals are scoped by their project (none = tenant-wide), and
	// every type not deliberately unscoped needs tenant-wide scope.
	refused("journal, another project's marker", present(sign("u-approver", "journal.approve", "journal", j, jhash,
		append([]string{"principal.project:" + other}, sess...)...)), "outside the attested scope")
	var per, perHash string
	must(t, "period", f.admin.QueryRow(f.ctx, `SELECT id::text FROM fiscal_periods WHERE tenant_id = $1::uuid ORDER BY starts_on LIMIT 1`, f.tenant).Scan(&per))
	perHash = f.subjectHash(t, "fiscal_period", per)
	refused("entity-level subject (fiscal period), project scope", present(sign("u-cfo", "period.reopen", "fiscal_period", per, perHash,
		append([]string{"principal.project:" + f.project}, sess...)...)), "outside the attested scope")
	accepted("journal, tenant scope", present(sign("u-approver", "journal.approve", "journal", j, jhash,
		append([]string{"principal.scope:tenant"}, sess...)...)))

	// Revocation: every session of u-approver issued before now is revoked.
	_, err = f.svc.RevokeSessions(f.ctx, fresh(c.finMgr), "u-approver", "Device lost: revoke every session")
	if err != nil {
		// Fall back to the table (the revoker's permission set is not the
		// point of this test).
		t.Logf("revocation through the kernel: %v; recording it directly", err)
		must(t, "revoke", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO session_revocations(tenant_id, subject, revoked_before, reason, revoked_by) VALUES ($1::uuid, 'u-approver', now(), 'Device lost: revoke every session', 'u-cfo')`, f.tenant)
			return err
		}))
	}
	time.Sleep(1100 * time.Millisecond)
	refused("session issued before the revocation", present(sign("u-approver", "journal.approve", "journal", j, jhash,
		"principal.scope:tenant", "principal.session:-", fmt.Sprintf("principal.iat:%d", now.Add(-time.Minute).Unix()))), "is revoked")
	refused("issue time unknown (iat 0) after a revocation (fail closed)", present(sign("u-approver", "journal.approve", "journal", j, jhash,
		"principal.scope:tenant", "principal.session:-", "principal.iat:0")), "is revoked")
	accepted("session issued after the revocation", present(sign("u-approver", "journal.approve", "journal", j, jhash,
		"principal.scope:tenant", "principal.session:-", fmt.Sprintf("principal.iat:%d", time.Now().Unix()))))
}
