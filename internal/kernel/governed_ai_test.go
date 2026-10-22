package kernel

// Governed AI (migration 0019): principals the identity provider does not
// assert are human may prepare and submit drafts, but every decision needs
// the platform-signed principal.human marker — in the kernel and, for a
// caller that bypasses the kernel with a validly signed attestation, in SQL.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func TestGovernedAI_DraftOnly(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	ipc := w.certifiedIPC(t, 15, "ERA-IPC-01")

	ai := w.ar.arClerk
	ai.UserID, ai.Kind = "u-ar-assistant", auth.KindAI
	// Drafting is allowed: the AI assistant prepares the customer invoice.
	inv, err := f.svc.IssueCustomerInvoice(f.ctx, ai, ipc, today(), today().AddDate(0, 0, 30))
	must(t, "AI drafts a customer invoice", err)
	t.Logf("held: AI principal drafted customer invoice %s", inv[:8])
	// Deciding is not, for any non-human kind, whatever the roles say. The
	// subjects are pending, so only the kind rule can refuse.
	pendingCustomer, err := f.svc.CreateCustomer(f.ctx, w.ar.arClerk, f.entity, "OROMIA-RB", "Oromia Roads Bureau", "")
	must(t, "pending customer", err)
	submitted, err := f.svc.CreateContract(f.ctx, c.commercial, w.contractInput())
	must(t, "contract", err)
	must(t, "contract submit", f.svc.SubmitContract(f.ctx, c.commercial, submitted))
	const why = "reserved to human principals"
	for _, kind := range []string{auth.KindAI, auth.KindService, ""} {
		p := w.ar.arSup
		p.UserID, p.Kind = "u-ar-approver-"+kind, kind
		_, err := f.svc.ApproveCustomerInvoice(f.ctx, p, inv)
		arDenied(t, "customer invoice approval by kind "+kind, err, why)
		fm := c.finMgr
		fm.UserID, fm.Kind = "u-fm-"+kind, kind
		arDenied(t, "customer approval by kind "+kind, f.svc.ApproveCustomer(f.ctx, fm, pendingCustomer), why)
		cfo := c.cfo
		cfo.UserID, cfo.Kind = "u-cfo-"+kind, kind
		arDenied(t, "contract approval by kind "+kind, f.svc.DecideContract(f.ctx, cfo, submitted, true, ""), why)
	}
	// A human approves the AI's draft.
	if _, err := f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv); err != nil {
		t.Fatalf("human approval of an AI-drafted invoice: %v", err)
	}

	// SQL: a correctly signed attestation for a decision without the human
	// marker is refused at insert, even when presented directly.
	j := f.draftJournal(t, f.balanced(key("gai")))
	sign := func(perms []string) attest.Attestation {
		a, err := attest.Signer{Master: testdb.ApprovalMaster, Now: time.Now}.Sign(attest.Claims{Tenant: f.tenant, Actor: "u-approver", Action: "journal.approve",
			SubjectType: "journal", SubjectID: j, SubjectHash: f.subjectHash(t, "journal", j), Perms: perms})
		must(t, "sign", err)
		return a
	}
	present := func(a attest.Attestation) error {
		return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return postgres.Authorize(ctx, tx, a.JSON())
		})
	}
	arDenied(t, "SQL: signed journal.approve attestation without principal.human", present(sign([]string{"journal.approve"})), "reserved to principals the identity provider asserts are human")
	if err := present(sign([]string{"journal.approve", "principal.human"})); err != nil {
		t.Errorf("SQL: signed journal.approve attestation with principal.human refused: %v", err)
	}
	// The draft-action list in SQL and Go agree.
	for _, a := range []string{"customer.create", "contract.submit", "ipc.submit", "ar.invoice.create", "rfq.quote.record", "bank.import", "workflow.start",
		"journal.approve", "journal.post", "ipc.certify", "measure.verify", "payment.approve", "period.close", "workflow.define", "contract.decide", "x.created"} {
		var sqlDraft bool
		must(t, "draft action", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT approval_is_draft_action($1)`, a).Scan(&sqlDraft)
		}))
		if sqlDraft != auth.IsDraftAction(a) {
			t.Errorf("draft action %q: SQL %v, Go %v", a, sqlDraft, auth.IsDraftAction(a))
		}
	}
}
