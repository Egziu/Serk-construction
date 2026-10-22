package kernel

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// TestJourneyB_CreditNote: a commercial concession on an approved invoice is
// made with a credit note (JB-CREDIT-NOTE, migration 0022), never by editing
// or reversing the invoice. Figures (ETB, synthetic):
//
//	IPC 1: gross 5,310,000; retention 5% 265,500; no advance received, so no
//	recovery; VAT 15% on 5,310,000 = 796,500; due 5,841,000.
//	Credit note: net 200,000 (agreed settlement for defective kerb rework), VAT 30,000,
//	total 230,000: Dr revenue 200,000 (project), Dr VAT output 30,000;
//	Cr AR 230,000.
//	Receipt of the original 5,841,000 is refused (the credited part is no
//	longer receivable); 5,611,000 settles the invoice.
//	GL: AR 0; revenue -5,110,000; VAT output -766,500; retention 265,500.
func TestJourneyB_CreditNote(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	ipc := w.certifiedIPC(t, 15, "ERA-IPC-01")
	w.checkIPC(t, ipc, ipcFigures{"5310000", "0", "5310000", "265500", "0", "796500", "5841000"})

	// A credit note needs an approved invoice.
	draftInv, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc, today(), today().AddDate(0, 0, 30))
	must(t, "invoice", err)
	_, err = f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, draftInv, dec("1000"), today(), "Credit before approval")
	arDenied(t, "a credit note on a DRAFT invoice", err, "DRAFT")
	jInv, err := f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, draftInv)
	must(t, "invoice approve", err)
	inv := draftInv

	// Input controls at issue.
	_, err = f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), today(), "")
	arDenied(t, "a credit note without a reason", err, "reason")
	_, err = f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("5310000.01"), today(), "More than was billed")
	arDenied(t, "credits beyond the invoice gross", err, "exceed its gross")
	_, err = f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("100.001"), today(), "Sub-cent amount")
	arDenied(t, "an amount finer than the currency", err, "decimal place")
	_, err = f.svc.IssueCreditNote(f.ctx, c.commercial, inv, dec("1000"), today(), "Commercial manager issuing")
	arDenied(t, "issue by someone without ar.credit.create", err, "forbidden: ar.credit.create")

	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), today(), "Agreed commercial settlement for defective kerb rework")
	must(t, "credit note", err)
	var vat, total decimal.Decimal
	must(t, "credit figures", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT vat_amount, total FROM customer_credit_notes WHERE id = $1::uuid`, cn).Scan(&vat, &total)
	}))
	if !vat.Equal(dec("30000")) || !total.Equal(dec("230000")) {
		t.Fatalf("credit note VAT %s total %s, want 30,000 and 230,000", vat, total)
	}

	// Approval controls: fresh MFA, a different person, a human, no direct writes.
	_, err = f.svc.ApproveCreditNote(f.ctx, c.commercial, cn)
	arDenied(t, "approval without fresh MFA", err, "multi-factor")
	both := w.ar.arClerk
	both.Roles = append([]string{"commercial_manager"}, both.Roles...)
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(both), cn)
	arDenied(t, "self-approval of a credit note", err, "segregation of duties")
	ai := w.mfa(c.commercial)
	ai.UserID, ai.Kind = "u-commercial-assistant", auth.KindAI
	_, err = f.svc.ApproveCreditNote(f.ctx, ai, cn)
	arDenied(t, "approval by an AI principal", err, "reserved to human principals")
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE customer_credit_notes SET status = 'APPROVED', approved_by = 'u-x' WHERE id = $1::uuid`, cn)
		return err
	})
	arDenied(t, "direct approval without attestation or journal", err, "approval attestation")
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE customer_credit_notes SET net_amount = 1 WHERE id = $1::uuid`, cn)
		return err
	})
	arDenied(t, "direct edit of the credited amount", err, "permission denied")

	jCN, err := f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn)
	must(t, "credit note approve", err)

	// The credited part is no longer receivable.
	lines := w.statement(t, c.bankOfficer, "CBE-CN-001", "0", "11452000",
		[3]string{"5841000", "ERA IPC 1 FULL", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"5611000", "ERA IPC 1 NET OF CN", "ETHIOPIAN ROADS ADMIN"})
	wrong, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("5841000")}})
	must(t, "over-allocated draft", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, wrong)
	arDenied(t, "a receipt allocated to the credited part", err, "credited")
	must(t, "cancel wrong receipt", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, wrong, "Allocated beyond the credited invoice"))
	_, jR := w.confirmedReceipt(t, lines[1], ReceiptAllocation{InvoiceID: inv, Amount: dec("5611000")})

	// Nothing is left to credit: a further credit is refused at approval and
	// withdrawn by the clerk.
	cn2, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("10000"), today(), "Second concession after settlement")
	must(t, "second credit note", err)
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn2)
	arDenied(t, "a credit beyond what is open on the invoice", err, "exceeds what is open")
	arDenied(t, "cancellation by an AI principal", f.svc.CancelCreditNote(f.ctx, ai, cn2, "Withdrawn"), "reserved to human principals")
	must(t, "cancel second credit", f.svc.CancelCreditNote(f.ctx, w.ar.arClerk, cn2, "Nothing left open on the invoice"))
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn2)
	arDenied(t, "approving a cancelled credit note", err, "CANCELLED")

	w.financePost(t, jInv, jCN, jR)

	// The credit note journal is never reversed or cancelled.
	_, err = f.svc.ReverseJournal(f.ctx, c.controller, jCN, "rev-"+jCN, "Reverse the credit", today())
	arDenied(t, "reversing an AR_CREDIT journal", err, "not reversed")

	// Ledger, subledger and contract position agree.
	for code, want := range map[string]string{"1100": "0", "1150": "265500", "2300": "-766500", "4000": "-5110000"} {
		if got := w.balance(t, code); !got.Equal(dec(want)) {
			t.Errorf("GL %s: got %s, want %s", code, got, want)
		} else {
			t.Logf("GL %s = %s", code, got)
		}
	}
	ar, err := f.svc.ARReconciliation(f.ctx, c.controller, f.entity)
	must(t, "AR reconciliation", err)
	for _, r := range ar {
		t.Logf("AR recon %-66s subledger %14s gl %14s diff %s open %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
		if strings.HasPrefix(r.Check, "Unapplied") {
			if !r.Subledger.Equal(dec("5841000")) || r.Unposted != 1 {
				t.Errorf("unapplied money in should be the refused line only: %+v", r)
			}
			continue
		}
		if !r.Difference.IsZero() || r.Unposted != 0 {
			t.Errorf("%s does not reconcile: %+v", r.Check, r)
		}
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	if !pos.InvoicedTotal.Equal(dec("5841000")) || !pos.CreditedTotal.Equal(dec("230000")) || !pos.Received.Equal(dec("5611000")) || !pos.ReceivableOpen.IsZero() {
		t.Errorf("contract position after the credit: %+v", pos)
	}
	pr, err := f.svc.ProjectProfitability(f.ctx, c.controller, f.project)
	must(t, "profitability", err)
	if !pr.RevenuePosted.Equal(dec("5110000")) {
		t.Errorf("project revenue after the credit: %s", pr.RevenuePosted)
	}
	t.Logf("credit note %s: journal %s; position %+v; revenue %s", cn[:8], jCN[:8], pos, pr.RevenuePosted)
}

// A credit note and a receipt for the whole invoice race: the invoice row
// lock serialises them, so exactly one succeeds and the invoice is never
// both fully paid and credited.
func TestJourneyB_CreditNoteRacesReceipt(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), today(), "Agreed commercial settlement for defective kerb rework")
	must(t, "credit note", err)
	lines := w.statement(t, c.bankOfficer, "CBE-RACE-1", "0", "5841000", [3]string{"5841000", "ERA IPC 1", "ETHIOPIAN ROADS ADMIN"})
	rc, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("5841000")}})
	must(t, "receipt", err)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn) }()
	go func() { defer wg.Done(); _, errs[1] = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, rc) }()
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Errorf("credit note / receipt race: %v / %v (want exactly one to succeed)", errs[0], errs[1])
	} else {
		t.Logf("refused: concurrent credit and full receipt: one succeeded, the other %v", firstErr(errs))
	}
}
