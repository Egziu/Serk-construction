package kernel

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

const releaseSHA = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

func (w *arWorld) release(amount, milestone, ref string) RetentionReleaseInput {
	return RetentionReleaseInput{Amount: dec(amount), ReleaseDate: today(), Milestone: milestone, CertificateRef: ref, CertificateSHA256: releaseSHA}
}

// TestJourneyB_RetentionRelease (migration 0023). Figures (ETB, synthetic,
// no advance):
//
//	IPC 1: gross 5,310,000, retention 265,500, VAT 796,500, due 5,841,000.
//	IPC 2: gross 3,330,000, retention 166,500, VAT 499,500, due 3,663,000.
//	Retention held 432,000. Released in two halves of 216,000 (taking over,
//	end of defects liability): AR_RETENTION Dr AR / Cr retention.
//	Receipts: 5,841,000 (invoice 1); 216,000 (release 1); 300,000 split
//	216,000 release 2 + 84,000 invoice 2.
//	GL: retention 0; AR 5,841,000 + 3,663,000 + 432,000 - 6,357,000 =
//	3,579,000; revenue -8,640,000 (unchanged by releases).
func TestJourneyB_RetentionRelease(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv1, jInv1 := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	w.measure(t, 20, "3000", "200", "10")
	ipc2 := w.certifiedIPC(t, 20, "ERA-IPC-02")
	w.checkIPC(t, ipc2, ipcFigures{"8640000", "5310000", "3330000", "166500", "0", "499500", "3663000"})
	inv2, jInv2 := w.approvedInvoice(t, ipc2)

	// Input controls.
	bad := w.release("216000", "TAKING_OVER", "ERA-TOC-01")
	bad.CertificateSHA256 = "not-a-hash"
	_, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, bad)
	arDenied(t, "a release without the certificate hash", err, "SHA-256")
	_, err = f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("216000", "WHENEVER", "ERA-TOC-01"))
	arDenied(t, "a release with an unknown milestone", err, "milestone")
	_, err = f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("432000.01", "TAKING_OVER", "ERA-TOC-01"))
	arDenied(t, "a release above the retention held", err, "would exceed the retention held")
	_, err = f.svc.RecordRetentionRelease(f.ctx, w.ar.qs, ctr, w.release("216000", "TAKING_OVER", "ERA-TOC-01"))
	arDenied(t, "a release recorded without ar.retention.create", err, "forbidden: ar.retention.create")

	rel1, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("216000", "TAKING_OVER", "ERA-TOC-01"))
	must(t, "release 1", err)

	// Approval controls.
	_, err = f.svc.ApproveRetentionRelease(f.ctx, c.commercial, rel1)
	arDenied(t, "approval without fresh MFA", err, "multi-factor")
	both := w.ar.arClerk
	both.Roles = append([]string{"commercial_manager"}, both.Roles...)
	_, err = f.svc.ApproveRetentionRelease(f.ctx, w.mfa(both), rel1)
	arDenied(t, "self-approval of a release", err, "segregation of duties")
	ai := w.mfa(c.commercial)
	ai.UserID, ai.Kind = "u-commercial-assistant", auth.KindAI
	_, err = f.svc.ApproveRetentionRelease(f.ctx, ai, rel1)
	arDenied(t, "approval by an AI principal", err, "reserved to human principals")
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE retention_releases SET amount = 432000 WHERE id = $1::uuid`, rel1)
		return err
	})
	arDenied(t, "direct edit of the released amount", err, "permission denied")
	jRel1, err := f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel1)
	must(t, "release 1 approve", err)

	// Second half; nothing more can be drafted, even 0.01.
	rel2, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("216000", "DEFECTS_LIABILITY_END", "ERA-DLP-01"))
	must(t, "release 2", err)
	_, err = f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("0.01", "NEGOTIATED", "ERA-NEG-01"))
	arDenied(t, "a release beyond what is held (drafts counted)", err, "would exceed the retention held")
	jRel2, err := f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel2)
	must(t, "release 2 approve", err)

	// Receipts against invoices and releases.
	lines := w.statement(t, c.bankOfficer, "CBE-RT-001", "0", "6657000",
		[3]string{"5841000", "ERA IPC 1", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"216000", "ERA RETENTION 1", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"300000", "ERA RETENTION 2 + IPC 2", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"300000", "ERA DUPLICATE", "ETHIOPIAN ROADS ADMIN"})
	_, jR1 := w.confirmedReceipt(t, lines[0], ReceiptAllocation{InvoiceID: inv1, Amount: dec("5841000")})
	_, jR2 := w.confirmedReceipt(t, lines[1], ReceiptAllocation{RetentionReleaseID: rel1, Amount: dec("216000")})
	over, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[3], []ReceiptAllocation{{RetentionReleaseID: rel2, Amount: dec("300000")}})
	must(t, "over-allocated draft", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, over)
	arDenied(t, "a receipt over-allocated to a release", err, "retention release")
	must(t, "cancel over-allocation", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, over, "Allocated beyond the release"))
	_, jR3 := w.confirmedReceipt(t, lines[2], ReceiptAllocation{RetentionReleaseID: rel2, Amount: dec("216000")}, ReceiptAllocation{InvoiceID: inv2, Amount: dec("84000")})

	w.financePost(t, jInv1, jInv2, jRel1, jRel2, jR1, jR2, jR3)
	_, err = f.svc.ReverseJournal(f.ctx, c.controller, jRel1, "rev-"+jRel1, "Undo the release", today())
	arDenied(t, "reversing an AR_RETENTION journal", err, "not reversed")

	for code, want := range map[string]string{"1100": "3579000", "1150": "0", "4000": "-8640000", "2300": "-1296000"} {
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
			if !r.Subledger.Equal(dec("300000")) || r.Unposted != 1 {
				t.Errorf("unapplied money in should be the refused duplicate only: %+v", r)
			}
			continue
		}
		if !r.Difference.IsZero() || r.Unposted != 0 {
			t.Errorf("%s does not reconcile: %+v", r.Check, r)
		}
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	if !pos.RetentionHeld.IsZero() || !pos.RetentionReleased.Equal(dec("432000")) || !pos.InvoicedTotal.Equal(dec("9504000")) ||
		!pos.Received.Equal(dec("6357000")) || !pos.ReceivableOpen.Equal(dec("3579000")) {
		t.Errorf("contract position after the releases: %+v", pos)
	}
	t.Logf("position %+v", pos)
}

// Two releases of the whole retention, recorded and approved concurrently.
// Recording locks the contract (kernel visibility lock), and the database
// counts drafts, so in practice the second recording is refused; approval
// re-checks under FOR UPDATE on the contract as a second line. Either way at
// most one release is approved.
func TestJourneyB_RetentionReleaseRace(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	ids := make([]string, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("265500", "TAKING_OVER", "ERA-TOC-0"+string(rune('1'+i))))
		}()
	}
	wg.Wait()
	var drafts []string
	for i := range 2 {
		if errs[i] == nil {
			drafts = append(drafts, ids[i])
		} else {
			t.Logf("refused at recording: %v", errs[i])
		}
	}
	approved := 0
	aerrs := make([]error, len(drafts))
	for i, id := range drafts {
		wg.Add(1)
		go func() { defer wg.Done(); _, aerrs[i] = f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), id) }()
	}
	wg.Wait()
	for _, e := range aerrs {
		if e == nil {
			approved++
		} else {
			t.Logf("refused at approval: %v", e)
		}
	}
	if approved != 1 {
		t.Errorf("concurrent full releases: %d approved (drafts %d), want exactly 1", approved, len(drafts))
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	if !pos.RetentionReleased.Equal(dec("265500")) || !pos.RetentionHeld.IsZero() {
		t.Errorf("retention after the race: held %s released %s", pos.RetentionHeld, pos.RetentionReleased)
	}
}
