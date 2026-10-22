package kernel

// Review 8 regression tests. Written as independent probes of migrations
// 0022-0025 at commit 8caddaa (docs/security/INDEPENDENT_REVIEW_8_2026-10-22.md
// keeps their failing output); kept after the 0028 corrections so each defect
// stays closed. "OPEN:" (t.Errorf) = the defect is back; "held:" = the control
// worked. R8-F3 and R8-F5 assert the corrected / accepted semantics.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func r8open(t *testing.T, format string, a ...any) {
	t.Helper()
	t.Errorf("OPEN: "+format, a...)
}

func r8held(t *testing.T, format string, a ...any) {
	t.Helper()
	t.Logf("held: "+format, a...)
}

// r8refused: err != nil is the control holding.
func r8refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		r8open(t, "%s was accepted", what)
		return
	}
	r8held(t, "%s refused: %v", what, err)
}

func r8principal(f *fixture, id string, projects []string, roles ...string) auth.Principal {
	return auth.Principal{Kind: auth.KindHuman, UserID: id, TenantID: f.tenant, Roles: roles, ProjectIDs: projects, IssuedAt: time.Now().Add(-time.Minute)}
}

func (w *arWorld) r8val(t *testing.T, sql string, args ...any) decimal.Decimal {
	t.Helper()
	var v decimal.Decimal
	must(t, "value", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&v)
	}))
	return v
}

func (w *arWorld) r8recon(t *testing.T) []postgres.ReconCheck {
	t.Helper()
	ar, err := w.f.svc.ARReconciliation(w.f.ctx, w.cast.controller, w.f.entity)
	must(t, "AR reconciliation", err)
	for _, r := range ar {
		t.Logf("  AR recon %-64s sub %14s gl %14s diff %s open %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
	}
	return ar
}

// ---------------------------------------------------------------------------
// AR lifecycle: approval after the period closed; future dates.
// ---------------------------------------------------------------------------
func TestR8_ARApprovalAfterPeriodClose(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, jInv := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	w.financePost(t, jInv)
	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), today(), "Agreed settlement for kerb rework")
	must(t, "credit note", err)
	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("100000", "TAKING_OVER", "ERA-TOC-01"))
	must(t, "release", err)
	per := f.period(t)
	_, err = f.svc.ClosePeriod(f.ctx, f.post, per, false)
	must(t, "close period", err)
	t.Logf("period FY2026-Q4 (the only period, covering %s) CLOSED while credit note %s and release %s are DRAFT", today().Format("2006-01-02"), cn[:8], rel[:8])
	for _, x := range []struct {
		what    string
		approve func() (string, error)
	}{
		{"credit note", func() (string, error) { return f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn) }},
		{"retention release", func() (string, error) { return f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel) }},
	} {
		j, err := x.approve()
		if err != nil {
			r8held(t, "%s approval in a closed period refused: %v", x.what, err)
			continue
		}
		ap := f.svc.ApproveJournals(f.ctx, c.finMgr, []string{j})
		ps := f.svc.PostJournals(f.ctx, c.controller, []string{j})
		r8open(t, "%s APPROVED after its period was closed; its journal %s: approve ok=%v %s / post ok=%v %s",
			x.what, j[:8], ap[0].OK, ap[0].Error, ps[0].OK, ps[0].Error)
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	t.Logf("contract position: invoiced %s credited %s retention held %s released %s receivable open %s",
		pos.InvoicedTotal, pos.CreditedTotal, pos.RetentionHeld, pos.RetentionReleased, pos.ReceivableOpen)
	w.r8recon(t)
	// A receipt for the full original invoice is now refused because of the
	// approved-but-unposted credit.
	lines := w.statement(t, c.bankOfficer, "CBE-R8-PC", "0", "5841000", [3]string{"5841000", "ERA IPC 1", "ETHIOPIAN ROADS ADMIN"})
	rc, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("5841000")}})
	must(t, "receipt", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, rc)
	t.Logf("receipt of the full original invoice after the closed-period credit: %v", err)
}

func TestR8_ARFutureDated(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	future := today().AddDate(0, 0, 20)
	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), future, "Settlement agreed for next month")
	if err != nil {
		r8held(t, "credit note dated %s refused: %v", future.Format("2006-01-02"), err)
	} else if _, err := f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn); err == nil {
		pos, _ := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
		r8open(t, "credit note dated %s (today %s) recorded and APPROVED now; credited %s already counts in the position and blocks receipts",
			future.Format("2006-01-02"), today().Format("2006-01-02"), pos.CreditedTotal)
	} else {
		r8held(t, "future credit refused at approval: %v", err)
	}
	in := w.release("100000", "TAKING_OVER", "ERA-TOC-01")
	in.ReleaseDate = future
	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, in)
	if err != nil {
		r8held(t, "release dated %s refused: %v", future.Format("2006-01-02"), err)
	} else if _, err := f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel); err == nil {
		r8open(t, "retention release dated %s APPROVED today (stock documents refuse future dates since R7-F3)", future.Format("2006-01-02"))
	}
}

// ---------------------------------------------------------------------------
// VAT on credits is rounded per credit note, not cumulatively.
// ---------------------------------------------------------------------------
func TestR8_CreditVATPerNoteRounding(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	for _, tc := range []struct{ net string }{{"0.10"}, {"0.30"}} {
		var vats decimal.Decimal
		nets := decimal.Zero
		for i := 0; i < 10; i++ {
			cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec(tc.net), today(), fmt.Sprintf("Small concession %s no %d", tc.net, i))
			must(t, "credit", err)
			_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn)
			must(t, "approve credit", err)
			vats = vats.Add(w.r8val(t, `SELECT vat_amount FROM customer_credit_notes WHERE id = $1::uuid`, cn))
			nets = nets.Add(dec(tc.net))
		}
		// R8-F5 accepted (ADR 0011 addendum): VAT is a property of each tax
		// document. Each note's VAT is round(net x 15%); the sum of n notes may
		// differ from the VAT on their total by at most n x 0.005.
		want := w.r8val(t, `SELECT p2p_round($1::numeric * 0.15, 'ETB')`, nets)
		perNote := w.r8val(t, `SELECT 10 * p2p_round($1::numeric * 0.15, 'ETB')`, dec(tc.net))
		if !vats.Equal(perNote) {
			t.Errorf("10 credit notes of net %s credit VAT %s, want 10 x round(net x 15%%) = %s", tc.net, vats, perNote)
		}
		if vats.Sub(want).Abs().GreaterThan(dec("0.05")) {
			t.Errorf("per-document VAT rounding drifted %s from the VAT on the total, beyond 10 x 0.005", vats.Sub(want))
		}
		t.Logf("accepted (R8-F5): 10 notes of net %s carry VAT %s; VAT on the total %s would be %s", tc.net, vats, nets, want)
	}
}

// ---------------------------------------------------------------------------
// Ordering: credit after partial payment, release, exact settlement.
// ---------------------------------------------------------------------------
func TestR8_CreditAfterPartialPaymentAndRelease(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, jInv := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	lines := w.statement(t, c.bankOfficer, "CBE-R8-PP", "0", "5265500.01",
		[3]string{"5000000", "ERA IPC 1 PART", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"0.01", "ERA ROUNDING", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"265500", "ERA RETENTION", "ETHIOPIAN ROADS ADMIN"})
	_, jR1 := w.confirmedReceipt(t, lines[0], ReceiptAllocation{InvoiceID: inv, Amount: dec("5000000")})
	big, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("800000"), today(), "Concession larger than what is open")
	must(t, "credit 800000", err)
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), big)
	r8refused(t, "credit of total 920,000 after 5,000,000 received on a 5,841,000 invoice", err)
	must(t, "cancel big", f.svc.CancelCreditNote(f.ctx, w.ar.arClerk, big, "Too large after the receipt"))
	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("731304.35"), today(), "Exact concession for the open balance")
	must(t, "credit exact", err)
	jCN, err := f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn)
	must(t, "approve exact credit", err)
	t.Logf("credit net 731,304.35 total %s approved", w.r8val(t, `SELECT total FROM customer_credit_notes WHERE id=$1::uuid`, cn))
	rc, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[1], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("0.01")}})
	must(t, "receipt 0.01", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, rc)
	r8refused(t, "receipt of 0.01 on the fully paid-and-credited invoice", err)
	must(t, "cancel 0.01", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, rc, "Nothing open on the invoice"))
	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("265500", "TAKING_OVER", "ERA-TOC-01"))
	must(t, "release", err)
	jRel, err := f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel)
	must(t, "approve release", err)
	cn2, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("1"), today(), "Credit after release and settlement")
	if err == nil {
		_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn2)
	}
	r8refused(t, "a further credit after settlement and release", err)
	_, jR2 := w.confirmedReceipt(t, lines[2], ReceiptAllocation{RetentionReleaseID: rel, Amount: dec("265500")})
	w.financePost(t, jInv, jR1, jCN, jRel, jR2)
	bad := false
	for _, r := range w.r8recon(t) {
		if !strings.HasPrefix(r.Check, "Unapplied") && (!r.Difference.IsZero() || r.Unposted != 0) {
			bad = true
		}
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	gl := map[string]decimal.Decimal{}
	for _, code := range []string{"1100", "1150", "2300", "4000"} {
		gl[code] = w.balance(t, code)
	}
	t.Logf("position open %s held %s released %s received %s credited %s; GL AR %s retention %s VAT %s revenue %s",
		pos.ReceivableOpen, pos.RetentionHeld, pos.RetentionReleased, pos.Received, pos.CreditedTotal, gl["1100"], gl["1150"], gl["2300"], gl["4000"])
	if bad || !pos.ReceivableOpen.IsZero() || !gl["1100"].IsZero() || !gl["1150"].IsZero() {
		r8open(t, "ordering credit-after-payment then release leaves residue: position open %s, GL AR %s, retention %s", pos.ReceivableOpen, gl["1100"], gl["1150"])
	} else {
		r8held(t, "partial payment -> exact credit -> release -> receipt: AR 0, retention 0, position open 0, every reconciliation row 0")
	}
}

// ---------------------------------------------------------------------------
// Concurrency: two credits and a receipt on one invoice; two receipts on one release.
// ---------------------------------------------------------------------------
func TestR8_ConcurrentCreditsAndReceipt(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	w.activeContract(t)
	days := []int{15, 20, 25}
	opening := decimal.Zero
	qty := [][3]string{{"4000", "300", "20"}, {"3000", "200", "10"}, {"2000", "100", "5"}}
	for round := 0; round < 3; round++ {
		w.measure(t, days[round], qty[round][0], qty[round][1], qty[round][2])
		inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, days[round], fmt.Sprintf("ERA-IPC-0%d", round+1)))
		gross := w.r8val(t, `SELECT gross FROM customer_invoices WHERE id=$1::uuid`, inv)
		total := w.r8val(t, `SELECT total FROM customer_invoices WHERE id=$1::uuid`, inv)
		net := gross.Mul(dec("0.49")).Round(2)
		recAmt := total.Mul(dec("0.3")).Round(2)
		cnA, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, net, today(), "Concession A for the race")
		must(t, "credit A", err)
		cnB, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, net, today(), "Concession B for the race")
		must(t, "credit B", err)
		lines := w.statement(t, c.bankOfficer, fmt.Sprintf("CBE-R8-RACE-%d", round), opening.String(), opening.Add(recAmt).String(), [3]string{recAmt.String(), "ERA PART", "ETHIOPIAN ROADS ADMIN"})
		opening = opening.Add(recAmt)
		rc, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: recAmt}})
		must(t, "receipt", err)
		errs := make([]error, 3)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); _, errs[0] = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cnA) }()
		go func() { defer wg.Done(); _, errs[1] = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cnB) }()
		go func() { defer wg.Done(); _, errs[2] = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, rc) }()
		wg.Wait()
		cred := w.r8val(t, `SELECT (ar_invoice_credited($1::uuid)).total`, inv)
		paid := w.r8val(t, `SELECT COALESCE(sum(a.amount),0) FROM receipt_allocations a JOIN customer_receipts r ON r.id=a.receipt_id WHERE a.invoice_id=$1::uuid AND r.status='CONFIRMED'`, inv)
		t.Logf("round %d: invoice total %s; credits of %s net each and a receipt of %s raced: errs %v / %v / %v; credited %s + received %s = %s",
			round, total, net, recAmt, errs[0], errs[1], errs[2], cred, paid, cred.Add(paid))
		if cred.Add(paid).GreaterThan(total) {
			r8open(t, "round %d: credited %s + received %s exceeds the invoice total %s", round, cred, paid, total)
		} else {
			r8held(t, "round %d: credited + received %s <= total %s", round, cred.Add(paid), total)
		}
	}
}

func TestR8_ConcurrentReleaseReceipts(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("265500", "TAKING_OVER", "ERA-TOC-01"))
	must(t, "release", err)
	_, err = f.svc.ApproveRetentionRelease(f.ctx, w.mfa(c.commercial), rel)
	must(t, "approve release", err)
	lines := w.statement(t, c.bankOfficer, "CBE-R8-REL", "0", "400000",
		[3]string{"200000", "ERA RET A", "ETHIOPIAN ROADS ADMIN"}, [3]string{"200000", "ERA RET B", "ETHIOPIAN ROADS ADMIN"})
	ids := make([]string, 2)
	for i := range ids {
		ids[i], err = f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[i], []ReceiptAllocation{{RetentionReleaseID: rel, Amount: dec("200000")}})
		must(t, "receipt", err)
	}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func() { defer wg.Done(); _, errs[i] = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, ids[i]) }()
	}
	wg.Wait()
	paid := w.r8val(t, `SELECT COALESCE(sum(a.amount),0) FROM receipt_allocations a JOIN customer_receipts r ON r.id=a.receipt_id WHERE a.retention_release_id=$1::uuid AND r.status='CONFIRMED'`, rel)
	if paid.GreaterThan(dec("265500")) {
		r8open(t, "two concurrent receipts of 200,000 on a 265,500 release both confirmed (%s): %v", paid, errs)
	} else {
		r8held(t, "concurrent receipts on one release: received %s of 265,500 (%v / %v)", paid, errs[0], errs[1])
	}
}

// ---------------------------------------------------------------------------
// Raw SQL as the tenant runtime role (AR).
// ---------------------------------------------------------------------------
func TestR8_RawSQL_AR(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, jInv := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	probe := func(what, sql string, args ...any) {
		t.Helper()
		r8refused(t, what, f.rawExec(sql, args...))
	}
	// Forged figures on a raw credit note insert.
	var vat, tot decimal.Decimal
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO customer_credit_notes(legal_entity_id, project_id, contract_id, customer_id, invoice_id, policy_id, number, credit_date,
			currency, net_amount, vat_amount, total, reason, created_by)
			SELECT legal_entity_id, project_id, contract_id, customer_id, id, policy_id, 'R8-FORGED', current_date, currency, 1000, 0, 1000, 'Forged credit note', 'u-ar-clerk'
			  FROM customer_invoices WHERE id = $1::uuid RETURNING vat_amount, total`, inv).Scan(&vat, &tot)
	})
	t.Logf("raw credit insert with vat 0 / total 1000: stored vat %s total %s before commit; commit: %v", vat, tot, err)
	r8refused(t, "unattested raw credit note insert", err)

	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("200000"), today(), "Agreed settlement for kerb rework")
	must(t, "credit", err)
	cnDraft, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("1000"), today(), "Second credit kept in draft")
	must(t, "credit 2", err)
	jCN, err := f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn)
	must(t, "approve credit", err)
	probe("swap the journal of an APPROVED credit note for the invoice journal", `UPDATE customer_credit_notes SET journal_id = $2::uuid WHERE id = $1::uuid`, cn, jInv)
	probe("cancel an APPROVED credit note", `UPDATE customer_credit_notes SET status = 'CANCELLED', decision_reason = 'Withdrawn after approval' WHERE id = $1::uuid`, cn)
	probe("approve a DRAFT credit note raw, reusing the approved note's journal", `UPDATE customer_credit_notes SET status='APPROVED', approved_by='u-commercial', journal_id=$2::uuid WHERE id = $1::uuid`, cnDraft, jCN)

	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("100000", "TAKING_OVER", "ERA-TOC-01"))
	must(t, "release", err)
	probe("approve a release raw without attestation", `UPDATE retention_releases SET status='APPROVED', approved_by='u-commercial' WHERE id = $1::uuid`, rel)
	probe("insert a contract line into an ACTIVE contract", `INSERT INTO contract_lines(contract_id, line_no, description, unit, quantity, rate) VALUES ($1::uuid, 9, 'Extra excavation', 'm3', 1000, 350)`, ctr)
	probe("raw release insert above the retention held", `INSERT INTO retention_releases(legal_entity_id, project_id, contract_id, customer_id, policy_id, number, release_date, currency, amount, milestone, certificate_ref, certificate_sha256, created_by)
		SELECT legal_entity_id, project_id, id, customer_id, policy_id, 'R8-REL', current_date, currency, 999999, 'NEGOTIATED', 'R8-CERT', $2, 'u-ar-clerk' FROM contracts WHERE id = $1::uuid`, ctr, releaseSHA)

	lines := w.statement(t, c.bankOfficer, "CBE-R8-RAW", "0", "200", [3]string{"100", "ERA A", "ETHIOPIAN ROADS ADMIN"}, [3]string{"100", "ERA B", "ETHIOPIAN ROADS ADMIN"})
	rcDraft, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("100")}})
	must(t, "receipt draft", err)
	probe("allocation with two targets (invoice and release)", `INSERT INTO receipt_allocations(receipt_id, line_no, invoice_id, retention_release_id, amount) VALUES ($1::uuid, 9, $2::uuid, $3::uuid, 1)`, rcDraft, inv, rel)
	must(t, "cancel draft receipt", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, rcDraft, "Replaced by the release probe"))
	rcRel, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{RetentionReleaseID: rel, Amount: dec("100")}})
	if err == nil {
		_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, rcRel)
	}
	r8refused(t, "a receipt allocated to a DRAFT retention release", err)
	rcConf, _ := w.confirmedReceipt(t, lines[1], ReceiptAllocation{InvoiceID: inv, Amount: dec("100")})
	probe("allocation added to a CONFIRMED receipt", `INSERT INTO receipt_allocations(receipt_id, line_no, invoice_id, amount) VALUES ($1::uuid, 9, $2::uuid, 1)`, rcConf, inv)

	// Reserved idempotency namespace for an AR document.
	probe("tenant role inserts the AR_CREDIT journal of a DRAFT credit note (exact reserved key)", `INSERT INTO journals(legal_entity_id, functional_currency, business_event_at, description,
		source_type, source_ref, idempotency_key, command_hash, created_by, created_txid) VALUES ($1::uuid, 'ETB', now(), 'x', 'AR_CREDIT', $2, 'p2p:AR_CREDIT:' || $2, 'x', 'u-x', txid_current())`, f.entity, cnDraft)
	for _, k := range []string{"P2P:AR_CREDIT:" + cnDraft, "p2p:ar_credit:" + cnDraft, "p2p:AR_CREDIT:" + strings.ToUpper(cnDraft)} {
		err := f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO journals(tenant_id, legal_entity_id, functional_currency, business_event_at, description, source_type, source_ref, idempotency_key, command_hash, created_by, created_txid)
				VALUES ($3::uuid, $1::uuid, 'ETB', now(), 'x', 'AR_CREDIT', $4, $2, 'x', 'u-x', txid_current())`, f.entity, k, f.tenant, strings.ToUpper(cnDraft))
			return err
		})
		r8refused(t, "schema-owner journal with key variant "+k[:16]+"…", err)
	}
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cnDraft)
	if err != nil && strings.Contains(err.Error(), "idempotency") {
		r8open(t, "the draft credit note can no longer be approved: %v", err)
	} else {
		r8held(t, "the draft credit note still approves after the key attempts: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Raw SQL as the tenant runtime role (stock transfers, PO line item).
// ---------------------------------------------------------------------------
func TestR8_RawSQL_Stock(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	pmgr := r8principal(f, "u-proc-manager", []string{f.project}, "procurement_manager")
	storeB, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Second store")
	must(t, "store B", err)
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	probe := func(what, sql string, args ...any) {
		t.Helper()
		r8refused(t, what, w.rawExec(sql, args...))
	}
	probe("raw transfer insert with a preset amount", `INSERT INTO stock_transfers(legal_entity_id, number, stock_item_id, from_warehouse_id, to_warehouse_id, quantity, transfer_date, currency, created_by, amount)
		VALUES ($1::uuid, 'R8-T1', $2::uuid, $3::uuid, $4::uuid, 1, current_date, 'ETB', 'u-storekeeper', 1)`, f.entity, w.itemSteel, w.store, storeB)
	probe("raw transfer insert without attestation", `INSERT INTO stock_transfers(legal_entity_id, number, stock_item_id, from_warehouse_id, to_warehouse_id, quantity, transfer_date, currency, created_by)
		VALUES ($1::uuid, 'R8-T2', $2::uuid, $3::uuid, $4::uuid, 1, current_date, 'ETB', 'u-storekeeper')`, f.entity, w.itemSteel, w.store, storeB)
	tr, err := f.svc.CreateStockTransfer(f.ctx, w.cast.store, StockTransferInput{StockItemID: w.itemSteel, FromWarehouseID: w.store, ToWarehouseID: storeB, Quantity: dec("2"), TransferDate: today()})
	must(t, "transfer", err)
	probe("raw transfer approval without attestation", `UPDATE stock_transfers SET status='APPROVED', approved_by='u-inventory-controller' WHERE id = $1::uuid`, tr)
	probe("change the quantity of a DRAFT transfer", `UPDATE stock_transfers SET quantity = 12 WHERE id = $1::uuid`, tr)
	probe("change the destination of a DRAFT transfer", `UPDATE stock_transfers SET to_warehouse_id = $2::uuid WHERE id = $1::uuid`, tr, w.store)
	probe("insert a TRANSFER layer", `INSERT INTO stock_layers(stock_item_id, warehouse_id, source_type, source_id, qty_in, qty_remaining, unit_cost, value_in, value_remaining)
		VALUES ($1::uuid, $2::uuid, 'TRANSFER', $3::uuid, 1, 1, 1, 1, 1)`, w.itemSteel, storeB, tr)
	probe("change po_lines.stock_item_id after approval", `UPDATE po_lines SET stock_item_id = $2::uuid WHERE po_id = $1::uuid AND line_no = 1`, po, w.itemCement)
	probe("add a PO line to an APPROVED purchase order", `INSERT INTO po_lines(po_id, line_no, legal_entity_id, description, unit, quantity, unit_price, account_id, cost_code_id, stock_item_id)
		SELECT po_id, 9, legal_entity_id, description, unit, quantity, unit_price, account_id, cost_code_id, stock_item_id FROM po_lines WHERE po_id = $1::uuid AND line_no = 1`, po)
	must(t, "approve transfer", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, tr))
	probe("re-open an APPROVED transfer", `UPDATE stock_transfers SET status = 'DRAFT' WHERE id = $1::uuid`, tr)
	probe("cancel an APPROVED transfer", `UPDATE stock_transfers SET status = 'CANCELLED', decision_reason = 'Undo after approval' WHERE id = $1::uuid`, tr)
}

// ---------------------------------------------------------------------------
// Transfers: FIFO and WAC with values that do not divide evenly.
// ---------------------------------------------------------------------------
func TestR8_TransferFractionalNoResidue(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pmgr := r8principal(f, "u-proc-manager", []string{f.project}, "procurement_manager")
	storeB, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Second store")
	must(t, "store B", err)
	var js []string
	for _, p := range [][2]string{{"84500.333333", "940.37"}, {"86000.777777", "951.13"}, {"85123.456789", "947.777777"}} {
		po := w.inventoryPO(t, "3.3333", "333.3333", p[0], p[1])
		grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("3.3333")}, GRNLine{POLineNo: 2, QtyReceived: dec("333.3333")})
		js = append(js, j)
		w.putAway(t, grn, 1, w.itemSteel, "1.1111")
		w.putAway(t, grn, 1, w.itemSteel, "2.2222")
		w.putAway(t, grn, 2, w.itemCement, "111.1111")
		w.putAway(t, grn, 2, w.itemCement, "222.2222")
	}
	w.financePost(t, js...)
	bal := func(wh, item string) (decimal.Decimal, decimal.Decimal) {
		return w.stockValue(t, `SELECT COALESCE(sum(qty),0) FROM stock_balances WHERE warehouse_id=$1::uuid AND stock_item_id=$2::uuid`, wh, item),
			w.stockValue(t, `SELECT COALESCE(sum(value),0) FROM stock_balances WHERE warehouse_id=$1::uuid AND stock_item_id=$2::uuid`, wh, item)
	}
	transfer := func(item, from, to, qty string) {
		t.Helper()
		id, err := f.svc.CreateStockTransfer(f.ctx, c.store, StockTransferInput{StockItemID: item, FromWarehouseID: from, ToWarehouseID: to, Quantity: dec(qty), TransferDate: today()})
		must(t, "transfer "+qty, err)
		must(t, "approve transfer "+qty, f.svc.ApproveStockTransfer(f.ctx, w.invCtl, id))
		amt := w.stockValue(t, `SELECT amount FROM stock_transfers WHERE id=$1::uuid`, id)
		cons := w.stockValue(t, `SELECT COALESCE(sum(value),0) FROM stock_consumptions WHERE doc_type='TRANSFER' AND doc_id=$1::uuid`, id)
		lay := w.stockValue(t, `SELECT COALESCE(sum(value_in),0) FROM stock_layers WHERE source_type='TRANSFER' AND source_id=$1::uuid`, id)
		b, l, d := w.invariants(t)
		t.Logf("transfer %s of %s: amount %s consumed %s destination layers %s; balances %s layers %s documents %s", qty, item[:8], amt, cons, lay, b, l, d)
		if !amt.Equal(cons) || (lay.Sign() != 0 && !lay.Equal(amt)) || !b.Equal(l) || !b.Equal(d) {
			r8open(t, "transfer %s: amount %s, consumed %s, destination layers %s; balances %s layers %s documents %s", qty, amt, cons, lay, b, l, d)
		}
	}
	issueFrom := func(wh, item, qty string) {
		t.Helper()
		id, err := f.svc.CreateStockIssue(f.ctx, c.store, StockIssueInput{WarehouseID: wh, StockItemID: item, ProjectID: f.project, CostCodeID: w.costCode,
			ExpenseAccountID: w.acct["5000"], Quantity: dec(qty), IssueDate: today()})
		must(t, "issue "+qty, err)
		j, err := f.svc.ApproveStockIssue(f.ctx, c.siteEng, id)
		must(t, "approve issue "+qty, err)
		if j != "" {
			w.financePost(t, j)
		}
	}
	transfer(w.itemSteel, w.store, storeB, "1.5")
	transfer(w.itemSteel, w.store, storeB, "2.7777")
	transfer(w.itemCement, w.store, storeB, "111.1111")
	transfer(w.itemCement, w.store, storeB, "77.7777")
	// a surplus at B becomes a COUNT layer after the transferred ones; then move some back
	for _, it := range []string{w.itemSteel, w.itemCement} {
		q, _ := bal(storeB, it)
		ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: storeB, StockItemID: it, CountedQty: q.Add(dec("0.3333")),
			VarianceAccountID: w.acct["5200"], CountDate: today()})
		must(t, "surplus count", err)
		jc, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
		must(t, "approve surplus", err)
		w.financePost(t, jc)
	}
	q, _ := bal(storeB, w.itemSteel)
	transfer(w.itemSteel, storeB, w.store, q.String()) // whole of B including the surplus layer
	transfer(w.itemCement, storeB, w.store, "50.0001")
	for i := 0; i < 7; i++ {
		issueFrom(w.store, w.itemSteel, "0.4321")
		issueFrom(w.store, w.itemCement, "37.0037")
		issueFrom(storeB, w.itemCement, "3.0303")
	}
	for _, wh := range []string{w.store, storeB} {
		for _, it := range []string{w.itemSteel, w.itemCement} {
			if q, _ := bal(wh, it); q.IsPositive() {
				issueFrom(wh, it, q.String())
			}
		}
	}
	b, l, d := w.invariants(t)
	gl := w.glBalance(t, "1200")
	var resid string
	must(t, "residue", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(string_agg(warehouse_id::text || ':' || qty || '@' || value, ', '), '') FROM stock_balances WHERE qty <> 0 OR value <> 0`).Scan(&resid)
	}))
	t.Logf("closing: balances %s layers %s documents %s GL inventory %s residue [%s]", b, l, d, gl, resid)
	if !b.IsZero() || !l.IsZero() || !d.IsZero() || !gl.IsZero() || resid != "" {
		r8open(t, "residue after fractional transfers: balances %s layers %s documents %s GL %s [%s]", b, l, d, gl, resid)
	} else {
		r8held(t, "FIFO and WAC through 6 transfers (split layers, a COUNT layer moved back), 21 fractional issues and exact closes: stock 0, layers 0, GL 0")
	}
	for _, r := range w.recon(t) {
		if r.Difference.Sign() != 0 {
			r8open(t, "reconciliation row %s difference %s", r.Check, r.Difference)
		}
	}
}

// ---------------------------------------------------------------------------
// Transfers across projects: visibility of the approver and receiver, and
// the budget netting of R7-F4.
// ---------------------------------------------------------------------------
func TestR8_TransferAcrossProjects(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	var p2 string
	must(t, "project 2", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		p2, err = postgres.CreateProject(ctx, tx, f.tenant, f.entity, "P-002", "Adigrat water works", "ETB")
		return err
	}))
	pm2 := r8principal(f, "u-pm-2", []string{p2}, "project_manager")
	v, _, err := f.svc.ProposeWBSVersion(f.ctx, pm2, p2, "Tender WBS P-002", []postgres.WBSNode{{Code: "01", Name: "Pipework"}},
		[]postgres.CostCode{{NodeCode: "01", Code: "02-MAT", Name: "Pipework materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	must(t, "wbs p2", err)
	must(t, "wbs p2 approve", f.svc.DecideWBSVersion(f.ctx, f.appr, v.ID, true, "approved for construction"))
	var cc2 string
	must(t, "cc2", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT c.id::text FROM cost_codes c JOIN wbs_nodes n ON n.id = c.wbs_node_id WHERE n.version_id = $1::uuid AND c.code = '02-MAT'`, v.ID).Scan(&cc2)
	}))
	store2, err := f.svc.CreateWarehouse(f.ctx, r8principal(f, "u-proc-manager-2", []string{p2}, "procurement_manager"), f.entity, p2, "P002-STORE", "Project 002 store")
	must(t, "store p2", err)

	po := w.inventoryPO(t, "20", "500", "84500", "940")
	position := func(cc string) (committed, actual, available decimal.Decimal) {
		must(t, "cost position", w.raw(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT committed, actual_other, available FROM p2p_cost_position($1::uuid, NULL, NULL)`, cc).Scan(&committed, &actual, &available)
		}))
		return
	}
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	_, _, av0 := position(w.costCode)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	c1, a1, av1 := position(w.costCode)
	_, a2, av2 := position(cc2)
	t.Logf("before: P-001 01-MAT committed %s actual %s available %s; P-002 02-MAT actual %s available %s", c1, a1, av1, a2, av2)

	in := StockTransferInput{StockItemID: w.itemSteel, FromWarehouseID: w.store, ToWarehouseID: store2, Quantity: dec("12"), TransferDate: today()}
	_, err = f.svc.CreateStockTransfer(f.ctx, c.store, in)
	r8refused(t, "a P-001 storekeeper requesting a transfer into a P-002 warehouse", err)
	both := r8principal(f, "u-store-both", []string{f.project, p2}, "storekeeper")
	tr, err := f.svc.CreateStockTransfer(f.ctx, both, in)
	must(t, "transfer P1->P2", err)
	ctlP1 := r8principal(f, "u-invctl-p1", []string{f.project}, "inventory_controller")
	_, errWh := f.svc.GetP2PDoc(f.ctx, ctlP1, "warehouse", store2)
	if err := f.svc.ApproveStockTransfer(f.ctx, ctlP1, tr); err == nil {
		r8open(t, "a P-001-scoped inventory controller, for whom the destination warehouse is %q, approved moving 12 t into it", errWh)
	} else {
		r8held(t, "P-001-scoped controller cannot approve into P-002: %v", err)
		must(t, "approve transfer", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, tr))
	}
	store2p := r8principal(f, "u-store-2", []string{p2}, "storekeeper")
	list, err := f.svc.ListP2PDocs(f.ctx, store2p, "stock_transfer", "", 50)
	must(t, "list", err)
	_, errTr := f.svc.GetP2PDoc(f.ctx, store2p, "stock_transfer", tr)
	onHand, err := f.svc.StockOnHand(f.ctx, store2p, f.entity)
	must(t, "on hand", err)
	var q2 decimal.Decimal
	for _, l := range onHand {
		if l.WarehouseID == store2 {
			q2 = q2.Add(l.Qty)
		}
	}
	t.Logf("info: P-002 storekeeper sees %s t on hand in P002-STORE, %d stock_transfer documents in the list, and the transfer detail -> %v", q2, len(list), errTr)

	site2 := r8principal(f, "u-site-2", []string{p2}, "site_engineer")
	is, err := f.svc.CreateStockIssue(f.ctx, store2p, StockIssueInput{WarehouseID: store2, StockItemID: w.itemSteel, ProjectID: p2, CostCodeID: cc2,
		ExpenseAccountID: w.acct["5000"], Quantity: dec("12"), IssueDate: today()})
	must(t, "issue in P2", err)
	ji, err := f.svc.ApproveStockIssue(f.ctx, site2, is)
	must(t, "approve issue in P2", err)
	w.financePost(t, ji)
	amt := w.stockValue(t, `SELECT amount FROM stock_issues WHERE id=$1::uuid`, is)
	c1b, a1b, av1b := position(w.costCode)
	_, a2b, av2b := position(cc2)
	t.Logf("after P-002 consumed the 12 t (%s): P-001 committed %s actual %s available %s; P-002 actual %s available %s", amt, c1b, a1b, av1b, a2b, av2b)
	// R8-F3: put-away released P-001's commitment by the put-away value (the
	// steel became stock, an asset); P-002's issue bears it as actual. Counted
	// once: only on P-002.
	if !av1.Sub(av0).Equal(amt) {
		t.Errorf("put-away released %s of P-001's commitment, want the put-away value %s", av1.Sub(av0), amt)
	}
	if !av1b.Equal(av1) {
		t.Errorf("P-001 available moved from %s to %s when P-002 issued the stock", av1, av1b)
	}
	if !av2.Sub(av2b).Equal(amt) {
		t.Errorf("P-002 available fell by %s, want the issue value %s", av2.Sub(av2b), amt)
	}
}

// ---------------------------------------------------------------------------
// R7-F9 posture check.
// ---------------------------------------------------------------------------
func TestR8_PostureCheck(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	var role string
	must(t, "role", w.raw(func(ctx context.Context, tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT current_user`).Scan(&role) }))
	issues, err := f.app.Posture(f.ctx)
	must(t, "posture", err)
	var supers []string
	rows, err := f.admin.Query(f.ctx, `SELECT rolname FROM pg_roles WHERE rolsuper`)
	must(t, "supers", err)
	supers, err = pgx.CollectRows(rows, pgx.RowTo[string])
	must(t, "supers rows", err)
	t.Logf("posture with TEMP revoked from PUBLIC and from %s: %q; superusers %v", role, issues, supers)
	for _, s := range issues {
		for _, su := range supers {
			if strings.HasSuffix(s, " "+su) {
				r8open(t, "the posture check reports superuser %q as a tenant login (%q); cmd/serk-api exits in production whenever it reports anything", su, s)
			}
		}
	}

	// CREATE on a schema gives the same trigger-depth bypass as TEMP.
	cleanup := func() {
		_, _ = f.admin.Exec(f.ctx, `DROP TABLE IF EXISTS public.r8_depth`)
		_, _ = f.admin.Exec(f.ctx, `DROP FUNCTION IF EXISTS public.r8_depth_fn()`)
		_, _ = f.admin.Exec(f.ctx, fmt.Sprintf(`REVOKE CREATE ON SCHEMA public FROM %q`, role))
	}
	defer cleanup()
	if _, err := f.admin.Exec(f.ctx, fmt.Sprintf(`GRANT CREATE ON SCHEMA public TO %q`, role)); err != nil {
		t.Skipf("cannot grant CREATE: %v", err)
	}
	issues2, err := f.app.Posture(f.ctx)
	must(t, "posture 2", err)
	err = w.raw(func(ctx context.Context, tx pgx.Tx) error {
		for _, s := range []string{
			`CREATE TABLE public.r8_depth(x int)`,
			`CREATE FUNCTION public.r8_depth_fn() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN
			   UPDATE public.stock_balances SET qty = qty + 1000, value = value + 1; RETURN NEW; END $f$`,
			`CREATE TRIGGER r8_depth_t AFTER INSERT ON public.r8_depth FOR EACH ROW EXECUTE FUNCTION public.r8_depth_fn()`,
			`INSERT INTO public.r8_depth VALUES (1)`,
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%.40s: %w", s, err)
			}
		}
		return nil
	})
	q, v := w.balanceOf(t, w.itemSteel)
	mentions := false
	for _, s := range issues2 {
		if strings.Contains(s, role) {
			mentions = true
		}
	}
	t.Logf("with CREATE on schema public granted to %s: posture %q; trigger write: %v; steel now %s t at %s", role, issues2, err, q, v)
	if err == nil && q.GreaterThan(dec("12")) && !mentions {
		r8open(t, "(conditional) with CREATE on a schema, the tenant login wrote stock_balances (+1,000 t) through its own trigger and the posture check did not name it")
	}
	cleanup()

	// Advisory locks: only one overload is checked.
	fn := `pg_catalog.pg_try_advisory_xact_lock(bigint)`
	defer f.admin.Exec(f.ctx, `REVOKE EXECUTE ON FUNCTION `+fn+` FROM PUBLIC`)
	if _, err := f.admin.Exec(f.ctx, `GRANT EXECUTE ON FUNCTION `+fn+` TO PUBLIC`); err != nil {
		t.Skipf("cannot grant: %v", err)
	}
	issues3, err := f.app.Posture(f.ctx)
	must(t, "posture 3", err)
	var got bool
	errLock := w.raw(func(ctx context.Context, tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(727002)`).Scan(&got) })
	t.Logf("with %s executable by PUBLIC: posture %q; tenant login takes it: %v %v", fn, issues3, got, errLock)
	if errLock == nil && got && len(issues3) == len(issues) {
		r8open(t, "(conditional) a tenant login takes advisory lock 727002 (the relay leader lock) through %s and the posture check reports nothing new", fn)
	}
}

// ---------------------------------------------------------------------------
// Human-only decisions, draft-action parity, scope of the new documents.
// ---------------------------------------------------------------------------
func TestR8_HumanDecisionsAndScope(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "4000", "300", "20")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	cn, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv, dec("1000"), today(), "Small concession for scope probes")
	must(t, "credit", err)
	rel, err := f.svc.RecordRetentionRelease(f.ctx, w.ar.arClerk, ctr, w.release("1000", "NEGOTIATED", "ERA-NEG-01"))
	must(t, "release", err)
	for _, k := range []string{auth.KindAI, auth.KindService} {
		p := w.mfa(c.commercial)
		p.Kind, p.UserID = k, "u-cm-"+k
		_, err := f.svc.ApproveCreditNote(f.ctx, p, cn)
		r8refused(t, "credit note approval by a "+k+" principal", err)
		_, err = f.svc.ApproveRetentionRelease(f.ctx, p, rel)
		r8refused(t, "release approval by a "+k+" principal", err)
	}
	for _, a := range []string{"ar.credit.create", "ar.credit.approve", "ar.credit.cancel", "ar.retention.create", "ar.retention.approve", "ar.retention.cancel",
		"stock.transfer.create", "stock.transfer.approve", "stock.transfer.reject", "stock.transfer.cancel", "stock.receipt.create"} {
		var sqlDraft bool
		must(t, "draft", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT approval_is_draft_action($1)`, a).Scan(&sqlDraft)
		}))
		if sqlDraft != auth.IsDraftAction(a) {
			r8open(t, "draft-action disagreement for %s: Go %v SQL %v", a, auth.IsDraftAction(a), sqlDraft)
		}
	}
	t.Logf("held: Go IsDraftAction and SQL approval_is_draft_action agree on the 11 new/changed actions")
	other := w.mfa(r8principal(f, "u-cm-other", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, "commercial_manager"))
	for _, x := range []struct{ typ, id string }{{"customer_credit_note", cn}, {"retention_release", rel}} {
		_, errD := f.svc.GetP2PDoc(f.ctx, other, x.typ, x.id)
		l, errL := f.svc.ListP2PDocs(f.ctx, other, x.typ, "", 50)
		if errD == nil || len(l) > 0 {
			r8open(t, "another project's commercial manager sees %s: detail %v, list %d rows", x.typ, errD, len(l))
		} else {
			r8held(t, "%s of P-001 invisible to another project's manager: detail %v; list %d rows %v", x.typ, errD, len(l), errL)
		}
	}
	_, err = f.svc.ApproveCreditNote(f.ctx, other, cn)
	r8refused(t, "approval by another project's commercial manager", err)
	for _, x := range []struct{ typ, id string }{{"customer_credit_note", cn}, {"retention_release", rel}} {
		for _, p := range []auth.Principal{w.ar.arClerk, c.commercial, c.controller} {
			d, err := f.svc.GetP2PDoc(f.ctx, p, x.typ, x.id)
			l, errL := f.svc.ListP2PDocs(f.ctx, p, x.typ, "", 50)
			if err != nil || errL != nil || len(l) == 0 {
				r8open(t, "%s cannot read %s: detail %v, list %d %v", p.UserID, x.typ, err, len(l), errL)
			} else {
				r8held(t, "%s reads %s (status %s) and lists %d", p.UserID, x.typ, d.Status, len(l))
			}
		}
	}
	clerk2 := r8principal(f, "u-ar-clerk-2", nil, "ar_clerk")
	if err := f.svc.CancelCreditNote(f.ctx, clerk2, cn, "Withdrawn by a colleague"); err == nil {
		t.Logf("info: a second AR clerk (not the issuer, not an approver) cancelled credit note %s (stock transfers allow only the preparer)", cn[:8])
	}
	if err := f.svc.CancelRetentionRelease(f.ctx, clerk2, rel, "Withdrawn by a colleague"); err == nil {
		t.Logf("info: a second AR clerk cancelled retention release %s", rel[:8])
	}
}

// R7-F5 completeness: an undesignated PO line is still put away as any item on its first put-away.
func TestR8_PutAwayUndesignatedLine(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	other, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: "CU-WIRE-16", Name: "Copper wire 16mm2", Unit: "t",
		ValuationMethod: "FIFO", InventoryAccountID: w.acct["1200"]})
	must(t, "item", err)
	must(t, "approve item", f.svc.ApproveStockItem(f.ctx, c.finMgr, other))
	po := w.inventoryPOUndesignated(t)
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	if _, err := f.svc.PutAway(f.ctx, c.store, grn, 1, other, w.store, dec("12")); err == nil {
		q, v := w.balanceOf(t, other)
		r8open(t, "PO line 1 'Reinforcement steel Grade 60' (no designated item) put away by the storekeeper as CU-WIRE-16: %s t valued %s, no checker", q, v)
	} else {
		r8held(t, "%v", err)
	}
	// The 0028 designation path: never raw, never by an AI or service
	// principal, never an item that does not match the line.
	r8refused(t, "raw designation of the line by the tenant role without attestation",
		w.rawExec(`UPDATE po_lines SET stock_item_id = $2::uuid WHERE po_id = $1::uuid AND line_no = 1`, po, w.itemSteel))
	for _, k := range []string{auth.KindAI, auth.KindService} {
		p := c.buyer
		p.Kind, p.UserID = k, "u-buyer-"+k
		r8refused(t, "designation by a "+k+" principal", f.svc.DesignatePOLineItem(f.ctx, p, po, 1, w.itemSteel))
	}
	if auth.IsDraftAction("po.line.designate") {
		r8open(t, "po.line.designate is a draft action in Go")
	}
	var sqlDraft bool
	must(t, "sql draft", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT approval_is_draft_action('po.line.designate')`).Scan(&sqlDraft)
	}))
	if sqlDraft {
		r8open(t, "po.line.designate is a draft action in SQL")
	}
	r8refused(t, "designating the cement item (bags, other account rules) on the steel line",
		f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 1, w.itemCement))
	must(t, "designate steel", f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 1, w.itemSteel))
	_, err = f.svc.PutAway(f.ctx, c.store, grn, 1, w.itemSteel, w.store, dec("12"))
	must(t, "put-away after designation", err)
	r8refused(t, "re-designation after put-away", f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 1, other))
}

// ---------------------------------------------------------------------------
// Transfers: closed period at approval; concurrent transfers of the whole
// balance; a transfer racing a destination count.
// ---------------------------------------------------------------------------
func TestR8_TransferLifecycleAndRaces(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pmgr := r8principal(f, "u-proc-manager", []string{f.project}, "procurement_manager")
	storeB, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Second store")
	must(t, "store B", err)
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	w.putAway(t, grn, 2, w.itemCement, "300")
	req := func(item, from, to, qty string) string {
		t.Helper()
		id, err := f.svc.CreateStockTransfer(f.ctx, c.store, StockTransferInput{StockItemID: item, FromWarehouseID: from, ToWarehouseID: to, Quantity: dec(qty), TransferDate: today()})
		must(t, "transfer", err)
		return id
	}
	// two transfers of the whole steel balance, approved concurrently
	a, b := req(w.itemSteel, w.store, storeB, "12"), req(w.itemSteel, w.store, storeB, "12")
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = f.svc.ApproveStockTransfer(f.ctx, w.invCtl, a) }()
	go func() { defer wg.Done(); errs[1] = f.svc.ApproveStockTransfer(f.ctx, w.invCtl, b) }()
	wg.Wait()
	qB := w.stockValue(t, `SELECT COALESCE(sum(qty),0) FROM stock_balances WHERE warehouse_id=$1::uuid AND stock_item_id=$2::uuid`, storeB, w.itemSteel)
	if (errs[0] == nil) == (errs[1] == nil) || !qB.Equal(dec("12")) {
		r8open(t, "concurrent transfers of the whole balance: %v / %v; B holds %s t", errs[0], errs[1], qB)
	} else {
		r8held(t, "concurrent whole-balance transfers: one approved, the other %v; B holds %s t", firstErr(errs), qB)
	}
	// a count at the destination, then a transfer into it: the count is stale
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: storeB, StockItemID: w.itemCement, CountedQty: dec("5"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count at B", err)
	must(t, "transfer cement in", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, req(w.itemCement, w.store, storeB, "100")))
	_, err = f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
	r8refused(t, "a destination count recorded before an incoming transfer (stale)", err)
	for _, p := range []auth.Principal{c.store, w.invCtl, c.controller} {
		d, err := f.svc.GetP2PDoc(f.ctx, p, "stock_transfer", a)
		l, errL := f.svc.ListP2PDocs(f.ctx, p, "stock_transfer", "", 50)
		if err != nil || errL != nil || len(l) == 0 {
			r8open(t, "%s cannot read stock_transfer: detail %v, list %d %v", p.UserID, err, len(l), errL)
		} else {
			r8held(t, "%s reads stock_transfer (status %s) and lists %d", p.UserID, d.Status, len(l))
		}
	}
	// closed period between request and approval
	late := req(w.itemCement, w.store, storeB, "10")
	_, err = f.svc.ClosePeriod(f.ctx, f.post, f.period(t), false)
	must(t, "close period", err)
	r8refused(t, "transfer approval after its period closed", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, late))
	b2, l2, d2 := w.invariants(t)
	if !b2.Equal(l2) || !b2.Equal(d2) {
		r8open(t, "invariants after races: balances %s layers %s documents %s", b2, l2, d2)
	}
}

// R7-F4 netting is by amount, not by where the issued stock came from: stock
// that did not come from the cost code's commitment (here a count surplus)
// is issued to the code without reducing its available budget.
func TestR8_BudgetNettingByCount(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	position := func() (committed, actual, available decimal.Decimal) {
		must(t, "cost position", w.raw(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT committed, actual_other, available FROM p2p_cost_position($1::uuid, NULL, NULL)`, w.costCode).Scan(&committed, &actual, &available)
		}))
		return
	}
	c0, a0, av0 := position()
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("17"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "surplus count", err)
	jc, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
	must(t, "approve surplus", err)
	w.financePost(t, jc)
	amt := w.issueApprovePost(t, w.itemSteel, "17")
	c1, a1, av1 := position()
	t.Logf("before: committed %s actual %s available %s; surplus 5 t found and all 17 t issued to 01-MAT (%s): committed %s actual %s available %s",
		c0, a0, av0, amt, c1, a1, av1)
	if av1.Equal(av0) {
		r8open(t, "01-MAT consumed %s of stock (12 t received + 5 t surplus) while 8 t of its PO are still open, yet its available budget is unchanged at %s: committed fell %s -> %s",
			amt, av1, c0, c1)
	} else {
		r8held(t, "available %s -> %s", av0, av1)
	}
}

// Surplus valuation after a transfer: "this warehouse first" picks the
// warehouse's own (older) receipt, not the cost of what the warehouse holds.
func TestR8_SurplusCostAfterTransfer(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pmgr := r8principal(f, "u-proc-manager", []string{f.project}, "procurement_manager")
	storeB, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Second store")
	must(t, "store B", err)
	po1 := w.inventoryPO(t, "20", "500", "84500", "940")
	g1, j1 := w.receipt(t, po1, GRNLine{POLineNo: 1, QtyReceived: dec("2")})
	po2 := w.inventoryPO(t, "20", "500", "120000", "940")
	g2, j2 := w.receipt(t, po2, GRNLine{POLineNo: 1, QtyReceived: dec("10")})
	w.financePost(t, j1, j2)
	w.putAway(t, g1, 1, w.itemSteel, "2")
	if _, err := f.svc.PutAway(f.ctx, c.store, g2, 1, w.itemSteel, storeB, dec("10")); err != nil {
		t.Fatal(err)
	}
	w.issueApprovePost(t, w.itemSteel, "2") // A's own 84,500 stock is gone
	tr, err := f.svc.CreateStockTransfer(f.ctx, c.store, StockTransferInput{StockItemID: w.itemSteel, FromWarehouseID: storeB, ToWarehouseID: w.store, Quantity: dec("10"), TransferDate: today()})
	must(t, "transfer", err)
	must(t, "approve", f.svc.ApproveStockTransfer(f.ctx, w.invCtl, tr))
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("11"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count", err)
	unit := w.stockValue(t, `SELECT surplus_unit_cost FROM stock_counts WHERE id=$1::uuid`, ct)
	layers := w.stockValue(t, `SELECT min(unit_cost) FROM stock_layers WHERE warehouse_id=$1::uuid AND stock_item_id=$2::uuid AND qty_remaining > 0`, w.store, w.itemSteel)
	t.Logf("info: store A holds only transferred layers at %s; a surplus there is valued at %s (A's own older receipt), the latest receipt of the item is 120000", layers, unit)
}
