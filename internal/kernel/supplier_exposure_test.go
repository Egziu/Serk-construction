package kernel

import (
	"sync"
	"testing"
)

// R-SPLIT-SUPPLIER: dual approval is decided on the supplier's exposure, not
// only on one payment or one invoice (migration 0016).
func TestSupplierExposureNeedsDualApproval(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	// Three invoices of 4 t each (388,700 incl. VAT), all below the 500,000 threshold.
	var invs []string
	for i, n := range []string{"SPLIT-1", "SPLIT-2", "SPLIT-3"} {
		_, _, inv, _ := w.r3invoice(t, po, "4", n)
		invs = append(invs, inv)
		_ = i
	}
	pay := func(inv string, daysAhead int) string {
		t.Helper()
		id, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today().AddDate(0, 0, daysAhead), []Allocation{{inv, dec("388700")}})
		must(t, "prepare", err)
		must(t, "submit", f.svc.SubmitPayment(f.ctx, c.treasury, id))
		return id
	}
	// First payment alone: exposure 388,700 < 500,000 -> one approver.
	p1 := pay(invs[0], 0)
	if st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, p1); err != nil || st != "APPROVED" {
		t.Fatalf("first payment: %s %v, want APPROVED by one approver", st, err)
	}
	// Second payment to the same supplier within the window: exposure 777,400 -> two approvers.
	p2 := pay(invs[1], 3)
	st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, p2)
	if err != nil || st != "PARTIALLY_APPROVED" {
		t.Fatalf("second payment within the window: %s %v, want PARTIALLY_APPROVED", st, err)
	}
	t.Logf("held: second payment to the same supplier within 30 days needs a second approver (%s)", st)
	// A single approval forced through raw SQL is refused by the database.
	p3 := pay(invs[2], 5)
	err = f.rawAs(c.finMgr, "payment.approve", "payment_instruction", p3, "APPROVED",
		`UPDATE payment_instructions SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, p3)
	wantErr(t, "raw single approval of a split payment", err, "two")
	if st, err := f.svc.ApprovePayment(f.ctx, c.cfo, p2); err != nil || st != "APPROVED" {
		t.Errorf("second approver: %s %v", st, err)
	}
}

func TestSupplierExposureWindowAndConcurrency(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv1, _ := w.r3invoice(t, po, "4", "WIN-1")
	_, _, inv2, _ := w.r3invoice(t, po, "4", "WIN-2")
	mk := func(inv string, days int) string {
		id, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today().AddDate(0, 0, days), []Allocation{{inv, dec("388700")}})
		must(t, "prepare", err)
		must(t, "submit", f.svc.SubmitPayment(f.ctx, c.treasury, id))
		return id
	}
	// Two payments submitted together within the window: each sees the other.
	a, b := mk(inv1, 0), mk(inv2, 1)
	var wg sync.WaitGroup
	sts := make([]string, 2)
	errs := make([]error, 2)
	for i, id := range []string{a, b} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sts[i], errs[i] = f.svc.ApprovePayment(f.ctx, c.finMgr, id)
		}(i, id)
	}
	wg.Wait()
	for i := range sts {
		if errs[i] == nil && sts[i] == "APPROVED" {
			t.Errorf("concurrent payment %d single-approved while the supplier's exposure is 777,400", i+1)
		} else {
			t.Logf("held: concurrent payment %d: %s %v", i+1, sts[i], errs[i])
		}
	}
	// Outside the policy window, payments are judged separately again.
	_, _, inv3, _ := w.r3invoice(t, po, "4", "WIN-3")
	far := mk(inv3, 45)
	_ = far
	// The two earlier payments are still live and within 45±30? No: |45-0|, |45-1| >= 30.
	if st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, far); err != nil || st != "APPROVED" {
		t.Errorf("payment 45 days later: %s %v, want one approver", st, err)
	}
}
