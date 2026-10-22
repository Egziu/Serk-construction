package kernel

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// JB-CREDIT-QTY (0033). Line 3: 120 t of steel at 98,000. The surveyor
// measures 60 t when only 50 t is in place; IPC 1 certifies 60 t. The
// over-measurement is corrected by a quantity-correction credit note for
// 10 t (980,000). The remaining 70 t of real work must then be measurable
// (the cap is 120 t net of the credit), and the client must be billed, over
// the whole job, exactly 120 t: 60 t + 70 t certified, 10 t credited.
func TestCreditQuantityCorrection_NoDoubleDeduction(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	w.activeContract(t)
	w.measure(t, 10, "0", "0", "60")
	ipc1 := w.certifiedIPC(t, 10, "ERA-IPC-01")
	inv1, _ := w.approvedInvoice(t, ipc1)
	ipcOf := func(id string) (cum, prev, this decimal.Decimal) {
		must(t, "ipc", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT cumulative_gross, previous_gross, this_gross FROM ipcs WHERE id = $1::uuid`, id).Scan(&cum, &prev, &this)
		}))
		return
	}
	cum1, _, this1 := ipcOf(ipc1)
	if !this1.Equal(dec("5880000")) {
		t.Fatalf("IPC 1 this %s, want 5,880,000 (60 t)", this1)
	}

	// Controls on the correction itself.
	if _, err := f.svc.IssueQuantityCorrection(f.ctx, w.ar.arClerk, inv1, 3, dec("61"), today(), "More than was ever measured"); err == nil {
		t.Errorf("correction beyond the verified quantity accepted")
	}
	if _, err := f.svc.IssueQuantityCorrection(f.ctx, w.ar.arClerk, inv1, 9, dec("1"), today(), "A line that does not exist"); err == nil {
		t.Errorf("correction on a missing line accepted")
	}
	raw := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO customer_credit_notes(legal_entity_id, project_id, contract_id, customer_id, invoice_id, policy_id, number, credit_date, currency, net_amount, reason, created_by, kind, correction_line_no, correction_qty)
			SELECT i.legal_entity_id, i.project_id, i.contract_id, i.customer_id, i.id, i.policy_id, 'CRN-RAW', current_date, i.currency, 1, 'Mispriced correction', 'u-ar-clerk', 'QUANTITY_CORRECTION', 3, 10
			  FROM customer_invoices i WHERE i.id = $1::uuid`, inv1)
		return err
	})
	if raw == nil || !strings.Contains(raw.Error(), "the net amount must be") {
		t.Errorf("a quantity correction priced below the line rate: %v", raw)
	}

	cn, err := f.svc.IssueQuantityCorrection(f.ctx, w.ar.arClerk, inv1, 3, dec("10"), today(), "Re-survey: 10 t of steel measured in IPC 1 was not in place")
	must(t, "quantity correction", err)
	var net, total string
	must(t, "credit", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT net_amount::text, total::text FROM customer_credit_notes WHERE id = $1::uuid`, cn).Scan(&net, &total)
	}))
	if !decimal.RequireFromString(net).Equal(dec("980000")) {
		t.Errorf("correction net %s, want 980,000 (10 t x 98,000)", net)
	}
	// Before approval nothing changes: the remaining 70 t cannot all be measured.
	if id, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, w.contract, today(), []MeasurementLine{{3, dec("70"), "Km 14+500 to 16+000"}}); err == nil {
		if err := f.svc.SubmitMeasurement(f.ctx, w.ar.qs, id); err == nil {
			if err := f.svc.DecideMeasurement(f.ctx, c.siteEng, id, true, ""); err == nil {
				t.Fatalf("70 t verified while the correction is still a draft: 130 t > 120 t")
			}
		}
	}
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cn)
	must(t, "approve correction", err)
	t.Logf("correction approved: net %s total %s", net, total)

	// With the correction approved, the verified quantity of line 3 is 50 t;
	// an IPC now certifies nothing more (the credit already settled it)...
	var verified decimal.Decimal
	must(t, "verified", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT contract_verified_qty($1::uuid, 3, NULL)`, w.contract).Scan(&verified)
	}))
	if !verified.Equal(dec("50")) {
		t.Errorf("verified quantity after the correction %s, want 50", verified)
	}
	if _, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, w.contract, today()); err == nil || !strings.Contains(err.Error(), "nothing to certify") {
		t.Errorf("an IPC right after the correction: %v (want 'nothing to certify': the credit settled it)", err)
	}
	var cum2, prev2, this2 decimal.Decimal
	must(t, "compute", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT cumulative_gross, previous_gross, this_gross FROM ipc_compute($1::uuid, NULL)`, w.contract).Scan(&cum2, &prev2, &this2)
	}))
	if !this2.IsZero() || !cum2.Equal(dec("4900000")) || !prev2.Equal(dec("4900000")) {
		t.Errorf("certificate after the correction: cumulative %s previous %s this %s; want 4,900,000 / 4,900,000 / 0 (no second deduction, no re-billing)", cum2, prev2, this2)
	}

	// ...and the remaining 70 t of real work is measurable up to the 120 t cap.
	w.measure(t, 20, "0", "0", "70")
	if id, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, w.contract, today(), []MeasurementLine{{3, dec("1"), "Beyond the contract"}}); err == nil {
		if err := f.svc.SubmitMeasurement(f.ctx, w.ar.qs, id); err == nil {
			if err := f.svc.DecideMeasurement(f.ctx, c.siteEng, id, true, ""); err == nil {
				t.Errorf("121 t verified against a 120 t line")
			}
		}
	}
	ipc2 := w.certifiedIPC(t, 20, "ERA-IPC-02")
	cum3, prev3, this3 := ipcOf(ipc2)
	if !this3.Equal(dec("6860000")) {
		t.Errorf("IPC 2 this %s, want 6,860,000 (70 t)", this3)
	}
	// Billed over the job: IPC 1 + IPC 2 - credit = 60 + 70 - 10 = 120 t.
	billed := this1.Add(this3).Sub(dec("980000"))
	if !billed.Equal(dec("11760000")) {
		t.Errorf("billed over the job %s, want 11,760,000 (120 t)", billed)
	}
	t.Logf("IPC 1 cumulative %s this %s; after correction cumulative %s; IPC 2 cumulative %s previous %s this %s; billed net of credit %s",
		cum1, this1, cum2, cum3, prev3, this3, billed)

	// A commercial credit note has no quantity effect.
	inv2, _ := w.approvedInvoice(t, ipc2)
	cc, err := f.svc.IssueCreditNote(f.ctx, w.ar.arClerk, inv2, dec("1000"), today(), "Goodwill settlement")
	must(t, "commercial credit", err)
	_, err = f.svc.ApproveCreditNote(f.ctx, w.mfa(c.commercial), cc)
	must(t, "approve commercial", err)
	must(t, "verified 2", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT contract_verified_qty($1::uuid, 3, NULL)`, w.contract).Scan(&verified)
	}))
	if !verified.Equal(dec("120")) {
		t.Errorf("a commercial credit changed the verified quantity: %s", verified)
	}
}
