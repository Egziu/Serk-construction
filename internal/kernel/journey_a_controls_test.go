package kernel

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// Journey A controls: each test attacks one rule, through the kernel (the
// API path) or as raw tenant SQL (a compromised DB credential).

func wantErr(t *testing.T, what string, err error, contains ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("CONTROL FAILED: %s succeeded", what)
		return
	}
	for _, c := range contains {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("%s: refused for an unexpected reason: %v (want %q)", what, err, c)
			return
		}
	}
	t.Logf("refused %-60s %s", what+":", firstLine(err.Error()))
}

func TestJourneyA_SegregationOfDutiesAndBudget(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	// Maker cannot approve their own BOQ, even holding both roles.
	both := c.estimator
	both.UserID, both.Roles = "u-both", []string{"estimator", "commercial_manager"}
	boq, err := f.svc.CreateBOQ(f.ctx, both, f.project, "Self-approved BOQ", []BOQItem{{ItemNo: "1", Description: "Steel", Unit: "t", Quantity: dec("1"), Rate: dec("1000"), CostCodeID: w.costCode}})
	must(t, "boq", err)
	must(t, "submit", f.svc.SubmitBOQ(f.ctx, both, boq))
	wantErr(t, "BOQ approved by its author", f.svc.DecideBOQ(f.ctx, both, boq, true, ""), "segregation")
	// ...nor through raw SQL with a genuine attestation for themselves.
	wantErr(t, "raw self-approval of the BOQ with a genuine attestation",
		f.rawAs(both, "boq.decide", "boq_version", boq, "APPROVED", `UPDATE boq_versions SET status='APPROVED', approved_by='u-both' WHERE id=$1::uuid`, boq), "boq_maker_checker")
	must(t, "reject", f.svc.DecideBOQ(f.ctx, c.commercial, boq, false, "superseded by the full BOQ"))
	w.approvedBOQ(t)

	// A requisition above the available budget is refused (budget 12.1m).
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Oversized order", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("200"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	err = f.svc.DecidePR(f.ctx, c.pm, pr, true, "")
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("over-budget PR: %v", err)
	}
	// Raw approval with a genuine attestation is refused by the database's own budget check.
	wantErr(t, "raw approval of an over-budget PR", f.rawAs(c.pm, "pr.decide", "purchase_requisition", pr, "APPROVED",
		`UPDATE purchase_requisitions SET status='APPROVED', approved_by='u-pm' WHERE id=$1::uuid`, pr), "exceeds the approved BOQ budget")
	// The requester cannot approve their own PR.
	pr2, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Small order", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")}})
	must(t, "pr2", err)
	must(t, "submit2", f.svc.SubmitPR(f.ctx, c.siteEng, pr2))
	selfPM := c.siteEng
	selfPM.Roles = []string{"site_engineer", "project_manager"}
	wantErr(t, "PR approved by its requester", f.svc.DecidePR(f.ctx, selfPM, pr2, true, ""), "segregation")
	// Someone without project scope sees nothing.
	outsider := c.pm
	outsider.UserID, outsider.ProjectIDs = "u-other-pm", []string{"00000000-0000-0000-0000-000000000000"}
	if err := f.svc.DecidePR(f.ctx, outsider, pr2, true, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("out-of-scope PM: %v", err)
	}
}

func TestJourneyA_ProcurementRules(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Steel", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("10"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	// Fewer than 3 suppliers without a single-source justification.
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 3, "", w.sup[:1])
	must(t, "rfq", err)
	wantErr(t, "RFQ issued to 1 supplier without justification", f.svc.IssueRFQ(f.ctx, c.buyer, rfq), "at least 3 suppliers")
	must(t, "cancel", f.p2pRawCancelRFQ(t, rfq))
	rfq, err = f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 3, "", w.sup[:])
	must(t, "rfq2", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	valid := time.Now().AddDate(0, 1, 0)
	q0, _ := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[0], valid, "", []QuoteLine{{1, dec("88000")}})
	q1, _ := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[1], valid, "", []QuoteLine{{1, dec("84000")}})
	// The buyer cannot evaluate the quotes they recorded.
	evalBuyer := c.buyer
	evalBuyer.Roles = []string{"procurement_officer", "site_engineer"}
	wantErr(t, "quote evaluated by the person who recorded it", f.svc.EvaluateQuote(f.ctx, evalBuyer, q0, true, ""), "segregation")
	must(t, "eval0", f.svc.EvaluateQuote(f.ctx, c.siteEng, q0, true, ""))
	must(t, "eval1", f.svc.EvaluateQuote(f.ctx, c.siteEng, q1, true, ""))
	// Not the lowest compliant quote without a documented reason.
	wantErr(t, "award to a dearer compliant quote without a reason", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q0, ""), "lowest compliant")
	// A quote total cannot be rewritten by tenant SQL (recomputed from lines).
	if err := f.rawExec(`UPDATE rfq_quotes SET total = 1 WHERE id = $1::uuid`, q0); err == nil {
		if tot := f.scalar(t, `SELECT total::text FROM rfq_quotes WHERE id=$1::uuid`, q0); tot != "880000.000000" {
			t.Errorf("quote total rewritten to %s", tot)
		}
	}
	must(t, "award with reason", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q0, "Supplier 2 cannot deliver before the slab pour date"))
	// PO line price must equal the award: tenant SQL raising its own PO with
	// a line at 1 ETB/t is refused.
	wantErr(t, "raw PO with a line at a price other than the award", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var raw string
		if err := tx.QueryRow(ctx, `INSERT INTO purchase_orders(legal_entity_id, project_id, number, rfq_id, quote_id, supplier_id, currency, created_by)
			VALUES ($1::uuid, $2::uuid, 'PO-RAW-1', $3::uuid, $4::uuid, $5::uuid, 'ETB', 'u-buyer') RETURNING id::text`, f.entity, f.project, rfq, q0, w.sup[0]).Scan(&raw); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO po_lines(po_id, line_no, legal_entity_id, cost_code_id, account_id, description, unit, quantity, unit_price)
			VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'Steel', 't', 10, 1)`, raw, f.entity, w.costCode, w.acct["5000"])
		return err
	}), "awarded price")
	po, err := f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["5000"]})
	must(t, "po", err)
	// The buyer cannot approve their own PO.
	selfApprover := c.buyer
	selfApprover.Roles = []string{"procurement_officer", "procurement_manager"}
	wantErr(t, "PO approved by its author", f.svc.ApprovePO(f.ctx, selfApprover, po, ""), "segregation")
	must(t, "po approve", f.svc.ApprovePO(f.ctx, c.procMgr, po, ""))
	// Approved PO content is frozen.
	// (the guard recomputes the total from the lines, so the statement is a no-op)
	_ = f.rawExec(`UPDATE purchase_orders SET total = 1 WHERE id=$1::uuid`, po)
	if tot := f.scalar(t, `SELECT total::text FROM purchase_orders WHERE id=$1::uuid`, po); tot != "880000.000000" {
		t.Errorf("approved PO total rewritten to %s", tot)
	}
	wantErr(t, "raw re-pointing of an approved PO to another supplier", f.rawExec(`UPDATE purchase_orders SET approved_by = 'u-someone' WHERE id=$1::uuid`, po), "cannot be changed")
}

func (f *fixture) p2pRawCancelRFQ(t *testing.T, rfq string) error {
	t.Helper()
	return f.rawAs(auth.Principal{Kind: auth.KindHuman, UserID: "u-buyer", TenantID: f.tenant, Roles: []string{"procurement_officer"}, ProjectIDs: []string{f.project}},
		"rfq.cancel", "rfq", rfq, "", `UPDATE rfqs SET status='CANCELLED' WHERE id=$1::uuid`, rfq)
}

func TestJourneyA_ReceiptAndMatchingControls(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	// Over-receipt beyond the 5% tolerance is refused at confirmation.
	g, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now(), "DN-1", []GRNLine{{POLineNo: 1, QtyReceived: dec("21.5")}})
	must(t, "grn", err)
	must(t, "grn submit", f.svc.SubmitGRN(f.ctx, c.store, g))
	_, err = f.svc.ConfirmGRN(f.ctx, c.siteEng, g)
	wantErr(t, "receipt of 21.5 t against 20 t ordered (5% tolerance)", err, "over-receipt tolerance")
	// The storekeeper cannot confirm their own receipt.
	selfConfirm := c.store
	selfConfirm.Roles = []string{"storekeeper", "site_engineer"}
	_, err = f.svc.ConfirmGRN(f.ctx, selfConfirm, g)
	wantErr(t, "receipt confirmed by the storekeeper who recorded it", err, "segregation")
	// A receipt journal with different accounting is refused by the database.
	g2, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now(), "DN-2", []GRNLine{{POLineNo: 1, QtyReceived: dec("10")}})
	must(t, "grn2", err)
	must(t, "grn2 submit", f.svc.SubmitGRN(f.ctx, c.store, g2))
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.siteEng, "grn.confirm", "grn", g2, "CONFIRMED"); err != nil {
			return err
		}
		// A journal valued at 1 instead of 845,000.
		var jid string
		if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id, legal_entity_id, project_id, functional_currency, business_event_at, description, source_type, source_ref, idempotency_key, command_hash, created_by)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'ETB', current_date::timestamp AT TIME ZONE 'UTC', 'x', 'P2P_GRN', $4, 'forged-grn', 'x', 'u-site-engineer') RETURNING id::text`,
			f.tenant, f.entity, f.project, g2).Scan(&jid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id, tenant_id, legal_entity_id, line_no, account_id, side, amount, currency, project_id, cost_code_id) VALUES
			($1::uuid, $2::uuid, $3::uuid, 1, $4::uuid, 'DEBIT', 1, 'ETB', $5::uuid, $6::uuid), ($1::uuid, $2::uuid, $3::uuid, 2, $7::uuid, 'CREDIT', 1, 'ETB', $5::uuid, NULL)`,
			jid, f.tenant, f.entity, w.acct["5000"], f.project, w.costCode, w.acct["2100"]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE grns SET status='CONFIRMED', confirmed_by='u-site-engineer', journal_id=$2::uuid WHERE id=$1::uuid`, g2, jid)
		return err
	})
	wantErr(t, "receipt confirmed with a journal that undervalues it", err, "do not equal the accounting")
	_, err = f.svc.ConfirmGRN(f.ctx, c.siteEng, g2)
	must(t, "grn2 confirm", err)

	// Billing more than received is refused (hard stop, not approvable).
	inv, err := f.svc.EnterInvoice(f.ctx, c.apClerk, InvoiceInput{POID: po, InvoiceNumber: "INV-9", InvoiceDate: today(), DueDate: today(),
		Subtotal: dec("1014000"), TaxAmount: dec("152100"), Total: dec("1166100"), Lines: []InvoiceLine{{1, dec("12"), dec("84500")}}})
	must(t, "enter", err)
	_, err = f.svc.SubmitInvoice(f.ctx, c.apClerk, inv)
	wantErr(t, "invoice for 12 t when 10 t were received", err, "exceeds confirmed receipts")
	// Wrong VAT arithmetic is refused.
	inv2, err := f.svc.EnterInvoice(f.ctx, c.apClerk, InvoiceInput{POID: po, InvoiceNumber: "INV-10", InvoiceDate: today(), DueDate: today(),
		Subtotal: dec("845000"), TaxAmount: dec("120000"), Total: dec("965000"), Lines: []InvoiceLine{{1, dec("10"), dec("84500")}}})
	must(t, "enter2", err)
	_, err = f.svc.SubmitInvoice(f.ctx, c.apClerk, inv2)
	wantErr(t, "invoice whose VAT is not subtotal x policy rate", err, "tax")
	// Price 3% above the PO: EXCEPTION. AP supervisor cannot approve it; the
	// exception approver needs ap.approve_exception + MFA + reason.
	inv3, m := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "INV-11", InvoiceDate: today(), DueDate: today(),
		Subtotal: dec("870350"), TaxAmount: dec("130552.50"), Total: dec("1000902.50"), Lines: []InvoiceLine{{1, dec("10"), dec("87035")}}})
	if m != "EXCEPTION" {
		t.Fatalf("3%% price variance matched as %s", m)
	}
	_, err = f.svc.ApproveInvoice(f.ctx, c.apSup, inv3, "")
	wantErr(t, "AP supervisor approving a price exception", err, "ap.approve_exception")
	senior := c.apSup
	senior.UserID, senior.Roles = "u-ap-manager", []string{"ap_supervisor", "finance_manager"}
	_, err = f.svc.ApproveInvoice(f.ctx, senior, inv3, "ok")
	wantErr(t, "exception approval without MFA", err, "multi-factor")
	senior.MFA, senior.AuthTime = true, time.Now()
	_, err = f.svc.ApproveInvoice(f.ctx, senior, inv3, "short")
	wantErr(t, "exception approval with a 5-character reason", err, "20+")
	// Raw: a genuine MATCHED-context attestation cannot approve an EXCEPTION invoice.
	wantErr(t, "raw approval of an exception with a MATCHED attestation", f.rawAs(c.apSup, "ap.approve", "supplier_invoice", inv3, "MATCHED",
		`UPDATE supplier_invoices SET status='APPROVED', approved_by='u-ap-supervisor' WHERE id=$1::uuid`, inv3), "different decision")
	// Raw: match status cannot be set by the statement.
	wantErr(t, "raw rewrite of match_status", f.rawExec(`UPDATE supplier_invoices SET match_status='MATCHED' WHERE id=$1::uuid`, inv3), "permission denied")
	_, err = f.svc.ApproveInvoice(f.ctx, senior, inv3, "Steel price escalation clause 14.2 applies to this delivery")
	must(t, "exception approved properly", err)
	// Duplicate invoice number (normalised) from the same supplier.
	_, err = f.svc.EnterInvoice(f.ctx, c.apClerk, InvoiceInput{POID: po, InvoiceNumber: "inv 11", InvoiceDate: today(), DueDate: today(),
		Subtotal: dec("1"), TaxAmount: dec("0.15"), Total: dec("1.15"), Lines: nil})
	wantErr(t, "duplicate invoice 'inv 11' vs 'INV-11'", err, "supplier_invoices_no_duplicates")
}

func TestJourneyA_PaymentControls(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, j1 := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("4")})
	inv, _ := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: "S-1", InvoiceDate: today(), DueDate: today(),
		Subtotal: dec("338000"), TaxAmount: dec("50700"), Total: dec("388700"), Lines: []InvoiceLine{{1, dec("4"), dec("84500")}}})
	j2, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv, "")
	must(t, "approve", err)
	w.financePost(t, j1, j2)

	// Overpayment: two payments of the same invoice beyond its total.
	p1, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec("300000")}})
	must(t, "p1", err)
	must(t, "p1 submit", f.svc.SubmitPayment(f.ctx, c.treasury, p1))
	p2, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec("100000")}})
	must(t, "p2", err)
	wantErr(t, "second payment taking the invoice beyond its total", f.svc.SubmitPayment(f.ctx, c.treasury, p2), "cannot take this allocation")

	// The preparer cannot approve; approval needs MFA; AI/system identities never.
	selfApprove := c.treasury
	selfApprove.Roles = []string{"treasury_officer", "finance_manager"}
	_, err = f.svc.ApprovePayment(f.ctx, selfApprove, p1)
	wantErr(t, "payment approved by its preparer", err, "segregation")
	noMFA := c.finMgr
	noMFA.MFA = false
	_, err = f.svc.ApprovePayment(f.ctx, noMFA, p1)
	wantErr(t, "payment approval without MFA", err, "multi-factor")
	ai := auth.Principal{Kind: auth.KindHuman, UserID: "ai:payments-copilot", TenantID: f.tenant, Roles: []string{"finance_manager"}, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute)}
	_, err = f.svc.ApprovePayment(f.ctx, ai, p1)
	wantErr(t, "payment approval by an AI principal", err, "human principals")
	// A plausible-looking user id is not enough: the identity provider did
	// not assert a human principal (Kind unset or "service").
	for _, kind := range []string{"", auth.KindService, auth.KindAI} {
		svc := c.finMgr
		svc.UserID, svc.Kind = "finance-approvals", kind
		_, err = f.svc.ApprovePayment(f.ctx, svc, p1)
		wantErr(t, "payment approval by a principal of kind "+strconv.Quote(kind), err, "human")
	}

	// Bank-detail fraud: the payee account is revoked and replaced after the
	// payment was prepared; the payment can no longer be approved.
	must(t, "revoke bank", f.rawAs(c.buyer, "supplier.bank.revoke", "supplier_bank_account", w.supBank, "REVOKED",
		`UPDATE supplier_bank_accounts SET status='REVOKED' WHERE id=$1::uuid`, w.supBank))
	_, err = f.svc.ApprovePayment(f.ctx, c.finMgr, p1)
	wantErr(t, "approval after the payee bank details changed", err, "no longer the approved details")
	newBank, err := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "Awash Bank", "ABC Steel PLC", "2000555444333", "ETB")
	must(t, "new bank", err)
	// New details need a second person with MFA; the buyer who entered them cannot.
	selfBank := c.buyer
	selfBank.Roles, selfBank.MFA, selfBank.AuthTime = []string{"procurement_officer", "finance_manager"}, true, time.Now()
	wantErr(t, "bank details approved by the person who entered them", f.svc.ApproveSupplierBankAccount(f.ctx, selfBank, newBank), "segregation")
	must(t, "approve new bank", f.svc.ApproveSupplierBankAccount(f.ctx, c.finMgr, newBank))
	must(t, "cancel p1", f.svc.CancelPayment(f.ctx, c.treasury, p1, "payee bank details changed"))

	// Single-approval payment below the dual threshold, then release rules.
	p3, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], newBank, w.bank, today(), []Allocation{{inv, dec("388700")}})
	must(t, "p3", err)
	must(t, "p3 submit", f.svc.SubmitPayment(f.ctx, c.treasury, p3))
	st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, p3)
	must(t, "p3 approve", err)
	if st != "APPROVED" {
		t.Fatalf("payment below threshold: %s", st)
	}
	approverReleases := c.finMgr
	approverReleases.Roles = []string{"finance_manager", "treasury_officer"}
	_, err = f.svc.ReleasePayment(f.ctx, approverReleases, p3)
	wantErr(t, "payment released by its approver", err, "payment_release_separation")
	// The preparer cannot release (two treasury officers).
	_, err = f.svc.ReleasePayment(f.ctx, c.treasury, p3)
	wantErr(t, "payment released by its preparer", err, "prepared a payment cannot release")
	// Raw: settlement without a bank statement.
	_, err = f.svc.ReleasePayment(f.ctx, c.treasury2, p3)
	must(t, "release", err)
	wantErr(t, "raw settlement without a bank statement", f.rawExec(`UPDATE payment_instructions SET status='SETTLED' WHERE id=$1::uuid`, p3), "settled only by reconciling")
	// Raw: a statement cannot be imported by tenant SQL (attested file digest).
	wantErr(t, "raw bank statement import", f.rawExec(`INSERT INTO bank_statements(company_bank_id, statement_no, statement_date, opening_balance, closing_balance, source_sha256, imported_by)
		VALUES ($1::uuid, 'FAKE', current_date, 0, -388700, repeat('a', 64), 'u-treasury')`, w.bank), "attestation")
	// Statements must balance and continue the previous closing balance.
	_, err = f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "S-1", today(), "1000", "999", [3]string{"-2", "x", "y"}))
	wantErr(t, "statement that does not balance", err, "does not balance")
	// Treasury (who prepares and releases payments) cannot import statements.
	_, err = f.svc.ImportBankStatement(f.ctx, c.treasury2, stmt(w.bank, "S-T", today(), "1000000", "1000000"))
	wantErr(t, "statement import by treasury", err, "forbidden")
	// The releaser cannot reconcile their own payment.
	d, _ := f.svc.GetP2PDoc(f.ctx, c.treasury, "payment_instruction", p3)
	s2 := stmt(w.bank, "S-2", today(), "1000000", "611300", [3]string{"-388700", d.Number, "ABC"})
	stID, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, s2)
	must(t, "import", err)
	selfRec := c.treasury2
	selfRec.Roles = []string{"treasury_officer", "accountant"}
	res, err := f.svc.AutoReconcile(f.ctx, selfRec, stID)
	must(t, "reconcile run", err)
	if len(res.Matched) != 0 || len(res.Unmatched) != 1 || !strings.Contains(res.Unmatched[0].Reason, "released") {
		t.Errorf("releaser reconciled own payment: %+v", res)
	}
	res, err = f.svc.AutoReconcile(f.ctx, c.accountant, stID)
	must(t, "reconcile", err)
	if len(res.Matched) != 1 {
		t.Errorf("accountant reconciliation: %+v", res)
	}
	// The same file cannot be imported twice.
	_, err = f.svc.ImportBankStatement(f.ctx, c.bankOfficer, s2)
	wantErr(t, "re-import of the same statement file", err)
}

func TestJourneyA_SubledgerJournalIntegrity(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, j1 := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("5")})
	// A subledger journal cannot be cancelled (correct the document instead).
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return f.svc.cancelJournalTx(ctx, tx, c.finMgr, j1, "trying to drop a receipt accrual")
	})
	wantErr(t, "cancel a goods-receipt journal", err, "subledger journals are not cancelled")
	// A manual journal cannot masquerade as a subledger journal.
	wantErr(t, "raw journal with a reserved source type and no document", f.rawExec(`INSERT INTO journals(tenant_id, legal_entity_id, functional_currency, business_event_at, description, source_type, source_ref, idempotency_key, command_hash, created_by)
		VALUES ($1::uuid, $2::uuid, 'ETB', now(), 'fake', 'P2P_INVOICE', gen_random_uuid()::text, 'fake-p2p', 'x', 'u-x')`, f.tenant, f.entity), "reserved source type")
	// The finance poster cannot approve the journal of a document they confirmed? (journal SoD still applies)
	selfPost := c.siteEng
	selfPost.Roles = []string{"site_engineer", "finance_manager"}
	if err := f.svc.ApproveJournal(f.ctx, selfPost, j1); err == nil {
		t.Errorf("the person who generated the receipt journal approved it")
	}
}

// Rule-based escalation: an over-budget, high-value PO needs budget.override
// and approval.high_value, a recent MFA and a documented reason.
func TestJourneyA_OverBudgetHighValuePOEscalation(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t) // 12,100,000 on 01-MAT
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Bulk steel", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("140"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "approve pr (12.04m within 12.1m)", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 1, "Only mill with stock for this tonnage this quarter", w.sup[:1])
	must(t, "rfq", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q, err := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[0], time.Now().AddDate(0, 1, 0), "", []QuoteLine{{1, dec("90000")}})
	must(t, "quote", err)
	must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q, true, ""))
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q, ""))
	po, err := f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["5000"]})
	must(t, "po", err) // 12,600,000 > 12,100,000 budget and >= 5,000,000 high-value threshold
	if err := f.svc.ApprovePO(f.ctx, c.procMgr, po, ""); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-budget PO: %v", err)
	}
	if err := f.svc.ApprovePO(f.ctx, c.procMgr, po, "Steel price escalation; budget transfer to follow"); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over-budget PO by an approver without budget.override: %v", err)
	}
	senior := auth.Principal{Kind: auth.KindHuman, UserID: "u-commercial-director", TenantID: f.tenant, Roles: []string{"procurement_manager", "cfo"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	wantErr(t, "override without MFA", f.svc.ApprovePO(f.ctx, senior, po, "Steel price escalation; budget transfer to follow"), "multi-factor")
	// Raw: a plain APPROVED attestation cannot approve an over-budget PO.
	wantErr(t, "raw approval of an over-budget PO with a plain APPROVED attestation", f.rawAs(c.procMgr, "po.approve", "purchase_order", po, "APPROVED",
		`UPDATE purchase_orders SET status='APPROVED', approved_by='u-proc-manager' WHERE id=$1::uuid`, po), "different decision")
	senior.MFA, senior.AuthTime = true, time.Now()
	must(t, "override approval", f.svc.ApprovePO(f.ctx, senior, po, "Steel price escalation; budget transfer to follow"))
	if v := f.scalar(t, `SELECT over_budget::text || '/' || approver_mfa::text FROM purchase_orders WHERE id=$1::uuid`, po); v != "true/true" {
		t.Errorf("over_budget/approver_mfa = %s", v)
	}
}

// The database's banker's rounding equals pkg/money's (differential test).
func TestJourneyA_RoundingMatchesGo(t *testing.T) {
	f := newFixture(t)
	vals := []string{"0.5", "1.5", "2.5", "-0.5", "-1.5", "-2.5", "0.125", "0.135", "-0.125", "84500.005", "84500.015", "1.0049999", "2.675", "1e-7"}
	for i := 0; i < 2000; i++ {
		vals = append(vals, decimal.New(int64((i*7919)%2000003)-1000000, -3).String()) // includes many exact x.xx5 ties
	}
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, v := range vals {
			for _, places := range []int32{0, 2, 3} {
				var got decimal.Decimal
				if err := tx.QueryRow(ctx, `SELECT round_half_even($1::numeric, $2)`, v, places).Scan(&got); err != nil {
					return err
				}
				if want := decimal.RequireFromString(v).RoundBank(places); !got.Equal(want) {
					t.Errorf("round_half_even(%s, %d) = %s, Go RoundBank = %s", v, places, got, want)
				}
			}
		}
		return nil
	})
	must(t, "rounding", err)
}
