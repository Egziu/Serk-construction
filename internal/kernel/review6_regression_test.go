package kernel

// Independent review 6 probes: Journey B (contract to cash, 0018) and the
// human-decision rule (0019) at commit 297ab8f. Each probe asserts the
// SECURE / CORRECT behaviour: "held:" is logged when the control holds,
// t.Errorf "OPEN:" when it does not, "info:" for observations.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

func r6held(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("OPEN: %s succeeded", name)
		return
	}
	t.Logf("held: %-70s %s", name, firstLine(err.Error()))
}

func r6info(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("info: "+format, args...)
}

// r6contract creates and activates a contract with custom terms on the
// fixture project (one line, 10,000 m3 @ 350 = 3,500,000).
func (w *arWorld) r6contract(t *testing.T, project, retention, advance, recovery string) string {
	t.Helper()
	f, c := w.f, w.cast
	in := w.contractInput()
	in.ProjectID = project
	in.RetentionPct, in.AdvanceAmount, in.AdvanceRecoveryPct = dec(retention), dec(advance), dec(recovery)
	in.Lines = []ContractLine{{LineNo: 1, Description: "Bulk excavation", Unit: "m3", Quantity: dec("10000"), Rate: dec("350")}}
	cm := c.commercial
	if project != f.project {
		cm.ProjectIDs = []string{project}
	}
	id, err := f.svc.CreateContract(f.ctx, cm, in)
	must(t, "r6 contract", err)
	must(t, "r6 contract submit", f.svc.SubmitContract(f.ctx, cm, id))
	must(t, "r6 contract approve", f.svc.DecideContract(f.ctx, c.cfo, id, true, ""))
	return id
}

func (w *arWorld) r6scalar(t *testing.T, q string, args ...any) string {
	t.Helper()
	var s string
	must(t, "scalar", w.f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&s)
	}))
	return s
}

var r6stmtNo int

func (w *arWorld) r6lines(t *testing.T, amounts ...string) []string {
	t.Helper()
	// Opening/closing must chain; read the last closing balance of the account.
	var opening decimal.Decimal
	_ = w.f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE((SELECT closing_balance FROM bank_statements WHERE company_bank_id = $1::uuid ORDER BY imported_at DESC LIMIT 1), 0)`, w.bank).Scan(&opening)
	})
	closing := opening
	var ls [][3]string
	for i, a := range amounts {
		closing = closing.Add(dec(a))
		ls = append(ls, [3]string{a, fmt.Sprintf("R6 LINE %d", i), "ERA"})
	}
	r6stmtNo++
	return w.statement(t, w.cast.bankOfficer, fmt.Sprintf("R6-%d-%d", time.Now().UnixNano()%100000, r6stmtNo), opening.String(), closing.String(), ls...)
}

// ---------------------------------------------------------------------------
// 1. Money
// ---------------------------------------------------------------------------

// Contract terms the database accepts (retention 20%, recovery 100%) give an
// IPC whose amount due is negative; its invoice cannot be approved because
// the expected lines drop non-positive amounts and the journal does not balance.
func TestR6_01_NegativeAmountDue(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.r6contract(t, f.project, "0.20", "1000000", "1.0")
	w.contract = ctr
	ls := w.r6lines(t, "1000000")
	w.confirmedReceipt(t, ls[0], ReceiptAllocation{ContractID: ctr, Amount: dec("1000000")})
	w.measure(t, 15, "1000", "0", "0") // 350,000 gross
	ipc := w.certifiedIPC(t, 15, "R6-NEG-01")
	due := w.r6scalar(t, `SELECT amount_due::text || ' (gross ' || this_gross || ', retention ' || retention_amount || ', recovery ' || advance_recovery || ', VAT ' || vat_amount || ')' FROM ipcs WHERE id = $1::uuid`, ipc)
	if strings.HasPrefix(due, "-") {
		t.Errorf("OPEN: IPC certified with a negative amount due: %s", due)
	} else {
		t.Logf("held: amount due %s", due)
	}
	inv, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc, today(), today().AddDate(0, 0, 30))
	if err != nil {
		t.Logf("held/info: invoice issue refused: %v", err)
		return
	}
	_, err = f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv)
	if err != nil {
		t.Errorf("OPEN: certified IPC %s cannot be invoiced (stuck: IPC stays CERTIFIED, invoice DRAFT, no credit to the client's account): %v", ipc[:8], firstLine(err.Error()))
	} else {
		t.Logf("held (after 0020): recovery is capped, so the amount due is non-negative and the invoice approves normally")
	}
}

// Receipt allocations are numeric(24,6) with no currency-precision check:
// sub-cent allocations that sum to the (2-decimal) statement amount.
func TestR6_02_SubCentAllocations(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "R6-SUBCENT"))
	ls := w.r6lines(t, "200.00")
	r, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("199.995")}, {ContractID: ctr, Amount: dec("0.005")}})
	if err != nil {
		t.Logf("held: sub-cent allocation refused at recording: %v", err)
		return
	}
	jid, err := f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, r)
	if err != nil {
		t.Logf("held (late): sub-cent receipt recorded as DRAFT %s but refused at confirmation: %s", r[:8], firstLine(err.Error()))
		t.Errorf("OPEN: sub-cent allocations accepted at recording (receipt %s now DRAFT, unconfirmable, and blocks its statement line)", r[:8])
		return
	}
	lines := w.r6scalar(t, `SELECT string_agg(side || ' ' || amount::text, ', ' ORDER BY line_no) FROM journal_lines WHERE journal_id = $1::uuid`, jid)
	t.Errorf("OPEN: receipt with sub-cent allocations confirmed; journal lines: %s; advance received %s", lines,
		w.r6scalar(t, `SELECT contract_advance_received($1::uuid)::text`, ctr))
}

// The advance received after an IPC was prepared makes it stale; recovery is
// limited to what was received; two IPCs never recover more than received.
func TestR6_03_AdvanceRecoveryEdges(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.r6contract(t, f.project, "0.05", "1000000", "0.5")
	w.contract = ctr
	ls := w.r6lines(t, "300000", "700000", "5000000")
	w.confirmedReceipt(t, ls[0], ReceiptAllocation{ContractID: ctr, Amount: dec("300000")})
	w.measure(t, 15, "4000", "0", "0") // 1,400,000 gross: 50% = 700,000 but only 300,000 received
	ipc1 := w.certifiedIPC(t, 15, "R6-ADV-1")
	rec1 := w.r6scalar(t, `SELECT advance_recovery::text FROM ipcs WHERE id = $1::uuid`, ipc1)
	if !dec(rec1).Equal(dec("300000")) {
		t.Errorf("OPEN: IPC1 recovery %s, want 300000 (limited to advance received)", rec1)
	} else {
		t.Logf("held: IPC1 recovery limited to the advance received: %s", rec1)
	}
	// IPC2 prepared, then the rest of the advance arrives: IPC2 is stale.
	w.measure(t, 20, "1000", "0", "0")
	ipc2, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	must(t, "ipc2", err)
	must(t, "ipc2 submit", f.svc.SubmitIPC(f.ctx, w.ar.qs, ipc2))
	w.confirmedReceipt(t, ls[1], ReceiptAllocation{ContractID: ctr, Amount: dec("700000")})
	r6held(t, "certify an IPC prepared before an advance receipt (stale)", f.svc.CertifyIPC(f.ctx, w.mfa(w.cast.commercial), ipc2, "R6-ADV-2", arCertSHA))
	must(t, "cancel", f.svc.CancelIPC(f.ctx, w.ar.qs, ipc2, "stale after advance receipt"))
	ipc3 := w.certifiedIPC(t, 20, "R6-ADV-3")
	got := w.r6scalar(t, `SELECT this_gross || '/' || advance_recovery || '/' || (SELECT sum(advance_recovery) FROM ipcs WHERE contract_id = $1::uuid AND status IN ('CERTIFIED','INVOICED')) FROM ipcs WHERE id = $2::uuid`, ctr, ipc3)
	t.Logf("info: IPC3 this_gross/recovery/total recovered = %s (catch-up of IPC1's shortfall is capped by 50%% of this gross)", got)
	parts := strings.Split(got, "/")
	if dec(parts[2]).GreaterThan(dec("1000000")) {
		t.Errorf("OPEN: total recovered %s exceeds the advance", parts[2])
	} else {
		t.Logf("held: total recovered %s <= advance received 1000000", parts[2])
	}
}

// IPC period_end is caller-chosen and unconstrained: a certificate "to" a
// date before the measured work (or before the contract was signed) still
// certifies all verified work.
func TestR6_04_IPCPeriodUnconstrained(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	w.measure(t, 20, "100", "0", "0")
	ipc, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Logf("held: IPC period before contract signature refused: %v", err)
		return
	}
	t.Errorf("OPEN (low): IPC %s 'to 2025-01-01' (contract signed 2026-10-01, work measured to 2026-10-20) prepared with gross %s",
		ipc[:8], w.r6scalar(t, `SELECT this_gross::text FROM ipcs WHERE id = $1::uuid`, ipc))
}

// ---------------------------------------------------------------------------
// 2. Workflow integrity as the tenant runtime role
// ---------------------------------------------------------------------------

func TestR6_05_RawWorkflowSkips(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	exec := func(q string, args ...any) error {
		return f.r3tx(func(ctx context.Context, tx pgx.Tx) error { _, err := tx.Exec(ctx, q, args...); return err })
	}
	r6held(t, "INSERT an IPC directly as CERTIFIED", exec(`INSERT INTO ipcs(contract_id, number, seq, period_end, currency, policy_id, status, created_by, certified_by)
		SELECT id, 'R6-IPC-X', 1, '2026-10-15', currency, policy_id, 'CERTIFIED', 'u-qs', 'u-commercial' FROM contracts WHERE id = $1::uuid`, ctr))
	r6held(t, "INSERT a measurement directly as VERIFIED", exec(`INSERT INTO measurements(contract_id, number, period_end, status, created_by, verified_by)
		VALUES ($1::uuid, 'R6-MS-X', '2026-10-16', 'VERIFIED', 'u-qs', 'u-site-engineer')`, ctr))
	r6held(t, "INSERT a contract directly as ACTIVE", exec(`INSERT INTO contracts(legal_entity_id, project_id, customer_id, number, title, client_reference, signed_on, currency, retention_pct, status, created_by, approved_by)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'R6-CTR-X', 'Raw contract', 'REF-X', '2026-10-01', 'ETB', 0.05, 'ACTIVE', 'u-x', 'u-y')`, f.entity, f.project, w.customer))
	r6held(t, "INSERT a contract line after activation", exec(`INSERT INTO contract_lines(contract_id, line_no, description, unit, quantity, rate) VALUES ($1::uuid, 9, 'Extra work', 'm3', 1000, 99999)`, ctr))
	r6held(t, "UPDATE a contract line rate after activation", exec(`UPDATE contract_lines SET rate = rate * 2 WHERE contract_id = $1::uuid`, ctr))
	r6held(t, "DELETE a contract line after activation", exec(`DELETE FROM contract_lines WHERE contract_id = $1::uuid AND line_no = 3`, ctr))
	r6held(t, "UPDATE retention_pct on an ACTIVE contract", exec(`UPDATE contracts SET retention_pct = 0 WHERE id = $1::uuid`, ctr))
	r6held(t, "UPDATE a verified measurement quantity", exec(`UPDATE measurement_lines SET quantity = quantity * 10 WHERE measurement_id IN (SELECT id FROM measurements WHERE contract_id = $1::uuid)`, ctr))
	r6held(t, "INSERT a measurement line into a VERIFIED measurement", exec(`INSERT INTO measurement_lines(measurement_id, contract_line_no, quantity) SELECT id, 2, 100 FROM measurements WHERE contract_id = $1::uuid AND status = 'VERIFIED' LIMIT 1`, ctr))

	ipc, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	must(t, "ipc", err)
	r6held(t, "UPDATE an IPC's amount_due", exec(`UPDATE ipcs SET amount_due = amount_due * 2 WHERE id = $1::uuid`, ipc))
	r6held(t, "DRAFT IPC -> CERTIFIED skipping SUBMITTED (attested certifier)",
		f.rawAs(w.mfa(c.commercial), "ipc.certify", "ipc", ipc, "CERTIFIED", `UPDATE ipcs SET status='CERTIFIED', certified_by='u-commercial', certificate_ref='R6-REF', certificate_sha256=$2 WHERE id=$1::uuid`, ipc, arCertSHA))
	must(t, "ipc submit", f.svc.SubmitIPC(f.ctx, w.ar.qs, ipc))
	r6held(t, "certify an IPC with an attestation lacking MFA",
		f.rawAs(c.commercial, "ipc.certify", "ipc", ipc, "CERTIFIED", `UPDATE ipcs SET status='CERTIFIED', certified_by='u-commercial', certificate_ref='R6-REF', certificate_sha256=$2 WHERE id=$1::uuid`, ipc, arCertSHA))
	r6held(t, "certify as a different actor than attested",
		f.rawAs(w.mfa(c.commercial), "ipc.certify", "ipc", ipc, "CERTIFIED", `UPDATE ipcs SET status='CERTIFIED', certified_by='u-cfo', certificate_ref='R6-REF', certificate_sha256=$2 WHERE id=$1::uuid`, ipc, arCertSHA))
	must(t, "certify", f.svc.CertifyIPC(f.ctx, w.mfa(c.commercial), ipc, "R6-REF", arCertSHA))
	r6held(t, "CERTIFIED -> INVOICED without an invoice approval", exec(`UPDATE ipcs SET status='INVOICED' WHERE id=$1::uuid`, ipc))

	inv, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc, today(), today().AddDate(0, 0, 30))
	must(t, "invoice", err)
	tot := w.r6scalar(t, `SELECT total::text FROM customer_invoices WHERE id = $1::uuid`, inv)
	r6held(t, "INSERT a customer invoice with caller figures (second invoice for the IPC)", exec(`INSERT INTO customer_invoices(legal_entity_id, project_id, contract_id, customer_id, ipc_id, policy_id, number, invoice_date, due_date, currency, total, created_by)
		SELECT legal_entity_id, project_id, contract_id, customer_id, ipc_id, policy_id, 'R6-CINV-X', invoice_date, due_date, currency, 1, 'u-ar-clerk' FROM customer_invoices WHERE id = $1::uuid`, inv))
	r6held(t, "approve the invoice without its journal (attested approver)",
		f.rawAs(w.ar.arSup, "ar.invoice.approve", "customer_invoice", inv, "APPROVED", `UPDATE customer_invoices SET status='APPROVED', approved_by='u-ar-supervisor' WHERE id=$1::uuid`, inv))
	// A manual journal with the right lines, bound to the invoice in the approval tx.
	r6held(t, "approve the invoice with a MANUAL-source journal carrying its exact lines", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, w.ar.arSup, "ar.invoice.approve", "customer_invoice", inv, "APPROVED"); err != nil {
			return err
		}
		exp, err := postgres.ExpectedLines(ctx, tx, "AR_INVOICE", inv)
		if err != nil {
			return err
		}
		j := ledger.Journal{TenantID: f.tenant, LegalEntityID: f.entity, ProjectID: f.project, FunctionalCurrency: "ETB", BusinessEventAt: today(),
			Description: "r6 manual", SourceType: "MANUAL", SourceRef: inv, IdempotencyKey: key("r6-man"), CreatedBy: "u-ar-supervisor"}
		for i, l := range exp {
			j.Lines = append(j.Lines, ledger.Line{LineNo: i + 1, AccountID: l.AccountID, Side: ledger.Side(l.Side), Amount: money.MustNew(l.Amount.StringFixed(2), "ETB"), ProjectID: l.ProjectID})
		}
		jid, _, err := postgres.CreateJournal(ctx, tx, j)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE customer_invoices SET status='APPROVED', approved_by='u-ar-supervisor', journal_id=$2::uuid WHERE id=$1::uuid`, inv, jid)
		return err
	}))
	// A kernel-created journal claiming a reserved AR source type.
	for _, st := range []string{"AR_INVOICE", "AR_RECEIPT", "AR_OTHER"} {
		jl := f.journal(key("r6-res"),
			ledger.Line{AccountID: w.acct["1100"], Side: ledger.Debit, Amount: mustMoney("10.00")},
			ledger.Line{AccountID: w.acct["4000"], Side: ledger.Credit, Amount: mustMoney("10.00")})
		jl.SourceType, jl.SourceRef = st, inv
		_, err := f.svc.CreateJournal(f.ctx, c.accountant, jl)
		r6held(t, "manual journal with reserved source type "+st, err)
	}
	// Reuse: an attestation for invoice A cannot approve invoice B.
	w.measure(t, 20, "100", "0", "0")
	ipcB := w.certifiedIPC(t, 20, "R6-REF-B")
	invB, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipcB, today(), today())
	must(t, "invoice B", err)
	r6held(t, "approve invoice B with invoice A's attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, w.ar.arSup, "ar.invoice.approve", "customer_invoice", inv, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE customer_invoices SET status='APPROVED', approved_by='u-ar-supervisor' WHERE id=$1::uuid`, invB)
		return err
	}))
	jA, err := f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv)
	must(t, "approve A", err)
	// Bind invoice B to invoice A's journal.
	r6held(t, "approve invoice B bound to invoice A's journal", f.rawAs(w.ar.arSup, "ar.invoice.approve", "customer_invoice", invB, "APPROVED",
		`UPDATE customer_invoices SET status='APPROVED', approved_by='u-ar-supervisor', journal_id=$2::uuid WHERE id=$1::uuid`, invB, jA))
	r6held(t, "change the approved invoice's journal_id", exec(`UPDATE customer_invoices SET journal_id = NULL WHERE id=$1::uuid`, inv))

	// Receipts.
	ls := w.r6lines(t, "100", "-50")
	r6held(t, "receipt for a money-out statement line", exec(`INSERT INTO customer_receipts(legal_entity_id, number, statement_line_id, company_bank_id, receipt_date, currency, created_by)
		SELECT b.legal_entity_id, 'R6-RC-OUT', l.id, b.id, l.booking_date, b.currency, 'u-ar-clerk' FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
		JOIN company_bank_accounts b ON b.id = s.company_bank_id WHERE l.id = $1::uuid`, ls[1]))
	r6held(t, "receipt INSERTed as CONFIRMED", exec(`INSERT INTO customer_receipts(legal_entity_id, number, statement_line_id, company_bank_id, receipt_date, currency, status, created_by, confirmed_by)
		SELECT b.legal_entity_id, 'R6-RC-C', l.id, b.id, l.booking_date, b.currency, 'CONFIRMED', 'u-ar-clerk', 'u-ar-supervisor' FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
		JOIN company_bank_accounts b ON b.id = s.company_bank_id WHERE l.id = $1::uuid`, ls[0]))
	r6held(t, "receipt with a caller-chosen amount (no attestation)", exec(`INSERT INTO customer_receipts(legal_entity_id, number, statement_line_id, company_bank_id, receipt_date, currency, amount, created_by)
		SELECT b.legal_entity_id, 'R6-RC-A', l.id, b.id, l.booking_date, b.currency, 999999, 'u-ar-clerk' FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
		JOIN company_bank_accounts b ON b.id = s.company_bank_id WHERE l.id = $1::uuid`, ls[0]))
	rc, _ := w.confirmedReceipt(t, ls[0], ReceiptAllocation{InvoiceID: inv, Amount: dec("100")})
	r6held(t, "add an allocation after confirmation", exec(`INSERT INTO receipt_allocations(receipt_id, line_no, contract_id, amount) VALUES ($1::uuid, 7, $2::uuid, 5)`, rc, ctr))
	r6held(t, "change an allocation after confirmation", exec(`UPDATE receipt_allocations SET amount = 1 WHERE receipt_id = $1::uuid`, rc))
	r6held(t, "delete an allocation after confirmation", exec(`DELETE FROM receipt_allocations WHERE receipt_id = $1::uuid`, rc))
	r6held(t, "match the receipted money-in line to something else", exec(`UPDATE bank_statement_lines SET status='MATCHED' WHERE id=$1::uuid`, ls[0]))
	_ = tot
}

// A receipt cannot be cancelled through the kernel/API, and even an attested
// cancellation leaves its statement line permanently unusable (UNIQUE
// statement_line_id): one wrong draft blocks applying that money for good.
func TestR6_06_ReceiptCancelAndLineReuse(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "R6-CAN"))
	ls := w.r6lines(t, "35000")
	// The AR clerk allocates to the wrong document (the contract advance).
	wrong, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("35000")}})
	must(t, "wrong receipt", err)
	_, err = f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("35000")}})
	t.Logf("info: re-recording the line while the wrong draft exists: %v", firstLine(fmt.Sprint(err)))
	// The only way out is an attested cancel written as raw SQL (no kernel command exists).
	err = f.rawAs(w.ar.arSup, "ar.receipt.cancel", "customer_receipt", wrong, "CANCELLED", `UPDATE customer_receipts SET status='CANCELLED', cancel_reason='Allocated to the wrong document' WHERE id=$1::uuid`, wrong)
	must(t, "attested raw cancel", err)
	_, err = f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("35000")}})
	if err != nil {
		t.Errorf("OPEN: after cancelling the wrong draft receipt the money-in line can never be receipted again: %s", firstLine(err.Error()))
	} else {
		t.Logf("held: line re-usable after cancellation")
	}
	recon, err := f.svc.ARReconciliation(f.ctx, w.cast.controller, f.entity)
	must(t, "recon", err)
	for _, r := range recon {
		if strings.HasPrefix(r.Check, "Unapplied") {
			t.Logf("info: AR recon %q: %s in %d lines (permanently, for this line)", r.Check, r.Subledger, r.Unposted)
		}
	}
}

// A receipt on a foreign-currency company bank account allocated to a
// functional-currency contract advance.
func TestR6_07_ForeignCurrencyReceiptToAdvance(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	must(t, "usd accounts", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, a := range []struct{ code, name string }{{"1010", "Bank USD"}, {"1060", "USD in transit"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: a.code, Name: a.name, Type: "ASSET", Active: true})
			if err != nil {
				return err
			}
			w.acct[a.code] = id
		}
		return nil
	}))
	usd, err := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "CBE USD", "1000555444333", "USD", w.acct["1010"], w.acct["1060"])
	if err != nil {
		t.Logf("held: USD company bank account refused: %v", err)
		return
	}
	must(t, "usd approve", f.svc.ApproveCompanyBankAccount(f.ctx, c.cfo, usd))
	st, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(usd, "USD-R6-1", today(), "0", "1000", [3]string{"1000", "ERA ADV USD", "ERA"}))
	must(t, "usd import", err)
	line := w.r6scalar(t, `SELECT id::text FROM bank_statement_lines WHERE statement_id = $1::uuid`, st)
	r, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, line, []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000")}})
	if err != nil {
		t.Logf("held: USD receipt to ETB contract advance refused at recording: %v", err)
		return
	}
	jid, err := f.svc.ConfirmReceipt(f.ctx, c.finMgr /*has no confirm perm*/, r)
	_ = jid
	jid, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, r)
	if err != nil {
		t.Logf("held (at confirmation): USD 1000 receipt to an ETB contract advance refused: %s", firstLine(err.Error()))
		t.Logf("info: but it was accepted as DRAFT %s and now blocks the statement line", r[:8])
		return
	}
	t.Errorf("OPEN: USD 1,000 receipt confirmed against the ETB contract advance; advance received now %s ETB; journal %s currency %s",
		w.r6scalar(t, `SELECT contract_advance_received($1::uuid)::text`, ctr), jid[:8], w.r6scalar(t, `SELECT functional_currency FROM journals WHERE id = $1::uuid`, jid))
}

// ---------------------------------------------------------------------------
// 3. Ledger and reconciliation
// ---------------------------------------------------------------------------

// Reversing a posted AR_INVOICE journal (the ADR 0009 correction path) leaves
// the invoice APPROVED and payable and the IPC INVOICED; does the AR
// reconciliation still report zero difference?
func TestR6_08_ReversedInvoiceJournal(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	inv, jInv := w.approvedInvoice(t, w.certifiedIPC(t, 15, "R6-REV"))
	w.financePost(t, jInv)
	total := w.r6scalar(t, `SELECT total::text FROM customer_invoices WHERE id = $1::uuid`, inv)
	rev, err := f.svc.ReverseJournal(f.ctx, c.controller, jInv, key("r6-rev"), "posted to the wrong client", today())
	if err != nil {
		t.Logf("held: reversal of an AR journal refused: %v", err)
		return
	}
	ctrl2 := c.controller
	ctrl2.UserID = "u-controller-2"
	for _, r := range f.svc.ApproveJournals(f.ctx, c.finMgr, []string{rev.JournalID}) {
		must(t, "approve reversal", errOf(r.OK, r.Error))
	}
	for _, r := range f.svc.PostJournals(f.ctx, ctrl2, []string{rev.JournalID}) {
		must(t, "post reversal", errOf(r.OK, r.Error))
	}
	st := w.r6scalar(t, `SELECT i.status || ' / journal ' || j.status || ' / IPC ' || p.status FROM customer_invoices i JOIN journals j ON j.id = i.journal_id JOIN ipcs p ON p.id = i.ipc_id WHERE i.id = $1::uuid`, inv)
	t.Logf("info: after reversal: invoice %s", st)
	// The client then pays the (reversed) invoice.
	ls := w.r6lines(t, total)
	_, jR := w.confirmedReceipt(t, ls[0], ReceiptAllocation{InvoiceID: inv, Amount: dec(total)})
	w.financePost(t, jR)
	recon, err := f.svc.ARReconciliation(f.ctx, c.controller, f.entity)
	must(t, "recon", err)
	allZero := true
	for _, r := range recon {
		t.Logf("info: AR recon %-28.28s subledger %14s gl %14s diff %v open %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
		if !strings.HasPrefix(r.Check, "Unapplied") && !r.Difference.IsZero() {
			allZero = false
		}
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	ar := w.balance(t, "1100")
	rev4000 := w.balance(t, "4000")
	t.Logf("info: contract position invoiced %s certified %s receivable_open %s; GL AR %s revenue %s", pos.InvoicedTotal, pos.CertifiedGross, pos.ReceivableOpen, ar, rev4000)
	w.measure(t, 20, "1", "0", "0")
	ipcN, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Logf("info: next IPC gross %s (the reversed 35,000 of work is treated as already certified: previous_gross %s)",
			w.r6scalar(t, `SELECT this_gross::text FROM ipcs WHERE id = $1::uuid`, ipcN), w.r6scalar(t, `SELECT previous_gross::text FROM ipcs WHERE id = $1::uuid`, ipcN))
	}
	if allZero && ar.IsNegative() {
		t.Errorf("OPEN: AR reconciliation reports zero difference on every check while the GL shows AR %s (a credit: cash received against an invoice whose revenue was reversed) and the contract position still reports %s invoiced/certified; the invoice remains APPROVED and payable",
			ar, pos.InvoicedTotal)
	}
}

// Contract policy succession: a successor must keep the AR, retention and
// advance accounts (approval guard), but the insert guard refuses accounts
// that any contract policy already uses.
func TestR6_09_ContractPolicySuccession(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	cp := ContractPolicy{LegalEntityID: f.entity, VATRate: dec("0.10"), VATBase: "GROSS",
		ARAccountID: w.acct["1100"], RetentionAccountID: w.acct["1150"], AdvanceAccountID: w.acct["2200"], RevenueAccountID: w.acct["4000"], VATOutputAccountID: w.acct["2300"]}
	_, errSame := f.svc.ProposeContractPolicy(f.ctx, c.controller, cp)
	// Successor with fresh accounts.
	must(t, "fresh accounts", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, a := range []struct{ code, typ string }{{"1101", "ASSET"}, {"1151", "ASSET"}, {"2201", "LIABILITY"}, {"2301", "LIABILITY"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: a.code, Name: "r6 " + a.code, Type: ledger.AccountType(a.typ), Active: true})
			if err != nil {
				return err
			}
			w.acct[a.code] = id
		}
		return nil
	}))
	cp2 := cp
	cp2.ARAccountID, cp2.RetentionAccountID, cp2.AdvanceAccountID, cp2.VATOutputAccountID = w.acct["1101"], w.acct["1151"], w.acct["2201"], w.acct["2301"]
	var errFresh error
	id2, err := f.svc.ProposeContractPolicy(f.ctx, c.controller, cp2)
	if err == nil {
		errFresh = f.svc.DecideContractPolicy(f.ctx, c.cfo, id2, true)
	} else {
		errFresh = err
	}
	// Only same VAT output account changed.
	cp3 := cp
	cp3.VATOutputAccountID = w.acct["2301"]
	_, errVAT := f.svc.ProposeContractPolicy(f.ctx, c.controller, cp3)
	if errSame != nil && errFresh != nil && errVAT != nil {
		t.Errorf("OPEN: no successor contract policy can ever be approved (VAT rate/base frozen forever):\n  same control accounts: %s\n  fresh control accounts: %s\n  same AR/retention/advance, new VAT account: %s",
			firstLine(errSame.Error()), firstLine(errFresh.Error()), firstLine(errVAT.Error()))
	} else {
		t.Logf("held: a successor is possible (same %v / fresh %v / vat %v)", errSame, errFresh, errVAT)
	}
	// AR control accounts used as the bank GL / clearing account of a new company bank account.
	must(t, "clearing acct", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: "1062", Name: "r6 clearing", Type: "ASSET", Active: true})
		w.acct["1062"] = id
		return err
	}))
	_, err = f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "Odd bank", "1000777666555", "ETB", w.acct["1100"], w.acct["1062"])
	if err == nil {
		odd := ""
		_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT id::text FROM company_bank_accounts WHERE name = 'Odd bank'`).Scan(&odd)
		})
		aerr := f.svc.ApproveCompanyBankAccount(f.ctx, c.cfo, odd)
		t.Errorf("OPEN (low): a company bank account was registered with the AR control account as its bank GL account; CFO approval: %v", aerr)
	} else {
		t.Logf("held: company bank account on the AR control account refused: %s", firstLine(err.Error()))
	}
	// AR control account as a P2P policy AP account.
	_, err = f.svc.ProposeP2PPolicy(f.ctx, c.controller, postgres.P2PPolicy{LegalEntityID: f.entity, PriceTolerancePct: dec("0.02"), OverReceiptPct: dec("0.05"),
		VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: w.acct["2100"], APAccountID: w.acct["2200"], VATInputAccountID: w.acct["1300"], PPVAccountID: w.acct["5100"]})
	if err == nil {
		t.Errorf("OPEN (low): a P2P policy was proposed with the customer-advance control account (2200) as its AP account")
	} else {
		t.Logf("held: P2P policy on an AR control account refused: %s", firstLine(err.Error()))
	}
}

// A manual journal posted to the AR control account is detected by the AR
// reconciliation (the reverse case of R6_08).
func TestR6_10_ManualJournalOnARControl(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	jl := f.journal(key("r6-man"),
		ledger.Line{AccountID: w.acct["1100"], Side: ledger.Debit, Amount: mustMoney("5000.00")},
		ledger.Line{AccountID: w.acct["4000"], Side: ledger.Credit, Amount: mustMoney("5000.00")})
	res, err := f.svc.CreateJournal(f.ctx, c.accountant, jl)
	if err != nil {
		t.Logf("held: manual journal on the AR control account refused at creation: %v", err)
		return
	}
	for _, r := range f.svc.ApproveJournals(f.ctx, c.finMgr, []string{res.JournalID}) {
		if !r.OK {
			t.Logf("held: manual AR journal refused at approval: %s", r.Error)
			return
		}
	}
	for _, r := range f.svc.PostJournals(f.ctx, c.controller, []string{res.JournalID}) {
		if !r.OK {
			t.Logf("held: manual AR journal refused at posting: %s", r.Error)
			return
		}
	}
	t.Logf("info: a manual journal Dr AR / Cr contract revenue 5,000 was created, approved and posted (no control-account guard on manual journals)")
	recon, err := f.svc.ARReconciliation(f.ctx, c.controller, f.entity)
	must(t, "recon", err)
	for _, r := range recon {
		if r.Check == "Accounts receivable" {
			if r.Difference.IsZero() {
				t.Errorf("OPEN: AR reconciliation shows zero difference after a manual AR posting")
			} else {
				t.Logf("held: AR reconciliation detects it: difference %s", r.Difference)
			}
		}
	}
	pr, err := f.svc.ProjectProfitability(f.ctx, c.controller, f.project)
	must(t, "profitability", err)
	t.Logf("info: project profitability revenue %s (the manual revenue is on the project)", pr.RevenuePosted)
}

// ---------------------------------------------------------------------------
// 4. Human decisions and separation of duties
// ---------------------------------------------------------------------------

func TestR6_11_HumanRuleAndDraftParity(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	// Every action string used by the kernel (authorize / submitDoc) and by
	// SQL approval_use / creation triggers, collected by grep at 297ab8f.
	actions := []string{"ap.approve", "ap.reject", "ap.submit", "ar.invoice.approve", "ar.invoice.create", "ar.receipt.cancel", "ar.receipt.confirm", "ar.receipt.create",
		"bank.import", "bank.reconcile", "bankacct.approve", "bankacct.close", "bankacct.create", "boq.decide", "boq.submit", "contract.decide", "contract.policy.create",
		"contract.policy.decide", "contract.submit", "customer.approve", "customer.block", "customer.create", "fx.policy.decide", "fx.snapshot.approve", "fx.snapshot.reject",
		"fx.snapshot.withdraw", "fx.source.approve", "fx.source.retire", "grn.confirm", "grn.submit", "ipc.cancel", "ipc.certify", "ipc.submit", "journal.approve",
		"journal.cancel", "journal.post", "measure.submit", "measure.verify", "payment.approve", "payment.cancel", "payment.release", "payment.submit", "period.close",
		"period.reopen", "po.approve", "po.cancel", "po.close", "po.create", "pr.decide", "pr.submit", "rfq.award", "rfq.cancel", "rfq.evaluate", "rfq.issue",
		"rfq.quote.record", "supplier.approve", "supplier.bank.approve", "supplier.bank.create", "supplier.bank.revoke", "supplier.block", "supplier.create", "wbs.decide",
		"workflow.cancel", "workflow.decide", "workflow.decide_definition", "workflow.define", "workflow.start",
		// edge strings
		"x.CREATE", "x.create\n", "create", ".create", "x.create.approve", "x.submitted", "x.precreate"}
	var mism []string
	drafts := []string{}
	for _, a := range actions {
		var sqlv bool
		must(t, "draft "+a, f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT approval_is_draft_action($1)`, a).Scan(&sqlv)
		}))
		if sqlv != auth.IsDraftAction(a) {
			mism = append(mism, fmt.Sprintf("%q go=%v sql=%v", a, auth.IsDraftAction(a), sqlv))
		}
		if sqlv {
			drafts = append(drafts, strings.TrimSpace(a))
		}
	}
	if len(mism) > 0 {
		t.Errorf("OPEN: IsDraftAction and approval_is_draft_action disagree: %v", mism)
	} else {
		t.Logf("held: Go and SQL draft-action lists agree on %d actions; draft (non-human allowed): %v", len(actions), drafts)
	}

	// Non-human principals on every Journey B decision.
	w.measure(t, 15, "100", "0", "0")
	ipc, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	must(t, "ipc", err)
	must(t, "submit", f.svc.SubmitIPC(f.ctx, w.ar.qs, ipc))
	for _, kind := range []string{auth.KindService, auth.KindAI, "", "Human", "human "} {
		cm := w.mfa(c.commercial)
		cm.UserID, cm.Kind = "u-bot-"+strings.TrimSpace(kind), kind
		r6held(t, fmt.Sprintf("IPC certification by kind %q", kind), f.svc.CertifyIPC(f.ctx, cm, ipc, "R6-BOT", arCertSHA))
	}
	ms, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("1"), ""}})
	must(t, "ms", err)
	must(t, "ms submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, ms))
	bot := c.siteEng
	bot.UserID, bot.Kind = "u-bot-eng", auth.KindService
	r6held(t, "measurement verification by a service principal", f.svc.DecideMeasurement(f.ctx, bot, ms, true, ""))
	r6held(t, "measurement rejection by a service principal", f.svc.DecideMeasurement(f.ctx, bot, ms, false, "not a real measurement"))
	botQS := w.ar.qs
	botQS.UserID, botQS.Kind = "u-bot-qs", auth.KindAI
	r6held(t, "IPC cancellation by an AI principal", f.svc.CancelIPC(f.ctx, botQS, ipc, "cancel by the assistant"))

	// SQL: a validly signed ipc.certify attestation WITHOUT principal.human.
	var hash string
	_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		var err error
		hash, err = postgres.SubjectHash(ctx, tx, "ipc", ipc)
		return err
	})
	now := time.Now()
	a, err := attest.Signer{Master: testdb.ApprovalMaster, Now: func() time.Time { return now }}.Sign(attest.Claims{Tenant: f.tenant, Actor: "u-commercial", Action: "ipc.certify",
		SubjectType: "ipc", SubjectID: ipc, SubjectHash: hash, Context: "CERTIFIED", Perms: []string{"ipc.certify", "p2p.read"}, MFA: true, AuthTime: now.Unix()})
	must(t, "sign", err)
	r6held(t, "signed ipc.certify attestation without principal.human", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := postgres.Authorize(ctx, tx, a.JSON()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE ipcs SET status='CERTIFIED', certified_by='u-commercial', certificate_ref='R6-X', certificate_sha256=$2 WHERE id=$1::uuid`, ipc, arCertSHA)
		return err
	}))
	// A draft-action attestation (ar.receipt.create, allowed for non-humans)
	// cannot stand in for a decision.
	ls := w.r6lines(t, "1000")
	botClerk := w.ar.arClerk
	botClerk.UserID, botClerk.Kind = "u-bot-clerk", auth.KindAI
	r, err := f.svc.RecordReceipt(f.ctx, botClerk, ls[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000")}})
	if err == nil {
		t.Logf("info: an AI principal recorded receipt %s (draft action, by design)", r[:8])
		r6held(t, "confirm a receipt using the AI's ar.receipt.create attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, botClerk, "ar.receipt.create", "customer_receipt", r, "CONFIRMED"); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE customer_receipts SET status='CONFIRMED', confirmed_by='u-bot-clerk' WHERE id=$1::uuid`, r)
			return err
		}))
		botSup := w.ar.arSup
		botSup.UserID, botSup.Kind = "u-bot-sup", auth.KindService
		_, err = f.svc.ConfirmReceipt(f.ctx, botSup, r)
		r6held(t, "receipt confirmation by a service principal", err)
	} else {
		t.Logf("info: AI receipt recording refused: %v", err)
	}
}

func TestR6_12_SoDCombinedRoles(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	ipc := w.certifiedIPC(t, 15, "R6-SOD")
	both := auth.Principal{UserID: "u-ar-both", TenantID: f.tenant, Roles: []string{"ar_clerk", "ar_supervisor"}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	inv, err := f.svc.IssueCustomerInvoice(f.ctx, both, ipc, today(), today())
	must(t, "invoice by both", err)
	_, err = f.svc.ApproveCustomerInvoice(f.ctx, both, inv)
	r6held(t, "invoice approved by its issuer (ar_clerk+ar_supervisor)", err)
	r6held(t, "raw: invoice approved by its issuer with a genuine attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, both, "ar.invoice.approve", "customer_invoice", inv, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE customer_invoices SET status='APPROVED', approved_by='u-ar-both' WHERE id=$1::uuid`, inv)
		return err
	}))
	_, err = f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv)
	must(t, "approve", err)
	// Statement importer who is also an AR supervisor and AR clerk.
	imp := auth.Principal{UserID: "u-imp", TenantID: f.tenant, Roles: []string{"bank_statement_officer", "ar_clerk", "ar_supervisor"}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	ls := w.statement(t, imp, "R6-IMP-1", "0", "1000", [3]string{"1000", "ERA", "ERA"})
	_, err = f.svc.RecordReceipt(f.ctx, imp, ls[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000")}})
	if err == nil {
		t.Logf("info: the importer could RECORD a receipt on its own statement line (refused only at confirmation)")
	}
	impCase := imp
	impCase.UserID = " U-IMP "
	rr, err := f.svc.RecordReceipt(f.ctx, impCase, ls[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000")}})
	t.Logf("info: importer with differently-cased id records: %v %v", rr, err)
	_ = c
}

// ---------------------------------------------------------------------------
// 5. Visibility
// ---------------------------------------------------------------------------

func TestR6_13_Visibility(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	var projB string
	must(t, "project B", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		projB, err = postgres.CreateProject(ctx, tx, f.tenant, f.entity, "P-R6B", "Second project", "ETB")
		return err
	}))
	ctr := w.activeContract(t)
	ms := w.measure(t, 15, "100", "0", "0")
	ipc := w.certifiedIPC(t, 15, "R6-VIS")
	inv, jInv := w.approvedInvoice(t, ipc)
	ls := w.r6lines(t, "1000")
	rc, _ := w.confirmedReceipt(t, ls[0], ReceiptAllocation{ContractID: ctr, Amount: dec("1000")})
	w.financePost(t, jInv)
	mk := func(id string, roles ...string) auth.Principal {
		return auth.Principal{UserID: id, TenantID: f.tenant, Roles: roles, ProjectIDs: []string{projB}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	}
	qsB := mk("u-qs-b", "quantity_surveyor")
	cmB := mk("u-cm-b", "commercial_manager")
	pmB := mk("u-pm-b", "project_manager")
	// Project-restricted AR staff (ar roles carry scope.tenant_wide, but a project list restricts them).
	arB := mk("u-ar-b", "ar_clerk")
	supB := mk("u-sup-b", "ar_supervisor")
	random := "00000000-0000-4000-8000-0000000000aa"
	docs := map[string]string{"contract": ctr, "measurement": ms, "ipc": ipc, "customer_invoice": inv, "customer_receipt": rc}
	for _, p := range []auth.Principal{qsB, cmB, pmB, arB, supB, f.outsider} {
		for typ, id := range docs {
			_, err := f.svc.GetP2PDoc(f.ctx, p, typ, id)
			_, errR := f.svc.GetP2PDoc(f.ctx, p, typ, random)
			switch {
			case err == nil:
				t.Errorf("OPEN: %s (projects %v, tenant %s) reads %s %s of another project", p.UserID, p.ProjectIDs, p.TenantID[:8], typ, id[:8])
			case errors.Is(err, ErrNotFound) != errors.Is(errR, ErrNotFound):
				t.Errorf("OPEN: %s: %s out of scope -> %v but nonexistent -> %v (existence disclosure)", p.UserID, typ, err, errR)
			}
		}
		for typ := range docs {
			items, err := f.svc.ListP2PDocs(f.ctx, p, typ, "", 500)
			if err == nil && len(items) > 0 {
				t.Errorf("OPEN: %s lists %d %s of other projects/entity level", p.UserID, len(items), typ)
			}
		}
		for _, typ := range []string{"money_in", "bank_statement"} {
			items, err := f.svc.ListP2PDocs(f.ctx, p, typ, "", 500)
			if err == nil && len(items) > 0 {
				t.Errorf("OPEN: %s lists %d %s", p.UserID, len(items), typ)
			}
		}
		_, errP := f.svc.ContractPosition(f.ctx, p, ctr)
		_, errPR := f.svc.ContractPosition(f.ctx, p, random)
		if errP == nil {
			t.Errorf("OPEN: %s reads the contract position of another project", p.UserID)
		} else if errors.Is(errP, ErrNotFound) != errors.Is(errPR, ErrNotFound) {
			t.Errorf("OPEN: contract position: out of scope %v vs nonexistent %v", errP, errPR)
		}
		prof, errPf := f.svc.ProjectProfitability(f.ctx, p, f.project)
		if errPf == nil && !prof.RevenuePosted.IsZero() {
			t.Errorf("OPEN: %s reads profitability of project A: %+v", p.UserID, prof)
		} else if errPf == nil {
			r6info(t, "%s (tenant %s) gets zero profitability for project A (RLS: no data)", p.UserID, p.TenantID[:8])
		}
		if rc, err := f.svc.ARReconciliation(f.ctx, p, f.entity); err == nil && len(rc) > 0 {
			t.Errorf("OPEN: %s runs the AR reconciliation: %+v", p.UserID, rc)
		} else if err == nil {
			r6info(t, "%s gets an empty AR reconciliation for tenant-1's entity (RLS: no data)", p.UserID)
		}
	}
	t.Logf("held (unless OPEN above): project-B and tenant-2 principals cannot read/list/position/profitability/reconcile project-A Journey B documents; out-of-scope == nonexistent")
	// Mutations by project-restricted AR staff.
	w.measure(t, 20, "100", "0", "0")
	ipc2 := w.certifiedIPC(t, 20, "R6-VIS-2")
	_, err := f.svc.IssueCustomerInvoice(f.ctx, arB, ipc2, today(), today())
	r6held(t, "project-B AR clerk issues an invoice for a project-A IPC", err)
	ls2 := w.r6lines(t, "500")
	_, err = f.svc.RecordReceipt(f.ctx, arB, ls2[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("500")}})
	r6held(t, "project-B AR clerk records a receipt (entity level)", err)
	// Cross-project measurement on a project-B contract referencing project-A?
	ctrB := w.r6contract(t, projB, "0.05", "0", "0")
	_, err = f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctrB, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("1"), ""}})
	r6held(t, "project-A QS measures a project-B contract", err)
	// Contract position takes a FOR UPDATE lock for a read (loadDoc).
	r6info(t, "ContractPosition calls loadDoc (SELECT ... FOR UPDATE) although it only reads")
}

func mustMoney(s string) money.Money { return money.MustNew(s, "ETB") }

// Sub-cent allocations that round to a balanced journal: the database must
// still refuse them (journal lines != expected lines).
func TestR6_02b_SubCentAllocationsBalanced(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "R6-SUBCENT-B"))
	ls := w.r6lines(t, "200.00")
	_, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("199.994")}, {ContractID: ctr, Amount: dec("0.006")}})
	r6held(t, "record a receipt with allocations 199.994 + 0.006 (refused at recording since 0020)", err)
}

// Concurrent confirmations must not over-allocate an invoice or an advance.
func TestR6_14_ConcurrentConfirmations(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	w.measure(t, 15, "100", "0", "0")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "R6-CONC"))
	total := dec(w.r6scalar(t, `SELECT total::text FROM customer_invoices WHERE id = $1::uuid`, inv))
	part := total.Mul(dec("0.6")).Round(2)
	ls := w.r6lines(t, part.String(), part.String(), "600000", "600000")
	r1, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[0], []ReceiptAllocation{{InvoiceID: inv, Amount: part}})
	must(t, "r1", err)
	r2, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[1], []ReceiptAllocation{{InvoiceID: inv, Amount: part}})
	must(t, "r2", err)
	a1, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[2], []ReceiptAllocation{{ContractID: ctr, Amount: dec("600000")}})
	must(t, "a1", err)
	a2, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, ls[3], []ReceiptAllocation{{ContractID: ctr, Amount: dec("600000")}})
	must(t, "a2", err)
	for round := 0; round < 1; round++ {
		errs := make(chan error, 4)
		for _, id := range []string{r1, r2, a1, a2} {
			id := id
			go func() { _, err := f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, id); errs <- err }()
		}
		ok := 0
		for i := 0; i < 4; i++ {
			if err := <-errs; err == nil {
				ok++
			} else {
				t.Logf("info: concurrent confirmation refused: %s", firstLine(err.Error()))
			}
		}
		alloc := dec(w.r6scalar(t, `SELECT COALESCE(sum(a.amount),0)::text FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id WHERE a.invoice_id = $1::uuid AND r.status = 'CONFIRMED'`, inv))
		adv := dec(w.r6scalar(t, `SELECT contract_advance_received($1::uuid)::text`, ctr))
		if alloc.GreaterThan(total) || adv.GreaterThan(dec("1000000")) {
			t.Errorf("OPEN: concurrent confirmations over-allocated: invoice %s/%s, advance %s/1000000", alloc, total, adv)
		} else {
			t.Logf("held: concurrent confirmations: %d succeeded; invoice allocated %s of %s; advance received %s of 1000000", ok, alloc, total, adv)
		}
	}
}

// Concurrent verification of two measurements that together exceed the
// contract quantity.
func TestR6_15_ConcurrentMeasurementVerification(t *testing.T) {
	w := newARWorld(t)
	f := w.f
	ctr := w.activeContract(t)
	var ids []string
	for i, d := range []int{15, 16} {
		id, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC), []MeasurementLine{{3, dec("70"), fmt.Sprint(i)}})
		must(t, "ms", err)
		must(t, "submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, id))
		ids = append(ids, id)
	}
	errs := make(chan error, 2)
	for _, id := range ids {
		id := id
		go func() { errs <- f.svc.DecideMeasurement(f.ctx, w.cast.siteEng, id, true, "") }()
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Logf("info: %s", firstLine(err.Error()))
		}
	}
	q := dec(w.r6scalar(t, `SELECT contract_verified_qty($1::uuid, 3, NULL)::text`, ctr))
	if q.GreaterThan(dec("120")) {
		t.Errorf("OPEN: concurrent verifications exceeded the contract quantity: %s > 120", q)
	} else {
		t.Logf("held: verified quantity %s <= 120 under concurrent verification", q)
	}
}
