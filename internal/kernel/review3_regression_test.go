package kernel

// Independent review 3 probes (0013 procure-to-pay), kept as regression tests
// after the fixes in 0014. Written by the independent reviewer; adapted only
// where the API changed (statement files, two treasury officers, an
// independent statement officer) and where an observation became a control.
// Each probe asserts the SECURE behaviour: "held:" is logged when the control
// holds, t.Errorf "OPEN:" when it does not.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func r3held(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("OPEN: %s succeeded", name)
		return
	}
	t.Logf("held: %-70s %s", name, firstLine(err.Error()))
}

func (f *fixture) r3id(q string, args ...any) (string, error) {
	var id string
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&id)
	})
	return id, err
}

func (f *fixture) r3tx(fn func(ctx context.Context, tx pgx.Tx) error) error {
	return f.app.WithTenant(f.ctx, f.tenant, fn)
}

// r3invoice: receipt of qty t on PO line 1 at 84,500 and an approved,
// matched invoice for it. Returns grn, grn journal, invoice, invoice journal.
func (w *p2pWorld) r3invoice(t *testing.T, po, qty, num string) (string, string, string, string) {
	t.Helper()
	f, c := w.f, w.cast
	g, jg := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec(qty)})
	sub := dec(qty).Mul(dec("84500"))
	tax := sub.Mul(dec("0.15")).RoundBank(2)
	inv, m := w.invoice(t, InvoiceInput{POID: po, InvoiceNumber: num, InvoiceDate: today(), DueDate: today(),
		Subtotal: sub, TaxAmount: tax, Total: sub.Add(tax), Lines: []InvoiceLine{{1, dec(qty), dec("84500")}}})
	if m != "MATCHED" {
		t.Fatalf("invoice match %s", m)
	}
	ji, err := f.svc.ApproveInvoice(f.ctx, c.apSup, inv, "")
	must(t, "approve invoice", err)
	return g, jg, inv, ji
}

func (w *p2pWorld) r3payment(t *testing.T, inv, amount string) string {
	t.Helper()
	f, c := w.f, w.cast
	id, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec(amount)}})
	must(t, "prepare", err)
	must(t, "submit", f.svc.SubmitPayment(f.ctx, c.treasury, id))
	return id
}

// ---------------------------------------------------------------------------
// Area 1: money
// ---------------------------------------------------------------------------

// A generated journal stays DRAFT after the document transition bound it;
// tenant SQL can append lines afterwards and nothing re-checks the binding at
// journal approve/post.
func TestR3_01_SubledgerJournalLinesAppendedAfterBinding(t *testing.T) {
	w := newP2PWorld(t)
	f := w.f
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	g, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("5")})
	before := f.scalar(t, `SELECT available::text FROM p2p_cost_position($1::uuid, NULL, NULL)`, w.costCode)
	err := f.rawExec(`INSERT INTO journal_lines(journal_id, tenant_id, legal_entity_id, line_no, account_id, side, amount, currency, project_id, cost_code_id) VALUES
		($1::uuid, $2::uuid, $3::uuid, 90, $4::uuid, 'DEBIT', 1000000, 'ETB', $5::uuid, $6::uuid),
		($1::uuid, $2::uuid, $3::uuid, 91, $7::uuid, 'CREDIT', 1000000, 'ETB', $5::uuid, NULL)`,
		j, f.tenant, f.entity, w.acct["5000"], f.project, w.costCode, w.acct["1000"])
	r3held(t, "raw append of a balanced pair to a CONFIRMED receipt's DRAFT journal", err)
	_ = g
	_ = before
	// Defence in depth: even if lines were changed below the tenant login
	// (simulated here as the cluster superuser with triggers disabled), the
	// database refuses to approve or post a subledger journal that no longer
	// equals its document's accounting.
	if _, err := f.admin.Exec(f.ctx, `BEGIN; SET LOCAL session_replication_role = replica;
		INSERT INTO journal_lines(journal_id, tenant_id, legal_entity_id, line_no, account_id, side, amount, currency, project_id, cost_code_id) VALUES
		('`+j+`', '`+f.tenant+`', '`+f.entity+`', 90, '`+w.acct["5000"]+`', 'DEBIT', 1000000, 'ETB', '`+f.project+`', '`+w.costCode+`'),
		('`+j+`', '`+f.tenant+`', '`+f.entity+`', 91, '`+w.acct["1000"]+`', 'CREDIT', 1000000, 'ETB', '`+f.project+`', NULL); COMMIT;`); err != nil {
		t.Fatalf("superuser tamper setup: %v", err)
	}
	r3held(t, "journal.approve (genuine finance attestation) of a tampered P2P_GRN journal", f.rawAs(w.cast.finMgr, "journal.approve", "journal", j, "",
		`UPDATE journals SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, j))
	for _, r := range f.svc.ApproveJournals(f.ctx, w.cast.finMgr, []string{j}) {
		if r.OK {
			t.Errorf("OPEN: tampered subledger journal approved through the kernel")
		}
	}
}

// No DELETE/TRUNCATE on any new table.
func TestR3_02_NoDeleteOrTruncate(t *testing.T) {
	f := newFixture(t)
	for _, tbl := range []string{"p2p_counters", "p2p_policies", "suppliers", "supplier_bank_accounts", "boq_versions", "boq_items",
		"purchase_requisitions", "pr_lines", "rfqs", "rfq_suppliers", "rfq_quotes", "rfq_quote_lines", "purchase_orders", "po_lines",
		"grns", "grn_lines", "supplier_invoices", "invoice_lines", "company_bank_accounts", "payment_instructions", "payment_allocations",
		"bank_statements", "bank_statement_lines"} {
		r3held(t, "DELETE FROM "+tbl, f.rawExec(`DELETE FROM `+tbl+` WHERE false`))
		r3held(t, "TRUNCATE "+tbl, f.rawExec(`TRUNCATE `+tbl))
	}
}

// Children of documents that have left DRAFT: no inserts, no updates.
func TestR3_03_ChildRowsFrozenAfterParentLeavesDraft(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	boq := w.approvedBOQ(t)
	pr, rfq, po := w.awardedPO(t, "20", "500")
	g, _, inv, _ := w.r3invoice(t, po, "5", "R3-03")
	pay := w.r3payment(t, inv, "485875")
	quote := f.scalar(t, `SELECT awarded_quote_id::text FROM rfqs WHERE id=$1::uuid`, rfq)
	_ = c
	r3held(t, "INSERT boq_items into APPROVED BOQ", f.rawExec(`INSERT INTO boq_items(version_id, item_no, description, unit, quantity, rate, cost_code_id) VALUES ($1::uuid, '9.9', 'Extra budget', 't', 1000, 100000, $2::uuid)`, boq, w.costCode))
	r3held(t, "UPDATE boq_items quantity of APPROVED BOQ", f.rawExec(`UPDATE boq_items SET quantity = quantity * 100 WHERE version_id=$1::uuid`, boq))
	r3held(t, "INSERT pr_lines into APPROVED PR", f.rawExec(`INSERT INTO pr_lines(pr_id, line_no, cost_code_id, description, unit, quantity, est_unit_price) VALUES ($1::uuid, 3, $2::uuid, 'Extra', 't', 1, 1)`, pr, w.costCode))
	r3held(t, "UPDATE pr_lines of APPROVED PR", f.rawExec(`UPDATE pr_lines SET est_unit_price = 1 WHERE pr_id=$1::uuid`, pr))
	r3held(t, "INSERT rfq_suppliers into AWARDED RFQ", f.rawExec(`INSERT INTO rfq_suppliers(rfq_id, supplier_id) SELECT $1::uuid, $2::uuid`, rfq, w.sup[2]))
	r3held(t, "INSERT rfq_quote_lines into evaluated/awarded quote", f.rawExec(`INSERT INTO rfq_quote_lines(quote_id, pr_line_no, unit_price) VALUES ($1::uuid, 3, 1)`, quote))
	r3held(t, "UPDATE rfq_quote_lines price of awarded quote", f.rawExec(`UPDATE rfq_quote_lines SET unit_price = 1, amount = 1 WHERE quote_id=$1::uuid`, quote))
	r3held(t, "INSERT po_lines into APPROVED PO", f.rawExec(`INSERT INTO po_lines(po_id, line_no, legal_entity_id, cost_code_id, account_id, description, unit, quantity, unit_price) VALUES ($1::uuid, 3, $2::uuid, $3::uuid, $4::uuid, 'x', 't', 1, 1)`, po, f.entity, w.costCode, w.acct["5000"]))
	r3held(t, "UPDATE po_lines price/qty/amount of APPROVED PO", f.rawExec(`UPDATE po_lines SET unit_price = 1, quantity = 1, amount = 1 WHERE po_id=$1::uuid`, po))
	r3held(t, "INSERT grn_lines into CONFIRMED GRN", f.rawExec(`INSERT INTO grn_lines(grn_id, po_line_no, qty_received) VALUES ($1::uuid, 2, 400)`, g))
	r3held(t, "UPDATE grn_lines qty of CONFIRMED GRN", f.rawExec(`UPDATE grn_lines SET qty_received = 20 WHERE grn_id=$1::uuid`, g))
	r3held(t, "INSERT invoice_lines into APPROVED invoice", f.rawExec(`INSERT INTO invoice_lines(invoice_id, po_line_no, quantity, unit_price) VALUES ($1::uuid, 2, 1, 1)`, inv))
	r3held(t, "UPDATE invoice_lines of APPROVED invoice", f.rawExec(`UPDATE invoice_lines SET unit_price = 1 WHERE invoice_id=$1::uuid`, inv))
	r3held(t, "UPDATE supplier_invoices amounts", f.rawExec(`UPDATE supplier_invoices SET subtotal = 1, total = 1 WHERE id=$1::uuid`, inv))
	r3held(t, "INSERT payment_allocations into SUBMITTED payment", f.rawExec(`INSERT INTO payment_allocations(payment_id, invoice_id, amount) SELECT $1::uuid, $2::uuid, 1`, pay, inv))
	r3held(t, "UPDATE payment_allocations amount", f.rawExec(`UPDATE payment_allocations SET amount = 1 WHERE payment_id=$1::uuid`, pay))
	r3held(t, "UPDATE payment_instructions amount", f.rawExec(`UPDATE payment_instructions SET amount = 1 WHERE id=$1::uuid`, pay))
	r3held(t, "UPDATE boq_items moving it to another version", f.rawExec(`UPDATE boq_items SET version_id = version_id WHERE version_id=$1::uuid`, boq))
}

// Lines added between the attestation and the transition it authorises.
func TestR3_04_LinesAddedAfterAttestation(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	g, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now(), "DN-R3", []GRNLine{{POLineNo: 1, QtyReceived: dec("1")}})
	must(t, "grn", err)
	r3held(t, "GRN submitted after an extra line was added post-attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.store, "grn.submit", "grn", g, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO grn_lines(grn_id, po_line_no, qty_received) VALUES ($1::uuid, 2, 500)`, g); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE grns SET status='SUBMITTED' WHERE id=$1::uuid`, g)
		return err
	}))
	_, _, inv, _ := w.r3invoice(t, po, "5", "R3-04")
	_, _, inv2, _ := w.r3invoice(t, po, "1", "R3-04b")
	pay, err := f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec("100")}})
	must(t, "prepare", err)
	r3held(t, "payment submitted after amount+allocation changed post-attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.treasury, "payment.submit", "payment_instruction", pay, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO payment_allocations(payment_id, invoice_id, amount) VALUES ($1::uuid, $2::uuid, 1)`, pay, inv2); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='SUBMITTED' WHERE id=$1::uuid`, pay)
		return err
	}))
}

// ---------------------------------------------------------------------------
// Area 2: maker/checker, separation, one attestation per transition
// ---------------------------------------------------------------------------

func TestR3_05_DualApprovalWithOneAttestation(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "10", "R3-05")
	pay := w.r3payment(t, inv, "971750") // >= 500,000 dual threshold
	r3held(t, "one CFO attestation: PARTIALLY_APPROVED then APPROVED", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.cfo, "payment.approve", "payment_instruction", pay, "PARTIALLY_APPROVED"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='PARTIALLY_APPROVED', approved_by='u-cfo' WHERE id=$1::uuid`, pay); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='APPROVED', second_approved_by='u-finance-manager' WHERE id=$1::uuid`, pay)
		return err
	}))
	r3held(t, "single approval straight to APPROVED above the dual threshold", f.rawAs(c.cfo, "payment.approve", "payment_instruction", pay, "APPROVED",
		`UPDATE payment_instructions SET status='APPROVED', approved_by='u-cfo' WHERE id=$1::uuid`, pay))
	r3held(t, "same person as first and second approver", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.cfo, "payment.approve", "payment_instruction", pay, "PARTIALLY_APPROVED"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='PARTIALLY_APPROVED', approved_by='u-cfo' WHERE id=$1::uuid`, pay); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, c.cfo, "payment.approve", "payment_instruction", pay, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='APPROVED', second_approved_by='u-cfo' WHERE id=$1::uuid`, pay)
		return err
	}))
}

func TestR3_06_AnotherDocumentsAttestation(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	mk := func() string {
		g, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now(), "DN-"+key("r3"), []GRNLine{{POLineNo: 1, QtyReceived: dec("1")}})
		must(t, "grn", err)
		must(t, "submit", f.svc.SubmitGRN(f.ctx, c.store, g))
		return g
	}
	g1, g2 := mk(), mk()
	r3held(t, "confirm GRN 2 with GRN 1's confirm attestation", f.rawAs(c.siteEng, "grn.confirm", "grn", g1, "CONFIRMED",
		`UPDATE grns SET status='CONFIRMED', confirmed_by='u-site-engineer' WHERE id=$1::uuid`, g2))
}

// The creator column of documents whose creation is not attested was free
// text, so the checker could name someone else as maker and approve alone.
// Since 0014 the named creator's own attestation is consumed at commit, so
// the forged row itself never exists (and the approval step has nothing to
// approve). Each forged insert below is attempted with a genuine attestation
// of the would-be checker in the same transaction.
func TestR3_07_ForgedMakerThenSelfApproval(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	forge := func(name string, checker auth.Principal, q string, args ...any) {
		t.Helper()
		r3held(t, name, f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			var id string
			if err := tx.QueryRow(ctx, q, args...).Scan(&id); err != nil {
				return err
			}
			typ := map[string]string{"supplier_bank_accounts": "supplier_bank_account", "suppliers": "supplier", "company_bank_accounts": "company_bank_account",
				"p2p_policies": "p2p_policy", "rfq_quotes": "rfq_quote"}
			for tbl, ty := range typ {
				if strings.Contains(q, "INTO "+tbl+"(") {
					// The checker attests the creation under their own name: it
					// still does not vouch for the named maker.
					_ = f.authorizeIn(ctx, tx, checker, "x.create", ty, id, "")
				}
			}
			return nil
		}))
	}
	forge("finance manager inserts supplier bank details naming 'u-buyer' as maker", c.finMgr,
		`INSERT INTO supplier_bank_accounts(supplier_id, bank_name, account_name, account_number, currency, created_by)
		VALUES ($1::uuid, 'Ghost Bank', 'ABC Steel PLC', 'GHOST0001112', 'ETB', 'u-buyer') RETURNING id::text`, w.sup[0])
	forge("procurement manager inserts a supplier naming 'u-buyer' as maker", c.procMgr,
		`INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'GHOST-CO', 'Ghost Trading PLC', 'u-buyer') RETURNING id::text`, f.entity)
	forge("CFO inserts a company bank account naming 'u-treasury' as maker", c.cfo,
		`INSERT INTO company_bank_accounts(legal_entity_id, name, account_number, currency, gl_account_id, clearing_account_id, created_by)
		VALUES ($1::uuid, 'Side account', 'SIDE0009998', 'ETB', $2::uuid, $3::uuid, 'u-treasury') RETURNING id::text`, f.entity, w.acct["1000"], w.acct["1050"])
	forge("CFO inserts a policy (25% tolerances, no dual approval) naming 'u-controller' as maker", c.cfo,
		`INSERT INTO p2p_policies(legal_entity_id, version, currency, price_tolerance_pct, over_receipt_pct, vat_rate, high_value_po_threshold,
		dual_payment_threshold, grni_account_id, ap_account_id, vat_input_account_id, ppv_account_id, created_by)
		VALUES ($1::uuid, 2, 'ETB', 0.25, 0.25, 0.15, 999999999999, 999999999999, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'u-controller') RETURNING id::text`,
		f.entity, w.acct["2100"], w.acct["2000"], w.acct["1300"], w.acct["5100"])
	w.approvedBOQ(t)
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Steel for R3", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	forge("site engineer records a quote naming 'u-buyer' as receiver (to evaluate it)", c.siteEng,
		`INSERT INTO rfq_quotes(rfq_id, supplier_id, currency, valid_until, received_by) VALUES ($1::uuid, $2::uuid, 'ETB', current_date + 30, 'u-buyer') RETURNING id::text`, rfq, w.sup[1])
	// The legitimate flow still works: the real buyer records, the engineer evaluates.
	q, err := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[1], time.Now().AddDate(0, 1, 0), "Q-R3", []QuoteLine{{1, dec("99000")}})
	must(t, "genuine quote", err)
	must(t, "genuine evaluation", f.svc.EvaluateQuote(f.ctx, c.siteEng, q, true, ""))
}

// Human-only payment authority is a user-id naming convention.
func TestR3_08_HumanOnlyByNamingConvention(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "5", "R3-08")
	for _, id := range []string{"ai.payments-copilot", "svc/payments-bot"} {
		pay := w.r3payment(t, inv, "1")
		ai := auth.Principal{UserID: id, TenantID: f.tenant, Roles: []string{"finance_manager"}, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute)}
		_, err := f.svc.ApprovePayment(f.ctx, ai, pay)
		r3held(t, "payment approved by non-human principal "+id, err)
		_ = c
	}
}

// ---------------------------------------------------------------------------
// Area 3: statements, settlement, reconciliation
// ---------------------------------------------------------------------------

// Settlement evidence must be independent of the payment and exactly the
// attested file's content.
func TestR3_09_FabricatedStatementSettlesPayment(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "5", "R3-09")
	pay := w.r3payment(t, inv, "485875")
	_, err := f.svc.ApprovePayment(f.ctx, c.finMgr, pay)
	must(t, "approve", err)
	_, err = f.svc.ReleasePayment(f.ctx, c.treasury2, pay)
	must(t, "release", err)
	d, _ := f.svc.GetP2PDoc(f.ctx, c.treasury2, "payment_instruction", pay)
	// (a) The original probe: raw SQL with the releaser's attestation over an arbitrary digest.
	digest := strings.Repeat("ab", 32)
	r3held(t, "statement with lines typed by the payment's releaser (raw SQL, releaser's attestation)", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.treasury2, "bank.import", "bank_statement_source", digest, w.bank); err != nil {
			return err
		}
		var sid string
		if err := tx.QueryRow(ctx, `INSERT INTO bank_statements(company_bank_id, statement_no, statement_date, opening_balance, closing_balance, source_sha256, imported_by)
			VALUES ($1::uuid, 'FABRICATED-1', current_date, 0, -485875, $2, 'u-treasury-2') RETURNING id::text`, w.bank, digest).Scan(&sid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO bank_statement_lines(statement_id, line_no, booking_date, amount, reference, counterparty) VALUES ($1::uuid, 1, current_date, -485875, $2, 'ABC')`, sid, d.Number)
		return err
	}))
	// (b) A genuine statement officer's attestation for file F, but different lines stored.
	file := stmt(w.bank, "GENUINE-1", today(), "0", "-485875", [3]string{"-485875", "UNRELATED TRANSFER", "XYZ"})
	in, err := ParseStatement(file)
	must(t, "parse", err)
	r3held(t, "stored lines differ from the attested file's content", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.bankOfficer, "bank.import", "bank_statement_source", in.SourceSHA256, w.bank+"|"+in.ContentDigest()); err != nil {
			return err
		}
		var sid string
		if err := tx.QueryRow(ctx, `INSERT INTO bank_statements(company_bank_id, statement_no, statement_date, opening_balance, closing_balance, source_sha256, imported_by)
			VALUES ($1::uuid, 'GENUINE-1', $2, 0, -485875, $3, 'u-bank-officer') RETURNING id::text`, w.bank, today(), in.SourceSHA256).Scan(&sid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO bank_statement_lines(statement_id, line_no, booking_date, amount, reference, counterparty) VALUES ($1::uuid, 1, $2, -485875, $3, 'ABC')`, sid, today(), d.Number)
		return err
	}))
	// (c) The releaser also holds the statement-officer role (a role
	// combination the catalogue forbids but an administrator could assign):
	// the import is accepted as data, the settlement is not.
	both := c.treasury2
	both.Roles = []string{"treasury_officer", "bank_statement_officer"}
	sid, err := f.svc.ImportBankStatement(f.ctx, both, stmt(w.bank, "SELF-1", today(), "0", "-485875", [3]string{"-485875", "TRF " + d.Number, "ABC"}))
	must(t, "import by releaser", err)
	res, err := f.svc.AutoReconcile(f.ctx, c.accountant, sid)
	if err == nil && len(res.Matched) > 0 {
		t.Errorf("OPEN: payment matched to a statement imported by its releaser: %+v", res)
	}
	if st := f.scalar(t, `SELECT status FROM payment_instructions WHERE id=$1::uuid`, pay); st == "SETTLED" {
		t.Errorf("OPEN: payment %s SETTLED from a statement imported by its releaser", d.Number)
	} else {
		t.Logf("held: payment not settled from the releaser's own statement (%s; reconcile err=%v, %+v)", st, err, res)
	}
	// The refusal comes from the database's independence rule (review 4: an
	// earlier version of this probe stopped on a missing settlement journal).
	if len(res.Unmatched) != 1 || !strings.Contains(res.Unmatched[0].Reason, "independent") {
		t.Errorf("OPEN: releaser's statement not refused by the independence rule: %+v", res)
	} else {
		t.Logf("held: database independence rule: %s", res.Unmatched[0].Reason)
	}
}

func TestR3_10_StatementAppendAndContinuity(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	s1, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R3-S1", today(), "1000", "900", [3]string{"-100", "x", "y"}))
	must(t, "import s1", err)
	r3held(t, "append a line to an existing statement", f.rawExec(`INSERT INTO bank_statement_lines(statement_id, line_no, booking_date, amount, reference) VALUES ($1::uuid, 2, current_date, -5, 'PAY-x')`, s1))
	r3held(t, "rewrite a statement line amount/reference", f.rawExec(`UPDATE bank_statement_lines SET amount = -1, reference = 'PAY' WHERE statement_id=$1::uuid`, s1))
	r3held(t, "rewrite statement closing balance", f.rawExec(`UPDATE bank_statements SET closing_balance = 0 WHERE id=$1::uuid`, s1))
	// Continuity: a back-dated statement escapes the opening = previous closing rule.
	_, err = f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R3-S0", today().AddDate(0, 0, -10), "777", "777"))
	r3held(t, "back-dated statement with an opening balance that continues nothing", err)
}

// ---------------------------------------------------------------------------
// Area 4: tenant isolation
// ---------------------------------------------------------------------------

func TestR3_11_CrossTenant(t *testing.T) {
	w := newP2PWorld(t)
	f := w.f
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	g, j, inv, _ := w.r3invoice(t, po, "5", "R3-11")
	err := f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		for _, tbl := range []string{"p2p_counters", "p2p_policies", "suppliers", "supplier_bank_accounts", "boq_versions", "boq_items",
			"purchase_requisitions", "pr_lines", "rfqs", "rfq_suppliers", "rfq_quotes", "rfq_quote_lines", "purchase_orders", "po_lines",
			"grns", "grn_lines", "supplier_invoices", "invoice_lines", "company_bank_accounts", "payment_instructions", "payment_allocations",
			"bank_statements", "bank_statement_lines"} {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("OPEN: tenant 2 sees %d rows of %s", n, tbl)
			}
		}
		var n int
		var s *string
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM p2p_expected_lines('P2P_GRN', $1::uuid)`, g).Scan(&n); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT p2p_subject_text('supplier_invoice', $1)`, inv).Scan(&s); err != nil {
			return err
		}
		var lt string
		if err := tx.QueryRow(ctx, `SELECT p2p_lines_text($1::uuid)`, j).Scan(&lt); err != nil {
			return err
		}
		var m int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM p2p_gl_reconciliation($1::uuid)`, f.entity).Scan(&m); err != nil {
			return err
		}
		if n != 0 || s != nil || lt != "" || m != 0 {
			t.Errorf("OPEN: tenant 2 reads tenant 1 through functions: expected_lines=%d subject_text=%v lines_text=%q recon_rows=%d", n, s != nil, lt, m)
		} else {
			t.Logf("held: functions return nothing for tenant 1 ids (expected_lines=0, subject_text=NULL, lines_text='', recon rows=0)")
		}
		return nil
	})
	must(t, "tenant2 reads", err)
	r3held(t, "tenant 2 inserts a supplier into tenant 1", f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO suppliers(tenant_id, legal_entity_id, code, name, created_by) VALUES ($1::uuid, $2::uuid, 'X-T2', 'Cross tenant', 'u-x')`, f.tenant, f.entity)
		return err
	}))
	r3held(t, "tenant 2 sets tenant 1's counters", f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO p2p_counters(tenant_id, doc_type, year, last) VALUES ($1::uuid, 'PAY', 2026, 5)`, f.tenant)
		return err
	}))
	err = f.app.WithTenant(f.ctx, f.tenant2, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE supplier_invoices SET status = status WHERE id=$1::uuid`, inv)
		if err == nil && tag.RowsAffected() != 0 {
			return fmt.Errorf("updated %d rows", tag.RowsAffected())
		}
		if err == nil {
			return fmt.Errorf("0 rows (RLS hides the row)")
		}
		return err
	})
	t.Logf("held: tenant 2 UPDATE of tenant 1 invoice: %v", err)
	var defs string
	_ = f.admin.QueryRow(f.ctx, `SELECT COALESCE(string_agg(p.proname, ','), '') FROM pg_proc p WHERE p.prosecdef AND (p.proname LIKE 'p2p%' OR p.proname IN ('round_half_even'))
		OR (p.prosecdef AND p.oid IN (SELECT tgfoid FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relname IN ('suppliers','grns','supplier_invoices','payment_instructions','bank_statements','bank_statement_lines','purchase_orders')))`).Scan(&defs)
	if defs != "" {
		t.Errorf("OPEN: SECURITY DEFINER functions among the new ones: %s", defs)
	} else {
		t.Logf("held: no new p2p function or P2P trigger function is SECURITY DEFINER")
	}
}

// ---------------------------------------------------------------------------
// Area 5: other
// ---------------------------------------------------------------------------

// A PO line may post receipts to any ASSET account (here: the bank GL account).
func TestR3_12_POLineToBankGLAccount(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Steel R3-12", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 1, "Only mill with stock for this tonnage this quarter", w.sup[:1])
	must(t, "rfq", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q, err := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[0], time.Now().AddDate(0, 1, 0), "", []QuoteLine{{1, dec("85000")}})
	must(t, "quote", err)
	must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q, true, ""))
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q, ""))
	_, err = f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["1000"]})
	r3held(t, "PO line whose receipt debits the bank GL account (Cash at Bank)", err)
}

func TestR3_13_SplitPaymentsPreparerReleaseNumbering(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "10", "R3-13")
	// L2: splitting a 971,750 invoice into two 485,875 payments does not avoid dual approval.
	for i := 0; i < 2; i++ {
		p := w.r3payment(t, inv, "485875")
		st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, p)
		if err == nil && st == "APPROVED" {
			t.Errorf("OPEN: split payment %d single-approved for an invoice above the dual threshold", i+1)
		} else if err == nil {
			t.Logf("held: split payment %d went to %s (second approver required)", i+1, st)
		} else {
			t.Logf("held: split payment %d: %s", i+1, firstLine(err.Error()))
		}
	}
	// L3: the preparer cannot release.
	_, _, inv2, _ := w.r3invoice(t, po, "1", "R3-13b")
	p2 := w.r3payment(t, inv2, "97175")
	_, err := f.svc.ApprovePayment(f.ctx, c.finMgr, p2)
	must(t, "approve", err)
	_, err = f.svc.ReleasePayment(f.ctx, c.treasury, p2)
	r3held(t, "payment released by its preparer", err)
	// Info: numbering continues past 999,999 instead of truncating.
	must(t, "counter", f.rawExec(`UPDATE p2p_counters SET last = 999999 WHERE doc_type = 'PAY'`))
	num := ""
	_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT p2p_next_number('PAY')`).Scan(&num)
	})
	if !strings.HasSuffix(num, "-1000000") {
		t.Errorf("OPEN: next payment number after 999999 is %q", num)
	} else {
		t.Logf("held: next payment number after 999999 is %s", num)
	}
}

// R3-X1 and quote timing (found during remediation / review info items).
func TestR3_14_PolicyControlAccountsAndLateQuotes(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	_, err := f.svc.ProposeP2PPolicy(f.ctx, c.controller, postgres.P2PPolicy{LegalEntityID: f.entity, PriceTolerancePct: dec("0.02"),
		OverReceiptPct: dec("0.05"), VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: w.acct["2000"], APAccountID: w.acct["2100"], VATInputAccountID: w.acct["1300"], PPVAccountID: w.acct["5100"]})
	r3held(t, "successor policy swapping the GRNI and AP control accounts", err)
	_, err = f.svc.ProposeP2PPolicy(f.ctx, c.controller, postgres.P2PPolicy{LegalEntityID: f.entity, PriceTolerancePct: dec("0.02"),
		OverReceiptPct: dec("0.05"), VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: w.acct["2100"], APAccountID: w.acct["2000"], VATInputAccountID: w.acct["1000"], PPVAccountID: w.acct["5100"]})
	r3held(t, "policy using the bank GL account as VAT input", err)
	w.approvedBOQ(t)
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Late quote", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(2*time.Second), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	time.Sleep(2500 * time.Millisecond)
	_, err = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[0], time.Now().AddDate(0, 1, 0), "late", []QuoteLine{{1, dec("80000")}})
	r3held(t, "quote recorded after the RFQ due time", err)
}
