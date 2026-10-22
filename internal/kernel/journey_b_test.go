package kernel

// Journey B (contract to cash) against PostgreSQL: contract -> measurement ->
// IPC -> customer invoice -> bank receipt -> GL, with every figure checked to
// the cent and every subledger reconciled to the ledger. The scenario and its
// expected numbers are worked out by hand in docs/testing/E2E_JOURNEY_B.md.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

type arCast struct {
	qs, arClerk, arSup auth.Principal
}

type arWorld struct {
	*p2pWorld
	ar       arCast
	cpolicy  string
	customer string
	contract string
	boqSteel string
}

const arCertSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func newARWorld(t *testing.T) *arWorld {
	t.Helper()
	w := &arWorld{p2pWorld: newP2PWorld(t)}
	f, c := w.f, w.cast
	now := time.Now()
	mk := func(id string, projects []string, roles ...string) auth.Principal {
		return auth.Principal{UserID: id, TenantID: f.tenant, Roles: roles, ProjectIDs: projects, IssuedAt: now.Add(-time.Minute), Kind: auth.KindHuman}
	}
	w.ar = arCast{qs: mk("u-qs", []string{f.project}, "quantity_surveyor"), arClerk: mk("u-ar-clerk", nil, "ar_clerk"), arSup: mk("u-ar-supervisor", nil, "ar_supervisor")}
	// Receivable accounts (operator setup, synthetic data).
	err := f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, a := range []struct{ code, name, typ string }{{"1100", "Accounts receivable", "ASSET"}, {"1150", "Retention receivable", "ASSET"},
			{"2200", "Advances from customers", "LIABILITY"}, {"2300", "VAT output", "LIABILITY"}, {"4000", "Contract revenue", "REVENUE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: a.code, Name: a.name, Type: ledger.AccountType(a.typ), Active: true})
			if err != nil {
				return err
			}
			w.acct[a.code] = id
		}
		return nil
	})
	must(t, "AR accounts", err)
	// Contract policy: controller proposes, CFO approves. The VAT rate is
	// tenant-configured test data, not a statement of current law.
	w.cpolicy, err = f.svc.ProposeContractPolicy(f.ctx, c.controller, ContractPolicy{LegalEntityID: f.entity, VATRate: dec("0.15"), VATBase: "GROSS_LESS_ADVANCE",
		ARAccountID: w.acct["1100"], RetentionAccountID: w.acct["1150"], AdvanceAccountID: w.acct["2200"], RevenueAccountID: w.acct["4000"], VATOutputAccountID: w.acct["2300"]})
	must(t, "contract policy", err)
	must(t, "contract policy approve", f.svc.DecideContractPolicy(f.ctx, c.cfo, w.cpolicy, true))
	// Customer: AR clerk creates, finance manager approves.
	w.customer, err = f.svc.CreateCustomer(f.ctx, w.ar.arClerk, f.entity, "ERA", "Ethiopian Roads Administration", "TIN-ERA-01")
	must(t, "customer", err)
	must(t, "customer approve", f.svc.ApproveCustomer(f.ctx, c.finMgr, w.customer))
	// Approved BOQ; the reinforcement line of the contract delivers item 3.1.
	w.approvedBOQ(t)
	must(t, "boq item", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT i.id::text FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
			WHERE v.project_id = $1::uuid AND v.status = 'APPROVED' AND i.item_no = '3.1'`, f.project).Scan(&w.boqSteel)
	}))
	return w
}

// activeContract: 23,060,000; 5% retention; advance 1,000,000 recovered at 20%.
func (w *arWorld) activeContract(t *testing.T) string {
	t.Helper()
	f, c := w.f, w.cast
	id, err := f.svc.CreateContract(f.ctx, c.commercial, w.contractInput())
	must(t, "contract", err)
	must(t, "contract submit", f.svc.SubmitContract(f.ctx, c.commercial, id))
	must(t, "contract approve", f.svc.DecideContract(f.ctx, c.cfo, id, true, ""))
	w.contract = id
	return id
}

func (w *arWorld) contractInput() ContractInput {
	return ContractInput{ProjectID: w.f.project, CustomerID: w.customer, Title: "Adama-Awash road section 2", ClientReference: "ERA/CW/2026/014",
		SignedOn: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), RetentionPct: dec("0.05"), AdvanceAmount: dec("1000000"), AdvanceRecoveryPct: dec("0.20"),
		Lines: []ContractLine{
			{LineNo: 1, Description: "Bulk excavation", Unit: "m3", Quantity: dec("10000"), Rate: dec("350")},
			{LineNo: 2, Description: "Concrete C30", Unit: "m3", Quantity: dec("1200"), Rate: dec("6500")},
			{LineNo: 3, BOQItemID: w.boqSteel, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec("120"), Rate: dec("98000")},
		}}
}

func (w *arWorld) measure(t *testing.T, day int, q1, q2, q3 string) string {
	t.Helper()
	f := w.f
	var lines []MeasurementLine
	for i, q := range []string{q1, q2, q3} {
		if !dec(q).IsZero() {
			lines = append(lines, MeasurementLine{i + 1, dec(q), "Km 12+000 to 14+500"})
		}
	}
	id, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, w.contract, time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC), lines)
	must(t, "measurement", err)
	must(t, "measurement submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, id))
	must(t, "measurement verify", f.svc.DecideMeasurement(f.ctx, w.cast.siteEng, id, true, ""))
	return id
}

func (w *arWorld) certifiedIPC(t *testing.T, day int, ref string) string {
	t.Helper()
	f := w.f
	id, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, w.contract, time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC))
	must(t, "ipc", err)
	must(t, "ipc submit", f.svc.SubmitIPC(f.ctx, w.ar.qs, id))
	must(t, "ipc certify", f.svc.CertifyIPC(f.ctx, w.mfa(w.cast.commercial), id, ref, arCertSHA))
	return id
}

func (w *arWorld) mfa(p auth.Principal) auth.Principal {
	p.MFA, p.AuthTime = true, time.Now()
	return p
}

func (w *arWorld) approvedInvoice(t *testing.T, ipc string) (inv, journal string) {
	t.Helper()
	f := w.f
	inv, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc, today(), today().AddDate(0, 0, 30))
	must(t, "customer invoice", err)
	journal, err = f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv)
	must(t, "customer invoice approve", err)
	return inv, journal
}

// statement imports money-in lines and returns their ids in order.
func (w *arWorld) statement(t *testing.T, officer auth.Principal, no, opening, closing string, lines ...[3]string) []string {
	t.Helper()
	f := w.f
	st, err := f.svc.ImportBankStatement(f.ctx, officer, stmt(w.bank, no, today(), opening, closing, lines...))
	must(t, "statement import", err)
	var ids []string
	must(t, "statement lines", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT id::text FROM bank_statement_lines WHERE statement_id = $1::uuid ORDER BY line_no`, st)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(r, pgx.RowTo[string])
		return err
	}))
	return ids
}

func (w *arWorld) confirmedReceipt(t *testing.T, line string, allocs ...ReceiptAllocation) (receipt, journal string) {
	t.Helper()
	f := w.f
	receipt, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, line, allocs)
	must(t, "receipt", err)
	journal, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, receipt)
	must(t, "receipt confirm", err)
	return receipt, journal
}

type ipcFigures struct{ cumulative, previous, this, retention, recovery, vat, due string }

func (w *arWorld) checkIPC(t *testing.T, id string, want ipcFigures) {
	t.Helper()
	var got [7]decimal.Decimal
	must(t, "ipc figures", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT cumulative_gross, previous_gross, this_gross, retention_amount, advance_recovery, vat_amount, amount_due FROM ipcs WHERE id = $1::uuid`, id).
			Scan(&got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6])
	}))
	names := []string{"cumulative gross", "previous gross", "this gross", "retention", "advance recovery", "VAT", "amount due"}
	for i, s := range []string{want.cumulative, want.previous, want.this, want.retention, want.recovery, want.vat, want.due} {
		if !got[i].Equal(dec(s)) {
			t.Errorf("IPC %s: got %s, want %s", names[i], got[i], s)
		}
	}
	t.Logf("IPC %s: cumulative %s previous %s this %s retention %s recovery %s VAT %s due %s", id[:8], got[0], got[1], got[2], got[3], got[4], got[5], got[6])
}

func (w *arWorld) balance(t *testing.T, code string) decimal.Decimal {
	t.Helper()
	var b decimal.Decimal
	must(t, "balance", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(sum(CASE WHEN l.side = 'DEBIT' THEN l.amount ELSE -l.amount END), 0) FROM journal_lines l
			JOIN journals j ON j.id = l.journal_id WHERE l.account_id = $1::uuid AND j.status IN ('POSTED', 'REVERSED')`, w.acct[code]).Scan(&b)
	}))
	return b
}

func TestJourneyB_ContractToCashToGL(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)

	// The client pays the advance first; the statement officer imports the
	// statement, the AR clerk allocates, the AR supervisor confirms.
	lines := w.statement(t, c.bankOfficer, "CBE-2026-10-101", "10000000", "17691000",
		[3]string{"1000000", "ERA ADVANCE CTR", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"4691000", "ERA IPC 1", "ETHIOPIAN ROADS ADMIN"},
		[3]string{"2000000", "ERA PART IPC 2", "ETHIOPIAN ROADS ADMIN"})
	_, jAdv := w.confirmedReceipt(t, lines[0], ReceiptAllocation{ContractID: ctr, Amount: dec("1000000")})

	// Measurement 1 and IPC 1.
	w.measure(t, 15, "4000", "300", "20")
	ipc1 := w.certifiedIPC(t, 15, "ERA-IPC-01")
	w.checkIPC(t, ipc1, ipcFigures{"5310000", "0", "5310000", "265500", "1000000", "646500", "4691000"})
	inv1, jInv1 := w.approvedInvoice(t, ipc1)
	_, jR1 := w.confirmedReceipt(t, lines[1], ReceiptAllocation{InvoiceID: inv1, Amount: dec("4691000")})

	// Measurement 2 (cumulative 7,000 / 500 / 30) and IPC 2.
	w.measure(t, 20, "3000", "200", "10")
	ipc2 := w.certifiedIPC(t, 20, "ERA-IPC-02")
	w.checkIPC(t, ipc2, ipcFigures{"8640000", "5310000", "3330000", "166500", "0", "499500", "3663000"})
	inv2, jInv2 := w.approvedInvoice(t, ipc2)
	_, jR2 := w.confirmedReceipt(t, lines[2], ReceiptAllocation{InvoiceID: inv2, Amount: dec("2000000")})

	// Finance approves and posts every AR journal (different people from the
	// AR staff that generated them).
	w.financePost(t, jAdv, jInv1, jR1, jInv2, jR2)

	// Contract position.
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	for name, pair := range map[string][2]decimal.Decimal{
		"contract value": {pos.ContractValue, dec("23060000")}, "measured": {pos.MeasuredValue, dec("8640000")},
		"certified": {pos.CertifiedGross, dec("8640000")}, "retention held": {pos.RetentionHeld, dec("432000")},
		"advance received": {pos.AdvanceReceived, dec("1000000")}, "advance recovered": {pos.AdvanceRecovered, dec("1000000")},
		"invoiced": {pos.InvoicedTotal, dec("8354000")}, "received on invoices": {pos.Received, dec("6691000")},
		"receivable open": {pos.ReceivableOpen, dec("1663000")},
	} {
		if !pair[0].Equal(pair[1]) {
			t.Errorf("contract position %s: got %s, want %s", name, pair[0], pair[1])
		}
	}
	t.Logf("contract position: %+v", pos)

	// Ledger balances (debit positive).
	for code, want := range map[string]string{"1100": "1663000", "1150": "432000", "2200": "0", "2300": "-1146000", "4000": "-8640000", "1000": "7691000"} {
		if got := w.balance(t, code); !got.Equal(dec(want)) {
			t.Errorf("GL %s: got %s, want %s", code, got, want)
		} else {
			t.Logf("GL %s = %s", code, got)
		}
	}

	// Every receivable subledger equals its control account; no money in is unapplied.
	ar, err := f.svc.ARReconciliation(f.ctx, c.controller, f.entity)
	must(t, "AR reconciliation", err)
	if len(ar) != 4 {
		t.Fatalf("AR reconciliation returned %d checks", len(ar))
	}
	for _, r := range ar {
		t.Logf("AR recon %-66s subledger %14s gl %14s diff %s open %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
		if strings.HasPrefix(r.Check, "Unapplied") {
			if !r.Subledger.IsZero() || r.Unposted != 0 {
				t.Errorf("unapplied money in: %s in %d lines", r.Subledger, r.Unposted)
			}
			continue
		}
		if !r.Difference.IsZero() || r.Unposted != 0 {
			t.Errorf("%s does not reconcile: %+v", r.Check, r)
		}
	}
	// The bank account reconciles too: receipts are reconciled bank movements.
	gl, err := f.svc.GLReconciliation(f.ctx, c.controller, f.entity)
	must(t, "GL reconciliation", err)
	for _, r := range gl {
		if strings.HasPrefix(r.Check, "Bank") {
			t.Logf("P2P recon %s: subledger %s gl %s diff %s unmatched %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
			if !r.Difference.IsZero() || !r.Subledger.Equal(dec("7691000")) || r.Unposted != 0 {
				t.Errorf("bank reconciliation with receipts: %+v", r)
			}
		}
	}
	// Project profitability from the ledger: posted contract revenue on the project.
	pr, err := f.svc.ProjectProfitability(f.ctx, c.controller, f.project)
	must(t, "profitability", err)
	if !pr.RevenuePosted.Equal(dec("8640000")) {
		t.Errorf("project revenue posted: %s", pr.RevenuePosted)
	}
	t.Logf("project profitability: revenue %s cost %s margin %s", pr.RevenuePosted, pr.CostPosted, pr.Margin)
}

// arDenied asserts a refused step and logs the reason as evidence.
func arDenied(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Errorf("OPEN: %s was accepted", what)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: refused for an unexpected reason: %v (want %q)", what, err, want)
		return
	}
	t.Logf("refused: %-62s %v", what, err)
}

func TestJourneyB_Controls(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)

	// Contracts: no self-approval; approval needs fresh MFA; the advance cannot exceed the value.
	in := w.contractInput()
	in.AdvanceAmount = dec("23060001")
	big, err := f.svc.CreateContract(f.ctx, c.commercial, in)
	if err == nil { // the value is known once the lines are in: checked at submission
		err = f.svc.SubmitContract(f.ctx, c.commercial, big)
	}
	arDenied(t, "contract with an advance above the contract value", err, "exceeds the contract value")
	in = w.contractInput()
	draft, err := f.svc.CreateContract(f.ctx, c.commercial, in)
	must(t, "second contract", err)
	must(t, "second contract submit", f.svc.SubmitContract(f.ctx, c.commercial, draft))
	stale := c.cfo
	stale.AuthTime = time.Now().Add(-time.Hour)
	arDenied(t, "contract approval with stale MFA", f.svc.DecideContract(f.ctx, stale, draft, true, ""), "multi-factor")
	both := auth.Principal{UserID: "u-commercial", TenantID: f.tenant, Roles: []string{"commercial_manager", "cfo"}, Kind: auth.KindHuman, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute)}
	arDenied(t, "contract approved by its own author", f.svc.DecideContract(f.ctx, both, draft, true, ""), "segregation of duties")

	// Measurements: over the contract quantity, a nonexistent line, a repeated period, another project.
	over, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("10000.001"), ""}})
	if err == nil {
		must(t, "submit over", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, over))
		err = f.svc.DecideMeasurement(f.ctx, c.siteEng, over, true, "")
	}
	arDenied(t, "measurement above the contract quantity", err, "exceeds the contract quantity")
	_, err = f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), []MeasurementLine{{9, dec("1"), ""}})
	arDenied(t, "measurement of a nonexistent contract line", err, "does not exist")
	w.measure(t, 15, "4000", "300", "20")
	_, err = f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("1"), ""}})
	arDenied(t, "second measurement for the same period", err, "measurements_one_per_period")
	selfMeasure, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("1"), ""}})
	must(t, "measurement for self-verification", err)
	must(t, "submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, selfMeasure))
	qsEng := auth.Principal{UserID: "u-qs", TenantID: f.tenant, Roles: []string{"quantity_surveyor", "site_engineer"}, ProjectIDs: []string{f.project}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	arDenied(t, "measurement verified by its own author", f.svc.DecideMeasurement(f.ctx, qsEng, selfMeasure, true, ""), "segregation of duties")
	must(t, "reject self measurement", f.svc.DecideMeasurement(f.ctx, c.siteEng, selfMeasure, false, "Duplicate of sheet MS-1"))
	other := auth.Principal{UserID: "u-qs-other", TenantID: f.tenant, Roles: []string{"quantity_surveyor"}, ProjectIDs: []string{"8c1d4c2e-0000-4000-8000-000000000001"}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	_, err = f.svc.CreateMeasurement(f.ctx, other, ctr, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), []MeasurementLine{{1, dec("1"), ""}})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("measurement on another project's contract: %v, want not found", err)
	} else {
		t.Logf("refused: %-62s %v", "measurement by a QS of another project", err)
	}

	// IPC: self-certification, stale MFA, missing certificate, stale figures.
	ipc, err := f.svc.PrepareIPC(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	must(t, "ipc", err)
	must(t, "ipc submit", f.svc.SubmitIPC(f.ctx, w.ar.qs, ipc))
	qsCm := auth.Principal{UserID: "u-qs", TenantID: f.tenant, Roles: []string{"quantity_surveyor", "commercial_manager"}, ProjectIDs: []string{f.project}, Kind: auth.KindHuman, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute)}
	arDenied(t, "IPC certified by its preparer", f.svc.CertifyIPC(f.ctx, qsCm, ipc, "ERA-IPC-01", arCertSHA), "segregation of duties")
	arDenied(t, "IPC certification without fresh MFA", f.svc.CertifyIPC(f.ctx, c.commercial, ipc, "ERA-IPC-01", arCertSHA), "multi-factor")
	arDenied(t, "IPC certification without the certificate hash", f.svc.CertifyIPC(f.ctx, w.mfa(c.commercial), ipc, "ERA-IPC-01", "not-a-hash"), "SHA-256")
	w.measure(t, 18, "100", "0", "0") // verified after the IPC was prepared
	arDenied(t, "certification of a stale IPC", f.svc.CertifyIPC(f.ctx, w.mfa(c.commercial), ipc, "ERA-IPC-01", arCertSHA), "is stale")
	must(t, "cancel stale IPC", f.svc.CancelIPC(f.ctx, w.ar.qs, ipc, "Superseded by later measurement"))
	ipc1 := w.certifiedIPC(t, 18, "ERA-IPC-01")
	w.checkIPC(t, ipc1, ipcFigures{"5345000", "0", "5345000", "267250", "0", "801750", "5879500"}) // no advance received yet

	// An AI principal cannot approve a customer invoice or confirm a receipt.
	inv, err := f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc1, today(), today().AddDate(0, 0, 30))
	must(t, "invoice", err)
	ai := w.ar.arSup
	ai.UserID, ai.Kind = "u-ar-assistant", auth.KindAI
	_, err = f.svc.ApproveCustomerInvoice(f.ctx, ai, inv)
	arDenied(t, "AI principal approves a customer invoice", err, "reserved to human principals")
	_, err = f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arClerk, inv)
	arDenied(t, "invoice approved without ar.invoice.approve", err, "forbidden: ar.invoice.approve")
	jInv, err := f.svc.ApproveCustomerInvoice(f.ctx, w.ar.arSup, inv)
	must(t, "invoice approve", err)

	// The AR journal is bound to its document: altered lines are refused.
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE journal_lines SET amount = amount + 1 WHERE journal_id = $1::uuid AND side = 'DEBIT'`, jInv)
		return err
	})
	arDenied(t, "editing the lines of a generated AR journal", err, "permission denied")

	// Receipts: importer independence, over-allocation, advance above the agreed amount, double allocation.
	importerSup := auth.Principal{UserID: "u-ar-supervisor", TenantID: f.tenant, Roles: []string{"bank_statement_officer"}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	lines := w.statement(t, importerSup, "CBE-2026-10-201", "0", "8879501",
		[3]string{"1000001", "ERA ADVANCE", "ERA"}, [3]string{"5879500", "ERA IPC 1", "ERA"}, [3]string{"2000000", "ERA IPC 1 AGAIN", "ERA"})
	r, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[1], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("5879500")}})
	must(t, "receipt", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, r)
	arDenied(t, "receipt confirmed by the person who imported the statement", err, "independent of the statement import")

	// A fresh statement imported by the independent statement officer.
	lines = w.statement(t, c.bankOfficer, "CBE-2026-10-202", "8879501", "19259002",
		[3]string{"1000001", "ERA ADVANCE", "ERA"}, [3]string{"5879500", "ERA IPC 1", "ERA"}, [3]string{"2000000", "ERA IPC 1 AGAIN", "ERA"},
		[3]string{"1500000", "ERA ON ACCOUNT", "ERA"})
	adv, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000001")}})
	must(t, "advance receipt", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, adv)
	arDenied(t, "advance receipt above the agreed advance", err, "cannot take this advance")
	ok1, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[2], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("2000000")}})
	must(t, "receipt A", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, ok1)
	must(t, "receipt A confirm", err)
	full, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[1], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("5879500")}})
	must(t, "receipt B", err)
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, full)
	arDenied(t, "allocation that over-allocates an invoice already part paid", err, "over-allocated")
	short, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[3], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("1000000")}})
	if err == nil {
		_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, short)
	}
	arDenied(t, "allocations short of the amount received", err, "must equal the amount received")
	// The same invariant holds at confirmation when the kernel is bypassed: an
	// allocation added directly to a recorded receipt makes it unconfirmable.
	tampered, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[3], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("1500000")}})
	must(t, "receipt to tamper with", err)
	must(t, "raw extra allocation", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO receipt_allocations(receipt_id, line_no, contract_id, amount) VALUES ($1::uuid, 2, $2::uuid, 1)`, tampered, ctr)
		return err
	}))
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, tampered)
	if err != nil && strings.Contains(err.Error(), "does not balance") {
		err = errors.New("must equal the amount received (refused by the journal builder: " + err.Error() + ")")
	}
	arDenied(t, "confirming a receipt whose allocations were altered directly", err, "must equal the amount received")

	// Closed period. A period with approved, unposted journals cannot be
	// closed; once closed, the draft AR journal can be neither approved nor
	// posted into it.
	for _, r := range f.svc.ApproveJournals(f.ctx, c.finMgr, []string{jInv}) {
		must(t, "approve AR journal", errOf(r.OK, r.Error))
	}
	_, err = f.svc.ClosePeriod(f.ctx, c.controller, f.period(t), false)
	arDenied(t, "closing a period with an approved journal awaiting posting", err, "awaiting posting")
	for _, r := range f.svc.PostJournals(f.ctx, c.controller, []string{jInv}) {
		must(t, "post AR journal", errOf(r.OK, r.Error))
	}
	_, err = f.svc.IssueCustomerInvoice(f.ctx, w.ar.arClerk, ipc1, today(), today())
	arDenied(t, "a second invoice for the same IPC", err, "from a CERTIFIED IPC")
	// New work, certified and invoiced: its AR journal is generated DRAFT.
	w.measure(t, 25, "500", "0", "0")
	_, jInv2 := w.approvedInvoice(t, w.certifiedIPC(t, 25, "ERA-IPC-02"))
	if _, err := f.svc.ClosePeriod(f.ctx, c.controller, f.period(t), false); err != nil {
		t.Fatalf("close period: %v", err)
	}
	var postErr error
	for _, r := range f.svc.ApproveJournals(f.ctx, c.finMgr, []string{jInv2}) {
		postErr = errOf(r.OK, r.Error)
	}
	if postErr == nil {
		for _, r := range f.svc.PostJournals(f.ctx, c.controller, []string{jInv2}) {
			postErr = errOf(r.OK, r.Error)
		}
	}
	arDenied(t, "approving and posting an AR journal into a closed period", postErr, "CLOSED")
}

func errOf(ok bool, msg string) error {
	if ok {
		return nil
	}
	return errors.New(msg)
}

// The certificate hash used in the tests is the SHA-256 of "test".
func TestJourneyB_CertificateHashConstant(t *testing.T) {
	s := sha256.Sum256([]byte("test"))
	if hex.EncodeToString(s[:]) != arCertSHA {
		t.Fatal("arCertSHA is not sha256(\"test\")")
	}
}

// R6-F2: a wrong DRAFT receipt is cancelled through the kernel and its
// statement line is applied correctly afterwards; decisions stay human.
func TestJourneyB_CancelReceipt(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 15, "1000", "0", "0")
	inv, _ := w.approvedInvoice(t, w.certifiedIPC(t, 15, "ERA-IPC-01"))
	lines := w.statement(t, c.bankOfficer, "CBE-C-001", "0", "1000000", [3]string{"1000000", "ERA ADVANCE", "ERA"})
	wrong, err := f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{InvoiceID: inv, Amount: dec("1000000")}})
	if err == nil {
		t.Logf("note: over-allocation is refused only at confirmation; recorded draft %s", wrong[:8])
	} else {
		wrong, err = f.svc.RecordReceipt(f.ctx, w.ar.arClerk, lines[0], []ReceiptAllocation{{ContractID: ctr, Amount: dec("1000000")}})
		must(t, "wrong draft", err)
	}
	arDenied(t, "cancelling without a reason", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, wrong, ""), "reason")
	ai := w.ar.arClerk
	ai.UserID, ai.Kind = "u-ar-assistant", auth.KindAI
	arDenied(t, "cancellation by an AI principal", f.svc.CancelReceipt(f.ctx, ai, wrong, "Allocated to the wrong document"), "reserved to human principals")
	must(t, "cancel", f.svc.CancelReceipt(f.ctx, w.ar.arClerk, wrong, "Allocated to the wrong document"))
	_, err = f.svc.ConfirmReceipt(f.ctx, w.ar.arSup, wrong)
	arDenied(t, "confirming a cancelled receipt", err, "CANCELLED")
	// The line is free again: the correct receipt goes through.
	_, j := w.confirmedReceipt(t, lines[0], ReceiptAllocation{ContractID: ctr, Amount: dec("1000000")})
	w.financePost(t, j)
	if got := w.balance(t, "2200"); !got.Equal(dec("-1000000")) {
		t.Errorf("advance account after the corrected receipt: %s", got)
	}
}
