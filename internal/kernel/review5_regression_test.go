package kernel

// Independent review 5 probes for IA-040-01 (commit 0dcf5d3). Each probe
// asserts the SECURE behaviour: "held:" is logged when the control holds,
// t.Errorf "OPEN:" when it does not, "info:" for observations.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

const r5Random = "00000000-0000-4000-8000-0000000000aa"

func r5scoped(p auth.Principal, projects ...string) auth.Principal {
	p.ProjectIDs = projects
	p.UserID += "-scoped"
	return p
}

// r5released: the IA world's payment submitted, approved, released and its
// journals posted; returns the payment number.
func r5released(t *testing.T, w *iaWorld) string {
	t.Helper()
	f, c := w.f, w.cast
	must(t, "submit", f.svc.SubmitPayment(f.ctx, c.treasury, w.payment))
	st, err := f.svc.ApprovePayment(f.ctx, c.finMgr, w.payment)
	must(t, "approve", err)
	if st != "APPROVED" {
		t.Fatalf("payment status %s", st)
	}
	jid, err := f.svc.ReleasePayment(f.ctx, c.treasury2, w.payment)
	must(t, "release", err)
	w.financePost(t, jid)
	d, err := f.svc.GetP2PDoc(f.ctx, c.treasury, "payment_instruction", w.payment)
	must(t, "read payment", err)
	return d.Number
}

// ---------------------------------------------------------------------------
// Area 1/2: paths that bypass canSee because they use Has(scope.tenant_wide)
// instead of ScopeOf (a token that lists projects is restricted, SC-05).
// ---------------------------------------------------------------------------

func TestR5_01_TenantWideCheckIsNotTheVisibilityPolicy(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	payNo := r5released(t, w)
	P := f.project

	// (a) A project-restricted treasury officer can create an entity-level
	// document it is not allowed to see.
	sTreas := r5scoped(c.treasury2, P)
	_, _, po2 := w.awardedPO(t, "5", "10")
	_, _, inv2, _ := w.r3invoice(t, po2, "1", "R5-01")
	id, err := f.svc.PreparePayment(f.ctx, sTreas, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv2, dec("97175")}})
	if err == nil {
		_, gerr := f.svc.GetP2PDoc(f.ctx, sTreas, "payment_instruction", id)
		t.Errorf("OPEN: project-restricted treasury officer PREPARED payment instruction %s (entity-level); reading it back: %v", id[:8], gerr)
	} else {
		t.Logf("held: scoped PreparePayment refused: %v", err)
	}

	// (b) A project-restricted statement officer imports statements for a
	// company bank account and learns its balance from the continuity error.
	sBank := r5scoped(c.bankOfficer, P)
	st1, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R5-STMT-1", today(), "1000000", "902825",
		[3]string{"-97175", "TRF " + payNo + " ABC", "ABC STEEL PLC"}))
	must(t, "import (tenant-wide officer)", err)
	_, err = f.svc.ImportBankStatement(f.ctx, sBank, stmt(w.bank, "R5-STMT-2", today(), "1", "1"))
	if err != nil && strings.Contains(err.Error(), "902825") {
		t.Errorf("OPEN: project-restricted statement officer learns the company account balance from the error: %q", firstLine(err.Error()))
	} else {
		t.Logf("scoped import with wrong opening balance: %v", err)
	}
	if _, err := f.svc.ImportBankStatement(f.ctx, sBank, stmt(w.bank, "R5-STMT-3", today(), "902825", "902825")); err == nil {
		t.Errorf("OPEN: project-restricted statement officer IMPORTED a statement on an entity-level company account it cannot see")
	} else {
		t.Logf("held: scoped import refused: %v", err)
	}
	if _, err := f.svc.GetP2PDoc(f.ctx, sBank, "company_bank_account", w.bank); errors.Is(err, ErrNotFound) {
		t.Logf("      (the same officer gets not-found reading that company account: %v)", err)
	}

	// (c) A project-restricted accountant reconciles: the result carries the
	// payment number and id, and the payment is mutated to SETTLED, without
	// any canSee check on the payment instruction.
	sAcct := r5scoped(c.accountant, P)
	rec, err := f.svc.AutoReconcile(f.ctx, sAcct, st1)
	if err == nil {
		raw, _ := json.Marshal(rec)
		var status string
		_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status FROM payment_instructions WHERE id = $1::uuid`, w.payment).Scan(&status)
		})
		_, gerr := f.svc.GetP2PDoc(f.ctx, sAcct, "payment_instruction", w.payment)
		t.Errorf("OPEN: project-restricted accountant ran AutoReconcile: %s; payment now %s; same principal reading the payment: %v", raw, status, gerr)
	} else {
		t.Logf("held: scoped AutoReconcile refused: %v", err)
	}

	// (d) Journal worklist vs journal detail for the same principal.
	js, err := f.svc.ListJournals(f.ctx, sAcct, "", "P2P_", 200)
	if err == nil && len(js) > 0 {
		var payJ, otherProj int
		var sample string
		for _, j := range js {
			if j.SourceType == "P2P_PAYMENT" || j.SourceType == "P2P_SETTLEMENT" {
				payJ++
				sample = fmt.Sprintf("%s %q source_ref=%s debits=%s", j.SourceType, j.Description, j.SourceRef[:8], j.Debits)
			}
			if j.ProjectID != "" && j.ProjectID != P {
				otherProj++
			}
		}
		_, gerr := f.svc.GetJournal(f.ctx, sAcct, js[0].ID)
		_, rerr := f.svc.GetJournal(f.ctx, sAcct, r5Random)
		t.Errorf("OPEN: project-restricted accountant lists %d P2P journals (%d payment/settlement, e.g. %s); GetJournal of the first: %v", len(js), payJ, sample, gerr)
		if gerr != nil && rerr != nil && gerr.Error() != rerr.Error() {
			t.Errorf("OPEN (low): journal detail distinguishes out-of-scope (%v) from nonexistent (%v)", gerr, rerr)
		}
	} else {
		t.Logf("held: scoped ListJournals: %d rows, %v", len(js), err)
	}

	// (e) Subledger-to-GL reconciliation (payments in transit, bank) per entity.
	sCtrl := r5scoped(c.controller, P)
	if rc, err := f.svc.GLReconciliation(f.ctx, sCtrl, f.entity); err == nil {
		raw, _ := json.Marshal(rc)
		t.Errorf("OPEN: project-restricted controller reads entity-level GL reconciliation (%d checks): %.300s", len(rc), raw)
	} else {
		t.Logf("held: scoped GLReconciliation refused: %v", err)
	}

	// (f) Whoami reports tenant_wide for a restricted token (display only).
	if id := f.svc.Whoami(sAcct); id.TenantWide {
		t.Logf("info: Whoami(project-restricted accountant).TenantWide = true (console shows tenant-wide; ScopeOf says restricted)")
	}
}

// ---------------------------------------------------------------------------
// Area 3: masking -- every detail type, every principal; and where the full
// numbers are persisted (audit, outbox, attestations, workflow, ...).
// ---------------------------------------------------------------------------

func TestR5_02_MaskingAcrossAllDetailTypesAndStores(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	payNo := r5released(t, w)
	st, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R5-M-1", today(), "1000000", "902825",
		[3]string{"-97175", "TRF " + payNo, "ABC STEEL PLC"}))
	must(t, "import", err)
	_, err = f.svc.AutoReconcile(f.ctx, c.accountant, st)
	must(t, "reconcile", err)
	purpose := "Independent review 5: verify payee details before release"
	_, err = f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, purpose)
	must(t, "reveal", err)
	_, err = f.svc.RevealBankAccount(f.ctx, c.cfo, "company_bank_account", w.bank, purpose)
	must(t, "reveal company", err)

	var snapshot string
	ids := map[string][]string{}
	_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT bank_snapshot FROM payment_instructions WHERE id = $1::uuid`, w.payment).Scan(&snapshot)
		for typ, tbl := range map[string]string{"p2p_policy": "p2p_policies", "supplier": "suppliers", "supplier_bank_account": "supplier_bank_accounts",
			"company_bank_account": "company_bank_accounts", "boq_version": "boq_versions", "purchase_requisition": "purchase_requisitions", "rfq": "rfqs",
			"rfq_quote": "rfq_quotes", "purchase_order": "purchase_orders", "grn": "grns", "supplier_invoice": "supplier_invoices", "payment_instruction": "payment_instructions"} {
			rows, err := tx.Query(ctx, `SELECT id::text FROM `+tbl)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				_ = rows.Scan(&id)
				ids[typ] = append(ids[typ], id)
			}
			rows.Close()
		}
		return nil
	})
	secrets := []string{iaSupplierAcct, iaCompanyAcct}
	if snapshot != "" {
		secrets = append(secrets, snapshot)
	}
	readers := map[string]auth.Principal{"cfo": c.cfo, "finance manager": c.finMgr, "treasury": c.treasury, "controller": c.controller,
		"auditor-tw": {UserID: "u-aud", TenantID: f.tenant, Roles: []string{"auditor"}, Kind: auth.KindHuman},
		"buyer":      c.buyer, "pm": c.pm, "ap supervisor": c.apSup}
	reads, leaks := 0, 0
	for who, p := range readers {
		for typ, list := range ids {
			for _, id := range list {
				d, err := f.svc.GetP2PDoc(f.ctx, p, typ, id)
				if err != nil {
					continue
				}
				reads++
				raw, _ := json.Marshal(d)
				for _, s := range secrets {
					if strings.Contains(string(raw), s) {
						leaks++
						t.Errorf("OPEN: %s reading %s %s gets %q", who, typ, id[:8], s[:8])
					}
				}
			}
			items, err := f.svc.ListP2PDocs(f.ctx, p, typ, "", 500)
			if err == nil {
				raw, _ := json.Marshal(items)
				for _, s := range secrets {
					if strings.Contains(string(raw), s) {
						leaks++
						t.Errorf("OPEN: %s listing %s gets %q", who, typ, s[:8])
					}
				}
			}
		}
	}
	if leaks == 0 {
		t.Logf("held: %d successful detail reads across %d types and %d principals (+ lists): no full account number, no bank_snapshot", reads, len(ids), len(readers))
	}
	// Bank statement list (another type in listSQL).
	if items, err := f.svc.ListP2PDocs(f.ctx, c.accountant, "bank_statement", "", 50); err == nil {
		raw, _ := json.Marshal(items)
		t.Logf("info: bank_statement list for accountant: %.200s", raw)
	}

	// Where are the full numbers persisted? Scan every table as the operator.
	rows, err := f.admin.Query(f.ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`)
	must(t, "tables", err)
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tbl := range tables {
		for _, s := range []string{iaSupplierAcct, iaCompanyAcct} {
			var n int
			if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM public.`+tbl+` x WHERE x::text LIKE '%' || $1 || '%'`, s).Scan(&n); err != nil {
				t.Logf("scan %s: %v", tbl, err)
				continue
			}
			if n > 0 {
				msg := fmt.Sprintf("full number %s...%s stored in %s (%d rows)", s[:2], s[len(s)-2:], tbl, n)
				if tbl == "supplier_bank_accounts" || tbl == "company_bank_accounts" {
					t.Logf("held: %s (expected master table)", msg)
				} else {
					t.Errorf("OPEN: %s", msg)
				}
			}
		}
	}
	// What the audit records of the add and the reveal contain.
	_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT action, payload::text FROM audit_log WHERE action IN ('supplier.bank.add', 'bank.details.reveal') ORDER BY seq`)
		if err != nil {
			t.Logf("audit query: %v", err)
			return nil
		}
		defer r.Close()
		for r.Next() {
			var a, p string
			_ = r.Scan(&a, &p)
			t.Logf("info: audit %-20s %s", a, p)
			if strings.Contains(p, "*****") {
				t.Errorf("OPEN: audit %s reveals the account-number length: %s", a, p)
			}
		}
		return nil
	})
}

// A company account number can be confirmed by registering a guess: the
// unique constraint answers "already exists" (constraint name in the error)
// while a wrong guess succeeds (and leaves a PENDING row).
func TestR5_03_CompanyAccountNumberGuessOracle(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	wrong := iaCompanyAcct[:len(iaCompanyAcct)-6] + "000777" // a wrong guess
	_, e1 := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury2, f.entity, "Guess A", wrong, "ETB", w.acct["1000"], w.acct["1050"])
	_, e2 := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury2, f.entity, "Guess B", iaCompanyAcct, "ETB", w.acct["1000"], w.acct["1050"])
	t.Logf("wrong guess -> %v", e1)
	t.Logf("right guess -> %v", e2)
	// Accepted residual (ISSUE_REGISTER IA-040-F3): company account numbers
	// are the company's own and known to treasury; a duplicate registration
	// must be refused, so success vs refusal cannot be hidden. Mitigation:
	// a generic error and an audited attempt (masked number only).
	if e1 == nil && e2 != nil {
		if !errors.Is(e2, ErrInvalidInput) || strings.Contains(e2.Error(), "company_bank_accounts") {
			t.Errorf("OPEN: duplicate registration error is not generic: %v", e2)
		}
		var n int
		_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'bankacct.register_refused' AND actor_id = 'u-treasury-2'`).Scan(&n)
		})
		if n != 1 {
			t.Errorf("OPEN: refused duplicate registration not audited (%d records)", n)
		} else {
			t.Logf("held (accepted residual): duplicate refused generically and audited")
		}
	}
	if e2 != nil && strings.Contains(e2.Error(), iaCompanyAcct) {
		t.Errorf("OPEN: error echoes the full number")
	}
	// Supplier accounts: no uniqueness, so duplicates are accepted (no oracle).
	_, e3 := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "CBE", "dup", iaSupplierAcct, "ETB")
	t.Logf("supplier duplicate -> %v (no uniqueness: no oracle, but duplicates allowed)", e3)
	// Invalid number: the error does not echo it.
	_, e4 := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "CBE", "bad", "abc-123456789xyz", "ETB")
	if e4 != nil && strings.Contains(e4.Error(), "123456789") {
		t.Errorf("OPEN: invalid-number error echoes the number: %v", e4)
	} else {
		t.Logf("held: invalid supplier account rejected without echo: %v", e4)
	}
}

// ---------------------------------------------------------------------------
// Area 4: reveal
// ---------------------------------------------------------------------------

func TestR5_04_Reveal(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	purpose := "Independent review 5: call-back verification of payee"
	audits := func() int {
		var n int
		_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'bank.details.reveal'`).Scan(&n)
		})
		return n
	}
	// Wrong / case-variant types for an existing id.
	for _, typ := range []string{"payment_instruction", "supplier", "Supplier_Bank_Account", "supplier_bank_account ", "SUPPLIER_BANK_ACCOUNT"} {
		_, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, typ, w.supBank, purpose)
		if errors.Is(err, ErrNotFound) {
			t.Logf("held: reveal type %-24q -> not found", typ)
		} else {
			t.Errorf("OPEN: reveal type %q -> %v", typ, err)
		}
	}
	// Purpose: trimmed, byte-length; low-quality purposes accepted.
	if _, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, "                   x                  "); errors.Is(err, ErrInvalidInput) {
		t.Logf("held: whitespace-padded purpose refused")
	} else {
		t.Errorf("OPEN: padded purpose -> %v", err)
	}
	for _, p := range []string{strings.Repeat("a", 20), "ሰላምሰላምሰላም"} {
		if _, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, p); err == nil {
			t.Logf("info: purpose %q (%d runes) accepted", p, len([]rune(p)))
		}
	}
	// MFA freshness boundary.
	for _, age := range []time.Duration{9 * time.Minute, 11 * time.Minute} {
		p := c.finMgr
		p.AuthTime = time.Now().Add(-age)
		_, err := f.svc.RevealBankAccount(f.ctx, p, "supplier_bank_account", w.supBank, purpose)
		t.Logf("MFA age %v -> %v", age, err)
		if age > 10*time.Minute && !errors.Is(err, auth.ErrStepUpRequired) {
			t.Errorf("OPEN: stale MFA accepted")
		}
	}
	noMFA := c.finMgr
	noMFA.MFA = false
	if _, err := f.svc.RevealBankAccount(f.ctx, noMFA, "supplier_bank_account", w.supBank, purpose); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Errorf("OPEN: no MFA -> %v", err)
	}
	// Replay: every reveal audited.
	before := audits()
	for i := 0; i < 2; i++ {
		_, err := f.svc.RevealBankAccount(f.ctx, c.finMgr, "supplier_bank_account", w.supBank, purpose)
		must(t, "reveal", err)
	}
	if got := audits() - before; got != 2 {
		t.Errorf("OPEN: 2 reveals produced %d audit records", got)
	} else {
		t.Logf("held: 2 identical reveals -> 2 audit records")
	}
	// Failed probes (nonexistent / out of scope) are not audited.
	scoped := r5scoped(c.finMgr, f.project)
	before = audits()
	_, e1 := f.svc.RevealBankAccount(f.ctx, scoped, "company_bank_account", w.bank, purpose)
	_, e2 := f.svc.RevealBankAccount(f.ctx, scoped, "company_bank_account", r5Random, purpose)
	_, e3 := f.svc.RevealBankAccount(f.ctx, c.finMgr, "company_bank_account", r5Random, purpose)
	if e1 == nil || e2 == nil || e1.Error() != e2.Error() || e2.Error() != e3.Error() {
		t.Errorf("OPEN: reveal existence disclosure: out-of-scope %v / random %v / random(tenant-wide) %v", e1, e2, e3)
	} else {
		t.Logf("held: reveal out-of-scope == nonexistent: %v", e1)
	}
	t.Logf("info: audit records for 3 refused reveal attempts: %d (failed attempts leave no audit trail)", audits()-before)
	// Cross-tenant.
	out := f.outsider
	out.Roles, out.MFA, out.AuthTime = []string{"cfo"}, true, time.Now()
	if _, err := f.svc.RevealBankAccount(f.ctx, out, "company_bank_account", w.bank, purpose); errors.Is(err, ErrNotFound) {
		t.Logf("held: cross-tenant reveal -> not found")
	} else {
		t.Errorf("OPEN: cross-tenant reveal -> %v", err)
	}
	// Revoked session.
	victim := c.cfo
	if _, err := f.svc.RevokeSessions(f.ctx, victim, victim.UserID, "review 5 revocation probe"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.svc.RevealBankAccount(f.ctx, victim, "company_bank_account", w.bank, purpose); errors.Is(err, ErrSessionRevoked) {
		t.Logf("held: reveal with a revoked session -> %v", err)
	} else {
		t.Errorf("OPEN: reveal with a revoked session -> %v", err)
	}
	// Are ordinary reads also refused for the revoked session at the kernel?
	if _, err := f.svc.GetP2PDoc(f.ctx, victim, "company_bank_account", w.bank); err == nil {
		t.Logf("info: GetP2PDoc does not re-check revocation in the kernel (the HTTP layer does, on every request)")
	}

	// A role that combines supplier.manage with bank.details.reveal (roles are
	// tenant data in production): canSee lets ANY project-restricted
	// supplier.manage holder see every supplier's bank account, so the reveal
	// is not project-scoped either.
	roles := map[string]auth.Role{}
	for k, v := range auth.DefaultRoles {
		roles[k] = v
	}
	roles["procurement_lead"] = auth.Role{Name: "procurement_lead", Permissions: []auth.Permission{auth.PermSupplierManage, auth.PermBankDetailsReveal, auth.PermP2PRead}}
	svc2 := New(f.app, auth.NewAuthorizer(roles, true)).UseApprovalSigner(attest.Signer{Master: testdb.ApprovalMaster}).UseBankDataKeys(testdb.BankDataKeys)
	lead := auth.Principal{UserID: "u-proc-lead", TenantID: f.tenant, Roles: []string{"procurement_lead"}, ProjectIDs: []string{w.other},
		IssuedAt: time.Now().Add(-time.Minute), Kind: auth.KindHuman, MFA: true, AuthTime: time.Now()}
	if got, err := svc2.RevealBankAccount(f.ctx, lead, "supplier_bank_account", w.supBank, purpose); err == nil {
		t.Errorf("OPEN: project-restricted (other project) holder of supplier.manage+bank.details.reveal revealed %s", MaskAccount(got.AccountNumber))
	} else if !errors.Is(err, ErrNotFound) {
		t.Errorf("project-restricted reveal refused with %v, want not-found", err)
	} else {
		t.Logf("held: %v", err)
	}
	// Reveal needs no p2p.read.
	roles["revealer"] = auth.Role{Name: "revealer", Permissions: []auth.Permission{auth.PermBankDetailsReveal, auth.PermScopeTenantWide}}
	svc3 := New(f.app, auth.NewAuthorizer(roles, true)).UseApprovalSigner(attest.Signer{Master: testdb.ApprovalMaster}).UseBankDataKeys(testdb.BankDataKeys)
	rv := auth.Principal{UserID: "u-revealer", TenantID: f.tenant, Roles: []string{"revealer"}, Kind: auth.KindHuman, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute)}
	_, err := svc3.RevealBankAccount(f.ctx, rv, "company_bank_account", w.bank, purpose)
	if err == nil {
		t.Errorf("OPEN: reveal by a principal without p2p.read succeeded")
	} else {
		t.Logf("held: reveal without p2p.read -> %v", err)
	}
}

// ---------------------------------------------------------------------------
// Area 5: existence disclosure on mutations
// ---------------------------------------------------------------------------

func TestR5_05_MutationExistenceDisclosure(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	must(t, "submit", f.svc.SubmitPayment(f.ctx, c.treasury, w.payment))
	// a PENDING company account and supplier bank account
	pendBank, err := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "Pending", "1000555444333", "ETB", w.acct["1000"], w.acct["1050"])
	must(t, "pending bank", err)
	pendSup, err := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[1], "CBE", "Habesha", "1000222333444", "ETB")
	must(t, "pending sup bank", err)
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "review 5 probe", nil, []PRLine{{LineNo: 1, CostCodeID: w.costCode, Description: "probe line", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("1")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))

	P := f.project
	otherPM := auth.Principal{UserID: "u-pm-other", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{w.other}, Kind: auth.KindHuman}
	cases := []struct {
		name string
		real string
		fn   func(id string) error
	}{
		{"ApprovePayment(scoped FM)", w.payment, func(id string) error { _, e := f.svc.ApprovePayment(f.ctx, r5scoped(c.finMgr, P), id); return e }},
		{"ReleasePayment(scoped treasury2)", w.payment, func(id string) error { _, e := f.svc.ReleasePayment(f.ctx, r5scoped(c.treasury2, P), id); return e }},
		{"CancelPayment(scoped treasury)", w.payment, func(id string) error {
			return f.svc.CancelPayment(f.ctx, r5scoped(c.treasury, P), id, "review 5 probe reason")
		}},
		{"SubmitPayment(scoped treasury)", w.payment, func(id string) error { return f.svc.SubmitPayment(f.ctx, r5scoped(c.treasury, P), id) }},
		{"DecideP2PPolicy(scoped cfo)", w.policy, func(id string) error { return f.svc.DecideP2PPolicy(f.ctx, r5scoped(c.cfo, P), id, false) }},
		{"ApproveCompanyBank(scoped cfo)", pendBank, func(id string) error { return f.svc.ApproveCompanyBankAccount(f.ctx, r5scoped(c.cfo, P), id) }},
		{"ApproveSupplierBank(scoped FM)", pendSup, func(id string) error { return f.svc.ApproveSupplierBankAccount(f.ctx, r5scoped(c.finMgr, P), id) }},
		{"DecidePR(other-project PM)", pr, func(id string) error { return f.svc.DecidePR(f.ctx, otherPM, id, true, "") }},
		{"GetP2PDoc payment(pm)", w.payment, func(id string) error { _, e := f.svc.GetP2PDoc(f.ctx, c.pm, "payment_instruction", id); return e }},
		{"GetP2PDoc PR(other PM)", pr, func(id string) error { _, e := f.svc.GetP2PDoc(f.ctx, otherPM, "purchase_requisition", id); return e }},
	}
	for _, k := range cases {
		e1, e2 := k.fn(k.real), k.fn(r5Random)
		switch {
		case e1 == nil:
			t.Errorf("OPEN: %s on an out-of-scope document SUCCEEDED", k.name)
		case e2 == nil || e1.Error() != e2.Error():
			t.Errorf("OPEN: %s distinguishes: real=%v random=%v", k.name, e1, e2)
		default:
			t.Logf("held: %-36s real == random: %v", k.name, e1)
		}
	}

	// Row lock taken BEFORE the visibility check: an out-of-scope caller
	// blocks behind another transaction's lock on a document that exists, and
	// returns at once for one that does not (deterministic existence oracle).
	tx, err := f.app.BeginTenant(f.ctx, f.tenant)
	must(t, "begin", err)
	if _, err := tx.Exec(f.ctx, `SELECT 1 FROM payment_instructions WHERE id = $1::uuid FOR UPDATE`, w.payment); err != nil {
		t.Fatalf("lock: %v", err)
	}
	timed := func(id string) (time.Duration, error) {
		ctx, cancel := context.WithTimeout(f.ctx, 1500*time.Millisecond)
		defer cancel()
		t0 := time.Now()
		_, err := f.svc.ApprovePayment(ctx, r5scoped(c.finMgr, P), id)
		return time.Since(t0), err
	}
	dR, eR := timed(w.payment)
	dN, eN := timed(r5Random)
	_ = tx.Rollback(f.ctx)
	t.Logf("locked out-of-scope payment: %v after %v; nonexistent: %v after %v", eR, dR.Round(time.Millisecond), eN, dN.Round(time.Millisecond))
	if dR > time.Second && dN < 500*time.Millisecond {
		t.Errorf("OPEN (low): out-of-scope mutation takes FOR UPDATE before canSee: blocks %v on an existing locked document vs %v for a nonexistent id", dR.Round(time.Millisecond), dN.Round(time.Millisecond))
	}
}

// ---------------------------------------------------------------------------
// Area 2: scope semantics
// ---------------------------------------------------------------------------

func TestR5_06_ScopeSemantics(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	_, _, po := w.awardedPO(t, "5", "10")
	none := auth.Principal{UserID: "u-none", TenantID: f.tenant, Kind: auth.KindHuman}
	_, e1 := f.svc.GetP2PDoc(f.ctx, none, "purchase_order", po)
	_, e2 := f.svc.GetP2PDoc(f.ctx, none, "purchase_order", r5Random)
	_, e3 := f.svc.ListP2PDocs(f.ctx, none, "purchase_order", "", 10)
	if errors.Is(e1, auth.ErrForbidden) && e1.Error() == e2.Error() && errors.Is(e3, auth.ErrForbidden) {
		t.Logf("held: no roles -> forbidden for real and random ids and lists (%v)", e1)
	} else {
		t.Errorf("OPEN: no-role principal: %v / %v / %v", e1, e2, e3)
	}
	// p2p.read without project list and without tenant-wide.
	unscoped := auth.Principal{UserID: "u-est", TenantID: f.tenant, Roles: []string{"estimator"}, Kind: auth.KindHuman}
	if _, err := f.svc.GetP2PDoc(f.ctx, unscoped, "purchase_order", po); errors.Is(err, ErrNotFound) {
		t.Logf("held: p2p.read with empty project list and no tenant_wide -> not found")
	} else {
		t.Errorf("OPEN: empty-scope estimator reads PO: %v", err)
	}
	if l, _ := f.svc.ListP2PDocs(f.ctx, unscoped, "purchase_order", "", 10); len(l) != 0 {
		t.Errorf("OPEN: empty-scope estimator lists %d POs", len(l))
	}
	// tenant_wide role + project list of another project.
	tw := auth.Principal{UserID: "u-aud2", TenantID: f.tenant, Roles: []string{"auditor"}, ProjectIDs: []string{w.other}, Kind: auth.KindHuman}
	for typ, id := range map[string]string{"purchase_order": po, "supplier_bank_account": w.supBank, "payment_instruction": w.payment} {
		if _, err := f.svc.GetP2PDoc(f.ctx, tw, typ, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("OPEN: tenant_wide role + other-project list reads %s: %v", typ, err)
		}
	}
	t.Logf("held: tenant_wide role + project list confined to its projects")
	// Project list containing "" or the id in upper case.
	odd := auth.Principal{UserID: "u-odd", TenantID: f.tenant, Roles: []string{"auditor"}, ProjectIDs: []string{"", strings.ToUpper(f.project)}, Kind: auth.KindHuman}
	for typ, id := range map[string]string{"purchase_order": po, "payment_instruction": w.payment, "p2p_policy": w.policy} {
		_, err := f.svc.GetP2PDoc(f.ctx, odd, typ, id)
		t.Logf("project list [\"\", UPPER(project)] reading %s -> %v", typ, err)
		if err == nil && typ != "purchase_order" {
			t.Errorf("OPEN: odd project list reads entity-level %s", typ)
		}
	}
	// Cross tenant.
	for typ, id := range map[string]string{"purchase_order": po, "payment_instruction": w.payment, "supplier": w.sup[0]} {
		if _, err := f.svc.GetP2PDoc(f.ctx, f.outsider, typ, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("OPEN: cross-tenant %s -> %v", typ, err)
		}
	}
	t.Logf("held: cross-tenant ids -> not found")
	// Unknown types and case variants.
	for _, typ := range []string{"Payment_Instruction", "PAYMENT_INSTRUCTION", "payment_instruction ", "bank_statement", "bank_statement_line", "journal", ""} {
		_, eReal := f.svc.GetP2PDoc(f.ctx, c.cfo, typ, w.payment)
		_, eRand := f.svc.GetP2PDoc(f.ctx, c.cfo, typ, r5Random)
		t.Logf("type %-24q real -> %v | random -> %v", typ, eReal, eRand)
		if eReal == nil {
			t.Errorf("OPEN: type %q returns a document", typ)
		}
	}
	// Malformed / variant ids at the kernel boundary.
	for _, id := range []string{strings.ToUpper(w.payment), "{" + w.payment + "}", strings.ReplaceAll(w.payment, "-", ""), "urn:uuid:" + w.payment, "x' OR '1'='1"} {
		d, err := f.svc.GetP2PDoc(f.ctx, c.pm, "payment_instruction", id)
		d2, err2 := f.svc.GetP2PDoc(f.ctx, c.cfo, "payment_instruction", id)
		t.Logf("id %-46q pm -> %v | cfo -> err=%v detail=%dB", id, err, err2, len(d2.Detail))
		if err == nil {
			t.Errorf("OPEN: pm reads payment via id variant %q (%dB)", id, len(d.Detail))
		}
	}
	// Project roles reading project documents that embed other data.
	_, rfq, _ := w.awardedPO(t, "1", "1")
	d, err := f.svc.GetP2PDoc(f.ctx, c.store, "rfq", rfq)
	if err == nil {
		t.Logf("info: storekeeper (p2p.read only) reads RFQ with all quotes/prices: %dB", len(d.Detail))
	}
	if d, err := f.svc.GetP2PDoc(f.ctx, c.store, "supplier", w.sup[0]); err == nil {
		t.Logf("info: storekeeper reads supplier master (tax id) by design: %.160s", d.Detail)
	}
}

// The approval attestations store sha256(p2p_subject_text(...)), i.e. a hash
// over the full row INCLUDING the account number. Everything else in that row
// is in the masked projection, so whoever can read approval_attestations (any
// tenant-database reader; no API exposes it today) can confirm guesses offline.
// The guess is checked using ONLY the masked API response + tenant id.
func TestR5_07_AttestationHashConfirmsGuessedAccountNumber(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	d, err := f.svc.GetP2PDoc(f.ctx, c.buyer, "supplier_bank_account", w.supBank)
	must(t, "masked read", err)
	var stored string
	_ = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT subject_hash FROM approval_attestations WHERE subject_type = 'supplier_bank_account' AND subject_id = $1 AND action = 'supplier.bank.approve'`, w.supBank).Scan(&stored)
	})
	if stored == "" {
		t.Skip("no attestation row found")
	}
	// Attacker knows the masked "****6789" and searches 1000 xxxxx 6789 (10^5
	// synthetic candidates), using only the masked JSON and the tenant id.
	hit, tried := "", 100000
	err = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE((SELECT g FROM (SELECT '1000' || lpad(i::text, 5, '0') || '6789' AS g FROM generate_series(0, 99999) i) c
			WHERE encode(sha256(convert_to((($1::jsonb - 'account_number_masked')
				|| jsonb_build_object('account_number', c.g, 'tenant_id', $2::text, 'status', 'PENDING', 'approved_by', NULL, 'approved_at', NULL))::text, 'UTF8')), 'hex') = $3
			LIMIT 1), '')`, string(d.Detail), f.tenant, stored).Scan(&hit)
	})
	must(t, "search", err)
	if hit != "" {
		t.Errorf("OPEN (info/low): the stored approval subject hash confirms the account number %s from the masked projection after %d guesses", MaskAccount(hit)+" (full match)", tried)
	} else {
		t.Logf("held: no match after %d guesses", tried)
	}
}
