package kernel

// Independent review 4 probes: re-verification of 0014 (fixes for review 3).
// Convention: "held:" = control holds; t.Errorf("OPEN: ...") = weakness
// reproduced; "OBSERVATION:" = fact recorded without a verdict.

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
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func r4obs(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("OBSERVATION: "+format, args...)
}

// r4accounts creates extra accounts as the operator.
func (w *p2pWorld) r4accounts(t *testing.T, defs ...[3]string) {
	t.Helper()
	f := w.f
	err := f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, a := range defs {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: a[0], Name: a[1], Type: ledger.AccountType(a[2]), Active: true})
			if err != nil {
				return err
			}
			w.acct[a[0]] = id
		}
		return nil
	})
	must(t, "extra accounts", err)
}

// r4award: approved 2-line PR, single-source RFQ, quote recorded by the buyer
// for the given lines only; returns rfq and quote.
func (w *p2pWorld) r4award(t *testing.T, award bool, lines ...QuoteLine) (string, string) {
	t.Helper()
	f, c := w.f, w.cast
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "R4 PR", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Steel", Unit: "t", Quantity: dec("1"), EstUnitPrice: dec("86000")},
		{LineNo: 2, CostCodeID: w.costCode, Description: "Cement", Unit: "bag", Quantity: dec("10"), EstUnitPrice: dec("950")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(48*time.Hour), 1, "Only supplier with stock this quarter", w.sup[:1])
	must(t, "rfq", err)
	must(t, "issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q, err := f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[0], time.Now().AddDate(0, 1, 0), "R4", lines)
	must(t, "quote", err)
	if award {
		must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q, true, ""))
		must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q, ""))
	}
	return rfq, q
}

// r4import stores a statement file with raw SQL under a genuine statement
// officer attestation; mutate may change the lines that are stored.
func (w *p2pWorld) r4import(ctx context.Context, tx pgx.Tx, file []byte, mutate func([]StatementLine) []struct {
	no int
	l  StatementLine
}) (string, error) {
	f, c := w.f, w.cast
	in, err := ParseStatement(file)
	if err != nil {
		return "", err
	}
	if err := f.authorizeIn(ctx, tx, c.bankOfficer, "bank.import", "bank_statement_source", in.SourceSHA256, in.CompanyBankID+"|"+in.ContentDigest()); err != nil {
		return "", err
	}
	var sid string
	if err := tx.QueryRow(ctx, `INSERT INTO bank_statements(company_bank_id, statement_no, statement_date, opening_balance, closing_balance, source_sha256, imported_by)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, 'u-bank-officer') RETURNING id::text`, in.CompanyBankID, in.StatementNo, in.StatementDate, in.OpeningBalance, in.ClosingBalance, in.SourceSHA256).Scan(&sid); err != nil {
		return "", err
	}
	type nl = struct {
		no int
		l  StatementLine
	}
	var rows []nl
	if mutate != nil {
		rows = mutate(in.Lines)
	} else {
		for i, l := range in.Lines {
			rows = append(rows, nl{i + 1, l})
		}
	}
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `INSERT INTO bank_statement_lines(statement_id, line_no, booking_date, amount, reference, counterparty) VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			sid, r.no, r.l.BookingDate, r.l.Amount, r.l.Reference, r.l.Counterparty); err != nil {
			return "", err
		}
	}
	return sid, nil
}

// ---------------------------------------------------------------------------
// H1 creator binding
// ---------------------------------------------------------------------------
func TestR4_01_CreatorBinding(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast

	r3held(t, "tenant login SET session_replication_role = replica", f.rawExec(`SET LOCAL session_replication_role = replica`))
	r3held(t, "tenant login ALTER TABLE suppliers DISABLE TRIGGER suppliers_created_by", f.rawExec(`ALTER TABLE suppliers DISABLE TRIGGER suppliers_created_by`))
	r3held(t, "tenant login UPDATE suppliers.created_by", f.rawExec(`UPDATE suppliers SET created_by = 'u-someone' WHERE id = $1::uuid`, w.sup[0]))
	r3held(t, "tenant login UPDATE supplier_bank_accounts.created_by", f.rawExec(`UPDATE supplier_bank_accounts SET created_by = 'u-someone' WHERE id = $1::uuid`, w.supBank))
	r3held(t, "tenant login UPDATE rfq_quotes.received_by", f.rawExec(`UPDATE rfq_quotes SET received_by = 'u-someone' WHERE true`))
	r3held(t, "tenant login CREATE FUNCTION (to call approval_use from its own trigger)", f.rawExec(`CREATE FUNCTION r4x() RETURNS int LANGUAGE sql AS 'SELECT 1'`))

	// SET CONSTRAINTS tricks.
	r3held(t, "SET CONSTRAINTS ALL IMMEDIATE, forged supplier + checker's own create attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			return err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'R4-IMM', 'Imm PLC', 'u-buyer') RETURNING id::text`, f.entity).Scan(&id); err != nil {
			return err
		}
		return f.authorizeIn(ctx, tx, c.procMgr, "supplier.create", "supplier", id, "")
	}))
	r3held(t, "SET CONSTRAINTS suppliers_created_by DEFERRED then forged insert", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS suppliers_created_by DEFERRED`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'R4-DEF', 'Def PLC', 'u-buyer')`, f.entity)
		return err
	}))

	// Another document's create attestation (here: u-buyer's genuine one for row Y) does not cover row X.
	r3held(t, "forged row X alongside row Y that carries u-buyer's genuine create attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		var y string
		if err := tx.QueryRow(ctx, `INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'R4-Y', 'Y PLC', 'u-buyer') RETURNING id::text`, f.entity).Scan(&y); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, c.buyer, "supplier.create", "supplier", y, ""); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'R4-X', 'X PLC', 'u-buyer')`, f.entity)
		return err
	}))
	// Two rows, one statement, one attestation.
	r3held(t, "two supplier rows in one INSERT with one create attestation", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `INSERT INTO suppliers(legal_entity_id, code, name, created_by) VALUES ($1::uuid, 'R4-T1', 'T1 PLC', 'u-buyer'), ($1::uuid, 'R4-T2', 'T2 PLC', 'u-buyer') RETURNING id::text`, f.entity)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			ids = append(ids, s)
		}
		rows.Close()
		return f.authorizeIn(ctx, tx, c.buyer, "supplier.create", "supplier", ids[0], "")
	}))
	// Attest, then mutate before commit (approve in the same transaction).
	err := f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO supplier_bank_accounts(supplier_id, bank_name, account_name, account_number, currency, created_by)
			VALUES ($1::uuid, 'Ghost Bank', 'ABC Steel PLC', 'GHOST0001113', 'ETB', 'u-buyer') RETURNING id::text`, w.sup[0]).Scan(&id); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, c.buyer, "supplier.bank.create", "supplier_bank_account", id, ""); err != nil {
			return err
		}
		if err := f.authorizeIn(ctx, tx, c.finMgr, "supplier.bank.approve", "supplier_bank_account", id, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE supplier_bank_accounts SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, id)
		return err
	})
	r3held(t, "bank details attested at creation then approved (mutated) in the same transaction", err)

	// Quote content added after the receiver's attested creation (later
	// transaction, raw tenant SQL, no attestation at all).
	w.approvedBOQ(t)
	rfq, q := w.r4award(t, false, QuoteLine{1, dec("85000")})
	before := f.scalar(t, `SELECT total::text FROM rfq_quotes WHERE id=$1::uuid`, q)
	err = f.rawExec(`INSERT INTO rfq_quote_lines(quote_id, pr_line_no, unit_price) VALUES ($1::uuid, 2, 1)`, q)
	if err == nil {
		after := f.scalar(t, `SELECT total::text FROM rfq_quotes WHERE id=$1::uuid`, q)
		t.Errorf("OPEN: unattested raw INSERT of a quote line into a quote 'received_by u-buyer' (total %s -> %s)", before, after)
		e1 := f.svc.EvaluateQuote(f.ctx, c.siteEng, q, true, "")
		e2 := f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q, "")
		r4obs(t, "the altered quote is then evaluated (err=%v) and awarded (err=%v); received_by=%s", e1, e2,
			f.scalar(t, `SELECT received_by FROM rfq_quotes WHERE id=$1::uuid`, q))
	} else {
		t.Logf("held: raw quote line after creation: %s", firstLine(err.Error()))
	}
}

// ---------------------------------------------------------------------------
// H2 statement binding
// ---------------------------------------------------------------------------
func TestR4_02_StatementDigestDifferential(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	day := today().Format("2006-01-02")
	closing := decimal.Zero
	type ln struct{ amt, ref, cp string } // raw JSON literals
	cases := []struct {
		name, no, opening string
		lines             []ln
	}{
		{"negative-zero opening", `"R4-D0"`, `"-0.00"`, []ln{{`-1.5`, `"PAY|1\nX"`, `"a|b"`}}},
		{"pipe/newline/CR in text", `"R4-D1"`, "", []ln{{`"-2"`, `"a|b\r\n|c"`, `"\n"`}}},
		{"combining vs precomposed", `"R4-D2"`, "", []ln{{`"-0.01"`, `"e\u0301"`, `"\u00e9"`}}},
		{"6 decimals on a 2-decimal currency", `"R4-D2b"`, "", []ln{{`"-0.000001"`, `"x"`, `""`}}},
		{"emoji, tab, U+2028", `"R4-D3"`, "", []ln{{`1e2`, `"😀\t "`, `""`}}},
		{"lone surrogate", `"R4-D4"`, "", []ln{{`-2.0000000`, `"\ud800"`, `"x"`}}},
		{"invalid UTF-8 byte", `"R4-D5"`, "", []ln{{`-3`, "\"bad\xffbyte\"", `"x"`}}},
		{"7 decimals non-zero", `"R4-D6"`, "", []ln{{`-0.1234567`, `"x"`, `"y"`}}},
		{"NUL in reference", `"R4-D7"`, "", []ln{{`-1`, `"a\u0000b"`, `"y"`}}},
		{"18 integer digits", `"R4-D8"`, "", []ln{{`999999999999999999.99`, `"in"`, `""`}, {`-999999999999999999.99`, `"out"`, `""`}}},
		{"19 integer digits", `"R4-D9"`, "", []ln{{`9999999999999999999`, `"in"`, `""`}, {`-9999999999999999999`, `"out"`, `""`}}},
		{"zero amount", `"R4-D10"`, "", []ln{{`0`, `"z"`, `""`}}},
		{"unicode statement_no", `"R4-Ñ/1|2"`, "", []ln{{`-1`, `"u"`, `""`}}},
		{"duplicate JSON key (last wins)", `"R4-D12"`, "", []ln{{`1, "amount": -5`, `"dup"`, `""`}}},
		{"amount as string with spaces", `"R4-D13"`, "", []ln{{`" -1 "`, `"s"`, `""`}}},
	}
	for _, cs := range cases {
		sum := decimal.Zero
		var parts []string
		for _, l := range cs.lines {
			lit := strings.Trim(strings.SplitN(l.amt, ",", 2)[0], `" `)
			if strings.Contains(l.amt, `"amount": -5`) {
				lit = "-5"
			}
			if d, err := decimal.NewFromString(lit); err == nil {
				sum = sum.Add(d)
			}
			parts = append(parts, fmt.Sprintf(`{"booking_date":"%s","amount":%s,"reference":%s,"counterparty":%s}`, day, l.amt, l.ref, l.cp))
		}
		open := cs.opening
		if open == "" {
			open = `"` + closing.StringFixed(6) + `"`
		}
		openD, _ := decimal.NewFromString(strings.Trim(open, `"`))
		cl := openD.Add(sum)
		raw := []byte(fmt.Sprintf(`{"company_bank_id":"%s","statement_no":%s,"statement_date":"%s","opening_balance":%s,"closing_balance":"%s","lines":[%s]}`,
			w.bank, cs.no, day, open, cl.StringFixed(6), strings.Join(parts, ",")))
		in, perr := ParseStatement(raw)
		if perr != nil {
			t.Logf("DIFF %-32s parse refused: %s", cs.name, firstLine(perr.Error()))
			continue
		}
		sid, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, raw)
		if err != nil {
			t.Logf("DIFF %-32s import refused: %s", cs.name, firstLine(err.Error()))
			if strings.Contains(err.Error(), "not the content parsed") {
				t.Errorf("OPEN: Go/SQL digest mismatch for %s (legitimate file cannot be imported)", cs.name)
			}
			continue
		}
		sqlD := f.scalar(t, `SELECT p2p_statement_digest($1::uuid)`, sid)
		stored := f.scalar(t, `SELECT string_agg(amount::text || ' ' || encode(convert_to(reference,'UTF8'),'hex'), ';' ORDER BY line_no) FROM bank_statement_lines WHERE statement_id=$1::uuid`, sid)
		if sqlD != in.ContentDigest() {
			t.Errorf("OPEN: digest differs for %s: go=%s sql=%s", cs.name, in.ContentDigest(), sqlD)
		} else {
			t.Logf("DIFF %-32s imported; go digest == sql digest (%s...) stored=%s", cs.name, sqlD[:12], stored)
		}
		closing = cl
	}
}

func TestR4_03_StatementLinesBinding(t *testing.T) {
	w := newP2PWorld(t)
	f := w.f
	type nl = struct {
		no int
		l  StatementLine
	}
	file := func(no string) []byte {
		return stmt(w.bank, no, today(), "0", "-30", [3]string{"-10", "REF-A", "A"}, [3]string{"-20", "REF-B", "B"})
	}
	r3held(t, "stored lines reordered (same multiset) vs attested file", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := w.r4import(ctx, tx, file("R4-L1"), func(ls []StatementLine) []nl { return []nl{{1, ls[1]}, {2, ls[0]}} })
		return err
	}))
	r3held(t, "extra line inserted in the same tx after the header", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := w.r4import(ctx, tx, file("R4-L2"), func(ls []StatementLine) []nl {
			x := ls[0]
			x.Amount, x.Reference = dec("10"), "PAY-ADDED"
			return []nl{{1, ls[0]}, {2, ls[1]}, {3, x}}
		})
		return err
	}))
	r3held(t, "line_no gap (1,3) with otherwise identical lines", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := w.r4import(ctx, tx, file("R4-L3"), func(ls []StatementLine) []nl { return []nl{{1, ls[0]}, {3, ls[1]}} })
		return err
	}))
	r3held(t, "reference changed only in letter case", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := w.r4import(ctx, tx, file("R4-L4"), func(ls []StatementLine) []nl {
			y := ls[1]
			y.Reference = strings.ToLower(y.Reference)
			return []nl{{1, ls[0]}, {2, y}}
		})
		return err
	}))
	err := f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		_, err := w.r4import(ctx, tx, file("R4-L5"), nil)
		return err
	})
	must(t, "unaltered raw import with genuine attestation (control)", err)
	t.Logf("held: control: the same raw path stores the unaltered file")
}

// L3 / H2 separation at reconciliation: matched_by NULL and case variants.
func TestR4_04_ReconcilerSeparation(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "5", "R4-04")
	rel := c.treasury2
	rel.Roles = []string{"treasury_officer", "accountant"} // releaser who also reconciles (role combination)
	release := func(amount string) (string, string) {
		pay := w.r3payment(t, inv, amount)
		_, err := f.svc.ApprovePayment(f.ctx, c.finMgr, pay)
		must(t, "approve", err)
		_, err = f.svc.ReleasePayment(f.ctx, rel, pay)
		must(t, "release", err)
		return pay, f.scalar(t, `SELECT number FROM payment_instructions WHERE id=$1::uuid`, pay)
	}
	p1, n1 := release("1000")
	p2, n2 := release("2000")
	p3, n3 := release("3000")
	sid, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R4-REC", today(), "0", "-6000",
		[3]string{"-1000", "TRF " + n1, "ABC"}, [3]string{"-2000", "TRF " + n2, "ABC"}, [3]string{"-3000", "TRF " + n3, "ABC"}))
	must(t, "import (independent officer)", err)
	line := func(no int) string {
		return f.scalar(t, `SELECT id::text FROM bank_statement_lines WHERE statement_id=$1::uuid AND line_no=$2`, sid, no)
	}
	match := func(lineID, pay, matchedBy string) error {
		return f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			if err := f.authorizeIn(ctx, tx, rel, "bank.reconcile", "bank_statement_line", lineID, pay); err != nil {
				return err
			}
			jid, err := f.svc.subledgerJournal(ctx, tx, rel, "P2P_SETTLEMENT", lineID, f.entity, "ETB", "settle", today())
			if err != nil {
				return err
			}
			var mb any
			if matchedBy != "" {
				mb = matchedBy
			}
			if _, err := tx.Exec(ctx, `UPDATE bank_statement_lines SET status='MATCHED', payment_id=$2::uuid, matched_by=$3, journal_id=$4::uuid WHERE id=$1::uuid`, lineID, pay, mb, jid); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE payment_instructions SET status='SETTLED' WHERE id=$1::uuid`, pay)
			return err
		})
	}
	r3held(t, "control: releaser reconciles own payment, matched_by = releaser", match(line(1), p1, "u-treasury-2"))
	if err := match(line(2), p2, ""); err == nil {
		t.Errorf("OPEN: releaser's own reconcile attestation settled %s with matched_by NULL (status %s, matched_by %s)", n2,
			f.scalar(t, `SELECT status FROM payment_instructions WHERE id=$1::uuid`, p2),
			f.scalar(t, `SELECT COALESCE(matched_by,'<NULL>') FROM bank_statement_lines WHERE id=$1::uuid`, line(2)))
	} else {
		t.Logf("held: matched_by NULL: %s", firstLine(err.Error()))
	}
	// Case variant identity: separation compares user ids byte-wise.
	variant := auth.Principal{UserID: "U-TREASURY-2", TenantID: f.tenant, Roles: []string{"accountant"}, Kind: auth.KindHuman, IssuedAt: time.Now().Add(-time.Minute)}
	res, err := f.svc.AutoReconcile(f.ctx, variant, sid)
	r4obs(t, "principal 'U-TREASURY-2' (case variant of the releaser 'u-treasury-2') AutoReconcile: err=%v matched=%d unmatched=%+v; %s status=%s", err, len(res.Matched), res.Unmatched,
		n3, f.scalar(t, `SELECT status FROM payment_instructions WHERE id=$1::uuid`, p3))
}

// L1: concurrent imports fork the balance chain.
func TestR4_05_StatementContinuityRace(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	_, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "R4-P", today(), "0", "-10", [3]string{"-10", "x", "y"}))
	must(t, "prev", err)
	fa := stmt(w.bank, "R4-A", today(), "-10", "-30", [3]string{"-20", "a", "b"})
	fb := stmt(w.bank, "R4-B", today(), "-10", "-50", [3]string{"-40", "c", "d"})
	// A imports and keeps its transaction open; B starts concurrently. Since
	// 0015, B must wait for A (row lock on the bank account) and, once A has
	// committed, be refused because it no longer continues the chain.
	aInserted, aCommit := make(chan struct{}), make(chan struct{})
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errA = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			_, err := w.r4import(ctx, tx, fa, nil)
			close(aInserted)
			<-aCommit
			return err
		})
	}()
	<-aInserted
	go func() {
		defer wg.Done()
		errB = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
			_, err := w.r4import(ctx, tx, fb, nil)
			return err
		})
	}()
	blocked := false
	for i := 0; i < 50 && !blocked; i++ {
		time.Sleep(100 * time.Millisecond)
		var n int
		// Other roles' wait events are visible only to a superuser (or pg_read_all_stats).
		_ = f.super.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n)
		blocked = n > 0
	}
	close(aCommit)
	wg.Wait()
	chain := f.scalar(t, `SELECT string_agg(statement_no || ':' || opening_balance::text || '->' || closing_balance::text, ', ' ORDER BY statement_no) FROM bank_statements`)
	switch {
	case errA == nil && errB == nil:
		t.Errorf("OPEN: two concurrent statements both continue the same previous closing balance: %s", chain)
	case errA != nil:
		t.Errorf("first import failed: %v", errA)
	case !blocked:
		t.Errorf("OPEN: the second import did not wait for the first (errB=%v)", errB)
	default:
		t.Logf("held: second import waited for the first and was refused: %s (%s)", firstLine(errB.Error()), chain)
	}
}

// ---------------------------------------------------------------------------
// M1 journal freeze and rebind
// ---------------------------------------------------------------------------
func TestR4_06_JournalFreeze(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("1")})

	ins := f.scalar(t, `SELECT has_column_privilege('journals', 'created_txid', 'INSERT')::text || '/' || has_column_privilege('journals', 'created_txid', 'UPDATE')::text`)
	r4obs(t, "tenant login column privilege on journals.created_txid INSERT/UPDATE = %s", ins)
	if strings.HasPrefix(ins, "true") {
		t.Errorf("OPEN (Info): journals.created_txid is insertable by the tenant login (table-level INSERT grant), contrary to the 0014 comment")
	}
	r4obs(t, "types: txid_current()=%s, journals.created_txid=%s, current txid=%s",
		f.scalar(t, `SELECT pg_typeof(txid_current())::text`),
		f.scalar(t, `SELECT format_type(atttypid, atttypmod) FROM pg_attribute WHERE attrelid='journals'::regclass AND attname='created_txid'`),
		f.scalar(t, `SELECT txid_current()::text`))

	r3held(t, "UPDATE journals.created_txid of a P2P journal", f.rawExec(`UPDATE journals SET created_txid = txid_current() WHERE id=$1::uuid`, j))
	r3held(t, "DELETE a P2P journal line", f.rawExec(`DELETE FROM journal_lines WHERE journal_id=$1::uuid`, j))
	r3held(t, "UPDATE a P2P journal line amount", f.rawExec(`UPDATE journal_lines SET amount = 1 WHERE journal_id=$1::uuid`, j))
	r3held(t, "UPDATE journal_lines.journal_id moving a line into the P2P journal", f.rawExec(`UPDATE journal_lines SET journal_id=$1::uuid WHERE false`, j))

	// A P2P journal born with a chosen (future) created_txid, in a raw GRN
	// confirmation under a genuine site-engineer attestation.
	g, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now().UTC(), "DN-R4", []GRNLine{{POLineNo: 1, QtyReceived: dec("1")}})
	must(t, "grn", err)
	must(t, "grn submit", f.svc.SubmitGRN(f.ctx, c.store, g))
	r3held(t, "raw GRN confirm whose P2P journal is inserted with created_txid = txid_current()+5", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.siteEng, "grn.confirm", "grn", g, "CONFIRMED"); err != nil {
			return err
		}
		var jid string
		if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id, legal_entity_id, project_id, functional_currency, status, business_event_at, description,
			source_type, source_ref, idempotency_key, command_hash, created_by, created_txid)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'ETB', 'DRAFT', date_trunc('day', now()), 'r4', 'P2P_GRN', $4, 'r4-'||$4, 'x', 'u-site-engineer', txid_current()+5) RETURNING id::text`,
			f.tenant, f.entity, f.project, g).Scan(&jid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id, tenant_id, legal_entity_id, line_no, account_id, side, amount, currency, project_id, cost_code_id)
			SELECT $1::uuid, $2::uuid, $3::uuid, row_number() OVER (), account_id, side, amount, 'ETB', project_id, cost_code_id FROM p2p_expected_lines('P2P_GRN', $4::uuid)`,
			jid, f.tenant, f.entity, g); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE grns SET status='CONFIRMED', confirmed_by='u-site-engineer', journal_id=$2::uuid WHERE id=$1::uuid`, g, jid)
		return err
	}))
	// Lines appended in the generating transaction after the binding check.
	g2, err := f.svc.CreateGRN(f.ctx, c.store, po, time.Now().UTC(), "DN-R4b", []GRNLine{{POLineNo: 1, QtyReceived: dec("1")}})
	must(t, "grn2", err)
	must(t, "grn2 submit", f.svc.SubmitGRN(f.ctx, c.store, g2))
	var j2 string
	err = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		if err := f.authorizeIn(ctx, tx, c.siteEng, "grn.confirm", "grn", g2, "CONFIRMED"); err != nil {
			return err
		}
		var err error
		var on time.Time
		if err := tx.QueryRow(ctx, `SELECT received_on FROM grns WHERE id=$1::uuid`, g2).Scan(&on); err != nil {
			return err
		}
		j2, err = f.svc.subledgerJournal(ctx, tx, c.siteEng, "P2P_GRN", g2, f.entity, "ETB", "r4", on)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE grns SET status='CONFIRMED', confirmed_by='u-site-engineer', journal_id=$2::uuid WHERE id=$1::uuid`, g2, j2); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO journal_lines(journal_id, tenant_id, legal_entity_id, line_no, account_id, side, amount, currency, project_id, cost_code_id) VALUES
			($1::uuid, $2::uuid, $3::uuid, 90, $4::uuid, 'DEBIT', 1000000, 'ETB', $5::uuid, $6::uuid),
			($1::uuid, $2::uuid, $3::uuid, 91, $7::uuid, 'CREDIT', 1000000, 'ETB', $5::uuid, NULL)`, j2, f.tenant, f.entity, w.acct["5000"], f.project, w.costCode, w.acct["1000"])
		return err
	})
	if err != nil {
		t.Logf("held: append after binding in the generating tx: %s", firstLine(err.Error()))
	} else {
		r4obs(t, "lines appended after p2p_assert_journal in the generating tx were committed (journal %s); M1 now rests on the rebind trigger", j2)
		r3held(t, "raw journal.approve (genuine attestation) of that journal", f.rawAs(c.finMgr, "journal.approve", "journal", j2, "",
			`UPDATE journals SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, j2))
	}
	// Legitimate: the untampered first journal approves and posts.
	w.financePost(t, j)
	t.Logf("held: legitimate P2P_GRN journal approved and posted")
}

// R3-X1 / rebind: a DRAFT policy proposed before the first approval keeps a
// different GRNI account and can be approved later.
func TestR4_07_PolicySuccessorGRNI(t *testing.T) {
	// Build the world, but with a second DRAFT policy created while no
	// policy is APPROVED yet (newP2PWorld approves immediately, so the
	// sequence is reproduced here with the operator retiring nothing).
	w := newP2PWorldR4(t, func(w *p2pWorld) string {
		w.r4accounts(t, [3]string{"2200", "GRNI (new)", "LIABILITY"})
		id, err := w.f.svc.ProposeP2PPolicy(w.f.ctx, w.cast.controller, postgres.P2PPolicy{LegalEntityID: w.f.entity, PriceTolerancePct: dec("0.02"),
			OverReceiptPct: dec("0.05"), VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
			GRNIAccountID: w.acct["2200"], APAccountID: w.acct["2000"], VATInputAccountID: w.acct["1300"], PPVAccountID: w.acct["5100"]})
		must(t, "second draft policy", err)
		return id
	})
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("2")})
	err := f.svc.DecideP2PPolicy(f.ctx, c.cfo, w.r4draft, true)
	if err == nil {
		t.Errorf("OPEN: successor policy with a different GRNI account approved (it was DRAFTed before the first approval)")
		res := f.svc.ApproveJournals(f.ctx, c.finMgr, []string{j})
		r4obs(t, "pending GRN journal after the successor: approve ok=%v", res[0].OK)
		r4obs(t, "GRNI credit account: journal=%s expected-now=%s",
			f.scalar(t, `SELECT a.code FROM journal_lines l JOIN accounts a ON a.id=l.account_id WHERE l.journal_id=$1::uuid AND l.side='CREDIT'`, j),
			f.scalar(t, `SELECT a.code FROM p2p_expected_lines('P2P_GRN', (SELECT source_ref::uuid FROM journals WHERE id=$1::uuid)) e JOIN accounts a ON a.id=e.account_id WHERE e.side='CREDIT'`, j))
	} else {
		t.Logf("held: successor with different GRNI: %s", firstLine(err.Error()))
	}
}

// newP2PWorldR4 is newP2PWorld with a hook between proposing and approving
// the first policy.
func newP2PWorldR4(t *testing.T, hook func(w *p2pWorld) string) *r4World {
	t.Helper()
	orig := newP2PWorldHook
	var draft string
	newP2PWorldHook = func(w *p2pWorld) { draft = hook(w) }
	defer func() { newP2PWorldHook = orig }()
	w := newP2PWorld(t)
	return &r4World{p2pWorld: w, r4draft: draft}
}

type r4World struct {
	*p2pWorld
	r4draft string
}

// ---------------------------------------------------------------------------
// M2 human marker
// ---------------------------------------------------------------------------
func TestR4_08_HumanMarker(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "5", "R4-08")

	// A tenant/operator role catalogue that lists the marker.
	roles := map[string]auth.Role{}
	for k, v := range auth.DefaultRoles {
		roles[k] = v
	}
	fm := roles["finance_manager"]
	fm.Permissions = append(append([]auth.Permission{}, fm.Permissions...), "principal.human", "Principal.human")
	roles["finance_manager"] = fm
	az := auth.NewAuthorizer(roles, true)
	bot := auth.Principal{UserID: "u-fm-bot", TenantID: f.tenant, Roles: []string{"finance_manager"}, MFA: true, AuthTime: time.Now(), IssuedAt: time.Now().Add(-time.Minute), Kind: auth.KindAI}
	r4obs(t, "Permissions() with a role granting principal.human: %v", az.Permissions(bot))
	svc2 := New(f.app, az).UseApprovalSigner(attest.Signer{Master: testdb.ApprovalMaster}).UseBankDataKeys(testdb.BankDataKeys)
	pa := w.r3payment(t, inv, "100")
	_, err := svc2.ApprovePayment(f.ctx, bot, pa)
	r3held(t, "AI principal whose role lists principal.human approves a payment", err)
	unk := bot
	unk.Kind, unk.UserID = "Human", "u-fm-unknown"
	_, err = svc2.ApprovePayment(f.ctx, unk, pa)
	r3held(t, "principal with kind 'Human' (wrong case) approves a payment", err)

	// Marker from an unrelated action of the same actor in the same tx.
	r3held(t, "AI-kind attestation + same actor's human journal.approve attestation in the tx", f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		jid := f.draftJournal(t, f.balanced(key("r4")))
		human := c.finMgr
		if err := f.authorizeIn(ctx, tx, human, "journal.approve", "journal", jid, ""); err != nil {
			return err
		}
		ai := human
		ai.Kind = auth.KindAI
		if err := f.authorizeIn(ctx, tx, ai, "payment.approve", "payment_instruction", pa, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, pa)
		return err
	}))
	// Marker from a payment.approve on ANOTHER payment by the same user id.
	pb := w.r3payment(t, inv, "200")
	err = f.r3tx(func(ctx context.Context, tx pgx.Tx) error {
		human := c.finMgr
		if err := f.authorizeIn(ctx, tx, human, "payment.approve", "payment_instruction", pa, "APPROVED"); err != nil {
			return err
		}
		ai := human
		ai.Kind = auth.KindAI
		if err := f.authorizeIn(ctx, tx, ai, "payment.approve", "payment_instruction", pb, "APPROVED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE payment_instructions SET status='APPROVED', approved_by='u-finance-manager' WHERE id=$1::uuid`, pb)
		return err
	})
	if err == nil {
		used := f.scalar(t, `SELECT ('principal.human' = ANY(a.perms))::text FROM approval_consumptions c JOIN approval_attestations a ON a.nonce=c.nonce
			WHERE a.action='payment.approve' AND a.subject_id=$1 ORDER BY c.used_at DESC LIMIT 1`, pb)
		t.Errorf("OPEN (Low): payment approved on an attestation without the human marker (consumed attestation has marker: %s); the marker came from the same user id's attestation for another payment", used)
	} else {
		t.Logf("held: marker borrowed from another payment's attestation: %s", firstLine(err.Error()))
	}
}

// ---------------------------------------------------------------------------
// M3 control accounts, legitimate successor flow
// ---------------------------------------------------------------------------
func TestR4_09_ControlAccounts(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.r4accounts(t, [3]string{"1310", "VAT Input (new)", "ASSET"}, [3]string{"1010", "Petty cash", "ASSET"}, [3]string{"1060", "Transit 2", "ASSET"})
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500") // PO lines on 5000
	_, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("1")})

	_, err := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "Late bank", "LATE0001", "ETB", w.acct["5000"], w.acct["1060"])
	r3held(t, "company bank account registered on an account PO lines already use", err)

	// Legitimate successor (same GRNI/AP, new VAT input) between GRN confirm and journal post.
	p2, err := f.svc.ProposeP2PPolicy(f.ctx, c.controller, postgres.P2PPolicy{LegalEntityID: f.entity, PriceTolerancePct: dec("0.03"),
		OverReceiptPct: dec("0.05"), VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: w.acct["2100"], APAccountID: w.acct["2000"], VATInputAccountID: w.acct["1310"], PPVAccountID: w.acct["5100"]})
	must(t, "propose successor", err)
	must(t, "approve successor", f.svc.DecideP2PPolicy(f.ctx, c.cfo, p2, true))
	res := f.svc.ApproveJournals(f.ctx, c.finMgr, []string{j})
	if !res[0].OK {
		t.Errorf("OPEN (regression): GRN journal confirmed under policy v1 cannot be approved after a legitimate successor: %s", res[0].Error)
	} else {
		pr := f.svc.PostJournals(f.ctx, c.controller, []string{j})
		t.Logf("held: legitimate successor between confirm and post: approve ok, post ok=%v %s", pr[0].OK, pr[0].Error)
	}

	award := func(acct string) error {
		rfq, _ := w.r4award(t, true, QuoteLine{1, dec("85000")}, QuoteLine{2, dec("940")})
		_, err := f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: acct, 2: w.acct["5000"]})
		return err
	}
	if err := award(w.acct["1300"]); err == nil {
		t.Errorf("OPEN (Low): PO line accepted on the RETIRED policy's VAT input account 1300 (still carries VAT input balances)")
	} else {
		t.Logf("held: PO line on retired VAT input account: %s", firstLine(err.Error()))
	}
	if err := award(w.acct["1010"]); err == nil {
		r4obs(t, "PO line accepted on an unregistered cash-type ASSET account 1010 'Petty cash' (only registered control accounts are excluded)")
	} else {
		t.Logf("held: PO line on petty cash: %s", firstLine(err.Error()))
	}
	if err := award(w.acct["1050"]); err == nil {
		t.Errorf("OPEN: PO line on the payments-in-transit account")
	} else {
		t.Logf("held: PO line on payments-in-transit: %s", firstLine(err.Error()))
	}
}
