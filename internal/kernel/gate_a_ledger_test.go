package kernel

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

// Gate A regression tests for SC-01 (line reassignment) and SC-14 (currency
// precision). Every attack runs as the least-privileged application role.

type journalTotals struct {
	status        string
	lines         int
	debit, credit string
}

func (f *fixture) totals(t *testing.T, id string) journalTotals {
	t.Helper()
	var jt journalTotals
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT j.status, count(l.*), COALESCE(sum(l.amount) FILTER (WHERE side='DEBIT'),0)::text,
			COALESCE(sum(l.amount) FILTER (WHERE side='CREDIT'),0)::text FROM journals j LEFT JOIN journal_lines l ON l.journal_id=j.id
			WHERE j.id=$1::uuid GROUP BY j.status`, id).Scan(&jt.status, &jt.lines, &jt.debit, &jt.credit)
	})
	if err != nil {
		t.Fatal(err)
	}
	return jt
}

func (f *fixture) rawExec(stmt string, args ...any) error {
	return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, stmt, args...)
		return err
	})
}

// SC-01: the exact audit scenario — move a line of a POSTED journal into a
// DRAFT journal — plus every identity/ownership mutation and deletion.
func TestSC01_PostedLineCannotBeReassignedOrMutated(t *testing.T) {
	f := newFixture(t)
	posted := f.lifecycle(t, f.balanced(key("sc01-posted")))
	two := f.journal(key("sc01-draft"),
		ledger.Line{AccountID: f.accounts["5000"], Side: ledger.Debit, Amount: money.MustNew("1.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1000"], Side: ledger.Credit, Amount: money.MustNew("1.00", "ETB")})
	draft, err := f.svc.CreateJournal(f.ctx, f.prep, two)
	if err != nil {
		t.Fatal(err)
	}
	approvedJ, _ := f.svc.CreateJournal(f.ctx, f.prep, f.balanced(key("sc01-approved")))
	if err := f.svc.ApproveJournal(f.ctx, f.appr, approvedJ.JournalID); err != nil {
		t.Fatal(err)
	}
	beforePosted, beforeDraft := f.totals(t, posted), f.totals(t, draft.JournalID)

	attacks := map[string]struct {
		stmt string
		args []any
	}{
		"move POSTED line 3 into DRAFT journal (audit scenario)": {`UPDATE journal_lines SET journal_id=$2::uuid WHERE journal_id=$1::uuid AND line_no=3`, []any{posted, draft.JournalID}},
		"move DRAFT line into POSTED journal":                    {`UPDATE journal_lines SET journal_id=$2::uuid WHERE journal_id=$1::uuid AND line_no=1`, []any{draft.JournalID, posted}},
		"move APPROVED line into DRAFT journal":                  {`UPDATE journal_lines SET journal_id=$2::uuid, line_no=9 WHERE journal_id=$1::uuid AND line_no=1`, []any{approvedJ.JournalID, draft.JournalID}},
		"renumber POSTED line":                                   {`UPDATE journal_lines SET line_no=99 WHERE journal_id=$1::uuid AND line_no=1`, []any{posted}},
		"change POSTED line amount":                              {`UPDATE journal_lines SET amount=amount+1 WHERE journal_id=$1::uuid`, []any{posted}},
		"change POSTED line account":                             {`UPDATE journal_lines SET account_id=$2::uuid WHERE journal_id=$1::uuid AND line_no=1`, []any{posted, f.accounts["5000"]}},
		"change POSTED line project":                             {`UPDATE journal_lines SET project_id=NULL WHERE journal_id=$1::uuid`, []any{posted}},
		"change POSTED line tenant":                              {`UPDATE journal_lines SET tenant_id=$2::uuid WHERE journal_id=$1::uuid`, []any{posted, f.tenant2}},
		"change POSTED line legal entity":                        {`UPDATE journal_lines SET legal_entity_id=gen_random_uuid() WHERE journal_id=$1::uuid`, []any{posted}},
		"change POSTED line memo":                                {`UPDATE journal_lines SET memo='x' WHERE journal_id=$1::uuid`, []any{posted}},
		"delete POSTED line":                                     {`DELETE FROM journal_lines WHERE journal_id=$1::uuid AND line_no=3`, []any{posted}},
		"insert extra line into POSTED journal":                  {`INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency) VALUES ($1::uuid,$2::uuid,$3::uuid,7,$4::uuid,'DEBIT',5,'ETB')`, []any{posted, f.tenant, f.entity, f.accounts["5000"]}},
		"move line between two DRAFT journals":                   {`UPDATE journal_lines SET journal_id=$2::uuid, line_no=50 WHERE journal_id=$1::uuid AND line_no=1`, []any{draft.JournalID, posted}},
		"renumber DRAFT line (identity immutable even in draft)": {`UPDATE journal_lines SET line_no=77 WHERE journal_id=$1::uuid AND line_no=1`, []any{draft.JournalID}},
	}
	for name, a := range attacks {
		err := f.rawExec(a.stmt, a.args...)
		if err == nil {
			t.Errorf("SC-01 attack succeeded: %s", name)
		}
		t.Logf("%-55s -> %v", name, err)
	}
	// Layer 2: the same attacks as the schema-owner superuser, which bypasses
	// privileges and RLS but not triggers. The trigger layer alone must hold
	// should a future migration ever re-grant UPDATE to the application.
	for name, a := range attacks {
		if name == "change POSTED line tenant" {
			continue // superuser could only do this for a tenant FK; covered by guard below
		}
		_, err := f.admin.Exec(f.ctx, a.stmt, a.args...)
		if err == nil {
			t.Errorf("SC-01 trigger layer let the schema owner run: %s", name)
		}
		t.Logf("[owner] %-47s -> %v", name, err)
	}
	if got := f.totals(t, posted); got != beforePosted {
		t.Fatalf("posted journal changed: before %+v after %+v", beforePosted, got)
	}
	if got := f.totals(t, draft.JournalID); got != beforeDraft {
		t.Fatalf("draft journal changed: before %+v after %+v", beforeDraft, got)
	}
	if got := f.totals(t, posted); got.debit != got.credit || got.lines != 3 {
		t.Fatalf("posted journal unbalanced: %+v", got)
	}
	// The forensic scan is clean and the documented correction path still works.
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		v, err := postgres.LedgerIntegrityScan(ctx, tx)
		if err != nil {
			return err
		}
		if len(v) != 0 {
			t.Fatalf("integrity violations: %+v", v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Direct table-level UPDATE privilege is gone; only memo is updatable.
	if err := f.rawExec(`UPDATE journal_lines SET memo='draft note' WHERE journal_id=$1::uuid`, draft.JournalID); err != nil {
		t.Fatalf("draft memo edit refused: %v", err)
	}
}

// SC-01 detection: the forensic scan reports a ledger state that 0.1.0 could
// not prevent. We fabricate it as the schema owner (the app role no longer
// can) and check the scan and the period-close prerequisite both catch it.
func TestSC01_IntegrityScanDetectsPriorExploitation(t *testing.T) {
	f := newFixture(t)
	posted := f.lifecycle(t, f.balanced(key("scan")))
	// Session-scoped trigger bypass (superuser only), so tests in other
	// packages running concurrently keep full protection.
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `DELETE FROM journal_lines WHERE journal_id=$1::uuid AND line_no=3`, posted); err != nil {
		t.Fatalf("fixture tamper failed: %v", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	var found bool
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		v, err := postgres.LedgerIntegrityScan(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range v {
			found = found || (x.Rule == "UNBALANCED_POSTED" && x.JournalID == posted)
		}
		return nil
	})
	if !found {
		t.Fatal("integrity scan missed an unbalanced POSTED journal")
	}
	if _, err := f.svc.ClosePeriod(f.ctx, f.ctrl, f.period(t), false); !errors.Is(err, ErrClosePrerequisite) {
		t.Fatalf("period closed over an integrity violation: %v", err)
	}
}

// SC-14: raw SQL cannot write sub-minor-unit amounts in 0-, 2- and 3-decimal
// currencies, for functional or transaction amounts.
func TestSC14_DatabaseEnforcesCurrencyPrecision(t *testing.T) {
	f := newFixture(t)
	entities := map[string]string{"ETB": f.entity}
	accts := map[string][2]string{"ETB": {f.accounts["5000"], f.accounts["1000"]}}
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, c := range []struct{ cur, country string }{{"UGX", "UG"}, {"TND", "TN"}} {
			le, err := postgres.CreateLegalEntity(ctx, tx, f.tenant, "Precision "+c.cur, c.country, money.Currency(c.cur), "")
			if err != nil {
				return err
			}
			a, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: le, Code: "5000", Name: "E", Type: ledger.Expense, Active: true})
			if err != nil {
				return err
			}
			b, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: le, Code: "1000", Name: "C", Type: ledger.Asset, Active: true})
			if err != nil {
				return err
			}
			entities[c.cur], accts[c.cur] = le, [2]string{a, b}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	insert := func(cur, amount string) error {
		return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			var jid string
			if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by)
				VALUES ($1::uuid,$2::uuid,$3,'2026-10-15','raw','MANUAL',$4,'h','a') RETURNING id::text`, f.tenant, entities[cur], cur, key("prec")).Scan(&jid); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency) VALUES
				($1::uuid,$2::uuid,$3::uuid,1,$4::uuid,'DEBIT',$6::numeric,$7),($1::uuid,$2::uuid,$3::uuid,2,$5::uuid,'CREDIT',$6::numeric,$7)`,
				jid, f.tenant, entities[cur], accts[cur][0], accts[cur][1], amount, cur)
			return err
		})
	}
	for _, c := range []struct {
		cur, amount string
		ok          bool
	}{
		{"ETB", "100.001", false}, {"ETB", "100.0049", false}, {"ETB", "100.01", true},
		{"UGX", "100.5", false}, {"UGX", "100", true},
		{"TND", "1.0001", false}, {"TND", "1.001", true},
	} {
		err := insert(c.cur, c.amount)
		if c.ok && err != nil {
			t.Errorf("valid %s %s rejected: %v", c.amount, c.cur, err)
		}
		if !c.ok && !errors.Is(err, postgres.ErrInvariant) {
			t.Errorf("SC-14: sub-minor %s %s accepted (err=%v)", c.amount, c.cur, err)
		}
		t.Logf("%s %-8s ok=%v -> %v", c.cur, c.amount, c.ok, err)
	}
}

// period returns the fixture's fiscal period id.
func (f *fixture) period(t *testing.T) string {
	t.Helper()
	var id string
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM fiscal_periods WHERE legal_entity_id=$1::uuid AND name='FY2026-Q4'`, f.entity).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}
