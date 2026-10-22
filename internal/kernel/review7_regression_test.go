package kernel

// Review 7 probes (independent): stock valuation slice (migration 0021),
// docs/security/INDEPENDENT_REVIEW_7_2026-10-22.md. Kept as regression tests
// after migration 0024: every former OPEN now fails the test.
// held: = the control worked; OPEN: = a defect, with the actual output.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

func (w *stockWorld) raw(fn func(ctx context.Context, tx pgx.Tx) error) error {
	return w.f.app.WithTenant(w.f.ctx, w.f.tenant, fn)
}

func (w *stockWorld) rawExec(sql string, args ...any) error {
	return w.raw(func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

// issueApprovePost creates, approves and posts an issue; returns amount.
func (w *stockWorld) issueApprovePost(t *testing.T, item, qty string) decimal.Decimal {
	t.Helper()
	id, err := w.issue(t, item, qty)
	must(t, "issue "+qty, err)
	j, err := w.f.svc.ApproveStockIssue(w.f.ctx, w.cast.siteEng, id)
	must(t, "approve issue "+qty, err)
	if j != "" {
		w.financePost(t, j)
	}
	return w.stockValue(t, `SELECT amount FROM stock_issues WHERE id = $1::uuid`, id)
}

// invariants returns (balance value, layers+WAC value, documents value).
func (w *stockWorld) invariants(t *testing.T) (bal, layers, docs decimal.Decimal) {
	t.Helper()
	bal = w.stockValue(t, `SELECT COALESCE(sum(value),0) FROM stock_balances`)
	layers = w.stockValue(t, `SELECT COALESCE((SELECT sum(l.value_remaining) FROM stock_layers l),0)
		+ COALESCE((SELECT sum(b.value) FROM stock_balances b JOIN stock_items i ON i.id=b.stock_item_id WHERE i.valuation_method='WAC'),0)`)
	docs = w.stockValue(t, `SELECT COALESCE((SELECT sum(amount) FROM stock_receipts),0)
		+ COALESCE((SELECT sum(CASE WHEN difference>0 THEN amount ELSE -amount END) FROM stock_counts WHERE status='APPROVED'),0)
		- COALESCE((SELECT sum(amount) FROM stock_issues WHERE status='APPROVED'),0)`)
	return
}

func (w *stockWorld) recon(t *testing.T) []postgres.ReconCheck {
	t.Helper()
	r, err := w.f.svc.StockReconciliation(w.f.ctx, w.cast.controller, w.f.entity)
	must(t, "stock recon", err)
	for _, c := range r {
		t.Logf("  recon %-48s sub %14s gl %14s diff %s open %d", c.Check, c.Subledger, c.GL, c.Difference, c.Unposted)
	}
	return r
}

// ---------------------------------------------------------------------------
// 1. Valuation: FIFO across many layers, many small 4-dp issues, exact rest.
// ---------------------------------------------------------------------------
func TestR7_FIFOManyLayersSmallIssues(t *testing.T) {
	w := newStockWorld(t)
	var js []string
	prices := []string{"84500.333333", "86000.777777", "85123.456789"}
	for _, p := range prices {
		po := w.inventoryPO(t, "3.3333", "10", p, "940")
		grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("3.3333")})
		js = append(js, j)
		w.putAway(t, grn, 1, w.itemSteel, "1.1111")
		w.putAway(t, grn, 1, w.itemSteel, "2.2222") // completes the line
	}
	w.financePost(t, js...)
	total := decimal.Zero
	for i := 0; i < 23; i++ {
		total = total.Add(w.issueApprovePost(t, w.itemSteel, "0.4321"))
	}
	q, v := w.balanceOf(t, w.itemSteel)
	t.Logf("after 23 issues of 0.4321 t: on hand %s at %s; issued %s", q, v, total)
	total = total.Add(w.issueApprovePost(t, w.itemSteel, q.String())) // exact balance
	q, v = w.balanceOf(t, w.itemSteel)
	grnTotal := w.stockValue(t, `SELECT sum(amount) FROM stock_receipts`)
	bal, layers, docs := w.invariants(t)
	gl := w.glBalance(t, "1200")
	t.Logf("closing qty %s value %s; receipts %s issued %s; bal %s layers %s docs %s; GL inventory %s", q, v, grnTotal, total, bal, layers, docs, gl)
	if !q.IsZero() || !v.IsZero() || !grnTotal.Equal(total) || !gl.IsZero() || !bal.Equal(layers) || !bal.Equal(docs) {
		t.Errorf("OPEN: FIFO residue: qty %s value %s receipts %s issued %s GL %s", q, v, grnTotal, total, gl)
	} else {
		t.Logf("held: FIFO over 3 layers x 2 put-aways and 24 issues leaves no residue (GL 0, stock 0, issued = received %s)", total)
	}
	for _, r := range w.recon(t) {
		if r.Difference.Sign() != 0 {
			t.Errorf("OPEN: recon difference %+v", r)
		}
	}
}

// WAC with fractional averages and 4-dp quantities, ending with the exact balance.
func TestR7_WACFractionalToZero(t *testing.T) {
	w := newStockWorld(t)
	var js []string
	for _, p := range []string{"940.37", "951.13", "947.777777"} {
		po := w.inventoryPO(t, "1", "333.3333", "84500", p)
		grn, j := w.receipt(t, po, GRNLine{POLineNo: 2, QtyReceived: dec("333.3333")})
		js = append(js, j)
		w.putAway(t, grn, 2, w.itemCement, "111.1111")
		w.putAway(t, grn, 2, w.itemCement, "222.2222")
	}
	w.financePost(t, js...)
	issued := decimal.Zero
	for i := 0; i < 17; i++ {
		issued = issued.Add(w.issueApprovePost(t, w.itemCement, "37.0037"))
	}
	// count after partial consumption: shortage 1.2345
	q, _ := w.balanceOf(t, w.itemCement)
	ct, err := w.f.svc.CreateStockCount(w.f.ctx, w.cast.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemCement, CountedQty: q.Sub(dec("1.2345")),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count", err)
	jc, err := w.f.svc.ApproveStockCount(w.f.ctx, w.invCtl, ct)
	must(t, "approve count", err)
	w.financePost(t, jc)
	q, _ = w.balanceOf(t, w.itemCement)
	issued = issued.Add(w.issueApprovePost(t, w.itemCement, q.String()))
	q, v := w.balanceOf(t, w.itemCement)
	gl := w.glBalance(t, "1200")
	bal, layers, docs := w.invariants(t)
	t.Logf("WAC closing qty %s value %s GL %s bal %s layers %s docs %s", q, v, gl, bal, layers, docs)
	if !q.IsZero() || !v.IsZero() || !gl.IsZero() || !bal.Equal(docs) || !bal.Equal(layers) {
		t.Errorf("OPEN: WAC residue qty %s value %s GL %s", q, v, gl)
	} else {
		t.Logf("held: WAC with fractional averages, 4-dp issues and a shortage ends at stock 0 / GL 0")
	}
	for _, r := range w.recon(t) {
		if r.Difference.Sign() != 0 {
			t.Errorf("OPEN: recon difference %+v", r)
		}
	}
}

// ---------------------------------------------------------------------------
// Surplus valuation at the average of a near-empty balance.
// ---------------------------------------------------------------------------
func TestR7_SurplusValuedFromRoundingRemainder(t *testing.T) {
	for _, tc := range []struct{ price, note string }{{"10.40", "deflate to zero"}, {"60.00", "inflate"}} {
		t.Run(tc.note, func(t *testing.T) {
			w := newStockWorld(t)
			po := w.inventoryPO(t, "1", "300", "84500", tc.price)
			grn, j := w.receipt(t, po, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
			w.financePost(t, j)
			w.putAway(t, grn, 2, w.itemCement, "300")
			w.issueApprovePost(t, w.itemCement, "299.9999")
			q, v := w.balanceOf(t, w.itemCement)
			t.Logf("after issuing 299.9999 of 300 at %s: book %s bags valued %s", tc.price, q, v)
			ct, err := w.f.svc.CreateStockCount(w.f.ctx, w.cast.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemCement, CountedQty: dec("1000.0001"),
				VarianceAccountID: w.acct["5200"], CountDate: today()})
			must(t, "count", err)
			unit := w.stockValue(t, `SELECT COALESCE(surplus_unit_cost, 0) FROM stock_counts WHERE id = $1::uuid`, ct)
			if !unit.Equal(dec(tc.price)) {
				t.Errorf("OPEN: the surplus unit cost recorded with the count is %s, want the last receipt cost %s", unit, tc.price)
			}
			jc, err := w.f.svc.ApproveStockCount(w.f.ctx, w.invCtl, ct)
			must(t, "approve surplus", err)
			amt := w.stockValue(t, `SELECT amount FROM stock_counts WHERE id = $1::uuid`, ct)
			want := dec("1000").Mul(dec(tc.price))
			q, v = w.balanceOf(t, w.itemCement)
			t.Logf("surplus of 1000 bags valued %s (journal %q); at the receipt price it is %s; book now %s bags at %s", amt, jc, want, q, v)
			if !amt.Sub(want).Abs().LessThan(want.Mul(dec("0.05"))) {
				t.Errorf("OPEN: surplus of 1000 bags at receipt price %s valued %s (%.0f%% of cost) because the average is taken from a %s-bag remainder worth %s",
					tc.price, amt, amt.Div(want).Mul(dec("100")).InexactFloat64(), "0.0001", "rounding")
				if amt.IsZero() {
					// the free stock is now issued to the project at zero cost
					c := w.issueApprovePost(t, w.itemCement, "500")
					t.Errorf("OPEN: 500 of those bags then issued to the project at cost %s (no STK_ISSUE journal)", c)
				}
			} else {
				t.Logf("held: surplus valued within 5%% of the receipt price")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Partial put-aways are not capped by the line's remaining value.
// ---------------------------------------------------------------------------
func TestR7_PartialPutAwayOvershoot(t *testing.T) {
	w := newStockWorld(t)
	po := w.inventoryPO(t, "1", "0.0106", "84500", "1.5")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 2, QtyReceived: dec("0.0106")})
	w.financePost(t, j)
	for i := 0; i < 3; i++ {
		w.putAway(t, grn, 2, w.itemCement, "0.0035")
	}
	_, v := w.balanceOf(t, w.itemCement)
	grnVal := w.stockValue(t, `SELECT round(0.0106 * 1.5, 2)`)
	_, err := w.f.svc.PutAway(w.f.ctx, w.cast.store, grn, 2, w.itemCement, w.store, dec("0.0001"))
	t.Logf("GRN line debited inventory %s; three put-aways of 0.0035 carry %s; completing put-away: %v", grnVal, v, err)
	if err != nil {
		t.Errorf("OPEN: the completing put-away is refused: %v", err)
	}
	if _, vEnd := w.balanceOf(t, w.itemCement); !vEnd.Equal(grnVal) {
		t.Errorf("OPEN: the completed line carries %s, the goods receipt debited %s", vEnd, grnVal)
	}
	r := w.recon(t)
	if v.GreaterThan(grnVal) {
		zero := true
		for _, c := range r {
			if c.Difference.Sign() != 0 {
				zero = false
			}
		}
		t.Errorf("OPEN: put-away value %s exceeds what the GRN line debited (%s); completing put-away refused (%v); recon all-zero differences = %v",
			v, grnVal, err, zero)
	}
}

// ---------------------------------------------------------------------------
// 2. Integrity bypass as the tenant runtime role.
// ---------------------------------------------------------------------------
func TestR7_RawSQLBypass(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "6")

	probe := func(what, want, sql string, args ...any) {
		t.Helper()
		err := w.rawExec(sql, args...)
		if err == nil {
			t.Errorf("OPEN: %s accepted", what)
			return
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Logf("held (unexpected reason): %s: %v", what, err)
			return
		}
		t.Logf("held: %s: %v", what, err)
	}
	probe("INSERT stock_consumptions", "", `INSERT INTO stock_consumptions(doc_type, doc_id, qty, value) VALUES ('ISSUE', gen_random_uuid(), 1, 0)`)
	probe("DELETE stock_layers", "", `DELETE FROM stock_layers`)
	probe("UPDATE stock_layers value", "", `UPDATE stock_layers SET value_remaining = value_remaining + 1`)
	probe("INSERT stock_balances ON CONFLICT", "", `INSERT INTO stock_balances(stock_item_id, warehouse_id, qty, value) VALUES ($1::uuid, $2::uuid, 1, 1)
		ON CONFLICT (stock_item_id, warehouse_id) DO UPDATE SET qty = stock_balances.qty + 1`, w.itemSteel, w.store)
	probe("stk_consume in a CTE", "", `WITH x AS (SELECT stk_consume($1::uuid, $2::uuid, 1, 'ISSUE', gen_random_uuid()) c) SELECT * FROM x`, w.itemSteel, w.store)
	probe("stk_receive in INSERT ... SELECT", "", `INSERT INTO stock_issues(legal_entity_id, number, warehouse_id, stock_item_id, project_id, cost_code_id, expense_account_id, quantity, issue_date, currency, created_by)
		SELECT $3::uuid, 'X-'||(SELECT stk_receive($1::uuid, $2::uuid, 5, 1, 0.2, 'RECEIPT', gen_random_uuid())), $2::uuid, $1::uuid, $4::uuid, $5::uuid, $6::uuid, 1, current_date, 'ETB', 'u-storekeeper'`,
		w.itemSteel, w.store, f.entity, f.project, w.costCode, w.acct["5000"])
	probe("session_replication_role=replica", "", `SET session_replication_role = replica`)
	probe("put-away without attestation (raw insert)", "", `INSERT INTO stock_receipts(legal_entity_id, number, grn_id, po_line_no, stock_item_id, warehouse_id, quantity, currency, created_by, amount, unit_cost)
		VALUES ($1::uuid, 'R7-1', $2::uuid, 1, $3::uuid, $4::uuid, 1, 'ETB', 'u-storekeeper', 1, 1)`, f.entity, grn, w.itemSteel, w.store)
	probe("stock_balances via a forged deferred-constraint (SET CONSTRAINTS)", "", `SET CONSTRAINTS ALL IMMEDIATE; UPDATE stock_balances SET qty = 99`)

	// Approve an issue properly, then try journal_id / approved_txid games in later transactions.
	is, err := w.issue(t, w.itemSteel, "1")
	must(t, "issue", err)
	ji, err := f.svc.ApproveStockIssue(f.ctx, w.cast.siteEng, is)
	must(t, "approve", err)
	probe("swap journal_id after approval", "", `UPDATE stock_issues SET journal_id = gen_random_uuid() WHERE id = $1::uuid`, is)
	probe("re-approve an APPROVED issue (amount change)", "", `UPDATE stock_issues SET amount = 1 WHERE id = $1::uuid`, is)
	probe("edit STK journal lines in a later txn", "", `UPDATE journal_lines SET amount = amount + 1 WHERE journal_id = $1::uuid`, ji)
	probe("cancel STK journal", "", `UPDATE journals SET status = 'CANCELLED' WHERE id = $1::uuid`, ji)
	probe("orphan STK_ISSUE journal", "", `INSERT INTO journals(legal_entity_id, functional_currency, business_event_at, description, source_type, source_ref, idempotency_key, created_by, created_txid)
		VALUES ($1::uuid, 'ETB', now(), 'x', 'STK_ISSUE', $2, 'r7-orphan', 'u-x', txid_current())`, f.entity, is)
	ctRaw, err := f.svc.CreateStockCount(f.ctx, w.cast.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("3"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count for raw probe", err)
	probe("count DRAFT->APPROVED raw without attestation", "attestation", `UPDATE stock_counts SET status='APPROVED', approved_by='u-x' WHERE id = $1::uuid`, ctRaw)
	is2, err := w.issue(t, w.itemSteel, "1")
	must(t, "issue 2", err)
	probe("approve issue raw without attestation", "attestation", `UPDATE stock_issues SET status='APPROVED', approved_by='u-site-engineer' WHERE id = $1::uuid`, is2)

	// Manual journal to the inventory account must surface in the reconciliation.
	f.lifecycle(t, f.balanced(key("r7-manual")))
	found := false
	for _, r := range w.recon(t) {
		if strings.HasPrefix(r.Check, "Inventory:") && r.Difference.Equal(dec("100000")) {
			found = true
		}
	}
	if found {
		t.Logf("held: a manual 100,000 journal to inventory shows as a reconciliation difference")
	} else {
		t.Errorf("OPEN: manual journal to inventory not detected")
	}
}

// Pre-claiming the STK journal idempotency key with a manual journal.
func TestR7_IdempotencyKeyPreclaim(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	is, err := w.issue(t, w.itemSteel, "1")
	must(t, "issue", err)
	_, err = f.svc.CreateJournal(f.ctx, f.prep, f.balanced("p2p:STK_ISSUE:"+is))
	t.Logf("accountant creates manual journal with key p2p:STK_ISSUE:%s: %v", is[:8], err)
	arDenied(t, "a manual journal in the reserved p2p: key namespace", err, "reserved")
	// The database rule, below the kernel (schema owner, so table grants do not intervene).
	err = f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO journals(tenant_id, legal_entity_id, functional_currency, business_event_at, description, source_type, idempotency_key, command_hash, created_by, created_txid)
			VALUES ($3::uuid, $1::uuid, 'ETB', now(), 'x', 'MANUAL', $2, 'x', 'u-x', txid_current())`, f.entity, "P2P:STK_ISSUE:"+is, f.tenant)
		return err
	})
	arDenied(t, "a raw journal in the reserved namespace", err, "reserved")
	_, err = f.svc.ApproveStockIssue(f.ctx, w.cast.siteEng, is)
	if err != nil {
		t.Errorf("OPEN: a manual journal pre-claiming the idempotency key blocks the stock issue approval: %v", err)
	} else {
		t.Logf("held: issue approved despite the pre-claimed key")
	}
}

// ---------------------------------------------------------------------------
// 3. Dates: issue/count journals dated outside any open period.
// ---------------------------------------------------------------------------
func TestR7_IssueDateOutsidePeriods(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	for _, d := range []time.Time{time.Date(2025, 6, 30, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC), {}} {
		is, err := f.svc.CreateStockIssue(f.ctx, c.store, StockIssueInput{WarehouseID: w.store, StockItemID: w.itemSteel, ProjectID: f.project,
			CostCodeID: w.costCode, ExpenseAccountID: w.acct["5000"], Quantity: dec("1"), IssueDate: d})
		if err != nil {
			t.Logf("held: issue dated %s refused at creation: %v", d.Format("2006-01-02"), err)
			continue
		}
		ji, err := f.svc.ApproveStockIssue(f.ctx, c.siteEng, is)
		if err != nil {
			t.Logf("held: issue dated %s refused at approval: %v", d.Format("2006-01-02"), err)
			continue
		}
		ap := f.svc.ApproveJournals(f.ctx, c.finMgr, []string{ji})
		ps := f.svc.PostJournals(f.ctx, c.controller, []string{ji})
		q, _ := w.balanceOf(t, w.itemSteel)
		t.Errorf("OPEN: issue dated %s APPROVED (stock now %s t), journal %s: approve ok=%v %s / post ok=%v %s",
			d.Format("2006-01-02"), q, ji[:8], ap[0].OK, ap[0].Error, ps[0].OK, ps[0].Error)
	}
	// Counts carry no cost code, so a past date outside every period is not caught either.
	for _, d := range []time.Time{time.Date(2025, 6, 30, 0, 0, 0, 0, time.UTC), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)} {
		q, _ := w.balanceOf(t, w.itemSteel)
		ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: q.Sub(dec("0.5")),
			VarianceAccountID: w.acct["5200"], CountDate: d})
		if err != nil {
			t.Logf("held: count dated %s refused: %v", d.Format("2006-01-02"), err)
			continue
		}
		jc, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
		if err != nil {
			t.Logf("held: count dated %s refused at approval: %v", d.Format("2006-01-02"), err)
			continue
		}
		ap := f.svc.ApproveJournals(f.ctx, c.finMgr, []string{jc})
		ps := f.svc.PostJournals(f.ctx, c.controller, []string{jc})
		q2, _ := w.balanceOf(t, w.itemSteel)
		t.Errorf("OPEN: count dated %s APPROVED (stock %s -> %s t), journal %s: approve ok=%v %s / post ok=%v %s",
			d.Format("2006-01-02"), q, q2, jc[:8], ap[0].OK, ap[0].Error, ps[0].OK, ps[0].Error)
	}
	// Subledger journals cannot be cancelled or reversed: the stranded journal stays.
	w.recon(t)
}

// ---------------------------------------------------------------------------
// Budget: the issue's cost is counted again on top of the inventory PO commitment.
// ---------------------------------------------------------------------------
func TestR7_BudgetDoubleCount(t *testing.T) {
	// Since R9-F2 (0030): an inventory purchase stays committed on the
	// ordering code until its stock is issued to that code (put-away releases
	// nothing, so the PR/PO gate keeps limiting stock purchases); an issue to
	// the code moves cost from commitment to actual, capped at what the
	// code's orders put away. Order to issue: available never moves.
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pos := func() postgres.CostPosition {
		r, err := f.svc.ProjectCostReport(f.ctx, c.pm, f.project)
		must(t, "cost report", err)
		for _, p := range r {
			if p.CostCodeID == w.costCode {
				return p
			}
		}
		t.Fatal("cost code missing")
		return postgres.CostPosition{}
	}
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	ordered := pos()
	w.putAway(t, grn, 1, w.itemSteel, "12")
	stocked := pos()
	amt := w.issueApprovePost(t, w.itemSteel, "10")
	after := pos()
	t.Logf("ordered: committed %s actual %s available %s", ordered.Committed, ordered.ActualOther, ordered.Available)
	t.Logf("put away 12 t: committed %s actual %s available %s", stocked.Committed, stocked.ActualOther, stocked.Available)
	t.Logf("issued 10 t (%s): committed %s actual %s available %s", amt, after.Committed, after.ActualOther, after.Available)
	if !stocked.Committed.Equal(ordered.Committed) {
		t.Errorf("OPEN: putting 12 t into stock released %s of commitment (R9-F2: it must release nothing)", ordered.Committed.Sub(stocked.Committed))
	}
	if !stocked.Committed.Sub(after.Committed).Equal(amt) || !after.ActualOther.Equal(amt) {
		t.Errorf("OPEN: the issue of %s moved %s out of commitment (actual %s)", amt, stocked.Committed.Sub(after.Committed), after.ActualOther)
	}
	if !after.Available.Equal(ordered.Available) {
		t.Errorf("OPEN: from order to issue available moved by %s, want 0 (counted once, never released early)", after.Available.Sub(ordered.Available))
	} else {
		t.Logf("held: 10 t consumed counted once; the 2 t on the shelf stays committed to the ordering code")
	}
}

// ---------------------------------------------------------------------------
// Put-away item identity; AI put-away.
// ---------------------------------------------------------------------------
func TestR7_PutAwayItemIdentityAndAI(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	other, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: "CU-WIRE-16", Name: "Copper wire 16mm2", Unit: "t",
		ValuationMethod: "FIFO", InventoryAccountID: w.acct["1200"]})
	must(t, "item", err)
	must(t, "approve item", f.svc.ApproveStockItem(f.ctx, c.finMgr, other))
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	w.financePost(t, j)
	if _, err := f.svc.PutAway(f.ctx, c.store, grn, 1, other, w.store, dec("12")); err == nil {
		q, v := w.balanceOf(t, other)
		t.Errorf("OPEN: PO line 1 (Reinforcement steel Grade 60) put away as CU-WIRE-16: %s t valued %s", q, v)
	} else {
		t.Logf("held: %v", err)
	}
	// A line ordered without a designated item (R8-F8): nothing is put away
	// until procurement names the item; the storekeeper cannot name it.
	poLess := w.inventoryPOUndesignated(t)
	grn2, j2 := w.receipt(t, poLess, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j2)
	_, err = f.svc.PutAway(f.ctx, c.store, grn2, 1, w.itemSteel, w.store, dec("6"))
	arDenied(t, "a put-away from an undesignated line", err, "designates it before put-away")
	arDenied(t, "the storekeeper designating the item", f.svc.DesignatePOLineItem(f.ctx, c.store, poLess, 1, other), "forbidden")
	arDenied(t, "the buyer designating the item (R9-I2)", f.svc.DesignatePOLineItem(f.ctx, c.buyer, poLess, 1, w.itemSteel), "forbidden")
	must(t, "designate steel", f.svc.DesignatePOLineItem(f.ctx, c.procMgr, poLess, 1, w.itemSteel))
	arDenied(t, "a second designation", f.svc.DesignatePOLineItem(f.ctx, c.procMgr, poLess, 1, other), "set once")
	_, err = f.svc.PutAway(f.ctx, c.store, grn2, 1, other, w.store, dec("6"))
	arDenied(t, "a put-away as another item than designated", err, "ordered as another stock item")
	w.putAway(t, grn2, 1, w.itemSteel, "6")
	ai := c.store
	ai.UserID, ai.Kind = "u-store-agent", auth.KindAI
	if id, err := f.svc.PutAway(f.ctx, ai, grn, 2, w.itemCement, w.store, dec("300")); err == nil {
		t.Errorf("OPEN (design): an AI principal put away 300 bags (receipt %s) - a final, unchecked valuation movement under a draft action name", id[:8])
	} else {
		t.Logf("held: AI put-away refused: %v", err)
	}
	aiPM := auth.Principal{Kind: auth.KindAI, UserID: "u-pm-agent", TenantID: f.tenant, Roles: []string{"procurement_manager"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	if _, err := f.svc.CreateWarehouse(f.ctx, aiPM, f.entity, f.project, "AI-STORE", "Agent-created store"); err == nil {
		t.Logf("note: AI principal created a warehouse (no checker step exists for warehouses)")
	}
	// AI / service inventory controller cannot approve a count.
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemCement, CountedQty: dec("290"), VarianceAccountID: w.acct["5200"], CountDate: today()})
	if err == nil {
		for _, k := range []string{auth.KindAI, auth.KindService} {
			p := w.invCtl
			p.Kind, p.UserID = k, "u-invctl-"+k
			_, err := f.svc.ApproveStockCount(f.ctx, p, ct)
			arDenied(t, "count approved by a "+k+" principal", err, "human")
		}
	}
	// Go / SQL draft-action parity for every stock action.
	for _, a := range []string{"stock.item.create", "stock.item.approve", "warehouse.create", "stock.receipt.create", "stock.issue.create", "stock.issue.approve",
		"stock.issue.reject", "stock.issue.cancel", "stock.count.create", "stock.count.approve", "stock.count.reject"} {
		var sqlDraft bool
		must(t, "draft", w.raw(func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT approval_is_draft_action($1)`, a).Scan(&sqlDraft)
		}))
		if sqlDraft != auth.IsDraftAction(a) {
			t.Errorf("OPEN: draft-action disagreement for %s: Go %v SQL %v", a, auth.IsDraftAction(a), sqlDraft)
		}
	}
	t.Logf("held: Go IsDraftAction and SQL approval_is_draft_action agree on all 11 stock actions")
}

// ---------------------------------------------------------------------------
// 6. Visibility.
// ---------------------------------------------------------------------------
func TestR7_Visibility(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("10")})
	w.financePost(t, j)
	tw := auth.Principal{Kind: auth.KindHuman, UserID: "u-central-store", TenantID: f.tenant, Roles: []string{"storekeeper", "procurement_manager", "inventory_controller"}, IssuedAt: time.Now().Add(-time.Minute)}
	central, err := f.svc.CreateWarehouse(f.ctx, tw, f.entity, "", "CENTRAL-01", "Central warehouse")
	must(t, "central", err)
	if _, err := f.svc.PutAway(f.ctx, tw, grn, 1, w.itemSteel, central, dec("12")); err != nil {
		t.Fatalf("central put-away: %v", err)
	}
	// project storekeeper: central stock invisible in StockOnHand
	lines, err := f.svc.StockOnHand(f.ctx, c.store, f.entity)
	must(t, "on hand", err)
	for _, l := range lines {
		if l.WarehouseID == central {
			t.Errorf("OPEN: project storekeeper sees central warehouse stock")
		}
	}
	// the receipt into central is listed / visible to the project (by PO project)
	var rcpt string
	must(t, "rcpt", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM stock_receipts WHERE warehouse_id = $1::uuid`, central).Scan(&rcpt)
	}))
	_, errDoc := f.svc.GetP2PDoc(f.ctx, c.store, "stock_receipt", rcpt)
	_, errWh := f.svc.GetP2PDoc(f.ctx, c.store, "warehouse", central)
	t.Logf("project storekeeper: receipt into central -> %v ; central warehouse -> %v", errDoc, errWh)
	// Detail read of an ordinary project-store receipt, by its own preparer and by a tenant-wide controller.
	w.putAway(t, grn, 2, w.itemCement, "1")
	var rcpt2 string
	must(t, "rcpt2", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM stock_receipts WHERE warehouse_id = $1::uuid`, w.store).Scan(&rcpt2)
	}))
	for _, p := range []auth.Principal{c.store, c.controller} {
		if _, err := f.svc.GetP2PDoc(f.ctx, p, "stock_receipt", rcpt2); err != nil {
			t.Errorf("OPEN: %s cannot read stock receipt %s detail: %v", p.UserID, rcpt2[:8], err)
		}
	}
	if l, err := f.svc.ListP2PDocs(f.ctx, c.store, "stock_receipt", "", 50); err == nil {
		t.Logf("list stock_receipt for project storekeeper: %d rows (incl. central put-away)", len(l))
	} else {
		t.Logf("list stock_receipt: %v", err)
	}
	// other tenant cannot read stock on hand of this entity
	out := auth.Principal{Kind: auth.KindHuman, UserID: "u-x", TenantID: f.tenant2, Roles: []string{"controller"}, IssuedAt: time.Now().Add(-time.Minute)}
	if l, err := f.svc.StockOnHand(f.ctx, out, f.entity); err == nil && len(l) > 0 {
		t.Errorf("OPEN: tenant 2 sees %d stock lines of tenant 1", len(l))
	} else {
		t.Logf("held: tenant 2 stock on hand of tenant 1 entity: %d lines, %v", len(l), err)
	}
	if r, err := f.svc.StockReconciliation(f.ctx, out, f.entity); err == nil && len(r) > 0 {
		t.Errorf("OPEN: tenant 2 reconciles tenant 1")
	}
	// project-scoped issue from the central warehouse (project storekeeper)
	_, err = f.svc.CreateStockIssue(f.ctx, c.store, StockIssueInput{WarehouseID: central, StockItemID: w.itemSteel, ProjectID: f.project,
		CostCodeID: w.costCode, ExpenseAccountID: w.acct["5000"], Quantity: dec("1"), IssueDate: today()})
	t.Logf("project storekeeper issue from central warehouse: %v", err)
}

// ---------------------------------------------------------------------------
// 7. Concurrency.
// ---------------------------------------------------------------------------
func TestR7_ConcurrentPutAwayAndCount(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	w.financePost(t, j)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.svc.PutAway(f.ctx, c.store, grn, 1, w.itemSteel, w.store, dec("8"))
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, e := range errs {
		if e == nil {
			ok++
		}
	}
	q, _ := w.balanceOf(t, w.itemSteel)
	if ok != 1 || !q.Equal(dec("8")) {
		t.Errorf("OPEN: 4 concurrent put-aways of 8 on a 12 t line: %d succeeded, stock %s (%v)", ok, q, errs)
	} else {
		t.Logf("held: concurrent put-aways: 1 of 4 succeeded, stock %s; e.g. %v", q, firstErr(errs))
	}
	// count approval racing an issue approval
	w.putAway(t, grn, 2, w.itemCement, "300")
	for round := 0; round < 5; round++ {
		qb, _ := w.balanceOf(t, w.itemCement)
		ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemCement, CountedQty: qb.Sub(dec("3")),
			VarianceAccountID: w.acct["5200"], CountDate: today()})
		must(t, "count", err)
		is, err := w.issue(t, w.itemCement, "5")
		must(t, "issue", err)
		var e1, e2 error
		wg.Add(2)
		go func() { defer wg.Done(); _, e1 = f.svc.ApproveStockCount(f.ctx, w.invCtl, ct) }()
		go func() { defer wg.Done(); _, e2 = f.svc.ApproveStockIssue(f.ctx, c.siteEng, is) }()
		wg.Wait()
		bal, layers, docs := w.invariants(t)
		qa, _ := w.balanceOf(t, w.itemCement)
		t.Logf("round %d: count err=%v issue err=%v; book %s -> %s; bal %s docs %s layers %s", round, e1, e2, qb, qa, bal, docs, layers)
		if e1 == nil && e2 == nil && !qa.Equal(qb.Sub(dec("8"))) {
			t.Errorf("OPEN: both approved but book %s -> %s", qb, qa)
		}
		if !bal.Equal(docs) || !bal.Equal(layers) {
			t.Errorf("OPEN: invariants broken after race: bal %s docs %s layers %s", bal, docs, layers)
		}
	}
}

// Two items sharing the inventory account, two warehouses, a GRN journal left
// unposted, and a stock item later pointed at by a control account.
func TestR7_ReconSharedAccountUnposted(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pmgr := auth.Principal{Kind: auth.KindHuman, UserID: "u-proc-manager", TenantID: f.tenant, Roles: []string{"procurement_manager"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	store2, err := f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE-B", "Second site store")
	must(t, "store2", err)
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grnA, jA := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("10")}, GRNLine{POLineNo: 2, QtyReceived: dec("100")})
	grnB, jB := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("5")})
	w.financePost(t, jA) // jB left DRAFT
	_, _ = grnB, jB
	w.putAway(t, grnA, 1, w.itemSteel, "4")
	if _, err := f.svc.PutAway(f.ctx, c.store, grnA, 1, w.itemSteel, store2, dec("6")); err != nil {
		t.Fatalf("store2: %v", err)
	}
	w.putAway(t, grnA, 2, w.itemCement, "100")
	if _, err := f.svc.PutAway(f.ctx, c.store, grnB, 1, w.itemSteel, store2, dec("5")); err != nil {
		t.Fatalf("unposted grn put-away: %v", err)
	}
	w.issueApprovePost(t, w.itemSteel, "3")
	r := w.recon(t)
	gl := w.glBalance(t, "1200")
	bal, _, _ := w.invariants(t)
	t.Logf("GL inventory %s; stock balances %s (includes 5 t put away from the unposted GRN)", gl, bal)
	seen := map[string]bool{}
	for _, x := range r {
		switch {
		case strings.HasPrefix(x.Check, "Stock balances vs GL:"):
			seen["stock-gl"] = true
			if x.Difference.Sign() != 0 || x.Unposted < 1 {
				t.Errorf("OPEN: stock balances vs GL row: %+v (want difference 0 with the unposted receipt counted)", x)
			}
		case strings.HasPrefix(x.Check, "Put away from goods receipts not yet posted:"):
			seen["pa-unposted"] = true
			if !x.Subledger.Equal(dec("422500")) || x.Unposted != 1 {
				t.Errorf("OPEN: put-away from the unposted receipt is not shown as 422,500 on 1 receipt: %+v", x)
			}
		case strings.HasPrefix(x.Check, "Inventory:"):
			if x.Unposted < 1 {
				t.Errorf("OPEN: the inventory row does not count the unposted goods receipt: %+v", x)
			}
		}
	}
	if !seen["stock-gl"] || !seen["pa-unposted"] {
		t.Errorf("OPEN: reconciliation rows missing: %v", seen)
	}
	// A manual journal to inventory now also breaks the stock-to-GL row.
	f.lifecycle(t, f.balanced(key("r7-manual-2")))
	for _, x := range w.recon(t) {
		if strings.HasPrefix(x.Check, "Stock balances vs GL:") && !x.Difference.Equal(dec("100000")) {
			t.Errorf("OPEN: a manual 100,000 inventory journal is not a stock-to-GL difference: %+v", x)
		}
	}
	_ = errors.New
	_ = fmt.Sprint
	_ = ledger.Debit
	_ = money.MustNew
}

// Conditional: the trigger-depth guard relies on TEMP being revoked (0006 /
// deploy/02). Simulate a deployment where that step did not run.
func TestR7_TriggerDepthGuardNeedsTempRevoked(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")})
	w.financePost(t, j)
	w.putAway(t, grn, 1, w.itemSteel, "12")
	var role, db string
	must(t, "role", w.raw(func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_user, current_database()`).Scan(&role, &db)
	}))
	if _, err := f.admin.Exec(f.ctx, fmt.Sprintf(`GRANT TEMPORARY ON DATABASE %q TO %q`, db, role)); err != nil {
		t.Skipf("cannot grant TEMP: %v", err)
	}
	defer f.admin.Exec(f.ctx, fmt.Sprintf(`REVOKE TEMPORARY ON DATABASE %q FROM %q`, db, role))
	err := w.raw(func(ctx context.Context, tx pgx.Tx) error {
		for _, s := range []string{
			`CREATE TEMP TABLE r7(x int)`,
			`CREATE FUNCTION pg_temp.r7f() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN
			   UPDATE public.stock_balances SET qty = qty + 1000, value = value + 1;
			   RETURN NEW; END $f$`,
			`CREATE TRIGGER r7t AFTER INSERT ON pg_temp.r7 FOR EACH ROW EXECUTE FUNCTION pg_temp.r7f()`,
			`INSERT INTO pg_temp.r7 VALUES (1)`,
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%.40s: %w", s, err)
			}
		}
		return nil
	})
	q, v := w.balanceOf(t, w.itemSteel)
	if err == nil && q.GreaterThan(dec("12")) {
		// Still possible with TEMP granted: the control is the start-up
		// posture check, which must report it (the API then refuses to start
		// in production).
		t.Logf("conditional: with TEMP granted, the tenant login wrote stock_balances through a pg_temp trigger (steel %s t at %s)", q, v)
	} else {
		t.Logf("held: %v (steel %s t)", err, q)
	}
	var issues []string
	rows, err := f.admin.Query(f.ctx, `SELECT issue FROM serk_database_posture()`)
	must(t, "posture", err)
	issues, err = pgx.CollectRows(rows, pgx.RowTo[string])
	must(t, "posture rows", err)
	found := false
	for _, s := range issues {
		if strings.Contains(s, role) {
			found = true
		}
	}
	if !found {
		t.Errorf("OPEN: the database posture check does not report TEMP held by %s: %v", role, issues)
	} else {
		t.Logf("held: posture check reports %v", issues)
	}
}

// inventoryPOUndesignated is inventoryPO without stock items on the lines.
func (w *stockWorld) inventoryPOUndesignated(t *testing.T) string {
	t.Helper()
	f, c := w.f, w.cast
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Undesignated stock purchase", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec("12"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(72*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "rfq issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q := make([]string, 3)
	for i := range q {
		q[i], err = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[i], time.Now().AddDate(0, 1, 0), "SQ-"+key("u"), []QuoteLine{{1, dec("84500").Add(decimal.NewFromInt(int64(i * 1000)))}})
		must(t, "quote", err)
		must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[i], true, "Mill certificates provided"))
	}
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q[0], ""))
	po, err := f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["1200"]})
	must(t, "po", err)
	must(t, "po approve", f.svc.ApprovePO(f.ctx, c.procMgr, po, ""))
	return po
}
