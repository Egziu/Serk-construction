package kernel

// Journey C (stock valuation) against PostgreSQL. Figures are worked by hand
// in docs/testing/E2E_JOURNEY_C.md: two purchase orders at different prices,
// FIFO steel and WAC cement, partial put-away, issues to the project, a
// shortage and a surplus count, every journal posted, inventory = GL.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

type stockWorld struct {
	*p2pWorld
	itemSteel, itemCement, store string
	invCtl                       auth.Principal
}

func newStockWorld(t *testing.T) *stockWorld {
	t.Helper()
	w := &stockWorld{p2pWorld: newP2PWorld(t)}
	f, c := w.f, w.cast
	w.invCtl = auth.Principal{Kind: auth.KindHuman, UserID: "u-inventory-controller", TenantID: f.tenant, Roles: []string{"inventory_controller"}, IssuedAt: time.Now().Add(-time.Minute)}
	must(t, "variance account", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: f.entity, Code: "5200", Name: "Stock count variance", Type: "EXPENSE", Active: true})
		w.acct["5200"] = id
		return err
	}))
	w.approvedBOQ(t)
	var err error
	for _, it := range []struct {
		code, name, unit, method string
		id                       *string
	}{{"STEEL-G60", "Reinforcement steel Grade 60", "t", "FIFO", &w.itemSteel}, {"CEM-OPC50", "OPC cement 50kg", "bag", "WAC", &w.itemCement}} {
		*it.id, err = f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: it.code, Name: it.name, Unit: it.unit,
			ValuationMethod: it.method, InventoryAccountID: w.acct["1200"]})
		must(t, "stock item", err)
		must(t, "stock item approve", f.svc.ApproveStockItem(f.ctx, c.finMgr, *it.id))
	}
	pmgr := auth.Principal{Kind: auth.KindHuman, UserID: "u-proc-manager", TenantID: f.tenant, Roles: []string{"procurement_manager"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	w.store, err = f.svc.CreateWarehouse(f.ctx, pmgr, f.entity, f.project, "P001-STORE", "Project 001 site store")
	must(t, "warehouse", err)
	return w
}

// inventoryPO runs PR -> RFQ -> award -> PO with both lines posting to the
// inventory account, awarding the given steel and cement prices.
func (w *stockWorld) inventoryPO(t *testing.T, steelQty, cementQty, steelPrice, cementPrice string) string {
	t.Helper()
	f, c := w.f, w.cast
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Stock replenishment for the site store", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec(steelQty), EstUnitPrice: dec("86000")},
		{LineNo: 2, CostCodeID: w.costCode, Description: "OPC cement 50kg", Unit: "bag", Quantity: dec(cementQty), EstUnitPrice: dec("960")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(72*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "rfq issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	sp, cp := dec(steelPrice), dec(cementPrice)
	q := make([]string, 3)
	for i := range q {
		bump := decimal.NewFromInt(int64(i))
		q[i], err = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[i], time.Now().AddDate(0, 1, 0), "SQ-"+key("q"), []QuoteLine{{1, sp.Add(bump.Mul(dec("1000")))}, {2, cp.Add(bump.Mul(dec("10")))}})
		must(t, "quote", err)
		must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[i], true, "Mill certificates provided"))
	}
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q[0], ""))
	po, err := f.svc.CreatePOFromAwardItems(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["1200"], 2: w.acct["1200"]}, map[int]string{1: w.itemSteel, 2: w.itemCement})
	must(t, "po", err)
	must(t, "po approve", f.svc.ApprovePO(f.ctx, c.procMgr, po, ""))
	return po
}

func (w *stockWorld) putAway(t *testing.T, grn string, line int, item, qty string) {
	t.Helper()
	_, err := w.f.svc.PutAway(w.f.ctx, w.cast.store, grn, line, item, w.store, dec(qty))
	must(t, "put-away", err)
}

func (w *stockWorld) issue(t *testing.T, item, qty string) (string, error) {
	t.Helper()
	return w.f.svc.CreateStockIssue(w.f.ctx, w.cast.store, StockIssueInput{WarehouseID: w.store, StockItemID: item, ProjectID: w.f.project,
		CostCodeID: w.costCode, ExpenseAccountID: w.acct["5000"], Quantity: dec(qty), IssueDate: today(), Note: "Level 3 slab"})
}

func (w *stockWorld) stockValue(t *testing.T, sql string, args ...any) decimal.Decimal {
	t.Helper()
	var v decimal.Decimal
	must(t, "value", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&v)
	}))
	return v
}

func (w *stockWorld) balanceOf(t *testing.T, item string) (decimal.Decimal, decimal.Decimal) {
	t.Helper()
	var q, v decimal.Decimal
	must(t, "balance", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(sum(qty), 0), COALESCE(sum(value), 0) FROM stock_balances WHERE stock_item_id = $1::uuid`, item).Scan(&q, &v)
	}))
	return q, v
}

func TestJourneyC_StockValuationToGL(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	var journals []string

	// Two purchase orders at different prices, received and put away.
	po1 := w.inventoryPO(t, "20", "500", "84500", "940")
	grn1, j1 := w.receipt(t, po1, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	po2 := w.inventoryPO(t, "20", "500", "86000", "950")
	grn2, j2 := w.receipt(t, po2, GRNLine{POLineNo: 1, QtyReceived: dec("10")}, GRNLine{POLineNo: 2, QtyReceived: dec("200")})
	journals = append(journals, j1, j2)
	w.putAway(t, grn1, 1, w.itemSteel, "12")
	w.putAway(t, grn1, 2, w.itemCement, "200")
	w.putAway(t, grn1, 2, w.itemCement, "100") // completes the line: exact remainder 94,000
	w.putAway(t, grn2, 1, w.itemSteel, "10")
	w.putAway(t, grn2, 2, w.itemCement, "150") // 50 bags stay received, not put away
	for item, want := range map[string][2]string{w.itemSteel: {"22", "1874000"}, w.itemCement: {"450", "424500"}} {
		q, v := w.balanceOf(t, item)
		if !q.Equal(dec(want[0])) || !v.Equal(dec(want[1])) {
			t.Errorf("after put-away: %s qty %s value %s, want %s / %s", item[:8], q, v, want[0], want[1])
		}
	}

	// Issues: FIFO steel 15 t = 12 x 84,500 + 3 x 86,000; WAC cement 120 bags at 424,500/450.
	is1, err := w.issue(t, w.itemSteel, "15")
	must(t, "issue steel", err)
	ji1, err := f.svc.ApproveStockIssue(f.ctx, c.siteEng, is1)
	must(t, "approve steel issue", err)
	is2, err := w.issue(t, w.itemCement, "120")
	must(t, "issue cement", err)
	ji2, err := f.svc.ApproveStockIssue(f.ctx, c.pm, is2)
	must(t, "approve cement issue", err)
	journals = append(journals, ji1, ji2)
	for id, want := range map[string]string{is1: "1272000", is2: "113200"} {
		if got := w.stockValue(t, `SELECT amount FROM stock_issues WHERE id = $1::uuid`, id); !got.Equal(dec(want)) {
			t.Errorf("issue %s valued %s, want %s", id[:8], got, want)
		} else {
			t.Logf("issue %s valued %s", id[:8], got)
		}
	}

	// Counts: steel 6.5 t on the shelf (book 7): shortage 0.5 t at FIFO 86,000;
	// cement 335 bags (book 330): surplus 5 at the last receipt cost 950 (0024, R7-F1).
	ct1, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("6.5"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count steel", err)
	jc1, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct1)
	must(t, "approve steel count", err)
	ct2, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemCement, CountedQty: dec("335"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count cement", err)
	jc2, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct2)
	must(t, "approve cement count", err)
	journals = append(journals, jc1, jc2)
	for id, want := range map[string]string{ct1: "43000", ct2: "4750"} {
		if got := w.stockValue(t, `SELECT amount FROM stock_counts WHERE id = $1::uuid`, id); !got.Equal(dec(want)) {
			t.Errorf("count %s valued %s, want %s", id[:8], got, want)
		}
	}
	for item, want := range map[string][2]string{w.itemSteel: {"6.5", "559000"}, w.itemCement: {"335", "316050"}} {
		q, v := w.balanceOf(t, item)
		if !q.Equal(dec(want[0])) || !v.Equal(dec(want[1])) {
			t.Errorf("closing balance %s: qty %s value %s, want %s / %s", item[:8], q, v, want[0], want[1])
		} else {
			t.Logf("closing balance %s: %s at %s", item[:8], q, v)
		}
	}

	w.financePost(t, journals...)

	// Inventory to GL.
	if got := w.glBalance(t, "1200"); !got.Equal(dec("922550")) {
		t.Errorf("GL inventory %s, want 922550", got)
	}
	recon, err := f.svc.StockReconciliation(f.ctx, c.controller, f.entity)
	must(t, "stock reconciliation", err)
	if len(recon) != 6 {
		t.Fatalf("stock reconciliation returned %d checks", len(recon))
	}
	for _, r := range recon {
		t.Logf("stock recon %-52s subledger %12s gl %12s diff %s open %d", r.Check, r.Subledger, r.GL, r.Difference, r.Unposted)
		switch {
		case strings.HasPrefix(r.Check, "Received, not yet put away"):
			if !r.Subledger.Equal(dec("47500")) || r.Unposted != 1 {
				t.Errorf("received not put away: %+v, want 47,500 on 1 line", r)
			}
		case !r.Difference.IsZero() || r.Unposted != 0:
			t.Errorf("%s does not reconcile: %+v", r.Check, r)
		}
	}
	// The P2P reconciliation (GRNI) is unaffected by put-away.
	gl, err := f.svc.GLReconciliation(f.ctx, c.controller, f.entity)
	must(t, "p2p recon", err)
	for _, r := range gl {
		if !r.Difference.IsZero() {
			t.Errorf("P2P reconciliation break: %+v", r)
		}
	}
	// Project cost from the ledger: issues and count variances on the project.
	pr, err := f.svc.ProjectProfitability(f.ctx, c.controller, f.project)
	must(t, "profitability", err)
	if !pr.CostPosted.Equal(dec("1423450")) {
		t.Errorf("project cost posted %s, want 1423450", pr.CostPosted)
	}
	onHand, err := f.svc.StockOnHand(f.ctx, c.store, f.entity)
	must(t, "on hand", err)
	if len(onHand) != 2 {
		t.Errorf("storekeeper sees %d stock lines, want 2", len(onHand))
	}
}

func TestJourneyC_Controls(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	po := w.inventoryPO(t, "20", "500", "84500", "940")
	grn, jg := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("12")}, GRNLine{POLineNo: 2, QtyReceived: dec("300")})
	w.financePost(t, jg)

	// Items: maker/checker; inventory account must not be a control account.
	_, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: "BAD-ACCT", Name: "Item on GRNI", Unit: "t",
		ValuationMethod: "FIFO", InventoryAccountID: w.acct["2100"]})
	arDenied(t, "stock item on a control account", err, "inventory account")
	both := auth.Principal{Kind: auth.KindHuman, UserID: "u-buyer", TenantID: f.tenant, Roles: []string{"procurement_officer", "finance_manager"}, IssuedAt: time.Now().Add(-time.Minute)}
	self, err := f.svc.CreateStockItem(f.ctx, both, StockItemInput{LegalEntityID: f.entity, Code: "SELF-1", Name: "Self approved", Unit: "t", ValuationMethod: "WAC",
		InventoryAccountID: w.acct["1200"]})
	must(t, "item for self approval", err)
	arDenied(t, "stock item approved by its creator", f.svc.ApproveStockItem(f.ctx, both, self), "segregation of duties")

	// Put-away: not beyond the receipt line; not from a line posted to expense.
	_, err = f.svc.PutAway(f.ctx, c.store, grn, 1, w.itemSteel, w.store, dec("12.0001"))
	arDenied(t, "put-away beyond the goods receipt line", err, "exceeds")
	_, _, expPO := w.awardedPO(t, "5", "50") // posted to expense (5000)
	expGRN, _ := w.receipt(t, expPO, GRNLine{POLineNo: 1, QtyReceived: dec("5")})
	_, err = f.svc.PutAway(f.ctx, c.store, expGRN, 1, w.itemSteel, w.store, dec("5"))
	arDenied(t, "put-away of a receipt posted to an expense account", err, "does not name its stock item")
	w.putAway(t, grn, 1, w.itemSteel, "12")
	w.putAway(t, grn, 2, w.itemCement, "300")

	// Valuation state is written only by documents.
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE stock_balances SET qty = qty + 100 WHERE stock_item_id = $1::uuid`, w.itemSteel)
		return err
	})
	arDenied(t, "direct change of a stock balance", err, "written only by stock documents")
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT stk_receive($1::uuid, $2::uuid, 100, 1, 0.01, 'RECEIPT', gen_random_uuid())`, w.itemSteel, w.store)
		return err
	})
	arDenied(t, "calling the valuation engine directly", err, "only by a stock document")

	// Issues: no negative stock; no self-approval; no AI approval; cost code of the project.
	big, err := w.issue(t, w.itemSteel, "12.5")
	must(t, "issue beyond stock", err)
	_, err = f.svc.ApproveStockIssue(f.ctx, c.siteEng, big)
	arDenied(t, "issue beyond the stock on hand", err, "insufficient stock")
	selfIss, err := w.issue(t, w.itemSteel, "1")
	must(t, "issue", err)
	storeEng := auth.Principal{Kind: auth.KindHuman, UserID: "u-storekeeper", TenantID: f.tenant, Roles: []string{"storekeeper", "site_engineer"}, ProjectIDs: []string{f.project}, IssuedAt: time.Now().Add(-time.Minute)}
	_, err = f.svc.ApproveStockIssue(f.ctx, storeEng, selfIss)
	arDenied(t, "issue approved by its preparer", err, "segregation of duties")
	ai := c.siteEng
	ai.UserID, ai.Kind = "u-site-assistant", auth.KindAI
	_, err = f.svc.ApproveStockIssue(f.ctx, ai, selfIss)
	arDenied(t, "issue approved by an AI principal", err, "reserved to human principals")
	jIss, err := f.svc.ApproveStockIssue(f.ctx, c.siteEng, selfIss)
	must(t, "approve issue", err)

	// The STK journal is bound: lines cannot be edited, the journal cannot be reversed.
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE journal_lines SET amount = amount + 1 WHERE journal_id = $1::uuid`, jIss)
		return err
	})
	arDenied(t, "editing the lines of a stock journal", err, "permission denied")
	w.financePost(t, jIss)
	_, err = f.svc.ReverseJournal(f.ctx, c.controller, jIss, key("rev"), "wrong project", today())
	arDenied(t, "reversing a stock journal", err, "not reversed")

	// Counts: stale after a movement; no surplus without a cost basis.
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("10"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "count", err)
	moved, err := w.issue(t, w.itemSteel, "1")
	must(t, "issue", err)
	_, err = f.svc.ApproveStockIssue(f.ctx, c.siteEng, moved)
	must(t, "approve issue", err)
	_, err = f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
	arDenied(t, "approving a stale count", err, "is stale")
	_, err = f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("10"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	arDenied(t, "a count that agrees with the books", err, "nothing to adjust")
	newItem, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: "SAND-01", Name: "River sand", Unit: "m3",
		ValuationMethod: "WAC", InventoryAccountID: w.acct["1200"]})
	must(t, "new item", err)
	must(t, "approve new item", f.svc.ApproveStockItem(f.ctx, c.finMgr, newItem))
	_, err = f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: newItem, CountedQty: dec("4"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	arDenied(t, "a surplus with no cost basis (refused when recorded)", err, "no cost basis")
	_, err = f.svc.ApproveStockCount(f.ctx, c.store, ct)
	arDenied(t, "count approved by the storekeeper", err, "forbidden")

	// Visibility: another project's storekeeper sees neither the store nor its stock.
	other := auth.Principal{Kind: auth.KindHuman, UserID: "u-store-2", TenantID: f.tenant, Roles: []string{"storekeeper"}, ProjectIDs: []string{"8c1d4c2e-0000-4000-8000-000000000001"}, IssuedAt: time.Now().Add(-time.Minute)}
	_, err = f.svc.CreateStockIssue(f.ctx, other, StockIssueInput{WarehouseID: w.store, StockItemID: w.itemSteel, ProjectID: "8c1d4c2e-0000-4000-8000-000000000001",
		CostCodeID: w.costCode, ExpenseAccountID: w.acct["5000"], Quantity: dec("1"), IssueDate: today()})
	arDenied(t, "issue from another project's store", err, "not found")
	if lines, _ := f.svc.StockOnHand(f.ctx, other, f.entity); len(lines) != 0 {
		t.Errorf("another project's storekeeper sees %d stock lines", len(lines))
	}

	// Concurrency: two issues of 6 t against 10 t on hand; exactly one succeeds.
	a, err := w.issue(t, w.itemSteel, "6")
	must(t, "issue a", err)
	b, err := w.issue(t, w.itemSteel, "6")
	must(t, "issue b", err)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{a, b} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			_, errs[i] = f.svc.ApproveStockIssue(f.ctx, c.siteEng, id)
		}(i, id)
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Errorf("concurrent issues: %v / %v (want exactly one to succeed)", errs[0], errs[1])
	} else {
		t.Logf("refused: concurrent over-issue: one approved, the other %v", firstErr(errs))
	}
	if q, _ := w.balanceOf(t, w.itemSteel); q.IsNegative() || !q.Equal(dec("4")) {
		t.Errorf("steel on hand after the race: %s, want 4", q)
	}
}

// glBalance is the posted GL balance (debit positive) of an account code.
func (w *p2pWorld) glBalance(t *testing.T, code string) decimal.Decimal {
	t.Helper()
	var b decimal.Decimal
	must(t, "gl balance", w.f.app.WithTenant(w.f.ctx, w.f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(sum(CASE WHEN l.side = 'DEBIT' THEN l.amount ELSE -l.amount END), 0) FROM journal_lines l
			JOIN journals j ON j.id = l.journal_id WHERE l.account_id = $1::uuid AND j.status IN ('POSTED', 'REVERSED')`, w.acct[code]).Scan(&b)
	}))
	return b
}

func firstErr(errs []error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
