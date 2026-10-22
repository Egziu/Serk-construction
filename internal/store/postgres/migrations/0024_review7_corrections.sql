-- 0024: corrections from independent review 7 (stock valuation, 0021).
-- docs/security/INDEPENDENT_REVIEW_7_2026-10-22.md; ADR 0012 addendum.
--
--   R7-F1  a surplus count is valued at the item's last receipt cost, fixed
--          when the count is recorded (visible to the approver), never at the
--          average of a rounding remainder; a zero-valued surplus is refused.
--   R7-F2  the stock reconciliation compares stock balances with the GL, with
--          explicit reconciling items, and flags a negative "not yet put away".
--   R7-F3  issue and count dates: not in the future, in an OPEN fiscal period
--          of the entity, re-checked at approval.
--   R7-F4  stock issued to a cost code first consumes that code's open
--          inventory purchase commitment (no double count of budget).
--   R7-F5  a purchase-order line is put away as one stock item only; put-away
--          is a decision reserved to human principals.
--   R7-F6  stock receipts carry a status (always POSTED) so the generic
--          document read works.
--   R7-F7  put-away values are rounded cumulatively and never exceed what the
--          goods receipt line debited.
--   R7-F8  the "p2p:" idempotency namespace is reserved to the subledger
--          journal of the named document.
--   R7-I1  put-aways are scoped by their warehouse (central stock is visible
--          only with tenant-wide scope), in the kernel (docProject).
--   R7-F9  is handled at runtime: the API refuses to start in production when
--          a tenant login holds TEMP on the database (internal/store/postgres
--          Router.Posture); see the review document.

-- R7-F6 ----------------------------------------------------------------------
ALTER TABLE stock_receipts ADD COLUMN status text NOT NULL DEFAULT 'POSTED' CHECK (status = 'POSTED');

-- R7-F1: the surplus unit cost recorded with the count -------------------------
ALTER TABLE stock_counts ADD COLUMN surplus_unit_cost numeric(24,6);

-- R7-F5: put-away is a human decision -------------------------------------------
CREATE OR REPLACE FUNCTION approval_is_draft_action(p_action text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT (p_action ~ '\.(create|submit)$' OR p_action IN ('rfq.quote.record', 'bank.import', 'workflow.start'))
     AND p_action NOT IN ('stock.receipt.create')
$$;

-- R7-F5: a PO line may designate its stock item; the put-away must match it.
ALTER TABLE po_lines ADD COLUMN stock_item_id uuid;
ALTER TABLE po_lines ADD CONSTRAINT po_lines_stock_item_fk FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id);
CREATE OR REPLACE FUNCTION po_lines_stock_item() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.stock_item_id IS DISTINCT FROM OLD.stock_item_id THEN
    RAISE EXCEPTION 'the stock item of a purchase order line is set when the line is created' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.stock_item_id IS NOT NULL THEN
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> NEW.legal_entity_id OR it.inventory_account_id <> NEW.account_id
       OR lower(btrim(it.unit)) <> lower(btrim(NEW.unit)) THEN
      RAISE EXCEPTION 'purchase order line %: the stock item must be ACTIVE, of the entity, in the line''s unit, with the line''s account as its inventory account',
        NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER po_lines_stock_item BEFORE INSERT OR UPDATE ON po_lines FOR EACH ROW EXECUTE FUNCTION po_lines_stock_item();

-- Last receipt cost of an item: this warehouse first, else any warehouse.
CREATE OR REPLACE FUNCTION stk_last_receipt_cost(p_item uuid, p_wh uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT r.unit_cost FROM stock_receipts r
   WHERE r.stock_item_id = p_item AND r.tenant_id = current_tenant()
   ORDER BY (r.warehouse_id = p_wh) DESC, r.created_at DESC, r.id LIMIT 1
$$;

-- R7-F5 + R7-F7: the 0021 body with item identity per PO line and cumulative rounding.
CREATE OR REPLACE FUNCTION stock_receipts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE g grns; o purchase_orders; pl po_lines; gl grn_lines; it stock_items; w warehouses; done_qty numeric; done_amt numeric; line_amt numeric;
        other_item uuid;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'stock receipts are not changed; record a count to correct stock' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO g FROM grns WHERE id = NEW.grn_id AND tenant_id = current_tenant() FOR UPDATE;  -- serialises put-away of one receipt
  SELECT * INTO o FROM purchase_orders WHERE id = g.po_id FOR UPDATE;                          -- and of one PO line across receipts
  SELECT * INTO pl FROM po_lines WHERE po_id = o.id AND line_no = NEW.po_line_no;
  SELECT * INTO gl FROM grn_lines WHERE grn_id = g.id AND po_line_no = NEW.po_line_no;
  SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
  SELECT * INTO w FROM warehouses WHERE id = NEW.warehouse_id AND tenant_id = current_tenant();
  IF g.status IS DISTINCT FROM 'CONFIRMED' OR gl.grn_id IS NULL THEN
    RAISE EXCEPTION 'stock is put away only from a line of a CONFIRMED goods receipt' USING ERRCODE = 'check_violation';
  END IF;
  IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> o.legal_entity_id OR pl.account_id <> it.inventory_account_id
     OR lower(btrim(pl.unit)) <> lower(btrim(it.unit)) THEN
    RAISE EXCEPTION 'the goods receipt line must have been posted to the item''s inventory account, in the item''s unit, for an ACTIVE item of the entity'
      USING ERRCODE = 'check_violation';
  END IF;
  -- R7-F5: a designated line is put away as its item; any line is one item.
  IF pl.stock_item_id IS NOT NULL AND pl.stock_item_id <> NEW.stock_item_id THEN
    RAISE EXCEPTION 'purchase order line % was ordered as another stock item', NEW.po_line_no USING ERRCODE = 'check_violation';
  END IF;
  -- R7-F5: one purchase-order line is one stock item.
  SELECT r.stock_item_id INTO other_item FROM stock_receipts r JOIN grns g2 ON g2.id = r.grn_id
   WHERE g2.po_id = o.id AND r.po_line_no = NEW.po_line_no AND r.stock_item_id <> NEW.stock_item_id LIMIT 1;
  IF other_item IS NOT NULL THEN
    RAISE EXCEPTION 'purchase order line % is already put away as another stock item; one line is one item', NEW.po_line_no
      USING ERRCODE = 'check_violation';
  END IF;
  IF w.legal_entity_id IS DISTINCT FROM o.legal_entity_id OR (w.project_id IS NOT NULL AND w.project_id <> o.project_id) THEN
    RAISE EXCEPTION 'the warehouse belongs to another entity or project' USING ERRCODE = 'check_violation';
  END IF;
  SELECT COALESCE(sum(quantity), 0), COALESCE(sum(amount), 0) INTO done_qty, done_amt FROM stock_receipts WHERE grn_id = g.id AND po_line_no = NEW.po_line_no;
  IF done_qty + NEW.quantity > gl.qty_received THEN
    RAISE EXCEPTION 'put-away % exceeds what the goods receipt line still holds (% of % already put away)', NEW.quantity, done_qty, gl.qty_received
      USING ERRCODE = 'check_violation';
  END IF;
  line_amt := p2p_round(gl.qty_received * pl.unit_price, o.currency);
  NEW.legal_entity_id := o.legal_entity_id;
  NEW.currency := o.currency;
  NEW.unit_cost := pl.unit_price;
  NEW.status := 'POSTED';
  -- R7-F7: cumulative rounding. Each put-away takes round(cumulative qty x
  -- price) less what earlier put-aways took; the completing one takes the
  -- exact remainder of what the receipt debited. The running total never
  -- exceeds the line's debit.
  NEW.amount := CASE WHEN done_qty + NEW.quantity = gl.qty_received THEN line_amt - done_amt
                     ELSE least(line_amt, p2p_round((done_qty + NEW.quantity) * pl.unit_price, o.currency)) - done_amt END;
  IF NEW.amount < 0 OR done_amt + NEW.amount > line_amt THEN
    RAISE EXCEPTION 'put-away value would be negative or exceed the goods receipt line (integrity)' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM stk_receive(NEW.stock_item_id, NEW.warehouse_id, NEW.quantity, NEW.amount, pl.unit_price, 'RECEIPT', NEW.id);
  RETURN NEW;
END$$;

-- R7-F1: the 0021 body; a surplus is valued at the last receipt cost recorded
-- with the count.
CREATE OR REPLACE FUNCTION stock_counts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; w warehouses; a accounts; le legal_entities; b stock_balances; v numeric;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO w FROM warehouses WHERE id = NEW.warehouse_id AND tenant_id = current_tenant();
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    SELECT * INTO a FROM accounts WHERE id = NEW.variance_account_id AND tenant_id = current_tenant();
    SELECT * INTO le FROM legal_entities WHERE id = w.legal_entity_id;
    SELECT * INTO b FROM stock_balances WHERE stock_item_id = NEW.stock_item_id AND warehouse_id = NEW.warehouse_id;
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.amount IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'stock counts are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> w.legal_entity_id THEN
      RAISE EXCEPTION 'stock is counted for an ACTIVE item of the warehouse''s entity' USING ERRCODE = 'check_violation';
    END IF;
    IF a.type IS DISTINCT FROM 'EXPENSE' OR NOT a.active OR p2p_is_control_account(a.id) THEN
      RAISE EXCEPTION 'stock count differences post to an active EXPENSE (variance) account' USING ERRCODE = 'check_violation';
    END IF;
    NEW.system_qty := COALESCE(b.qty, 0);
    NEW.difference := NEW.counted_qty - NEW.system_qty;
    IF NEW.difference = 0 THEN
      RAISE EXCEPTION 'the count agrees with the books: nothing to adjust' USING ERRCODE = 'check_violation';
    END IF;
    NEW.legal_entity_id := w.legal_entity_id;
    NEW.project_id := w.project_id;
    NEW.currency := le.functional_currency;
    NEW.surplus_unit_cost := NULL;
    IF NEW.difference > 0 THEN
      -- A surplus is valued at the item's last receipt cost (not at the
      -- average of what is left, which rounding can distort). Without a
      -- receipt, or at a zero value, it must come in through purchasing.
      NEW.surplus_unit_cost := stk_last_receipt_cost(NEW.stock_item_id, NEW.warehouse_id);
      IF NEW.surplus_unit_cost IS NULL OR p2p_round(NEW.difference * NEW.surplus_unit_cost, NEW.currency) <= 0 THEN
        RAISE EXCEPTION 'no cost basis for a surplus of %: receive it through purchasing', it.code USING ERRCODE = 'check_violation';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approved_txid', 'amount'], 'stock count');
    PERFORM approval_use('stock.count.approve', 'stock_count', NEW.id::text, NEW.approved_by, ARRAY['stock.adjust.approve'], false, 'APPROVED', NULL);
    SELECT * INTO b FROM stock_balances WHERE stock_item_id = NEW.stock_item_id AND warehouse_id = NEW.warehouse_id FOR UPDATE;
    IF COALESCE(b.qty, 0) <> NEW.system_qty THEN
      RAISE EXCEPTION 'count % is stale: the book quantity changed from % to % since it was recorded; count again', OLD.number, NEW.system_qty, COALESCE(b.qty, 0)
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.difference < 0 THEN
      v := stk_consume(NEW.stock_item_id, NEW.warehouse_id, -NEW.difference, 'COUNT', NEW.id);
    ELSE
      v := p2p_round(NEW.difference * NEW.surplus_unit_cost, NEW.currency);
      IF v <= 0 THEN
        RAISE EXCEPTION 'a surplus is not valued at zero' USING ERRCODE = 'check_violation';
      END IF;
      PERFORM stk_receive(NEW.stock_item_id, NEW.warehouse_id, NEW.difference, v, NEW.surplus_unit_cost, 'COUNT', NEW.id);
    END IF;
    NEW.amount := v;
    NEW.approved_at := now();
    NEW.approved_txid := txid_current();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['journal_id'], 'stock count');
    IF OLD.journal_id IS NOT NULL OR OLD.approved_txid IS DISTINCT FROM txid_current() OR NEW.journal_id IS NULL THEN
      RAISE EXCEPTION 'the journal of a stock count is attached once, by the approving transaction' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.amount > 0 THEN
      PERFORM stk_assert_journal(NEW.journal_id, 'STK_ADJUST', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.count_date);
    END IF;
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'stock count');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a stock count requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('stock.count.reject', 'stock_count', NEW.id::text, NULL, ARRAY['stock.adjust.approve'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal stock count transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- R7-F3: document dates ------------------------------------------------------------
CREATE OR REPLACE FUNCTION stk_document_date() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE d date := COALESCE(to_jsonb(NEW)->>'issue_date', to_jsonb(NEW)->>'count_date')::date;
BEGIN
  IF TG_OP = 'INSERT' AND d > current_date THEN
    RAISE EXCEPTION 'a stock % is not dated in the future (%)', CASE TG_TABLE_NAME WHEN 'stock_issues' THEN 'issue' ELSE 'count' END, d
      USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' OR (NEW.status = 'APPROVED' AND OLD.status IS DISTINCT FROM 'APPROVED') THEN
    IF NOT EXISTS (SELECT 1 FROM fiscal_periods fp WHERE fp.tenant_id = current_tenant() AND fp.legal_entity_id = NEW.legal_entity_id
                     AND d BETWEEN fp.starts_on AND fp.ends_on AND fp.status = 'OPEN') THEN
      RAISE EXCEPTION 'stock document date % is not in an open fiscal period of the entity', d USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
-- Named to fire after the guards (which set legal_entity_id).
CREATE TRIGGER stock_issues_xdate BEFORE INSERT OR UPDATE ON stock_issues FOR EACH ROW EXECUTE FUNCTION stk_document_date();
CREATE TRIGGER stock_counts_xdate BEFORE INSERT OR UPDATE ON stock_counts FOR EACH ROW EXECUTE FUNCTION stk_document_date();

-- R7-F8: the subledger idempotency namespace ---------------------------------------
CREATE OR REPLACE FUNCTION journals_reserved_idempotency() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF lower(NEW.idempotency_key) LIKE 'p2p:%'
     AND (NEW.source_type !~ '^(P2P|AR|STK)_' OR NEW.idempotency_key IS DISTINCT FROM 'p2p:' || NEW.source_type || ':' || NEW.source_ref) THEN
    RAISE EXCEPTION 'idempotency keys beginning "p2p:" are reserved to the subledger journal of the named document' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_reserved_idempotency BEFORE INSERT ON journals FOR EACH ROW EXECUTE FUNCTION journals_reserved_idempotency();

-- R7-F4: budget (the 0014 body; inventory commitments net of issued stock) -----------
CREATE OR REPLACE FUNCTION p2p_cost_position(p_cost_code uuid, p_exclude_pr uuid, p_exclude_po uuid,
  OUT budget numeric, OUT committed numeric, OUT reserved numeric, OUT actual_other numeric, OUT available numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE inv_committed numeric; stk_actual numeric;
BEGIN
  SELECT COALESCE(sum(i.amount), 0) INTO budget
    FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
   WHERE i.tenant_id = current_tenant() AND i.cost_code_id = p_cost_code AND v.status = 'APPROVED';
  SELECT COALESCE(sum(c.amt) FILTER (WHERE NOT c.inventory), 0), COALESCE(sum(c.amt) FILTER (WHERE c.inventory), 0) INTO committed, inv_committed
    FROM (SELECT greatest(l.amount, p2p_round(p2p_received_qty(l.po_id, l.line_no) * l.unit_price, o.currency)) AS amt,
                 EXISTS (SELECT 1 FROM stock_items si WHERE si.inventory_account_id = l.account_id) AS inventory
            FROM po_lines l JOIN purchase_orders o ON o.id = l.po_id
           WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND o.status IN ('APPROVED', 'CLOSED')
             AND o.id IS DISTINCT FROM p_exclude_po) c;
  SELECT COALESCE(sum(l.est_amount), 0) INTO reserved
    FROM pr_lines l JOIN purchase_requisitions r ON r.id = l.pr_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND r.status = 'APPROVED'
     AND r.id IS DISTINCT FROM p_exclude_pr
     AND NOT EXISTS (SELECT 1 FROM rfqs q JOIN purchase_orders o ON o.rfq_id = q.id
                      WHERE q.pr_id = r.id AND o.status IN ('APPROVED', 'CLOSED'));
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO actual_other
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status IN ('POSTED', 'REVERSED')
     AND j.source_type <> 'P2P_GRN';
  -- Stock issued to this code first consumes the code's own open inventory
  -- commitment: the purchase and the issue are the same cost, counted once.
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO stk_actual
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status = 'POSTED' AND j.source_type LIKE 'STK\_%';
  committed := committed + greatest(0, inv_committed - greatest(stk_actual, 0));
  available := budget - committed - reserved - actual_other;
END$$;

-- R7-F2: reconciliation ---------------------------------------------------------------
CREATE OR REPLACE FUNCTION stock_gl_reconciliation(p_entity uuid)
RETURNS TABLE (check_name text, subledger numeric, gl numeric, difference numeric, unposted_documents bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE acc record; grn_posted numeric; moves numeric; g numeric; un bigint; putaway numeric; bal numeric; docs numeric; layers numeric;
        pa_unposted numeric; un_grn bigint; un_moves numeric; un_docs bigint;
BEGIN
  FOR acc IN SELECT DISTINCT a.id, a.code, a.name FROM stock_items i JOIN accounts a ON a.id = i.inventory_account_id
              WHERE i.tenant_id = current_tenant() AND i.legal_entity_id = p_entity ORDER BY a.code LOOP
    SELECT COALESCE(sum(p2p_round(gl.qty_received * pl.unit_price, o.currency)), 0) INTO grn_posted
      FROM grns gr JOIN journals j ON j.id = gr.journal_id JOIN purchase_orders o ON o.id = gr.po_id
      JOIN grn_lines gl ON gl.grn_id = gr.id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
     WHERE o.legal_entity_id = p_entity AND pl.account_id = acc.id AND j.status = 'POSTED';
    SELECT COALESCE((SELECT sum(CASE WHEN c.difference > 0 THEN c.amount ELSE -c.amount END) FROM stock_counts c JOIN journals j ON j.id = c.journal_id
                      JOIN stock_items i ON i.id = c.stock_item_id WHERE i.inventory_account_id = acc.id AND j.status = 'POSTED'), 0)
         - COALESCE((SELECT sum(s.amount) FROM stock_issues s JOIN journals j ON j.id = s.journal_id JOIN stock_items i ON i.id = s.stock_item_id
                      WHERE i.inventory_account_id = acc.id AND j.status = 'POSTED'), 0) INTO moves;
    SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
      FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = acc.id AND j.status IN ('POSTED', 'REVERSED');
    -- Unposted documents on the account: stock issues and counts, and goods receipts.
    SELECT (SELECT count(*) FROM stock_issues s JOIN journals j ON j.id = s.journal_id JOIN stock_items i ON i.id = s.stock_item_id
             WHERE i.inventory_account_id = acc.id AND j.status <> 'POSTED')
         + (SELECT count(*) FROM stock_counts c JOIN journals j ON j.id = c.journal_id JOIN stock_items i ON i.id = c.stock_item_id
             WHERE i.inventory_account_id = acc.id AND j.status <> 'POSTED') INTO un_docs;
    SELECT count(DISTINCT gr.id) INTO un_grn FROM grns gr JOIN journals j ON j.id = gr.journal_id JOIN purchase_orders o ON o.id = gr.po_id
      JOIN grn_lines gl ON gl.grn_id = gr.id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
     WHERE o.legal_entity_id = p_entity AND pl.account_id = acc.id AND j.status <> 'POSTED';
    check_name := 'Inventory: ' || acc.code || ' ' || acc.name; subledger := grn_posted + moves; gl := g; difference := g - (grn_posted + moves);
    unposted_documents := un_docs + un_grn; RETURN NEXT;
    -- Received on the account (posted) but not yet put away; negative is an error.
    SELECT COALESCE(sum(r.amount), 0) INTO putaway FROM stock_receipts r JOIN grns gr ON gr.id = r.grn_id JOIN journals j ON j.id = gr.journal_id
      JOIN stock_items i ON i.id = r.stock_item_id WHERE i.inventory_account_id = acc.id AND j.status = 'POSTED';
    check_name := 'Received, not yet put away: ' || acc.code; subledger := grn_posted - putaway; gl := NULL; difference := least(grn_posted - putaway, 0);
    unposted_documents := (SELECT count(*) FROM grns gr JOIN purchase_orders o ON o.id = gr.po_id JOIN grn_lines gl ON gl.grn_id = gr.id
                            JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
                           WHERE pl.account_id = acc.id AND gr.status = 'CONFIRMED'
                             AND gl.qty_received > COALESCE((SELECT sum(quantity) FROM stock_receipts r WHERE r.grn_id = gr.id AND r.po_line_no = gl.po_line_no), 0));
    RETURN NEXT;
    -- Stock balances against the GL with explicit reconciling items:
    --   GL = stock - put away from unposted receipts + posted receipts not yet put away
    --        + approved issues and shortages not yet posted - approved surpluses not yet posted
    SELECT COALESCE(sum(b.value), 0) INTO bal FROM stock_balances b JOIN stock_items i ON i.id = b.stock_item_id WHERE i.inventory_account_id = acc.id;
    SELECT COALESCE(sum(r.amount), 0) INTO pa_unposted FROM stock_receipts r JOIN grns gr ON gr.id = r.grn_id JOIN stock_items i ON i.id = r.stock_item_id
      LEFT JOIN journals j ON j.id = gr.journal_id WHERE i.inventory_account_id = acc.id AND j.status IS DISTINCT FROM 'POSTED';
    SELECT COALESCE((SELECT sum(s.amount) FROM stock_issues s JOIN stock_items i ON i.id = s.stock_item_id LEFT JOIN journals j ON j.id = s.journal_id
                      WHERE i.inventory_account_id = acc.id AND s.status = 'APPROVED' AND s.amount > 0 AND j.status IS DISTINCT FROM 'POSTED'), 0)
         + COALESCE((SELECT sum(CASE WHEN c.difference < 0 THEN c.amount ELSE -c.amount END) FROM stock_counts c JOIN stock_items i ON i.id = c.stock_item_id
                      LEFT JOIN journals j ON j.id = c.journal_id
                      WHERE i.inventory_account_id = acc.id AND c.status = 'APPROVED' AND c.amount > 0 AND j.status IS DISTINCT FROM 'POSTED'), 0) INTO un_moves;
    check_name := 'Stock balances vs GL: ' || acc.code; subledger := bal - pa_unposted + (grn_posted - putaway) + un_moves; gl := g;
    difference := g - (bal - pa_unposted + (grn_posted - putaway) + un_moves); unposted_documents := un_docs + un_grn; RETURN NEXT;
    check_name := 'Put away from goods receipts not yet posted: ' || acc.code; subledger := pa_unposted; gl := NULL; difference := NULL;
    unposted_documents := un_grn; RETURN NEXT;
    -- Integrity: running balances = documents (all approved, posted or not), and FIFO layers = balances.
    SELECT COALESCE((SELECT sum(r.amount) FROM stock_receipts r JOIN stock_items i ON i.id = r.stock_item_id WHERE i.inventory_account_id = acc.id), 0)
         + COALESCE((SELECT sum(CASE WHEN c.difference > 0 THEN c.amount ELSE -c.amount END) FROM stock_counts c JOIN stock_items i ON i.id = c.stock_item_id
                      WHERE i.inventory_account_id = acc.id AND c.status = 'APPROVED'), 0)
         - COALESCE((SELECT sum(s.amount) FROM stock_issues s JOIN stock_items i ON i.id = s.stock_item_id
                      WHERE i.inventory_account_id = acc.id AND s.status = 'APPROVED'), 0) INTO docs;
    SELECT COALESCE(sum(l.value_remaining), 0) + COALESCE((SELECT sum(b.value) FROM stock_balances b JOIN stock_items i ON i.id = b.stock_item_id
                                                             WHERE i.inventory_account_id = acc.id AND i.valuation_method = 'WAC'), 0) INTO layers
      FROM stock_layers l JOIN stock_items i ON i.id = l.stock_item_id WHERE i.inventory_account_id = acc.id AND i.valuation_method = 'FIFO';
    check_name := 'Stock balances vs documents: ' || acc.code; subledger := docs; gl := bal; difference := bal - docs;
    unposted_documents := 0; RETURN NEXT;
    check_name := 'Cost layers vs stock balances: ' || acc.code; subledger := layers; gl := bal; difference := layers - bal;
    unposted_documents := 0; RETURN NEXT;
  END LOOP;
END$$;

REVOKE ALL ON FUNCTION stk_last_receipt_cost(uuid, uuid), stk_document_date(), journals_reserved_idempotency(), po_lines_stock_item() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stk_last_receipt_cost(uuid, uuid) TO serk_app;

-- Database posture for the API's start-up check (R7-F9): tenant logins must
-- not hold TEMP (pg_temp triggers would raise the trigger depth the stock
-- guards rely on) or advisory-lock functions. Callable by the privilege-less
-- health role; it reveals only booleans about SERK roles.
CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT 'TEMP is granted on the database to tenant login ' || r.rolname
    FROM pg_roles r
   WHERE pg_has_role(r.oid, 'serk_app', 'MEMBER') AND has_database_privilege(r.oid, current_database(), 'TEMP')
  UNION ALL
  SELECT 'pg_advisory_lock is executable by tenant logins'
   WHERE has_function_privilege('serk_app', 'pg_catalog.pg_advisory_lock(bigint)', 'EXECUTE')
$$;
REVOKE ALL ON FUNCTION serk_database_posture() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION serk_database_posture() TO serk_monitor;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') THEN
    GRANT EXECUTE ON FUNCTION serk_database_posture() TO serk_health;
  END IF;
END$$;
