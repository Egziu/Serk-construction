-- 0021: Journey C, stock valuation (GATEB-05). ADR 0012.
--
-- stock item (maker/checker) -> put-away of confirmed goods receipts into a
-- warehouse (no journal: the GRN already debited the inventory account) ->
-- issues to a project cost code (storekeeper prepares, site engineer or
-- project manager approves; the database consumes FIFO layers or the moving
-- average and refuses negative stock; STK_ISSUE journal) -> counts with
-- maker/checker (STK_ADJUST journal) -> inventory-to-GL reconciliation.
-- Valuation state (balances, layers, consumptions) is written only by the
-- document triggers (trigger depth), never directly by the tenant login.

-- ===========================================================================
-- Tables
-- ===========================================================================
CREATE TABLE stock_items (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id      uuid NOT NULL,
  code                 text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9._-]{1,39}$'),
  name                 text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 200),
  unit                 text NOT NULL CHECK (length(btrim(unit)) BETWEEN 1 AND 20),
  valuation_method     text NOT NULL CHECK (valuation_method IN ('FIFO', 'WAC')),
  inventory_account_id uuid NOT NULL,
  status               text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE')),
  created_by           text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  approved_by          text,
  approved_at          timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, code),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, inventory_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  CONSTRAINT stock_item_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE warehouses (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  project_id      uuid,
  code            text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9._-]{1,31}$'),
  name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 200),
  status          text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, code),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id)
);

CREATE TABLE stock_balances (
  tenant_id     uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  stock_item_id uuid NOT NULL,
  warehouse_id  uuid NOT NULL,
  qty           numeric(20,4) NOT NULL DEFAULT 0 CHECK (qty >= 0),
  value         numeric(24,6) NOT NULL DEFAULT 0 CHECK (value >= 0),
  PRIMARY KEY (stock_item_id, warehouse_id),
  CHECK (qty > 0 OR value = 0),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, warehouse_id) REFERENCES warehouses(tenant_id, id)
);

-- FIFO cost layers (FIFO items only; WAC items are valued by the balance).
CREATE TABLE stock_layers (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  stock_item_id   uuid NOT NULL,
  warehouse_id    uuid NOT NULL,
  seq             bigint GENERATED ALWAYS AS IDENTITY,
  source_type     text NOT NULL CHECK (source_type IN ('RECEIPT', 'COUNT')),
  source_id       uuid NOT NULL,
  qty_in          numeric(20,4) NOT NULL CHECK (qty_in > 0),
  qty_remaining   numeric(20,4) NOT NULL CHECK (qty_remaining >= 0 AND qty_remaining <= qty_in),
  unit_cost       numeric(24,6) NOT NULL CHECK (unit_cost >= 0),
  value_in        numeric(24,6) NOT NULL CHECK (value_in >= 0),
  value_remaining numeric(24,6) NOT NULL CHECK (value_remaining >= 0 AND value_remaining <= value_in),
  CHECK (qty_remaining > 0 OR value_remaining = 0),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, warehouse_id) REFERENCES warehouses(tenant_id, id)
);
CREATE INDEX stock_layers_open ON stock_layers (stock_item_id, warehouse_id, seq) WHERE qty_remaining > 0;

CREATE TABLE stock_consumptions (
  tenant_id uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  doc_type  text NOT NULL CHECK (doc_type IN ('ISSUE', 'COUNT')),
  doc_id    uuid NOT NULL,
  layer_id  uuid,
  qty       numeric(20,4) NOT NULL CHECK (qty > 0),
  value     numeric(24,6) NOT NULL CHECK (value >= 0),
  FOREIGN KEY (tenant_id, layer_id) REFERENCES stock_layers(tenant_id, id)
);
CREATE INDEX stock_consumptions_doc ON stock_consumptions (doc_type, doc_id);

CREATE TABLE stock_receipts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  number          text NOT NULL,
  grn_id          uuid NOT NULL,
  po_line_no      integer NOT NULL,
  stock_item_id   uuid NOT NULL,
  warehouse_id    uuid NOT NULL,
  quantity        numeric(20,4) NOT NULL CHECK (quantity > 0),
  unit_cost       numeric(24,6) NOT NULL DEFAULT 0,
  amount          numeric(24,6) NOT NULL DEFAULT 0,
  currency        char(3) NOT NULL REFERENCES currencies(code),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, grn_id) REFERENCES grns(tenant_id, id),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, warehouse_id) REFERENCES warehouses(tenant_id, id)
);

CREATE TABLE stock_issues (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id    uuid NOT NULL,
  number             text NOT NULL,
  warehouse_id       uuid NOT NULL,
  stock_item_id      uuid NOT NULL,
  project_id         uuid NOT NULL,
  cost_code_id       uuid NOT NULL,
  expense_account_id uuid NOT NULL,
  quantity           numeric(20,4) NOT NULL CHECK (quantity > 0),
  issue_date         date NOT NULL,
  note               text,
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED', 'CANCELLED')),
  unit_cost          numeric(24,6),
  amount             numeric(24,6),
  currency           char(3) NOT NULL REFERENCES currencies(code),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  approved_by        text,
  approved_at        timestamptz,
  approved_txid      bigint,
  decision_reason    text,
  journal_id         uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, warehouse_id) REFERENCES warehouses(tenant_id, id),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, expense_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  CONSTRAINT stock_issue_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE stock_counts (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id     uuid NOT NULL,
  number              text NOT NULL,
  warehouse_id        uuid NOT NULL,
  stock_item_id       uuid NOT NULL,
  project_id          uuid,
  counted_qty         numeric(20,4) NOT NULL CHECK (counted_qty >= 0),
  system_qty          numeric(20,4) NOT NULL DEFAULT 0,
  difference          numeric(20,4) NOT NULL DEFAULT 0,
  variance_account_id uuid NOT NULL,
  count_date          date NOT NULL,
  note                text,
  status              text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED')),
  amount              numeric(24,6),
  currency            char(3) NOT NULL REFERENCES currencies(code),
  created_by          text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  approved_by         text,
  approved_at         timestamptz,
  approved_txid       bigint,
  decision_reason     text,
  journal_id          uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, warehouse_id) REFERENCES warehouses(tenant_id, id),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, variance_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  CONSTRAINT stock_count_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

-- ===========================================================================
-- Valuation engine (called only from the document triggers)
-- ===========================================================================
CREATE OR REPLACE FUNCTION stk_state_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  -- Depth 1 would be a direct statement by the tenant login (or a trigger of
  -- it); valuation state changes only inside a document trigger (depth >= 2).
  IF pg_trigger_depth() < 2 THEN
    RAISE EXCEPTION 'stock valuation state (%) is written only by stock documents', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END$$;
CREATE TRIGGER stock_balances_guard BEFORE INSERT OR UPDATE OR DELETE ON stock_balances FOR EACH ROW EXECUTE FUNCTION stk_state_guard();
CREATE TRIGGER stock_layers_guard BEFORE INSERT OR UPDATE OR DELETE ON stock_layers FOR EACH ROW EXECUTE FUNCTION stk_state_guard();
CREATE TRIGGER stock_consumptions_guard BEFORE INSERT OR UPDATE OR DELETE ON stock_consumptions FOR EACH ROW EXECUTE FUNCTION stk_state_guard();

-- Adds quantity and value to an item in a warehouse (FIFO: as a new layer).
CREATE OR REPLACE FUNCTION stk_receive(p_item uuid, p_wh uuid, p_qty numeric, p_value numeric, p_unit numeric, p_src text, p_src_id uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items;
BEGIN
  IF pg_trigger_depth() < 1 THEN
    RAISE EXCEPTION 'stock is received only by a stock document' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO it FROM stock_items WHERE id = p_item AND tenant_id = current_tenant();
  INSERT INTO stock_balances(stock_item_id, warehouse_id, qty, value) VALUES (p_item, p_wh, p_qty, p_value)
    ON CONFLICT (stock_item_id, warehouse_id) DO UPDATE SET qty = stock_balances.qty + EXCLUDED.qty, value = stock_balances.value + EXCLUDED.value;
  IF it.valuation_method = 'FIFO' THEN
    INSERT INTO stock_layers(stock_item_id, warehouse_id, source_type, source_id, qty_in, qty_remaining, unit_cost, value_in, value_remaining)
    VALUES (p_item, p_wh, p_src, p_src_id, p_qty, p_qty, p_unit, p_value, p_value);
  END IF;
END$$;

-- Removes quantity at cost and returns the cost: FIFO consumes the oldest
-- layers (a fully consumed layer gives its exact remaining value, so no
-- rounding residue stays behind); WAC uses the moving average (issuing the
-- whole balance gives its exact value). Negative stock is refused.
CREATE OR REPLACE FUNCTION stk_consume(p_item uuid, p_wh uuid, p_qty numeric, p_doc text, p_doc_id uuid) RETURNS numeric
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; b stock_balances; ccy char(3); need numeric := p_qty; take numeric; v numeric; cost numeric := 0; l stock_layers;
BEGIN
  IF pg_trigger_depth() < 1 THEN
    RAISE EXCEPTION 'stock is consumed only by a stock document' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT * INTO it FROM stock_items WHERE id = p_item AND tenant_id = current_tenant();
  SELECT functional_currency INTO ccy FROM legal_entities WHERE id = it.legal_entity_id;
  SELECT * INTO b FROM stock_balances WHERE stock_item_id = p_item AND warehouse_id = p_wh FOR UPDATE;
  IF b.stock_item_id IS NULL OR b.qty < p_qty THEN
    RAISE EXCEPTION 'insufficient stock of % in the warehouse: % on hand, % requested', it.code, COALESCE(b.qty, 0), p_qty USING ERRCODE = 'check_violation';
  END IF;
  IF it.valuation_method = 'FIFO' THEN
    FOR l IN SELECT * FROM stock_layers WHERE stock_item_id = p_item AND warehouse_id = p_wh AND qty_remaining > 0 ORDER BY seq FOR UPDATE LOOP
      EXIT WHEN need = 0;
      take := least(need, l.qty_remaining);
      v := CASE WHEN take = l.qty_remaining THEN l.value_remaining ELSE least(l.value_remaining, p2p_round(take * l.unit_cost, ccy)) END;
      UPDATE stock_layers SET qty_remaining = qty_remaining - take, value_remaining = value_remaining - v WHERE id = l.id;
      INSERT INTO stock_consumptions(doc_type, doc_id, layer_id, qty, value) VALUES (p_doc, p_doc_id, l.id, take, v);
      need := need - take;
      cost := cost + v;
    END LOOP;
    IF need > 0 THEN
      RAISE EXCEPTION 'stock layers of % do not cover the balance (integrity)', it.code USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    cost := CASE WHEN p_qty = b.qty THEN b.value ELSE p2p_round(p_qty * b.value / b.qty, ccy) END;
    INSERT INTO stock_consumptions(doc_type, doc_id, layer_id, qty, value) VALUES (p_doc, p_doc_id, NULL, p_qty, cost);
  END IF;
  UPDATE stock_balances SET qty = qty - p_qty, value = CASE WHEN qty - p_qty = 0 THEN 0 ELSE value - cost END
   WHERE stock_item_id = p_item AND warehouse_id = p_wh;
  IF b.qty - p_qty = 0 AND b.value <> cost THEN
    RAISE EXCEPTION 'issuing the whole balance of % must take its whole value (integrity)', it.code USING ERRCODE = 'check_violation';
  END IF;
  RETURN cost;
END$$;

-- ===========================================================================
-- Guards
-- ===========================================================================
CREATE OR REPLACE FUNCTION stk_creation_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; perm text;
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'stock_items' THEN act := 'stock.item.create'; typ := 'stock_item'; perm := 'stock.item.manage';
    WHEN 'warehouses' THEN act := 'warehouse.create'; typ := 'warehouse'; perm := 'warehouse.manage';
    WHEN 'stock_receipts' THEN act := 'stock.receipt.create'; typ := 'stock_receipt'; perm := 'stock.receive';
    WHEN 'stock_issues' THEN act := 'stock.issue.create'; typ := 'stock_issue'; perm := 'stock.issue';
    WHEN 'stock_counts' THEN act := 'stock.count.create'; typ := 'stock_count'; perm := 'stock.count';
    ELSE RAISE EXCEPTION 'stk_creation_attested: unexpected table %', TG_TABLE_NAME;
  END CASE;
  PERFORM approval_use(act, typ, NEW.id::text, NEW.created_by, ARRAY[perm], false, NULL, NULL);
  RETURN NULL;
END$$;

CREATE OR REPLACE FUNCTION stock_items_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE a accounts;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO a FROM accounts WHERE id = NEW.inventory_account_id AND tenant_id = current_tenant();
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'stock items are created PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF a.type IS DISTINCT FROM 'ASSET' OR NOT a.active OR p2p_is_control_account(a.id) THEN
      RAISE EXCEPTION 'the inventory account must be an active ASSET account that is not a bank, payables or receivables control account'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'PENDING' AND NEW.status = 'ACTIVE' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'stock item');
    PERFORM approval_use('stock.item.approve', 'stock_item', NEW.id::text, NEW.approved_by, ARRAY['stock.item.approve'], false, 'ACTIVE', NULL);
    NEW.approved_at := now();
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'illegal stock item change % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
END$$;
CREATE TRIGGER stock_items_guard BEFORE INSERT OR UPDATE ON stock_items FOR EACH ROW EXECUTE FUNCTION stock_items_guard();

CREATE OR REPLACE FUNCTION warehouses_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'warehouses are not changed' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'warehouses are created ACTIVE' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER warehouses_guard BEFORE INSERT OR UPDATE ON warehouses FOR EACH ROW EXECUTE FUNCTION warehouses_guard();

CREATE OR REPLACE FUNCTION stock_receipts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE g grns; o purchase_orders; pl po_lines; gl grn_lines; it stock_items; w warehouses; done_qty numeric; done_amt numeric; line_amt numeric;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'stock receipts are not changed; record a count to correct stock' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO g FROM grns WHERE id = NEW.grn_id AND tenant_id = current_tenant() FOR UPDATE;  -- serialises put-away of one receipt
  SELECT * INTO o FROM purchase_orders WHERE id = g.po_id;
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
  -- The put-away completing the line takes the exact remainder of what the
  -- goods receipt debited to inventory, so no rounding residue is left.
  NEW.amount := CASE WHEN done_qty + NEW.quantity = gl.qty_received THEN line_amt - done_amt ELSE p2p_round(NEW.quantity * pl.unit_price, o.currency) END;
  IF NEW.amount < 0 THEN
    RAISE EXCEPTION 'put-away value would be negative (integrity)' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM stk_receive(NEW.stock_item_id, NEW.warehouse_id, NEW.quantity, NEW.amount, pl.unit_price, 'RECEIPT', NEW.id);
  RETURN NEW;
END$$;
CREATE TRIGGER stock_receipts_guard BEFORE INSERT OR UPDATE OR DELETE ON stock_receipts FOR EACH ROW EXECUTE FUNCTION stock_receipts_guard();

CREATE OR REPLACE FUNCTION stk_assert_journal(p_journal uuid, p_doc text, p_id uuid, p_entity uuid, p_ccy char(3), p_date date) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE j journals; want text; got text;
BEGIN
  SELECT * INTO j FROM journals WHERE id = p_journal AND tenant_id = current_tenant();
  IF j.id IS NULL OR j.status <> 'DRAFT' OR j.source_type <> p_doc OR j.source_ref IS DISTINCT FROM p_id::text OR j.legal_entity_id <> p_entity
     OR j.functional_currency <> p_ccy OR (j.business_event_at AT TIME ZONE 'UTC')::date <> p_date THEN
    RAISE EXCEPTION 'journal % is not the DRAFT % journal of % (entity, currency, date)', p_journal, p_doc, p_id USING ERRCODE = 'check_violation';
  END IF;
  want := stk_expected_text(p_doc, p_id);
  got := p2p_lines_text(p_journal);
  IF want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'journal % lines do not equal the accounting of % % (expected %, got %)', p_journal, p_doc, p_id, want, got USING ERRCODE = 'check_violation';
  END IF;
END$$;

CREATE OR REPLACE FUNCTION stock_issues_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; w warehouses; cc cost_codes; a accounts; le legal_entities; cost numeric;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO w FROM warehouses WHERE id = NEW.warehouse_id AND tenant_id = current_tenant();
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    SELECT * INTO cc FROM cost_codes WHERE id = NEW.cost_code_id AND tenant_id = current_tenant();
    SELECT * INTO a FROM accounts WHERE id = NEW.expense_account_id AND tenant_id = current_tenant();
    SELECT * INTO le FROM legal_entities WHERE id = w.legal_entity_id;
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.amount IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'stock issues are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> w.legal_entity_id THEN
      RAISE EXCEPTION 'stock is issued for an ACTIVE item of the warehouse''s entity' USING ERRCODE = 'check_violation';
    END IF;
    IF (w.project_id IS NOT NULL AND w.project_id <> NEW.project_id) OR cc.project_id IS DISTINCT FROM NEW.project_id THEN
      RAISE EXCEPTION 'the issue''s project must own the cost code and, for a project warehouse, the warehouse' USING ERRCODE = 'check_violation';
    END IF;
    IF a.type IS DISTINCT FROM 'EXPENSE' OR NOT a.active OR p2p_is_control_account(a.id) THEN
      RAISE EXCEPTION 'stock is issued to an active EXPENSE account' USING ERRCODE = 'check_violation';
    END IF;
    NEW.legal_entity_id := w.legal_entity_id;
    NEW.currency := le.functional_currency;
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approved_txid', 'unit_cost', 'amount'], 'stock issue');
    PERFORM approval_use('stock.issue.approve', 'stock_issue', NEW.id::text, NEW.approved_by, ARRAY['stock.issue.approve'], false, 'APPROVED', NULL);
    cost := stk_consume(NEW.stock_item_id, NEW.warehouse_id, NEW.quantity, 'ISSUE', NEW.id);
    NEW.amount := cost;
    NEW.unit_cost := round(cost / NEW.quantity, 6);
    NEW.approved_at := now();
    NEW.approved_txid := txid_current();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'APPROVED' THEN
    -- The generated journal is attached once, in the approving transaction.
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['journal_id'], 'stock issue');
    IF OLD.journal_id IS NOT NULL OR OLD.approved_txid IS DISTINCT FROM txid_current() OR NEW.journal_id IS NULL THEN
      RAISE EXCEPTION 'the journal of a stock issue is attached once, by the approving transaction' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.amount > 0 THEN
      PERFORM stk_assert_journal(NEW.journal_id, 'STK_ISSUE', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.issue_date);
    END IF;
  ELSIF OLD.status = 'DRAFT' AND NEW.status IN ('REJECTED', 'CANCELLED') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'stock issue');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting or cancelling a stock issue requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'REJECTED' THEN
      PERFORM approval_use('stock.issue.reject', 'stock_issue', NEW.id::text, NULL, ARRAY['stock.issue.approve'], false, 'REJECTED', NULL);
    ELSE
      PERFORM approval_use('stock.issue.cancel', 'stock_issue', NEW.id::text, NEW.created_by, ARRAY['stock.issue'], false, 'CANCELLED', NULL);
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal stock issue transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER stock_issues_guard BEFORE INSERT OR UPDATE ON stock_issues FOR EACH ROW EXECUTE FUNCTION stock_issues_guard();

CREATE OR REPLACE FUNCTION stock_counts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; w warehouses; a accounts; le legal_entities; b stock_balances; unit numeric; v numeric;
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
      SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id;
      -- A surplus is valued at the current average cost, or the most recent
      -- receipt cost when nothing is on hand; with no cost basis it must come
      -- in through purchasing instead.
      IF COALESCE(b.qty, 0) > 0 THEN
        unit := b.value / b.qty;
      ELSE
        SELECT r.unit_cost INTO unit FROM stock_receipts r WHERE r.stock_item_id = NEW.stock_item_id AND r.warehouse_id = NEW.warehouse_id
         ORDER BY r.created_at DESC, r.id LIMIT 1;
      END IF;
      IF unit IS NULL THEN
        RAISE EXCEPTION 'no cost basis for a surplus of %: receive it through purchasing', it.code USING ERRCODE = 'check_violation';
      END IF;
      v := p2p_round(NEW.difference * unit, NEW.currency);
      PERFORM stk_receive(NEW.stock_item_id, NEW.warehouse_id, NEW.difference, v, round(unit, 6), 'COUNT', NEW.id);
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
CREATE TRIGGER stock_counts_guard BEFORE INSERT OR UPDATE ON stock_counts FOR EACH ROW EXECUTE FUNCTION stock_counts_guard();

-- An approved issue or count carries its journal at commit (when it has value).
CREATE OR REPLACE FUNCTION stk_journal_present() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st text; jid uuid; amt numeric;
BEGIN
  EXECUTE format('SELECT status, journal_id, amount FROM %I WHERE id = $1', TG_TABLE_NAME) INTO st, jid, amt USING NEW.id;
  IF st = 'APPROVED' AND amt > 0 AND jid IS NULL THEN
    RAISE EXCEPTION '% % was approved without its journal', TG_TABLE_NAME, NEW.id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER stock_issues_journal AFTER UPDATE ON stock_issues DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_journal_present();
CREATE CONSTRAINT TRIGGER stock_counts_journal AFTER UPDATE ON stock_counts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_journal_present();

CREATE CONSTRAINT TRIGGER stock_items_created_by AFTER INSERT ON stock_items DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();
CREATE CONSTRAINT TRIGGER warehouses_created_by AFTER INSERT ON warehouses DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();
CREATE CONSTRAINT TRIGGER stock_receipts_created_by AFTER INSERT ON stock_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();
CREATE CONSTRAINT TRIGGER stock_issues_created_by AFTER INSERT ON stock_issues DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();
CREATE CONSTRAINT TRIGGER stock_counts_created_by AFTER INSERT ON stock_counts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();

-- ===========================================================================
-- Expected accounting and journal binding for STK_* journals
-- ===========================================================================
CREATE OR REPLACE FUNCTION stk_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH e(account_id, side, amount, project_id, cost_code_id) AS (
    -- Issue: Dr project cost (cost code); Cr inventory.
    SELECT i.expense_account_id, 'DEBIT', i.amount, i.project_id, i.cost_code_id
      FROM stock_issues i WHERE p_doc = 'STK_ISSUE' AND i.id = p_id AND i.tenant_id = current_tenant() AND i.status = 'APPROVED'
    UNION ALL
    SELECT it.inventory_account_id, 'CREDIT', i.amount, i.project_id, NULL::uuid
      FROM stock_issues i JOIN stock_items it ON it.id = i.stock_item_id
     WHERE p_doc = 'STK_ISSUE' AND i.id = p_id AND i.tenant_id = current_tenant() AND i.status = 'APPROVED'
    UNION ALL
    -- Count: shortage Dr variance, Cr inventory; surplus the reverse.
    SELECT c.variance_account_id, CASE WHEN c.difference < 0 THEN 'DEBIT' ELSE 'CREDIT' END, c.amount, c.project_id, NULL::uuid
      FROM stock_counts c WHERE p_doc = 'STK_ADJUST' AND c.id = p_id AND c.tenant_id = current_tenant() AND c.status = 'APPROVED'
    UNION ALL
    SELECT it.inventory_account_id, CASE WHEN c.difference < 0 THEN 'CREDIT' ELSE 'DEBIT' END, c.amount, c.project_id, NULL::uuid
      FROM stock_counts c JOIN stock_items it ON it.id = c.stock_item_id
     WHERE p_doc = 'STK_ADJUST' AND c.id = p_id AND c.tenant_id = current_tenant() AND c.status = 'APPROVED'
  )
  SELECT account_id, side, amount, project_id, cost_code_id FROM e WHERE amount > 0
$$;

CREATE OR REPLACE FUNCTION stk_expected_text(p_doc text, p_id uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(string_agg(concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')),
                             ';' ORDER BY concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')) COLLATE "C"), '')
    FROM stk_expected_lines(p_doc, p_id)
$$;

CREATE OR REPLACE FUNCTION subledger_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT * FROM p2p_expected_lines(p_doc, p_id) WHERE p_doc LIKE 'P2P\_%'
  UNION ALL
  SELECT * FROM ar_expected_lines(p_doc, p_id) WHERE p_doc LIKE 'AR\_%'
  UNION ALL
  SELECT * FROM stk_expected_lines(p_doc, p_id) WHERE p_doc LIKE 'STK\_%'
$$;
CREATE OR REPLACE FUNCTION subledger_expected_text(p_doc text, p_id uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN p_doc LIKE 'P2P\_%' THEN p2p_expected_text(p_doc, p_id) WHEN p_doc LIKE 'AR\_%' THEN ar_expected_text(p_doc, p_id)
              WHEN p_doc LIKE 'STK\_%' THEN stk_expected_text(p_doc, p_id) ELSE '' END
$$;

-- Subledger journal protections now cover STK_* as well.
CREATE OR REPLACE FUNCTION journals_subledger_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.source_type ~ '^(P2P|AR|STK)_' AND TG_OP = 'UPDATE' AND NEW.status = 'CANCELLED' AND OLD.status <> 'CANCELLED' THEN
    RAISE EXCEPTION 'subledger journals are not cancelled; correct the source document' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION journal_lines_p2p_birth() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE j record; jid uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.journal_id ELSE NEW.journal_id END;
BEGIN
  SELECT source_type, created_txid INTO j FROM journals WHERE id = jid AND tenant_id = current_tenant();
  IF j.source_type ~ '^(P2P|AR|STK)_' AND j.created_txid IS DISTINCT FROM txid_current() THEN
    RAISE EXCEPTION 'lines of subledger journal % are written only by the transaction that generated it', jid USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END$$;

DROP TRIGGER journals_subledger_no_reversal ON journals;
CREATE TRIGGER journals_subledger_no_reversal BEFORE UPDATE OF status ON journals FOR EACH ROW
  WHEN (NEW.status = 'REVERSED' AND OLD.status <> 'REVERSED' AND NEW.source_type ~ '^(P2P|AR|STK)_')
  EXECUTE FUNCTION journals_subledger_no_reversal();

CREATE OR REPLACE FUNCTION journals_stk_binding() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE bound boolean;
BEGIN
  bound := CASE NEW.source_type
      WHEN 'STK_ISSUE' THEN EXISTS (SELECT 1 FROM stock_issues WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'STK_ADJUST' THEN EXISTS (SELECT 1 FROM stock_counts WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      ELSE false END;
  IF NOT bound THEN
    RAISE EXCEPTION 'journal % uses reserved source type % but no % document references it', NEW.id, NEW.source_type, NEW.source_type
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER journals_stk_binding AFTER INSERT ON journals DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.source_type LIKE 'STK\_%') EXECUTE FUNCTION journals_stk_binding();

CREATE OR REPLACE FUNCTION journals_stk_rebind() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE want text; got text;
BEGIN
  IF NEW.source_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'subledger journal % has no document reference', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  want := stk_expected_text(NEW.source_type, NEW.source_ref::uuid);
  got := p2p_lines_text(NEW.id);
  IF want IS NULL OR want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'subledger journal % no longer equals the accounting of % % (expected %, got %)', NEW.id, NEW.source_type, NEW.source_ref, want, got
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_stk_rebind BEFORE UPDATE OF status ON journals FOR EACH ROW
  WHEN (NEW.source_type LIKE 'STK\_%' AND NEW.status IN ('APPROVED', 'POSTED') AND OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION journals_stk_rebind();

-- ===========================================================================
-- Reports
-- ===========================================================================
-- Inventory to GL, per inventory account of the entity. Subledger figures
-- count only documents whose journals are POSTED: goods receipts on the
-- account, approved surpluses, issues and shortages. Two further checks:
-- what has been received but not yet put away, and that the running
-- balances equal the documents (and, for FIFO, the open layers).
CREATE OR REPLACE FUNCTION stock_gl_reconciliation(p_entity uuid)
RETURNS TABLE (check_name text, subledger numeric, gl numeric, difference numeric, unposted_documents bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE acc record; grn_posted numeric; moves numeric; g numeric; un bigint; putaway numeric; bal numeric; docs numeric; layers numeric;
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
    SELECT (SELECT count(*) FROM stock_issues s JOIN journals j ON j.id = s.journal_id JOIN stock_items i ON i.id = s.stock_item_id
             WHERE i.inventory_account_id = acc.id AND j.status <> 'POSTED')
         + (SELECT count(*) FROM stock_counts c JOIN journals j ON j.id = c.journal_id JOIN stock_items i ON i.id = c.stock_item_id
             WHERE i.inventory_account_id = acc.id AND j.status <> 'POSTED') INTO un;
    check_name := 'Inventory: ' || acc.code || ' ' || acc.name; subledger := grn_posted + moves; gl := g; difference := g - (grn_posted + moves);
    unposted_documents := un; RETURN NEXT;
    -- Received on the account but not yet put away into a warehouse.
    SELECT COALESCE(sum(r.amount), 0) INTO putaway FROM stock_receipts r JOIN grns gr ON gr.id = r.grn_id JOIN journals j ON j.id = gr.journal_id
      JOIN stock_items i ON i.id = r.stock_item_id WHERE i.inventory_account_id = acc.id AND j.status = 'POSTED';
    check_name := 'Received, not yet put away: ' || acc.code; subledger := grn_posted - putaway; gl := NULL; difference := NULL;
    unposted_documents := (SELECT count(*) FROM grns gr JOIN purchase_orders o ON o.id = gr.po_id JOIN grn_lines gl ON gl.grn_id = gr.id
                            JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
                           WHERE pl.account_id = acc.id AND gr.status = 'CONFIRMED'
                             AND gl.qty_received > COALESCE((SELECT sum(quantity) FROM stock_receipts r WHERE r.grn_id = gr.id AND r.po_line_no = gl.po_line_no), 0));
    RETURN NEXT;
    -- Integrity: running balances = documents (all approved, posted or not), and FIFO layers = balances.
    SELECT COALESCE(sum(b.value), 0) INTO bal FROM stock_balances b JOIN stock_items i ON i.id = b.stock_item_id WHERE i.inventory_account_id = acc.id;
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

CREATE OR REPLACE FUNCTION stock_on_hand(p_entity uuid)
RETURNS TABLE (stock_item_id uuid, item_code text, item_name text, unit text, valuation_method text, warehouse_id uuid, warehouse_code text,
               project_id uuid, qty numeric, value numeric, unit_cost numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT i.id, i.code, i.name, i.unit, i.valuation_method, w.id, w.code, w.project_id, b.qty, b.value,
         CASE WHEN b.qty > 0 THEN round(b.value / b.qty, 6) ELSE 0 END
    FROM stock_balances b JOIN stock_items i ON i.id = b.stock_item_id JOIN warehouses w ON w.id = b.warehouse_id
   WHERE i.tenant_id = current_tenant() AND i.legal_entity_id = p_entity
   ORDER BY i.code, w.code
$$;

-- ===========================================================================
-- Approval subject text for the stock documents (the 0018 body, with the
-- stock branches added; earlier branches unchanged).
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_subject_text(p_type text, p_id text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE t uuid := current_tenant(); j jsonb;
BEGIN
  IF p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN NULL;
  END IF;
  CASE p_type
  WHEN 'p2p_policy' THEN SELECT to_jsonb(x) INTO j FROM p2p_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier' THEN SELECT to_jsonb(x) INTO j FROM suppliers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', p2p_account_digest(x.account_number)) INTO j FROM supplier_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'company_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', p2p_account_digest(x.account_number)) INTO j FROM company_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'boq_version' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'items', (SELECT jsonb_agg(to_jsonb(i) ORDER BY i.item_no COLLATE "C") FROM boq_items i WHERE i.version_id = x.id))
      INTO j FROM boq_versions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'purchase_requisition' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM pr_lines l WHERE l.pr_id = x.id))
      INTO j FROM purchase_requisitions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'rfq' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'suppliers', (SELECT jsonb_agg(s.supplier_id ORDER BY s.supplier_id) FROM rfq_suppliers s WHERE s.rfq_id = x.id),
             'quotes', (SELECT jsonb_agg(jsonb_build_object('q', to_jsonb(q), 'lines',
                          (SELECT jsonb_agg(to_jsonb(ql) ORDER BY ql.pr_line_no) FROM rfq_quote_lines ql WHERE ql.quote_id = q.id)) ORDER BY q.id)
                          FROM rfq_quotes q WHERE q.rfq_id = x.id))
      INTO j FROM rfqs x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'rfq_quote' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.pr_line_no) FROM rfq_quote_lines l WHERE l.quote_id = x.id))
      INTO j FROM rfq_quotes x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'purchase_order' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM po_lines l WHERE l.po_id = x.id))
      INTO j FROM purchase_orders x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'grn' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id', 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.po_line_no) FROM grn_lines l WHERE l.grn_id = x.id))
      INTO j FROM grns x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_invoice' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id', 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.po_line_no) FROM invoice_lines l WHERE l.invoice_id = x.id))
      INTO j FROM supplier_invoices x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'payment_instruction' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'release_journal_id',
             'alloc', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.invoice_id) FROM payment_allocations a WHERE a.payment_id = x.id),
             'payee', (SELECT to_jsonb(b) || jsonb_build_object('account_number', p2p_account_digest(b.account_number)) FROM supplier_bank_accounts b WHERE b.id = x.supplier_bank_id))
      INTO j FROM payment_instructions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'bank_statement_line' THEN
    SELECT jsonb_build_object('l', to_jsonb(x) - 'journal_id', 's', (SELECT to_jsonb(s) FROM bank_statements s WHERE s.id = x.statement_id))
      INTO j FROM bank_statement_lines x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer' THEN SELECT to_jsonb(x) INTO j FROM customers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract_policy' THEN SELECT to_jsonb(x) INTO j FROM contract_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM contract_lines l WHERE l.contract_id = x.id))
      INTO j FROM contracts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'measurement' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.contract_line_no) FROM measurement_lines l WHERE l.measurement_id = x.id))
      INTO j FROM measurements x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'ipc' THEN SELECT to_jsonb(x) INTO j FROM ipcs x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer_invoice' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM customer_invoices x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'customer_receipt' THEN
    SELECT jsonb_build_object('h', to_jsonb(x) - 'journal_id',
             'alloc', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.line_no) FROM receipt_allocations a WHERE a.receipt_id = x.id),
             'line', (SELECT to_jsonb(l) - 'journal_id' FROM bank_statement_lines l WHERE l.id = x.statement_line_id))
      INTO j FROM customer_receipts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_item' THEN SELECT to_jsonb(x) INTO j FROM stock_items x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'warehouse' THEN SELECT to_jsonb(x) INTO j FROM warehouses x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_receipt' THEN SELECT to_jsonb(x) INTO j FROM stock_receipts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_issue' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM stock_issues x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_count' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM stock_counts x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- ===========================================================================
-- Row-level security and grants
-- ===========================================================================
DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['stock_items', 'warehouses', 'stock_balances', 'stock_layers', 'stock_consumptions', 'stock_receipts',
                             'stock_issues', 'stock_counts'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;
-- Valuation state: updated by the document triggers (stk_state_guard
-- refuses any direct statement).
GRANT UPDATE (qty, value) ON stock_balances TO serk_app;
GRANT UPDATE (qty_remaining, value_remaining) ON stock_layers TO serk_app;
GRANT UPDATE (status, approved_by) ON stock_items TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason, journal_id) ON stock_issues TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason, journal_id) ON stock_counts TO serk_app;

REVOKE ALL ON FUNCTION stk_receive(uuid, uuid, numeric, numeric, numeric, text, uuid), stk_consume(uuid, uuid, numeric, text, uuid),
  stk_expected_lines(text, uuid), stk_expected_text(text, uuid), stk_assert_journal(uuid, text, uuid, uuid, char, date),
  stock_gl_reconciliation(uuid), stock_on_hand(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stk_receive(uuid, uuid, numeric, numeric, numeric, text, uuid), stk_consume(uuid, uuid, numeric, text, uuid),
  stk_expected_lines(text, uuid), stk_expected_text(text, uuid), stk_assert_journal(uuid, text, uuid, uuid, char, date),
  stock_gl_reconciliation(uuid), stock_on_hand(uuid) TO serk_app;
