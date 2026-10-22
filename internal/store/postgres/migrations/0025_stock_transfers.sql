-- 0025: stock transfers between warehouses (JC-TRANSFER, ADR 0012 addendum).
--
-- Before this, moving stock meant an issue (expensing it to a project) and a
-- new receipt, which misstates value. A transfer moves quantity and its cost
-- from one warehouse to another of the same entity:
--
--   storekeeper requests a DRAFT transfer -> an inventory controller (a
--   different person, a human) approves it -> the database consumes the
--   quantity at cost from the source (FIFO layers or the moving average) and
--   receives it at the destination at exactly that cost. FIFO layers keep
--   their unit cost and order (one destination layer per consumed layer).
--
-- No journal: the item, and so its inventory account, is the same on both
-- sides. Stock value, the GL and project cost are unchanged; only where the
-- stock is changes. Dates follow the R7-F3 rule (today or earlier, in an OPEN
-- fiscal period, re-checked at approval).

ALTER TABLE stock_layers DROP CONSTRAINT stock_layers_source_type_check;
ALTER TABLE stock_layers ADD CONSTRAINT stock_layers_source_type_check CHECK (source_type IN ('RECEIPT', 'COUNT', 'TRANSFER'));
ALTER TABLE stock_consumptions DROP CONSTRAINT stock_consumptions_doc_type_check;
ALTER TABLE stock_consumptions ADD CONSTRAINT stock_consumptions_doc_type_check CHECK (doc_type IN ('ISSUE', 'COUNT', 'TRANSFER'));

CREATE TABLE stock_transfers (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id   uuid NOT NULL,
  number            text NOT NULL,
  stock_item_id     uuid NOT NULL,
  from_warehouse_id uuid NOT NULL,
  to_warehouse_id   uuid NOT NULL,
  quantity          numeric(20,4) NOT NULL CHECK (quantity > 0),
  transfer_date     date NOT NULL,
  note              text,
  status            text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED', 'CANCELLED')),
  amount            numeric(24,6),
  currency          char(3) NOT NULL REFERENCES currencies(code),
  created_by        text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  approved_by       text,
  approved_at       timestamptz,
  decision_reason   text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, stock_item_id) REFERENCES stock_items(tenant_id, id),
  FOREIGN KEY (tenant_id, from_warehouse_id) REFERENCES warehouses(tenant_id, id),
  FOREIGN KEY (tenant_id, to_warehouse_id) REFERENCES warehouses(tenant_id, id),
  CONSTRAINT stock_transfer_two_places CHECK (from_warehouse_id <> to_warehouse_id),
  CONSTRAINT stock_transfer_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE OR REPLACE FUNCTION stock_transfers_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; wf warehouses; wt warehouses; le legal_entities; cost numeric; c record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    SELECT * INTO wf FROM warehouses WHERE id = NEW.from_warehouse_id AND tenant_id = current_tenant();
    SELECT * INTO wt FROM warehouses WHERE id = NEW.to_warehouse_id AND tenant_id = current_tenant();
    SELECT * INTO le FROM legal_entities WHERE id = wf.legal_entity_id;
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.amount IS NOT NULL OR NEW.decision_reason IS NOT NULL THEN
      RAISE EXCEPTION 'stock transfers are requested DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF it.status IS DISTINCT FROM 'ACTIVE' OR wf.id IS NULL OR wt.id IS NULL
       OR it.legal_entity_id <> wf.legal_entity_id OR wt.legal_entity_id <> wf.legal_entity_id THEN
      RAISE EXCEPTION 'a transfer moves an ACTIVE item between two warehouses of its entity' USING ERRCODE = 'check_violation';
    END IF;
    NEW.legal_entity_id := wf.legal_entity_id;
    NEW.currency := le.functional_currency;
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'amount'], 'stock transfer');
    PERFORM approval_use('stock.transfer.approve', 'stock_transfer', NEW.id::text, NEW.approved_by, ARRAY['stock.transfer.approve'], false, 'APPROVED', NULL);
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id;
    cost := stk_consume(NEW.stock_item_id, NEW.from_warehouse_id, NEW.quantity, 'TRANSFER', NEW.id);
    IF it.valuation_method = 'FIFO' THEN
      -- One destination layer per consumed layer, at its unit cost, in order.
      FOR c IN SELECT sc.qty, sc.value, l.unit_cost FROM stock_consumptions sc JOIN stock_layers l ON l.id = sc.layer_id
                WHERE sc.doc_type = 'TRANSFER' AND sc.doc_id = NEW.id ORDER BY l.seq LOOP
        PERFORM stk_receive(NEW.stock_item_id, NEW.to_warehouse_id, c.qty, c.value, c.unit_cost, 'TRANSFER', NEW.id);
      END LOOP;
    ELSE
      PERFORM stk_receive(NEW.stock_item_id, NEW.to_warehouse_id, NEW.quantity, cost, round(cost / NEW.quantity, 6), 'TRANSFER', NEW.id);
    END IF;
    NEW.amount := cost;
    NEW.approved_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status IN ('REJECTED', 'CANCELLED') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'stock transfer');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting or cancelling a stock transfer requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'REJECTED' THEN
      PERFORM approval_use('stock.transfer.reject', 'stock_transfer', NEW.id::text, NULL, ARRAY['stock.transfer.approve'], false, 'REJECTED', NULL);
    ELSE
      PERFORM approval_use('stock.transfer.cancel', 'stock_transfer', NEW.id::text, NEW.created_by, ARRAY['stock.transfer'], false, 'CANCELLED', NULL);
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal stock transfer transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER stock_transfers_guard BEFORE INSERT OR UPDATE ON stock_transfers FOR EACH ROW EXECUTE FUNCTION stock_transfers_guard();

-- Dates (the 0024 function, now also reading transfer_date).
CREATE OR REPLACE FUNCTION stk_document_date() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE d date := COALESCE(to_jsonb(NEW)->>'issue_date', to_jsonb(NEW)->>'count_date', to_jsonb(NEW)->>'transfer_date')::date;
BEGIN
  IF TG_OP = 'INSERT' AND d > current_date THEN
    RAISE EXCEPTION 'a stock document is not dated in the future (%)', d USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' OR (NEW.status = 'APPROVED' AND OLD.status IS DISTINCT FROM 'APPROVED') THEN
    IF NOT EXISTS (SELECT 1 FROM fiscal_periods fp WHERE fp.tenant_id = current_tenant() AND fp.legal_entity_id = NEW.legal_entity_id
                     AND d BETWEEN fp.starts_on AND fp.ends_on AND fp.status = 'OPEN') THEN
      RAISE EXCEPTION 'stock document date % is not in an open fiscal period of the entity', d USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER stock_transfers_xdate BEFORE INSERT OR UPDATE ON stock_transfers FOR EACH ROW EXECUTE FUNCTION stk_document_date();

-- Creation attestation (the 0021 function with the transfer branch).
CREATE OR REPLACE FUNCTION stk_creation_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; perm text;
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'stock_items' THEN act := 'stock.item.create'; typ := 'stock_item'; perm := 'stock.item.manage';
    WHEN 'warehouses' THEN act := 'warehouse.create'; typ := 'warehouse'; perm := 'warehouse.manage';
    WHEN 'stock_receipts' THEN act := 'stock.receipt.create'; typ := 'stock_receipt'; perm := 'stock.receive';
    WHEN 'stock_issues' THEN act := 'stock.issue.create'; typ := 'stock_issue'; perm := 'stock.issue';
    WHEN 'stock_counts' THEN act := 'stock.count.create'; typ := 'stock_count'; perm := 'stock.count';
    WHEN 'stock_transfers' THEN act := 'stock.transfer.create'; typ := 'stock_transfer'; perm := 'stock.transfer';
    ELSE RAISE EXCEPTION 'stk_creation_attested: unexpected table %', TG_TABLE_NAME;
  END CASE;
  PERFORM approval_use(act, typ, NEW.id::text, NEW.created_by, ARRAY[perm], false, NULL, NULL);
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER stock_transfers_created_by AFTER INSERT ON stock_transfers DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION stk_creation_attested();

ALTER TABLE stock_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE stock_transfers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON stock_transfers USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
REVOKE ALL ON stock_transfers FROM PUBLIC;
GRANT SELECT, INSERT ON stock_transfers TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON stock_transfers TO serk_app;

-- Approval subject text (the 0023 body with the transfer branch).
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
  WHEN 'customer_credit_note' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM customer_credit_notes x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'retention_release' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM retention_releases x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'stock_transfer' THEN SELECT to_jsonb(x) INTO j FROM stock_transfers x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;
