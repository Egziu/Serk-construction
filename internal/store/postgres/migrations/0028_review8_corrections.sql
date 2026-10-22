-- 0028: corrections from independent review 8 (migrations 0022-0025).
-- docs/security/INDEPENDENT_REVIEW_8_2026-10-22.md.
--
--   R8-F1/F4  credit notes and retention releases: dated today or earlier, in
--             an OPEN fiscal period, re-checked at approval (as stock
--             documents since R7-F3).
--   R8-F2/F7  serk_database_posture(): only tenant logins (LOGIN, not
--             superuser, members of serk_app) are examined; it also reports
--             CREATE on any schema and EXECUTE on any advisory-lock function.
--   R8-F3     budget: an inventory purchase line commits budget only for what
--             has not been put away into stock; stock is an asset until it is
--             issued, and the issue's cost code bears it (no netting by
--             amount, so no double or missing count across codes/projects).
--   R8-F8     a purchase-order line on a stock inventory account must name its
--             stock item before anything is put away from it; procurement may
--             designate it later (once, attested, a human decision), never the
--             storekeeper.
--   R8-I1     the surplus cost basis is the item's most recent receipt cost
--             (any warehouse), not an older receipt of the counting warehouse.
--   R8-F6/I2  (kernel) transfer approval needs both warehouses in scope; only
--             the preparer or an approver cancels a draft credit or release.
--   R8-F5     accepted: VAT is computed per credit note, as on any tax
--             document; ten small credits may round to a different total than
--             one large one (ADR 0011 addendum).

-- R8-F1/F4 ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ar_document_date() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE d date := COALESCE(to_jsonb(NEW)->>'credit_date', to_jsonb(NEW)->>'release_date')::date;
BEGIN
  IF TG_OP = 'INSERT' AND d > current_date THEN
    RAISE EXCEPTION 'the document is dated today or earlier (%)', d USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' OR (NEW.status = 'APPROVED' AND OLD.status IS DISTINCT FROM 'APPROVED') THEN
    IF NOT EXISTS (SELECT 1 FROM fiscal_periods fp WHERE fp.tenant_id = current_tenant() AND fp.legal_entity_id = NEW.legal_entity_id
                     AND d BETWEEN fp.starts_on AND fp.ends_on AND fp.status = 'OPEN') THEN
      RAISE EXCEPTION 'document date % is not in an open fiscal period of the entity', d USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER customer_credit_notes_xdate BEFORE INSERT OR UPDATE ON customer_credit_notes FOR EACH ROW EXECUTE FUNCTION ar_document_date();
CREATE TRIGGER retention_releases_xdate BEFORE INSERT OR UPDATE ON retention_releases FOR EACH ROW EXECUTE FUNCTION ar_document_date();

-- R8-F2/F7 ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  WITH tenant_logins AS (
    SELECT r.oid, r.rolname FROM pg_roles r
     WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid, 'serk_app', 'MEMBER'))
  SELECT 'TEMP is granted on the database to tenant login ' || t.rolname
    FROM tenant_logins t WHERE has_database_privilege(t.oid, current_database(), 'TEMP')
  UNION ALL
  SELECT 'tenant login ' || t.rolname || ' may CREATE in schema ' || n.nspname
    FROM tenant_logins t CROSS JOIN pg_namespace n
   WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND has_schema_privilege(t.oid, n.oid, 'CREATE')
  UNION ALL
  SELECT DISTINCT 'advisory-lock function ' || p.proname || ' is executable by tenant logins'
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege('serk_app', p.oid, 'EXECUTE')
$$;

-- R8-F3 --------------------------------------------------------------------------
-- Put-away value of a purchase-order line (all its goods receipts).
CREATE OR REPLACE FUNCTION p2p_put_away_value(p_po uuid, p_line integer) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(r.amount), 0) FROM stock_receipts r JOIN grns g ON g.id = r.grn_id
   WHERE g.po_id = p_po AND r.po_line_no = p_line AND r.tenant_id = current_tenant()
$$;

CREATE OR REPLACE FUNCTION p2p_cost_position(p_cost_code uuid, p_exclude_pr uuid, p_exclude_po uuid,
  OUT budget numeric, OUT committed numeric, OUT reserved numeric, OUT actual_other numeric, OUT available numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  SELECT COALESCE(sum(i.amount), 0) INTO budget
    FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
   WHERE i.tenant_id = current_tenant() AND i.cost_code_id = p_cost_code AND v.status = 'APPROVED';
  -- Commitment of a line: the order, or what was received if more. An
  -- inventory line commits only what has not yet been put away: stock is an
  -- asset until it is issued, and the issue's cost code bears it as actual.
  SELECT COALESCE(sum(CASE WHEN EXISTS (SELECT 1 FROM stock_items si WHERE si.inventory_account_id = l.account_id)
                           THEN greatest(0, greatest(l.amount, p2p_round(p2p_received_qty(l.po_id, l.line_no) * l.unit_price, o.currency))
                                            - p2p_put_away_value(l.po_id, l.line_no))
                           ELSE greatest(l.amount, p2p_round(p2p_received_qty(l.po_id, l.line_no) * l.unit_price, o.currency)) END), 0) INTO committed
    FROM po_lines l JOIN purchase_orders o ON o.id = l.po_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND o.status IN ('APPROVED', 'CLOSED')
     AND o.id IS DISTINCT FROM p_exclude_po;
  SELECT COALESCE(sum(l.est_amount), 0) INTO reserved
    FROM pr_lines l JOIN purchase_requisitions r ON r.id = l.pr_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND r.status = 'APPROVED'
     AND r.id IS DISTINCT FROM p_exclude_pr
     AND NOT EXISTS (SELECT 1 FROM rfqs q JOIN purchase_orders o ON o.rfq_id = q.id
                      WHERE q.pr_id = r.id AND o.status IN ('APPROVED', 'CLOSED'));
  -- Receipt journals are inside the commitment above; stock issues and count
  -- variances are actual cost of the code they are charged to.
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO actual_other
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status IN ('POSTED', 'REVERSED')
     AND j.source_type <> 'P2P_GRN';
  available := budget - committed - reserved - actual_other;
END$$;

-- R8-F8 --------------------------------------------------------------------------
-- The 0024 function: a line may also be designated later, once, by an
-- attested procurement decision (po.line.designate), while nothing has been
-- put away from it.
CREATE OR REPLACE FUNCTION po_lines_stock_item() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.stock_item_id IS NOT DISTINCT FROM OLD.stock_item_id THEN
      RETURN NEW;
    END IF;
    IF OLD.stock_item_id IS NOT NULL OR NEW.stock_item_id IS NULL THEN
      RAISE EXCEPTION 'the stock item of a purchase order line is set once' USING ERRCODE = 'check_violation';
    END IF;
    IF p2p_put_away_value(NEW.po_id, NEW.line_no) > 0 OR EXISTS (
         SELECT 1 FROM stock_receipts r JOIN grns g ON g.id = r.grn_id WHERE g.po_id = NEW.po_id AND r.po_line_no = NEW.line_no) THEN
      RAISE EXCEPTION 'purchase order line % already has stock put away', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('po.line.designate', 'purchase_order', NEW.po_id::text, NULL, ARRAY['po.manage'], false, 'DESIGNATE', NULL);
  END IF;
  IF NEW.stock_item_id IS NOT NULL THEN
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> NEW.legal_entity_id OR it.inventory_account_id <> NEW.account_id
       OR lower(btrim(it.unit)) <> lower(btrim(NEW.unit)) THEN
      RAISE EXCEPTION 'purchase order line %: the stock item must be ACTIVE, of the entity, in the line''s unit, with the line''s account as its inventory account',
        NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
GRANT UPDATE (stock_item_id) ON po_lines TO serk_app;

-- The 0024 put-away guard; an undesignated line is refused.
CREATE OR REPLACE FUNCTION stock_receipts_designated() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE pl po_lines;
BEGIN
  SELECT l.* INTO pl FROM po_lines l JOIN grns g ON g.po_id = l.po_id WHERE g.id = NEW.grn_id AND l.line_no = NEW.po_line_no AND g.tenant_id = current_tenant();
  IF pl.stock_item_id IS NULL THEN
    RAISE EXCEPTION 'purchase order line % does not name its stock item: procurement designates it before put-away', NEW.po_line_no
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
-- Named to fire before stock_receipts_guard (which values and receives the stock).
CREATE TRIGGER stock_receipts_adesignated BEFORE INSERT ON stock_receipts FOR EACH ROW EXECUTE FUNCTION stock_receipts_designated();

-- R8-I1 ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION stk_last_receipt_cost(p_item uuid, p_wh uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT r.unit_cost FROM stock_receipts r
   WHERE r.stock_item_id = p_item AND r.tenant_id = current_tenant()
   ORDER BY r.created_at DESC, r.id LIMIT 1
$$;

REVOKE ALL ON FUNCTION ar_document_date(), p2p_put_away_value(uuid, integer), stock_receipts_designated() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION p2p_put_away_value(uuid, integer) TO serk_app;
