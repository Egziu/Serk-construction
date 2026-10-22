-- 0036: corrections from independent review 11 (migration 0035, the signer
-- markers, the offsite drill). docs/security/INDEPENDENT_REVIEW_11_2026-10-22.md.
--
--   R11-F1 (High, regression): serk_object_owner() (0035) was left with the
--          default "no PUBLIC execute", so serk_database_posture(), which the
--          API runs at start-up through the privilege-less health role,
--          failed with "permission denied": production would never start.
--   R11-F2 (Medium): serk_subject_project() returned NULL (no scope check)
--          for every subject type it did not list, including journals, WBS
--          versions, workflow instances and the entity-level documents the
--          kernel restricts to tenant-wide principals (payments, company
--          bank accounts, receipts, statements, policies, FX, periods). It
--          now fails closed: an unlisted type needs tenant-wide scope, and
--          only master data every project role acts on is explicitly
--          unscoped.
--   R11-F3 (Medium, conditional on TEMP): 48 functions had no pinned
--          search_path at all, so pg_temp shadowing still worked inside
--          trigger functions (e.g. the mandatory-workflow gate). Every
--          function in public now pins pg_catalog, public, pg_temp.

-- R11-F1 ------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION serk_object_owner() TO serk_monitor;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') THEN
    GRANT EXECUTE ON FUNCTION serk_object_owner() TO serk_health;
  END IF;
END$$;

-- R11-F3 ------------------------------------------------------------------------
DO $$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND NOT COALESCE(array_to_string(p.proconfig, ',') LIKE 'search_path=%', false)
              AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f.sig);
  END LOOP;
END$$;

-- R11-F2 ------------------------------------------------------------------------
-- Project of an attested subject, for the scope check in approval_authorize():
--   NULL  deliberately unscoped (master data every project role must act on:
--         suppliers, customers, stock items, supplier bank accounts as
--         entered by procurement; workflow definitions, which have no
--         project);
--   ''    tenant-wide scope required: entity-level documents, any subject
--         type not listed here (fail closed), and a project document without
--         a project;
--   <id>  the project the subject belongs to (the kernel's docProject, plus
--         journals, WBS versions and workflow instances).
CREATE OR REPLACE FUNCTION serk_subject_project(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_id uuid; r text;
BEGIN
  IF p_type IN ('supplier', 'customer', 'stock_item', 'supplier_bank_account', 'workflow_definition', 'workflow_definition_body') THEN
    RETURN NULL;
  END IF;
  IF p_id IS NULL OR p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN '';
  END IF;
  v_id := p_id::uuid;
  CASE p_type
  WHEN 'boq_version' THEN SELECT project_id::text INTO r FROM boq_versions WHERE boq_versions.id = v_id;
  WHEN 'purchase_requisition' THEN SELECT project_id::text INTO r FROM purchase_requisitions x WHERE x.id = v_id;
  WHEN 'purchase_order' THEN SELECT project_id::text INTO r FROM purchase_orders x WHERE x.id = v_id;
  WHEN 'rfq' THEN SELECT pr.project_id::text INTO r FROM rfqs q JOIN purchase_requisitions pr ON pr.id = q.pr_id WHERE q.id = v_id;
  WHEN 'rfq_quote' THEN SELECT pr.project_id::text INTO r FROM rfq_quotes x JOIN rfqs q ON q.id = x.rfq_id JOIN purchase_requisitions pr ON pr.id = q.pr_id WHERE x.id = v_id;
  WHEN 'grn' THEN SELECT o.project_id::text INTO r FROM grns g JOIN purchase_orders o ON o.id = g.po_id WHERE g.id = v_id;
  WHEN 'supplier_invoice' THEN SELECT o.project_id::text INTO r FROM supplier_invoices x JOIN purchase_orders o ON o.id = x.po_id WHERE x.id = v_id;
  WHEN 'contract' THEN SELECT project_id::text INTO r FROM contracts x WHERE x.id = v_id;
  WHEN 'measurement' THEN SELECT c.project_id::text INTO r FROM measurements m JOIN contracts c ON c.id = m.contract_id WHERE m.id = v_id;
  WHEN 'ipc' THEN SELECT c.project_id::text INTO r FROM ipcs x JOIN contracts c ON c.id = x.contract_id WHERE x.id = v_id;
  WHEN 'customer_invoice' THEN SELECT project_id::text INTO r FROM customer_invoices x WHERE x.id = v_id;
  WHEN 'customer_credit_note' THEN SELECT project_id::text INTO r FROM customer_credit_notes x WHERE x.id = v_id;
  WHEN 'retention_release' THEN SELECT project_id::text INTO r FROM retention_releases x WHERE x.id = v_id;
  WHEN 'contract_variation' THEN SELECT c.project_id::text INTO r FROM contract_variations v JOIN contracts c ON c.id = v.contract_id WHERE v.id = v_id;
  WHEN 'schedule_version' THEN SELECT project_id::text INTO r FROM schedule_versions x WHERE x.id = v_id;
  WHEN 'schedule_progress' THEN SELECT project_id::text INTO r FROM schedule_progress x WHERE x.id = v_id;
  WHEN 'warehouse' THEN SELECT COALESCE(project_id::text, '') INTO r FROM warehouses x WHERE x.id = v_id;
  WHEN 'stock_receipt' THEN SELECT COALESCE(w.project_id::text, '') INTO r FROM stock_receipts x JOIN warehouses w ON w.id = x.warehouse_id WHERE x.id = v_id;
  WHEN 'stock_issue' THEN SELECT project_id::text INTO r FROM stock_issues x WHERE x.id = v_id;
  WHEN 'stock_count' THEN SELECT COALESCE(project_id::text, '') INTO r FROM stock_counts x WHERE x.id = v_id;
  WHEN 'stock_transfer' THEN SELECT COALESCE(w.project_id::text, '') INTO r FROM stock_transfers x JOIN warehouses w ON w.id = x.from_warehouse_id WHERE x.id = v_id;
  WHEN 'journal' THEN SELECT project_id::text INTO r FROM journals x WHERE x.id = v_id;
  WHEN 'wbs_version' THEN SELECT project_id::text INTO r FROM wbs_versions x WHERE x.id = v_id;
  WHEN 'workflow_instance' THEN SELECT NULLIF(facts->>'project_id', '') INTO r FROM workflow_instances x WHERE x.id = v_id;
  ELSE RETURN '';
  END CASE;
  RETURN COALESCE(r, '');
END$$;
REVOKE ALL ON FUNCTION serk_subject_project(text, text) FROM PUBLIC;
