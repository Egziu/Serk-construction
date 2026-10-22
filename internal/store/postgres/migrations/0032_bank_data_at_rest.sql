-- 0032: bank account numbers encrypted at rest (R-BANK-AT-REST).
--
-- Account numbers are now stored only as ciphertext (AES-256-GCM, keyed by
-- the API's SERK_BANK_DATA_KEY, which the database never holds), beside a
-- keyed digest (p2p_account_digest, under the tenant's owner-only approval
-- key, as since 0017) for uniqueness and approval hashes, and the last four
-- characters for display. A leaked tenant credential, a database export or
-- a backup therefore yields no account numbers. The plaintext column stays,
-- nullable, only so that pre-0032 rows can be converted by
-- serk-migrate encrypt-bank-accounts; new rows may not set it, and the
-- posture check reports any plaintext still present (production refuses to
-- start). Reveal (MFA, audited) decrypts in the API.

ALTER TABLE supplier_bank_accounts
  ADD COLUMN account_number_enc bytea,
  ADD COLUMN account_digest text,
  ADD COLUMN account_last4 text CHECK (account_last4 ~ '^[A-Z0-9]{1,4}$'),
  ALTER COLUMN account_number DROP NOT NULL;
ALTER TABLE supplier_bank_accounts DROP CONSTRAINT supplier_bank_accounts_account_number_check;
ALTER TABLE supplier_bank_accounts ADD CONSTRAINT supplier_bank_accounts_account_number_check
  CHECK (account_number IS NULL OR account_number ~ '^[A-Z0-9]{6,34}$');
ALTER TABLE supplier_bank_accounts ADD CONSTRAINT supplier_bank_accounts_number_form
  CHECK ((account_number IS NOT NULL) <> (account_number_enc IS NOT NULL AND account_digest IS NOT NULL AND account_last4 IS NOT NULL));

ALTER TABLE company_bank_accounts
  ADD COLUMN account_number_enc bytea,
  ADD COLUMN account_digest text,
  ADD COLUMN account_last4 text CHECK (account_last4 ~ '^[A-Z0-9]{1,4}$'),
  ALTER COLUMN account_number DROP NOT NULL;
ALTER TABLE company_bank_accounts DROP CONSTRAINT company_bank_accounts_account_number_check;
ALTER TABLE company_bank_accounts ADD CONSTRAINT company_bank_accounts_account_number_check
  CHECK (account_number IS NULL OR account_number ~ '^[A-Z0-9]{6,34}$');
ALTER TABLE company_bank_accounts ADD CONSTRAINT company_bank_accounts_number_form
  CHECK ((account_number IS NOT NULL) <> (account_number_enc IS NOT NULL AND account_digest IS NOT NULL AND account_last4 IS NOT NULL));
-- Uniqueness moves to the keyed digest (deterministic per tenant).
CREATE UNIQUE INDEX company_bank_accounts_tenant_digest ON company_bank_accounts (tenant_id, account_digest) WHERE account_digest IS NOT NULL;

-- New rows carry ciphertext only; the digest is the keyed digest the
-- database itself computes (the API supplies the plaintext to
-- p2p_account_digest in the same transaction and stores nothing else).
CREATE OR REPLACE FUNCTION bank_accounts_encrypted() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.account_number IS NOT NULL THEN
    RAISE EXCEPTION 'bank account numbers are stored encrypted (0032): the plaintext column is not written' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.account_digest IS NOT NULL AND NEW.account_digest !~ '^hmac:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'malformed account digest' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.account_number_enc IS DISTINCT FROM OLD.account_number_enc OR NEW.account_digest IS DISTINCT FROM OLD.account_digest
                           OR NEW.account_last4 IS DISTINCT FROM OLD.account_last4) AND OLD.account_number IS NULL THEN
    RAISE EXCEPTION 'encrypted bank details never change; revoke the account and add a new one' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
-- Named to run before the status guards.
CREATE TRIGGER supplier_bank_accounts_aencrypted BEFORE INSERT OR UPDATE ON supplier_bank_accounts FOR EACH ROW EXECUTE FUNCTION bank_accounts_encrypted();
CREATE TRIGGER company_bank_accounts_aencrypted BEFORE INSERT OR UPDATE ON company_bank_accounts FOR EACH ROW EXECUTE FUNCTION bank_accounts_encrypted();

-- Bank snapshot and approval subject text use the stored digest.
CREATE OR REPLACE FUNCTION p2p_bank_snapshot(p_bank uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT encode(sha256(convert_to(concat_ws('|', b.id, b.supplier_id, b.bank_name, b.account_name, b.account_digest, b.currency,
                                            b.status, b.approved_by), 'UTF8')), 'hex')
    FROM supplier_bank_accounts b WHERE b.id = p_bank AND b.tenant_id = current_tenant()
$$;

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
  WHEN 'supplier_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', x.account_digest, 'account_number_enc', NULL) INTO j FROM supplier_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'company_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', x.account_digest, 'account_number_enc', NULL) INTO j FROM company_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
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
             'payee', (SELECT to_jsonb(b) || jsonb_build_object('account_number', b.account_digest, 'account_number_enc', NULL) FROM supplier_bank_accounts b WHERE b.id = x.supplier_bank_id))
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
  WHEN 'schedule_version' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'activities', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.code COLLATE "C") FROM schedule_activities a WHERE a.version_id = x.id),
             'links', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.pred_code COLLATE "C", l.succ_code COLLATE "C") FROM schedule_links l WHERE l.version_id = x.id))
      INTO j FROM schedule_versions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'schedule_progress' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.activity_code COLLATE "C") FROM schedule_progress_lines l WHERE l.progress_id = x.id))
      INTO j FROM schedule_progress x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract_variation' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM variation_lines l WHERE l.variation_id = x.id))
      INTO j FROM contract_variations x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;
-- Owner-only digest for the conversion of pre-0032 rows (serk-migrate runs
-- as the schema owner, which has no tenant identity). Not granted to anyone.
CREATE OR REPLACE FUNCTION p2p_account_digest_for(p_tenant uuid, p_number text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE k bytea;
BEGIN
  SELECT key INTO k FROM approval_keys WHERE tenant_id = p_tenant ORDER BY created_at, key_id LIMIT 1;
  IF k IS NULL THEN
    RAISE EXCEPTION 'no approval key for tenant %', p_tenant USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN 'hmac:' || encode(hmac(convert_to('bank-account|' || p_number, 'UTF8'), k, 'sha256'), 'hex');
END$$;
REVOKE ALL ON FUNCTION p2p_account_digest_for(uuid, text) FROM PUBLIC;

-- Plaintext still present (pre-0032 rows not yet converted): reported by
-- the posture check, which production refuses to start on.
CREATE OR REPLACE FUNCTION serk_bank_plaintext_rows() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT (SELECT count(*) FROM supplier_bank_accounts WHERE account_number IS NOT NULL)
       + (SELECT count(*) FROM company_bank_accounts WHERE account_number IS NOT NULL)
$$;
REVOKE ALL ON FUNCTION serk_bank_plaintext_rows() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION serk_bank_plaintext_rows() TO serk_monitor;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') THEN
    GRANT EXECUTE ON FUNCTION serk_bank_plaintext_rows() TO serk_health;
  END IF;
END$$;

CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
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
  SELECT 'advisory-lock function ' || p.proname || ' is executable by tenant login ' || t.rolname
    FROM tenant_logins t CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege(t.oid, p.oid, 'EXECUTE')
  UNION ALL
  SELECT DISTINCT 'advisory-lock function ' || p.proname || ' is executable by serk_app'
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege('serk_app', p.oid, 'EXECUTE')
  UNION ALL
  SELECT 'bank account numbers stored in plaintext: ' || n || ' row(s); run serk-migrate encrypt-bank-accounts'
    FROM (SELECT serk_bank_plaintext_rows() AS n) x WHERE n > 0
  UNION ALL
  -- Query parameters (account numbers travel as parameters) must not be
  -- logged in full.
  SELECT 'log_parameter_max_length is ' || current_setting('log_parameter_max_length') || ' (set 0 so bound parameters are never logged)'
   WHERE current_setting('log_parameter_max_length') NOT IN ('0')
$$;
REVOKE ALL ON FUNCTION bank_accounts_encrypted() FROM PUBLIC;
