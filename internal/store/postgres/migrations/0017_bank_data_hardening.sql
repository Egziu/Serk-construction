-- 0017: bank data hardening (independent review 5 of the IA-040-01 fix, F4).
--
-- Approval subject hashes and the payee fingerprint (payment_instructions.
-- bank_snapshot) were plain SHA-256 over rows that include the full account
-- number, so anyone holding an export of those tables plus a masked number
-- could confirm a guessed number offline. Both now use a keyed digest of the
-- number: HMAC-SHA256 under the tenant's FIRST approval key (owner-only
-- table; the first key is kept when keys rotate, so stored fingerprints stay
-- stable). The tenant runtime login can still read account numbers directly
-- (R-BANK-AT-REST); this closes the export/backup oracle, not that.

CREATE OR REPLACE FUNCTION p2p_account_digest(p_number text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE k bytea;
BEGIN
  IF p_number IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT key INTO k FROM approval_keys WHERE tenant_id = current_tenant() ORDER BY created_at, key_id LIMIT 1;
  IF k IS NULL THEN
    RAISE EXCEPTION 'no approval key for this tenant' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN 'hmac:' || encode(hmac(convert_to('bank-account|' || p_number, 'UTF8'), k, 'sha256'), 'hex');
END$$;
REVOKE ALL ON FUNCTION p2p_account_digest(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION p2p_account_digest(text) TO serk_app;

CREATE OR REPLACE FUNCTION p2p_bank_snapshot(p_bank uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT encode(sha256(convert_to(concat_ws('|', b.id, b.supplier_id, b.bank_name, b.account_name, p2p_account_digest(b.account_number), b.currency,
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
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- Re-fingerprint live payments (the payee check compares the stored value
-- with p2p_bank_snapshot at every step). Done as the owner, per tenant, with
-- the guard suspended for this one maintenance update only.
ALTER TABLE payment_instructions DISABLE TRIGGER payment_instructions_guard;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT p.id, p.tenant_id, b.id AS bank, b.supplier_id, b.bank_name, b.account_name, b.account_number, b.currency, b.status, b.approved_by,
                  (SELECT key FROM approval_keys k WHERE k.tenant_id = p.tenant_id ORDER BY created_at, key_id LIMIT 1) AS k
             FROM payment_instructions p JOIN supplier_bank_accounts b ON b.id = p.supplier_bank_id
            WHERE p.status IN ('DRAFT', 'SUBMITTED', 'PARTIALLY_APPROVED', 'APPROVED') LOOP
    IF r.k IS NOT NULL THEN
      UPDATE payment_instructions SET bank_snapshot = encode(sha256(convert_to(concat_ws('|', r.bank, r.supplier_id, r.bank_name, r.account_name,
               'hmac:' || encode(hmac(convert_to('bank-account|' || r.account_number, 'UTF8'), r.k, 'sha256'), 'hex'), r.currency, r.status, r.approved_by), 'UTF8')), 'hex')
       WHERE id = r.id;
    END IF;
  END LOOP;
END$$;
ALTER TABLE payment_instructions ENABLE TRIGGER payment_instructions_guard;
