-- 0026: contract variations (change orders), GATEB-06 (ADR 0011 addendum).
--
-- A variation changes the scope of an ACTIVE contract on the client's
-- instruction: it adds new priced lines or changes the quantity of existing
-- lines (a reduction is an omission). The original contract lines stay as
-- signed; the effective quantity of a line is its signed quantity plus the
-- approved variations (contract_line_qty), and measurement is capped by it.
--
--   commercial manager records a DRAFT variation with the client's
--   instruction (reference + SHA-256 of the signed variation order) and its
--   lines -> submits it -> the CFO (a different person, a human, fresh MFA)
--   approves or rejects it. On approval the new lines become contract lines
--   (rate fixed by the variation) and the revised contract value includes it.
--
-- Rules enforced here: a quantity change uses the contract line's rate (the
-- rate is not renegotiated by a quantity change); a reduction never takes a
-- line below what has already been verified; new line numbers are unique
-- across the contract and its live variations; nothing changes after
-- submission. No accounting entry: revenue follows certification (IPC).

CREATE TABLE contract_variations (
  id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                 uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  contract_id               uuid NOT NULL,
  number                    text NOT NULL,
  title                     text NOT NULL CHECK (length(btrim(title)) BETWEEN 3 AND 300),
  reason                    text NOT NULL CHECK (length(btrim(reason)) BETWEEN 5 AND 2000),
  client_instruction_ref    text NOT NULL CHECK (length(btrim(client_instruction_ref)) BETWEEN 3 AND 100),
  client_instruction_sha256 text NOT NULL CHECK (client_instruction_sha256 ~ '^[0-9a-f]{64}$'),
  value_change              numeric(24,6) NOT NULL DEFAULT 0,
  status                    text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'CANCELLED')),
  created_by                text NOT NULL,
  created_at                timestamptz NOT NULL DEFAULT now(),
  submitted_at              timestamptz,
  approved_by               text,
  approved_at               timestamptz,
  approver_mfa              boolean NOT NULL DEFAULT false,
  decision_reason           text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  CONSTRAINT contract_variation_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE variation_lines (
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  variation_id uuid NOT NULL,
  line_no      integer NOT NULL CHECK (line_no BETWEEN 1 AND 9999),
  kind         text NOT NULL CHECK (kind IN ('NEW', 'CHANGE')),
  boq_item_id  uuid,
  description  text NOT NULL CHECK (length(btrim(description)) BETWEEN 2 AND 500),
  unit         text NOT NULL CHECK (unit ~ '^[A-Za-z0-9/.²³]{1,12}$'),
  qty_delta    numeric(20,4) NOT NULL CHECK (qty_delta <> 0),
  rate         numeric(24,6) NOT NULL CHECK (rate >= 0),
  amount       numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (variation_id, line_no),
  FOREIGN KEY (tenant_id, variation_id) REFERENCES contract_variations(tenant_id, id),
  FOREIGN KEY (tenant_id, boq_item_id) REFERENCES boq_items(tenant_id, id),
  CONSTRAINT variation_new_line_positive CHECK (kind = 'CHANGE' OR qty_delta > 0)
);

-- Effective quantity of a contract line: as signed plus approved variations.
CREATE OR REPLACE FUNCTION contract_line_qty(p_contract uuid, p_line integer) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT quantity FROM contract_lines WHERE contract_id = p_contract AND line_no = p_line AND tenant_id = current_tenant()), 0)
       + COALESCE((SELECT sum(vl.qty_delta) FROM variation_lines vl JOIN contract_variations v ON v.id = vl.variation_id
                    WHERE v.contract_id = p_contract AND v.status = 'APPROVED' AND vl.kind = 'CHANGE' AND vl.line_no = p_line
                      AND v.tenant_id = current_tenant()), 0)
$$;

CREATE OR REPLACE FUNCTION contract_variations_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; bad record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant() FOR SHARE;
    IF c.status IS DISTINCT FROM 'ACTIVE' OR NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.approver_mfa OR NEW.decision_reason IS NOT NULL THEN
      RAISE EXCEPTION 'variations are recorded DRAFT on an ACTIVE contract' USING ERRCODE = 'check_violation';
    END IF;
    NEW.value_change := 0;
    NEW.client_instruction_ref := btrim(NEW.client_instruction_ref);
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'variation');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at', 'value_change'], 'variation');
    IF NOT EXISTS (SELECT 1 FROM variation_lines WHERE variation_id = NEW.id) THEN
      RAISE EXCEPTION 'a variation needs at least one line' USING ERRCODE = 'check_violation';
    END IF;
    NEW.value_change := (SELECT sum(amount) FROM variation_lines WHERE variation_id = NEW.id);
    PERFORM approval_use('contract.variation.submit', 'contract_variation', NEW.id::text, NEW.created_by, ARRAY['contract.manage'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approver_mfa'], 'variation');
    -- Serialise with measurement verification and other variations of the contract.
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id FOR UPDATE;
    IF c.status IS DISTINCT FROM 'ACTIVE' THEN
      RAISE EXCEPTION 'the contract is not ACTIVE' USING ERRCODE = 'check_violation';
    END IF;
    -- A reduction never goes below what is verified (re-checked now: work may
    -- have been measured since the variation was prepared).
    SELECT vl.line_no, contract_line_qty(c.id, vl.line_no) + vl.qty_delta AS after, contract_verified_qty(c.id, vl.line_no, NULL) AS verified INTO bad
      FROM variation_lines vl WHERE vl.variation_id = NEW.id AND vl.kind = 'CHANGE'
       AND contract_line_qty(c.id, vl.line_no) + vl.qty_delta < contract_verified_qty(c.id, vl.line_no, NULL)
     LIMIT 1;
    IF bad.line_no IS NOT NULL THEN
      RAISE EXCEPTION 'contract line %: the variation leaves % but % is already verified', bad.line_no, bad.after, bad.verified USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM variation_lines vl JOIN contract_lines cl ON cl.contract_id = c.id AND cl.line_no = vl.line_no
                WHERE vl.variation_id = NEW.id AND vl.kind = 'NEW') THEN
      RAISE EXCEPTION 'a new variation line number is already a contract line' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.variation.approve', 'contract_variation', NEW.id::text, NEW.approved_by, ARRAY['contract.approve'], true, 'APPROVED', NULL);
    NEW.approver_mfa := true;
    NEW.approved_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'variation');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a variation requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.variation.reject', 'contract_variation', NEW.id::text, NULL, ARRAY['contract.approve'], false, 'REJECTED', NULL);
  ELSIF OLD.status IN ('DRAFT', 'SUBMITTED') AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'variation');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling a variation requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.variation.cancel', 'contract_variation', NEW.id::text, NULL, ARRAY['contract.manage'], false, 'CANCELLED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal variation transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER contract_variations_guard BEFORE INSERT OR UPDATE ON contract_variations FOR EACH ROW EXECUTE FUNCTION contract_variations_guard();

CREATE OR REPLACE FUNCTION variation_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v contract_variations; c contracts; cl contract_lines;
BEGIN
  SELECT * INTO v FROM contract_variations WHERE id = NEW.variation_id AND tenant_id = current_tenant() FOR SHARE;
  SELECT * INTO c FROM contracts WHERE id = v.contract_id;
  IF v.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'variation lines change only while the variation is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO cl FROM contract_lines WHERE contract_id = c.id AND line_no = NEW.line_no;
  IF NEW.kind = 'CHANGE' THEN
    IF cl.contract_id IS NULL THEN
      RAISE EXCEPTION 'variation line %: contract line % does not exist (use a NEW line)', NEW.line_no, NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    -- A quantity change is priced at the contract rate, in the contract unit.
    NEW.rate := cl.rate; NEW.unit := cl.unit; NEW.boq_item_id := cl.boq_item_id;
    NEW.description := COALESCE(NULLIF(btrim(NEW.description), ''), cl.description);
    IF contract_line_qty(c.id, NEW.line_no) + NEW.qty_delta < contract_verified_qty(c.id, NEW.line_no, NULL) THEN
      RAISE EXCEPTION 'contract line %: the change leaves % but % is already verified', NEW.line_no,
        contract_line_qty(c.id, NEW.line_no) + NEW.qty_delta, contract_verified_qty(c.id, NEW.line_no, NULL) USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    IF cl.contract_id IS NOT NULL OR EXISTS (
         SELECT 1 FROM variation_lines vl JOIN contract_variations v2 ON v2.id = vl.variation_id
          WHERE v2.contract_id = c.id AND v2.status IN ('DRAFT', 'SUBMITTED', 'APPROVED') AND vl.kind = 'NEW' AND vl.line_no = NEW.line_no
            AND v2.id <> v.id) THEN
      RAISE EXCEPTION 'variation line %: the line number is already used on the contract or a live variation', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.boq_item_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM boq_items i JOIN boq_versions bv ON bv.id = i.version_id
          WHERE i.id = NEW.boq_item_id AND bv.project_id = c.project_id AND bv.status = 'APPROVED') THEN
      RAISE EXCEPTION 'variation line % must reference an item of the project''s approved BOQ', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  PERFORM assert_currency_precision(NEW.rate, c.currency, 'variation rate');
  NEW.amount := p2p_round(NEW.qty_delta * NEW.rate, c.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER variation_lines_guard BEFORE INSERT ON variation_lines FOR EACH ROW EXECUTE FUNCTION variation_lines_guard();

-- The 0018 contract-line guard: lines are added while the contract is DRAFT,
-- or, for an ACTIVE contract, as the NEW lines of a variation approved in
-- this transaction (copied exactly).
CREATE OR REPLACE FUNCTION contract_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; vl variation_lines;
BEGIN
  SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant() FOR SHARE;
  IF c.status = 'ACTIVE' THEN
    SELECT l.* INTO vl FROM variation_lines l JOIN contract_variations v ON v.id = l.variation_id
     WHERE v.contract_id = c.id AND v.status = 'APPROVED' AND l.kind = 'NEW' AND l.line_no = NEW.line_no
       AND approval_consumed_in_tx(ARRAY['contract.variation.approve'], 'contract_variation', v.id::text, 'APPROVED') IS NOT NULL;
    IF vl.variation_id IS NULL OR NEW.description IS DISTINCT FROM vl.description OR NEW.unit IS DISTINCT FROM vl.unit
       OR NEW.quantity IS DISTINCT FROM vl.qty_delta OR NEW.rate IS DISTINCT FROM vl.rate OR NEW.boq_item_id IS DISTINCT FROM vl.boq_item_id THEN
      RAISE EXCEPTION 'lines are added to an ACTIVE contract only by an approved variation' USING ERRCODE = 'check_violation';
    END IF;
  ELSIF c.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'contract lines change only while the contract is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.boq_item_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
        WHERE i.id = NEW.boq_item_id AND v.project_id = c.project_id AND v.status = 'APPROVED') THEN
    RAISE EXCEPTION 'contract line % must reference an item of the project''s approved BOQ', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  NEW.amount := p2p_round(NEW.quantity * NEW.rate, c.currency);
  RETURN NEW;
END$$;

-- Every approved variation's NEW lines exist as contract lines at commit.
CREATE OR REPLACE FUNCTION contract_variations_applied() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.status = 'APPROVED' AND EXISTS (
       SELECT 1 FROM variation_lines vl WHERE vl.variation_id = NEW.id AND vl.kind = 'NEW'
          AND NOT EXISTS (SELECT 1 FROM contract_lines cl WHERE cl.contract_id = NEW.contract_id AND cl.line_no = vl.line_no)) THEN
    RAISE EXCEPTION 'approved variation % has new lines that were not added to the contract', NEW.number USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER contract_variations_applied AFTER UPDATE ON contract_variations DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION contract_variations_applied();

CREATE OR REPLACE FUNCTION contract_variations_created() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM approval_use('contract.variation.create', 'contract_variation', NEW.id::text, NEW.created_by, ARRAY['contract.manage'], false, NULL, NULL);
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER contract_variations_created_by AFTER INSERT ON contract_variations DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION contract_variations_created();


-- Measurement is capped by the effective quantity (the 0018 body).
CREATE OR REPLACE FUNCTION measurements_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; l record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant();
    IF c.status IS DISTINCT FROM 'ACTIVE' OR NEW.status <> 'DRAFT' OR NEW.verified_by IS NOT NULL THEN
      RAISE EXCEPTION 'measurements are recorded DRAFT against an ACTIVE contract' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.period_end < c.signed_on THEN
      RAISE EXCEPTION 'a measurement period cannot end before the contract was signed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'measurement');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'measurement');
    IF NOT EXISTS (SELECT 1 FROM measurement_lines WHERE measurement_id = NEW.id) THEN
      RAISE EXCEPTION 'a measurement needs at least one line' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('measure.submit', 'measurement', NEW.id::text, NEW.created_by, ARRAY['measure.create'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'VERIFIED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'verified_by', 'verified_at', 'decision_reason'], 'measurement');
    -- Serialise verifications of one contract; no line beyond its contract quantity.
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id FOR UPDATE;
    IF c.status IS DISTINCT FROM 'ACTIVE' THEN
      RAISE EXCEPTION 'the contract is not ACTIVE' USING ERRCODE = 'check_violation';
    END IF;
    FOR l IN SELECT ml.contract_line_no, ml.quantity, contract_line_qty(NEW.contract_id, ml.contract_line_no) AS contract_qty
               FROM measurement_lines ml JOIN contract_lines cl ON cl.contract_id = NEW.contract_id AND cl.line_no = ml.contract_line_no
              WHERE ml.measurement_id = NEW.id LOOP
      IF contract_verified_qty(NEW.contract_id, l.contract_line_no, NEW.id) + l.quantity > l.contract_qty THEN
        RAISE EXCEPTION 'contract line %: cumulative measured % exceeds the contract quantity % including approved variations (a variation is required)',
          l.contract_line_no, contract_verified_qty(NEW.contract_id, l.contract_line_no, NEW.id) + l.quantity, l.contract_qty
          USING ERRCODE = 'check_violation';
      END IF;
    END LOOP;
    PERFORM approval_use('measure.verify', 'measurement', NEW.id::text, NEW.verified_by, ARRAY['measure.verify'], false, 'VERIFIED', NULL);
    NEW.verified_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'verified_by', 'decision_reason'], 'measurement');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a measurement requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('measure.verify', 'measurement', NEW.id::text, NEW.verified_by, ARRAY['measure.verify'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal measurement transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- Contract position with variations (the 0023 body plus two columns).
DROP FUNCTION ar_contract_position(uuid);
CREATE FUNCTION ar_contract_position(p_contract uuid)
RETURNS TABLE (contract_value numeric, variations_approved numeric, revised_contract_value numeric, measured_value numeric, certified_gross numeric, retention_held numeric, retention_released numeric,
               advance_amount numeric, advance_received numeric, advance_recovered numeric, invoiced_total numeric, credited_total numeric,
               received numeric, receivable_open numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH x AS (
    SELECT c.*,
           COALESCE((SELECT sum(total) FROM customer_invoices WHERE contract_id = c.id AND status = 'APPROVED'), 0) AS inv,
           COALESCE((SELECT sum(total) FROM customer_credit_notes WHERE contract_id = c.id AND status = 'APPROVED'), 0) AS cred,
           COALESCE((SELECT sum(amount) FROM retention_releases WHERE contract_id = c.id AND status = 'APPROVED'), 0) AS rel,
           COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id
                      LEFT JOIN customer_invoices i ON i.id = a.invoice_id LEFT JOIN retention_releases rr ON rr.id = a.retention_release_id
                     WHERE COALESCE(i.contract_id, rr.contract_id) = c.id AND r.status = 'CONFIRMED'), 0) AS rec
      FROM contracts c WHERE c.id = p_contract AND c.tenant_id = current_tenant())
  SELECT x.contract_value,
         COALESCE((SELECT sum(value_change) FROM contract_variations WHERE contract_id = x.id AND status = 'APPROVED'), 0),
         x.contract_value + COALESCE((SELECT sum(value_change) FROM contract_variations WHERE contract_id = x.id AND status = 'APPROVED'), 0),
         COALESCE((SELECT sum(p2p_round(contract_verified_qty(x.id, l.line_no, NULL) * l.rate, x.currency)) FROM contract_lines l WHERE l.contract_id = x.id), 0),
         COALESCE((SELECT sum(this_gross) FROM ipcs WHERE contract_id = x.id AND status IN ('CERTIFIED', 'INVOICED')), 0),
         COALESCE((SELECT sum(retention_amount) FROM customer_invoices WHERE contract_id = x.id AND status = 'APPROVED'), 0) - x.rel,
         x.rel,
         x.advance_amount,
         contract_advance_received(x.id),
         COALESCE((SELECT sum(advance_recovery) FROM customer_invoices WHERE contract_id = x.id AND status = 'APPROVED'), 0),
         x.inv, x.cred, x.rec, x.inv - x.cred + x.rel - x.rec
    FROM x
$$;

-- Approval subject text (the 0025 body with the variation branch).
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
  WHEN 'contract_variation' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM variation_lines l WHERE l.variation_id = x.id))
      INTO j FROM contract_variations x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

ALTER TABLE contract_variations ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_variations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contract_variations USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
ALTER TABLE variation_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE variation_lines FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON variation_lines USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
REVOKE ALL ON contract_variations, variation_lines FROM PUBLIC;
GRANT SELECT, INSERT ON contract_variations, variation_lines TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON contract_variations TO serk_app;
REVOKE ALL ON FUNCTION contract_line_qty(uuid, integer), ar_contract_position(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contract_line_qty(uuid, integer), ar_contract_position(uuid) TO serk_app;
