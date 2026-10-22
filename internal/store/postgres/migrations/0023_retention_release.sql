-- 0023: retention release (ADR 0011 addendum).
--
-- Retention deducted on each certificate sits in retention receivable (Dr
-- retention at invoice, 0018). When the client certifies a release (taking
-- over / practical completion, end of the defects liability period, or a
-- negotiated release), the released amount becomes due:
--
--   AR clerk records a DRAFT retention release on an ACTIVE contract with the
--   client's release certificate (reference + SHA-256 of the signed file) ->
--   a commercial manager approves it (a different person, a human, fresh MFA)
--   -> AR_RETENTION journal: Dr accounts receivable / Cr retention receivable
--   -> the customer pays it through an ordinary receipt allocated to the
--   release.
--
-- VAT was charged on the full certified gross at invoice time (0018), so a
-- release carries no VAT. The database caps approved releases at the
-- retention held on approved invoices, under a row lock on the contract.

CREATE TABLE retention_releases (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id    uuid NOT NULL,
  project_id         uuid NOT NULL,
  contract_id        uuid NOT NULL,
  customer_id        uuid NOT NULL,
  policy_id          uuid NOT NULL,
  number             text NOT NULL,
  release_date       date NOT NULL,
  currency           char(3) NOT NULL REFERENCES currencies(code),
  amount             numeric(24,6) NOT NULL CHECK (amount > 0),
  milestone          text NOT NULL CHECK (milestone IN ('TAKING_OVER', 'DEFECTS_LIABILITY_END', 'NEGOTIATED')),
  certificate_ref    text NOT NULL CHECK (length(btrim(certificate_ref)) BETWEEN 3 AND 100),
  certificate_sha256 text NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'CANCELLED')),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  approved_by        text,
  approved_at        timestamptz,
  approver_mfa       boolean NOT NULL DEFAULT false,
  decision_reason    text,
  journal_id         uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES contract_policies(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, customer_id) REFERENCES customers(tenant_id, legal_entity_id, id),
  CONSTRAINT retention_release_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE INDEX retention_releases_contract ON retention_releases (contract_id) WHERE status <> 'CANCELLED';

-- Retention held on a contract (approved invoices) and released (approved releases).
CREATE OR REPLACE FUNCTION ar_retention_balance(p_contract uuid, OUT held numeric, OUT released numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT sum(retention_amount) FROM customer_invoices WHERE contract_id = p_contract AND status = 'APPROVED' AND tenant_id = current_tenant()), 0),
         COALESCE((SELECT sum(amount) FROM retention_releases WHERE contract_id = p_contract AND status = 'APPROVED' AND tenant_id = current_tenant()), 0)
$$;

CREATE OR REPLACE FUNCTION retention_releases_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; bal record; live numeric;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant() FOR SHARE;
    IF c.status IS DISTINCT FROM 'ACTIVE' OR NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.journal_id IS NOT NULL
       OR NEW.approver_mfa OR NEW.decision_reason IS NOT NULL THEN
      RAISE EXCEPTION 'retention releases are recorded DRAFT on an ACTIVE contract' USING ERRCODE = 'check_violation';
    END IF;
    NEW.legal_entity_id := c.legal_entity_id; NEW.project_id := c.project_id; NEW.customer_id := c.customer_id;
    NEW.policy_id := c.policy_id; NEW.currency := c.currency;
    NEW.certificate_ref := btrim(NEW.certificate_ref);
    PERFORM assert_currency_precision(NEW.amount, NEW.currency, 'retention release');
    IF NEW.release_date < c.signed_on THEN
      RAISE EXCEPTION 'a retention release is not dated before the contract signature (%)', c.signed_on USING ERRCODE = 'check_violation';
    END IF;
    bal := ar_retention_balance(c.id);
    SELECT COALESCE(sum(amount), 0) INTO live FROM retention_releases WHERE contract_id = c.id AND status = 'DRAFT';
    IF bal.released + live + NEW.amount > bal.held THEN
      RAISE EXCEPTION 'releases of contract % (% released, % in draft, % now) would exceed the retention held %',
        c.number, bal.released, live, NEW.amount, bal.held USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'retention release');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approver_mfa', 'journal_id'], 'retention release');
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id FOR UPDATE;
    IF c.status <> 'ACTIVE' THEN
      RAISE EXCEPTION 'contract % is no longer ACTIVE', c.number USING ERRCODE = 'check_violation';
    END IF;
    bal := ar_retention_balance(c.id);
    IF bal.released + NEW.amount > bal.held THEN
      RAISE EXCEPTION 'release % (%) exceeds the retention still held on contract % (held %, released %)',
        NEW.number, NEW.amount, c.number, bal.held, bal.released USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ar.retention.approve', 'retention_release', NEW.id::text, NEW.approved_by, ARRAY['ar.retention.approve'], true, 'APPROVED', NULL);
    PERFORM ar_assert_journal(NEW.journal_id, 'AR_RETENTION', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.release_date);
    NEW.approver_mfa := true;
    NEW.approved_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'retention release');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling a retention release requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ar.retention.cancel', 'retention_release', NEW.id::text, NULL, ARRAY['ar.retention.create', 'ar.retention.approve'], false, 'CANCELLED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal retention release transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER retention_releases_guard BEFORE INSERT OR UPDATE ON retention_releases FOR EACH ROW EXECUTE FUNCTION retention_releases_guard();

CREATE OR REPLACE FUNCTION retention_releases_period() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM fiscal_periods ap WHERE ap.tenant_id = current_tenant() AND ap.legal_entity_id = NEW.legal_entity_id
                   AND NEW.release_date BETWEEN ap.starts_on AND ap.ends_on AND ap.status = 'OPEN') THEN
    RAISE EXCEPTION 'retention release date % is not in an open accounting period of the entity', NEW.release_date USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER retention_releases_period BEFORE INSERT ON retention_releases FOR EACH ROW EXECUTE FUNCTION retention_releases_period();

CREATE OR REPLACE FUNCTION ar_release_journal_present() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.status = 'APPROVED' AND NEW.journal_id IS NULL THEN
    RAISE EXCEPTION 'approved retention release % has no journal', NEW.number USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER retention_releases_journal AFTER UPDATE ON retention_releases DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ar_release_journal_present();

CREATE OR REPLACE FUNCTION ar_creation_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; perm text;
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'customers' THEN act := 'customer.create'; typ := 'customer'; perm := 'customer.manage';
    WHEN 'contract_policies' THEN act := 'contract.policy.create'; typ := 'contract_policy'; perm := 'contract.policy.manage';
    WHEN 'customer_invoices' THEN act := 'ar.invoice.create'; typ := 'customer_invoice'; perm := 'ar.invoice.create';
    WHEN 'customer_receipts' THEN act := 'ar.receipt.create'; typ := 'customer_receipt'; perm := 'ar.receipt.create';
    WHEN 'customer_credit_notes' THEN act := 'ar.credit.create'; typ := 'customer_credit_note'; perm := 'ar.credit.create';
    WHEN 'retention_releases' THEN act := 'ar.retention.create'; typ := 'retention_release'; perm := 'ar.retention.create';
    ELSE RAISE EXCEPTION 'ar_creation_attested: unexpected table %', TG_TABLE_NAME;
  END CASE;
  PERFORM approval_use(act, typ, NEW.id::text, NEW.created_by, ARRAY[perm], false, NULL, NULL);
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER retention_releases_created_by AFTER INSERT ON retention_releases DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION ar_creation_attested();

-- ===========================================================================
-- Receipts may be allocated to an approved retention release.
-- ===========================================================================
ALTER TABLE receipt_allocations ADD COLUMN retention_release_id uuid;
ALTER TABLE receipt_allocations ADD CONSTRAINT receipt_allocations_release_fk
  FOREIGN KEY (tenant_id, retention_release_id) REFERENCES retention_releases(tenant_id, id);
ALTER TABLE receipt_allocations DROP CONSTRAINT receipt_allocation_one_target;
ALTER TABLE receipt_allocations ADD CONSTRAINT receipt_allocation_one_target
  CHECK (num_nonnulls(invoice_id, contract_id, retention_release_id) = 1);
DROP INDEX receipt_allocations_once;
CREATE UNIQUE INDEX receipt_allocations_once ON receipt_allocations (receipt_id, COALESCE(invoice_id, contract_id, retention_release_id));

-- The 0020 body with the release branch.
CREATE OR REPLACE FUNCTION receipt_allocations_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE r customer_receipts; bad boolean;
BEGIN
  SELECT * INTO r FROM customer_receipts WHERE id = NEW.receipt_id AND tenant_id = current_tenant() FOR SHARE;
  IF r.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'allocations are added only while the receipt is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.amount <= 0 THEN
    RAISE EXCEPTION 'an allocation is a positive amount' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM assert_currency_precision(NEW.amount, r.currency, 'receipt allocation');
  IF NEW.invoice_id IS NOT NULL THEN
    SELECT i.currency <> r.currency OR i.legal_entity_id <> r.legal_entity_id INTO bad FROM customer_invoices i WHERE i.id = NEW.invoice_id;
  ELSIF NEW.retention_release_id IS NOT NULL THEN
    SELECT x.currency <> r.currency OR x.legal_entity_id <> r.legal_entity_id INTO bad FROM retention_releases x WHERE x.id = NEW.retention_release_id;
  ELSE
    SELECT c.currency <> r.currency OR c.legal_entity_id <> r.legal_entity_id INTO bad FROM contracts c WHERE c.id = NEW.contract_id;
  END IF;
  IF bad IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'an allocation must be to an invoice, retention release or contract of the receipt''s entity and currency' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- The 0022 body with the release over-allocation check.
CREATE OR REPLACE FUNCTION customer_receipts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE l bank_statement_lines; st bank_statements; cb company_bank_accounts; alloc numeric; bad record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO l FROM bank_statement_lines WHERE id = NEW.statement_line_id AND tenant_id = current_tenant() FOR SHARE;
    SELECT * INTO st FROM bank_statements WHERE id = l.statement_id;
    SELECT * INTO cb FROM company_bank_accounts WHERE id = st.company_bank_id;
    IF l.id IS NULL OR l.amount <= 0 OR l.status <> 'UNMATCHED' THEN
      RAISE EXCEPTION 'a receipt is recorded for an unmatched money-in statement line' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status <> 'DRAFT' OR NEW.confirmed_by IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'receipts are recorded DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    NEW.amount := l.amount; NEW.company_bank_id := cb.id; NEW.legal_entity_id := cb.legal_entity_id;
    NEW.currency := cb.currency; NEW.receipt_date := l.booking_date;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'receipt');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'CONFIRMED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'confirmed_by', 'confirmed_at', 'journal_id'], 'receipt');
    SELECT * INTO l FROM bank_statement_lines WHERE id = NEW.statement_line_id;
    SELECT * INTO st FROM bank_statements WHERE id = l.statement_id;
    IF lower(btrim(NEW.confirmed_by)) = lower(btrim(st.imported_by)) OR lower(btrim(NEW.created_by)) = lower(btrim(st.imported_by)) THEN
      RAISE EXCEPTION 'a receipt is allocated and confirmed by people independent of the statement import' USING ERRCODE = 'check_violation';
    END IF;
    SELECT COALESCE(sum(amount), 0) INTO alloc FROM receipt_allocations WHERE receipt_id = NEW.id;
    IF alloc <> NEW.amount THEN
      RAISE EXCEPTION 'allocations (%) must equal the amount received (%)', alloc, NEW.amount USING ERRCODE = 'check_violation';
    END IF;
    PERFORM 1 FROM customer_invoices i JOIN receipt_allocations a ON a.invoice_id = i.id WHERE a.receipt_id = NEW.id FOR UPDATE OF i;
    PERFORM 1 FROM contracts c JOIN receipt_allocations a ON a.contract_id = c.id WHERE a.receipt_id = NEW.id FOR UPDATE OF c;
    PERFORM 1 FROM retention_releases x JOIN receipt_allocations a ON a.retention_release_id = x.id WHERE a.receipt_id = NEW.id FOR UPDATE OF x;
    SELECT i.number, i.total, i.status, i.legal_entity_id INTO bad FROM receipt_allocations a JOIN customer_invoices i ON i.id = a.invoice_id
     WHERE a.receipt_id = NEW.id
       AND (i.status <> 'APPROVED' OR i.legal_entity_id <> NEW.legal_entity_id OR i.currency <> NEW.currency
            OR a.amount + (SELECT COALESCE(sum(a2.amount), 0) FROM receipt_allocations a2 JOIN customer_receipts r2 ON r2.id = a2.receipt_id
                            WHERE a2.invoice_id = i.id AND r2.status = 'CONFIRMED') > i.total - (ar_invoice_credited(i.id)).total)
     LIMIT 1;
    IF bad.number IS NOT NULL THEN
      RAISE EXCEPTION 'invoice % cannot take this allocation (status %, total %): it would be over-allocated, is credited, or is not payable', bad.number, bad.status, bad.total
        USING ERRCODE = 'check_violation';
    END IF;
    SELECT x.number, x.amount AS total, x.status INTO bad FROM receipt_allocations a JOIN retention_releases x ON x.id = a.retention_release_id
     WHERE a.receipt_id = NEW.id
       AND (x.status <> 'APPROVED' OR x.legal_entity_id <> NEW.legal_entity_id OR x.currency <> NEW.currency
            OR a.amount + (SELECT COALESCE(sum(a2.amount), 0) FROM receipt_allocations a2 JOIN customer_receipts r2 ON r2.id = a2.receipt_id
                            WHERE a2.retention_release_id = x.id AND r2.status = 'CONFIRMED') > x.amount)
     LIMIT 1;
    IF bad.number IS NOT NULL THEN
      RAISE EXCEPTION 'retention release % cannot take this allocation (status %, amount %): it would be over-allocated or is not payable', bad.number, bad.status, bad.total
        USING ERRCODE = 'check_violation';
    END IF;
    SELECT c.number, c.advance_amount INTO bad FROM receipt_allocations a JOIN contracts c ON c.id = a.contract_id
     WHERE a.receipt_id = NEW.id AND (c.status <> 'ACTIVE' OR c.legal_entity_id <> NEW.legal_entity_id
            OR a.amount + contract_advance_received(c.id) > c.advance_amount)
     LIMIT 1;
    IF bad.number IS NOT NULL THEN
      RAISE EXCEPTION 'contract % cannot take this advance (agreed advance %)', bad.number, bad.advance_amount USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ar.receipt.confirm', 'customer_receipt', NEW.id::text, NEW.confirmed_by, ARRAY['ar.receipt.confirm'], false, 'CONFIRMED', NULL);
    PERFORM ar_assert_journal(NEW.journal_id, 'AR_RECEIPT', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.receipt_date);
    NEW.confirmed_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'cancel_reason'], 'receipt');
    IF NEW.cancel_reason IS NULL OR length(btrim(NEW.cancel_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling a receipt requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ar.receipt.cancel', 'customer_receipt', NEW.id::text, NULL, ARRAY['ar.receipt.create', 'ar.receipt.confirm'], false, 'CANCELLED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal receipt transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- ===========================================================================
-- Expected accounting: the 0022 branches, receipts crediting AR for release
-- allocations, plus AR_RETENTION.
-- ===========================================================================
CREATE OR REPLACE FUNCTION ar_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH e(account_id, side, amount, project_id, cost_code_id) AS (
    SELECT pol.ar_account_id, 'DEBIT', i.total, NULL::uuid, NULL::uuid
      FROM customer_invoices i JOIN contract_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'AR_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.retention_account_id, 'DEBIT', i.retention_amount, NULL::uuid, NULL::uuid
      FROM customer_invoices i JOIN contract_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'AR_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.advance_account_id, 'DEBIT', i.advance_recovery, NULL::uuid, NULL::uuid
      FROM customer_invoices i JOIN contract_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'AR_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.revenue_account_id, 'CREDIT', i.gross, i.project_id, NULL::uuid
      FROM customer_invoices i JOIN contract_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'AR_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.vat_output_account_id, 'CREDIT', i.vat_amount, NULL::uuid, NULL::uuid
      FROM customer_invoices i JOIN contract_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'AR_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    SELECT b.gl_account_id, 'DEBIT', r.amount, NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN company_bank_accounts b ON b.id = r.company_bank_id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant()
    UNION ALL
    SELECT (contract_policy_for(r.legal_entity_id)).ar_account_id, 'CREDIT', sum(a.amount), NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN receipt_allocations a ON a.receipt_id = r.id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant() AND a.contract_id IS NULL
     GROUP BY r.legal_entity_id
    UNION ALL
    SELECT (contract_policy_for(r.legal_entity_id)).advance_account_id, 'CREDIT', sum(a.amount), NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN receipt_allocations a ON a.receipt_id = r.id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant() AND a.contract_id IS NOT NULL
     GROUP BY r.legal_entity_id
    UNION ALL
    SELECT pol.revenue_account_id, 'DEBIT', c.net_amount, c.project_id, NULL::uuid
      FROM customer_credit_notes c JOIN contract_policies pol ON pol.id = c.policy_id
     WHERE p_doc = 'AR_CREDIT' AND c.id = p_id AND c.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.vat_output_account_id, 'DEBIT', c.vat_amount, NULL::uuid, NULL::uuid
      FROM customer_credit_notes c JOIN contract_policies pol ON pol.id = c.policy_id
     WHERE p_doc = 'AR_CREDIT' AND c.id = p_id AND c.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.ar_account_id, 'CREDIT', c.total, NULL::uuid, NULL::uuid
      FROM customer_credit_notes c JOIN contract_policies pol ON pol.id = c.policy_id
     WHERE p_doc = 'AR_CREDIT' AND c.id = p_id AND c.tenant_id = current_tenant()
    UNION ALL
    -- Retention release: Dr AR / Cr retention receivable, on the contract policy.
    SELECT pol.ar_account_id, 'DEBIT', x.amount, NULL::uuid, NULL::uuid
      FROM retention_releases x JOIN contract_policies pol ON pol.id = x.policy_id
     WHERE p_doc = 'AR_RETENTION' AND x.id = p_id AND x.tenant_id = current_tenant()
    UNION ALL
    SELECT pol.retention_account_id, 'CREDIT', x.amount, NULL::uuid, NULL::uuid
      FROM retention_releases x JOIN contract_policies pol ON pol.id = x.policy_id
     WHERE p_doc = 'AR_RETENTION' AND x.id = p_id AND x.tenant_id = current_tenant()
  )
  SELECT account_id, side, amount, project_id, cost_code_id FROM e WHERE amount > 0
$$;

CREATE OR REPLACE FUNCTION journals_ar_binding() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE bound boolean;
BEGIN
  bound := CASE NEW.source_type
      WHEN 'AR_INVOICE' THEN EXISTS (SELECT 1 FROM customer_invoices WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'AR_RECEIPT' THEN EXISTS (SELECT 1 FROM customer_receipts WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'AR_CREDIT' THEN EXISTS (SELECT 1 FROM customer_credit_notes WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'AR_RETENTION' THEN EXISTS (SELECT 1 FROM retention_releases WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      ELSE false END;
  IF NOT bound THEN
    RAISE EXCEPTION 'journal % uses reserved source type % but no % document references it', NEW.id, NEW.source_type, NEW.source_type
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;

-- ===========================================================================
-- Reports
-- ===========================================================================
DROP FUNCTION ar_contract_position(uuid);
CREATE FUNCTION ar_contract_position(p_contract uuid)
RETURNS TABLE (contract_value numeric, measured_value numeric, certified_gross numeric, retention_held numeric, retention_released numeric,
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

-- The 0022 body; AR includes posted releases and receipts on them; retention
-- receivable nets posted releases.
CREATE OR REPLACE FUNCTION ar_gl_reconciliation(p_entity uuid)
RETURNS TABLE (check_name text, subledger numeric, gl numeric, difference numeric, unposted_documents bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE pol contract_policies; sub numeric; g numeric; un bigint; rel numeric;
BEGIN
  pol := contract_policy_for(p_entity);
  IF pol.id IS NULL THEN
    RETURN;
  END IF;
  SELECT COALESCE(sum(x.amount), 0) INTO rel FROM retention_releases x JOIN journals j ON j.id = x.journal_id
   WHERE x.legal_entity_id = p_entity AND x.status = 'APPROVED' AND j.status = 'POSTED';
  SELECT COALESCE(sum(i.total), 0) INTO sub FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
   WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED';
  sub := sub + rel;
  sub := sub - COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id JOIN journals j ON j.id = r.journal_id
                          WHERE r.legal_entity_id = p_entity AND r.status = 'CONFIRMED' AND j.status = 'POSTED' AND a.contract_id IS NULL), 0);
  sub := sub - COALESCE((SELECT sum(c.total) FROM customer_credit_notes c JOIN journals j ON j.id = c.journal_id
                          WHERE c.legal_entity_id = p_entity AND c.status = 'APPROVED' AND j.status = 'POSTED'), 0);
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.ar_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT (SELECT count(*) FROM customer_invoices i JOIN journals j ON j.id = i.journal_id WHERE i.legal_entity_id = p_entity AND j.status <> 'POSTED')
       + (SELECT count(*) FROM customer_credit_notes c JOIN journals j ON j.id = c.journal_id WHERE c.legal_entity_id = p_entity AND j.status <> 'POSTED')
       + (SELECT count(*) FROM retention_releases x JOIN journals j ON j.id = x.journal_id WHERE x.legal_entity_id = p_entity AND j.status <> 'POSTED')
    INTO un;
  check_name := 'Accounts receivable'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  SELECT (SELECT count(*) FROM customer_invoices i JOIN journals j ON j.id = i.journal_id WHERE i.legal_entity_id = p_entity AND j.status <> 'POSTED')
       + (SELECT count(*) FROM retention_releases x JOIN journals j ON j.id = x.journal_id WHERE x.legal_entity_id = p_entity AND j.status <> 'POSTED')
    INTO un;
  SELECT COALESCE(sum(i.retention_amount), 0) - rel INTO sub FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
   WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED';
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.retention_account_id AND j.status IN ('POSTED', 'REVERSED');
  check_name := 'Retention receivable'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  SELECT -(COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id JOIN journals j ON j.id = r.journal_id
                      WHERE r.legal_entity_id = p_entity AND r.status = 'CONFIRMED' AND j.status = 'POSTED' AND a.contract_id IS NOT NULL), 0)
         - COALESCE((SELECT sum(i.advance_recovery) FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
                      WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED'), 0)) INTO sub;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.advance_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT count(*) INTO un FROM customer_receipts r JOIN journals j ON j.id = r.journal_id WHERE r.legal_entity_id = p_entity AND j.status <> 'POSTED';
  check_name := 'Advances received'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  SELECT COALESCE(sum(l.amount), 0), count(*) INTO sub, un FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
    JOIN company_bank_accounts b ON b.id = s.company_bank_id
   WHERE b.legal_entity_id = p_entity AND l.amount > 0
     AND NOT EXISTS (SELECT 1 FROM customer_receipts r WHERE r.statement_line_id = l.id AND r.status = 'CONFIRMED');
  check_name := 'Unapplied money in (statement lines without a confirmed receipt)'; subledger := sub; gl := NULL; difference := NULL;
  unposted_documents := un; RETURN NEXT;
END$$;


-- ===========================================================================
-- Approval subject text (the 0022 body with the retention release branch).
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
  WHEN 'customer_credit_note' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM customer_credit_notes x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'retention_release' THEN SELECT to_jsonb(x) - 'journal_id' INTO j FROM retention_releases x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- ===========================================================================
-- Row-level security and grants
-- ===========================================================================
ALTER TABLE retention_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_releases FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON retention_releases USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());
REVOKE ALL ON retention_releases FROM PUBLIC;
GRANT SELECT, INSERT ON retention_releases TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason, journal_id) ON retention_releases TO serk_app;

REVOKE ALL ON FUNCTION ar_retention_balance(uuid), ar_contract_position(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ar_retention_balance(uuid), ar_contract_position(uuid) TO serk_app;
