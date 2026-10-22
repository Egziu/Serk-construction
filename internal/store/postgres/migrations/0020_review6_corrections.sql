-- 0020: corrections from independent review 6 (docs/security/INDEPENDENT_REVIEW_6_2026-10-22.md)
--   R6-F1 contract policy succession; R6-F2 receipt cancellation, line reuse
--   and recording checks; R6-F3 non-negative amount due; R6-F4 subledger
--   journals are not reversed; R6-F5 control-account conflicts with AR;
--   R6-F6 IPC period. Additive only: 0018 is released and unchanged.

-- R6-F1 -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION contract_policies_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE le legal_entities; prev contract_policies;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO le FROM legal_entities WHERE id = NEW.legal_entity_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'contract policies are created DRAFT in the entity''s functional currency' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT type FROM accounts WHERE id = NEW.ar_account_id) <> 'ASSET' OR (SELECT type FROM accounts WHERE id = NEW.retention_account_id) <> 'ASSET'
       OR (SELECT type FROM accounts WHERE id = NEW.advance_account_id) <> 'LIABILITY' OR (SELECT type FROM accounts WHERE id = NEW.revenue_account_id) <> 'REVENUE'
       OR (SELECT type FROM accounts WHERE id = NEW.vat_output_account_id) <> 'LIABILITY'
       OR NEW.ar_account_id = NEW.retention_account_id OR NEW.advance_account_id = NEW.vat_output_account_id THEN
      RAISE EXCEPTION 'contract policy accounts: AR and retention distinct ASSET, advance and VAT output distinct LIABILITY, revenue REVENUE'
        USING ERRCODE = 'check_violation';
    END IF;
    -- R6-F1: the entity's own contract policies are not a conflict (a
    -- successor must keep their AR, retention and advance accounts); bank
    -- and procure-to-pay control accounts are.
    IF EXISTS (SELECT 1 FROM company_bank_accounts b WHERE b.tenant_id = current_tenant()
                 AND (b.gl_account_id IN (NEW.ar_account_id, NEW.retention_account_id, NEW.advance_account_id, NEW.vat_output_account_id, NEW.revenue_account_id)
                   OR b.clearing_account_id IN (NEW.ar_account_id, NEW.retention_account_id, NEW.advance_account_id, NEW.vat_output_account_id, NEW.revenue_account_id)))
       OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant()
                 AND ARRAY[p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id]
                     && ARRAY[NEW.ar_account_id, NEW.retention_account_id, NEW.advance_account_id, NEW.vat_output_account_id, NEW.revenue_account_id])
       OR EXISTS (SELECT 1 FROM po_lines l WHERE l.tenant_id = current_tenant()
                 AND l.account_id IN (NEW.ar_account_id, NEW.retention_account_id, NEW.advance_account_id, NEW.vat_output_account_id)) THEN
      RAISE EXCEPTION 'contract policy control accounts must not be bank or procure-to-pay control accounts' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'contract policy');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'contract policy');
    -- Balances live on the AR, retention and advance accounts: a successor keeps them.
    SELECT * INTO prev FROM contract_policies WHERE tenant_id = current_tenant() AND legal_entity_id = NEW.legal_entity_id AND id <> NEW.id
       AND status IN ('APPROVED', 'RETIRED') ORDER BY version DESC LIMIT 1;
    IF prev.id IS NOT NULL AND (prev.ar_account_id <> NEW.ar_account_id OR prev.retention_account_id <> NEW.retention_account_id
                                OR prev.advance_account_id <> NEW.advance_account_id) THEN
      RAISE EXCEPTION 'a successor contract policy keeps the AR, retention and advance control accounts' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.policy.decide', 'contract_policy', NEW.id::text, NEW.approved_by, ARRAY['contract.policy.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'contract policy');
    PERFORM approval_use('contract.policy.decide', 'contract_policy', NEW.id::text, NULL, ARRAY['contract.policy.approve'], false, 'REJECTED', NULL);
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'RETIRED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'contract policy');
    IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN contract_policies p ON p.id::text = a.subject_id
                    WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'contract.policy.decide' AND a.ctx = 'APPROVED'
                      AND p.legal_entity_id = NEW.legal_entity_id AND p.id <> NEW.id) THEN
      RAISE EXCEPTION 'a contract policy is retired only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal contract policy transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- R6-F3 -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ipc_compute(p_contract uuid, p_exclude_ipc uuid,
  OUT cumulative_gross numeric, OUT previous_gross numeric, OUT this_gross numeric, OUT retention_amount numeric,
  OUT advance_recovery numeric, OUT vat_amount numeric, OUT amount_due numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE c contracts; pol contract_policies; recovered numeric; received numeric;
BEGIN
  SELECT * INTO c FROM contracts WHERE id = p_contract AND tenant_id = current_tenant();
  SELECT * INTO pol FROM contract_policies WHERE id = c.policy_id;
  SELECT COALESCE(sum(p2p_round(contract_verified_qty(c.id, l.line_no, NULL) * l.rate, c.currency)), 0) INTO cumulative_gross
    FROM contract_lines l WHERE l.contract_id = c.id;
  SELECT COALESCE(sum(i.this_gross), 0), COALESCE(sum(i.advance_recovery), 0) INTO previous_gross, recovered
    FROM ipcs i WHERE i.contract_id = c.id AND i.status IN ('CERTIFIED', 'INVOICED') AND i.id IS DISTINCT FROM p_exclude_ipc;
  this_gross := cumulative_gross - previous_gross;
  retention_amount := p2p_round(this_gross * c.retention_pct, c.currency);
  received := contract_advance_received(c.id);
  advance_recovery := greatest(0, least(p2p_round(this_gross * c.advance_recovery_pct, c.currency), received - recovered));
  -- R6-F3: a certificate never recovers more advance than the gross left
  -- after retention, so the amount due is never negative.
  advance_recovery := least(advance_recovery, greatest(0, this_gross - retention_amount));
  vat_amount := p2p_round(CASE pol.vat_base WHEN 'GROSS' THEN this_gross ELSE this_gross - advance_recovery END * pol.vat_rate, c.currency);
  amount_due := this_gross - retention_amount - advance_recovery + vat_amount;
END$$;

-- R6-F2: a cancelled receipt releases its statement line --------------------
ALTER TABLE customer_receipts DROP CONSTRAINT customer_receipts_statement_line_id_key;
CREATE UNIQUE INDEX customer_receipts_one_live_per_line ON customer_receipts (statement_line_id) WHERE status <> 'CANCELLED';

-- Refuse at recording what could never be confirmed.
CREATE OR REPLACE FUNCTION customer_receipts_recording() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE imp text;
BEGIN
  SELECT s.imported_by INTO imp FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
   WHERE l.id = NEW.statement_line_id AND l.tenant_id = current_tenant();
  IF lower(btrim(NEW.created_by)) = lower(btrim(imp)) THEN
    RAISE EXCEPTION 'a receipt is recorded by someone independent of the statement import' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER customer_receipts_recording BEFORE INSERT ON customer_receipts FOR EACH ROW EXECUTE FUNCTION customer_receipts_recording();

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
  ELSE
    SELECT c.currency <> r.currency OR c.legal_entity_id <> r.legal_entity_id INTO bad FROM contracts c WHERE c.id = NEW.contract_id;
  END IF;
  IF bad IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'an allocation must be to an invoice or contract of the receipt''s entity and currency' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- R6-F4: subledger journals are corrected at the document, never reversed --
CREATE OR REPLACE FUNCTION journals_subledger_no_reversal() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'subledger journal % (%) is not reversed: the document and the ledger would disagree; correct the source document (credit note) instead',
    NEW.id, NEW.source_type USING ERRCODE = 'check_violation';
END$$;
CREATE TRIGGER journals_subledger_no_reversal BEFORE UPDATE OF status ON journals FOR EACH ROW
  WHEN (NEW.status = 'REVERSED' AND OLD.status <> 'REVERSED' AND NEW.source_type ~ '^(P2P|AR)_')
  EXECUTE FUNCTION journals_subledger_no_reversal();

-- R6-F5: bank accounts and P2P policies may not use contract-policy accounts.
CREATE OR REPLACE FUNCTION ar_control_conflict(p_accounts uuid[]) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM contract_policies c WHERE c.tenant_id = current_tenant()
                   AND ARRAY[c.ar_account_id, c.retention_account_id, c.advance_account_id, c.vat_output_account_id, c.revenue_account_id] && p_accounts)
$$;
CREATE OR REPLACE FUNCTION company_bank_accounts_ar_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF ar_control_conflict(ARRAY[NEW.gl_account_id, NEW.clearing_account_id]) THEN
    RAISE EXCEPTION 'bank and payments-in-transit accounts must not be receivable, retention, advance, VAT output or revenue control accounts'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER company_bank_accounts_ar_control BEFORE INSERT ON company_bank_accounts FOR EACH ROW EXECUTE FUNCTION company_bank_accounts_ar_control();
CREATE OR REPLACE FUNCTION p2p_policies_ar_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF ar_control_conflict(ARRAY[NEW.grni_account_id, NEW.ap_account_id, NEW.vat_input_account_id, NEW.ppv_account_id]) THEN
    RAISE EXCEPTION 'P2P control accounts must not be receivable, retention, advance, VAT output or revenue control accounts' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER p2p_policies_ar_control BEFORE INSERT ON p2p_policies FOR EACH ROW EXECUTE FUNCTION p2p_policies_ar_control();

-- R6-F6: the certificate period follows the contract and the work ----------
CREATE OR REPLACE FUNCTION ipcs_period() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; last_measured date; last_certified date;
BEGIN
  SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant();
  SELECT max(period_end) INTO last_measured FROM measurements WHERE contract_id = NEW.contract_id AND status = 'VERIFIED';
  SELECT max(period_end) INTO last_certified FROM ipcs WHERE contract_id = NEW.contract_id AND status IN ('CERTIFIED', 'INVOICED');
  IF NEW.period_end < c.signed_on OR NEW.period_end < last_measured OR NEW.period_end <= last_certified THEN
    RAISE EXCEPTION 'the certificate period must end on or after the contract signature (%) and the last verified measurement (%), and after the last certificate (%)',
      c.signed_on, last_measured, last_certified USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER ipcs_period BEFORE INSERT ON ipcs FOR EACH ROW EXECUTE FUNCTION ipcs_period();

REVOKE ALL ON FUNCTION ar_control_conflict(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ar_control_conflict(uuid[]) TO serk_app;
