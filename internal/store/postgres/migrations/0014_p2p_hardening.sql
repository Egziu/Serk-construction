-- 0014: procure-to-pay hardening (independent review 3 of 0013; ADR 0009).
--
-- Additive only: new triggers and functions, replaced function bodies
-- (CREATE OR REPLACE, same signatures, existing grants kept) and one new
-- column. Every finding has a regression probe in
-- internal/kernel/review3_regression_test.go.
--
--  H1  creators of master data / quotes / POs are bound by an attestation
--      consumed at commit (no more free-text maker identities).
--  H2  bank statement lines must equal the content parsed from the attested
--      file; the importer must be independent of the payments it settles.
--  M1  subledger journal lines are written only by the generating transaction
--      and re-checked against the document at approve and post; over-receipt
--      counts against the budget.
--  M2  payment approval/release needs the platform-signed principal.human
--      marker (identity-provider assertion), not a user-id naming convention.
--  M3  PO lines cannot post to control accounts (bank, clearing, GRNI, AP,
--      VAT input, price variance).
--  L1  no back-dated statements.   L2  dual approval also by invoice total.
--  L3  preparer cannot release; reconciler independent of the payment and of
--      the importer.
--  R3-X1 (found during remediation) successor P2P policies keep the GRNI and
--      AP control accounts, so a document's expected accounting is stable.
--  Info: document numbers beyond 999,999; quotes after the RFQ due time.

-- ===========================================================================
-- H1: attested creation
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_creation_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; perm text; actor text := to_jsonb(NEW)->>'created_by';
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'p2p_policies' THEN act := 'p2p.policy.create'; typ := 'p2p_policy'; perm := 'p2p.policy.manage';
    WHEN 'suppliers' THEN act := 'supplier.create'; typ := 'supplier'; perm := 'supplier.manage';
    WHEN 'supplier_bank_accounts' THEN act := 'supplier.bank.create'; typ := 'supplier_bank_account'; perm := 'supplier.manage';
    WHEN 'company_bank_accounts' THEN act := 'bankacct.create'; typ := 'company_bank_account'; perm := 'bankacct.manage';
    WHEN 'rfq_quotes' THEN act := 'rfq.quote.record'; typ := 'rfq_quote'; perm := 'rfq.manage'; actor := NEW.received_by;
    WHEN 'purchase_orders' THEN act := 'po.create'; typ := 'purchase_order'; perm := 'po.manage';
    ELSE RAISE EXCEPTION 'p2p_creation_attested: unexpected table %', TG_TABLE_NAME;
  END CASE;
  -- At commit: the named creator's own attestation over the content as
  -- created (subject hash re-checked by approval_use).
  PERFORM approval_use(act, typ, NEW.id::text, actor, ARRAY[perm], false, NULL, NULL);
  RETURN NULL;
END$$;

CREATE CONSTRAINT TRIGGER p2p_policies_created_by AFTER INSERT ON p2p_policies DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();
CREATE CONSTRAINT TRIGGER suppliers_created_by AFTER INSERT ON suppliers DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();
CREATE CONSTRAINT TRIGGER supplier_bank_accounts_created_by AFTER INSERT ON supplier_bank_accounts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();
CREATE CONSTRAINT TRIGGER company_bank_accounts_created_by AFTER INSERT ON company_bank_accounts DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();
CREATE CONSTRAINT TRIGGER rfq_quotes_received_by AFTER INSERT ON rfq_quotes DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();
CREATE CONSTRAINT TRIGGER purchase_orders_created_by AFTER INSERT ON purchase_orders DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_creation_attested();

-- ===========================================================================
-- M3 + R3-X1: control accounts
-- ===========================================================================
-- An account that a bank account or a P2P policy uses as a control account.
CREATE OR REPLACE FUNCTION p2p_is_control_account(p_account uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM company_bank_accounts b WHERE b.tenant_id = current_tenant() AND p_account IN (b.gl_account_id, b.clearing_account_id))
      OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant()
                    AND p.status IN ('DRAFT', 'APPROVED') AND p_account IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id))
$$;

CREATE OR REPLACE FUNCTION po_lines_control_account() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF p2p_is_control_account(NEW.account_id) THEN
    RAISE EXCEPTION 'PO line % cannot post receipts to a control account (bank, payments in transit, GRNI, AP, VAT input or price variance)', NEW.line_no
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER po_lines_control_account BEFORE INSERT ON po_lines FOR EACH ROW EXECUTE FUNCTION po_lines_control_account();

CREATE OR REPLACE FUNCTION company_bank_accounts_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.gl_account_id = NEW.clearing_account_id
     OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant() AND p.status IN ('DRAFT', 'APPROVED')
                   AND (NEW.gl_account_id IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id)
                     OR NEW.clearing_account_id IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id)))
     OR EXISTS (SELECT 1 FROM po_lines l WHERE l.tenant_id = current_tenant() AND l.account_id IN (NEW.gl_account_id, NEW.clearing_account_id)) THEN
    RAISE EXCEPTION 'bank and payments-in-transit accounts must be distinct and not used as P2P control or PO cost accounts' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER company_bank_accounts_control BEFORE INSERT ON company_bank_accounts FOR EACH ROW EXECUTE FUNCTION company_bank_accounts_control();

CREATE OR REPLACE FUNCTION p2p_policies_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE prev p2p_policies;
BEGIN
  IF EXISTS (SELECT 1 FROM company_bank_accounts b WHERE b.tenant_id = current_tenant()
               AND (b.gl_account_id IN (NEW.grni_account_id, NEW.ap_account_id, NEW.vat_input_account_id, NEW.ppv_account_id)
                 OR b.clearing_account_id IN (NEW.grni_account_id, NEW.ap_account_id, NEW.vat_input_account_id, NEW.ppv_account_id)))
     OR EXISTS (SELECT 1 FROM po_lines l WHERE l.tenant_id = current_tenant()
                   AND l.account_id IN (NEW.grni_account_id, NEW.ap_account_id, NEW.vat_input_account_id, NEW.ppv_account_id))
     OR NEW.vat_input_account_id = NEW.ppv_account_id THEN
    RAISE EXCEPTION 'P2P control accounts must not be bank, payments-in-transit or PO cost accounts' USING ERRCODE = 'check_violation';
  END IF;
  -- R3-X1: GRNI and AP balances live on one account each; moving them is a
  -- ledger migration, not a policy change.
  prev := p2p_policy_for(NEW.legal_entity_id);
  IF prev.id IS NOT NULL AND (prev.grni_account_id <> NEW.grni_account_id OR prev.ap_account_id <> NEW.ap_account_id) THEN
    RAISE EXCEPTION 'a successor P2P policy keeps the GRNI and AP control accounts of the approved policy' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER p2p_policies_control BEFORE INSERT ON p2p_policies FOR EACH ROW EXECUTE FUNCTION p2p_policies_control();

-- ===========================================================================
-- M1: subledger journals are frozen at birth and re-bound at approve/post
-- ===========================================================================
-- The generating transaction. No grant on this column: the tenant login can
-- neither set nor change it (column-level privileges on journals).
ALTER TABLE journals ADD COLUMN created_txid bigint NOT NULL DEFAULT txid_current();

CREATE OR REPLACE FUNCTION journal_lines_p2p_birth() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE j record; jid uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.journal_id ELSE NEW.journal_id END;
BEGIN
  SELECT source_type, created_txid INTO j FROM journals WHERE id = jid AND tenant_id = current_tenant();
  IF j.source_type LIKE 'P2P\_%' AND j.created_txid IS DISTINCT FROM txid_current() THEN
    RAISE EXCEPTION 'lines of subledger journal % are written only by the transaction that generated it', jid USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END$$;
CREATE TRIGGER journal_lines_p2p_birth BEFORE INSERT OR UPDATE OR DELETE ON journal_lines FOR EACH ROW EXECUTE FUNCTION journal_lines_p2p_birth();

CREATE OR REPLACE FUNCTION journals_p2p_rebind() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE want text; got text;
BEGIN
  IF NEW.source_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'subledger journal % has no document reference', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  want := p2p_expected_text(NEW.source_type, NEW.source_ref::uuid);
  got := p2p_lines_text(NEW.id);
  IF want IS NULL OR want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'subledger journal % no longer equals the accounting of % % (expected %, got %)', NEW.id, NEW.source_type, NEW.source_ref, want, got
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_p2p_rebind BEFORE UPDATE OF status ON journals FOR EACH ROW
  WHEN (NEW.source_type LIKE 'P2P\_%' AND NEW.status IN ('APPROVED', 'POSTED') AND OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION journals_p2p_rebind();

-- Budget: a commitment is the PO amount or, after an over-receipt within
-- tolerance, the value actually received at the PO price.
CREATE OR REPLACE FUNCTION p2p_cost_position(p_cost_code uuid, p_exclude_pr uuid, p_exclude_po uuid,
  OUT budget numeric, OUT committed numeric, OUT reserved numeric, OUT actual_other numeric, OUT available numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  SELECT COALESCE(sum(i.amount), 0) INTO budget
    FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
   WHERE i.tenant_id = current_tenant() AND i.cost_code_id = p_cost_code AND v.status = 'APPROVED';
  SELECT COALESCE(sum(greatest(l.amount, p2p_round(p2p_received_qty(l.po_id, l.line_no) * l.unit_price, o.currency))), 0) INTO committed
    FROM po_lines l JOIN purchase_orders o ON o.id = l.po_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND o.status IN ('APPROVED', 'CLOSED')
     AND o.id IS DISTINCT FROM p_exclude_po;
  SELECT COALESCE(sum(l.est_amount), 0) INTO reserved
    FROM pr_lines l JOIN purchase_requisitions r ON r.id = l.pr_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND r.status = 'APPROVED'
     AND r.id IS DISTINCT FROM p_exclude_pr
     AND NOT EXISTS (SELECT 1 FROM rfqs q JOIN purchase_orders o ON o.rfq_id = q.id
                      WHERE q.pr_id = r.id AND o.status IN ('APPROVED', 'CLOSED'));
  -- Receipt journals are inside the commitment above; with M1 their lines
  -- are provably the receipt's expected accounting, so excluding them is exact.
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO actual_other
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status IN ('POSTED', 'REVERSED')
     AND j.source_type <> 'P2P_GRN';
  available := budget - committed - reserved - actual_other;
END$$;

-- ===========================================================================
-- M2: human principals only, by signed assertion
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_assert_human(p_actor text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  IF p_actor IS NULL OR p_actor ~* '^(system|ai|agent|bot|service|svc)[:_./-]' THEN
    RAISE EXCEPTION 'payments are authorised only by human principals (actor %)', p_actor USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- principal.human is added by the API signer only when the identity
  -- provider asserted a human principal; roles can never grant it.
  IF NOT EXISTS (SELECT 1 FROM approval_attestations a
                  WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.actor = p_actor
                    AND a.action IN ('payment.approve', 'payment.release') AND a.subject_type = 'payment_instruction'
                    AND 'principal.human' = ANY (a.perms)) THEN
    RAISE EXCEPTION 'payments are authorised only by principals the identity provider asserts are human (actor %)', p_actor
      USING ERRCODE = 'insufficient_privilege';
  END IF;
END$$;

-- ===========================================================================
-- L2 / L3: payment separation
-- ===========================================================================
CREATE OR REPLACE FUNCTION payment_instructions_separation() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE pol p2p_policies; big text;
BEGIN
  IF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    SELECT * INTO pol FROM p2p_policies WHERE id = NEW.policy_id;
    SELECT i.invoice_number INTO big FROM payment_allocations a JOIN supplier_invoices i ON i.id = a.invoice_id
     WHERE a.payment_id = NEW.id AND i.total >= pol.dual_payment_threshold LIMIT 1;
    IF big IS NOT NULL THEN
      RAISE EXCEPTION 'invoice % is % % or more: every payment against it needs two approvers', big, pol.dual_payment_threshold, NEW.currency
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'RELEASED' AND NEW.released_by = NEW.created_by THEN
    RAISE EXCEPTION 'the person who prepared a payment cannot release it' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER payment_instructions_separation BEFORE UPDATE OF status ON payment_instructions FOR EACH ROW
  WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION payment_instructions_separation();

-- ===========================================================================
-- H2 / L1 / L3: statements bound to their file and independent of payments
-- ===========================================================================
-- Canonical digest of a stored statement: the same text the API builds from
-- the parsed file (kernel.StatementInput.ContentDigest). Text fields are hex
-- encoded so no separator can be forged.
CREATE OR REPLACE FUNCTION p2p_statement_digest(p_statement uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT encode(sha256(convert_to(
           concat_ws('|', 'v1', s.company_bank_id::text, encode(convert_to(s.statement_no, 'UTF8'), 'hex'), to_char(s.statement_date, 'YYYY-MM-DD'),
                     s.opening_balance::text, s.closing_balance::text, s.source_sha256)
           || COALESCE((SELECT string_agg(E'\n' || concat_ws('|', l.line_no::text, to_char(l.booking_date, 'YYYY-MM-DD'), l.amount::text,
                                                         encode(convert_to(l.reference, 'UTF8'), 'hex'), encode(convert_to(l.counterparty, 'UTF8'), 'hex')),
                                          '' ORDER BY l.line_no)
                          FROM bank_statement_lines l WHERE l.statement_id = s.id), ''),
         'UTF8')), 'hex')
    FROM bank_statements s WHERE s.id = p_statement AND s.tenant_id = current_tenant()
$$;

CREATE OR REPLACE FUNCTION bank_statements_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE prev numeric;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'bank statements are immutable once imported' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (SELECT status FROM company_bank_accounts WHERE id = NEW.company_bank_id AND tenant_id = current_tenant()) IS DISTINCT FROM 'ACTIVE' THEN
    RAISE EXCEPTION 'statements are imported for ACTIVE bank accounts' USING ERRCODE = 'check_violation';
  END IF;
  -- L1: statements arrive in date order; no back-dating around continuity.
  IF EXISTS (SELECT 1 FROM bank_statements WHERE company_bank_id = NEW.company_bank_id AND statement_date > NEW.statement_date) THEN
    RAISE EXCEPTION 'a statement dated % precedes an already imported statement of this account', NEW.statement_date USING ERRCODE = 'check_violation';
  END IF;
  -- Continuity: opening balance = closing balance of the previous statement.
  SELECT closing_balance INTO prev FROM bank_statements
   WHERE company_bank_id = NEW.company_bank_id AND statement_date <= NEW.statement_date ORDER BY statement_date DESC, imported_at DESC LIMIT 1;
  IF prev IS NOT NULL AND prev <> NEW.opening_balance THEN
    RAISE EXCEPTION 'statement opening balance % does not continue the previous closing balance %', NEW.opening_balance, prev USING ERRCODE = 'check_violation';
  END IF;
  -- The importer's attestation over the file digest; its context (the parsed
  -- content digest) is verified at commit by bank_statements_content_check.
  PERFORM approval_use('bank.import', 'bank_statement_source', NEW.source_sha256, NEW.imported_by, ARRAY['bank.import'], false, NULL, NULL);
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION bank_statements_content_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM approval_consumptions c JOIN approval_attestations a ON a.nonce = c.nonce
                  WHERE c.tenant_id = current_tenant() AND c.txid = txid_current() AND a.action = 'bank.import'
                    AND a.subject_type = 'bank_statement_source' AND a.subject_id = NEW.source_sha256 AND a.actor = NEW.imported_by
                    AND a.ctx = NEW.company_bank_id::text || '|' || p2p_statement_digest(NEW.id)) THEN
    RAISE EXCEPTION 'statement %: the stored lines are not the content parsed from the attested statement file', NEW.statement_no
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER bank_statements_content_check AFTER INSERT ON bank_statements DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION bank_statements_content_check();

CREATE OR REPLACE FUNCTION bank_statement_lines_separation() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st bank_statements; p payment_instructions;
BEGIN
  SELECT * INTO st FROM bank_statements WHERE id = NEW.statement_id AND tenant_id = current_tenant();
  SELECT * INTO p FROM payment_instructions WHERE id = NEW.payment_id AND tenant_id = current_tenant();
  IF st.imported_by IN (p.created_by, p.approved_by, p.released_by) OR st.imported_by = p.second_approved_by THEN
    RAISE EXCEPTION 'a payment is settled only by a statement imported by someone independent of the payment' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.matched_by IN (st.imported_by, p.created_by, p.approved_by, p.released_by) OR NEW.matched_by = p.second_approved_by THEN
    RAISE EXCEPTION 'the reconciler must be independent of the statement import and of the payment' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER bank_statement_lines_separation BEFORE UPDATE ON bank_statement_lines FOR EACH ROW
  WHEN (OLD.status = 'UNMATCHED' AND NEW.status = 'MATCHED') EXECUTE FUNCTION bank_statement_lines_separation();

-- ===========================================================================
-- Info items
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_next_number(p_doc text) RETURNS text
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE y integer := extract(year FROM now())::integer; n bigint;
BEGIN
  INSERT INTO p2p_counters(doc_type, year, last) VALUES (p_doc, y, 1)
  ON CONFLICT (tenant_id, doc_type, year) DO UPDATE SET last = p2p_counters.last + 1
  RETURNING last INTO n;
  RETURN p_doc || '-' || y || '-' || lpad(n::text, greatest(6, length(n::text)), '0');
END$$;

CREATE OR REPLACE FUNCTION rfq_quotes_on_time() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF now() > (SELECT due_at FROM rfqs WHERE id = NEW.rfq_id AND tenant_id = current_tenant()) THEN
    RAISE EXCEPTION 'the RFQ closed for quotes at its due time' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER rfq_quotes_on_time BEFORE INSERT ON rfq_quotes FOR EACH ROW EXECUTE FUNCTION rfq_quotes_on_time();

GRANT EXECUTE ON FUNCTION p2p_is_control_account(uuid), p2p_statement_digest(uuid) TO serk_app;
