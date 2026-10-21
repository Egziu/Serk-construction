-- 0015: procure-to-pay hardening, round 2 (independent review 4 of 0014).
-- Additive: new triggers/constraint, replaced function bodies (same
-- signatures, grants kept). Regression probes: internal/kernel/
-- review4_regression_test.go (TestR4_*).
--
--  M-A  quote lines and PO lines are written only in the transaction whose
--       attested creation covers them (no later unattested lines).
--  M-B  a MATCHED statement line always names its reconciler; separation
--       checks refuse NULL identities.
--  L-A  the GRNI/AP control-account rule is re-checked when a policy is
--       approved (a draft proposed before the first approval cannot bypass it).
--  L-B  statement imports for one bank account are serialised, so two
--       statements cannot both continue the same closing balance.
--  L-C  the human marker must be on every payment attestation the actor
--       presents in the transaction (so on the one that is consumed).
--  L-D  accounts of retired/rejected policies remain control accounts.
--  Info journals.created_txid is forced by the database, never taken from
--       the caller; identity comparisons in separation checks ignore case.

-- ===========================================================================
-- M-A: child lines only with the attested creation of their header
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_lines_with_creation() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; parent uuid;
BEGIN
  IF TG_TABLE_NAME = 'rfq_quote_lines' THEN
    act := 'rfq.quote.record'; typ := 'rfq_quote'; parent := NEW.quote_id;
  ELSE
    act := 'po.create'; typ := 'purchase_order'; parent := NEW.po_id;
  END IF;
  -- The creator's attestation for the header was recorded in THIS
  -- transaction (approval_authorize verified its signature and the content
  -- hash, lines included). A later transaction has none.
  IF NOT EXISTS (SELECT 1 FROM approval_attestations a
                  WHERE a.txid = txid_current() AND a.tenant_id = current_tenant()
                    AND a.action = act AND a.subject_type = typ AND a.subject_id = parent::text) THEN
    RAISE EXCEPTION '% lines are written only by the attested creation of the %', typ, typ USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER rfq_quote_lines_with_creation AFTER INSERT ON rfq_quote_lines DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_lines_with_creation();
CREATE CONSTRAINT TRIGGER po_lines_with_creation AFTER INSERT ON po_lines DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION p2p_lines_with_creation();

-- ===========================================================================
-- M-B: reconciler identity is mandatory and independent
-- ===========================================================================
ALTER TABLE bank_statement_lines ADD CONSTRAINT bank_statement_lines_matched_by
  CHECK (status <> 'MATCHED' OR (matched_by IS NOT NULL AND btrim(matched_by) <> '')) NOT VALID;

CREATE OR REPLACE FUNCTION bank_statement_lines_separation() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st bank_statements; p payment_instructions; me text := lower(btrim(NEW.matched_by)); imp text;
BEGIN
  SELECT * INTO st FROM bank_statements WHERE id = NEW.statement_id AND tenant_id = current_tenant();
  SELECT * INTO p FROM payment_instructions WHERE id = NEW.payment_id AND tenant_id = current_tenant();
  imp := lower(btrim(st.imported_by));
  IF me IS NULL OR me = '' OR imp IS NULL THEN
    RAISE EXCEPTION 'a reconciled statement line names its reconciler and its importer' USING ERRCODE = 'check_violation';
  END IF;
  IF imp IN (lower(p.created_by), lower(p.approved_by), lower(p.released_by)) OR imp = lower(p.second_approved_by) THEN
    RAISE EXCEPTION 'a payment is settled only by a statement imported by someone independent of the payment' USING ERRCODE = 'check_violation';
  END IF;
  IF me IN (imp, lower(p.created_by), lower(p.approved_by), lower(p.released_by)) OR me = lower(p.second_approved_by) THEN
    RAISE EXCEPTION 'the reconciler must be independent of the statement import and of the payment' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

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
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'RELEASED' AND lower(btrim(NEW.released_by)) = lower(btrim(NEW.created_by)) THEN
    RAISE EXCEPTION 'the person who prepared a payment cannot release it' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- ===========================================================================
-- L-A: GRNI/AP accounts checked again at policy approval
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_policies_approval_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE prev p2p_policies;
BEGIN
  -- The most recent policy of the entity that was ever in force (it may
  -- already have been retired earlier in this transaction).
  SELECT * INTO prev FROM p2p_policies
   WHERE tenant_id = current_tenant() AND legal_entity_id = NEW.legal_entity_id AND id <> NEW.id AND status IN ('APPROVED', 'RETIRED')
   ORDER BY version DESC LIMIT 1;
  IF prev.id IS NOT NULL AND (prev.grni_account_id <> NEW.grni_account_id OR prev.ap_account_id <> NEW.ap_account_id) THEN
    RAISE EXCEPTION 'a successor P2P policy keeps the GRNI and AP control accounts of the policy in force' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER p2p_policies_approval_control BEFORE UPDATE ON p2p_policies FOR EACH ROW
  WHEN (OLD.status = 'DRAFT' AND NEW.status = 'APPROVED') EXECUTE FUNCTION p2p_policies_approval_control();

-- ===========================================================================
-- L-B: one statement import at a time per bank account
-- ===========================================================================
-- Fires before bank_statements_guard (trigger names sort "chain" < "guard");
-- the guard's continuity query then sees any statement committed meanwhile.
CREATE OR REPLACE FUNCTION bank_statements_chain_lock() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM 1 FROM company_bank_accounts WHERE id = NEW.company_bank_id AND tenant_id = current_tenant() FOR NO KEY UPDATE;
  RETURN NEW;
END$$;
CREATE TRIGGER bank_statements_chain_lock BEFORE INSERT ON bank_statements FOR EACH ROW EXECUTE FUNCTION bank_statements_chain_lock();

-- ===========================================================================
-- L-C: human marker on every payment attestation presented
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_assert_human(p_actor text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  IF p_actor IS NULL OR p_actor ~* '^(system|ai|agent|bot|service|svc)[:_./-]' THEN
    RAISE EXCEPTION 'payments are authorised only by human principals (actor %)', p_actor USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- Every payment.approve / payment.release attestation this actor
  -- presents in the transaction must carry the platform-signed marker, so
  -- the one approval_use consumes carries it too.
  IF NOT EXISTS (SELECT 1 FROM approval_attestations a
                  WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.actor = p_actor
                    AND a.action IN ('payment.approve', 'payment.release') AND a.subject_type = 'payment_instruction')
     OR EXISTS (SELECT 1 FROM approval_attestations a
                 WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.actor = p_actor
                   AND a.action IN ('payment.approve', 'payment.release') AND a.subject_type = 'payment_instruction'
                   AND NOT ('principal.human' = ANY (a.perms))) THEN
    RAISE EXCEPTION 'payments are authorised only by principals the identity provider asserts are human (actor %)', p_actor
      USING ERRCODE = 'insufficient_privilege';
  END IF;
END$$;

-- ===========================================================================
-- L-D: control accounts of every policy version
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_is_control_account(p_account uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM company_bank_accounts b WHERE b.tenant_id = current_tenant() AND p_account IN (b.gl_account_id, b.clearing_account_id))
      OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant()
                    AND p_account IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id))
$$;

CREATE OR REPLACE FUNCTION company_bank_accounts_control() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.gl_account_id = NEW.clearing_account_id
     OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant()
                   AND (NEW.gl_account_id IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id)
                     OR NEW.clearing_account_id IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id)))
     OR EXISTS (SELECT 1 FROM po_lines l WHERE l.tenant_id = current_tenant() AND l.account_id IN (NEW.gl_account_id, NEW.clearing_account_id)) THEN
    RAISE EXCEPTION 'bank and payments-in-transit accounts must be distinct and not used as P2P control or PO cost accounts' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- ===========================================================================
-- Info: created_txid is the database's value, never the caller's
-- ===========================================================================
CREATE OR REPLACE FUNCTION journals_created_txid() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_txid := txid_current();
  ELSE
    NEW.created_txid := OLD.created_txid;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_created_txid BEFORE INSERT OR UPDATE ON journals FOR EACH ROW EXECUTE FUNCTION journals_created_txid();

-- ...and the tenant login has no INSERT privilege on it at all: the
-- table-level INSERT grant is replaced by column-level grants on every other
-- column (same effective rights otherwise).
DO $$
DECLARE cols text;
BEGIN
  SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO cols
    FROM pg_attribute WHERE attrelid = 'journals'::regclass AND attnum > 0 AND NOT attisdropped AND attname <> 'created_txid';
  REVOKE INSERT ON journals FROM serk_app;
  EXECUTE format('GRANT INSERT (%s) ON journals TO serk_app', cols);
END$$;
