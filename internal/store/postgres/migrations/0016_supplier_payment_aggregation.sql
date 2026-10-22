-- 0016: supplier-level aggregation for dual payment approval (R-SPLIT-SUPPLIER)
-- and one definition of "needs two approvers" shared by the database and the
-- kernel. Additive: one policy column with a default, one helper, the payment
-- guard body replaced (same trigger, same signature, grants kept).
--
-- A payment needs two approvers when ANY of these reaches the entity policy's
-- dual_payment_threshold:
--   * its own amount;
--   * the total of an invoice it pays (0014, L2);
--   * NEW: its amount plus every other live payment (SUBMITTED onwards, not
--     cancelled) to the same supplier of the same entity whose value date lies
--     within dual_payment_window_days of it, so splitting one obligation
--     across invoices or days does not avoid dual approval.
-- Concurrent approvals for one supplier are serialised (row lock on the
-- supplier), so two "small" payments cannot both slip through in parallel.

ALTER TABLE p2p_policies ADD COLUMN dual_payment_window_days integer NOT NULL DEFAULT 30
  CHECK (dual_payment_window_days BETWEEN 1 AND 366);

CREATE OR REPLACE FUNCTION p2p_payment_needs_dual(p payment_instructions) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE pol p2p_policies; exposure numeric;
BEGIN
  SELECT * INTO pol FROM p2p_policies WHERE id = COALESCE(p.policy_id, (p2p_policy_for(p.legal_entity_id)).id) AND tenant_id = current_tenant();
  IF pol.id IS NULL THEN
    RETURN true;  -- no policy: never relax
  END IF;
  IF p.amount >= pol.dual_payment_threshold THEN
    RETURN true;
  END IF;
  IF EXISTS (SELECT 1 FROM payment_allocations a JOIN supplier_invoices i ON i.id = a.invoice_id
              WHERE a.payment_id = p.id AND i.total >= pol.dual_payment_threshold) THEN
    RETURN true;
  END IF;
  SELECT COALESCE(sum(o.amount), 0) INTO exposure FROM payment_instructions o
   WHERE o.tenant_id = current_tenant() AND o.supplier_id = p.supplier_id AND o.legal_entity_id = p.legal_entity_id AND o.id <> p.id
     AND o.status IN ('SUBMITTED', 'PARTIALLY_APPROVED', 'APPROVED', 'RELEASED', 'SETTLED')
     AND abs(o.value_date - p.value_date) < pol.dual_payment_window_days;
  RETURN exposure + p.amount >= pol.dual_payment_threshold;
END$$;

CREATE OR REPLACE FUNCTION p2p_payment_needs_dual_id(p_payment uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT p2p_payment_needs_dual(p) FROM payment_instructions p WHERE p.id = p_payment AND p.tenant_id = current_tenant()
$$;

-- Serialise approval decisions per supplier.
CREATE OR REPLACE FUNCTION payment_instructions_supplier_lock() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM 1 FROM suppliers WHERE id = NEW.supplier_id AND tenant_id = current_tenant() FOR NO KEY UPDATE;
  RETURN NEW;
END$$;
-- Name sorts before payment_instructions_guard so the lock is taken first.
CREATE TRIGGER payment_instructions_a_supplier_lock BEFORE UPDATE OF status ON payment_instructions FOR EACH ROW
  WHEN (OLD.status = 'SUBMITTED' AND NEW.status IN ('APPROVED', 'PARTIALLY_APPROVED')) EXECUTE FUNCTION payment_instructions_supplier_lock();

CREATE OR REPLACE FUNCTION payment_instructions_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE pol p2p_policies; alloc numeric; over record; sb supplier_bank_accounts; cb company_bank_accounts; line_id uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO sb FROM supplier_bank_accounts WHERE id = NEW.supplier_bank_id AND tenant_id = current_tenant();
    SELECT * INTO cb FROM company_bank_accounts WHERE id = NEW.company_bank_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.released_by IS NOT NULL OR NEW.release_journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'payment instructions are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF sb.supplier_id IS DISTINCT FROM NEW.supplier_id OR sb.currency <> NEW.currency OR cb.currency <> NEW.currency
       OR cb.legal_entity_id <> NEW.legal_entity_id THEN
      RAISE EXCEPTION 'payee account must belong to the supplier and paying account to the entity, both in the payment currency' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM assert_currency_precision(NEW.amount, NEW.currency, 'payment amount');
    NEW.bank_snapshot := p2p_bank_snapshot(NEW.supplier_bank_id);  -- computed, never accepted
    PERFORM p2p_assert_payee(NEW);
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'payment instruction');
    RETURN NEW;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at', 'policy_id'], 'payment instruction');
    SELECT COALESCE(sum(amount), 0) INTO alloc FROM payment_allocations WHERE payment_id = NEW.id;
    IF alloc <> NEW.amount THEN
      RAISE EXCEPTION 'allocations (%) must equal the payment amount (%)', alloc, NEW.amount USING ERRCODE = 'check_violation';
    END IF;
    -- Serialise against other payments of the same invoices, then check
    -- that no invoice is paid beyond its total.
    PERFORM 1 FROM supplier_invoices i JOIN payment_allocations a ON a.invoice_id = i.id WHERE a.payment_id = NEW.id FOR UPDATE OF i;
    SELECT i.invoice_number, i.total, i.status, i.supplier_id, i.currency,
           (SELECT COALESCE(sum(a2.amount), 0) FROM payment_allocations a2 JOIN payment_instructions p2 ON p2.id = a2.payment_id
             WHERE a2.invoice_id = i.id AND p2.status NOT IN ('DRAFT', 'CANCELLED') AND p2.id <> NEW.id) + a.amount AS paid
      INTO over
      FROM payment_allocations a JOIN supplier_invoices i ON i.id = a.invoice_id
     WHERE a.payment_id = NEW.id
       AND (i.status <> 'APPROVED' OR i.supplier_id <> NEW.supplier_id OR i.currency <> NEW.currency
            OR (SELECT COALESCE(sum(a2.amount), 0) FROM payment_allocations a2 JOIN payment_instructions p2 ON p2.id = a2.payment_id
                 WHERE a2.invoice_id = i.id AND p2.status NOT IN ('DRAFT', 'CANCELLED') AND p2.id <> NEW.id) + a.amount > i.total)
     LIMIT 1;
    IF over.invoice_number IS NOT NULL THEN
      RAISE EXCEPTION 'invoice % cannot take this allocation (status %, total %, would be paid %)', over.invoice_number, over.status, over.total, over.paid
        USING ERRCODE = 'check_violation';
    END IF;
    pol := p2p_policy_for(NEW.legal_entity_id);
    IF pol.id IS NULL THEN
      RAISE EXCEPTION 'no approved P2P policy for the entity' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM p2p_assert_payee(NEW);
    PERFORM approval_use('payment.submit', 'payment_instruction', NEW.id::text, NEW.created_by, ARRAY['payment.prepare'], false, NULL, NULL);
    NEW.policy_id := pol.id;
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status IN ('APPROVED', 'PARTIALLY_APPROVED') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'payment instruction');
    PERFORM p2p_assert_human(NEW.approved_by);
    PERFORM p2p_assert_payee(NEW);
    SELECT * INTO pol FROM p2p_policies WHERE id = NEW.policy_id;
    IF p2p_payment_needs_dual(NEW) <> (NEW.status = 'PARTIALLY_APPROVED') THEN
      RAISE EXCEPTION 'this payment needs % approver(s): amount, invoice or supplier exposure at or above % % within % days (first approval -> PARTIALLY_APPROVED)',
        CASE WHEN p2p_payment_needs_dual(NEW) THEN 'two' ELSE 'one' END, pol.dual_payment_threshold, NEW.currency, pol.dual_payment_window_days
        USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('payment.approve', 'payment_instruction', NEW.id::text, NEW.approved_by, ARRAY['payment.approve'], true, NEW.status, NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'PARTIALLY_APPROVED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'second_approved_by', 'second_approved_at'], 'payment instruction');
    PERFORM p2p_assert_human(NEW.second_approved_by);
    PERFORM p2p_assert_payee(NEW);
    PERFORM approval_use('payment.approve', 'payment_instruction', NEW.id::text, NEW.second_approved_by, ARRAY['payment.approve'], true, 'APPROVED', NULL);
    NEW.second_approved_at := now();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'RELEASED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'released_by', 'released_at', 'release_journal_id'], 'payment instruction');
    PERFORM p2p_assert_human(NEW.released_by);
    PERFORM p2p_assert_payee(NEW);
    PERFORM approval_use('payment.release', 'payment_instruction', NEW.id::text, NEW.released_by, ARRAY['payment.release'], true, 'RELEASED', NULL);
    PERFORM p2p_assert_journal(NEW.release_journal_id, 'P2P_PAYMENT', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.value_date);
    NEW.released_at := now();
  ELSIF OLD.status = 'RELEASED' AND NEW.status = 'SETTLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'settled_at'], 'payment instruction');
    -- Only from the bank: the statement line matched to it in this
    -- transaction, under the reconciler's attestation.
    SELECT id INTO line_id FROM bank_statement_lines WHERE payment_id = NEW.id AND status = 'MATCHED';
    IF line_id IS NULL OR approval_consumed_in_tx(ARRAY['bank.reconcile'], 'bank_statement_line', line_id::text, NEW.id::text) IS NULL THEN
      RAISE EXCEPTION 'a payment is settled only by reconciling it with a bank statement line' USING ERRCODE = 'insufficient_privilege';
    END IF;
    NEW.settled_at := now();
  ELSIF OLD.status IN ('DRAFT', 'SUBMITTED', 'PARTIALLY_APPROVED', 'APPROVED') AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'cancel_reason'], 'payment instruction');
    IF NEW.cancel_reason IS NULL OR length(btrim(NEW.cancel_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling a payment requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('payment.cancel', 'payment_instruction', NEW.id::text, NULL, ARRAY['payment.prepare', 'payment.approve'], false, NULL, NULL);
  ELSE
    RAISE EXCEPTION 'illegal payment transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

GRANT EXECUTE ON FUNCTION p2p_payment_needs_dual(payment_instructions), p2p_payment_needs_dual_id(uuid) TO serk_app;
