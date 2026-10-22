-- 0033: credit notes that correct a measured quantity (JB-CREDIT-QTY).
--
-- Measurement lines are strictly positive, so a verified cumulative quantity
-- never decreases: an over-measurement certified on an IPC can only be
-- corrected by a credit note. Until now a credit note was a pure AR
-- concession, and the contract-quantity cap then absorbed the same
-- over-measurement again on later measurements, so the client was credited
-- twice for the same work (register JB-CREDIT-QTY, "procedure only").
--
-- A credit note now has a kind:
--   COMMERCIAL           as before: a settlement with no quantity effect;
--   QUANTITY_CORRECTION  names a contract line and a quantity; its net is
--                        exactly quantity x line rate. Once APPROVED it
--                        reduces the line's verified quantity (the cap and
--                        the IPC cumulative), and the IPC's "previously
--                        certified" is reduced by its net, so the next
--                        certificate neither deducts the work again nor
--                        re-bills what was credited. The remaining real work
--                        can be measured up to the contract quantity.

ALTER TABLE customer_credit_notes
  ADD COLUMN kind text NOT NULL DEFAULT 'COMMERCIAL' CHECK (kind IN ('COMMERCIAL', 'QUANTITY_CORRECTION')),
  ADD COLUMN correction_line_no integer CHECK (correction_line_no BETWEEN 1 AND 9999),
  ADD COLUMN correction_qty numeric(20,4) CHECK (correction_qty > 0),
  ADD CONSTRAINT customer_credit_notes_correction_form
    CHECK ((kind = 'QUANTITY_CORRECTION') = (correction_line_no IS NOT NULL AND correction_qty IS NOT NULL));

-- Credited quantity of a contract line (approved quantity corrections).
CREATE OR REPLACE FUNCTION contract_credited_qty(p_contract uuid, p_line integer, p_exclude_credit uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(correction_qty), 0) FROM customer_credit_notes
   WHERE tenant_id = current_tenant() AND contract_id = p_contract AND correction_line_no = p_line
     AND kind = 'QUANTITY_CORRECTION' AND status = 'APPROVED' AND id IS DISTINCT FROM p_exclude_credit
$$;

-- Verified quantity net of approved quantity corrections (the 0018 body
-- minus contract_credited_qty). Used by the measurement cap, variations and
-- the IPC cumulative.
CREATE OR REPLACE FUNCTION contract_verified_qty(p_contract uuid, p_line integer, p_exclude_measurement uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT sum(ml.quantity) FROM measurement_lines ml JOIN measurements m ON m.id = ml.measurement_id
                    WHERE m.tenant_id = current_tenant() AND m.contract_id = p_contract AND ml.contract_line_no = p_line AND m.status = 'VERIFIED'
                      AND m.id IS DISTINCT FROM p_exclude_measurement), 0)
       - contract_credited_qty(p_contract, p_line, NULL)
$$;

-- The 0020 body with "previously certified" net of approved quantity
-- corrections.
CREATE OR REPLACE FUNCTION ipc_compute(p_contract uuid, p_exclude_ipc uuid,
  OUT cumulative_gross numeric, OUT previous_gross numeric, OUT this_gross numeric, OUT retention_amount numeric,
  OUT advance_recovery numeric, OUT vat_amount numeric, OUT amount_due numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE c contracts; pol contract_policies; recovered numeric; received numeric; credited numeric;
BEGIN
  SELECT * INTO c FROM contracts WHERE id = p_contract AND tenant_id = current_tenant();
  SELECT * INTO pol FROM contract_policies WHERE id = c.policy_id;
  SELECT COALESCE(sum(p2p_round(contract_verified_qty(c.id, l.line_no, NULL) * l.rate, c.currency)), 0) INTO cumulative_gross
    FROM contract_lines l WHERE l.contract_id = c.id;
  SELECT COALESCE(sum(i.this_gross), 0), COALESCE(sum(i.advance_recovery), 0) INTO previous_gross, recovered
    FROM ipcs i WHERE i.contract_id = c.id AND i.status IN ('CERTIFIED', 'INVOICED') AND i.id IS DISTINCT FROM p_exclude_ipc;
  SELECT COALESCE(sum(net_amount), 0) INTO credited FROM customer_credit_notes
   WHERE contract_id = c.id AND kind = 'QUANTITY_CORRECTION' AND status = 'APPROVED';
  previous_gross := previous_gross - credited;
  this_gross := cumulative_gross - previous_gross;
  retention_amount := p2p_round(this_gross * c.retention_pct, c.currency);
  received := contract_advance_received(c.id);
  advance_recovery := greatest(0, least(p2p_round(this_gross * c.advance_recovery_pct, c.currency), received - recovered));
  advance_recovery := least(advance_recovery, greatest(0, this_gross - retention_amount));
  vat_amount := p2p_round(CASE pol.vat_base WHEN 'GROSS' THEN this_gross ELSE this_gross - advance_recovery END * pol.vat_rate, c.currency);
  amount_due := this_gross - retention_amount - advance_recovery + vat_amount;
END$$;

-- A quantity correction names a line of the credited invoice's contract, a
-- quantity not above what is verified (net of earlier corrections, drafts
-- included at recording, re-checked under the contract lock at approval),
-- and a net of exactly quantity x rate.
CREATE OR REPLACE FUNCTION customer_credit_notes_correction() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE cl contract_lines; c contracts; verified numeric; pending numeric;
BEGIN
  IF NEW.kind <> 'QUANTITY_CORRECTION' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND NOT (OLD.status = 'DRAFT' AND NEW.status = 'APPROVED') THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id FOR UPDATE;
  END IF;
  SELECT * INTO cl FROM contract_lines WHERE contract_id = NEW.contract_id AND line_no = NEW.correction_line_no;
  IF cl.contract_id IS NULL THEN
    RAISE EXCEPTION 'quantity correction: contract line % does not exist', NEW.correction_line_no USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.net_amount <> p2p_round(NEW.correction_qty * cl.rate, NEW.currency) THEN
    RAISE EXCEPTION 'quantity correction: the net amount must be % x the line rate % = %', NEW.correction_qty, cl.rate,
      p2p_round(NEW.correction_qty * cl.rate, NEW.currency) USING ERRCODE = 'check_violation';
  END IF;
  verified := contract_verified_qty(NEW.contract_id, NEW.correction_line_no, NULL);
  SELECT COALESCE(sum(correction_qty), 0) INTO pending FROM customer_credit_notes
   WHERE contract_id = NEW.contract_id AND correction_line_no = NEW.correction_line_no AND kind = 'QUANTITY_CORRECTION'
     AND status = 'DRAFT' AND id <> NEW.id;
  IF NEW.correction_qty + pending > verified THEN
    RAISE EXCEPTION 'quantity correction of % on line % exceeds the verified quantity % (less % in other draft corrections)',
      NEW.correction_qty, NEW.correction_line_no, verified, pending USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
-- Named to run after the 0022 guard (which copies the contract from the invoice).
CREATE TRIGGER customer_credit_notes_zcorrection BEFORE INSERT OR UPDATE ON customer_credit_notes FOR EACH ROW EXECUTE FUNCTION customer_credit_notes_correction();
REVOKE ALL ON FUNCTION customer_credit_notes_correction() FROM PUBLIC;
REVOKE ALL ON FUNCTION contract_credited_qty(uuid, integer, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contract_credited_qty(uuid, integer, uuid) TO serk_app;
