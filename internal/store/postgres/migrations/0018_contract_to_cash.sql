-- 0017: Journey B, contract to cash (GATEC-02).
--
--   customer + approved contract (BOQ-linked lines, retention, advance terms)
--   -> site measurement (quantity surveyor) -> verification (site engineer)
--   -> IPC computed by the database from cumulative verified quantities
--   -> certification (commercial manager, MFA, client certificate reference)
--   -> customer invoice (AR clerk) -> approval (AR supervisor) -> AR journal
--   -> bank receipt (money-in statement line) allocated to invoices / contract
--      advance (AR clerk) -> confirmation (AR supervisor, independent of the
--      statement importer) -> receipt journal -> finance approve/post -> GL.
--
-- Principles are those of ADR 0008/0009/0010: attested transitions; the
-- database computes every amount; subledger journals (source types AR_*) are
-- generated DRAFT from the database's expected lines, bound to their
-- document, frozen at birth and re-checked at approve/post; finance approves
-- and posts them through the ordinary journal commands. Tax: the VAT rate and
-- VAT base are tenant configuration on the contract policy, not tax advice
-- (finance/tax sign-off: GATEP-03).

-- ===========================================================================
-- Tables
-- ===========================================================================
CREATE TABLE customers (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  code            text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9-]{1,31}$'),
  name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 200),
  tax_id          text CHECK (tax_id IS NULL OR length(btrim(tax_id)) BETWEEN 3 AND 40),
  status          text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'BLOCKED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  approved_by     text,
  approved_at     timestamptz,
  blocked_reason  text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, id),
  UNIQUE (tenant_id, legal_entity_id, code),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  CONSTRAINT customer_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE contract_policies (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id       uuid NOT NULL,
  version               integer NOT NULL CHECK (version >= 1),
  currency              char(3) NOT NULL REFERENCES currencies(code),
  vat_rate              numeric(7,6) NOT NULL CHECK (vat_rate >= 0 AND vat_rate < 1),
  vat_base              text NOT NULL DEFAULT 'GROSS_LESS_ADVANCE' CHECK (vat_base IN ('GROSS', 'GROSS_LESS_ADVANCE')),
  ar_account_id         uuid NOT NULL,
  retention_account_id  uuid NOT NULL,
  advance_account_id    uuid NOT NULL,
  revenue_account_id    uuid NOT NULL,
  vat_output_account_id uuid NOT NULL,
  status                text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED', 'RETIRED')),
  created_by            text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  approved_by           text,
  approved_at           timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, version),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  FOREIGN KEY (tenant_id, ar_account_id) REFERENCES accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, retention_account_id) REFERENCES accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, advance_account_id) REFERENCES accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, revenue_account_id) REFERENCES accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, vat_output_account_id) REFERENCES accounts(tenant_id, id),
  CONSTRAINT contract_policy_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE UNIQUE INDEX contract_policies_one_approved ON contract_policies (tenant_id, legal_entity_id) WHERE status = 'APPROVED';

CREATE TABLE contracts (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id      uuid NOT NULL,
  project_id           uuid NOT NULL,
  customer_id          uuid NOT NULL,
  number               text NOT NULL,
  title                text NOT NULL CHECK (length(btrim(title)) BETWEEN 3 AND 300),
  client_reference     text NOT NULL CHECK (length(btrim(client_reference)) BETWEEN 2 AND 100),
  signed_on            date NOT NULL,
  currency             char(3) NOT NULL REFERENCES currencies(code),
  contract_value       numeric(24,6) NOT NULL DEFAULT 0,
  retention_pct        numeric(7,6) NOT NULL CHECK (retention_pct >= 0 AND retention_pct <= 0.2),
  advance_amount       numeric(24,6) NOT NULL DEFAULT 0 CHECK (advance_amount >= 0),
  advance_recovery_pct numeric(7,6) NOT NULL DEFAULT 0 CHECK (advance_recovery_pct >= 0 AND advance_recovery_pct <= 1),
  policy_id            uuid,
  status               text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'ACTIVE', 'REJECTED', 'CLOSED')),
  created_by           text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  submitted_at         timestamptz,
  approved_by          text,
  approved_at          timestamptz,
  approver_mfa         boolean NOT NULL DEFAULT false,
  decision_reason      text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, customer_id) REFERENCES customers(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES contract_policies(tenant_id, id),
  CONSTRAINT contract_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by),
  CONSTRAINT contract_advance_within_value CHECK (status IN ('DRAFT', 'REJECTED') OR advance_amount <= contract_value)
);

CREATE TABLE contract_lines (
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  contract_id uuid NOT NULL,
  line_no     integer NOT NULL CHECK (line_no BETWEEN 1 AND 9999),
  boq_item_id uuid,
  description text NOT NULL CHECK (length(btrim(description)) BETWEEN 2 AND 500),
  unit        text NOT NULL CHECK (unit ~ '^[A-Za-z0-9/.²³]{1,12}$'),
  quantity    numeric(20,4) NOT NULL CHECK (quantity > 0),
  rate        numeric(24,6) NOT NULL CHECK (rate >= 0),
  amount      numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (contract_id, line_no),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  FOREIGN KEY (tenant_id, boq_item_id) REFERENCES boq_items(tenant_id, id)
);

CREATE TABLE measurements (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  contract_id     uuid NOT NULL,
  number          text NOT NULL,
  period_end      date NOT NULL,
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'VERIFIED', 'REJECTED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  submitted_at    timestamptz,
  verified_by     text,
  verified_at     timestamptz,
  decision_reason text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  CONSTRAINT measurement_maker_checker CHECK (verified_by IS NULL OR verified_by <> created_by)
);
-- One live measurement sheet per contract and period (no repeated measurement).
CREATE UNIQUE INDEX measurements_one_per_period ON measurements (tenant_id, contract_id, period_end) WHERE status <> 'REJECTED';

CREATE TABLE measurement_lines (
  tenant_id        uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  measurement_id   uuid NOT NULL,
  contract_line_no integer NOT NULL,
  quantity         numeric(20,4) NOT NULL CHECK (quantity > 0),
  location         text CHECK (location IS NULL OR length(location) <= 200),
  PRIMARY KEY (measurement_id, contract_line_no),
  FOREIGN KEY (tenant_id, measurement_id) REFERENCES measurements(tenant_id, id)
);

CREATE TABLE ipcs (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  contract_id        uuid NOT NULL,
  number             text NOT NULL,
  seq                integer NOT NULL CHECK (seq >= 1),
  period_end         date NOT NULL,
  currency           char(3) NOT NULL REFERENCES currencies(code),
  policy_id          uuid NOT NULL,
  cumulative_gross   numeric(24,6) NOT NULL DEFAULT 0,
  previous_gross     numeric(24,6) NOT NULL DEFAULT 0,
  this_gross         numeric(24,6) NOT NULL DEFAULT 0,
  retention_amount   numeric(24,6) NOT NULL DEFAULT 0,
  advance_recovery   numeric(24,6) NOT NULL DEFAULT 0,
  vat_amount         numeric(24,6) NOT NULL DEFAULT 0,
  amount_due         numeric(24,6) NOT NULL DEFAULT 0,
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'CERTIFIED', 'REJECTED', 'CANCELLED', 'INVOICED')),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  submitted_at       timestamptz,
  certified_by       text,
  certified_at       timestamptz,
  certifier_mfa      boolean NOT NULL DEFAULT false,
  certificate_ref    text,
  certificate_sha256 text CHECK (certificate_sha256 IS NULL OR certificate_sha256 ~ '^[0-9a-f]{64}$'),
  decision_reason    text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES contract_policies(tenant_id, id),
  CONSTRAINT ipc_maker_checker CHECK (certified_by IS NULL OR certified_by <> created_by)
);
CREATE UNIQUE INDEX ipcs_one_open ON ipcs (tenant_id, contract_id) WHERE status IN ('DRAFT', 'SUBMITTED');

CREATE TABLE customer_invoices (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id  uuid NOT NULL,
  project_id       uuid NOT NULL,
  contract_id      uuid NOT NULL,
  customer_id      uuid NOT NULL,
  ipc_id           uuid NOT NULL UNIQUE,
  policy_id        uuid NOT NULL,
  number           text NOT NULL,
  invoice_date     date NOT NULL,
  due_date         date NOT NULL,
  currency         char(3) NOT NULL REFERENCES currencies(code),
  gross            numeric(24,6) NOT NULL DEFAULT 0,
  retention_amount numeric(24,6) NOT NULL DEFAULT 0,
  advance_recovery numeric(24,6) NOT NULL DEFAULT 0,
  vat_amount       numeric(24,6) NOT NULL DEFAULT 0,
  total            numeric(24,6) NOT NULL DEFAULT 0,
  status           text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED')),
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  approved_by      text,
  approved_at      timestamptz,
  journal_id       uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  FOREIGN KEY (tenant_id, ipc_id) REFERENCES ipcs(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES contract_policies(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, customer_id) REFERENCES customers(tenant_id, legal_entity_id, id),
  CONSTRAINT customer_invoice_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by),
  CONSTRAINT customer_invoice_due CHECK (due_date >= invoice_date)
);

CREATE TABLE customer_receipts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id   uuid NOT NULL,
  number            text NOT NULL,
  statement_line_id uuid NOT NULL UNIQUE,
  company_bank_id   uuid NOT NULL,
  receipt_date      date NOT NULL,
  currency          char(3) NOT NULL REFERENCES currencies(code),
  amount            numeric(24,6) NOT NULL DEFAULT 0,
  status            text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'CONFIRMED', 'CANCELLED')),
  created_by        text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  confirmed_by      text,
  confirmed_at      timestamptz,
  cancel_reason     text,
  journal_id        uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, statement_line_id) REFERENCES bank_statement_lines(tenant_id, id),
  FOREIGN KEY (tenant_id, company_bank_id) REFERENCES company_bank_accounts(tenant_id, id),
  CONSTRAINT customer_receipt_maker_checker CHECK (confirmed_by IS NULL OR confirmed_by <> created_by)
);

CREATE TABLE receipt_allocations (
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  receipt_id  uuid NOT NULL,
  line_no     integer NOT NULL CHECK (line_no BETWEEN 1 AND 500),
  invoice_id  uuid,
  contract_id uuid,
  amount      numeric(24,6) NOT NULL CHECK (amount > 0),
  PRIMARY KEY (receipt_id, line_no),
  FOREIGN KEY (tenant_id, receipt_id) REFERENCES customer_receipts(tenant_id, id),
  FOREIGN KEY (tenant_id, invoice_id) REFERENCES customer_invoices(tenant_id, id),
  FOREIGN KEY (tenant_id, contract_id) REFERENCES contracts(tenant_id, id),
  CONSTRAINT receipt_allocation_one_target CHECK ((invoice_id IS NULL) <> (contract_id IS NULL))
);
CREATE UNIQUE INDEX receipt_allocations_once ON receipt_allocations (receipt_id, COALESCE(invoice_id, contract_id));

-- ===========================================================================
-- Computation
-- ===========================================================================
CREATE OR REPLACE FUNCTION contract_policy_for(p_entity uuid) RETURNS contract_policies
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT * FROM contract_policies WHERE tenant_id = current_tenant() AND legal_entity_id = p_entity AND status = 'APPROVED'
$$;

-- Cumulative verified quantity of a contract line.
CREATE OR REPLACE FUNCTION contract_verified_qty(p_contract uuid, p_line integer, p_exclude_measurement uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(ml.quantity), 0) FROM measurement_lines ml JOIN measurements m ON m.id = ml.measurement_id
   WHERE m.tenant_id = current_tenant() AND m.contract_id = p_contract AND ml.contract_line_no = p_line AND m.status = 'VERIFIED'
     AND m.id IS DISTINCT FROM p_exclude_measurement
$$;

-- Advance received for a contract (confirmed receipt allocations).
CREATE OR REPLACE FUNCTION contract_advance_received(p_contract uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(a.amount), 0) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id
   WHERE a.tenant_id = current_tenant() AND a.contract_id = p_contract AND r.status = 'CONFIRMED'
$$;

-- The certificate the contract's verified measurements support now. Every
-- figure of an IPC comes from here, at creation and again at submit and at
-- certification (a measurement verified meanwhile makes the IPC stale).
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
  vat_amount := p2p_round(CASE pol.vat_base WHEN 'GROSS' THEN this_gross ELSE this_gross - advance_recovery END * pol.vat_rate, c.currency);
  amount_due := this_gross - retention_amount - advance_recovery + vat_amount;
END$$;

-- ===========================================================================
-- Guards
-- ===========================================================================
-- Attested creation for documents without a creator-attested submit step.
CREATE OR REPLACE FUNCTION ar_creation_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE act text; typ text; perm text;
BEGIN
  CASE TG_TABLE_NAME
    WHEN 'customers' THEN act := 'customer.create'; typ := 'customer'; perm := 'customer.manage';
    WHEN 'contract_policies' THEN act := 'contract.policy.create'; typ := 'contract_policy'; perm := 'contract.policy.manage';
    WHEN 'customer_invoices' THEN act := 'ar.invoice.create'; typ := 'customer_invoice'; perm := 'ar.invoice.create';
    WHEN 'customer_receipts' THEN act := 'ar.receipt.create'; typ := 'customer_receipt'; perm := 'ar.receipt.create';
    ELSE RAISE EXCEPTION 'ar_creation_attested: unexpected table %', TG_TABLE_NAME;
  END CASE;
  PERFORM approval_use(act, typ, NEW.id::text, NEW.created_by, ARRAY[perm], false, NULL, NULL);
  RETURN NULL;
END$$;

CREATE OR REPLACE FUNCTION customers_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL OR NEW.blocked_reason IS NOT NULL THEN
      RAISE EXCEPTION 'customers are created PENDING' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'customer');
  ELSIF NEW.status = 'ACTIVE' AND OLD.status IN ('PENDING', 'BLOCKED') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'blocked_reason'], 'customer');
    PERFORM approval_use('customer.approve', 'customer', NEW.id::text, NEW.approved_by, ARRAY['customer.approve'], false, 'ACTIVE', NULL);
    NEW.approved_at := now();
    NEW.blocked_reason := NULL;
  ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'BLOCKED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'blocked_reason'], 'customer');
    IF NEW.blocked_reason IS NULL OR length(btrim(NEW.blocked_reason)) < 5 THEN
      RAISE EXCEPTION 'blocking a customer requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('customer.block', 'customer', NEW.id::text, NULL, ARRAY['customer.approve'], false, 'BLOCKED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal customer transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER customers_guard BEFORE INSERT OR UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION customers_guard();

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
    IF p2p_is_control_account(NEW.ar_account_id) OR p2p_is_control_account(NEW.retention_account_id) OR p2p_is_control_account(NEW.advance_account_id)
       OR p2p_is_control_account(NEW.vat_output_account_id) THEN
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
CREATE TRIGGER contract_policies_guard BEFORE INSERT OR UPDATE ON contract_policies FOR EACH ROW EXECUTE FUNCTION contract_policies_guard();

CREATE OR REPLACE FUNCTION contracts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE le legal_entities; pol contract_policies;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO le FROM legal_entities WHERE id = NEW.legal_entity_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.policy_id IS NOT NULL OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'contracts are created DRAFT in the entity''s functional currency' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT status FROM customers WHERE id = NEW.customer_id) IS DISTINCT FROM 'ACTIVE' THEN
      RAISE EXCEPTION 'contracts are made with ACTIVE customers' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM assert_currency_precision(NEW.advance_amount, NEW.currency, 'advance amount');
    NEW.contract_value := 0;
    NEW.approver_mfa := false;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'contract');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at', 'contract_value'], 'contract');
    NEW.contract_value := COALESCE((SELECT sum(amount) FROM contract_lines WHERE contract_id = NEW.id), 0);
    IF NEW.contract_value <= 0 THEN
      RAISE EXCEPTION 'a contract needs priced lines' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.advance_amount > NEW.contract_value THEN
      RAISE EXCEPTION 'the advance (%) exceeds the contract value (%)', NEW.advance_amount, NEW.contract_value USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.submit', 'contract', NEW.id::text, NEW.created_by, ARRAY['contract.manage'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'ACTIVE' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approver_mfa', 'policy_id', 'decision_reason'], 'contract');
    pol := contract_policy_for(NEW.legal_entity_id);
    IF pol.id IS NULL THEN
      RAISE EXCEPTION 'no approved contract policy for the entity' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT status FROM customers WHERE id = NEW.customer_id) IS DISTINCT FROM 'ACTIVE' THEN
      RAISE EXCEPTION 'the customer is not ACTIVE' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.decide', 'contract', NEW.id::text, NEW.approved_by, ARRAY['contract.approve'], true, 'ACTIVE', NULL);
    NEW.policy_id := pol.id;
    NEW.approver_mfa := true;
    NEW.approved_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'contract');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a contract requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('contract.decide', 'contract', NEW.id::text, NULL, ARRAY['contract.approve'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal contract transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER contracts_guard BEFORE INSERT OR UPDATE ON contracts FOR EACH ROW EXECUTE FUNCTION contracts_guard();

CREATE OR REPLACE FUNCTION contract_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts;
BEGIN
  SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant() FOR SHARE;
  IF c.status IS DISTINCT FROM 'DRAFT' THEN
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
CREATE TRIGGER contract_lines_guard BEFORE INSERT ON contract_lines FOR EACH ROW EXECUTE FUNCTION contract_lines_guard();

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
    FOR l IN SELECT ml.contract_line_no, ml.quantity, cl.quantity AS contract_qty
               FROM measurement_lines ml JOIN contract_lines cl ON cl.contract_id = NEW.contract_id AND cl.line_no = ml.contract_line_no
              WHERE ml.measurement_id = NEW.id LOOP
      IF contract_verified_qty(NEW.contract_id, l.contract_line_no, NEW.id) + l.quantity > l.contract_qty THEN
        RAISE EXCEPTION 'contract line %: cumulative measured % exceeds the contract quantity % (a variation is required)',
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
CREATE TRIGGER measurements_guard BEFORE INSERT OR UPDATE ON measurements FOR EACH ROW EXECUTE FUNCTION measurements_guard();

CREATE OR REPLACE FUNCTION measurement_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE m measurements;
BEGIN
  SELECT * INTO m FROM measurements WHERE id = NEW.measurement_id AND tenant_id = current_tenant() FOR SHARE;
  IF m.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'measurement lines change only while the measurement is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM contract_lines WHERE contract_id = m.contract_id AND line_no = NEW.contract_line_no) THEN
    RAISE EXCEPTION 'measurement line refers to contract line % which does not exist', NEW.contract_line_no USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER measurement_lines_guard BEFORE INSERT ON measurement_lines FOR EACH ROW EXECUTE FUNCTION measurement_lines_guard();

CREATE OR REPLACE FUNCTION ipcs_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE c contracts; x record;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO c FROM contracts WHERE id = NEW.contract_id AND tenant_id = current_tenant() FOR UPDATE;
    IF c.status IS DISTINCT FROM 'ACTIVE' OR NEW.status <> 'DRAFT' OR NEW.certified_by IS NOT NULL THEN
      RAISE EXCEPTION 'IPCs are prepared DRAFT for an ACTIVE contract' USING ERRCODE = 'check_violation';
    END IF;
    x := ipc_compute(c.id, NULL);
    IF x.this_gross <= 0 THEN
      RAISE EXCEPTION 'nothing to certify: no verified work since the last certificate' USING ERRCODE = 'check_violation';
    END IF;
    NEW.currency := c.currency;
    NEW.policy_id := c.policy_id;
    NEW.seq := 1 + (SELECT count(*) FROM ipcs WHERE contract_id = c.id AND status IN ('CERTIFIED', 'INVOICED'));
    NEW.cumulative_gross := x.cumulative_gross; NEW.previous_gross := x.previous_gross; NEW.this_gross := x.this_gross;
    NEW.retention_amount := x.retention_amount; NEW.advance_recovery := x.advance_recovery; NEW.vat_amount := x.vat_amount;
    NEW.amount_due := x.amount_due;
    NEW.certifier_mfa := false;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'IPC');
    RETURN NEW;
  END IF;
  IF NEW.status IN ('SUBMITTED', 'CERTIFIED') THEN
    -- Stale-certificate check: the figures still equal what the verified
    -- measurements and prior certificates support.
    x := ipc_compute(NEW.contract_id, NEW.id);
    IF (x.cumulative_gross, x.previous_gross, x.this_gross, x.retention_amount, x.advance_recovery, x.vat_amount, x.amount_due)
       IS DISTINCT FROM (OLD.cumulative_gross, OLD.previous_gross, OLD.this_gross, OLD.retention_amount, OLD.advance_recovery, OLD.vat_amount, OLD.amount_due) THEN
      RAISE EXCEPTION 'IPC % is stale: measurements, certificates or advance receipts changed since it was prepared; cancel and prepare it again', OLD.number
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'IPC');
    PERFORM approval_use('ipc.submit', 'ipc', NEW.id::text, NEW.created_by, ARRAY['ipc.prepare'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'CERTIFIED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'certified_by', 'certified_at', 'certifier_mfa', 'certificate_ref', 'certificate_sha256'], 'IPC');
    IF NEW.certificate_ref IS NULL OR length(btrim(NEW.certificate_ref)) < 3 OR NEW.certificate_sha256 IS NULL THEN
      RAISE EXCEPTION 'certification records the client''s certificate reference and the SHA-256 of the signed certificate' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ipc.certify', 'ipc', NEW.id::text, NEW.certified_by, ARRAY['ipc.certify'], true, 'CERTIFIED', NULL);
    NEW.certifier_mfa := true;
    NEW.certified_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'IPC');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting an IPC requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ipc.certify', 'ipc', NEW.id::text, NULL, ARRAY['ipc.certify'], false, 'REJECTED', NULL);
  ELSIF OLD.status IN ('DRAFT', 'SUBMITTED') AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'IPC');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling an IPC requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ipc.cancel', 'ipc', NEW.id::text, NULL, ARRAY['ipc.prepare', 'ipc.certify'], false, 'CANCELLED', NULL);
  ELSIF OLD.status = 'CERTIFIED' AND NEW.status = 'INVOICED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'IPC');
    IF NOT EXISTS (SELECT 1 FROM customer_invoices WHERE ipc_id = NEW.id AND status = 'APPROVED'
                     AND approval_consumed_in_tx(ARRAY['ar.invoice.approve'], 'customer_invoice', id::text, 'APPROVED') IS NOT NULL) THEN
      RAISE EXCEPTION 'an IPC becomes INVOICED only with the attested approval of its customer invoice' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal IPC transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER ipcs_guard BEFORE INSERT OR UPDATE ON ipcs FOR EACH ROW EXECUTE FUNCTION ipcs_guard();

CREATE OR REPLACE FUNCTION customer_invoices_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE i ipcs; c contracts;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO i FROM ipcs WHERE id = NEW.ipc_id AND tenant_id = current_tenant() FOR SHARE;
    SELECT * INTO c FROM contracts WHERE id = i.contract_id;
    IF i.status IS DISTINCT FROM 'CERTIFIED' OR NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'customer invoices are issued DRAFT from a CERTIFIED IPC' USING ERRCODE = 'check_violation';
    END IF;
    -- Every figure comes from the certificate, never from the caller.
    NEW.legal_entity_id := c.legal_entity_id; NEW.project_id := c.project_id; NEW.contract_id := c.id; NEW.customer_id := c.customer_id;
    NEW.policy_id := i.policy_id; NEW.currency := i.currency;
    NEW.gross := i.this_gross; NEW.retention_amount := i.retention_amount; NEW.advance_recovery := i.advance_recovery;
    NEW.vat_amount := i.vat_amount; NEW.total := i.amount_due;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'customer invoice');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'journal_id'], 'customer invoice');
    IF (SELECT status FROM ipcs WHERE id = NEW.ipc_id) IS DISTINCT FROM 'CERTIFIED' THEN
      RAISE EXCEPTION 'the IPC of this invoice is no longer CERTIFIED' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ar.invoice.approve', 'customer_invoice', NEW.id::text, NEW.approved_by, ARRAY['ar.invoice.approve'], false, 'APPROVED', NULL);
    PERFORM ar_assert_journal(NEW.journal_id, 'AR_INVOICE', NEW.id, NEW.legal_entity_id, NEW.currency, NEW.invoice_date);
    NEW.approved_at := now();
  ELSE
    RAISE EXCEPTION 'illegal customer invoice transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

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
    -- Serialise against other receipts of the same invoices / contracts, then
    -- refuse any over-allocation.
    PERFORM 1 FROM customer_invoices i JOIN receipt_allocations a ON a.invoice_id = i.id WHERE a.receipt_id = NEW.id FOR UPDATE OF i;
    PERFORM 1 FROM contracts c JOIN receipt_allocations a ON a.contract_id = c.id WHERE a.receipt_id = NEW.id FOR UPDATE OF c;
    SELECT i.number, i.total, i.status, i.legal_entity_id INTO bad FROM receipt_allocations a JOIN customer_invoices i ON i.id = a.invoice_id
     WHERE a.receipt_id = NEW.id
       AND (i.status <> 'APPROVED' OR i.legal_entity_id <> NEW.legal_entity_id OR i.currency <> NEW.currency
            OR a.amount + (SELECT COALESCE(sum(a2.amount), 0) FROM receipt_allocations a2 JOIN customer_receipts r2 ON r2.id = a2.receipt_id
                            WHERE a2.invoice_id = i.id AND r2.status = 'CONFIRMED') > i.total)
     LIMIT 1;
    IF bad.number IS NOT NULL THEN
      RAISE EXCEPTION 'invoice % cannot take this allocation (status %, total %): it would be over-allocated or is not payable', bad.number, bad.status, bad.total
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

CREATE OR REPLACE FUNCTION receipt_allocations_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT status FROM customer_receipts WHERE id = NEW.receipt_id AND tenant_id = current_tenant() FOR SHARE) IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'allocations are added only while the receipt is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER receipt_allocations_guard BEFORE INSERT ON receipt_allocations FOR EACH ROW EXECUTE FUNCTION receipt_allocations_guard();
-- A statement line used for a receipt can no longer be matched to a payment.
CREATE OR REPLACE FUNCTION bank_statement_lines_not_receipt() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM customer_receipts WHERE statement_line_id = NEW.id AND status <> 'CANCELLED') THEN
    RAISE EXCEPTION 'statement line % is already recorded as a customer receipt', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER bank_statement_lines_not_receipt BEFORE UPDATE ON bank_statement_lines FOR EACH ROW
  WHEN (OLD.status = 'UNMATCHED' AND NEW.status = 'MATCHED') EXECUTE FUNCTION bank_statement_lines_not_receipt();

-- ===========================================================================
-- Expected accounting and journal binding for AR_* journals
-- ===========================================================================
CREATE OR REPLACE FUNCTION ar_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH e(account_id, side, amount, project_id, cost_code_id) AS (
    -- Customer invoice (from a certified IPC): Dr AR (amount due), Dr
    -- retention receivable, Dr advance received (recovery); Cr revenue (the
    -- period's certified gross, on the project), Cr VAT output.
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
    -- Customer receipt: Dr bank; Cr AR (invoice allocations); Cr advance received.
    SELECT b.gl_account_id, 'DEBIT', r.amount, NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN company_bank_accounts b ON b.id = r.company_bank_id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant()
    UNION ALL
    SELECT (contract_policy_for(r.legal_entity_id)).ar_account_id, 'CREDIT', sum(a.amount), NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN receipt_allocations a ON a.receipt_id = r.id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant() AND a.invoice_id IS NOT NULL
     GROUP BY r.legal_entity_id
    UNION ALL
    SELECT (contract_policy_for(r.legal_entity_id)).advance_account_id, 'CREDIT', sum(a.amount), NULL::uuid, NULL::uuid
      FROM customer_receipts r JOIN receipt_allocations a ON a.receipt_id = r.id
     WHERE p_doc = 'AR_RECEIPT' AND r.id = p_id AND r.tenant_id = current_tenant() AND a.contract_id IS NOT NULL
     GROUP BY r.legal_entity_id
  )
  SELECT account_id, side, amount, project_id, cost_code_id FROM e WHERE amount > 0
$$;

CREATE OR REPLACE FUNCTION ar_expected_text(p_doc text, p_id uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(string_agg(concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')),
                             ';' ORDER BY concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')) COLLATE "C"), '')
    FROM ar_expected_lines(p_doc, p_id)
$$;

-- One entry point for every subledger (P2P_*, AR_*).
CREATE OR REPLACE FUNCTION subledger_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT * FROM p2p_expected_lines(p_doc, p_id) WHERE p_doc LIKE 'P2P\_%'
  UNION ALL
  SELECT * FROM ar_expected_lines(p_doc, p_id) WHERE p_doc LIKE 'AR\_%'
$$;
CREATE OR REPLACE FUNCTION subledger_expected_text(p_doc text, p_id uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN p_doc LIKE 'P2P\_%' THEN p2p_expected_text(p_doc, p_id) WHEN p_doc LIKE 'AR\_%' THEN ar_expected_text(p_doc, p_id) ELSE '' END
$$;

CREATE OR REPLACE FUNCTION ar_assert_journal(p_journal uuid, p_doc text, p_id uuid, p_entity uuid, p_ccy char(3), p_date date) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE j journals; want text; got text;
BEGIN
  SELECT * INTO j FROM journals WHERE id = p_journal AND tenant_id = current_tenant();
  IF j.id IS NULL THEN
    RAISE EXCEPTION '% % has no generated journal', p_doc, p_id USING ERRCODE = 'check_violation';
  END IF;
  IF j.status <> 'DRAFT' OR j.source_type <> p_doc OR j.source_ref IS DISTINCT FROM p_id::text OR j.legal_entity_id <> p_entity
     OR j.functional_currency <> p_ccy OR (j.business_event_at AT TIME ZONE 'UTC')::date <> p_date THEN
    RAISE EXCEPTION 'journal % is not the DRAFT % journal of % (entity, currency, date)', p_journal, p_doc, p_id USING ERRCODE = 'check_violation';
  END IF;
  want := ar_expected_text(p_doc, p_id);
  got := p2p_lines_text(p_journal);
  IF want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'journal % lines do not equal the accounting of % % (expected %, got %)', p_journal, p_doc, p_id, want, got USING ERRCODE = 'check_violation';
  END IF;
END$$;

CREATE TRIGGER customer_invoices_guard BEFORE INSERT OR UPDATE ON customer_invoices FOR EACH ROW EXECUTE FUNCTION customer_invoices_guard();
CREATE TRIGGER customer_receipts_guard BEFORE INSERT OR UPDATE ON customer_receipts FOR EACH ROW EXECUTE FUNCTION customer_receipts_guard();

CREATE CONSTRAINT TRIGGER customers_created_by AFTER INSERT ON customers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ar_creation_attested();
CREATE CONSTRAINT TRIGGER contract_policies_created_by AFTER INSERT ON contract_policies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ar_creation_attested();
CREATE CONSTRAINT TRIGGER customer_invoices_created_by AFTER INSERT ON customer_invoices DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ar_creation_attested();
CREATE CONSTRAINT TRIGGER customer_receipts_created_by AFTER INSERT ON customer_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ar_creation_attested();

-- Subledger journal protections, now for AR_* as well as P2P_*.
CREATE OR REPLACE FUNCTION journals_subledger_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.source_type ~ '^(P2P|AR)_' AND TG_OP = 'UPDATE' AND NEW.status = 'CANCELLED' AND OLD.status <> 'CANCELLED' THEN
    RAISE EXCEPTION 'subledger journals are not cancelled; correct the source document' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

CREATE OR REPLACE FUNCTION journal_lines_p2p_birth() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE j record; jid uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.journal_id ELSE NEW.journal_id END;
BEGIN
  SELECT source_type, created_txid INTO j FROM journals WHERE id = jid AND tenant_id = current_tenant();
  IF j.source_type ~ '^(P2P|AR)_' AND j.created_txid IS DISTINCT FROM txid_current() THEN
    RAISE EXCEPTION 'lines of subledger journal % are written only by the transaction that generated it', jid USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END$$;

CREATE OR REPLACE FUNCTION journals_ar_binding() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE bound boolean;
BEGIN
  bound := CASE NEW.source_type
      WHEN 'AR_INVOICE' THEN EXISTS (SELECT 1 FROM customer_invoices WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'AR_RECEIPT' THEN EXISTS (SELECT 1 FROM customer_receipts WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      ELSE false END;
  IF NOT bound THEN
    RAISE EXCEPTION 'journal % uses reserved source type % but no % document references it', NEW.id, NEW.source_type, NEW.source_type
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER journals_ar_binding AFTER INSERT ON journals DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.source_type LIKE 'AR\_%') EXECUTE FUNCTION journals_ar_binding();

CREATE OR REPLACE FUNCTION journals_ar_rebind() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE want text; got text;
BEGIN
  IF NEW.source_ref !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'subledger journal % has no document reference', NEW.id USING ERRCODE = 'check_violation';
  END IF;
  want := ar_expected_text(NEW.source_type, NEW.source_ref::uuid);
  got := p2p_lines_text(NEW.id);
  IF want IS NULL OR want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'subledger journal % no longer equals the accounting of % % (expected %, got %)', NEW.id, NEW.source_type, NEW.source_ref, want, got
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_ar_rebind BEFORE UPDATE OF status ON journals FOR EACH ROW
  WHEN (NEW.source_type LIKE 'AR\_%' AND NEW.status IN ('APPROVED', 'POSTED') AND OLD.status IS DISTINCT FROM NEW.status)
  EXECUTE FUNCTION journals_ar_rebind();

-- AR control accounts are control accounts for procure-to-pay too.
CREATE OR REPLACE FUNCTION p2p_is_control_account(p_account uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM company_bank_accounts b WHERE b.tenant_id = current_tenant() AND p_account IN (b.gl_account_id, b.clearing_account_id))
      OR EXISTS (SELECT 1 FROM p2p_policies p WHERE p.tenant_id = current_tenant()
                    AND p_account IN (p.grni_account_id, p.ap_account_id, p.vat_input_account_id, p.ppv_account_id))
      OR EXISTS (SELECT 1 FROM contract_policies c WHERE c.tenant_id = current_tenant()
                    AND p_account IN (c.ar_account_id, c.retention_account_id, c.advance_account_id, c.vat_output_account_id, c.revenue_account_id))
$$;

-- ===========================================================================
-- Reports
-- ===========================================================================
-- Commercial position of a contract, from documents.
CREATE OR REPLACE FUNCTION ar_contract_position(p_contract uuid)
RETURNS TABLE (contract_value numeric, measured_value numeric, certified_gross numeric, retention_held numeric, advance_amount numeric,
               advance_received numeric, advance_recovered numeric, invoiced_total numeric, received numeric, receivable_open numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT c.contract_value,
         COALESCE((SELECT sum(p2p_round(contract_verified_qty(c.id, l.line_no, NULL) * l.rate, c.currency)) FROM contract_lines l WHERE l.contract_id = c.id), 0),
         COALESCE((SELECT sum(this_gross) FROM ipcs WHERE contract_id = c.id AND status IN ('CERTIFIED', 'INVOICED')), 0),
         COALESCE((SELECT sum(retention_amount) FROM customer_invoices WHERE contract_id = c.id AND status = 'APPROVED'), 0),
         c.advance_amount,
         contract_advance_received(c.id),
         COALESCE((SELECT sum(advance_recovery) FROM customer_invoices WHERE contract_id = c.id AND status = 'APPROVED'), 0),
         COALESCE((SELECT sum(total) FROM customer_invoices WHERE contract_id = c.id AND status = 'APPROVED'), 0),
         COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id
                    JOIN customer_invoices i ON i.id = a.invoice_id WHERE i.contract_id = c.id AND r.status = 'CONFIRMED'), 0),
         COALESCE((SELECT sum(total) FROM customer_invoices WHERE contract_id = c.id AND status = 'APPROVED'), 0)
           - COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id
                        JOIN customer_invoices i ON i.id = a.invoice_id WHERE i.contract_id = c.id AND r.status = 'CONFIRMED'), 0)
    FROM contracts c WHERE c.id = p_contract AND c.tenant_id = current_tenant()
$$;

-- Each check compares a subledger figure from documents whose journals are
-- POSTED with the GL balance of its control account (debit-positive).
CREATE OR REPLACE FUNCTION ar_gl_reconciliation(p_entity uuid)
RETURNS TABLE (check_name text, subledger numeric, gl numeric, difference numeric, unposted_documents bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE pol contract_policies; sub numeric; g numeric; un bigint;
BEGIN
  pol := contract_policy_for(p_entity);
  IF pol.id IS NULL THEN
    RETURN;
  END IF;
  -- Accounts receivable: posted invoices less posted receipt allocations.
  SELECT COALESCE(sum(i.total), 0) INTO sub FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
   WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED';
  sub := sub - COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id JOIN journals j ON j.id = r.journal_id
                          WHERE r.legal_entity_id = p_entity AND r.status = 'CONFIRMED' AND j.status = 'POSTED' AND a.invoice_id IS NOT NULL), 0);
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.ar_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT count(*) INTO un FROM customer_invoices i JOIN journals j ON j.id = i.journal_id WHERE i.legal_entity_id = p_entity AND j.status <> 'POSTED';
  check_name := 'Accounts receivable'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  -- Retention receivable.
  SELECT COALESCE(sum(i.retention_amount), 0) INTO sub FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
   WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED';
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.retention_account_id AND j.status IN ('POSTED', 'REVERSED');
  check_name := 'Retention receivable'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  -- Advance received (credit balance shown as negative): receipts to advance less recoveries.
  SELECT -(COALESCE((SELECT sum(a.amount) FROM receipt_allocations a JOIN customer_receipts r ON r.id = a.receipt_id JOIN journals j ON j.id = r.journal_id
                      WHERE r.legal_entity_id = p_entity AND r.status = 'CONFIRMED' AND j.status = 'POSTED' AND a.contract_id IS NOT NULL), 0)
         - COALESCE((SELECT sum(i.advance_recovery) FROM customer_invoices i JOIN journals j ON j.id = i.journal_id
                      WHERE i.legal_entity_id = p_entity AND i.status = 'APPROVED' AND j.status = 'POSTED'), 0)) INTO sub;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.advance_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT count(*) INTO un FROM customer_receipts r JOIN journals j ON j.id = r.journal_id WHERE r.legal_entity_id = p_entity AND j.status <> 'POSTED';
  check_name := 'Advances received'; subledger := sub; gl := g; difference := sub - g; unposted_documents := un; RETURN NEXT;
  -- Unapplied money in: positive statement lines with no confirmed receipt.
  SELECT COALESCE(sum(l.amount), 0), count(*) INTO sub, un FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
    JOIN company_bank_accounts b ON b.id = s.company_bank_id
   WHERE b.legal_entity_id = p_entity AND l.amount > 0
     AND NOT EXISTS (SELECT 1 FROM customer_receipts r WHERE r.statement_line_id = l.id AND r.status = 'CONFIRMED');
  check_name := 'Unapplied money in (statement lines without a confirmed receipt)'; subledger := sub; gl := NULL; difference := NULL;
  unposted_documents := un; RETURN NEXT;
END$$;

-- Project profitability from the ledger: posted revenue and posted cost on the project.
CREATE OR REPLACE FUNCTION project_profitability(p_project uuid)
RETURNS TABLE (revenue_posted numeric, cost_posted numeric, margin numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH x AS (
    SELECT COALESCE(sum(CASE WHEN a.type = 'REVENUE' THEN CASE WHEN jl.side = 'CREDIT' THEN jl.amount ELSE -jl.amount END END), 0) AS rev,
           COALESCE(sum(CASE WHEN a.type = 'EXPENSE' THEN CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END END), 0) AS cost
      FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id JOIN accounts a ON a.id = jl.account_id
     WHERE jl.tenant_id = current_tenant() AND jl.project_id = p_project AND j.status IN ('POSTED', 'REVERSED'))
  SELECT rev, cost, rev - cost FROM x
$$;

-- ===========================================================================
-- Approval subject text for the new documents (canonical jsonb, children
-- included; the existing branches are carried over from 0017, keeping the
-- keyed account digests in place of account numbers).
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
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- ===========================================================================
-- Procure-to-pay bank reconciliation, extended for receipts (the 0013 body
-- with two changes: posted customer receipts are reconciled movements of the
-- bank account, and a money-in line with a posted receipt is not unmatched).
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_gl_reconciliation(p_entity uuid)
RETURNS TABLE (check_name text, subledger numeric, gl numeric, difference numeric, unposted_documents bigint)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE pol p2p_policies; sub numeric; g numeric; un bigint; b company_bank_accounts;
BEGIN
  pol := p2p_policy_for(p_entity);
  IF pol.id IS NULL THEN
    RETURN;
  END IF;
  -- GRNI: received at PO price minus invoiced at PO price.
  SELECT COALESCE((SELECT sum(p2p_round(gl.qty_received * pl.unit_price, o.currency)) FROM grns gr JOIN journals j ON j.id = gr.journal_id
                    JOIN grn_lines gl ON gl.grn_id = gr.id JOIN purchase_orders o ON o.id = gr.po_id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
                   WHERE o.legal_entity_id = p_entity AND j.status = 'POSTED'), 0)
       - COALESCE((SELECT sum(p2p_round(il.quantity * pl.unit_price, i.currency)) FROM supplier_invoices i JOIN journals j ON j.id = i.journal_id
                    JOIN invoice_lines il ON il.invoice_id = i.id JOIN po_lines pl ON pl.po_id = i.po_id AND pl.line_no = il.po_line_no
                    JOIN purchase_orders o ON o.id = i.po_id WHERE o.legal_entity_id = p_entity AND j.status = 'POSTED'), 0) INTO sub;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'CREDIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.grni_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT count(*) INTO un FROM grns gr JOIN journals j ON j.id = gr.journal_id JOIN purchase_orders o ON o.id = gr.po_id
   WHERE o.legal_entity_id = p_entity AND j.status <> 'POSTED';
  check_name := 'GRNI (goods received not invoiced)'; subledger := sub; gl := g; difference := g - sub; unposted_documents := un; RETURN NEXT;
  -- AP: approved invoices minus released payments.
  SELECT COALESCE((SELECT sum(i.total) FROM supplier_invoices i JOIN journals j ON j.id = i.journal_id JOIN purchase_orders o ON o.id = i.po_id
                   WHERE o.legal_entity_id = p_entity AND j.status = 'POSTED'), 0)
       - COALESCE((SELECT sum(p.amount) FROM payment_instructions p JOIN journals j ON j.id = p.release_journal_id
                   WHERE p.legal_entity_id = p_entity AND j.status = 'POSTED'), 0) INTO sub;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'CREDIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = pol.ap_account_id AND j.status IN ('POSTED', 'REVERSED');
  SELECT (SELECT count(*) FROM supplier_invoices i JOIN journals j ON j.id = i.journal_id JOIN purchase_orders o ON o.id = i.po_id
           WHERE o.legal_entity_id = p_entity AND j.status <> 'POSTED')
       + (SELECT count(*) FROM payment_instructions p JOIN journals j ON j.id = p.release_journal_id WHERE p.legal_entity_id = p_entity AND j.status <> 'POSTED') INTO un;
  check_name := 'Accounts payable'; subledger := sub; gl := g; difference := g - sub; unposted_documents := un; RETURN NEXT;
  FOR b IN SELECT * FROM company_bank_accounts WHERE tenant_id = current_tenant() AND legal_entity_id = p_entity ORDER BY name LOOP
    -- Payments in transit: released minus settled (bank-confirmed).
    SELECT COALESCE((SELECT sum(p.amount) FROM payment_instructions p JOIN journals j ON j.id = p.release_journal_id
                     WHERE p.company_bank_id = b.id AND j.status = 'POSTED'), 0)
         - COALESCE((SELECT sum(-l.amount) FROM bank_statement_lines l JOIN journals j ON j.id = l.journal_id
                      JOIN bank_statements s ON s.id = l.statement_id WHERE s.company_bank_id = b.id AND j.status = 'POSTED'), 0) INTO sub;
    SELECT COALESCE(sum(CASE WHEN jl.side = 'CREDIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
      FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = b.clearing_account_id AND j.status IN ('POSTED', 'REVERSED');
    SELECT count(*) INTO un FROM bank_statement_lines l JOIN journals j ON j.id = l.journal_id JOIN bank_statements s ON s.id = l.statement_id
     WHERE s.company_bank_id = b.id AND j.status <> 'POSTED';
    check_name := 'Payments in transit: ' || b.name; subledger := sub; gl := g; difference := g - sub; unposted_documents := un; RETURN NEXT;
    -- Bank: net movement of reconciled (matched + posted) statement lines vs the bank GL account.
    -- Since 0018 a money-in line is reconciled by a confirmed customer receipt,
    -- whose journal (Dr bank) is on the receipt rather than on the line.
    SELECT COALESCE((SELECT sum(l.amount) FROM bank_statement_lines l JOIN journals j ON j.id = l.journal_id
                      JOIN bank_statements s ON s.id = l.statement_id WHERE s.company_bank_id = b.id AND j.status = 'POSTED'), 0)
         + COALESCE((SELECT sum(r.amount) FROM customer_receipts r JOIN journals j ON j.id = r.journal_id
                      WHERE r.company_bank_id = b.id AND r.status = 'CONFIRMED' AND j.status = 'POSTED'), 0) INTO sub;
    SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
      FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = b.gl_account_id AND j.status IN ('POSTED', 'REVERSED');
    check_name := 'Bank (reconciled movements): ' || b.name; subledger := sub; gl := g; difference := g - sub;
    SELECT count(*) INTO unposted_documents FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
     WHERE s.company_bank_id = b.id AND l.status = 'UNMATCHED'
       AND NOT EXISTS (SELECT 1 FROM customer_receipts r JOIN journals j ON j.id = r.journal_id
                        WHERE r.statement_line_id = l.id AND r.status = 'CONFIRMED' AND j.status = 'POSTED');
    RETURN NEXT;
  END LOOP;
END$$;

-- ===========================================================================
-- Row-level security and grants
-- ===========================================================================
DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['customers', 'contract_policies', 'contracts', 'contract_lines', 'measurements', 'measurement_lines', 'ipcs',
                             'customer_invoices', 'customer_receipts', 'receipt_allocations'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;

GRANT UPDATE (status, approved_by, blocked_reason) ON customers TO serk_app;
GRANT UPDATE (status, approved_by) ON contract_policies TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON contracts TO serk_app;
GRANT UPDATE (status, verified_by, decision_reason) ON measurements TO serk_app;
GRANT UPDATE (status, certified_by, certificate_ref, certificate_sha256, decision_reason) ON ipcs TO serk_app;
GRANT UPDATE (status, approved_by, journal_id) ON customer_invoices TO serk_app;
GRANT UPDATE (status, confirmed_by, cancel_reason, journal_id) ON customer_receipts TO serk_app;

GRANT EXECUTE ON FUNCTION contract_policy_for(uuid), contract_verified_qty(uuid, integer, uuid), contract_advance_received(uuid),
  ipc_compute(uuid, uuid), ar_expected_lines(text, uuid), ar_expected_text(text, uuid), subledger_expected_lines(text, uuid),
  subledger_expected_text(text, uuid), ar_assert_journal(uuid, text, uuid, uuid, char, date), ar_contract_position(uuid),
  ar_gl_reconciliation(uuid), project_profitability(uuid)
TO serk_app;
