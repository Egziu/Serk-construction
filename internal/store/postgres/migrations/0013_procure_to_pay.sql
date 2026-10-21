-- 0013: Journey A, procure-to-pay (GATEB-02/03/04, GATEC-01).
--
--   BOQ (budget baseline) -> purchase requisition -> RFQ (technical +
--   commercial evaluation, award) -> purchase order (budget/commitment) ->
--   goods receipt (partial deliveries) -> supplier invoice (3-way match) ->
--   payment instruction (maker/checker, MFA, dual approval) -> bank statement
--   reconciliation -> general ledger.
--
-- Principles (ADR 0009):
--  * Every maker step (submit/issue) and checker step (decide/approve/confirm/
--    release/reconcile) is an attested transition (ADR 0008): the tenant DB
--    login alone can create drafts, nothing more. This also closes R-MAKER for
--    these documents.
--  * The database computes the money: line amounts (half-even to the currency
--    minor unit), budgets, commitments, availability, 3-way match results and
--    the expected accounting of every document; it refuses a generated journal
--    whose lines differ from that expectation.
--  * Subledger journals are created DRAFT and go through the ordinary attested
--    journal approve/post (finance), so ledger SoD is unchanged.
--  * Nothing here moves money: a RELEASED payment instruction is an instruction
--    record; settlement is recognised only from an imported bank statement.

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------
-- Banker's rounding, identical to pkg/money RoundHalfEven (differential-tested).
CREATE OR REPLACE FUNCTION round_half_even(v numeric, places integer) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
  SELECT CASE
    WHEN abs(v * 10::numeric ^ places - trunc(v * 10::numeric ^ places)) = 0.5 THEN
      round((trunc(v * 10::numeric ^ places)
             + CASE WHEN mod(trunc(v * 10::numeric ^ places), 2) = 0 THEN 0 ELSE sign(v) END) / 10::numeric ^ places, places)
    ELSE round(v, places)
  END
$$;

CREATE OR REPLACE FUNCTION p2p_round(v numeric, ccy char(3)) RETURNS numeric
LANGUAGE sql STABLE STRICT SET search_path = pg_catalog, public AS $$
  SELECT round_half_even(v, currency_minor_units(ccy))
$$;

-- Document counters (human-readable numbers). A tenant resetting its own
-- counter can only cause unique-number conflicts (refused), never reuse.
CREATE TABLE p2p_counters (
  tenant_id uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  doc_type  text NOT NULL,
  year      integer NOT NULL,
  last      integer NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, doc_type, year)
);

-- ---------------------------------------------------------------------------
-- Policy: tolerances, thresholds, tax rate and account mapping per entity.
-- Values are tenant data approved maker/checker; nothing is hardcoded here.
-- ---------------------------------------------------------------------------
CREATE TABLE p2p_policies (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id         uuid NOT NULL,
  version                 integer NOT NULL,
  currency                char(3) NOT NULL REFERENCES currencies(code),
  price_tolerance_pct     numeric(7,6) NOT NULL CHECK (price_tolerance_pct >= 0 AND price_tolerance_pct <= 0.25),
  over_receipt_pct        numeric(7,6) NOT NULL CHECK (over_receipt_pct >= 0 AND over_receipt_pct <= 0.25),
  vat_rate                numeric(7,6) NOT NULL CHECK (vat_rate >= 0 AND vat_rate < 1),
  high_value_po_threshold numeric(24,6) NOT NULL CHECK (high_value_po_threshold > 0),
  dual_payment_threshold  numeric(24,6) NOT NULL CHECK (dual_payment_threshold > 0),
  grni_account_id         uuid NOT NULL,
  ap_account_id           uuid NOT NULL,
  vat_input_account_id    uuid NOT NULL,
  ppv_account_id          uuid NOT NULL,
  status                  text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED', 'RETIRED')),
  created_by              text NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  approved_by             text,
  approved_at             timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, version),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, grni_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, ap_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, vat_input_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, ppv_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  CONSTRAINT p2p_policies_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE UNIQUE INDEX p2p_policies_one_approved ON p2p_policies (tenant_id, legal_entity_id) WHERE status = 'APPROVED';

CREATE OR REPLACE FUNCTION p2p_policy_for(p_entity uuid) RETURNS p2p_policies
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT * FROM p2p_policies WHERE tenant_id = current_tenant() AND legal_entity_id = p_entity AND status = 'APPROVED'
$$;

-- ---------------------------------------------------------------------------
-- Suppliers and their bank accounts (fraud control: details never change in
-- place; a new account is PENDING until a second person approves it)
-- ---------------------------------------------------------------------------
CREATE TABLE suppliers (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  code            text NOT NULL CHECK (code ~ '^[A-Z0-9][A-Z0-9-]{1,30}$'),
  name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 200),
  tax_id          text CHECK (tax_id IS NULL OR length(tax_id) BETWEEN 3 AND 40),
  status          text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'BLOCKED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  approved_by     text,
  approved_at     timestamptz,
  blocked_reason  text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, code),
  UNIQUE (tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  CONSTRAINT suppliers_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE supplier_bank_accounts (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  supplier_id    uuid NOT NULL,
  bank_name      text NOT NULL CHECK (length(btrim(bank_name)) BETWEEN 2 AND 120),
  account_name   text NOT NULL CHECK (length(btrim(account_name)) BETWEEN 2 AND 200),
  account_number text NOT NULL CHECK (account_number ~ '^[A-Z0-9]{6,34}$'),
  currency       char(3) NOT NULL REFERENCES currencies(code),
  status         text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REVOKED')),
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  approved_by    text,
  approved_at    timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, supplier_id) REFERENCES suppliers(tenant_id, id),
  CONSTRAINT supplier_bank_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

-- ---------------------------------------------------------------------------
-- BOQ: versioned bill of quantities = the approved project budget baseline
-- ---------------------------------------------------------------------------
CREATE TABLE boq_versions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  project_id      uuid NOT NULL,
  version         integer NOT NULL CHECK (version >= 1),
  currency        char(3) NOT NULL REFERENCES currencies(code),
  description     text NOT NULL CHECK (length(btrim(description)) BETWEEN 3 AND 500),
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'SUPERSEDED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  submitted_at    timestamptz,
  approved_by     text,
  approved_at     timestamptz,
  decision_reason text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, project_id, version),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  CONSTRAINT boq_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE UNIQUE INDEX boq_one_approved ON boq_versions (tenant_id, project_id) WHERE status = 'APPROVED';

CREATE TABLE boq_items (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  version_id   uuid NOT NULL,
  item_no      text NOT NULL CHECK (item_no ~ '^[0-9A-Z]+(\.[0-9A-Z]+)*$'),
  description  text NOT NULL CHECK (length(btrim(description)) BETWEEN 2 AND 500),
  unit         text NOT NULL CHECK (unit ~ '^[A-Za-z0-9/.²³]{1,12}$'),
  quantity     numeric(20,4) NOT NULL CHECK (quantity >= 0),
  rate         numeric(24,6) NOT NULL CHECK (rate >= 0),
  amount       numeric(24,6) NOT NULL DEFAULT 0,
  cost_code_id uuid NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (version_id, item_no),
  FOREIGN KEY (tenant_id, version_id) REFERENCES boq_versions(tenant_id, id),
  FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id)
);
CREATE INDEX boq_items_cost_code ON boq_items (tenant_id, cost_code_id);

-- ---------------------------------------------------------------------------
-- Purchase requisitions
-- ---------------------------------------------------------------------------
CREATE TABLE purchase_requisitions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  project_id      uuid NOT NULL,
  number          text NOT NULL,
  currency        char(3) NOT NULL REFERENCES currencies(code),
  justification   text NOT NULL CHECK (length(btrim(justification)) BETWEEN 5 AND 1000),
  needed_by       date,
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED')),
  requested_by    text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  submitted_at    timestamptz,
  approved_by     text,
  approved_at     timestamptz,
  decision_reason text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  CONSTRAINT pr_maker_checker CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE TABLE pr_lines (
  tenant_id      uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  pr_id          uuid NOT NULL,
  line_no        integer NOT NULL CHECK (line_no BETWEEN 1 AND 999),
  boq_item_id    uuid,
  cost_code_id   uuid NOT NULL,
  description    text NOT NULL CHECK (length(btrim(description)) BETWEEN 2 AND 500),
  unit           text NOT NULL CHECK (unit ~ '^[A-Za-z0-9/.²³]{1,12}$'),
  quantity       numeric(20,4) NOT NULL CHECK (quantity > 0),
  est_unit_price numeric(24,6) NOT NULL CHECK (est_unit_price > 0),
  est_amount     numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (pr_id, line_no),
  FOREIGN KEY (tenant_id, pr_id) REFERENCES purchase_requisitions(tenant_id, id),
  FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id),
  FOREIGN KEY (tenant_id, boq_item_id) REFERENCES boq_items(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- RFQ, invitations, quotes (technical + commercial evaluation)
-- ---------------------------------------------------------------------------
CREATE TABLE rfqs (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  pr_id                 uuid NOT NULL,
  number                text NOT NULL,
  due_at                timestamptz NOT NULL,
  min_suppliers         integer NOT NULL DEFAULT 3 CHECK (min_suppliers BETWEEN 1 AND 20),
  single_source_reason  text CHECK (single_source_reason IS NULL OR length(btrim(single_source_reason)) >= 20),
  status                text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ISSUED', 'AWARDED', 'CANCELLED')),
  created_by            text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  issued_at             timestamptz,
  awarded_quote_id      uuid,
  awarded_by            text,
  awarded_at            timestamptz,
  award_reason          text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, pr_id) REFERENCES purchase_requisitions(tenant_id, id),
  CONSTRAINT rfq_award_separation CHECK (awarded_by IS NULL OR awarded_by <> created_by)
);
-- One live RFQ per requisition.
CREATE UNIQUE INDEX rfqs_one_live_per_pr ON rfqs (tenant_id, pr_id) WHERE status IN ('DRAFT', 'ISSUED', 'AWARDED');

CREATE TABLE rfq_suppliers (
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  rfq_id      uuid NOT NULL,
  supplier_id uuid NOT NULL,
  invited_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (rfq_id, supplier_id),
  FOREIGN KEY (tenant_id, rfq_id) REFERENCES rfqs(tenant_id, id),
  FOREIGN KEY (tenant_id, supplier_id) REFERENCES suppliers(tenant_id, id)
);

CREATE TABLE rfq_quotes (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  rfq_id             uuid NOT NULL,
  supplier_id        uuid NOT NULL,
  currency           char(3) NOT NULL REFERENCES currencies(code),
  valid_until        date NOT NULL,
  supplier_reference text CHECK (supplier_reference IS NULL OR length(supplier_reference) <= 80),
  total              numeric(24,6) NOT NULL DEFAULT 0,
  technical_status   text NOT NULL DEFAULT 'PENDING' CHECK (technical_status IN ('PENDING', 'COMPLIANT', 'NON_COMPLIANT')),
  technical_note     text,
  evaluated_by       text,
  evaluated_at       timestamptz,
  received_by        text NOT NULL,
  received_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (rfq_id, supplier_id),
  FOREIGN KEY (tenant_id, rfq_id) REFERENCES rfqs(tenant_id, id),
  FOREIGN KEY (rfq_id, supplier_id) REFERENCES rfq_suppliers(rfq_id, supplier_id),
  CONSTRAINT quote_evaluation_separation CHECK (evaluated_by IS NULL OR evaluated_by <> received_by)
);

CREATE TABLE rfq_quote_lines (
  tenant_id  uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  quote_id   uuid NOT NULL,
  pr_line_no integer NOT NULL,
  unit_price numeric(24,6) NOT NULL CHECK (unit_price > 0),
  quantity   numeric(20,4) NOT NULL DEFAULT 0,
  amount     numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (quote_id, pr_line_no),
  FOREIGN KEY (tenant_id, quote_id) REFERENCES rfq_quotes(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Purchase orders (commitments)
-- ---------------------------------------------------------------------------
CREATE TABLE purchase_orders (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id              uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id        uuid NOT NULL,
  project_id             uuid NOT NULL,
  number                 text NOT NULL,
  rfq_id                 uuid NOT NULL,
  quote_id               uuid NOT NULL,
  supplier_id            uuid NOT NULL,
  currency               char(3) NOT NULL REFERENCES currencies(code),
  total                  numeric(24,6) NOT NULL DEFAULT 0,
  status                 text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'CLOSED', 'CANCELLED')),
  created_by             text NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  approved_by            text,
  approved_at            timestamptz,
  budget_override_reason text CHECK (budget_override_reason IS NULL OR length(btrim(budget_override_reason)) >= 20),
  over_budget            boolean NOT NULL DEFAULT false,
  approver_mfa           boolean NOT NULL DEFAULT false,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  UNIQUE (tenant_id, rfq_id),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, rfq_id) REFERENCES rfqs(tenant_id, id),
  FOREIGN KEY (tenant_id, quote_id) REFERENCES rfq_quotes(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, supplier_id) REFERENCES suppliers(tenant_id, legal_entity_id, id),
  CONSTRAINT po_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE po_lines (
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  po_id           uuid NOT NULL,
  line_no         integer NOT NULL CHECK (line_no BETWEEN 1 AND 999),
  legal_entity_id uuid NOT NULL,
  cost_code_id    uuid NOT NULL,
  account_id      uuid NOT NULL,
  description     text NOT NULL,
  unit            text NOT NULL,
  quantity        numeric(20,4) NOT NULL CHECK (quantity > 0),
  unit_price      numeric(24,6) NOT NULL CHECK (unit_price > 0),
  amount          numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (po_id, line_no),
  FOREIGN KEY (tenant_id, po_id) REFERENCES purchase_orders(tenant_id, id),
  FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, account_id) REFERENCES accounts(tenant_id, legal_entity_id, id)
);
CREATE INDEX po_lines_cost_code ON po_lines (tenant_id, cost_code_id);

-- ---------------------------------------------------------------------------
-- Goods receipts
-- ---------------------------------------------------------------------------
CREATE TABLE grns (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  po_id              uuid NOT NULL,
  number             text NOT NULL,
  received_on        date NOT NULL,
  delivery_note_ref  text NOT NULL CHECK (length(btrim(delivery_note_ref)) BETWEEN 1 AND 80),
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'CONFIRMED')),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  submitted_at       timestamptz,
  confirmed_by       text,
  confirmed_at       timestamptz,
  journal_id         uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, po_id) REFERENCES purchase_orders(tenant_id, id),
  CONSTRAINT grn_maker_checker CHECK (confirmed_by IS NULL OR confirmed_by <> created_by)
);

CREATE TABLE grn_lines (
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  grn_id       uuid NOT NULL,
  po_line_no   integer NOT NULL,
  qty_received numeric(20,4) NOT NULL CHECK (qty_received > 0),
  note         text,
  PRIMARY KEY (grn_id, po_line_no),
  FOREIGN KEY (tenant_id, grn_id) REFERENCES grns(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Supplier invoices (3-way match against PO price and confirmed receipts)
-- ---------------------------------------------------------------------------
CREATE TABLE supplier_invoices (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  supplier_id       uuid NOT NULL,
  po_id             uuid NOT NULL,
  policy_id         uuid,
  invoice_number    text NOT NULL CHECK (length(btrim(invoice_number)) BETWEEN 1 AND 60),
  normalized_number text NOT NULL DEFAULT '',
  invoice_date      date NOT NULL,
  due_date          date NOT NULL,
  currency          char(3) NOT NULL REFERENCES currencies(code),
  subtotal          numeric(24,6) NOT NULL CHECK (subtotal > 0),
  tax_amount        numeric(24,6) NOT NULL CHECK (tax_amount >= 0),
  total             numeric(24,6) NOT NULL CHECK (total > 0),
  status            text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED')),
  match_status      text NOT NULL DEFAULT 'PENDING' CHECK (match_status IN ('PENDING', 'MATCHED', 'EXCEPTION')),
  match_detail      jsonb,
  exception_reason  text,
  entered_by        text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  submitted_at      timestamptz,
  approved_by       text,
  approved_at       timestamptz,
  approver_mfa      boolean NOT NULL DEFAULT false,
  decision_reason   text,
  journal_id        uuid UNIQUE,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, supplier_id) REFERENCES suppliers(tenant_id, id),
  FOREIGN KEY (tenant_id, po_id) REFERENCES purchase_orders(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES p2p_policies(tenant_id, id),
  CONSTRAINT invoice_maker_checker CHECK (approved_by IS NULL OR approved_by <> entered_by),
  CHECK (due_date >= invoice_date)
);
-- Duplicate invoice protection: one live invoice per supplier and normalised
-- number (a REJECTED one may be re-entered).
CREATE UNIQUE INDEX supplier_invoices_no_duplicates ON supplier_invoices (tenant_id, supplier_id, normalized_number) WHERE status <> 'REJECTED';

CREATE TABLE invoice_lines (
  tenant_id  uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  invoice_id uuid NOT NULL,
  po_line_no integer NOT NULL,
  quantity   numeric(20,4) NOT NULL CHECK (quantity > 0),
  unit_price numeric(24,6) NOT NULL CHECK (unit_price > 0),
  amount     numeric(24,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (invoice_id, po_line_no),
  FOREIGN KEY (tenant_id, invoice_id) REFERENCES supplier_invoices(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Company bank accounts, payment instructions, allocations
-- ---------------------------------------------------------------------------
CREATE TABLE company_bank_accounts (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id    uuid NOT NULL,
  name               text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 120),
  account_number     text NOT NULL CHECK (account_number ~ '^[A-Z0-9]{6,34}$'),
  currency           char(3) NOT NULL REFERENCES currencies(code),
  gl_account_id      uuid NOT NULL,
  clearing_account_id uuid NOT NULL,
  status             text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'CLOSED')),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  approved_by        text,
  approved_at        timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, account_number),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, gl_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, clearing_account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  CONSTRAINT company_bank_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by),
  CHECK (gl_account_id <> clearing_account_id)
);

CREATE TABLE payment_instructions (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  legal_entity_id    uuid NOT NULL,
  number             text NOT NULL,
  supplier_id        uuid NOT NULL,
  supplier_bank_id   uuid NOT NULL,
  bank_snapshot      text NOT NULL,          -- sha256 of the approved bank details at creation
  company_bank_id    uuid NOT NULL,
  currency           char(3) NOT NULL REFERENCES currencies(code),
  amount             numeric(24,6) NOT NULL CHECK (amount > 0),
  value_date         date NOT NULL,
  policy_id          uuid,
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'PARTIALLY_APPROVED', 'APPROVED', 'RELEASED', 'SETTLED', 'CANCELLED')),
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  submitted_at       timestamptz,
  approved_by        text,
  approved_at        timestamptz,
  second_approved_by text,
  second_approved_at timestamptz,
  released_by        text,
  released_at        timestamptz,
  settled_at         timestamptz,
  release_journal_id uuid UNIQUE,
  cancel_reason      text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, legal_entity_id, supplier_id) REFERENCES suppliers(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, supplier_bank_id) REFERENCES supplier_bank_accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, company_bank_id) REFERENCES company_bank_accounts(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES p2p_policies(tenant_id, id),
  CONSTRAINT payment_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by),
  CONSTRAINT payment_dual_distinct CHECK (second_approved_by IS NULL OR (second_approved_by <> approved_by AND second_approved_by <> created_by)),
  CONSTRAINT payment_release_separation CHECK (released_by IS NULL OR (released_by <> approved_by AND released_by IS DISTINCT FROM second_approved_by))
);

CREATE TABLE payment_allocations (
  tenant_id  uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  payment_id uuid NOT NULL,
  invoice_id uuid NOT NULL,
  amount     numeric(24,6) NOT NULL CHECK (amount > 0),
  PRIMARY KEY (payment_id, invoice_id),
  FOREIGN KEY (tenant_id, payment_id) REFERENCES payment_instructions(tenant_id, id),
  FOREIGN KEY (tenant_id, invoice_id) REFERENCES supplier_invoices(tenant_id, id)
);

-- ---------------------------------------------------------------------------
-- Bank statements and reconciliation
-- ---------------------------------------------------------------------------
CREATE TABLE bank_statements (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  company_bank_id uuid NOT NULL,
  statement_no    text NOT NULL CHECK (length(btrim(statement_no)) BETWEEN 1 AND 60),
  statement_date  date NOT NULL,
  opening_balance numeric(24,6) NOT NULL,
  closing_balance numeric(24,6) NOT NULL,
  source_sha256   text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
  imported_by     text NOT NULL,
  imported_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, company_bank_id, statement_no),
  UNIQUE (tenant_id, source_sha256),
  FOREIGN KEY (tenant_id, company_bank_id) REFERENCES company_bank_accounts(tenant_id, id)
);

CREATE TABLE bank_statement_lines (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  statement_id uuid NOT NULL,
  line_no      integer NOT NULL CHECK (line_no BETWEEN 1 AND 100000),
  booking_date date NOT NULL,
  amount       numeric(24,6) NOT NULL CHECK (amount <> 0),   -- negative = money out
  reference    text NOT NULL DEFAULT '',
  counterparty text NOT NULL DEFAULT '',
  status       text NOT NULL DEFAULT 'UNMATCHED' CHECK (status IN ('UNMATCHED', 'MATCHED')),
  payment_id   uuid,
  matched_by   text,
  matched_at   timestamptz,
  journal_id   uuid UNIQUE,
  UNIQUE (tenant_id, id),
  UNIQUE (statement_id, line_no),
  FOREIGN KEY (tenant_id, statement_id) REFERENCES bank_statements(tenant_id, id),
  FOREIGN KEY (tenant_id, payment_id) REFERENCES payment_instructions(tenant_id, id)
);
CREATE UNIQUE INDEX bank_lines_one_per_payment ON bank_statement_lines (tenant_id, payment_id) WHERE payment_id IS NOT NULL;

-- ===========================================================================
-- Computation (the database is the arbiter of every number below)
-- ===========================================================================

-- Budget position of a cost code. reserved = approved requisitions not yet on
-- an approved PO; actual_other = posted cost NOT already inside a PO
-- commitment (everything except goods receipts; purchase price variance is
-- posted with the invoice and therefore counts here).
CREATE OR REPLACE FUNCTION p2p_cost_position(p_cost_code uuid, p_exclude_pr uuid, p_exclude_po uuid,
  OUT budget numeric, OUT committed numeric, OUT reserved numeric, OUT actual_other numeric, OUT available numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  SELECT COALESCE(sum(i.amount), 0) INTO budget
    FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
   WHERE i.tenant_id = current_tenant() AND i.cost_code_id = p_cost_code AND v.status = 'APPROVED';
  SELECT COALESCE(sum(l.amount), 0) INTO committed
    FROM po_lines l JOIN purchase_orders o ON o.id = l.po_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND o.status IN ('APPROVED', 'CLOSED')
     AND o.id IS DISTINCT FROM p_exclude_po;
  SELECT COALESCE(sum(l.est_amount), 0) INTO reserved
    FROM pr_lines l JOIN purchase_requisitions r ON r.id = l.pr_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND r.status = 'APPROVED'
     AND r.id IS DISTINCT FROM p_exclude_pr
     AND NOT EXISTS (SELECT 1 FROM rfqs q JOIN purchase_orders o ON o.rfq_id = q.id
                      WHERE q.pr_id = r.id AND o.status IN ('APPROVED', 'CLOSED'));
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO actual_other
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status IN ('POSTED', 'REVERSED')
     AND j.source_type <> 'P2P_GRN';
  available := budget - committed - reserved - actual_other;
END$$;

CREATE OR REPLACE FUNCTION p2p_received_qty(p_po uuid, p_line integer) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(gl.qty_received), 0) FROM grn_lines gl JOIN grns g ON g.id = gl.grn_id
   WHERE g.tenant_id = current_tenant() AND g.po_id = p_po AND gl.po_line_no = p_line AND g.status = 'CONFIRMED'
$$;

CREATE OR REPLACE FUNCTION p2p_billed_qty(p_po uuid, p_line integer, p_exclude_invoice uuid) RETURNS numeric
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(sum(il.quantity), 0) FROM invoice_lines il JOIN supplier_invoices i ON i.id = il.invoice_id
   WHERE i.tenant_id = current_tenant() AND i.po_id = p_po AND il.po_line_no = p_line
     AND i.status IN ('SUBMITTED', 'APPROVED') AND i.id <> p_exclude_invoice
$$;

-- 3-way match. Hard errors raise (they are never approvable); price
-- differences beyond the policy tolerance make the invoice an EXCEPTION
-- (approvable only with fx-like elevated rights + MFA + reason).
CREATE OR REPLACE FUNCTION p2p_match_invoice(p_invoice uuid, p_policy uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE
  inv supplier_invoices; pol p2p_policies; l record; lines jsonb := '[]'::jsonb; status text := 'MATCHED';
  sum_lines numeric := 0; want_tax numeric; var_pct numeric; received numeric; billed numeric; n integer := 0;
BEGIN
  SELECT * INTO inv FROM supplier_invoices WHERE id = p_invoice AND tenant_id = current_tenant();
  SELECT * INTO pol FROM p2p_policies WHERE id = p_policy AND tenant_id = current_tenant();
  IF inv.id IS NULL OR pol.id IS NULL THEN
    RAISE EXCEPTION 'invoice or policy not found' USING ERRCODE = 'foreign_key_violation';
  END IF;
  FOR l IN SELECT il.*, pl.unit_price AS po_price, pl.quantity AS po_qty
             FROM invoice_lines il LEFT JOIN po_lines pl ON pl.po_id = inv.po_id AND pl.line_no = il.po_line_no
            WHERE il.invoice_id = inv.id ORDER BY il.po_line_no LOOP
    n := n + 1;
    IF l.po_price IS NULL THEN
      RAISE EXCEPTION 'invoice line % refers to PO line % which does not exist', n, l.po_line_no USING ERRCODE = 'check_violation';
    END IF;
    received := p2p_received_qty(inv.po_id, l.po_line_no);
    billed := p2p_billed_qty(inv.po_id, l.po_line_no, inv.id) + l.quantity;
    IF billed > received THEN
      RAISE EXCEPTION 'PO line %: billed quantity % exceeds confirmed receipts % (3-way match)', l.po_line_no, billed, received
        USING ERRCODE = 'check_violation';
    END IF;
    var_pct := round(abs(l.unit_price - l.po_price) / l.po_price, 6);
    IF var_pct > pol.price_tolerance_pct THEN
      status := 'EXCEPTION';
    END IF;
    sum_lines := sum_lines + l.amount;
    lines := lines || jsonb_build_object('po_line', l.po_line_no, 'po_price', l.po_price, 'invoice_price', l.unit_price,
      'price_variance_pct', var_pct, 'within_tolerance', var_pct <= pol.price_tolerance_pct, 'received_qty', received, 'billed_qty_cumulative', billed);
  END LOOP;
  IF n = 0 THEN
    RAISE EXCEPTION 'an invoice needs at least one line' USING ERRCODE = 'check_violation';
  END IF;
  IF sum_lines <> inv.subtotal THEN
    RAISE EXCEPTION 'invoice subtotal % does not equal the sum of its lines %', inv.subtotal, sum_lines USING ERRCODE = 'check_violation';
  END IF;
  want_tax := p2p_round(inv.subtotal * pol.vat_rate, inv.currency);
  IF inv.tax_amount <> want_tax THEN
    RAISE EXCEPTION 'invoice tax % does not equal subtotal x policy VAT rate (%)', inv.tax_amount, want_tax USING ERRCODE = 'check_violation';
  END IF;
  IF inv.total <> inv.subtotal + inv.tax_amount THEN
    RAISE EXCEPTION 'invoice total % does not equal subtotal + tax', inv.total USING ERRCODE = 'check_violation';
  END IF;
  RETURN jsonb_build_object('status', status, 'policy_id', pol.id, 'policy_version', pol.version,
    'price_tolerance_pct', pol.price_tolerance_pct, 'vat_rate', pol.vat_rate, 'lines', lines);
END$$;

-- Canonical text of journal lines: one entry per line, sorted.
CREATE OR REPLACE FUNCTION p2p_lines_text(p_journal uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(string_agg(concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')),
                             ';' ORDER BY concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')) COLLATE "C"), '')
    FROM journal_lines WHERE journal_id = p_journal
$$;

-- The accounting each document must produce. The kernel builds the journal
-- from exactly these lines; p2p_assert_journal then binds the stored journal
-- to them, so tenant SQL cannot substitute different accounting.
CREATE OR REPLACE FUNCTION p2p_expected_lines(p_doc text, p_id uuid)
RETURNS TABLE (account_id uuid, side text, amount numeric, project_id uuid, cost_code_id uuid)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH e(account_id, side, amount, project_id, cost_code_id) AS (
    -- Goods receipt: Dr cost/inventory per line at PO price; Cr GRNI total.
    SELECT pl.account_id, 'DEBIT', p2p_round(gl.qty_received * pl.unit_price, o.currency), o.project_id, pl.cost_code_id
      FROM grns g JOIN purchase_orders o ON o.id = g.po_id JOIN grn_lines gl ON gl.grn_id = g.id
      JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
     WHERE p_doc = 'P2P_GRN' AND g.id = p_id AND g.tenant_id = current_tenant()
    UNION ALL
    SELECT (p2p_policy_for(o.legal_entity_id)).grni_account_id, 'CREDIT',
           sum(p2p_round(gl.qty_received * pl.unit_price, o.currency)), o.project_id, NULL::uuid
      FROM grns g JOIN purchase_orders o ON o.id = g.po_id JOIN grn_lines gl ON gl.grn_id = g.id
      JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
     WHERE p_doc = 'P2P_GRN' AND g.id = p_id AND g.tenant_id = current_tenant()
     GROUP BY o.legal_entity_id, o.project_id
    UNION ALL
    -- Invoice: Dr GRNI at PO price; Dr/Cr price variance per line; Dr VAT; Cr AP total.
    SELECT pol.grni_account_id, 'DEBIT', sum(p2p_round(il.quantity * pl.unit_price, i.currency)), o.project_id, NULL::uuid
      FROM supplier_invoices i JOIN purchase_orders o ON o.id = i.po_id JOIN p2p_policies pol ON pol.id = i.policy_id
      JOIN invoice_lines il ON il.invoice_id = i.id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = il.po_line_no
     WHERE p_doc = 'P2P_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
     GROUP BY pol.grni_account_id, o.project_id
    UNION ALL
    SELECT pol.ppv_account_id, CASE WHEN il.amount > p2p_round(il.quantity * pl.unit_price, i.currency) THEN 'DEBIT' ELSE 'CREDIT' END,
           abs(il.amount - p2p_round(il.quantity * pl.unit_price, i.currency)), o.project_id, pl.cost_code_id
      FROM supplier_invoices i JOIN purchase_orders o ON o.id = i.po_id JOIN p2p_policies pol ON pol.id = i.policy_id
      JOIN invoice_lines il ON il.invoice_id = i.id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = il.po_line_no
     WHERE p_doc = 'P2P_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant() AND il.amount <> p2p_round(il.quantity * pl.unit_price, i.currency)
    UNION ALL
    SELECT pol.vat_input_account_id, 'DEBIT', i.tax_amount, NULL::uuid, NULL::uuid
      FROM supplier_invoices i JOIN p2p_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'P2P_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant() AND i.tax_amount > 0
    UNION ALL
    SELECT pol.ap_account_id, 'CREDIT', i.total, NULL::uuid, NULL::uuid
      FROM supplier_invoices i JOIN p2p_policies pol ON pol.id = i.policy_id
     WHERE p_doc = 'P2P_INVOICE' AND i.id = p_id AND i.tenant_id = current_tenant()
    UNION ALL
    -- Payment release: Dr AP; Cr payments in transit (the bank's clearing account).
    SELECT pol.ap_account_id, 'DEBIT', p.amount, NULL::uuid, NULL::uuid
      FROM payment_instructions p JOIN p2p_policies pol ON pol.id = p.policy_id
     WHERE p_doc = 'P2P_PAYMENT' AND p.id = p_id AND p.tenant_id = current_tenant()
    UNION ALL
    SELECT b.clearing_account_id, 'CREDIT', p.amount, NULL::uuid, NULL::uuid
      FROM payment_instructions p JOIN company_bank_accounts b ON b.id = p.company_bank_id
     WHERE p_doc = 'P2P_PAYMENT' AND p.id = p_id AND p.tenant_id = current_tenant()
    UNION ALL
    -- Bank settlement (from the statement): Dr clearing; Cr bank.
    SELECT b.clearing_account_id, 'DEBIT', -l.amount, NULL::uuid, NULL::uuid
      FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id JOIN company_bank_accounts b ON b.id = s.company_bank_id
     WHERE p_doc = 'P2P_SETTLEMENT' AND l.id = p_id AND l.tenant_id = current_tenant()
    UNION ALL
    SELECT b.gl_account_id, 'CREDIT', -l.amount, NULL::uuid, NULL::uuid
      FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id JOIN company_bank_accounts b ON b.id = s.company_bank_id
     WHERE p_doc = 'P2P_SETTLEMENT' AND l.id = p_id AND l.tenant_id = current_tenant()
  )
  SELECT account_id, side, amount, project_id, cost_code_id FROM e WHERE amount > 0
$$;

CREATE OR REPLACE FUNCTION p2p_expected_text(p_doc text, p_id uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT COALESCE(string_agg(concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')),
                             ';' ORDER BY concat_ws('|', account_id, side, amount::numeric(24,6), COALESCE(project_id::text, '-'), COALESCE(cost_code_id::text, '-')) COLLATE "C"), '')
    FROM p2p_expected_lines(p_doc, p_id)
$$;

-- A generated journal must be this document's: DRAFT, right source, entity,
-- currency, business date and exactly the expected lines.
CREATE OR REPLACE FUNCTION p2p_assert_journal(p_journal uuid, p_doc text, p_id uuid, p_entity uuid, p_ccy char(3), p_date date) RETURNS void
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
  want := p2p_expected_text(p_doc, p_id);
  got := p2p_lines_text(p_journal);
  IF want = '' OR want IS DISTINCT FROM got THEN
    RAISE EXCEPTION 'journal % lines do not equal the accounting of % % (expected %, got %)', p_journal, p_doc, p_id, want, got
      USING ERRCODE = 'check_violation';
  END IF;
END$$;

-- Bank details fingerprint (fraud control: a payment carries the hash of the
-- approved details it was prepared against).
CREATE OR REPLACE FUNCTION p2p_bank_snapshot(p_bank uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT encode(sha256(convert_to(concat_ws('|', b.id, b.supplier_id, b.bank_name, b.account_name, b.account_number, b.currency, b.status, b.approved_by), 'UTF8')), 'hex')
    FROM supplier_bank_accounts b WHERE b.id = p_bank AND b.tenant_id = current_tenant()
$$;

-- Generic "only these columns may change" check for documents.
CREATE OR REPLACE FUNCTION p2p_only_changed(o jsonb, n jsonb, mutable text[], what text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS $$
DECLARE k text;
BEGIN
  FOR k IN SELECT jsonb_object_keys(n) LOOP
    IF NOT (k = ANY (mutable)) AND (o->k) IS DISTINCT FROM (n->k) THEN
      RAISE EXCEPTION '% column % cannot be changed in this transition', what, k USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END$$;

-- Next document number: PREFIX-YYYY-000001.
CREATE OR REPLACE FUNCTION p2p_next_number(p_doc text) RETURNS text
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, public AS $$
DECLARE y integer := extract(year FROM now())::integer; n integer;
BEGIN
  INSERT INTO p2p_counters(doc_type, year, last) VALUES (p_doc, y, 1)
  ON CONFLICT (tenant_id, doc_type, year) DO UPDATE SET last = p2p_counters.last + 1
  RETURNING last INTO n;
  RETURN p_doc || '-' || y || '-' || lpad(n::text, 6, '0');
END$$;

-- ===========================================================================
-- Guards: state machines, attested transitions, frozen content
-- ===========================================================================

CREATE OR REPLACE FUNCTION p2p_policies_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE le legal_entities;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO le FROM legal_entities WHERE id = NEW.legal_entity_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'P2P policies are created DRAFT in the entity''s functional currency' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT type FROM accounts WHERE id = NEW.grni_account_id) <> 'LIABILITY' OR (SELECT type FROM accounts WHERE id = NEW.ap_account_id) <> 'LIABILITY'
       OR (SELECT type FROM accounts WHERE id = NEW.vat_input_account_id) <> 'ASSET' OR (SELECT type FROM accounts WHERE id = NEW.ppv_account_id) <> 'EXPENSE'
       OR NEW.grni_account_id = NEW.ap_account_id THEN
      RAISE EXCEPTION 'P2P policy accounts: GRNI and AP must be distinct LIABILITY accounts, VAT input ASSET, price variance EXPENSE' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'p2p policy');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'p2p policy');
    PERFORM approval_use('p2p.policy.decide', 'p2p_policy', NEW.id::text, NEW.approved_by, ARRAY['p2p.policy.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'p2p policy');
    PERFORM approval_use('p2p.policy.decide', 'p2p_policy', NEW.id::text, NULL, ARRAY['p2p.policy.approve'], false, 'REJECTED', NULL);
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'RETIRED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'p2p policy');
    IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN p2p_policies p ON p.id::text = a.subject_id
                    WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'p2p.policy.decide' AND a.ctx = 'APPROVED'
                      AND p.legal_entity_id = NEW.legal_entity_id AND p.id <> NEW.id) THEN
      RAISE EXCEPTION 'a P2P policy is retired only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal P2P policy transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER p2p_policies_guard BEFORE INSERT OR UPDATE ON p2p_policies FOR EACH ROW EXECUTE FUNCTION p2p_policies_guard();

CREATE OR REPLACE FUNCTION p2p_policies_successor_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM p2p_policies WHERE tenant_id = NEW.tenant_id AND legal_entity_id = NEW.legal_entity_id AND status = 'APPROVED') THEN
    RAISE EXCEPTION 'retiring a P2P policy requires an approved successor at commit' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER p2p_policies_successor_check AFTER UPDATE ON p2p_policies DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.status = 'RETIRED' AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION p2p_policies_successor_check();

-- Suppliers -------------------------------------------------------------------
CREATE OR REPLACE FUNCTION suppliers_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL OR NEW.blocked_reason IS NOT NULL THEN
      RAISE EXCEPTION 'suppliers are created PENDING' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'supplier');
  ELSIF NEW.status = 'ACTIVE' AND OLD.status IN ('PENDING', 'BLOCKED') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'blocked_reason'], 'supplier');
    PERFORM approval_use('supplier.approve', 'supplier', NEW.id::text, NEW.approved_by, ARRAY['supplier.approve'], false, 'ACTIVE', NULL);
    NEW.approved_at := now();
    NEW.blocked_reason := NULL;
  ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'BLOCKED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'blocked_reason'], 'supplier');
    IF NEW.blocked_reason IS NULL OR length(btrim(NEW.blocked_reason)) < 5 THEN
      RAISE EXCEPTION 'blocking a supplier requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('supplier.block', 'supplier', NEW.id::text, NULL, ARRAY['supplier.approve'], false, 'BLOCKED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal supplier transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER suppliers_guard BEFORE INSERT OR UPDATE ON suppliers FOR EACH ROW EXECUTE FUNCTION suppliers_guard();

CREATE OR REPLACE FUNCTION supplier_bank_accounts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'supplier bank accounts are created PENDING (a second person approves, with MFA)' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'supplier bank account');
  ELSIF OLD.status = 'PENDING' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'supplier bank account');
    PERFORM approval_use('supplier.bank.approve', 'supplier_bank_account', NEW.id::text, NEW.approved_by, ARRAY['supplier.bank.approve'], true, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF NEW.status = 'REVOKED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'supplier bank account');
    PERFORM approval_use('supplier.bank.revoke', 'supplier_bank_account', NEW.id::text, NULL, ARRAY['supplier.bank.approve', 'supplier.manage'], false, 'REVOKED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal supplier bank account transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER supplier_bank_accounts_guard BEFORE INSERT OR UPDATE ON supplier_bank_accounts FOR EACH ROW EXECUTE FUNCTION supplier_bank_accounts_guard();

-- BOQ -------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION boq_versions_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE le legal_entities; bad text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO le FROM legal_entities WHERE id = NEW.legal_entity_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'BOQ versions are created DRAFT in the entity''s functional currency' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'BOQ version');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'BOQ version');
    IF NOT EXISTS (SELECT 1 FROM boq_items WHERE version_id = NEW.id) THEN
      RAISE EXCEPTION 'a BOQ needs at least one item' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('boq.submit', 'boq_version', NEW.id::text, NEW.created_by, ARRAY['boq.manage'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'decision_reason'], 'BOQ version');
    -- Every item must be costed to an ACTIVE code of this project's approved WBS.
    SELECT i.item_no INTO bad FROM boq_items i JOIN cost_codes c ON c.id = i.cost_code_id
      JOIN wbs_nodes n ON n.id = c.wbs_node_id JOIN wbs_versions w ON w.id = n.version_id
     WHERE i.version_id = NEW.id AND (c.project_id <> NEW.project_id OR c.status <> 'ACTIVE' OR w.status <> 'APPROVED') LIMIT 1;
    IF bad IS NOT NULL THEN
      RAISE EXCEPTION 'BOQ item % is not costed to an active code of the project''s approved WBS', bad USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('boq.decide', 'boq_version', NEW.id::text, NEW.approved_by, ARRAY['boq.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'BOQ version');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a BOQ requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('boq.decide', 'boq_version', NEW.id::text, NULL, ARRAY['boq.approve'], false, 'REJECTED', NULL);
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'SUPERSEDED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'BOQ version');
    IF NOT EXISTS (SELECT 1 FROM approval_attestations a JOIN boq_versions v ON v.id::text = a.subject_id
                    WHERE a.txid = txid_current() AND a.tenant_id = current_tenant() AND a.action = 'boq.decide' AND a.ctx = 'APPROVED'
                      AND v.project_id = NEW.project_id AND v.id <> NEW.id) THEN
      RAISE EXCEPTION 'a BOQ version is superseded only by the attested approval of its successor' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSE
    RAISE EXCEPTION 'illegal BOQ transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER boq_versions_guard BEFORE INSERT OR UPDATE ON boq_versions FOR EACH ROW EXECUTE FUNCTION boq_versions_guard();

CREATE OR REPLACE FUNCTION boq_versions_successor_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM boq_versions WHERE tenant_id = NEW.tenant_id AND project_id = NEW.project_id AND status = 'APPROVED') THEN
    RAISE EXCEPTION 'superseding a BOQ requires an approved successor at commit' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER boq_versions_successor_check AFTER UPDATE ON boq_versions DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.status = 'SUPERSEDED' AND OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION boq_versions_successor_check();

CREATE OR REPLACE FUNCTION boq_items_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v boq_versions;
BEGIN
  SELECT * INTO v FROM boq_versions WHERE id = NEW.version_id AND tenant_id = current_tenant() FOR SHARE;
  IF v.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'BOQ items change only while the version is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.version_id <> OLD.version_id OR NEW.id <> OLD.id) THEN
    RAISE EXCEPTION 'a BOQ item cannot move between versions' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM cost_codes c WHERE c.id = NEW.cost_code_id AND c.project_id = v.project_id) THEN
    RAISE EXCEPTION 'BOQ item % is costed to a code of another project', NEW.item_no USING ERRCODE = 'check_violation';
  END IF;
  NEW.amount := p2p_round(NEW.quantity * NEW.rate, v.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER boq_items_guard BEFORE INSERT OR UPDATE ON boq_items FOR EACH ROW EXECUTE FUNCTION boq_items_guard();

-- Purchase requisitions ----------------------------------------------------------
CREATE OR REPLACE FUNCTION p2p_assert_budget(p_pr uuid, p_po uuid) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
-- Returns NULL when every cost code of the document fits its available
-- budget, otherwise a description of the first shortfall.
DECLARE r record; pos record;
BEGIN
  FOR r IN SELECT cost_code_id, sum(amount) AS need FROM (
             SELECT cost_code_id, est_amount AS amount FROM pr_lines WHERE p_pr IS NOT NULL AND pr_id = p_pr
             UNION ALL SELECT cost_code_id, amount FROM po_lines WHERE p_po IS NOT NULL AND po_id = p_po) d
           GROUP BY cost_code_id ORDER BY cost_code_id LOOP
    SELECT * INTO pos FROM p2p_cost_position(r.cost_code_id, COALESCE(p_pr, (SELECT q.pr_id FROM purchase_orders o JOIN rfqs q ON q.id = o.rfq_id WHERE o.id = p_po)), p_po);
    IF r.need > pos.available THEN
      RETURN format('cost code %s: needs %s, available %s (budget %s, committed %s, reserved %s, other actual %s)',
                    (SELECT code FROM cost_codes WHERE id = r.cost_code_id), r.need, pos.available, pos.budget, pos.committed, pos.reserved, pos.actual_other);
    END IF;
  END LOOP;
  RETURN NULL;
END$$;

CREATE OR REPLACE FUNCTION purchase_requisitions_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE le legal_entities; short text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO le FROM legal_entities WHERE id = NEW.legal_entity_id AND tenant_id = current_tenant();
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'requisitions are created DRAFT in the entity''s functional currency' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'requisition');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'requisition');
    IF NOT EXISTS (SELECT 1 FROM pr_lines WHERE pr_id = NEW.id) THEN
      RAISE EXCEPTION 'a requisition needs at least one line' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('pr.submit', 'purchase_requisition', NEW.id::text, NEW.requested_by, ARRAY['pr.create'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'decision_reason'], 'requisition');
    PERFORM approval_use('pr.decide', 'purchase_requisition', NEW.id::text, NEW.approved_by, ARRAY['pr.approve'], false, 'APPROVED', NULL);
    short := p2p_assert_budget(NEW.id, NULL);
    IF short IS NOT NULL THEN
      RAISE EXCEPTION 'requisition exceeds the approved BOQ budget: %', short USING ERRCODE = 'check_violation';
    END IF;
    NEW.approved_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'requisition');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting a requisition requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('pr.decide', 'purchase_requisition', NEW.id::text, NULL, ARRAY['pr.approve'], false, 'REJECTED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal requisition transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER purchase_requisitions_guard BEFORE INSERT OR UPDATE ON purchase_requisitions FOR EACH ROW EXECUTE FUNCTION purchase_requisitions_guard();

CREATE OR REPLACE FUNCTION pr_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE r purchase_requisitions; bi record;
BEGIN
  SELECT * INTO r FROM purchase_requisitions WHERE id = NEW.pr_id AND tenant_id = current_tenant() FOR SHARE;
  IF r.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'requisition lines change only while DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM cost_codes c WHERE c.id = NEW.cost_code_id AND c.project_id = r.project_id AND c.status = 'ACTIVE') THEN
    RAISE EXCEPTION 'requisition line % must use an active cost code of the project', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.boq_item_id IS NOT NULL THEN
    SELECT i.cost_code_id, v.status, v.project_id INTO bi FROM boq_items i JOIN boq_versions v ON v.id = i.version_id WHERE i.id = NEW.boq_item_id;
    IF bi.status IS DISTINCT FROM 'APPROVED' OR bi.project_id <> r.project_id OR bi.cost_code_id <> NEW.cost_code_id THEN
      RAISE EXCEPTION 'requisition line % must reference an item of the project''s approved BOQ with the same cost code', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  NEW.est_amount := p2p_round(NEW.quantity * NEW.est_unit_price, r.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER pr_lines_guard BEFORE INSERT OR UPDATE ON pr_lines FOR EACH ROW EXECUTE FUNCTION pr_lines_guard();

-- RFQ ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rfqs_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE invited integer; q rfq_quotes; cheaper boolean; missing integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.awarded_quote_id IS NOT NULL OR NEW.awarded_by IS NOT NULL THEN
      RAISE EXCEPTION 'RFQs are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT status FROM purchase_requisitions WHERE id = NEW.pr_id AND tenant_id = current_tenant()) IS DISTINCT FROM 'APPROVED' THEN
      RAISE EXCEPTION 'an RFQ is raised only for an APPROVED requisition' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'RFQ');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'ISSUED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'issued_at'], 'RFQ');
    SELECT count(*) INTO invited FROM rfq_suppliers WHERE rfq_id = NEW.id;
    IF invited = 0 OR (invited < NEW.min_suppliers AND NEW.single_source_reason IS NULL) THEN
      RAISE EXCEPTION 'an RFQ is issued to at least % suppliers (invited %) unless single-sourcing is justified', NEW.min_suppliers, invited
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.due_at <= now() THEN
      RAISE EXCEPTION 'RFQ due date must be in the future when issued' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('rfq.issue', 'rfq', NEW.id::text, NEW.created_by, ARRAY['rfq.manage'], false, NULL, NULL);
    NEW.issued_at := now();
  ELSIF OLD.status = 'ISSUED' AND NEW.status = 'AWARDED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'awarded_quote_id', 'awarded_by', 'awarded_at', 'award_reason'], 'RFQ');
    SELECT * INTO q FROM rfq_quotes WHERE id = NEW.awarded_quote_id AND rfq_id = NEW.id;
    IF q.id IS NULL OR q.technical_status <> 'COMPLIANT' THEN
      RAISE EXCEPTION 'only a technically COMPLIANT quote of this RFQ can be awarded' USING ERRCODE = 'check_violation';
    END IF;
    IF q.valid_until < current_date THEN
      RAISE EXCEPTION 'the quote expired on %', q.valid_until USING ERRCODE = 'check_violation';
    END IF;
    SELECT count(*) INTO missing FROM pr_lines pl WHERE pl.pr_id = NEW.pr_id
       AND NOT EXISTS (SELECT 1 FROM rfq_quote_lines ql WHERE ql.quote_id = q.id AND ql.pr_line_no = pl.line_no);
    IF missing > 0 THEN
      RAISE EXCEPTION 'the awarded quote does not price % requisition line(s)', missing USING ERRCODE = 'check_violation';
    END IF;
    -- Commercial evaluation: not the lowest compliant total needs a reason.
    SELECT EXISTS (SELECT 1 FROM rfq_quotes o WHERE o.rfq_id = NEW.id AND o.technical_status = 'COMPLIANT' AND o.total < q.total
                    AND o.valid_until >= current_date) INTO cheaper;
    IF cheaper AND (NEW.award_reason IS NULL OR length(btrim(NEW.award_reason)) < 20) THEN
      RAISE EXCEPTION 'awarding other than the lowest compliant quote requires a documented reason (20+ characters)' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('rfq.award', 'rfq', NEW.id::text, NEW.awarded_by, ARRAY['rfq.award'], false, NEW.awarded_quote_id::text, NULL);
    NEW.awarded_at := now();
  ELSIF OLD.status IN ('DRAFT', 'ISSUED') AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'RFQ');
    PERFORM approval_use('rfq.cancel', 'rfq', NEW.id::text, NULL, ARRAY['rfq.manage', 'rfq.award'], false, NULL, NULL);
  ELSE
    RAISE EXCEPTION 'illegal RFQ transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER rfqs_guard BEFORE INSERT OR UPDATE ON rfqs FOR EACH ROW EXECUTE FUNCTION rfqs_guard();

CREATE OR REPLACE FUNCTION rfq_suppliers_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT status FROM rfqs WHERE id = NEW.rfq_id AND tenant_id = current_tenant()) IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'suppliers are invited only while the RFQ is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM suppliers s JOIN rfqs q ON q.id = NEW.rfq_id JOIN purchase_requisitions r ON r.id = q.pr_id
                  WHERE s.id = NEW.supplier_id AND s.status = 'ACTIVE' AND s.legal_entity_id = r.legal_entity_id) THEN
    RAISE EXCEPTION 'only ACTIVE suppliers of the requisition''s entity can be invited' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER rfq_suppliers_guard BEFORE INSERT ON rfq_suppliers FOR EACH ROW EXECUTE FUNCTION rfq_suppliers_guard();

CREATE OR REPLACE FUNCTION rfq_quotes_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st text; pr_ccy char(3);
BEGIN
  SELECT q.status, r.currency INTO st, pr_ccy FROM rfqs q JOIN purchase_requisitions r ON r.id = q.pr_id WHERE q.id = NEW.rfq_id AND q.tenant_id = current_tenant();
  IF TG_OP = 'INSERT' THEN
    IF st IS DISTINCT FROM 'ISSUED' OR NEW.technical_status <> 'PENDING' OR NEW.evaluated_by IS NOT NULL OR NEW.currency <> pr_ccy THEN
      RAISE EXCEPTION 'quotes are recorded PENDING, in the requisition currency, while the RFQ is ISSUED' USING ERRCODE = 'check_violation';
    END IF;
    NEW.total := 0;
    RETURN NEW;
  END IF;
  -- The total is always the sum of the lines (recomputed, never accepted).
  NEW.total := COALESCE((SELECT sum(amount) FROM rfq_quote_lines WHERE quote_id = NEW.id), 0);
  IF NEW.technical_status = OLD.technical_status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['total'], 'quote');
  ELSIF OLD.technical_status = 'PENDING' AND NEW.technical_status IN ('COMPLIANT', 'NON_COMPLIANT') THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['total', 'technical_status', 'technical_note', 'evaluated_by', 'evaluated_at'], 'quote');
    IF st IS DISTINCT FROM 'ISSUED' THEN
      RAISE EXCEPTION 'quotes are evaluated while the RFQ is ISSUED' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.technical_status = 'NON_COMPLIANT' AND (NEW.technical_note IS NULL OR length(btrim(NEW.technical_note)) < 5) THEN
      RAISE EXCEPTION 'a non-compliant evaluation requires a note' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rfq_quote_lines WHERE quote_id = NEW.id) THEN
      RAISE EXCEPTION 'an empty quote cannot be evaluated' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('rfq.evaluate', 'rfq_quote', NEW.id::text, NEW.evaluated_by, ARRAY['rfq.evaluate'], false, NEW.technical_status, NULL);
    NEW.evaluated_at := now();
  ELSE
    RAISE EXCEPTION 'illegal quote evaluation % -> %', OLD.technical_status, NEW.technical_status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER rfq_quotes_guard BEFORE INSERT OR UPDATE ON rfq_quotes FOR EACH ROW EXECUTE FUNCTION rfq_quotes_guard();

CREATE OR REPLACE FUNCTION rfq_quote_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE q rfq_quotes; st text; pl pr_lines;
BEGIN
  SELECT * INTO q FROM rfq_quotes WHERE id = NEW.quote_id AND tenant_id = current_tenant() FOR UPDATE;
  SELECT status INTO st FROM rfqs WHERE id = q.rfq_id;
  IF st IS DISTINCT FROM 'ISSUED' OR q.technical_status <> 'PENDING' THEN
    RAISE EXCEPTION 'quote lines are recorded only while the RFQ is ISSUED and the quote is not yet evaluated' USING ERRCODE = 'check_violation';
  END IF;
  SELECT l.* INTO pl FROM pr_lines l JOIN rfqs r ON r.pr_id = l.pr_id WHERE r.id = q.rfq_id AND l.line_no = NEW.pr_line_no;
  IF pl.pr_id IS NULL THEN
    RAISE EXCEPTION 'quote line % does not match a requisition line', NEW.pr_line_no USING ERRCODE = 'check_violation';
  END IF;
  NEW.quantity := pl.quantity;
  NEW.amount := p2p_round(pl.quantity * NEW.unit_price, q.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER rfq_quote_lines_guard BEFORE INSERT ON rfq_quote_lines FOR EACH ROW EXECUTE FUNCTION rfq_quote_lines_guard();

CREATE OR REPLACE FUNCTION rfq_quote_lines_total() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE rfq_quotes SET total = total WHERE id = NEW.quote_id;  -- the quote guard recomputes
  RETURN NULL;
END$$;
CREATE TRIGGER rfq_quote_lines_total AFTER INSERT ON rfq_quote_lines FOR EACH ROW EXECUTE FUNCTION rfq_quote_lines_total();

-- Purchase orders --------------------------------------------------------------------
CREATE OR REPLACE FUNCTION purchase_orders_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE q rfqs; qt rfq_quotes; r purchase_requisitions; le legal_entities; pol p2p_policies; short text; ev approval_attestations; lines_missing integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO q FROM rfqs WHERE id = NEW.rfq_id AND tenant_id = current_tenant();
    SELECT * INTO qt FROM rfq_quotes WHERE id = q.awarded_quote_id;
    SELECT * INTO r FROM purchase_requisitions WHERE id = q.pr_id;
    SELECT * INTO le FROM legal_entities WHERE id = r.legal_entity_id;
    IF q.status IS DISTINCT FROM 'AWARDED' OR NEW.quote_id IS DISTINCT FROM q.awarded_quote_id OR NEW.supplier_id <> qt.supplier_id
       OR NEW.project_id <> r.project_id OR NEW.legal_entity_id <> r.legal_entity_id OR NEW.currency <> qt.currency
       OR NEW.currency <> le.functional_currency THEN
      RAISE EXCEPTION 'a PO is raised from the awarded quote of an AWARDED RFQ (same supplier, project, entity, currency)' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL OR NEW.over_budget OR NEW.approver_mfa THEN
      RAISE EXCEPTION 'purchase orders are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    NEW.total := 0;
    RETURN NEW;
  END IF;
  NEW.total := COALESCE((SELECT sum(amount) FROM po_lines WHERE po_id = NEW.id), 0);
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), CASE WHEN OLD.status = 'DRAFT' THEN ARRAY['total', 'budget_override_reason'] ELSE '{}'::text[] END, 'purchase order');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['total', 'status', 'approved_by', 'approved_at', 'over_budget', 'approver_mfa', 'budget_override_reason'], 'purchase order');
    SELECT count(*) INTO lines_missing FROM rfq_quote_lines ql WHERE ql.quote_id = NEW.quote_id
       AND NOT EXISTS (SELECT 1 FROM po_lines l WHERE l.po_id = NEW.id AND l.line_no = ql.pr_line_no);
    IF lines_missing > 0 OR NEW.total = 0 THEN
      RAISE EXCEPTION 'the PO must carry every line of the awarded quote' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT status FROM suppliers WHERE id = NEW.supplier_id) <> 'ACTIVE' THEN
      RAISE EXCEPTION 'the supplier is not ACTIVE' USING ERRCODE = 'check_violation';
    END IF;
    pol := p2p_policy_for(NEW.legal_entity_id);
    IF pol.id IS NULL THEN
      RAISE EXCEPTION 'no approved P2P policy for the entity' USING ERRCODE = 'check_violation';
    END IF;
    short := p2p_assert_budget(NULL, NEW.id);
    ev := approval_use('po.approve', 'purchase_order', NEW.id::text, NEW.approved_by, ARRAY['po.approve'], false,
                       CASE WHEN short IS NULL THEN 'APPROVED' ELSE 'APPROVED_OVER_BUDGET' END, NULL);
    IF short IS NOT NULL THEN
      -- Rule-based escalation: an over-budget PO needs budget.override, a
      -- recent MFA and a documented reason.
      IF NOT ('budget.override' = ANY (ev.perms) AND ev.mfa_fresh) OR NEW.budget_override_reason IS NULL THEN
        RAISE EXCEPTION 'PO exceeds the approved budget (%); approval needs budget.override, recent MFA and a reason', short USING ERRCODE = 'insufficient_privilege';
      END IF;
      NEW.over_budget := true;
    END IF;
    IF NEW.total >= pol.high_value_po_threshold AND NOT ('approval.high_value' = ANY (ev.perms) AND ev.mfa_fresh) THEN
      RAISE EXCEPTION 'a PO of % % or more needs approval.high_value with a recent MFA', pol.high_value_po_threshold, NEW.currency USING ERRCODE = 'insufficient_privilege';
    END IF;
    NEW.approver_mfa := ev.mfa_fresh;
    NEW.approved_at := now();
  ELSIF OLD.status = 'APPROVED' AND NEW.status = 'CLOSED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'total'], 'purchase order');
    PERFORM approval_use('po.close', 'purchase_order', NEW.id::text, NULL, ARRAY['po.approve'], false, NULL, NULL);
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'CANCELLED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'total'], 'purchase order');
    PERFORM approval_use('po.cancel', 'purchase_order', NEW.id::text, NULL, ARRAY['po.manage', 'po.approve'], false, NULL, NULL);
  ELSE
    RAISE EXCEPTION 'illegal purchase order transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER purchase_orders_guard BEFORE INSERT OR UPDATE ON purchase_orders FOR EACH ROW EXECUTE FUNCTION purchase_orders_guard();

CREATE OR REPLACE FUNCTION po_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE o purchase_orders; ql rfq_quote_lines; pl pr_lines; acct accounts;
BEGIN
  SELECT * INTO o FROM purchase_orders WHERE id = NEW.po_id AND tenant_id = current_tenant() FOR UPDATE;
  IF o.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'PO lines are added only while the PO is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO ql FROM rfq_quote_lines WHERE quote_id = o.quote_id AND pr_line_no = NEW.line_no;
  SELECT l.* INTO pl FROM pr_lines l JOIN rfqs q ON q.pr_id = l.pr_id WHERE q.id = o.rfq_id AND l.line_no = NEW.line_no;
  IF ql.quote_id IS NULL OR pl.pr_id IS NULL THEN
    RAISE EXCEPTION 'PO line % has no awarded quote line', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  -- Price, quantity, cost code and description come from the award; only
  -- the GL account (cost vs inventory) is chosen here.
  IF NEW.unit_price <> ql.unit_price OR NEW.quantity <> pl.quantity OR NEW.cost_code_id <> pl.cost_code_id
     OR NEW.description <> pl.description OR NEW.unit <> pl.unit THEN
    RAISE EXCEPTION 'PO line % must carry the awarded price and the requisitioned quantity, cost code, description and unit', NEW.line_no
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO acct FROM accounts WHERE id = NEW.account_id AND tenant_id = current_tenant();
  IF acct.id IS NULL OR NOT acct.active OR acct.type NOT IN ('ASSET', 'EXPENSE') OR acct.legal_entity_id <> o.legal_entity_id THEN
    RAISE EXCEPTION 'PO line % must post to an active cost (EXPENSE) or inventory (ASSET) account of the entity', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  NEW.legal_entity_id := o.legal_entity_id;
  NEW.amount := p2p_round(NEW.quantity * NEW.unit_price, o.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER po_lines_guard BEFORE INSERT ON po_lines FOR EACH ROW EXECUTE FUNCTION po_lines_guard();

CREATE OR REPLACE FUNCTION po_lines_total() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE purchase_orders SET total = total WHERE id = NEW.po_id;
  RETURN NULL;
END$$;
CREATE TRIGGER po_lines_total AFTER INSERT ON po_lines FOR EACH ROW EXECUTE FUNCTION po_lines_total();

-- Goods receipts ------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION grns_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE o purchase_orders; pol p2p_policies; bad record;
BEGIN
  SELECT * INTO o FROM purchase_orders WHERE id = NEW.po_id AND tenant_id = current_tenant();
  IF TG_OP = 'INSERT' THEN
    IF o.status IS DISTINCT FROM 'APPROVED' OR NEW.status <> 'DRAFT' OR NEW.confirmed_by IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'goods receipts are created DRAFT against an APPROVED PO' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.received_on > current_date THEN
      RAISE EXCEPTION 'a receipt cannot be dated in the future' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'goods receipt');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'goods receipt');
    IF NOT EXISTS (SELECT 1 FROM grn_lines WHERE grn_id = NEW.id) THEN
      RAISE EXCEPTION 'a goods receipt needs at least one line' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('grn.submit', 'grn', NEW.id::text, NEW.created_by, ARRAY['grn.create'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'CONFIRMED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'confirmed_by', 'confirmed_at', 'journal_id'], 'goods receipt');
    IF o.status IS DISTINCT FROM 'APPROVED' THEN
      RAISE EXCEPTION 'the PO is %', o.status USING ERRCODE = 'check_violation';
    END IF;
    pol := p2p_policy_for(o.legal_entity_id);
    PERFORM 1 FROM purchase_orders WHERE id = o.id FOR UPDATE;  -- serialise receipts of one PO
    SELECT gl.po_line_no, pl.quantity AS ordered, p2p_received_qty(o.id, gl.po_line_no) + gl.qty_received AS cum INTO bad
      FROM grn_lines gl JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
     WHERE gl.grn_id = NEW.id AND p2p_received_qty(o.id, gl.po_line_no) + gl.qty_received > pl.quantity * (1 + pol.over_receipt_pct)
     LIMIT 1;
    IF bad.po_line_no IS NOT NULL THEN
      RAISE EXCEPTION 'PO line %: cumulative receipts % exceed ordered % beyond the over-receipt tolerance', bad.po_line_no, bad.cum, bad.ordered
        USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('grn.confirm', 'grn', NEW.id::text, NEW.confirmed_by, ARRAY['grn.confirm'], false, 'CONFIRMED', NULL);
    PERFORM p2p_assert_journal(NEW.journal_id, 'P2P_GRN', NEW.id, o.legal_entity_id, o.currency, NEW.received_on);
    NEW.confirmed_at := now();
  ELSE
    RAISE EXCEPTION 'illegal goods receipt transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER grns_guard BEFORE INSERT OR UPDATE ON grns FOR EACH ROW EXECUTE FUNCTION grns_guard();

CREATE OR REPLACE FUNCTION grn_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE g grns;
BEGIN
  SELECT * INTO g FROM grns WHERE id = NEW.grn_id AND tenant_id = current_tenant() FOR SHARE;
  IF g.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'receipt lines are added only while the receipt is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM po_lines WHERE po_id = g.po_id AND line_no = NEW.po_line_no) THEN
    RAISE EXCEPTION 'receipt line refers to PO line % which does not exist', NEW.po_line_no USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER grn_lines_guard BEFORE INSERT ON grn_lines FOR EACH ROW EXECUTE FUNCTION grn_lines_guard();

-- Supplier invoices -------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION supplier_invoices_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE o purchase_orders; pol p2p_policies; m jsonb; ev approval_attestations;
BEGIN
  SELECT * INTO o FROM purchase_orders WHERE id = NEW.po_id AND tenant_id = current_tenant();
  IF TG_OP = 'INSERT' THEN
    IF o.status IS DISTINCT FROM 'APPROVED' OR NEW.supplier_id <> o.supplier_id OR NEW.currency <> o.currency THEN
      RAISE EXCEPTION 'an invoice is entered against an APPROVED PO of the same supplier and currency' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status <> 'DRAFT' OR NEW.match_status <> 'PENDING' OR NEW.approved_by IS NOT NULL OR NEW.journal_id IS NOT NULL OR NEW.policy_id IS NOT NULL THEN
      RAISE EXCEPTION 'invoices are entered DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM assert_currency_precision(NEW.subtotal, NEW.currency, 'invoice subtotal');
    PERFORM assert_currency_precision(NEW.tax_amount, NEW.currency, 'invoice tax');
    PERFORM assert_currency_precision(NEW.total, NEW.currency, 'invoice total');
    NEW.normalized_number := upper(regexp_replace(NEW.invoice_number, '[^A-Za-z0-9]', '', 'g'));
    IF NEW.normalized_number = '' THEN
      RAISE EXCEPTION 'invoice number must contain letters or digits' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'invoice');
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at', 'policy_id', 'match_status', 'match_detail'], 'invoice');
    pol := p2p_policy_for(o.legal_entity_id);
    IF pol.id IS NULL THEN
      RAISE EXCEPTION 'no approved P2P policy for the entity' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM 1 FROM purchase_orders WHERE id = o.id FOR UPDATE;  -- serialise billing of one PO
    PERFORM approval_use('ap.submit', 'supplier_invoice', NEW.id::text, NEW.entered_by, ARRAY['ap.enter'], false, NULL, NULL);
    -- The match result is computed here; the statement cannot choose it.
    m := p2p_match_invoice(NEW.id, pol.id);
    NEW.policy_id := pol.id;
    NEW.match_status := m->>'status';
    NEW.match_detail := m;
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at', 'approver_mfa', 'exception_reason', 'journal_id'], 'invoice');
    PERFORM 1 FROM purchase_orders WHERE id = o.id FOR UPDATE;
    -- Re-run the match: receipts and other billing may have changed since submission.
    m := p2p_match_invoice(NEW.id, OLD.policy_id);
    IF m->>'status' IS DISTINCT FROM OLD.match_status THEN
      RAISE EXCEPTION 'the match result changed since submission (% -> %); re-submit the invoice', OLD.match_status, m->>'status' USING ERRCODE = 'check_violation';
    END IF;
    -- ctx binds the approver to the match outcome they saw.
    ev := approval_use('ap.approve', 'supplier_invoice', NEW.id::text, NEW.approved_by, ARRAY['ap.approve'], false, OLD.match_status, NULL);
    IF OLD.match_status = 'EXCEPTION' THEN
      IF NOT ('ap.approve_exception' = ANY (ev.perms) AND ev.mfa_fresh) OR NEW.exception_reason IS NULL OR length(btrim(NEW.exception_reason)) < 20 THEN
        RAISE EXCEPTION 'approving a match exception needs ap.approve_exception, a recent MFA and a reason (20+ characters)' USING ERRCODE = 'insufficient_privilege';
      END IF;
    ELSIF NEW.exception_reason IS NOT NULL THEN
      RAISE EXCEPTION 'exception_reason applies only to match exceptions' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM p2p_assert_journal(NEW.journal_id, 'P2P_INVOICE', NEW.id, o.legal_entity_id, o.currency, NEW.invoice_date);
    NEW.approver_mfa := ev.mfa_fresh;
    NEW.approved_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'REJECTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'invoice');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'rejecting an invoice requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('ap.reject', 'supplier_invoice', NEW.id::text, NULL, ARRAY['ap.approve'], false, NULL, NULL);
  ELSE
    RAISE EXCEPTION 'illegal invoice transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER supplier_invoices_guard BEFORE INSERT OR UPDATE ON supplier_invoices FOR EACH ROW EXECUTE FUNCTION supplier_invoices_guard();

CREATE OR REPLACE FUNCTION invoice_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE i supplier_invoices;
BEGIN
  SELECT * INTO i FROM supplier_invoices WHERE id = NEW.invoice_id AND tenant_id = current_tenant() FOR SHARE;
  IF i.status IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'invoice lines are added only while the invoice is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM po_lines WHERE po_id = i.po_id AND line_no = NEW.po_line_no) THEN
    RAISE EXCEPTION 'invoice line refers to PO line % which does not exist', NEW.po_line_no USING ERRCODE = 'check_violation';
  END IF;
  NEW.amount := p2p_round(NEW.quantity * NEW.unit_price, i.currency);
  RETURN NEW;
END$$;
CREATE TRIGGER invoice_lines_guard BEFORE INSERT ON invoice_lines FOR EACH ROW EXECUTE FUNCTION invoice_lines_guard();

-- Company bank accounts ----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION company_bank_accounts_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'company bank accounts are created PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT type FROM accounts WHERE id = NEW.gl_account_id) <> 'ASSET' OR (SELECT type FROM accounts WHERE id = NEW.clearing_account_id) <> 'ASSET' THEN
      RAISE EXCEPTION 'bank and payments-in-transit GL accounts must be ASSET accounts' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.status = OLD.status THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'company bank account');
  ELSIF OLD.status = 'PENDING' AND NEW.status = 'ACTIVE' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'company bank account');
    PERFORM approval_use('bankacct.approve', 'company_bank_account', NEW.id::text, NEW.approved_by, ARRAY['bankacct.approve'], true, 'ACTIVE', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status = 'ACTIVE' AND NEW.status = 'CLOSED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status'], 'company bank account');
    PERFORM approval_use('bankacct.close', 'company_bank_account', NEW.id::text, NULL, ARRAY['bankacct.approve'], true, 'CLOSED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal bank account transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER company_bank_accounts_guard BEFORE INSERT OR UPDATE ON company_bank_accounts FOR EACH ROW EXECUTE FUNCTION company_bank_accounts_guard();

-- Payment instructions ---------------------------------------------------------------------------
-- Re-validated at every step: supplier ACTIVE, bank account APPROVED and its
-- details unchanged since the instruction was prepared.
CREATE OR REPLACE FUNCTION p2p_assert_payee(p payment_instructions) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT status FROM suppliers WHERE id = p.supplier_id) IS DISTINCT FROM 'ACTIVE' THEN
    RAISE EXCEPTION 'the supplier is not ACTIVE' USING ERRCODE = 'check_violation';
  END IF;
  IF (SELECT status FROM supplier_bank_accounts WHERE id = p.supplier_bank_id) IS DISTINCT FROM 'APPROVED'
     OR p2p_bank_snapshot(p.supplier_bank_id) IS DISTINCT FROM p.bank_snapshot THEN
    RAISE EXCEPTION 'the supplier bank details are no longer the approved details this payment was prepared against' USING ERRCODE = 'check_violation';
  END IF;
  IF (SELECT status FROM company_bank_accounts WHERE id = p.company_bank_id) IS DISTINCT FROM 'ACTIVE' THEN
    RAISE EXCEPTION 'the paying bank account is not ACTIVE' USING ERRCODE = 'check_violation';
  END IF;
END$$;

-- No AI or system identity may ever authorise a payment (directive §5, §7).
CREATE OR REPLACE FUNCTION p2p_assert_human(p_actor text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, public AS $$
BEGIN
  IF p_actor IS NULL OR p_actor ~* '^(system|ai|agent|bot|service)[:_-]' THEN
    RAISE EXCEPTION 'payments are authorised only by human principals (actor %)', p_actor USING ERRCODE = 'insufficient_privilege';
  END IF;
END$$;

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
    IF (NEW.amount >= pol.dual_payment_threshold) <> (NEW.status = 'PARTIALLY_APPROVED') THEN
      RAISE EXCEPTION 'payments of % % or more need two approvers (first approval -> PARTIALLY_APPROVED)', pol.dual_payment_threshold, NEW.currency
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
CREATE TRIGGER payment_instructions_guard BEFORE INSERT OR UPDATE ON payment_instructions FOR EACH ROW EXECUTE FUNCTION payment_instructions_guard();

CREATE OR REPLACE FUNCTION payment_allocations_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF (SELECT status FROM payment_instructions WHERE id = NEW.payment_id AND tenant_id = current_tenant()) IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'allocations are added only while the payment is DRAFT' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER payment_allocations_guard BEFORE INSERT ON payment_allocations FOR EACH ROW EXECUTE FUNCTION payment_allocations_guard();

-- Bank statements --------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION bank_statements_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE prev numeric;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'bank statements are immutable once imported' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (SELECT status FROM company_bank_accounts WHERE id = NEW.company_bank_id AND tenant_id = current_tenant()) IS DISTINCT FROM 'ACTIVE' THEN
    RAISE EXCEPTION 'statements are imported for ACTIVE bank accounts' USING ERRCODE = 'check_violation';
  END IF;
  -- Continuity: opening balance = closing balance of the previous statement.
  SELECT closing_balance INTO prev FROM bank_statements
   WHERE company_bank_id = NEW.company_bank_id AND statement_date <= NEW.statement_date ORDER BY statement_date DESC, imported_at DESC LIMIT 1;
  IF prev IS NOT NULL AND prev <> NEW.opening_balance THEN
    RAISE EXCEPTION 'statement opening balance % does not continue the previous closing balance %', NEW.opening_balance, prev USING ERRCODE = 'check_violation';
  END IF;
  -- The statement file itself is attested (digest of the uploaded bytes).
  PERFORM approval_use('bank.import', 'bank_statement_source', NEW.source_sha256, NEW.imported_by, ARRAY['bank.import'], false, NEW.company_bank_id::text, NULL);
  RETURN NEW;
END$$;
CREATE TRIGGER bank_statements_guard BEFORE INSERT OR UPDATE ON bank_statements FOR EACH ROW EXECUTE FUNCTION bank_statements_guard();

CREATE OR REPLACE FUNCTION bank_statements_balance_check() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE s numeric;
BEGIN
  SELECT COALESCE(sum(amount), 0) INTO s FROM bank_statement_lines WHERE statement_id = NEW.id;
  IF NEW.opening_balance + s <> NEW.closing_balance THEN
    RAISE EXCEPTION 'statement % does not balance: opening % + lines % <> closing %', NEW.statement_no, NEW.opening_balance, s, NEW.closing_balance
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER bank_statements_balance_check AFTER INSERT ON bank_statements DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION bank_statements_balance_check();

CREATE OR REPLACE FUNCTION bank_statement_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE st bank_statements; p payment_instructions; cb company_bank_accounts;
BEGIN
  SELECT * INTO st FROM bank_statements WHERE id = NEW.statement_id AND tenant_id = current_tenant();
  SELECT * INTO cb FROM company_bank_accounts WHERE id = st.company_bank_id;
  IF TG_OP = 'INSERT' THEN
    -- Lines belong to the import transaction of their statement only.
    IF (SELECT xmin::text::bigint FROM bank_statements WHERE id = NEW.statement_id) <> txid_current() % 4294967296 THEN
      RAISE EXCEPTION 'statement lines are imported together with their statement' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status <> 'UNMATCHED' OR NEW.payment_id IS NOT NULL OR NEW.journal_id IS NOT NULL THEN
      RAISE EXCEPTION 'statement lines are imported UNMATCHED' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM assert_currency_precision(NEW.amount, cb.currency, 'statement line');
    RETURN NEW;
  END IF;
  IF OLD.status = 'UNMATCHED' AND NEW.status = 'MATCHED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'payment_id', 'matched_by', 'matched_at', 'journal_id'], 'statement line');
    SELECT * INTO p FROM payment_instructions WHERE id = NEW.payment_id AND tenant_id = current_tenant();
    IF p.status IS DISTINCT FROM 'RELEASED' OR p.company_bank_id <> st.company_bank_id OR NEW.amount <> -p.amount
       OR position(upper(p.number) IN upper(NEW.reference)) = 0 THEN
      RAISE EXCEPTION 'statement line % does not match payment % (must be RELEASED from this account, same amount out, reference containing the payment number)',
        NEW.line_no, p.number USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.matched_by = p.released_by THEN
      RAISE EXCEPTION 'the person who released a payment cannot reconcile it' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('bank.reconcile', 'bank_statement_line', NEW.id::text, NEW.matched_by, ARRAY['bank.reconcile'], false, NEW.payment_id::text, NULL);
    PERFORM p2p_assert_journal(NEW.journal_id, 'P2P_SETTLEMENT', NEW.id, cb.legal_entity_id, cb.currency, NEW.booking_date);
    NEW.matched_at := now();
  ELSE
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), '{}', 'statement line');
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER bank_statement_lines_guard BEFORE INSERT OR UPDATE ON bank_statement_lines FOR EACH ROW EXECUTE FUNCTION bank_statement_lines_guard();

-- ---------------------------------------------------------------------------
-- Subledger journals: reserved source types, bound to their document, never
-- cancelled (a document's accounting is corrected by reversal).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION journals_subledger_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.source_type LIKE 'P2P\_%' AND TG_OP = 'UPDATE' AND NEW.status = 'CANCELLED' AND OLD.status <> 'CANCELLED' THEN
    RAISE EXCEPTION 'subledger journals are not cancelled; correct the source document' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_subledger_guard BEFORE UPDATE ON journals FOR EACH ROW EXECUTE FUNCTION journals_subledger_guard();

CREATE OR REPLACE FUNCTION journals_subledger_binding() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE bound boolean;
BEGIN
  bound := CASE NEW.source_type
      WHEN 'P2P_GRN' THEN EXISTS (SELECT 1 FROM grns WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'P2P_INVOICE' THEN EXISTS (SELECT 1 FROM supplier_invoices WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      WHEN 'P2P_PAYMENT' THEN EXISTS (SELECT 1 FROM payment_instructions WHERE id::text = NEW.source_ref AND release_journal_id = NEW.id)
      WHEN 'P2P_SETTLEMENT' THEN EXISTS (SELECT 1 FROM bank_statement_lines WHERE id::text = NEW.source_ref AND journal_id = NEW.id)
      ELSE false END;
  IF NOT bound THEN
    RAISE EXCEPTION 'journal % uses reserved source type % but no % document references it', NEW.id, NEW.source_type, NEW.source_type
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER journals_subledger_binding AFTER INSERT ON journals DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW WHEN (NEW.source_type LIKE 'P2P\_%') EXECUTE FUNCTION journals_subledger_binding();

-- ===========================================================================
-- Approval subject hashes for the new documents (canonical jsonb of the row
-- and its children: every column is covered, cf. IR-L2). The 0007 branches
-- are carried over unchanged.
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_subject_text(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE t uuid := current_tenant(); j jsonb;
BEGIN
  IF p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN NULL;
  END IF;
  CASE p_type
  WHEN 'p2p_policy' THEN SELECT to_jsonb(x) INTO j FROM p2p_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier' THEN SELECT to_jsonb(x) INTO j FROM suppliers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_bank_account' THEN SELECT to_jsonb(x) INTO j FROM supplier_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'company_bank_account' THEN SELECT to_jsonb(x) INTO j FROM company_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
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
             'payee', (SELECT to_jsonb(b) FROM supplier_bank_accounts b WHERE b.id = x.supplier_bank_id))
      INTO j FROM payment_instructions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'bank_statement_line' THEN
    SELECT jsonb_build_object('l', to_jsonb(x) - 'journal_id', 's', (SELECT to_jsonb(s) FROM bank_statements s WHERE s.id = x.statement_id))
      INTO j FROM bank_statement_lines x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$$;

CREATE OR REPLACE FUNCTION approval_subject_hash(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE h text; t uuid := current_tenant();
BEGIN
  IF p_type = 'journal' THEN
    SELECT concat_ws('|', j.id, j.legal_entity_id, COALESCE(j.project_id::text, ''), j.functional_currency,
             extract(epoch FROM j.business_event_at)::text, j.description, j.source_type, COALESCE(j.source_ref, ''),
             COALESCE(j.reversal_of::text, ''), j.created_by, j.command_hash,
             (SELECT string_agg(concat_ws(',', l.line_no, l.account_id, l.side, l.amount::text, l.currency, COALESCE(l.txn_amount::text, ''),
                       COALESCE(l.txn_currency, ''), COALESCE(l.fx_snapshot_id::text, ''), COALESCE(l.project_id::text, ''),
                       COALESCE(l.cost_code_id::text, ''), COALESCE(l.memo, '')), ';' ORDER BY l.line_no)
                FROM journal_lines l WHERE l.journal_id = j.id))
      INTO h FROM journals j WHERE j.tenant_id = t AND j.id::text = p_id;
  ELSIF p_type = 'fx_snapshot' THEN
    SELECT concat_ws('|', snapshot_id, base_currency, quote_currency, rate::text, rate_type, source_id,
                     extract(epoch FROM effective_from_utc)::text, source_document_hash, approval_status)
      INTO h FROM fx_snapshots WHERE tenant_id = t AND snapshot_id::text = p_id;
  ELSIF p_type = 'fx_source' THEN
    SELECT concat_ws('|', source_id, source_type, max_variance::text, requires_document_hash::text, status, created_by)
      INTO h FROM fx_sources WHERE tenant_id = t AND source_id = p_id;
  ELSIF p_type = 'fx_policy' THEN
    SELECT concat_ws('|', id, legal_entity_id, purpose, version, rate_type, array_to_string(source_priority, ','),
                     extract(epoch FROM max_staleness)::text, allow_inverse::text, status, created_by)
      INTO h FROM fx_policies WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type = 'wbs_version' THEN
    SELECT concat_ws('|', v.id, v.project_id, v.version, v.status, v.created_by,
             (SELECT string_agg(n.code || '=' || n.name, ';' ORDER BY n.code COLLATE "C") FROM wbs_nodes n WHERE n.version_id = v.id),
             (SELECT string_agg(c.code || '=' || c.cost_type, ';' ORDER BY c.code COLLATE "C") FROM cost_codes c JOIN wbs_nodes n ON n.id = c.wbs_node_id WHERE n.version_id = v.id))
      INTO h FROM wbs_versions v WHERE v.tenant_id = t AND v.id::text = p_id;
  ELSIF p_type = 'fiscal_period' THEN
    SELECT concat_ws('|', id, legal_entity_id, starts_on, ends_on, status, COALESCE(closed_by, ''))
      INTO h FROM fiscal_periods WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type = 'workflow_definition' THEN
    SELECT concat_ws('|', id, key, version, status, body_hash, proposed_by) INTO h FROM workflow_definitions WHERE tenant_id = t AND id::text = p_id;
  ELSIF p_type IN ('workflow_definition_body', 'bank_statement_source') THEN
    RETURN p_id;  -- the subject IS a digest computed from the content
  ELSIF p_type = 'workflow_instance' THEN
    SELECT concat_ws('|', id, definition_id, current_step, status, facts->>'fingerprint') INTO h FROM workflow_instances WHERE tenant_id = t AND id::text = p_id;
  ELSE
    h := p2p_subject_text(p_type, p_id);
  END IF;
  IF h IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN encode(sha256(convert_to(h, 'UTF8')), 'hex');
END$$;

-- ===========================================================================
-- Reporting: project cost position and subledger-to-GL reconciliation
-- ===========================================================================
CREATE OR REPLACE FUNCTION p2p_project_cost_report(p_project uuid)
RETURNS TABLE (cost_code_id uuid, cost_code text, budget numeric, committed numeric, reserved numeric, received numeric,
               invoiced numeric, actual_posted numeric, actual_other numeric, available numeric)
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT c.id, c.code, pos.budget, pos.committed, pos.reserved,
         COALESCE((SELECT sum(p2p_round(gl.qty_received * pl.unit_price, o.currency)) FROM grn_lines gl JOIN grns g ON g.id = gl.grn_id
                    JOIN purchase_orders o ON o.id = g.po_id JOIN po_lines pl ON pl.po_id = o.id AND pl.line_no = gl.po_line_no
                   WHERE g.status = 'CONFIRMED' AND pl.cost_code_id = c.id), 0),
         COALESCE((SELECT sum(il.amount) FROM invoice_lines il JOIN supplier_invoices i ON i.id = il.invoice_id
                    JOIN po_lines pl ON pl.po_id = i.po_id AND pl.line_no = il.po_line_no
                   WHERE i.status = 'APPROVED' AND pl.cost_code_id = c.id), 0),
         COALESCE((SELECT sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END) FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
                   WHERE jl.cost_code_id = c.id AND j.status IN ('POSTED', 'REVERSED')), 0),
         pos.actual_other, pos.available
    FROM cost_codes c CROSS JOIN LATERAL p2p_cost_position(c.id, NULL, NULL) pos
   WHERE c.tenant_id = current_tenant() AND c.project_id = p_project
     AND (pos.budget <> 0 OR pos.committed <> 0 OR pos.reserved <> 0 OR pos.actual_other <> 0)
   ORDER BY c.code
$$;

-- Each check compares a subledger figure computed from documents whose
-- journals are POSTED with the GL balance of the mapped account. Any
-- non-zero difference is a reconciliation break.
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
    SELECT COALESCE((SELECT sum(l.amount) FROM bank_statement_lines l JOIN journals j ON j.id = l.journal_id
                      JOIN bank_statements s ON s.id = l.statement_id WHERE s.company_bank_id = b.id AND j.status = 'POSTED'), 0) INTO sub;
    SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO g
      FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id WHERE jl.account_id = b.gl_account_id AND j.status IN ('POSTED', 'REVERSED');
    check_name := 'Bank (reconciled movements): ' || b.name; subledger := sub; gl := g; difference := g - sub;
    SELECT count(*) INTO unposted_documents FROM bank_statement_lines l JOIN bank_statements s ON s.id = l.statement_id
     WHERE s.company_bank_id = b.id AND l.status = 'UNMATCHED';
    RETURN NEXT;
  END LOOP;
END$$;

-- ===========================================================================
-- Row-level security and grants (least privilege; no DELETE anywhere)
-- ===========================================================================
DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['p2p_counters', 'p2p_policies', 'suppliers', 'supplier_bank_accounts', 'boq_versions', 'boq_items',
                              'purchase_requisitions', 'pr_lines', 'rfqs', 'rfq_suppliers', 'rfq_quotes', 'rfq_quote_lines',
                              'purchase_orders', 'po_lines', 'grns', 'grn_lines', 'supplier_invoices', 'invoice_lines',
                              'company_bank_accounts', 'payment_instructions', 'payment_allocations', 'bank_statements', 'bank_statement_lines'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;

GRANT UPDATE (last) ON p2p_counters TO serk_app;
GRANT UPDATE (status, approved_by) ON p2p_policies TO serk_app;
GRANT UPDATE (status, approved_by, blocked_reason) ON suppliers TO serk_app;
GRANT UPDATE (status, approved_by) ON supplier_bank_accounts TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON boq_versions TO serk_app;
GRANT UPDATE (description, unit, quantity, rate, cost_code_id) ON boq_items TO serk_app;
GRANT UPDATE (status, approved_by, decision_reason) ON purchase_requisitions TO serk_app;
GRANT UPDATE (description, unit, quantity, est_unit_price, cost_code_id, boq_item_id) ON pr_lines TO serk_app;
GRANT UPDATE (status, awarded_quote_id, awarded_by, award_reason) ON rfqs TO serk_app;
GRANT UPDATE (total, technical_status, technical_note, evaluated_by) ON rfq_quotes TO serk_app;
GRANT UPDATE (total, status, approved_by, budget_override_reason) ON purchase_orders TO serk_app;
GRANT UPDATE (status, confirmed_by, journal_id) ON grns TO serk_app;
GRANT UPDATE (status, approved_by, exception_reason, decision_reason, journal_id) ON supplier_invoices TO serk_app;
GRANT UPDATE (status, approved_by) ON company_bank_accounts TO serk_app;
GRANT UPDATE (status, approved_by, second_approved_by, released_by, release_journal_id, cancel_reason) ON payment_instructions TO serk_app;
GRANT UPDATE (status, payment_id, matched_by, journal_id) ON bank_statement_lines TO serk_app;

GRANT EXECUTE ON FUNCTION round_half_even(numeric, integer), p2p_round(numeric, char), p2p_policy_for(uuid),
  p2p_cost_position(uuid, uuid, uuid), p2p_received_qty(uuid, integer), p2p_billed_qty(uuid, integer, uuid),
  p2p_match_invoice(uuid, uuid), p2p_lines_text(uuid), p2p_expected_lines(text, uuid), p2p_expected_text(text, uuid),
  p2p_assert_journal(uuid, text, uuid, uuid, char, date), p2p_bank_snapshot(uuid), p2p_only_changed(jsonb, jsonb, text[], text),
  p2p_next_number(text), p2p_assert_budget(uuid, uuid), p2p_assert_payee(payment_instructions), p2p_assert_human(text),
  p2p_subject_text(text, text), p2p_project_cost_report(uuid), p2p_gl_reconciliation(uuid)
TO serk_app;
