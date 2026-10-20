-- SERK Construction — PostgreSQL Financial Kernel, migration 0001
--
-- Enforces at the database boundary (LAW 03, LAW 04, LAW 06):
--   * every tenant-owned row carries tenant_id and is filtered by RLS
--   * journals, lines, accounts and projects are bound to one legal entity
--   * posted journals balance (deferred constraint trigger)
--   * approved/posted journals and their lines are immutable
--   * foreign-currency lines reference an APPROVED snapshot of the right pair
--     and reconcile to it
--   * the audit log is append-only, hash-chained and serialised per tenant
--   * every committed business change writes to the transactional outbox
--
-- Roles: migrations run as the schema owner; the application connects as a
-- member of serk_app, which is NOT a superuser and NOT the table owner, so RLS
-- applies. serk_publisher is the only role that may mark outbox rows sent.
--
-- Isolation note (LAW 04): RLS keyed on a session GUC protects against
-- application defects (a missing tenant filter) and limits every statement to
-- the tenant the kernel bound in the transaction. It is NOT a boundary against
-- an attacker who can execute arbitrary SQL as the application role, because
-- that role can itself call set_config. Tenants requiring that stronger
-- guarantee use the DEDICATED_DB deployment mode (one database per tenant).

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_app') THEN
    CREATE ROLE serk_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_publisher') THEN
    CREATE ROLE serk_publisher NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END$$;

CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------
-- Reference data: ISO 4217 precision used by the FX reconciliation trigger.
-- Mirrors pkg/money's seed; additional currencies are inserted by admins.
-- ---------------------------------------------------------------------------
CREATE TABLE currencies (
  code        char(3) PRIMARY KEY,
  minor_units smallint NOT NULL CHECK (minor_units BETWEEN 0 AND 6),
  name        text NOT NULL
);
INSERT INTO currencies(code, minor_units, name) VALUES
 ('ETB',2,'Ethiopian Birr'),('KES',2,'Kenyan Shilling'),('UGX',0,'Ugandan Shilling'),('TZS',2,'Tanzanian Shilling'),
 ('RWF',0,'Rwandan Franc'),('NGN',2,'Nigerian Naira'),('GHS',2,'Ghanaian Cedi'),('ZAR',2,'South African Rand'),
 ('EGP',2,'Egyptian Pound'),('MAD',2,'Moroccan Dirham'),('XOF',0,'CFA Franc BCEAO'),('XAF',0,'CFA Franc BEAC'),
 ('DJF',0,'Djiboutian Franc'),('SDG',2,'Sudanese Pound'),('SSP',2,'South Sudanese Pound'),('SOS',2,'Somali Shilling'),
 ('ERN',2,'Eritrean Nakfa'),('MZN',2,'Mozambican Metical'),('ZMW',2,'Zambian Kwacha'),('BWP',2,'Pula'),
 ('NAD',2,'Namibia Dollar'),('AOA',2,'Kwanza'),('CDF',2,'Congolese Franc'),('BIF',0,'Burundi Franc'),
 ('MWK',2,'Malawi Kwacha'),('MUR',2,'Mauritius Rupee'),('TND',3,'Tunisian Dinar'),('DZD',2,'Algerian Dinar'),
 ('LYD',3,'Libyan Dinar'),('USD',2,'US Dollar'),('EUR',2,'Euro'),('GBP',2,'Pound Sterling'),('CNY',2,'Yuan Renminbi'),
 ('AED',2,'UAE Dirham'),('SAR',2,'Saudi Riyal'),('INR',2,'Indian Rupee'),('JPY',0,'Yen'),('TRY',2,'Turkish Lira'),
 ('KWD',3,'Kuwaiti Dinar'),('BHD',3,'Bahraini Dinar'),('CHF',2,'Swiss Franc');

-- ---------------------------------------------------------------------------
-- Organisational entities
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  mode        text NOT NULL DEFAULT 'SHARED' CHECK (mode IN ('SHARED','DEDICATED_DB','DEDICATED_DEPLOYMENT')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE legal_entities (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES tenants(id),
  name                  text NOT NULL,
  country               char(2) NOT NULL,
  functional_currency   char(3) NOT NULL REFERENCES currencies(code),
  presentation_currency char(3) REFERENCES currencies(code),
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, id, functional_currency)
);

CREATE TABLE projects (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id   uuid NOT NULL,
  code              text NOT NULL,
  name              text NOT NULL,
  contract_currency char(3) REFERENCES currencies(code),
  status            text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PLANNED','ACTIVE','SUSPENDED','CLOSED')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, code),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id)
);

CREATE TABLE accounts (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  code            text NOT NULL,
  name            text NOT NULL,
  type            text NOT NULL CHECK (type IN ('ASSET','LIABILITY','EQUITY','REVENUE','EXPENSE')),
  currency        char(3) REFERENCES currencies(code),   -- restricts transaction currency when set
  active          boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, legal_entity_id, code),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id)
);

CREATE TABLE fiscal_periods (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  name            text NOT NULL,
  starts_on       date NOT NULL,
  ends_on         date NOT NULL CHECK (ends_on >= starts_on),
  status          text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED','LOCKED')),
  closed_by       text,
  closed_at       timestamptz,
  UNIQUE (tenant_id, legal_entity_id, name),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  EXCLUDE USING gist (tenant_id WITH =, legal_entity_id WITH =, daterange(starts_on, ends_on, '[]') WITH &&)
);

-- LOCKED is terminal; reopening a CLOSED period is allowed (and audited by the kernel).
CREATE OR REPLACE FUNCTION fiscal_periods_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fiscal periods cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status = 'LOCKED' THEN
    RAISE EXCEPTION 'fiscal period % is LOCKED and cannot change', OLD.name USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.legal_entity_id <> OLD.legal_entity_id
     OR NEW.starts_on <> OLD.starts_on OR NEW.ends_on <> OLD.ends_on THEN
    RAISE EXCEPTION 'fiscal period boundaries are immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fiscal_periods_guard BEFORE UPDATE OR DELETE ON fiscal_periods FOR EACH ROW EXECUTE FUNCTION fiscal_periods_guard();

-- ---------------------------------------------------------------------------
-- FX snapshots (immutable observations; field set per specification §3.2)
-- ---------------------------------------------------------------------------
CREATE TABLE fx_snapshots (
  snapshot_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id              uuid NOT NULL REFERENCES tenants(id),
  source_id              text NOT NULL,
  source_type            text NOT NULL,
  base_currency          char(3) NOT NULL REFERENCES currencies(code),
  quote_currency         char(3) NOT NULL REFERENCES currencies(code) CHECK (quote_currency <> base_currency),
  rate                   numeric(24,12) NOT NULL CHECK (rate > 0),
  rate_type              text NOT NULL,
  effective_from_utc     timestamptz NOT NULL,
  published_at_utc       timestamptz NOT NULL,
  captured_at_utc        timestamptz NOT NULL DEFAULT now(),
  business_event_at_utc  timestamptz,
  source_document_hash   text NOT NULL,
  algorithm_version      text NOT NULL,
  approval_status        text NOT NULL DEFAULT 'PENDING' CHECK (approval_status IN ('PENDING','APPROVED','DISPUTED','REJECTED')),
  approved_by            text,
  created_by             text NOT NULL,
  UNIQUE (tenant_id, snapshot_id),
  CHECK (captured_at_utc >= published_at_utc),
  CHECK (approval_status <> 'APPROVED' OR approved_by IS NOT NULL)
);
CREATE INDEX fx_snapshots_lookup ON fx_snapshots (tenant_id, base_currency, quote_currency, effective_from_utc DESC);

-- Observations never change; only approval_status/approved_by may move, and an
-- APPROVED snapshot referenced by a journal line can no longer be withdrawn.
CREATE OR REPLACE FUNCTION fx_snapshots_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fx_snapshots are immutable (LAW 06)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF row(NEW.snapshot_id, NEW.tenant_id, NEW.source_id, NEW.source_type, NEW.base_currency, NEW.quote_currency, NEW.rate,
         NEW.rate_type, NEW.effective_from_utc, NEW.published_at_utc, NEW.captured_at_utc, NEW.business_event_at_utc,
         NEW.source_document_hash, NEW.algorithm_version, NEW.created_by)
     IS DISTINCT FROM
     row(OLD.snapshot_id, OLD.tenant_id, OLD.source_id, OLD.source_type, OLD.base_currency, OLD.quote_currency, OLD.rate,
         OLD.rate_type, OLD.effective_from_utc, OLD.published_at_utc, OLD.captured_at_utc, OLD.business_event_at_utc,
         OLD.source_document_hash, OLD.algorithm_version, OLD.created_by) THEN
    RAISE EXCEPTION 'fx_snapshot observation fields are immutable (LAW 06)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.approval_status = 'APPROVED' AND NEW.approval_status <> 'APPROVED'
     AND EXISTS (SELECT 1 FROM journal_lines WHERE fx_snapshot_id = OLD.snapshot_id) THEN
    RAISE EXCEPTION 'snapshot % is referenced by journal lines and cannot be withdrawn', OLD.snapshot_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_snapshots_guard BEFORE UPDATE OR DELETE ON fx_snapshots FOR EACH ROW EXECUTE FUNCTION fx_snapshots_guard();

-- ---------------------------------------------------------------------------
-- Journals and lines
-- ---------------------------------------------------------------------------
CREATE TABLE journals (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id     uuid NOT NULL,
  project_id          uuid,
  functional_currency char(3) NOT NULL,
  status              text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','APPROVED','POSTED','REVERSED','CANCELLED')),
  business_event_at   timestamptz NOT NULL,
  description         text NOT NULL CHECK (length(description) BETWEEN 1 AND 2000),
  source_type         text NOT NULL,
  source_ref          text,
  idempotency_key     text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
  command_hash        text NOT NULL,      -- sha256 of the canonical command (incl. creator)
  created_by          text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  approved_by         text,
  approved_at         timestamptz,
  posted_by           text,
  posted_at           timestamptz,
  reversal_of         uuid,
  reversed_by         uuid,
  version             integer NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, legal_entity_id, id),
  -- The journal's currency IS the entity's functional currency, by foreign key.
  FOREIGN KEY (tenant_id, legal_entity_id, functional_currency) REFERENCES legal_entities(tenant_id, id, functional_currency),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, reversal_of) REFERENCES journals(tenant_id, id),
  FOREIGN KEY (tenant_id, reversed_by) REFERENCES journals(tenant_id, id),
  CHECK (status <> 'APPROVED' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
  CHECK (status NOT IN ('POSTED','REVERSED') OR (approved_by IS NOT NULL AND posted_by IS NOT NULL AND posted_at IS NOT NULL)),
  CHECK (status <> 'REVERSED' OR reversed_by IS NOT NULL),
  CHECK (reversed_by IS NULL OR status = 'REVERSED'),
  CONSTRAINT journals_sod_self_approval CHECK (approved_by IS NULL OR approved_by <> created_by)
);
CREATE INDEX journals_entity_event ON journals (tenant_id, legal_entity_id, business_event_at);
CREATE INDEX journals_project ON journals (tenant_id, project_id) WHERE project_id IS NOT NULL;

CREATE TABLE journal_lines (
  journal_id      uuid NOT NULL,
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  line_no         integer NOT NULL CHECK (line_no >= 1),
  account_id      uuid NOT NULL,
  side            text NOT NULL CHECK (side IN ('DEBIT','CREDIT')),
  amount          numeric(24,6) NOT NULL CHECK (amount > 0),
  currency        char(3) NOT NULL REFERENCES currencies(code),
  txn_amount      numeric(24,6) CHECK (txn_amount IS NULL OR txn_amount > 0),
  txn_currency    char(3) REFERENCES currencies(code),
  fx_snapshot_id  uuid,
  applied_rate    numeric(24,12) CHECK (applied_rate IS NULL OR applied_rate > 0),  -- functional per 1 txn unit
  project_id      uuid,
  cost_code_id    uuid,
  memo            text,
  PRIMARY KEY (journal_id, line_no),
  -- A line belongs to the journal's entity and references that entity's account/project.
  FOREIGN KEY (tenant_id, legal_entity_id, journal_id) REFERENCES journals(tenant_id, legal_entity_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, legal_entity_id, account_id) REFERENCES accounts(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  FOREIGN KEY (tenant_id, fx_snapshot_id) REFERENCES fx_snapshots(tenant_id, snapshot_id),
  -- LAW 06: a foreign-currency amount carries its currency, snapshot and the rate applied.
  CHECK ((txn_amount IS NULL AND txn_currency IS NULL AND fx_snapshot_id IS NULL AND applied_rate IS NULL)
      OR (txn_amount IS NOT NULL AND txn_currency IS NOT NULL AND fx_snapshot_id IS NOT NULL AND applied_rate IS NOT NULL AND txn_currency <> currency))
);
CREATE INDEX journal_lines_account ON journal_lines (tenant_id, account_id);
CREATE INDEX journal_lines_snapshot ON journal_lines (fx_snapshot_id) WHERE fx_snapshot_id IS NOT NULL;

-- Line-level invariants checked on every insert/update:
--   currency == journal functional currency; account active; account currency
--   restriction; FX snapshot APPROVED, right pair, rate consistent, amount reconciles.
CREATE OR REPLACE FUNCTION journal_lines_validate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  j_cur  char(3); j_proj uuid; j_le uuid;
  a_cur  char(3); a_active boolean;
  s      fx_snapshots%ROWTYPE;
  expect numeric; mu smallint;
BEGIN
  SELECT functional_currency, project_id, legal_entity_id INTO j_cur, j_proj, j_le FROM journals WHERE id = NEW.journal_id;
  IF j_cur IS NULL THEN
    RAISE EXCEPTION 'journal % not found for line', NEW.journal_id USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF NEW.currency <> j_cur OR NEW.legal_entity_id <> j_le THEN
    RAISE EXCEPTION 'line % currency/entity differs from journal (%/%)', NEW.line_no, j_cur, j_le USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.project_id IS NOT NULL AND NEW.project_id IS DISTINCT FROM j_proj THEN
    RAISE EXCEPTION 'line % project differs from journal project', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  SELECT currency, active INTO a_cur, a_active FROM accounts WHERE id = NEW.account_id;
  IF NOT a_active THEN
    RAISE EXCEPTION 'account % is inactive', NEW.account_id USING ERRCODE = 'check_violation';
  END IF;
  IF a_cur IS NOT NULL AND a_cur <> j_cur AND NEW.txn_currency IS DISTINCT FROM a_cur THEN
    RAISE EXCEPTION 'account % only accepts % transactions', NEW.account_id, a_cur USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.fx_snapshot_id IS NOT NULL THEN
    SELECT * INTO s FROM fx_snapshots WHERE snapshot_id = NEW.fx_snapshot_id;
    IF s.approval_status <> 'APPROVED' THEN
      RAISE EXCEPTION 'fx snapshot % is not APPROVED', NEW.fx_snapshot_id USING ERRCODE = 'check_violation';
    END IF;
    IF s.base_currency = NEW.txn_currency AND s.quote_currency = NEW.currency THEN
      IF NEW.applied_rate <> s.rate THEN
        RAISE EXCEPTION 'applied_rate % differs from snapshot rate %', NEW.applied_rate, s.rate USING ERRCODE = 'check_violation';
      END IF;
    ELSIF s.base_currency = NEW.currency AND s.quote_currency = NEW.txn_currency THEN
      IF abs(NEW.applied_rate - round(1 / s.rate, 12)) > 0.000000000001 THEN
        RAISE EXCEPTION 'applied_rate % is not the inverse of snapshot rate %', NEW.applied_rate, s.rate USING ERRCODE = 'check_violation';
      END IF;
    ELSE
      RAISE EXCEPTION 'fx snapshot % pair %/% does not convert %->%', NEW.fx_snapshot_id, s.base_currency, s.quote_currency, NEW.txn_currency, NEW.currency USING ERRCODE = 'check_violation';
    END IF;
    SELECT minor_units INTO mu FROM currencies WHERE code = NEW.currency;
    expect := NEW.txn_amount * NEW.applied_rate;
    -- Go quantises exactly (HALF_EVEN); the database tolerates one minor unit of rounding.
    IF abs(NEW.amount - expect) > power(10::numeric, -mu) THEN
      RAISE EXCEPTION 'line % amount % does not reconcile to % x % = %', NEW.line_no, NEW.amount, NEW.txn_amount, NEW.applied_rate, expect USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journal_lines_validate BEFORE INSERT OR UPDATE ON journal_lines FOR EACH ROW EXECUTE FUNCTION journal_lines_validate();

-- Balance invariant: evaluated at COMMIT for any journal that is or becomes POSTED.
CREATE OR REPLACE FUNCTION journal_balance_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  jid uuid; j journals%ROWTYPE; dr numeric; cr numeric; n integer; bad integer;
BEGIN
  IF TG_TABLE_NAME = 'journals' THEN
    jid := NEW.id;
  ELSIF TG_OP = 'DELETE' THEN
    jid := OLD.journal_id;
  ELSE
    jid := NEW.journal_id;
  END IF;
  SELECT * INTO j FROM journals WHERE id = jid;
  IF NOT FOUND OR j.status NOT IN ('APPROVED','POSTED','REVERSED') THEN
    RETURN NULL;
  END IF;
  SELECT COALESCE(SUM(amount) FILTER (WHERE side = 'DEBIT'), 0),
         COALESCE(SUM(amount) FILTER (WHERE side = 'CREDIT'), 0),
         COUNT(*),
         COUNT(*) FILTER (WHERE currency <> j.functional_currency OR tenant_id <> j.tenant_id OR legal_entity_id <> j.legal_entity_id)
    INTO dr, cr, n, bad
    FROM journal_lines WHERE journal_id = jid;
  IF n < 2 THEN
    RAISE EXCEPTION 'journal % has % line(s); at least two required', jid, n USING ERRCODE = 'check_violation';
  END IF;
  IF bad > 0 THEN
    RAISE EXCEPTION 'journal % has lines outside its functional currency, tenant or entity', jid USING ERRCODE = 'check_violation';
  END IF;
  IF dr <> cr THEN
    RAISE EXCEPTION 'journal % does not balance: debits % credits % (LAW 03)', jid, dr, cr USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER journal_balance_on_journal AFTER INSERT OR UPDATE OF status ON journals
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION journal_balance_check();
CREATE CONSTRAINT TRIGGER journal_balance_on_lines AFTER INSERT OR UPDATE OR DELETE ON journal_lines
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION journal_balance_check();

-- Journal guard: state machine, immutability from APPROVED on, period gate,
-- and validation of the reversal link.
CREATE OR REPLACE FUNCTION journals_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pstatus text; r journals%ROWTYPE; o_dr numeric; o_cr numeric; r_dr numeric; r_cr numeric; o_n int; r_n int;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'DRAFT' THEN
      RAISE EXCEPTION 'journal % is % and cannot be deleted (LAW 03)', OLD.id, OLD.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.status <> OLD.status THEN
    IF NOT ((OLD.status = 'DRAFT'    AND NEW.status IN ('APPROVED','CANCELLED')) OR
            (OLD.status = 'APPROVED' AND NEW.status IN ('POSTED','CANCELLED')) OR
            (OLD.status = 'POSTED'   AND NEW.status = 'REVERSED')) THEN
      RAISE EXCEPTION 'illegal journal transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  -- Content is frozen once approved: what the approver saw is what posts.
  IF OLD.status <> 'DRAFT' THEN
    IF row(NEW.tenant_id, NEW.legal_entity_id, NEW.project_id, NEW.functional_currency, NEW.business_event_at, NEW.description,
           NEW.source_type, NEW.source_ref, NEW.idempotency_key, NEW.command_hash, NEW.created_by, NEW.created_at,
           NEW.approved_by, NEW.approved_at, NEW.reversal_of)
       IS DISTINCT FROM
       row(OLD.tenant_id, OLD.legal_entity_id, OLD.project_id, OLD.functional_currency, OLD.business_event_at, OLD.description,
           OLD.source_type, OLD.source_ref, OLD.idempotency_key, OLD.command_hash, OLD.created_by, OLD.created_at,
           OLD.approved_by, OLD.approved_at, OLD.reversal_of) THEN
      RAISE EXCEPTION 'journal % is % and immutable (LAW 03)', OLD.id, OLD.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  IF OLD.status IN ('POSTED','REVERSED') AND (NEW.posted_by IS DISTINCT FROM OLD.posted_by OR NEW.posted_at IS DISTINCT FROM OLD.posted_at) THEN
    RAISE EXCEPTION 'posting record of journal % is immutable', OLD.id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status = 'REVERSED' AND NEW.reversed_by IS DISTINCT FROM OLD.reversed_by THEN
    RAISE EXCEPTION 'reversal link of journal % is immutable', OLD.id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status = 'POSTED' AND OLD.status <> 'POSTED' THEN
    SELECT status INTO pstatus FROM fiscal_periods
      WHERE tenant_id = NEW.tenant_id AND legal_entity_id = NEW.legal_entity_id
        AND (NEW.business_event_at AT TIME ZONE 'UTC')::date BETWEEN starts_on AND ends_on;
    IF pstatus IS NULL THEN
      RAISE EXCEPTION 'no fiscal period covers % for entity %', NEW.business_event_at, NEW.legal_entity_id USING ERRCODE = 'check_violation';
    ELSIF pstatus <> 'OPEN' THEN
      RAISE EXCEPTION 'fiscal period is % — posting refused', pstatus USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  -- A journal may only become REVERSED by a POSTED reversal that mirrors it.
  IF NEW.status = 'REVERSED' AND OLD.status = 'POSTED' THEN
    SELECT * INTO r FROM journals WHERE id = NEW.reversed_by;
    IF NOT FOUND OR r.status <> 'POSTED' OR r.reversal_of IS DISTINCT FROM OLD.id
       OR r.tenant_id <> OLD.tenant_id OR r.legal_entity_id <> OLD.legal_entity_id THEN
      RAISE EXCEPTION 'reversed_by must be a POSTED reversal of journal %', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    SELECT COALESCE(SUM(amount) FILTER (WHERE side='DEBIT'),0), COALESCE(SUM(amount) FILTER (WHERE side='CREDIT'),0), COUNT(*)
      INTO o_dr, o_cr, o_n FROM journal_lines WHERE journal_id = OLD.id;
    SELECT COALESCE(SUM(amount) FILTER (WHERE side='DEBIT'),0), COALESCE(SUM(amount) FILTER (WHERE side='CREDIT'),0), COUNT(*)
      INTO r_dr, r_cr, r_n FROM journal_lines WHERE journal_id = r.id;
    IF o_n <> r_n OR o_dr <> r_cr OR o_cr <> r_dr
       OR EXISTS (SELECT 1 FROM journal_lines a JOIN journal_lines b ON b.journal_id = r.id AND b.line_no = a.line_no
                  WHERE a.journal_id = OLD.id AND (a.account_id <> b.account_id OR a.amount <> b.amount OR a.side = b.side)) THEN
      RAISE EXCEPTION 'reversal % does not mirror journal %', r.id, OLD.id USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  NEW.version := OLD.version + 1;
  RETURN NEW;
END$$;
CREATE TRIGGER journals_guard BEFORE UPDATE OR DELETE ON journals FOR EACH ROW EXECUTE FUNCTION journals_guard();

-- Lines are editable only while the journal is DRAFT.
CREATE OR REPLACE FUNCTION journal_lines_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s text; jid uuid;
BEGIN
  jid := CASE WHEN TG_OP = 'DELETE' THEN OLD.journal_id ELSE NEW.journal_id END;
  SELECT status INTO s FROM journals WHERE id = jid;
  IF s IS DISTINCT FROM 'DRAFT' THEN
    RAISE EXCEPTION 'lines of % journal % are immutable (LAW 03)', COALESCE(s, 'unknown'), jid USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journal_lines_guard BEFORE INSERT OR UPDATE OR DELETE ON journal_lines FOR EACH ROW EXECUTE FUNCTION journal_lines_guard();

-- Reference data referenced by posted history is frozen.
CREATE OR REPLACE FUNCTION accounts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'accounts cannot be deleted; deactivate instead' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (NEW.type, NEW.code, NEW.currency, NEW.legal_entity_id, NEW.tenant_id) IS DISTINCT FROM (OLD.type, OLD.code, OLD.currency, OLD.legal_entity_id, OLD.tenant_id)
     AND EXISTS (SELECT 1 FROM journal_lines WHERE account_id = OLD.id) THEN
    RAISE EXCEPTION 'account % is referenced by journal lines; type/code/currency/entity are frozen', OLD.code USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER accounts_guard BEFORE UPDATE OR DELETE ON accounts FOR EACH ROW EXECUTE FUNCTION accounts_guard();

CREATE OR REPLACE FUNCTION legal_entities_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'legal entities cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (NEW.functional_currency, NEW.tenant_id) IS DISTINCT FROM (OLD.functional_currency, OLD.tenant_id)
     AND EXISTS (SELECT 1 FROM journals WHERE legal_entity_id = OLD.id) THEN
    RAISE EXCEPTION 'functional currency of entity % is frozen once journals exist', OLD.id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER legal_entities_guard BEFORE UPDATE OR DELETE ON legal_entities FOR EACH ROW EXECUTE FUNCTION legal_entities_guard();

-- ---------------------------------------------------------------------------
-- Append-only, hash-chained audit log.
-- Per-tenant head rows serialise appends: the UPDATE takes the row lock and,
-- under READ COMMITTED, re-reads the latest committed head, so the chain is
-- linear regardless of protocol or snapshot behaviour. seq is assigned inside
-- that lock so chain order == seq order. The trigger is SECURITY DEFINER and
-- the app role has no privileges on audit_heads.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_heads (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
  head_hash text NOT NULL,
  chain_len bigint NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
  seq            bigint PRIMARY KEY,
  chain_no       bigint NOT NULL,
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  occurred_at    timestamptz NOT NULL,
  actor_id       text NOT NULL,
  action         text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id   text NOT NULL,
  request_id     text,
  payload        jsonb NOT NULL,
  prev_hash      text NOT NULL,
  hash           text NOT NULL,
  UNIQUE (tenant_id, chain_no)
);
CREATE SEQUENCE audit_log_seq;

CREATE OR REPLACE FUNCTION audit_hash(prev text, seq bigint, chain_no bigint, tenant uuid, occurred timestamptz, actor text,
                                      act text, agg_type text, agg_id text, req text, payload jsonb) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(digest(prev || '|' || seq::text || '|' || chain_no::text || '|' || tenant::text || '|'
         || to_char(occurred AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' || actor || '|' || act || '|'
         || agg_type || '|' || agg_id || '|' || COALESCE(req, '') || '|' || payload::text, 'sha256'), 'hex')
$$;

CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE prev text; n bigint;
BEGIN
  INSERT INTO audit_heads(tenant_id, head_hash) VALUES (NEW.tenant_id, repeat('0', 64)) ON CONFLICT (tenant_id) DO NOTHING;
  UPDATE audit_heads SET chain_len = chain_len + 1 WHERE tenant_id = NEW.tenant_id RETURNING head_hash, chain_len INTO prev, n;
  NEW.seq := nextval('audit_log_seq');
  NEW.chain_no := n;
  NEW.occurred_at := clock_timestamp();
  NEW.prev_hash := prev;
  NEW.hash := audit_hash(prev, NEW.seq, n, NEW.tenant_id, NEW.occurred_at, NEW.actor_id, NEW.action, NEW.aggregate_type, NEW.aggregate_id, NEW.request_id, NEW.payload);
  UPDATE audit_heads SET head_hash = NEW.hash WHERE tenant_id = NEW.tenant_id;
  RETURN NEW;
END$$;
REVOKE ALL ON FUNCTION audit_log_chain() FROM PUBLIC;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

CREATE OR REPLACE FUNCTION audit_log_readonly() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = 'integrity_constraint_violation';
END$$;
CREATE TRIGGER audit_log_readonly BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_readonly();

-- Walks the chain in chain_no order; returns the first inconsistent seq, or NULL.
CREATE OR REPLACE FUNCTION audit_log_verify(p_tenant uuid) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE r audit_log%ROWTYPE; expect_prev text := repeat('0', 64); expect_no bigint := 1; last_seq bigint := 0;
BEGIN
  FOR r IN SELECT * FROM audit_log WHERE tenant_id = p_tenant ORDER BY chain_no LOOP
    IF r.chain_no <> expect_no OR r.seq <= last_seq OR r.prev_hash <> expect_prev
       OR r.hash <> audit_hash(r.prev_hash, r.seq, r.chain_no, r.tenant_id, r.occurred_at, r.actor_id, r.action, r.aggregate_type, r.aggregate_id, r.request_id, r.payload) THEN
      RETURN r.seq;
    END IF;
    expect_prev := r.hash; expect_no := r.chain_no + 1; last_seq := r.seq;
  END LOOP;
  IF EXISTS (SELECT 1 FROM audit_heads WHERE tenant_id = p_tenant AND (head_hash <> expect_prev OR chain_len <> expect_no - 1)) THEN
    RETURN -1;  -- head row disagrees with the log
  END IF;
  RETURN NULL;
END$$;
REVOKE ALL ON FUNCTION audit_log_verify(uuid) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Transactional outbox (LAW 02: AI and integrations consume events, never
-- write to the kernel). The API role can only append; serk_publisher marks rows sent.
-- ---------------------------------------------------------------------------
CREATE TABLE outbox (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  event_id       uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  aggregate_type text NOT NULL,
  aggregate_id   text NOT NULL,
  event_type     text NOT NULL,
  schema_version integer NOT NULL DEFAULT 1,
  payload        jsonb NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  published_at   timestamptz,
  attempts       integer NOT NULL DEFAULT 0
);
CREATE INDEX outbox_unpublished ON outbox (created_at) WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION outbox_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'outbox rows cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF row(NEW.id, NEW.tenant_id, NEW.event_id, NEW.aggregate_type, NEW.aggregate_id, NEW.event_type, NEW.schema_version, NEW.payload, NEW.created_at)
     IS DISTINCT FROM row(OLD.id, OLD.tenant_id, OLD.event_id, OLD.aggregate_type, OLD.aggregate_id, OLD.event_type, OLD.schema_version, OLD.payload, OLD.created_at) THEN
    RAISE EXCEPTION 'outbox event content is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER outbox_guard BEFORE UPDATE OR DELETE ON outbox FOR EACH ROW EXECUTE FUNCTION outbox_guard();

-- ---------------------------------------------------------------------------
-- Row-level security (LAW 04). FORCE so the owner is also constrained.
-- ---------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['legal_entities','projects','accounts','fiscal_periods','fx_snapshots','journals','journal_lines','audit_log','outbox'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END$$;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenants USING (id = current_tenant());
-- audit_heads is reachable only through the SECURITY DEFINER trigger.
ALTER TABLE audit_heads ENABLE ROW LEVEL SECURITY;

-- Application privileges: no DELETE anywhere; audit_log append-only; outbox append-only.
GRANT USAGE ON SCHEMA public TO serk_app, serk_publisher;
GRANT SELECT ON currencies, tenants TO serk_app;
GRANT SELECT, INSERT, UPDATE ON legal_entities, projects, accounts, fiscal_periods, fx_snapshots, journals, journal_lines TO serk_app;
GRANT SELECT, INSERT ON audit_log TO serk_app;
GRANT SELECT, INSERT ON outbox TO serk_app;
GRANT SELECT, UPDATE (published_at, attempts) ON outbox TO serk_publisher;
GRANT USAGE, SELECT ON SEQUENCE outbox_id_seq TO serk_app;
GRANT EXECUTE ON FUNCTION current_tenant() TO serk_app, serk_publisher;
GRANT EXECUTE ON FUNCTION audit_log_verify(uuid) TO serk_app;
GRANT EXECUTE ON FUNCTION audit_hash(text, bigint, bigint, uuid, timestamptz, text, text, text, text, text, jsonb) TO serk_app;
