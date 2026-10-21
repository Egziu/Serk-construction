-- SERK Construction — migration 0002: Gate A ledger integrity remediation
--
-- Additive migration; 0001 is released history and is not edited.
-- Closes (with regression tests in internal/kernel/gate_a_*_test.go):
--   SC-01  journal-line reassignment out of a non-DRAFT journal
--   SC-08  period-close / FX-withdraw races with concurrent posting
--   SC-14  sub-minor-unit amounts written by raw SQL
-- and narrows the application role's UPDATE rights to the columns the
-- kernel actually changes (least privilege).

-- ---------------------------------------------------------------------------
-- Legacy-data register: rows that violate a rule introduced by a later
-- migration are recorded, never silently rewritten (posted history is
-- immutable). Operators resolve them by reversal/re-entry.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS migration_exceptions (
  id          bigserial PRIMARY KEY,
  migration   text NOT NULL,
  rule        text NOT NULL,
  table_name  text NOT NULL,
  row_ref     text NOT NULL,
  detail      text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- SC-01: a line's identity (journal, tenant, entity, line number) is fixed at
-- insert. Any UPDATE/DELETE is checked against the OLD journal, and any
-- INSERT/UPDATE against the NEW journal; both must be DRAFT. The journal row
-- is share-locked so a concurrent approval cannot interleave with a line
-- change (SC-08 family).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION journal_lines_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s_old text; s_new text;
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    SELECT status INTO s_old FROM journals WHERE id = OLD.journal_id FOR SHARE;
    IF s_old IS DISTINCT FROM 'DRAFT' THEN
      RAISE EXCEPTION 'lines of % journal % are immutable (LAW 03)', COALESCE(s_old, 'unknown'), OLD.journal_id
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.journal_id, NEW.tenant_id, NEW.legal_entity_id, NEW.line_no)
       IS DISTINCT FROM (OLD.journal_id, OLD.tenant_id, OLD.legal_entity_id, OLD.line_no) THEN
      RAISE EXCEPTION 'journal line identity (journal, tenant, entity, line_no) is immutable'
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    SELECT status INTO s_new FROM journals WHERE id = NEW.journal_id FOR SHARE;
    IF s_new IS DISTINCT FROM 'DRAFT' THEN
      RAISE EXCEPTION 'lines of % journal % are immutable (LAW 03)', COALESCE(s_new, 'unknown'), NEW.journal_id
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END$$;

-- Balance invariant evaluated for every journal a statement touched: for an
-- UPDATE of a line both the OLD and the NEW journal are re-checked.
CREATE OR REPLACE FUNCTION journal_balance_assert(jid uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE j journals%ROWTYPE; dr numeric; cr numeric; n integer; bad integer;
BEGIN
  SELECT * INTO j FROM journals WHERE id = jid;
  IF NOT FOUND OR j.status NOT IN ('APPROVED', 'POSTED', 'REVERSED') THEN
    RETURN;
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
END$$;

CREATE OR REPLACE FUNCTION journal_balance_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'journals' THEN
    PERFORM journal_balance_assert(NEW.id);
  ELSIF TG_OP = 'DELETE' THEN
    PERFORM journal_balance_assert(OLD.journal_id);
  ELSIF TG_OP = 'UPDATE' THEN
    PERFORM journal_balance_assert(OLD.journal_id);
    IF NEW.journal_id IS DISTINCT FROM OLD.journal_id THEN
      PERFORM journal_balance_assert(NEW.journal_id);
    END IF;
  ELSE
    PERFORM journal_balance_assert(NEW.journal_id);
  END IF;
  RETURN NULL;
END$$;

-- ---------------------------------------------------------------------------
-- SC-14 + SC-08: line validation now enforces currency minor units for both
-- functional and transaction amounts, and share-locks the referenced FX
-- snapshot so a concurrent withdrawal is serialised with the insert.
-- (Superseded by the FX-policy version further below in this migration; the
-- precision and locking logic is carried forward unchanged.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION currency_minor_units(cur char(3)) RETURNS smallint
LANGUAGE sql STABLE AS $$ SELECT minor_units FROM currencies WHERE code = cur $$;

CREATE OR REPLACE FUNCTION assert_currency_precision(amount numeric, cur char(3), what text) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE mu smallint;
BEGIN
  IF amount IS NULL THEN RETURN; END IF;
  mu := currency_minor_units(cur);
  IF mu IS NULL THEN
    RAISE EXCEPTION '% currency % is not registered', what, cur USING ERRCODE = 'check_violation';
  END IF;
  IF amount <> round(amount, mu) THEN
    RAISE EXCEPTION '% % % has more than % decimal place(s) (SC-14)', what, amount, cur, mu USING ERRCODE = 'check_violation';
  END IF;
END$$;

-- ---------------------------------------------------------------------------
-- SC-08: period close is serialised with posting.
--   * posting share-locks the covering fiscal period row until COMMIT;
--   * closing takes the row lock (UPDATE), so it waits for in-flight posts and
--     in-flight posts started after it wait and then see CLOSED;
--   * closing is refused while APPROVED-but-unposted journals exist in the
--     period, and records an immutable closing trial-balance snapshot that is
--     computed after the lock is held.
-- ---------------------------------------------------------------------------
CREATE TABLE fiscal_period_closes (
  id              bigserial PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  period_id       uuid NOT NULL REFERENCES fiscal_periods(id),
  action          text NOT NULL CHECK (action IN ('CLOSE', 'LOCK', 'REOPEN')),
  actor           text NOT NULL,
  reason          text,
  journal_count   integer NOT NULL,
  tb_debits       numeric(28,6) NOT NULL,
  tb_credits      numeric(28,6) NOT NULL,
  tb_hash         text NOT NULL,
  recorded_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id)
);
CREATE INDEX fiscal_period_closes_period ON fiscal_period_closes (period_id, id);

ALTER TABLE fiscal_periods ADD COLUMN reopen_reason text, ADD COLUMN reopened_by text;

CREATE OR REPLACE FUNCTION fiscal_period_tb(p fiscal_periods) RETURNS TABLE (journal_count integer, debits numeric, credits numeric, tb_hash text)
LANGUAGE sql STABLE AS $$
  WITH lines AS (
    SELECT l.journal_id, l.account_id, l.side, l.amount
      FROM journal_lines l JOIN journals j ON j.id = l.journal_id
     WHERE j.tenant_id = p.tenant_id AND j.legal_entity_id = p.legal_entity_id
       AND j.status IN ('POSTED', 'REVERSED')
       AND (j.business_event_at AT TIME ZONE 'UTC')::date BETWEEN p.starts_on AND p.ends_on
  ), per_account AS (
    SELECT account_id, SUM(CASE WHEN side = 'DEBIT' THEN amount ELSE -amount END) AS net
      FROM lines GROUP BY account_id
  )
  SELECT (SELECT COUNT(DISTINCT journal_id) FROM lines)::integer,
         COALESCE((SELECT SUM(amount) FROM lines WHERE side = 'DEBIT'), 0),
         COALESCE((SELECT SUM(amount) FROM lines WHERE side = 'CREDIT'), 0),
         encode(digest(COALESCE((SELECT string_agg(account_id::text || ':' || net::text, '|' ORDER BY account_id) FROM per_account), ''), 'sha256'), 'hex')
$$;

CREATE OR REPLACE FUNCTION fiscal_periods_transition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pending integer; tb record; act text;
BEGIN
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  IF NOT ((OLD.status = 'OPEN' AND NEW.status IN ('CLOSED', 'LOCKED')) OR
          (OLD.status = 'CLOSED' AND NEW.status IN ('OPEN', 'LOCKED'))) THEN
    RAISE EXCEPTION 'illegal fiscal period transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status IN ('CLOSED', 'LOCKED') THEN
    IF NEW.closed_by IS NULL THEN
      RAISE EXCEPTION 'closing a period requires closed_by' USING ERRCODE = 'check_violation';
    END IF;
    SELECT COUNT(*) INTO pending FROM journals
     WHERE tenant_id = OLD.tenant_id AND legal_entity_id = OLD.legal_entity_id AND status = 'APPROVED'
       AND (business_event_at AT TIME ZONE 'UTC')::date BETWEEN OLD.starts_on AND OLD.ends_on;
    IF pending > 0 THEN
      RAISE EXCEPTION 'period % has % approved journal(s) awaiting posting; post or cancel them before closing', OLD.name, pending
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.closed_at := clock_timestamp();
    NEW.reopen_reason := NULL;
    NEW.reopened_by := NULL;
    act := CASE WHEN NEW.status = 'LOCKED' THEN 'LOCK' ELSE 'CLOSE' END;
  ELSE -- CLOSED -> OPEN
    IF NEW.reopen_reason IS NULL OR length(trim(NEW.reopen_reason)) < 5 OR NEW.reopened_by IS NULL THEN
      RAISE EXCEPTION 'reopening a closed period requires reopened_by and a reason' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.reopened_by = OLD.closed_by THEN
      RAISE EXCEPTION 'the user who closed a period cannot reopen it (segregation of duties)' USING ERRCODE = 'check_violation';
    END IF;
    act := 'REOPEN';
  END IF;
  SELECT * INTO tb FROM fiscal_period_tb(OLD);
  INSERT INTO fiscal_period_closes(tenant_id, legal_entity_id, period_id, action, actor, reason, journal_count, tb_debits, tb_credits, tb_hash)
  VALUES (OLD.tenant_id, OLD.legal_entity_id, OLD.id, act,
          CASE WHEN act = 'REOPEN' THEN NEW.reopened_by ELSE NEW.closed_by END,
          NEW.reopen_reason, tb.journal_count, tb.debits, tb.credits, tb.tb_hash);
  IF act = 'REOPEN' THEN
    NEW.closed_by := NULL;
    NEW.closed_at := NULL;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fiscal_periods_transition BEFORE UPDATE ON fiscal_periods FOR EACH ROW EXECUTE FUNCTION fiscal_periods_transition();

CREATE OR REPLACE FUNCTION append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END$$;
CREATE TRIGGER fiscal_period_closes_append_only BEFORE UPDATE OR DELETE ON fiscal_period_closes FOR EACH ROW EXECUTE FUNCTION append_only();
CREATE TRIGGER migration_exceptions_append_only BEFORE UPDATE OR DELETE ON migration_exceptions FOR EACH ROW EXECUTE FUNCTION append_only();

-- ---------------------------------------------------------------------------
-- Legacy data that violates SC-14 is recorded, not rewritten.
-- ---------------------------------------------------------------------------
INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0002', 'SC-14 currency precision', 'journal_lines', l.journal_id::text || '#' || l.line_no,
       'amount ' || l.amount || ' ' || l.currency
  FROM journal_lines l JOIN currencies c ON c.code = l.currency
 WHERE l.amount <> round(l.amount, c.minor_units);
INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0002', 'SC-14 currency precision', 'journal_lines', l.journal_id::text || '#' || l.line_no,
       'txn_amount ' || l.txn_amount || ' ' || l.txn_currency
  FROM journal_lines l JOIN currencies c ON c.code = l.txn_currency
 WHERE l.txn_amount IS NOT NULL AND l.txn_amount <> round(l.txn_amount, c.minor_units);

-- ---------------------------------------------------------------------------
-- Forensic integrity scan. Detects ledger states that the 0.1.0 triggers could
-- not prevent (e.g. a POSTED journal unbalanced via the SC-01 line move).
-- Used by this migration, by period close prerequisites and by reconciliation.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ledger_integrity_scan()
RETURNS TABLE (rule text, journal_id uuid, detail text) LANGUAGE sql STABLE AS $$
  SELECT 'UNBALANCED_POSTED', j.id,
         'status ' || j.status || ': debits ' || COALESCE(SUM(l.amount) FILTER (WHERE l.side = 'DEBIT'), 0)
         || ' credits ' || COALESCE(SUM(l.amount) FILTER (WHERE l.side = 'CREDIT'), 0) || ' lines ' || COUNT(l.*)
    FROM journals j LEFT JOIN journal_lines l ON l.journal_id = j.id
   WHERE j.status IN ('APPROVED', 'POSTED', 'REVERSED')
   GROUP BY j.id, j.status
  HAVING COUNT(l.*) < 2
      OR COALESCE(SUM(l.amount) FILTER (WHERE l.side = 'DEBIT'), 0) <> COALESCE(SUM(l.amount) FILTER (WHERE l.side = 'CREDIT'), 0)
  UNION ALL
  SELECT 'SUBMINOR_AMOUNT', l.journal_id, 'line ' || l.line_no || ' amount ' || l.amount || ' ' || l.currency
    FROM journal_lines l JOIN currencies c ON c.code = l.currency
   WHERE l.amount <> round(l.amount, c.minor_units)
  UNION ALL
  SELECT 'REVERSED_WITHOUT_POSTED_REVERSAL', j.id, 'reversed_by ' || COALESCE(j.reversed_by::text, 'NULL')
    FROM journals j LEFT JOIN journals r ON r.id = j.reversed_by
   WHERE j.status = 'REVERSED' AND (r.id IS NULL OR r.status <> 'POSTED' OR r.reversal_of IS DISTINCT FROM j.id)
$$;

INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0002', 'INTEGRITY ' || rule, 'journals', journal_id::text, detail || ' — investigate as possible prior SC-01 exploitation'
  FROM ledger_integrity_scan() WHERE rule <> 'SUBMINOR_AMOUNT';

-- ---------------------------------------------------------------------------
-- Least privilege: the application may only change the columns its commands
-- change. Everything else is fixed at INSERT or maintained by triggers.
-- (Column privileges also satisfy SELECT ... FOR SHARE in the triggers.)
-- ---------------------------------------------------------------------------
REVOKE UPDATE ON legal_entities, projects, accounts, fiscal_periods, fx_snapshots, journals, journal_lines FROM serk_app;
GRANT UPDATE (name, presentation_currency) ON legal_entities TO serk_app;
GRANT UPDATE (name, status) ON projects TO serk_app;
GRANT UPDATE (name, active) ON accounts TO serk_app;
GRANT UPDATE (status, closed_by, closed_at, reopen_reason, reopened_by) ON fiscal_periods TO serk_app;
GRANT UPDATE (status, approved_by, approved_at, posted_by, posted_at, reversed_by) ON journals TO serk_app;
GRANT UPDATE (memo) ON journal_lines TO serk_app;
GRANT SELECT, INSERT ON fiscal_period_closes TO serk_app;
GRANT USAGE, SELECT ON SEQUENCE fiscal_period_closes_id_seq TO serk_app;
GRANT EXECUTE ON FUNCTION journal_balance_assert(uuid), currency_minor_units(char), assert_currency_precision(numeric, char, text),
  fiscal_period_tb(fiscal_periods), ledger_integrity_scan() TO serk_app;

ALTER TABLE fiscal_period_closes ENABLE ROW LEVEL SECURITY;
ALTER TABLE fiscal_period_closes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fiscal_period_closes USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- ===========================================================================
-- SC-03: FX sources and snapshots under maker/checker control
-- ===========================================================================
-- A source (central bank, commercial bank, contract, provider) must be
-- registered and independently approved before its rates can be recorded.
CREATE TABLE fx_sources (
  tenant_id              uuid NOT NULL REFERENCES tenants(id),
  source_id              text NOT NULL CHECK (length(source_id) BETWEEN 2 AND 64),
  source_type            text NOT NULL CHECK (source_type IN ('CENTRAL_BANK', 'COMMERCIAL_BANK', 'CONTRACT', 'PROVIDER')),
  description            text NOT NULL,
  requires_document_hash boolean NOT NULL DEFAULT true,
  max_variance           numeric(9,6) NOT NULL DEFAULT 0.05 CHECK (max_variance > 0 AND max_variance <= 1),
  status                 text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'RETIRED')),
  created_by             text NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  approved_by            text,
  approved_at            timestamptz,
  PRIMARY KEY (tenant_id, source_id),
  CONSTRAINT fx_sources_maker_checker CHECK (status = 'PENDING' OR (approved_by IS NOT NULL AND approved_by <> created_by))
);

CREATE OR REPLACE FUNCTION fx_sources_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fx sources cannot be deleted; retire instead' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'fx sources are created PENDING and approved by a second person' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW.tenant_id, NEW.source_id, NEW.source_type, NEW.description, NEW.requires_document_hash, NEW.max_variance, NEW.created_by, NEW.created_at)
     IS DISTINCT FROM row(OLD.tenant_id, OLD.source_id, OLD.source_type, OLD.description, OLD.requires_document_hash, OLD.max_variance, OLD.created_by, OLD.created_at) THEN
    RAISE EXCEPTION 'fx source definition is immutable; register a new source' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT ((OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'RETIRED')) OR (OLD.status = 'APPROVED' AND NEW.status = 'RETIRED') OR OLD.status = NEW.status) THEN
    RAISE EXCEPTION 'illegal fx source transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'PENDING' AND row(NEW.approved_by, NEW.approved_at) IS DISTINCT FROM row(OLD.approved_by, OLD.approved_at) THEN
    RAISE EXCEPTION 'fx source approval record is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_sources_guard BEFORE INSERT OR UPDATE OR DELETE ON fx_sources FOR EACH ROW EXECUTE FUNCTION fx_sources_guard();

-- Snapshot decision record.
ALTER TABLE fx_snapshots
  ADD COLUMN decided_at           timestamptz,
  ADD COLUMN decision_reason      text,
  ADD COLUMN rejected_by          text,
  ADD COLUMN variance_exception   boolean NOT NULL DEFAULT false,
  ADD COLUMN approver_mfa         boolean NOT NULL DEFAULT false,
  ADD COLUMN legacy_self_approved boolean NOT NULL DEFAULT false;

-- Legacy (0.1.0) snapshots approved by their own creator: unreferenced ones
-- go back to PENDING for an independent decision; referenced ones keep their
-- status (history is immutable) but are flagged and become ineligible for any
-- new selection. Every affected row is registered.
INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0002', 'SC-03 self-approved FX snapshot', 'fx_snapshots', snapshot_id::text,
       CASE WHEN EXISTS (SELECT 1 FROM journal_lines l WHERE l.fx_snapshot_id = s.snapshot_id)
            THEN 'referenced by journal lines: kept APPROVED, flagged legacy_self_approved, ineligible for new lines'
            ELSE 'unreferenced: reset to PENDING for independent approval' END
  FROM fx_snapshots s WHERE approval_status = 'APPROVED' AND approved_by = created_by;
UPDATE fx_snapshots s SET approval_status = 'PENDING', approved_by = NULL
 WHERE approval_status = 'APPROVED' AND approved_by = created_by
   AND NOT EXISTS (SELECT 1 FROM journal_lines l WHERE l.fx_snapshot_id = s.snapshot_id);
UPDATE fx_snapshots SET legacy_self_approved = true WHERE approval_status = 'APPROVED' AND approved_by = created_by;

ALTER TABLE fx_snapshots
  ADD CONSTRAINT fx_snapshots_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by OR legacy_self_approved),
  ADD CONSTRAINT fx_snapshots_rejection_maker_checker CHECK (rejected_by IS NULL OR rejected_by <> created_by),
  ADD CONSTRAINT fx_snapshots_exception_needs_mfa CHECK (NOT variance_exception OR approver_mfa);

CREATE OR REPLACE FUNCTION fx_snapshots_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE src fx_sources%ROWTYPE; prev numeric; dev numeric;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fx_snapshots are immutable (LAW 06)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    -- Rates are only ever born PENDING: approval is a separate act by a different person.
    IF NEW.approval_status <> 'PENDING' OR NEW.approved_by IS NOT NULL OR NEW.rejected_by IS NOT NULL
       OR NEW.decided_at IS NOT NULL OR NEW.variance_exception OR NEW.approver_mfa OR NEW.legacy_self_approved THEN
      RAISE EXCEPTION 'fx snapshots are recorded PENDING; approval is a separate maker/checker step (SC-03)' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO src FROM fx_sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id;
    IF NOT FOUND OR src.status <> 'APPROVED' THEN
      RAISE EXCEPTION 'fx source % is not an approved, trusted source', NEW.source_id USING ERRCODE = 'check_violation';
    END IF;
    IF src.source_type <> NEW.source_type THEN
      RAISE EXCEPTION 'fx snapshot source_type % does not match registered source type %', NEW.source_type, src.source_type USING ERRCODE = 'check_violation';
    END IF;
    IF src.requires_document_hash AND (NEW.source_document_hash IS NULL OR NEW.source_document_hash !~ '^sha256:[0-9a-f]{64}$') THEN
      RAISE EXCEPTION 'source % requires a sha256:<64 hex> source document hash', NEW.source_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- UPDATE: observation fields and the legacy flag never change.
  IF row(NEW.snapshot_id, NEW.tenant_id, NEW.source_id, NEW.source_type, NEW.base_currency, NEW.quote_currency, NEW.rate,
         NEW.rate_type, NEW.effective_from_utc, NEW.published_at_utc, NEW.captured_at_utc, NEW.business_event_at_utc,
         NEW.source_document_hash, NEW.algorithm_version, NEW.created_by, NEW.legacy_self_approved)
     IS DISTINCT FROM
     row(OLD.snapshot_id, OLD.tenant_id, OLD.source_id, OLD.source_type, OLD.base_currency, OLD.quote_currency, OLD.rate,
         OLD.rate_type, OLD.effective_from_utc, OLD.published_at_utc, OLD.captured_at_utc, OLD.business_event_at_utc,
         OLD.source_document_hash, OLD.algorithm_version, OLD.created_by, OLD.legacy_self_approved) THEN
    RAISE EXCEPTION 'fx_snapshot observation fields are immutable (LAW 06)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.approval_status = OLD.approval_status THEN
    IF row(NEW.approved_by, NEW.rejected_by, NEW.decided_at, NEW.decision_reason, NEW.variance_exception, NEW.approver_mfa)
       IS DISTINCT FROM row(OLD.approved_by, OLD.rejected_by, OLD.decided_at, OLD.decision_reason, OLD.variance_exception, OLD.approver_mfa) THEN
      RAISE EXCEPTION 'fx snapshot decision record is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.approval_status = 'PENDING' AND NEW.approval_status = 'APPROVED' THEN
    IF NEW.approved_by IS NULL OR NEW.decided_at IS NULL OR NEW.rejected_by IS NOT NULL THEN
      RAISE EXCEPTION 'approval requires approved_by and decided_at' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO src FROM fx_sources WHERE tenant_id = NEW.tenant_id AND source_id = NEW.source_id FOR SHARE;
    IF src.status <> 'APPROVED' THEN
      RAISE EXCEPTION 'fx source % is no longer trusted', NEW.source_id USING ERRCODE = 'check_violation';
    END IF;
    -- Variance gate against the latest earlier approved observation of the same series.
    SELECT rate INTO prev FROM fx_snapshots
     WHERE tenant_id = NEW.tenant_id AND base_currency = NEW.base_currency AND quote_currency = NEW.quote_currency
       AND source_id = NEW.source_id AND rate_type = NEW.rate_type AND approval_status = 'APPROVED'
       AND effective_from_utc < NEW.effective_from_utc AND snapshot_id <> NEW.snapshot_id
     ORDER BY effective_from_utc DESC LIMIT 1;
    IF prev IS NOT NULL THEN
      dev := abs(NEW.rate / prev - 1);
      IF dev > src.max_variance AND NOT (NEW.variance_exception AND NEW.approver_mfa) THEN
        RAISE EXCEPTION 'rate moves % from the previous approved rate (tolerance %): approval must be an MFA-verified variance exception',
          round(dev, 6), src.max_variance USING ERRCODE = 'check_violation';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.approval_status = 'PENDING' AND NEW.approval_status = 'REJECTED' THEN
    IF NEW.rejected_by IS NULL OR NEW.decided_at IS NULL OR NEW.approved_by IS NOT NULL OR NEW.decision_reason IS NULL THEN
      RAISE EXCEPTION 'rejection requires rejected_by, decided_at and a reason' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.approval_status = 'APPROVED' AND NEW.approval_status = 'DISPUTED' THEN
    IF EXISTS (SELECT 1 FROM journal_lines WHERE fx_snapshot_id = OLD.snapshot_id) THEN
      RAISE EXCEPTION 'snapshot % is referenced by journal lines and cannot be withdrawn', OLD.snapshot_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.decision_reason IS NULL OR NEW.decision_reason = OLD.decision_reason THEN
      RAISE EXCEPTION 'withdrawing an approved rate requires a new reason' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- Legacy 0.1.0 migration path (APPROVED -> PENDING) ran before this guard existed.
  RAISE EXCEPTION 'illegal fx snapshot transition % -> %', OLD.approval_status, NEW.approval_status USING ERRCODE = 'check_violation';
END$$;
DROP TRIGGER fx_snapshots_guard ON fx_snapshots;
CREATE TRIGGER fx_snapshots_guard BEFORE INSERT OR UPDATE OR DELETE ON fx_snapshots FOR EACH ROW EXECUTE FUNCTION fx_snapshots_guard();

-- ===========================================================================
-- SC-02: entity- and purpose-specific FX policy, bound to every FX line
-- ===========================================================================
CREATE TABLE fx_policies (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  purpose         text NOT NULL CHECK (purpose IN ('TRANSACTION', 'REVALUATION', 'BUDGET')),
  version         integer NOT NULL CHECK (version >= 1),
  rate_type       text NOT NULL CHECK (rate_type IN ('OFFICIAL', 'COMMERCIAL', 'CONTRACTUAL', 'CLOSING', 'BUDGET')),
  source_priority text[] NOT NULL CHECK (cardinality(source_priority) BETWEEN 1 AND 10),
  max_staleness   interval NOT NULL CHECK (max_staleness > interval '0' AND max_staleness <= interval '400 days'),
  allow_inverse   boolean NOT NULL DEFAULT false,
  status          text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'RETIRED', 'REJECTED')),
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  approved_by     text,
  approved_at     timestamptz,
  UNIQUE (tenant_id, legal_entity_id, purpose, version),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id) REFERENCES legal_entities(tenant_id, id),
  CONSTRAINT fx_policies_maker_checker CHECK (status IN ('PENDING', 'REJECTED') OR (approved_by IS NOT NULL AND approved_by <> created_by))
);
CREATE UNIQUE INDEX fx_policies_one_approved ON fx_policies (tenant_id, legal_entity_id, purpose) WHERE status = 'APPROVED';

CREATE OR REPLACE FUNCTION fx_policies_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fx policies cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'fx policies are created PENDING and approved by a second person' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW.id, NEW.tenant_id, NEW.legal_entity_id, NEW.purpose, NEW.version, NEW.rate_type, NEW.source_priority,
         NEW.max_staleness, NEW.allow_inverse, NEW.created_by, NEW.created_at)
     IS DISTINCT FROM row(OLD.id, OLD.tenant_id, OLD.legal_entity_id, OLD.purpose, OLD.version, OLD.rate_type, OLD.source_priority,
         OLD.max_staleness, OLD.allow_inverse, OLD.created_by, OLD.created_at) THEN
    RAISE EXCEPTION 'fx policy content is immutable; create a new version' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NOT ((OLD.status = 'PENDING' AND NEW.status IN ('APPROVED', 'REJECTED')) OR (OLD.status = 'APPROVED' AND NEW.status = 'RETIRED') OR OLD.status = NEW.status) THEN
    RAISE EXCEPTION 'illegal fx policy transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'PENDING' AND row(NEW.approved_by, NEW.approved_at) IS DISTINCT FROM row(OLD.approved_by, OLD.approved_at) THEN
    RAISE EXCEPTION 'fx policy approval record is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER fx_policies_guard BEFORE INSERT OR UPDATE OR DELETE ON fx_policies FOR EACH ROW EXECUTE FUNCTION fx_policies_guard();

-- Lines carry the policy decision. fx_selected_at is the knowledge cutoff and
-- is set by the database, never by the client.
ALTER TABLE journal_lines
  ADD COLUMN fx_policy_id      uuid,
  ADD COLUMN fx_policy_version integer,
  ADD COLUMN fx_selected_at    timestamptz,
  ADD CONSTRAINT journal_lines_fx_policy_fk FOREIGN KEY (tenant_id, fx_policy_id) REFERENCES fx_policies(tenant_id, id);

INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0002', 'SC-02 FX line without policy binding', 'journal_lines', l.journal_id::text || '#' || l.line_no,
       'journal status ' || j.status || CASE WHEN j.status IN ('DRAFT', 'APPROVED') THEN ': cannot be posted; cancel and re-enter under an approved FX policy' ELSE ': historical, retained' END
  FROM journal_lines l JOIN journals j ON j.id = l.journal_id WHERE l.fx_snapshot_id IS NOT NULL;

ALTER TABLE journal_lines ADD CONSTRAINT journal_lines_fx_policy_binding CHECK (
  (fx_snapshot_id IS NULL AND fx_policy_id IS NULL AND fx_policy_version IS NULL AND fx_selected_at IS NULL)
  OR (fx_snapshot_id IS NOT NULL AND fx_policy_id IS NOT NULL AND fx_policy_version IS NOT NULL AND fx_selected_at IS NOT NULL)) NOT VALID;

-- Single source of truth for FX eligibility in the database. Locks the
-- snapshot (FOR SHARE) so a concurrent withdrawal serialises with the caller
-- (SC-08). Returns the rate in functional-per-transaction units.
CREATE OR REPLACE FUNCTION fx_assert_eligible(p_snapshot uuid, p_policy uuid, p_policy_version integer, p_txn char(3),
                                              p_functional char(3), p_entity uuid, p_event_at timestamptz, p_cutoff timestamptz)
RETURNS numeric LANGUAGE plpgsql AS $$
DECLARE s fx_snapshots%ROWTYPE; pol fx_policies%ROWTYPE; src_status text; r numeric;
BEGIN
  SELECT * INTO s FROM fx_snapshots WHERE snapshot_id = p_snapshot FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fx snapshot % not found', p_snapshot USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF s.approval_status <> 'APPROVED' THEN
    RAISE EXCEPTION 'fx snapshot % is %, not APPROVED', p_snapshot, s.approval_status USING ERRCODE = 'check_violation';
  END IF;
  IF s.legacy_self_approved THEN
    RAISE EXCEPTION 'fx snapshot % was self-approved under 0.1.0 and is not eligible for new postings', p_snapshot USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO pol FROM fx_policies WHERE id = p_policy;
  IF NOT FOUND OR pol.status NOT IN ('APPROVED', 'RETIRED') OR pol.version <> p_policy_version OR pol.legal_entity_id <> p_entity THEN
    RAISE EXCEPTION 'fx policy %/v% is not an approved policy of entity %', p_policy, p_policy_version, p_entity USING ERRCODE = 'check_violation';
  END IF;
  SELECT status INTO src_status FROM fx_sources WHERE tenant_id = s.tenant_id AND source_id = s.source_id;
  IF src_status IS DISTINCT FROM 'APPROVED' THEN
    RAISE EXCEPTION 'fx source % is not trusted', s.source_id USING ERRCODE = 'check_violation';
  END IF;
  IF s.rate_type <> pol.rate_type THEN
    RAISE EXCEPTION 'snapshot rate type % does not match policy rate type %', s.rate_type, pol.rate_type USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (s.source_id = ANY (pol.source_priority)) THEN
    RAISE EXCEPTION 'snapshot source % is not admitted by the policy', s.source_id USING ERRCODE = 'check_violation';
  END IF;
  IF s.effective_from_utc > p_event_at THEN
    RAISE EXCEPTION 'snapshot is effective from %, after the business event %', s.effective_from_utc, p_event_at USING ERRCODE = 'check_violation';
  END IF;
  IF s.published_at_utc > p_cutoff THEN
    RAISE EXCEPTION 'snapshot was published at %, after the knowledge cutoff %', s.published_at_utc, p_cutoff USING ERRCODE = 'check_violation';
  END IF;
  IF p_event_at - s.effective_from_utc > pol.max_staleness THEN
    RAISE EXCEPTION 'snapshot effective % is stale for event % (policy max %)', s.effective_from_utc, p_event_at, pol.max_staleness USING ERRCODE = 'check_violation';
  END IF;
  IF s.base_currency = p_txn AND s.quote_currency = p_functional THEN
    r := s.rate;
  ELSIF s.base_currency = p_functional AND s.quote_currency = p_txn THEN
    IF NOT pol.allow_inverse THEN
      RAISE EXCEPTION 'policy does not allow inverse rates' USING ERRCODE = 'check_violation';
    END IF;
    r := round(1 / s.rate, 12);
  ELSE
    RAISE EXCEPTION 'fx snapshot pair %/% does not convert %->%', s.base_currency, s.quote_currency, p_txn, p_functional USING ERRCODE = 'check_violation';
  END IF;
  RETURN r;
END$$;

-- Final line validation (supersedes 0001 and the SC-14 note above).
CREATE OR REPLACE FUNCTION journal_lines_validate() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  j journals%ROWTYPE; a_cur char(3); a_active boolean; r numeric; expect numeric; mu smallint;
BEGIN
  SELECT * INTO j FROM journals WHERE id = NEW.journal_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'journal % not found for line', NEW.journal_id USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF NEW.currency <> j.functional_currency OR NEW.legal_entity_id <> j.legal_entity_id OR NEW.tenant_id <> j.tenant_id THEN
    RAISE EXCEPTION 'line % currency/entity/tenant differs from its journal', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.project_id IS NOT NULL AND NEW.project_id IS DISTINCT FROM j.project_id THEN
    RAISE EXCEPTION 'line % project differs from journal project', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  SELECT currency, active INTO a_cur, a_active FROM accounts WHERE id = NEW.account_id;
  IF NOT a_active THEN
    RAISE EXCEPTION 'account % is inactive', NEW.account_id USING ERRCODE = 'check_violation';
  END IF;
  IF a_cur IS NOT NULL AND a_cur <> j.functional_currency AND NEW.txn_currency IS DISTINCT FROM a_cur THEN
    RAISE EXCEPTION 'account % only accepts % transactions', NEW.account_id, a_cur USING ERRCODE = 'check_violation';
  END IF;
  PERFORM assert_currency_precision(NEW.amount, NEW.currency, 'amount');
  PERFORM assert_currency_precision(NEW.txn_amount, NEW.txn_currency, 'txn_amount');
  IF NEW.fx_snapshot_id IS NOT NULL THEN
    IF TG_OP = 'INSERT' THEN
      NEW.fx_selected_at := now();          -- authoritative knowledge cutoff
    ELSIF NEW.fx_selected_at IS DISTINCT FROM OLD.fx_selected_at OR NEW.fx_policy_id IS DISTINCT FROM OLD.fx_policy_id
          OR NEW.fx_policy_version IS DISTINCT FROM OLD.fx_policy_version THEN
      RAISE EXCEPTION 'fx binding of a line is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.fx_policy_id IS NULL THEN
      RAISE EXCEPTION 'foreign-currency line % has no FX policy binding (SC-02)', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    r := fx_assert_eligible(NEW.fx_snapshot_id, NEW.fx_policy_id, NEW.fx_policy_version, NEW.txn_currency,
                            j.functional_currency, j.legal_entity_id, j.business_event_at, NEW.fx_selected_at);
    IF abs(NEW.applied_rate - r) > 0.000000000001 THEN
      RAISE EXCEPTION 'applied_rate % differs from the policy-eligible snapshot rate %', NEW.applied_rate, r USING ERRCODE = 'check_violation';
    END IF;
    mu := currency_minor_units(NEW.currency);
    expect := NEW.txn_amount * NEW.applied_rate;
    IF abs(NEW.amount - expect) > power(10::numeric, -mu) THEN
      RAISE EXCEPTION 'line % amount % does not reconcile to % x % = %', NEW.line_no, NEW.amount, NEW.txn_amount, NEW.applied_rate, expect USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.fx_policy_id IS NOT NULL OR NEW.fx_policy_version IS NOT NULL THEN
    RAISE EXCEPTION 'fx policy binding without a snapshot' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- Final journal guard (supersedes 0001): adds the fiscal-period share lock
-- (SC-08) and re-verifies FX eligibility of every line at posting (SC-02).
CREATE OR REPLACE FUNCTION journals_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pstatus text; r journals%ROWTYPE; o_dr numeric; o_cr numeric; r_dr numeric; r_cr numeric; o_n int; r_n int; l record;
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'DRAFT' THEN
      RAISE EXCEPTION 'journal % is % and cannot be deleted (LAW 03)', OLD.id, OLD.status USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.status <> OLD.status THEN
    IF NOT ((OLD.status = 'DRAFT'    AND NEW.status IN ('APPROVED', 'CANCELLED')) OR
            (OLD.status = 'APPROVED' AND NEW.status IN ('POSTED', 'CANCELLED')) OR
            (OLD.status = 'POSTED'   AND NEW.status = 'REVERSED')) THEN
      RAISE EXCEPTION 'illegal journal transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
  END IF;
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
  IF OLD.status IN ('POSTED', 'REVERSED') AND (NEW.posted_by IS DISTINCT FROM OLD.posted_by OR NEW.posted_at IS DISTINCT FROM OLD.posted_at) THEN
    RAISE EXCEPTION 'posting record of journal % is immutable', OLD.id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status = 'REVERSED' AND NEW.reversed_by IS DISTINCT FROM OLD.reversed_by THEN
    RAISE EXCEPTION 'reversal link of journal % is immutable', OLD.id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status <> 'POSTED' AND NEW.reversed_by IS NOT NULL THEN
    RAISE EXCEPTION 'only a POSTED journal can be reversed' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'POSTED' AND OLD.status <> 'POSTED' THEN
    -- SC-08: hold the covering period until COMMIT so a close cannot interleave.
    SELECT status INTO pstatus FROM fiscal_periods
      WHERE tenant_id = NEW.tenant_id AND legal_entity_id = NEW.legal_entity_id
        AND (NEW.business_event_at AT TIME ZONE 'UTC')::date BETWEEN starts_on AND ends_on
      FOR SHARE;
    IF pstatus IS NULL THEN
      RAISE EXCEPTION 'no fiscal period covers % for entity %', NEW.business_event_at, NEW.legal_entity_id USING ERRCODE = 'check_violation';
    ELSIF pstatus <> 'OPEN' THEN
      RAISE EXCEPTION 'fiscal period is % — posting refused', pstatus USING ERRCODE = 'check_violation';
    END IF;
    -- SC-02/SC-08: every FX line must still be eligible at posting; locks the snapshots.
    FOR l IN SELECT * FROM journal_lines WHERE journal_id = NEW.id AND fx_snapshot_id IS NOT NULL ORDER BY fx_snapshot_id LOOP
      IF l.fx_policy_id IS NULL THEN
        RAISE EXCEPTION 'journal % line % has no FX policy binding and cannot be posted (SC-02)', NEW.id, l.line_no USING ERRCODE = 'check_violation';
      END IF;
      PERFORM fx_assert_eligible(l.fx_snapshot_id, l.fx_policy_id, l.fx_policy_version, l.txn_currency,
                                 NEW.functional_currency, NEW.legal_entity_id, NEW.business_event_at, l.fx_selected_at);
    END LOOP;
  END IF;
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

-- Privileges and RLS for the new FX control tables.
GRANT SELECT, INSERT ON fx_sources, fx_policies TO serk_app;
GRANT UPDATE (status, approved_by, approved_at) ON fx_sources, fx_policies TO serk_app;
GRANT UPDATE (approval_status, approved_by, rejected_by, decided_at, decision_reason, variance_exception, approver_mfa) ON fx_snapshots TO serk_app;
GRANT EXECUTE ON FUNCTION fx_assert_eligible(uuid, uuid, integer, char, char, uuid, timestamptz, timestamptz) TO serk_app;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['fx_sources', 'fx_policies'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END$$;
