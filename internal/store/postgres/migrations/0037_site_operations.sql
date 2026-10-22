-- 0037: site operations and offline field capture (GATED-01, ADR 0017).
--
-- Field staff record a daily SITE DIARY per project: weather, notes, labour
-- (trade, headcount, hours) and equipment (hours worked and idle). A diary
-- can be prepared on a registered FIELD DEVICE while offline and synchronised
-- later, or entered online. It is operational, not financial (LAW 05): the
-- device prepares commands, the server validates and records them, and a
-- project manager (a different person, a human) approves the submitted
-- diary. Nothing here posts to the ledger.
--
--   site_devices         one per field device; the person registers their own
--                        device and receives a secret once (only its SHA-256
--                        is stored); the owner or a site.device.manage holder
--                        revokes it. A revoked device can never sync again,
--                        including commands queued before the revocation.
--   site_diaries         DRAFT -> SUBMITTED -> APPROVED | REJECTED. One live
--                        diary per project and date. Optimistic concurrency:
--                        every revision bumps `version`; a revision against a
--                        stale version is a CONFLICT (no merge).
--   site_diary_labour,   versioned lines: a revision inserts the lines of the
--   site_diary_equipment new version and keeps the old ones (history). Lines
--                        are written only in the transaction that wrote the
--                        diary header (checked with xmin), so every content
--                        change is covered by the header's attestation.
--   site_sync_commands   the offline command log: (device, client op id) is
--                        unique, so a retried command is answered from the log
--                        and never applied twice; the payload digest must
--                        match on a retry; the device sequence only moves
--                        forward. Claimed client time is kept as evidence.
--
-- Attestations: site.device.create, site.device.revoke, site.diary.create,
-- site.diary.revision.create, site.diary.submit (drafts) and
-- site.diary.approve / site.diary.reject (human decisions, maker-checker).

CREATE TABLE site_devices (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  user_id        text NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
  label          text NOT NULL CHECK (length(btrim(label)) BETWEEN 2 AND 100),
  key_hash       text NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  status         text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
  last_seq       bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  last_sync_at   timestamptz,
  registered_at  timestamptz NOT NULL DEFAULT now(),
  revoked_by     text,
  revoked_at     timestamptz,
  revoke_reason  text,
  UNIQUE (tenant_id, id),
  UNIQUE (key_hash),
  CONSTRAINT site_devices_revocation CHECK ((status = 'REVOKED') = (revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL))
);
CREATE INDEX site_devices_user ON site_devices (tenant_id, user_id);

CREATE TABLE site_diaries (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  project_id         uuid NOT NULL,
  number             text NOT NULL,
  client_ref         uuid NOT NULL,
  diary_date         date NOT NULL,
  weather            text NOT NULL CHECK (length(btrim(weather)) BETWEEN 2 AND 200),
  notes              text NOT NULL DEFAULT '' CHECK (length(notes) <= 8000),
  version            integer NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 10000),
  status             text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'CANCELLED')),
  origin_device_id   uuid,
  client_created_at  timestamptz,
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  submitted_at       timestamptz,
  approved_by        text,
  approved_at        timestamptz,
  decision_reason    text,
  rejected_by        text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  UNIQUE (tenant_id, client_ref),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id),
  FOREIGN KEY (tenant_id, origin_device_id) REFERENCES site_devices(tenant_id, id),
  CONSTRAINT site_diary_maker_checker CHECK (approved_by IS NULL OR approved_by <> created_by),
  -- R12-F6: rejection is a decision by someone other than the author.
  CONSTRAINT site_diary_reject_checker CHECK (rejected_by IS NULL OR rejected_by <> created_by)
);
-- One live diary per project and day; a rejected or cancelled one frees it.
CREATE UNIQUE INDEX site_diaries_one_per_day ON site_diaries (tenant_id, project_id, diary_date) WHERE status NOT IN ('REJECTED', 'CANCELLED');

CREATE TABLE site_diary_labour (
  tenant_id  uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  diary_id   uuid NOT NULL,
  version    integer NOT NULL,
  line_no    integer NOT NULL CHECK (line_no BETWEEN 1 AND 200),
  trade      text NOT NULL CHECK (length(btrim(trade)) BETWEEN 2 AND 100),
  headcount  integer NOT NULL CHECK (headcount BETWEEN 1 AND 10000),
  hours      numeric(10,2) NOT NULL CHECK (hours > 0),
  PRIMARY KEY (diary_id, version, line_no),
  FOREIGN KEY (tenant_id, diary_id) REFERENCES site_diaries(tenant_id, id),
  -- Person-hours cannot exceed 24 hours per person in the day.
  CONSTRAINT site_labour_hours CHECK (hours <= headcount * 24)
);

CREATE TABLE site_diary_equipment (
  tenant_id   uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  diary_id    uuid NOT NULL,
  version     integer NOT NULL,
  line_no     integer NOT NULL CHECK (line_no BETWEEN 1 AND 200),
  description text NOT NULL CHECK (length(btrim(description)) BETWEEN 2 AND 200),
  hours       numeric(5,2) NOT NULL CHECK (hours >= 0),
  idle_hours  numeric(5,2) NOT NULL DEFAULT 0 CHECK (idle_hours >= 0),
  PRIMARY KEY (diary_id, version, line_no),
  FOREIGN KEY (tenant_id, diary_id) REFERENCES site_diaries(tenant_id, id),
  CONSTRAINT site_equipment_day CHECK (hours + idle_hours BETWEEN 0.01 AND 24)
);

CREATE TABLE site_sync_commands (
  tenant_id     uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  device_id     uuid NOT NULL,
  client_op_id  uuid NOT NULL,
  seq           bigint NOT NULL CHECK (seq >= 1),
  kind          text NOT NULL CHECK (kind IN ('site_diary.save', 'site_diary.submit')),
  actor         text NOT NULL,
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  client_time   timestamptz NOT NULL,
  received_at   timestamptz NOT NULL DEFAULT now(),
  outcome       text NOT NULL CHECK (outcome IN ('APPLIED', 'CONFLICT', 'REJECTED')),
  diary_id      uuid,
  result        jsonb NOT NULL,
  PRIMARY KEY (tenant_id, device_id, client_op_id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES site_devices(tenant_id, id),
  CONSTRAINT site_sync_result_size CHECK (length(result::text) <= 16000)
);
CREATE INDEX site_sync_commands_seq ON site_sync_commands (tenant_id, device_id, seq);

-- ---------------------------------------------------------------- guards ---

CREATE OR REPLACE FUNCTION site_devices_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'ACTIVE' OR NEW.last_seq <> 0 OR NEW.last_sync_at IS NOT NULL OR NEW.revoked_by IS NOT NULL THEN
      RAISE EXCEPTION 'a device is registered ACTIVE with no history' USING ERRCODE = 'check_violation';
    END IF;
    -- R12-F7: at most 5 active devices per person (revoke one to add one),
    -- so a person cannot flood the device list. (Two registrations racing
    -- each other can overshoot by one; advisory locks are closed to tenant
    -- logins, and the cap is a flood limit, not a security boundary.)
    IF (SELECT count(*) FROM site_devices WHERE tenant_id = NEW.tenant_id AND user_id = NEW.user_id AND status = 'ACTIVE') >= 5 THEN
      RAISE EXCEPTION 'at most 5 active field devices per person; revoke one first' USING ERRCODE = 'check_violation';
    END IF;
    NEW.registered_at := now();
    RETURN NEW;
  END IF;
  IF OLD.status = 'REVOKED' THEN
    RAISE EXCEPTION 'a revoked device never changes' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.user_id <> OLD.user_id OR NEW.key_hash <> OLD.key_hash
     OR NEW.label <> OLD.label OR NEW.registered_at <> OLD.registered_at THEN
    RAISE EXCEPTION 'device identity never changes' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'ACTIVE' THEN
    -- Sync bookkeeping only: the sequence moves forward, set by the command log.
    IF NEW.revoked_by IS NOT NULL OR NEW.revoke_reason IS NOT NULL OR NEW.last_seq < OLD.last_seq THEN
      RAISE EXCEPTION 'the device sequence only moves forward' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.last_seq <> OLD.last_seq AND NOT EXISTS (
         SELECT 1 FROM site_sync_commands c WHERE c.tenant_id = NEW.tenant_id AND c.device_id = NEW.id AND c.seq = NEW.last_seq
            AND c.received_at = now()) THEN
      RAISE EXCEPTION 'the device sequence moves only with a recorded command' USING ERRCODE = 'check_violation';
    END IF;
    -- The last-sync time is the server's, set only with the sequence (R12-F1).
    IF NEW.last_seq <> OLD.last_seq THEN
      NEW.last_sync_at := now();
    ELSIF NEW.last_sync_at IS DISTINCT FROM OLD.last_sync_at THEN
      RAISE EXCEPTION 'the last-sync time moves only with a recorded command' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- ACTIVE -> REVOKED: by the owner, or by a site.device.manage holder.
  IF NEW.revoke_reason IS NULL OR length(btrim(NEW.revoke_reason)) < 5 THEN
    RAISE EXCEPTION 'revoking a device requires a reason' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.last_seq <> OLD.last_seq THEN
    RAISE EXCEPTION 'device identity never changes' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM approval_use('site.device.revoke', 'site_device', NEW.id::text, NEW.revoked_by,
                       CASE WHEN NEW.revoked_by = OLD.user_id THEN ARRAY['site.device.register', 'site.device.manage'] ELSE ARRAY['site.device.manage'] END,
                       false, 'REVOKED', NULL);
  NEW.revoked_at := now();
  RETURN NEW;
END$$;
CREATE TRIGGER site_devices_guard BEFORE INSERT OR UPDATE ON site_devices FOR EACH ROW EXECUTE FUNCTION site_devices_guard();

CREATE OR REPLACE FUNCTION site_device_active(p_device uuid, p_user text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM site_devices d WHERE d.id = p_device AND d.tenant_id = current_tenant() AND d.user_id = p_user AND d.status = 'ACTIVE')
$$;

-- True when the diary header was written by the current transaction: lines
-- may be written only then, so the header's (deferred) attestation covers them.
CREATE OR REPLACE FUNCTION site_diary_written_in_tx(p_diary uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM site_diaries d WHERE d.id = p_diary AND d.tenant_id = current_tenant()
                    AND d.xmin::text = (txid_current() % 4294967296)::text)
$$;

CREATE OR REPLACE FUNCTION site_diaries_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.version <> 1 OR NEW.approved_by IS NOT NULL OR NEW.submitted_at IS NOT NULL OR NEW.decision_reason IS NOT NULL OR NEW.rejected_by IS NOT NULL THEN
      RAISE EXCEPTION 'a site diary is recorded DRAFT, version 1' USING ERRCODE = 'check_violation';
    END IF;
    -- The server's date decides (a device clock is evidence, not authority):
    -- not in the future (one day of time-zone slack), at most 60 days back.
    IF NEW.diary_date > current_date + 1 OR NEW.diary_date < current_date - 60 THEN
      RAISE EXCEPTION 'the diary date must be within the last 60 days and not in the future' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.origin_device_id IS NOT NULL AND NOT site_device_active(NEW.origin_device_id, NEW.created_by) THEN
      RAISE EXCEPTION 'the field device is not an active device of %', NEW.created_by USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM projects WHERE id = NEW.project_id AND tenant_id = current_tenant() AND status = 'ACTIVE') THEN
      RAISE EXCEPTION 'site diaries are kept for ACTIVE projects' USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := now(); NEW.updated_at := now();
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id OR NEW.number <> OLD.number
     OR NEW.client_ref <> OLD.client_ref OR NEW.diary_date <> OLD.diary_date OR NEW.created_by <> OLD.created_by
     OR NEW.created_at <> OLD.created_at OR NEW.origin_device_id IS DISTINCT FROM OLD.origin_device_id
     OR NEW.client_created_at IS DISTINCT FROM OLD.client_created_at THEN
    RAISE EXCEPTION 'a diary''s identity, project, date and author never change' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'DRAFT' AND NEW.status = 'DRAFT' THEN
    -- A revision: content columns and exactly one version step; attested at
    -- commit (site_diary_attested).
    IF NEW.version <> OLD.version + 1 OR NEW.approved_by IS NOT NULL OR NEW.decision_reason IS NOT NULL OR NEW.submitted_at IS NOT NULL OR NEW.rejected_by IS NOT NULL THEN
      RAISE EXCEPTION 'a diary revision moves the version by exactly one' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'SUBMITTED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'submitted_at'], 'site diary');
    IF NOT EXISTS (SELECT 1 FROM site_diary_labour WHERE diary_id = NEW.id AND version = NEW.version)
       AND NOT EXISTS (SELECT 1 FROM site_diary_equipment WHERE diary_id = NEW.id AND version = NEW.version)
       AND length(btrim(NEW.notes)) < 5 THEN
      RAISE EXCEPTION 'a submitted diary records labour, equipment or notes' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('site.diary.submit', 'site_diary', NEW.id::text, NEW.created_by, ARRAY['site.diary.manage'], false, NULL, NULL);
    NEW.submitted_at := now();
  ELSIF OLD.status = 'SUBMITTED' AND NEW.status = 'APPROVED' THEN
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'approved_by', 'approved_at'], 'site diary');
    PERFORM approval_use('site.diary.approve', 'site_diary', NEW.id::text, NEW.approved_by, ARRAY['site.diary.approve'], false, 'APPROVED', NULL);
    NEW.approved_at := now();
  ELSIF OLD.status IN ('DRAFT', 'SUBMITTED') AND NEW.status = 'REJECTED' THEN
    -- An approver rejects a submitted diary, or clears a DRAFT that holds a
    -- project day (R12-F2), naming themselves (R12-F6).
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason', 'rejected_by'], 'site diary');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 OR NEW.rejected_by IS NULL THEN
      RAISE EXCEPTION 'rejecting a diary requires a reason and the rejecting person' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('site.diary.reject', 'site_diary', NEW.id::text, NEW.rejected_by, ARRAY['site.diary.approve'], false, 'REJECTED', NULL);
  ELSIF OLD.status = 'DRAFT' AND NEW.status = 'CANCELLED' THEN
    -- The author withdraws a DRAFT (R12-F2).
    PERFORM p2p_only_changed(to_jsonb(OLD), to_jsonb(NEW), ARRAY['status', 'decision_reason'], 'site diary');
    IF NEW.decision_reason IS NULL OR length(btrim(NEW.decision_reason)) < 5 THEN
      RAISE EXCEPTION 'cancelling a diary requires a reason' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('site.diary.cancel', 'site_diary', NEW.id::text, NEW.created_by, ARRAY['site.diary.manage'], false, 'CANCELLED', NULL);
  ELSE
    RAISE EXCEPTION 'illegal site diary transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER site_diaries_guard BEFORE INSERT OR UPDATE ON site_diaries FOR EACH ROW EXECUTE FUNCTION site_diaries_guard();

-- Creation and every revision are attested at commit, after the lines of the
-- version are in place (the attestation covers header and lines).
CREATE OR REPLACE FUNCTION site_diary_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE cur site_diaries;
BEGIN
  SELECT * INTO cur FROM site_diaries WHERE id = NEW.id;
  IF TG_OP = 'INSERT' THEN
    PERFORM approval_use('site.diary.create', 'site_diary', NEW.id::text, NEW.created_by, ARRAY['site.diary.manage'], false, NULL, NULL);
  ELSIF NEW.status = 'DRAFT' AND OLD.status = 'DRAFT' THEN
    -- Several revisions in one transaction are refused (each must be attested).
    IF cur.version <> NEW.version THEN
      RAISE EXCEPTION 'one diary revision per transaction' USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('site.diary.revision.create', 'site_diary', NEW.id::text, NEW.created_by, ARRAY['site.diary.manage'], false, NULL, NULL);
  END IF;
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER site_diary_attested AFTER INSERT OR UPDATE ON site_diaries DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION site_diary_attested();

CREATE OR REPLACE FUNCTION site_device_attested() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  -- Registering a device grants offline write capability: fresh MFA.
  PERFORM approval_use('site.device.create', 'site_device', NEW.id::text, NEW.user_id, ARRAY['site.device.register'], true, NULL, NULL);
  RETURN NULL;
END$$;
CREATE CONSTRAINT TRIGGER site_device_attested AFTER INSERT ON site_devices DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION site_device_attested();

CREATE OR REPLACE FUNCTION site_diary_lines_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE d site_diaries;
BEGIN
  SELECT * INTO d FROM site_diaries WHERE id = NEW.diary_id AND tenant_id = current_tenant() FOR SHARE;
  IF d.status IS DISTINCT FROM 'DRAFT' OR NEW.version IS DISTINCT FROM d.version THEN
    RAISE EXCEPTION 'diary lines are written for the current version of a DRAFT diary' USING ERRCODE = 'check_violation';
  END IF;
  IF NOT site_diary_written_in_tx(d.id) THEN
    RAISE EXCEPTION 'diary lines are written only with an attested revision of the diary' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- R12-F5: lines come before the revision's attestation is consumed (the
  -- attestation covers them); SET CONSTRAINTS ... IMMEDIATE cannot be used
  -- to attest first and add lines afterwards.
  IF approval_consumed_in_tx(ARRAY['site.diary.create', 'site.diary.revision.create'], 'site_diary', d.id::text, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'diary lines are written before the revision is attested' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER site_diary_labour_guard BEFORE INSERT ON site_diary_labour FOR EACH ROW EXECUTE FUNCTION site_diary_lines_guard();
CREATE TRIGGER site_diary_equipment_guard BEFORE INSERT ON site_diary_equipment FOR EACH ROW EXECUTE FUNCTION site_diary_lines_guard();

CREATE OR REPLACE FUNCTION site_sync_commands_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE dev site_devices;
BEGIN
  SELECT * INTO dev FROM site_devices WHERE id = NEW.device_id AND tenant_id = current_tenant() FOR UPDATE;
  IF dev.id IS NULL OR dev.status <> 'ACTIVE' OR dev.user_id <> NEW.actor THEN
    RAISE EXCEPTION 'the field device is not an active device of %', NEW.actor USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.seq <= dev.last_seq THEN
    RAISE EXCEPTION 'device sequence % is not after %', NEW.seq, dev.last_seq USING ERRCODE = 'check_violation';
  END IF;
  -- R12-F3: the sequence advances by at most 1000 per command, so one
  -- command can never exhaust it.
  IF NEW.seq > dev.last_seq + 1000 THEN
    RAISE EXCEPTION 'device sequence % jumps more than 1000 past %', NEW.seq, dev.last_seq USING ERRCODE = 'check_violation';
  END IF;
  -- R12-F1: every recorded command is attested by the device owner for this
  -- device and op id, so a leaked tenant database credential cannot forge
  -- log rows (the actor column alone proves nothing).
  PERFORM approval_use('site.sync.create', 'site_device', NEW.device_id::text, NEW.actor, ARRAY['site.diary.manage'], false, NEW.client_op_id::text, NULL);
  NEW.received_at := now();
  -- Applied commands refer to the diary they wrote, which is the actor's.
  IF NEW.outcome = 'APPLIED' AND NOT EXISTS (SELECT 1 FROM site_diaries WHERE id = NEW.diary_id AND created_by = NEW.actor) THEN
    RAISE EXCEPTION 'an applied command refers to a diary of its author' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER site_sync_commands_guard BEFORE INSERT ON site_sync_commands FOR EACH ROW EXECUTE FUNCTION site_sync_commands_guard();


-- ------------------------------------------- approval subjects and scope ---
-- Subject text (the 0032 body, search_path as rewritten by 0035/0036) with the
-- site branches. A device's sync bookkeeping is not part of its subject.
CREATE OR REPLACE FUNCTION public.p2p_subject_text(p_type text, p_id text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
DECLARE t uuid := current_tenant(); j jsonb;
BEGIN
  IF p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN NULL;
  END IF;
  CASE p_type
  WHEN 'p2p_policy' THEN SELECT to_jsonb(x) INTO j FROM p2p_policies x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier' THEN SELECT to_jsonb(x) INTO j FROM suppliers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'supplier_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', x.account_digest, 'account_number_enc', NULL) INTO j FROM supplier_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'company_bank_account' THEN SELECT to_jsonb(x) || jsonb_build_object('account_number', x.account_digest, 'account_number_enc', NULL) INTO j FROM company_bank_accounts x WHERE tenant_id = t AND id = p_id::uuid;
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
             'payee', (SELECT to_jsonb(b) || jsonb_build_object('account_number', b.account_digest, 'account_number_enc', NULL) FROM supplier_bank_accounts b WHERE b.id = x.supplier_bank_id))
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
  WHEN 'stock_transfer' THEN SELECT to_jsonb(x) INTO j FROM stock_transfers x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'schedule_version' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'activities', (SELECT jsonb_agg(to_jsonb(a) ORDER BY a.code COLLATE "C") FROM schedule_activities a WHERE a.version_id = x.id),
             'links', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.pred_code COLLATE "C", l.succ_code COLLATE "C") FROM schedule_links l WHERE l.version_id = x.id))
      INTO j FROM schedule_versions x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'schedule_progress' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.activity_code COLLATE "C") FROM schedule_progress_lines l WHERE l.progress_id = x.id))
      INTO j FROM schedule_progress x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'contract_variation' THEN
    SELECT jsonb_build_object('h', to_jsonb(x), 'lines', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM variation_lines l WHERE l.variation_id = x.id))
      INTO j FROM contract_variations x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'site_diary' THEN
    SELECT jsonb_build_object('h', to_jsonb(x),
             'labour', (SELECT jsonb_agg(to_jsonb(l) ORDER BY l.line_no) FROM site_diary_labour l WHERE l.diary_id = x.id AND l.version = x.version),
             'equipment', (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.line_no) FROM site_diary_equipment e WHERE e.diary_id = x.id AND e.version = x.version))
      INTO j FROM site_diaries x WHERE tenant_id = t AND id = p_id::uuid;
  WHEN 'site_device' THEN SELECT to_jsonb(x) - 'last_seq' - 'last_sync_at' INTO j FROM site_devices x WHERE tenant_id = t AND id = p_id::uuid;
  ELSE
    RETURN NULL;
  END CASE;
  RETURN j::text;
END$function$;

-- Project of an attested subject (the 0036 body) with the site types: a
-- diary is scoped by its project; a field device belongs to a person (its
-- owner or security administration acts on it), so it is not project-scoped.
CREATE OR REPLACE FUNCTION public.serk_subject_project(p_type text, p_id text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
DECLARE v_id uuid; r text;
BEGIN
  IF p_type IN ('supplier', 'customer', 'stock_item', 'supplier_bank_account', 'workflow_definition', 'workflow_definition_body', 'site_device') THEN
    RETURN NULL;
  END IF;
  IF p_id IS NULL OR p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN '';
  END IF;
  v_id := p_id::uuid;
  CASE p_type
  WHEN 'boq_version' THEN SELECT project_id::text INTO r FROM boq_versions WHERE boq_versions.id = v_id;
  WHEN 'purchase_requisition' THEN SELECT project_id::text INTO r FROM purchase_requisitions x WHERE x.id = v_id;
  WHEN 'purchase_order' THEN SELECT project_id::text INTO r FROM purchase_orders x WHERE x.id = v_id;
  WHEN 'rfq' THEN SELECT pr.project_id::text INTO r FROM rfqs q JOIN purchase_requisitions pr ON pr.id = q.pr_id WHERE q.id = v_id;
  WHEN 'rfq_quote' THEN SELECT pr.project_id::text INTO r FROM rfq_quotes x JOIN rfqs q ON q.id = x.rfq_id JOIN purchase_requisitions pr ON pr.id = q.pr_id WHERE x.id = v_id;
  WHEN 'grn' THEN SELECT o.project_id::text INTO r FROM grns g JOIN purchase_orders o ON o.id = g.po_id WHERE g.id = v_id;
  WHEN 'supplier_invoice' THEN SELECT o.project_id::text INTO r FROM supplier_invoices x JOIN purchase_orders o ON o.id = x.po_id WHERE x.id = v_id;
  WHEN 'contract' THEN SELECT project_id::text INTO r FROM contracts x WHERE x.id = v_id;
  WHEN 'measurement' THEN SELECT c.project_id::text INTO r FROM measurements m JOIN contracts c ON c.id = m.contract_id WHERE m.id = v_id;
  WHEN 'ipc' THEN SELECT c.project_id::text INTO r FROM ipcs x JOIN contracts c ON c.id = x.contract_id WHERE x.id = v_id;
  WHEN 'customer_invoice' THEN SELECT project_id::text INTO r FROM customer_invoices x WHERE x.id = v_id;
  WHEN 'customer_credit_note' THEN SELECT project_id::text INTO r FROM customer_credit_notes x WHERE x.id = v_id;
  WHEN 'retention_release' THEN SELECT project_id::text INTO r FROM retention_releases x WHERE x.id = v_id;
  WHEN 'contract_variation' THEN SELECT c.project_id::text INTO r FROM contract_variations v JOIN contracts c ON c.id = v.contract_id WHERE v.id = v_id;
  WHEN 'schedule_version' THEN SELECT project_id::text INTO r FROM schedule_versions x WHERE x.id = v_id;
  WHEN 'schedule_progress' THEN SELECT project_id::text INTO r FROM schedule_progress x WHERE x.id = v_id;
  WHEN 'warehouse' THEN SELECT COALESCE(project_id::text, '') INTO r FROM warehouses x WHERE x.id = v_id;
  WHEN 'stock_receipt' THEN SELECT COALESCE(w.project_id::text, '') INTO r FROM stock_receipts x JOIN warehouses w ON w.id = x.warehouse_id WHERE x.id = v_id;
  WHEN 'stock_issue' THEN SELECT project_id::text INTO r FROM stock_issues x WHERE x.id = v_id;
  WHEN 'stock_count' THEN SELECT COALESCE(project_id::text, '') INTO r FROM stock_counts x WHERE x.id = v_id;
  WHEN 'stock_transfer' THEN SELECT COALESCE(w.project_id::text, '') INTO r FROM stock_transfers x JOIN warehouses w ON w.id = x.from_warehouse_id WHERE x.id = v_id;
  WHEN 'journal' THEN SELECT project_id::text INTO r FROM journals x WHERE x.id = v_id;
  WHEN 'wbs_version' THEN SELECT project_id::text INTO r FROM wbs_versions x WHERE x.id = v_id;
  WHEN 'workflow_instance' THEN SELECT NULLIF(facts->>'project_id', '') INTO r FROM workflow_instances x WHERE x.id = v_id;
  WHEN 'site_diary' THEN SELECT project_id::text INTO r FROM site_diaries x WHERE x.id = v_id;
  ELSE RETURN '';
  END CASE;
  RETURN COALESCE(r, '');
END$function$;

-- ------------------------------------------------- row security, grants ---
DO $$
DECLARE tbl text; owner text := current_user;
BEGIN
  FOREACH tbl IN ARRAY ARRAY['site_devices', 'site_diaries', 'site_diary_labour', 'site_diary_equipment', 'site_sync_commands'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', tbl);
    EXECUTE format('CREATE POLICY owner_maintenance ON %I TO %I USING (serk_maintenance_session()) WITH CHECK (serk_maintenance_session())', tbl, owner);
    EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', tbl);
    EXECUTE format('GRANT SELECT, INSERT ON %I TO serk_app', tbl);
  END LOOP;
END$$;
GRANT UPDATE (status, revoked_by, revoke_reason, last_seq, last_sync_at) ON site_devices TO serk_app;
GRANT UPDATE (weather, notes, version, status, approved_by, decision_reason, rejected_by) ON site_diaries TO serk_app;
REVOKE ALL ON FUNCTION site_device_active(uuid, text), site_diary_written_in_tx(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION site_device_active(uuid, text), site_diary_written_in_tx(uuid) TO serk_app;
