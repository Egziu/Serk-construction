-- SERK Construction — migration 0005: versioned WBS and cost codes (SC-10)
--
-- A project's work breakdown structure is published as approved versions
-- (maker/checker). Cost codes hang off WBS nodes and are usable on journal
-- lines only while their version is the APPROVED one, the code is ACTIVE and
-- the business event falls inside its validity dates. Accounts may require
-- cost coding on project journals. Unknown, foreign-project, superseded,
-- closed and out-of-date codes are refused by the database.

CREATE TABLE wbs_versions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  legal_entity_id uuid NOT NULL,
  project_id      uuid NOT NULL,
  version         integer NOT NULL CHECK (version >= 1),
  status          text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'APPROVED', 'SUPERSEDED', 'REJECTED')),
  description     text NOT NULL,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  approved_by     text,
  approved_at     timestamptz,
  UNIQUE (tenant_id, project_id, version),
  UNIQUE (tenant_id, project_id, id),
  FOREIGN KEY (tenant_id, legal_entity_id, project_id) REFERENCES projects(tenant_id, legal_entity_id, id),
  CONSTRAINT wbs_versions_maker_checker CHECK (status IN ('DRAFT', 'REJECTED') OR (approved_by IS NOT NULL AND approved_by <> created_by))
);
CREATE UNIQUE INDEX wbs_versions_one_approved ON wbs_versions (tenant_id, project_id) WHERE status = 'APPROVED';

CREATE TABLE wbs_nodes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  project_id  uuid NOT NULL,
  version_id  uuid NOT NULL,
  parent_id   uuid,
  code        text NOT NULL CHECK (code ~ '^[0-9A-Z]+(\.[0-9A-Z]+)*$'),
  name        text NOT NULL,
  UNIQUE (version_id, code),
  UNIQUE (tenant_id, project_id, id),
  FOREIGN KEY (tenant_id, project_id, version_id) REFERENCES wbs_versions(tenant_id, project_id, id),
  FOREIGN KEY (tenant_id, project_id, parent_id) REFERENCES wbs_nodes(tenant_id, project_id, id)
);

CREATE TABLE cost_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  project_id  uuid NOT NULL,
  wbs_node_id uuid NOT NULL,
  code        text NOT NULL CHECK (code ~ '^[0-9A-Z]+([.-][0-9A-Z]+)*$'),
  name        text NOT NULL,
  cost_type   text NOT NULL CHECK (cost_type IN ('LABOUR', 'MATERIAL', 'PLANT', 'SUBCONTRACT', 'OVERHEAD', 'PRELIMINARIES')),
  status      text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'CLOSED')),
  valid_from  date NOT NULL,
  valid_to    date,
  created_by  text NOT NULL,
  UNIQUE (tenant_id, project_id, wbs_node_id, code),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, project_id, wbs_node_id) REFERENCES wbs_nodes(tenant_id, project_id, id),
  CHECK (valid_to IS NULL OR valid_to >= valid_from)
);

-- Structure is frozen once the version leaves DRAFT; codes may only be
-- CLOSED (or have valid_to set) afterwards.
CREATE OR REPLACE FUNCTION wbs_structure_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE st text; vid uuid;
BEGIN
  IF TG_TABLE_NAME = 'wbs_nodes' THEN
    vid := CASE WHEN TG_OP = 'DELETE' THEN OLD.version_id ELSE NEW.version_id END;
  ELSE
    SELECT version_id INTO vid FROM wbs_nodes WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.wbs_node_id ELSE NEW.wbs_node_id END;
  END IF;
  SELECT status INTO st FROM wbs_versions WHERE id = vid;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows cannot be deleted', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF st <> 'DRAFT' THEN
    IF TG_OP = 'INSERT' OR TG_TABLE_NAME = 'wbs_nodes' THEN
      RAISE EXCEPTION 'WBS version is %; its structure is frozen — create a new version', st USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF row(NEW.id, NEW.tenant_id, NEW.project_id, NEW.wbs_node_id, NEW.code, NEW.name, NEW.cost_type, NEW.valid_from, NEW.created_by)
       IS DISTINCT FROM row(OLD.id, OLD.tenant_id, OLD.project_id, OLD.wbs_node_id, OLD.code, OLD.name, OLD.cost_type, OLD.valid_from, OLD.created_by)
       OR (OLD.status = 'CLOSED' AND NEW.status = 'ACTIVE') THEN
      RAISE EXCEPTION 'approved cost codes can only be closed or end-dated' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER wbs_nodes_guard BEFORE INSERT OR UPDATE OR DELETE ON wbs_nodes FOR EACH ROW EXECUTE FUNCTION wbs_structure_guard();
CREATE TRIGGER cost_codes_guard BEFORE INSERT OR UPDATE OR DELETE ON cost_codes FOR EACH ROW EXECUTE FUNCTION wbs_structure_guard();

CREATE OR REPLACE FUNCTION wbs_versions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'WBS versions cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'DRAFT' OR NEW.approved_by IS NOT NULL THEN
      RAISE EXCEPTION 'WBS versions are created DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW.tenant_id, NEW.legal_entity_id, NEW.project_id, NEW.version, NEW.created_by, NEW.created_at)
     IS DISTINCT FROM row(OLD.tenant_id, OLD.legal_entity_id, OLD.project_id, OLD.version, OLD.created_by, OLD.created_at) THEN
    RAISE EXCEPTION 'WBS version identity is immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status <> OLD.status AND NOT ((OLD.status = 'DRAFT' AND NEW.status IN ('APPROVED', 'REJECTED')) OR (OLD.status = 'APPROVED' AND NEW.status = 'SUPERSEDED')) THEN
    RAISE EXCEPTION 'illegal WBS version transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER wbs_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON wbs_versions FOR EACH ROW EXECUTE FUNCTION wbs_versions_guard();

-- Journal lines: existence/tenant by FK; project, version, status and dates by trigger.
ALTER TABLE journal_lines ADD CONSTRAINT journal_lines_cost_code_fk FOREIGN KEY (tenant_id, cost_code_id) REFERENCES cost_codes(tenant_id, id) NOT VALID;
INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
SELECT '0005', 'SC-10 cost code reference without registry entry', 'journal_lines', l.journal_id::text || '#' || l.line_no, 'cost_code_id ' || l.cost_code_id
  FROM journal_lines l WHERE l.cost_code_id IS NOT NULL;

ALTER TABLE accounts ADD COLUMN cost_coding text NOT NULL DEFAULT 'OPTIONAL' CHECK (cost_coding IN ('NONE', 'OPTIONAL', 'REQUIRED_ON_PROJECT'));

CREATE OR REPLACE FUNCTION journal_lines_cost_code() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j journals%ROWTYPE; cc cost_codes%ROWTYPE; vstatus text; coding text;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.cost_code_id IS NOT DISTINCT FROM OLD.cost_code_id THEN
    RETURN NEW;
  END IF;
  SELECT * INTO j FROM journals WHERE id = NEW.journal_id;
  SELECT cost_coding INTO coding FROM accounts WHERE id = NEW.account_id;
  IF NEW.cost_code_id IS NULL THEN
    IF coding = 'REQUIRED_ON_PROJECT' AND j.project_id IS NOT NULL THEN
      RAISE EXCEPTION 'line % posts to an account that requires a cost code on project journals (SC-10)', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF coding = 'NONE' THEN
    RAISE EXCEPTION 'line % account does not accept cost codes', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  IF j.project_id IS NULL THEN
    RAISE EXCEPTION 'line % carries a cost code but the journal has no project', NEW.line_no USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO cc FROM cost_codes WHERE id = NEW.cost_code_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cost code % does not exist', NEW.cost_code_id USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF cc.project_id <> j.project_id THEN
    RAISE EXCEPTION 'cost code % belongs to another project', cc.code USING ERRCODE = 'check_violation';
  END IF;
  SELECT v.status INTO vstatus FROM wbs_nodes n JOIN wbs_versions v ON v.id = n.version_id WHERE n.id = cc.wbs_node_id;
  IF vstatus <> 'APPROVED' THEN
    RAISE EXCEPTION 'cost code % is in a % WBS version', cc.code, vstatus USING ERRCODE = 'check_violation';
  END IF;
  IF cc.status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'cost code % is %', cc.code, cc.status USING ERRCODE = 'check_violation';
  END IF;
  IF (j.business_event_at AT TIME ZONE 'UTC')::date < cc.valid_from OR (cc.valid_to IS NOT NULL AND (j.business_event_at AT TIME ZONE 'UTC')::date > cc.valid_to) THEN
    RAISE EXCEPTION 'cost code % is not valid on %', cc.code, (j.business_event_at AT TIME ZONE 'UTC')::date USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER journal_lines_cost_code BEFORE INSERT OR UPDATE ON journal_lines FOR EACH ROW EXECUTE FUNCTION journal_lines_cost_code();

-- Privileges and RLS.
GRANT SELECT, INSERT ON wbs_versions, wbs_nodes, cost_codes TO serk_app;
GRANT UPDATE (status, approved_by, approved_at) ON wbs_versions TO serk_app;
GRANT UPDATE (status, valid_to) ON cost_codes TO serk_app;
GRANT UPDATE (cost_coding) ON accounts TO serk_app;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['wbs_versions', 'wbs_nodes', 'cost_codes'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END$$;
