-- 0035: corrections from independent review 10 (migrations 0031-0034 and the
-- isolated signer). docs/security/INDEPENDENT_REVIEW_10_2026-10-22.md.
--
--   R10-F3  pg_temp shadowing: every function pins search_path, but without
--           naming pg_temp PostgreSQL searches the session's temporary schema
--           FIRST for relations. A tenant login with TEMP could create
--           pg_temp.approval_attestations and approve with no real evidence.
--           Every public function now ends its search_path with pg_temp.
--   (the other R10 corrections follow below)

-- R10-F3 ----------------------------------------------------------------------
DO $$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig, array_to_string(p.proconfig, ',') AS cfg
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proconfig IS NOT NULL
              AND array_to_string(p.proconfig, ',') LIKE 'search_path=%'
              AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') LOOP
    IF f.cfg = 'search_path=pg_catalog, public' THEN
      EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f.sig);
    ELSIF f.cfg = 'search_path=pg_catalog' THEN
      EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, pg_temp', f.sig);
    END IF;
  END LOOP;
END$$;

-- R10-F1/F2 ---------------------------------------------------------------------
-- The isolated signer verifies a person's token but has no database: it
-- could not know whether the subject of an approval is in the token's
-- project scope, nor whether the session was revoked. Since 0035 every
-- attestation carries signed markers (principal.scope:tenant or
-- principal.project:<id>..., principal.session:<jti>, principal.iat:<unix>);
-- the signer signs only the token's own, and approval_authorize() refuses a
-- revoked session and a subject whose project is outside the markers.

-- Project of an attested subject: NULL when the type is not project-scoped,
-- '' for an unassigned (tenant-wide) record. The same mapping as the
-- kernel's docProject (internal/kernel/p2p.go).
CREATE OR REPLACE FUNCTION serk_subject_project(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE v_id uuid; r text;
BEGIN
  IF p_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN NULL;
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
  ELSE RETURN NULL;
  END CASE;
  -- A mapped type whose row is missing or has no project is tenant-wide:
  -- only a tenant-scoped principal may decide it (fail closed).
  RETURN COALESCE(r, '');
END$$;
REVOKE ALL ON FUNCTION serk_subject_project(text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION approval_authorize(a jsonb) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  t uuid := current_tenant();
  k bytea;
  now_s bigint := floor(extract(epoch FROM clock_timestamp()))::bigint;
  iat bigint; exp bigint; at bigint;
  fresh boolean;
  want text;
  n uuid;
  f text;
  perms text[];
  m_session text; m_iat bigint; subj_project text;
BEGIN
  IF t IS NULL THEN
    RAISE EXCEPTION 'approval attestation: no tenant session' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF a IS NULL OR jsonb_typeof(a) <> 'object'
     OR (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(a) AS key) IS DISTINCT FROM
        ARRAY['action','actor','auth_time','ctx','exp','iat','kid','mfa','nonce','perms','sig','subject_hash','subject_id','subject_type','tenant','v']::text[] THEN
    RAISE EXCEPTION 'approval attestation: malformed (unexpected or missing fields)' USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOREACH f IN ARRAY ARRAY['action','actor','ctx','kid','nonce','sig','subject_hash','subject_id','subject_type','tenant'] LOOP
    IF jsonb_typeof(a->f) <> 'string' OR position(chr(31) IN a->>f) > 0 THEN
      RAISE EXCEPTION 'approval attestation: malformed field %', f USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  FOREACH f IN ARRAY ARRAY['v','auth_time','iat','exp'] LOOP
    IF jsonb_typeof(a->f) <> 'number' OR (a->>f) !~ '^[0-9]{1,12}$' THEN
      RAISE EXCEPTION 'approval attestation: malformed field %', f USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
  IF jsonb_typeof(a->'mfa') <> 'boolean' OR jsonb_typeof(a->'perms') <> 'array'
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(a->'perms') e
                 WHERE jsonb_typeof(e) <> 'string' OR e #>> '{}' = '' OR position(chr(31) IN e #>> '{}') > 0 OR position(',' IN e #>> '{}') > 0) THEN
    RAISE EXCEPTION 'approval attestation: malformed permissions or mfa' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (a->>'v') <> '1' OR (a->>'tenant') IS DISTINCT FROM t::text THEN
    RAISE EXCEPTION 'approval attestation: malformed or for another tenant' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF a->>'actor' = '' OR a->>'action' = '' OR a->>'sig' !~ '^[0-9a-f]{64}$' OR (a->>'nonce') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'approval attestation: missing fields' USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT key INTO k FROM approval_keys WHERE tenant_id = t AND key_id = a->>'kid' AND active;
  IF k IS NULL THEN
    RAISE EXCEPTION 'approval attestation: unknown signing key' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF encode(hmac(convert_to(approval_canonical(a), 'UTF8'), k, 'sha256'), 'hex') <> a->>'sig' THEN
    RAISE EXCEPTION 'approval attestation: bad signature' USING ERRCODE = 'insufficient_privilege';
  END IF;
  iat := (a->>'iat')::bigint; exp := (a->>'exp')::bigint; at := NULLIF((a->>'auth_time')::bigint, 0);
  IF iat > now_s + 60 OR exp <= now_s OR exp - iat > 300 OR exp <= iat THEN
    RAISE EXCEPTION 'approval attestation: expired or not yet valid' USING ERRCODE = 'insufficient_privilege';
  END IF;
  want := approval_subject_hash(a->>'subject_type', a->>'subject_id');
  IF want IS NULL OR want IS DISTINCT FROM a->>'subject_hash' THEN
    RAISE EXCEPTION 'approval attestation: subject changed or unknown' USING ERRCODE = 'insufficient_privilege';
  END IF;
  -- R10-F1/F2 (0035): scope and session markers, signed with the rest.
  perms := ARRAY(SELECT jsonb_array_elements_text(a->'perms'));
  SELECT substr(x, length('principal.session:') + 1) INTO m_session FROM unnest(perms) x WHERE x LIKE 'principal.session:%';
  SELECT substr(x, length('principal.iat:') + 1)::bigint INTO m_iat FROM unnest(perms) x WHERE x ~ '^principal\.iat:[0-9]{1,12}$';
  IF m_session IS NULL OR m_iat IS NULL
     OR (SELECT count(*) FROM unnest(perms) x WHERE x LIKE 'principal.session:%' OR x LIKE 'principal.iat:%') <> 2 THEN
    RAISE EXCEPTION 'approval attestation: missing session markers' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF session_is_revoked(a->>'actor', NULLIF(m_session, '-'), CASE WHEN m_iat = 0 THEN NULL ELSE to_timestamp(m_iat) END) THEN
    RAISE EXCEPTION 'approval attestation: the session of % is revoked', a->>'actor' USING ERRCODE = 'insufficient_privilege';
  END IF;
  subj_project := serk_subject_project(a->>'subject_type', a->>'subject_id');
  IF subj_project IS NOT NULL AND NOT ('principal.scope:tenant' = ANY (perms))
     AND (subj_project = '' OR NOT (('principal.project:' || subj_project) = ANY (perms))) THEN
    RAISE EXCEPTION 'approval attestation: % % is outside the attested scope of %', a->>'subject_type', a->>'subject_id', a->>'actor'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  fresh := (a->>'mfa')::boolean AND at IS NOT NULL AND at <= now_s + 60 AND now_s - at <= 600;
  n := (a->>'nonce')::uuid;
  BEGIN
    INSERT INTO approval_attestations(nonce, tenant_id, txid, actor, action, subject_type, subject_id, subject_hash, ctx, perms,
      mfa_claimed, mfa_fresh, auth_time, issued_at, expires_at, key_id, signature)
    VALUES (n, t, txid_current(), a->>'actor', a->>'action', a->>'subject_type', a->>'subject_id', a->>'subject_hash', a->>'ctx',
      ARRAY(SELECT jsonb_array_elements_text(a->'perms')), (a->>'mfa')::boolean, fresh,
      CASE WHEN at IS NULL THEN NULL ELSE to_timestamp(at) END, to_timestamp(iat), to_timestamp(exp), a->>'kid', a->>'sig');
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'approval attestation: already used (replay)' USING ERRCODE = 'insufficient_privilege';
  END;
  RETURN n;
END$$;

-- R10-F4 ------------------------------------------------------------------------
-- The bank account digest is computed by the API with its own key ("hkey:"),
-- never by the database: a tenant credential could otherwise test guesses
-- against stored digests at tens of thousands per second. The database
-- functions that computed it are closed to every runtime role.
REVOKE ALL ON FUNCTION p2p_account_digest(text) FROM PUBLIC, serk_app;
CREATE OR REPLACE FUNCTION bank_accounts_encrypted() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.account_number IS NOT NULL THEN
    RAISE EXCEPTION 'bank account numbers are stored encrypted (0032): the plaintext column is not written' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.account_digest IS NOT NULL AND NEW.account_digest !~ '^(hmac|hkey):[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'malformed account digest' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'INSERT' AND NEW.account_digest LIKE 'hmac:%' THEN
    RAISE EXCEPTION 'new bank account digests are computed by the API (hkey:), not by the database' USING ERRCODE = 'check_violation';
  END IF;
  -- The one permitted change to encrypted details: serk-migrate
  -- encrypt-bank-accounts replacing a database-computed digest (hmac:) with
  -- the API-keyed one (hkey:), in a maintenance session, nothing else.
  IF TG_OP = 'UPDATE' AND OLD.account_number IS NULL AND OLD.account_digest LIKE 'hmac:%' AND NEW.account_digest LIKE 'hkey:%'
     AND NEW.account_number_enc IS NOT DISTINCT FROM OLD.account_number_enc AND NEW.account_last4 IS NOT DISTINCT FROM OLD.account_last4
     AND NEW.account_number IS NULL THEN
    -- Evaluated only here (nested), so ordinary updates never call it.
    IF serk_maintenance_session() THEN
      RETURN NEW;
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.account_number_enc IS DISTINCT FROM OLD.account_number_enc OR NEW.account_digest IS DISTINCT FROM OLD.account_digest
                           OR NEW.account_last4 IS DISTINCT FROM OLD.account_last4) AND OLD.account_number IS NULL THEN
    RAISE EXCEPTION 'encrypted bank details never change; revoke the account and add a new one' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;

-- Rows still carrying a database-computed digest: duplicate detection
-- against them is ineffective until they are re-digested.
CREATE OR REPLACE FUNCTION serk_bank_legacy_digest_rows() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT (SELECT count(*) FROM supplier_bank_accounts WHERE account_digest LIKE 'hmac:%')
       + (SELECT count(*) FROM company_bank_accounts WHERE account_digest LIKE 'hmac:%')
$$;
REVOKE ALL ON FUNCTION serk_bank_legacy_digest_rows() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION serk_bank_legacy_digest_rows() TO serk_monitor;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') THEN
    GRANT EXECUTE ON FUNCTION serk_bank_legacy_digest_rows() TO serk_health;
  END IF;
END$$;

-- R10-F5/F7 ---------------------------------------------------------------------
-- The owner of the SERK objects is the role that ran the migrations (it owns
-- every table and SECURITY DEFINER function). 0034 identified it as the owner
-- of schema public, which is wrong when public is still owned by
-- pg_database_owner (the PostgreSQL 15+ default): the maintenance predicate
-- was then never true for the real owner. The owner of public.tenants is the
-- authoritative answer in both layouts.
CREATE OR REPLACE FUNCTION serk_object_owner() RETURNS oid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relname = 'tenants' AND c.relkind = 'r'
$$;
-- Left executable: it reveals only what pg_class already shows, and the
-- posture check (run as the privilege-less health role) needs it.

CREATE OR REPLACE FUNCTION serk_maintenance_session() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT NOT EXISTS (SELECT 1 FROM public.tenant_db_roles WHERE role_name = session_user)
     AND (session_user = (SELECT r.rolname FROM pg_roles r WHERE r.oid = public.serk_object_owner())
          OR pg_has_role(session_user, 'serk_monitor', 'MEMBER')
          OR pg_has_role(session_user, 'serk_scheduler', 'MEMBER')
          OR pg_has_role(session_user, 'serk_publisher', 'MEMBER')
          OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_health') AND pg_has_role(session_user, 'serk_health', 'MEMBER')))
$$;
REVOKE ALL ON FUNCTION serk_maintenance_session() FROM PUBLIC;
-- The workflow timer policy (0006) admitted every row to the owner in any
-- session; it now admits maintenance sessions only, like 0034.
ALTER POLICY owner_timer_scan ON workflow_instances USING (serk_maintenance_session());

CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
  WITH tenant_logins AS (
    SELECT r.oid, r.rolname FROM pg_roles r
     WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid, 'serk_app', 'MEMBER')
       -- The schema owner administers serk_app (it creates tenant roles IN
       -- ROLE serk_app) and is a member by that grant; it is not a tenant
       -- login and its own privileges are expected (0034).
       AND r.oid <> serk_object_owner())
  SELECT 'TEMP is granted on the database to tenant login ' || t.rolname
    FROM tenant_logins t WHERE has_database_privilege(t.oid, current_database(), 'TEMP')
  UNION ALL
  SELECT 'tenant login ' || t.rolname || ' may CREATE in schema ' || n.nspname
    FROM tenant_logins t CROSS JOIN pg_namespace n
   WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND has_schema_privilege(t.oid, n.oid, 'CREATE')
  UNION ALL
  SELECT 'advisory-lock function ' || p.proname || ' is executable by tenant login ' || t.rolname
    FROM tenant_logins t CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege(t.oid, p.oid, 'EXECUTE')
  UNION ALL
  SELECT DISTINCT 'advisory-lock function ' || p.proname || ' is executable by serk_app'
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg%advisory%' AND has_function_privilege('serk_app', p.oid, 'EXECUTE')
  UNION ALL
  SELECT 'bank account numbers stored in plaintext: ' || n || ' row(s); run serk-migrate encrypt-bank-accounts'
    FROM (SELECT serk_bank_plaintext_rows() AS n) x WHERE n > 0
  UNION ALL
  SELECT 'bank accounts with a database-computed digest: ' || n || ' row(s); run serk-migrate encrypt-bank-accounts (R10-F4)'
    FROM (SELECT serk_bank_legacy_digest_rows() AS n) x WHERE n > 0
  UNION ALL
  -- Query parameters (account numbers travel as parameters) must not be
  -- logged in full.
  SELECT 'log_parameter_max_length is ' || current_setting('log_parameter_max_length') || ' (set 0 so bound parameters are never logged)'
   WHERE current_setting('log_parameter_max_length') NOT IN ('0')
  UNION ALL
  -- R10-F7: parameters of a failing statement are logged under this one.
  SELECT 'log_parameter_max_length_on_error is ' || current_setting('log_parameter_max_length_on_error') || ' (set 0)'
   WHERE current_setting('log_parameter_max_length_on_error') NOT IN ('0')
  UNION ALL
  -- R10-F5: the schema owner must administer the platform roles without
  -- inheriting their privileges or policies (GRANT ... WITH ADMIN TRUE,
  -- INHERIT FALSE, SET FALSE; deploy/01-schema-owner.sql).
  SELECT 'schema owner inherits the privileges of ' || r.rolname
    FROM pg_roles r
   WHERE r.rolname IN ('serk_app', 'serk_publisher', 'serk_scheduler', 'serk_monitor', 'serk_abuse', 'serk_health')
     AND serk_object_owner() <> r.oid
     AND NOT (SELECT rolsuper FROM pg_roles o WHERE o.oid = serk_object_owner())
     AND pg_has_role(serk_object_owner(), r.oid, 'USAGE')
  UNION ALL
  -- Objects owned by anyone other than the migrating role escape the
  -- owner_maintenance design (and its privilege tests).
  SELECT 'table ' || c.relname || ' is owned by ' || pg_get_userbyid(c.relowner) || ', not the SERK object owner'
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relowner <> serk_object_owner()
  UNION ALL
  -- A superuser owner is not bound by FORCE ROW LEVEL SECURITY: every
  -- SECURITY DEFINER function then sees all tenants whoever calls it.
  SELECT 'the SERK object owner ' || r.rolname || ' is a superuser or has BYPASSRLS (row-level security does not bind its functions)'
    FROM pg_roles r WHERE r.oid = serk_object_owner() AND (r.rolsuper OR r.rolbypassrls)
$$;
