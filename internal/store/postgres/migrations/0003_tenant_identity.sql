-- SERK Construction — migration 0003: database-enforced tenant identity (SC-04)
--
-- Before: RLS compared tenant_id to the session GUC app.tenant_id, which any
-- session can rewrite with set_config(). A stolen application credential or
-- an SQL injection therefore reached every tenant.
--
-- After: each tenant has its own LOGIN role (serk_t_<uuid hex>), a member of
-- serk_app for privileges. The tenant a session may see is derived from
-- session_user through an owner-only mapping table. session_user cannot be
-- changed by a non-superuser: SET ROLE alters only current_user, and SET
-- SESSION AUTHORIZATION requires superuser. The GUC is no longer consulted
-- for authorization at all.
--
-- Residual risk (documented in THREAT_MODEL.md): a compromise of the
-- application process itself exposes every credential it holds; the
-- DEDICATED_DB tier additionally separates storage per tenant.

CREATE TABLE tenant_db_roles (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
  role_name  name NOT NULL UNIQUE CHECK (role_name ~ '^serk_t_[0-9a-f]{32}$'),
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON tenant_db_roles FROM PUBLIC;

-- The authorization source for every RLS policy. SECURITY DEFINER so tenant
-- roles need no access to the mapping; search_path pinned against hijacking.
CREATE OR REPLACE FUNCTION current_tenant() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT tenant_id FROM public.tenant_db_roles WHERE role_name = session_user
$$;
REVOKE ALL ON FUNCTION current_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION current_tenant() TO serk_app, serk_publisher;

-- Audit verification is a definer function; it must not let one tenant probe
-- another tenant's chain.
CREATE OR REPLACE FUNCTION audit_log_verify(p_tenant uuid) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE r audit_log%ROWTYPE; expect_prev text := repeat('0', 64); expect_no bigint := 1; last_seq bigint := 0;
BEGIN
  IF current_tenant() IS NULL THEN
    -- Unmapped sessions (e.g. the retired shared serk_api role) may not
    -- verify anything; only the superuser/operator may verify any tenant.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper) THEN
      RAISE EXCEPTION 'audit verification requires a tenant session' USING ERRCODE = 'insufficient_privilege';
    END IF;
  ELSIF p_tenant <> current_tenant() THEN
    RAISE EXCEPTION 'audit verification is limited to the session tenant' USING ERRCODE = 'insufficient_privilege';
  END IF;
  FOR r IN SELECT * FROM audit_log WHERE tenant_id = p_tenant ORDER BY chain_no LOOP
    IF r.chain_no <> expect_no OR r.seq <= last_seq OR r.prev_hash <> expect_prev
       OR r.hash <> audit_hash(r.prev_hash, r.seq, r.chain_no, r.tenant_id, r.occurred_at, r.actor_id, r.action, r.aggregate_type, r.aggregate_id, r.request_id, r.payload) THEN
      RETURN r.seq;
    END IF;
    expect_prev := r.hash; expect_no := r.chain_no + 1; last_seq := r.seq;
  END LOOP;
  IF EXISTS (SELECT 1 FROM audit_heads WHERE tenant_id = p_tenant AND (head_hash <> expect_prev OR chain_len <> expect_no - 1)) THEN
    RETURN -1;
  END IF;
  RETURN NULL;
END$$;

-- Tenant provisioning, callable only by the schema owner / provisioning
-- service: records the role mapping for an existing role.
CREATE OR REPLACE FUNCTION provision_tenant_role(p_tenant uuid, p_role name) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_role AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls) THEN
    RAISE EXCEPTION 'role % must exist as a non-superuser LOGIN role without BYPASSRLS', p_role;
  END IF;
  IF NOT pg_has_role(p_role, 'serk_app', 'MEMBER') THEN
    RAISE EXCEPTION 'role % must be a member of serk_app', p_role;
  END IF;
  IF pg_has_role(p_role, 'serk_publisher', 'MEMBER') THEN
    RAISE EXCEPTION 'a tenant role must not be a member of serk_publisher';
  END IF;
  INSERT INTO public.tenant_db_roles(tenant_id, role_name) VALUES (p_tenant, p_role);
END$$;
REVOKE ALL ON FUNCTION provision_tenant_role(uuid, name) FROM PUBLIC;

-- The outbox relay works across tenants: it gets its own policies, granted
-- only to serk_publisher (tenant roles are never members of it).
CREATE POLICY publisher_read ON outbox FOR SELECT TO serk_publisher USING (true);
CREATE POLICY publisher_mark ON outbox FOR UPDATE TO serk_publisher USING (true) WITH CHECK (true);

-- The tenants row policy now also uses the session identity.
DROP POLICY tenant_self ON tenants;
CREATE POLICY tenant_self ON tenants USING (id = current_tenant());
