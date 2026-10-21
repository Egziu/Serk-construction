-- 0009: session revocation (GATEA-07, the part that does not need a live IdP).
--
-- Bearer tokens are verified statelessly (HS256 dev / OIDC JWKS). Without a
-- server-side check, a terminated employee or a removed role keeps working
-- until the token expires. This table is the shared, append-only revocation
-- list every API replica consults on every request and again inside every
-- approval transaction:
--   * SUBJECT rows: every token of that subject issued at or before
--     revoked_before is dead (termination, role removal, "log out everywhere",
--     suspected compromise). New tokens issued afterwards work again; for a
--     termination the IdP must also stop issuing them.
--   * TOKEN rows: one token (jti) is dead (logout of one session).
-- revoked_before is database time, never client-supplied. Token iat has
-- one-second resolution, so a token issued in the same second as the
-- revocation is treated as revoked (fail closed).

-- R-10 (found by TestPrivileges_CatalogInvariants while adding this
-- migration): 0008's "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE
-- ON FUNCTIONS FROM PUBLIC" is a no-op — per-schema default privileges can only
-- ADD to the global defaults, never remove from them. The global form below is
-- what actually stops new functions from being executable by PUBLIC.
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE session_revocations (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid NOT NULL DEFAULT current_tenant() REFERENCES tenants(id),
  subject        text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
  token_id       text CHECK (token_id IS NULL OR length(token_id) BETWEEN 1 AND 256),
  revoked_before timestamptz NOT NULL DEFAULT now(),
  reason         text NOT NULL CHECK (length(btrim(reason)) BETWEEN 3 AND 500),
  revoked_by     text NOT NULL CHECK (length(revoked_by) BETWEEN 1 AND 256),
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_revocations_subject ON session_revocations (tenant_id, subject, revoked_before DESC);
CREATE INDEX session_revocations_token ON session_revocations (tenant_id, token_id) WHERE token_id IS NOT NULL;

ALTER TABLE session_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY session_revocations_tenant ON session_revocations
  USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant());

-- Database time only; append-only.
CREATE OR REPLACE FUNCTION session_revocations_stamp() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  NEW.revoked_before := now();
  NEW.created_at := now();
  RETURN NEW;
END$$;
REVOKE ALL ON FUNCTION session_revocations_stamp() FROM PUBLIC; -- explicit; does not rely on the default
CREATE TRIGGER session_revocations_stamp BEFORE INSERT ON session_revocations FOR EACH ROW EXECUTE FUNCTION session_revocations_stamp();
CREATE TRIGGER session_revocations_append_only BEFORE UPDATE OR DELETE ON session_revocations FOR EACH ROW EXECUTE FUNCTION append_only();

REVOKE ALL ON session_revocations FROM PUBLIC;
GRANT SELECT, INSERT ON session_revocations TO serk_app;
GRANT USAGE ON SEQUENCE session_revocations_id_seq TO serk_app;

-- True when the presented token is no longer valid. p_iat NULL (token without
-- iat) is treated as "issued at the beginning of time": any SUBJECT
-- revocation kills it.
CREATE OR REPLACE FUNCTION session_is_revoked(p_subject text, p_token_id text, p_iat timestamptz) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1 FROM session_revocations r
     WHERE r.tenant_id = current_tenant() AND r.subject = p_subject
       AND ((r.token_id IS NULL AND (p_iat IS NULL OR p_iat <= r.revoked_before))
            OR (r.token_id IS NOT NULL AND r.token_id = p_token_id)))
$$;
REVOKE ALL ON FUNCTION session_is_revoked(text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION session_is_revoked(text, text, timestamptz) TO serk_app;
