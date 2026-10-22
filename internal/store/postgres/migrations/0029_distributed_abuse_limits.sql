-- 0029: abuse counters shared by every API replica (SC-13 residual,
-- order item "distributed abuse protection").
--
-- The pre-authentication limits (requests per client IP, invalid credentials
-- per IP with lockout) were per process: N replicas allowed N times the
-- limit, and a client locked out on one replica was not on the others. The
-- counters now live here, keyed by an HMAC of the client key (no raw IP is
-- stored), on the database clock (one clock for all replicas). The API
-- reaches them through a dedicated login in role serk_abuse, which can only
-- execute these two functions; it holds no table privilege and no tenant
-- data is involved.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_abuse') THEN
    CREATE ROLE serk_abuse NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END$$;

-- Counters are disposable (a crash resets them, which only relaxes limits
-- for one window): UNLOGGED keeps them off the WAL and out of replicas.
CREATE UNLOGGED TABLE abuse_counters (
  scope         text NOT NULL CHECK (scope ~ '^[a-z_]{1,32}$'),
  key_hash      bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  window_end    timestamptz NOT NULL,
  hits          integer NOT NULL CHECK (hits >= 0),
  blocked_until timestamptz,
  PRIMARY KEY (scope, key_hash)
);
REVOKE ALL ON abuse_counters FROM PUBLIC;

-- Counts one event; returns false when the key is over its limit. With a
-- lockout (p_block_s > 0) the limit-th event starts it, as the in-process
-- limiter does.
CREATE OR REPLACE FUNCTION abuse_hit(p_scope text, p_key bytea, p_limit integer, p_window_s integer, p_block_s integer) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE c abuse_counters; t timestamptz := clock_timestamp();
BEGIN
  IF p_limit < 1 OR p_window_s < 1 OR p_window_s > 86400 OR p_block_s < 0 OR p_block_s > 86400 THEN
    RAISE EXCEPTION 'abuse_hit: invalid limits' USING ERRCODE = 'check_violation';
  END IF;
  INSERT INTO abuse_counters AS a (scope, key_hash, window_end, hits)
  VALUES (p_scope, p_key, t + make_interval(secs => p_window_s), 1)
  ON CONFLICT (scope, key_hash) DO UPDATE SET
    hits = CASE WHEN a.blocked_until > t THEN a.hits WHEN a.window_end < t THEN 1 ELSE a.hits + 1 END,
    window_end = CASE WHEN a.window_end < t AND NOT (a.blocked_until > t) THEN t + make_interval(secs => p_window_s) ELSE a.window_end END
  RETURNING * INTO c;
  IF c.blocked_until > t THEN
    RETURN false;
  END IF;
  IF p_block_s > 0 AND c.hits >= p_limit THEN
    UPDATE abuse_counters SET blocked_until = t + make_interval(secs => p_block_s) WHERE scope = p_scope AND key_hash = p_key;
  END IF;
  -- Opportunistic sweep of expired counters (about one call in 500).
  IF random() < 0.002 THEN
    DELETE FROM abuse_counters WHERE window_end < t - interval '1 hour' AND (blocked_until IS NULL OR blocked_until < t);
  END IF;
  RETURN c.hits <= p_limit;
END$$;

CREATE OR REPLACE FUNCTION abuse_blocked(p_scope text, p_key bytea) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT blocked_until > clock_timestamp() FROM abuse_counters WHERE scope = p_scope AND key_hash = p_key), false)
$$;

REVOKE ALL ON FUNCTION abuse_hit(text, bytea, integer, integer, integer), abuse_blocked(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION abuse_hit(text, bytea, integer, integer, integer), abuse_blocked(text, bytea) TO serk_abuse;
