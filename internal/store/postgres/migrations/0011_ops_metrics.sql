-- 0010: operational health metrics (GATEA-11).
--
-- A monitoring login must see that the system is healthy without seeing any
-- tenant's business data. serk_monitor gets EXECUTE on exactly one function,
-- which returns cluster-wide aggregates only: no tenant ids, no amounts, no
-- names. Deploy a login `serk_metrics IN ROLE serk_monitor` (deploy/00-roles.sql).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'serk_monitor') THEN
    CREATE ROLE serk_monitor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END$$;

-- Each row: metric name (Prometheus-safe), value. Cheap enough for a 30-60 s
-- scrape: indexed outbox predicates, the ledger integrity scan (bounded by
-- APPROVED/POSTED/REVERSED journals) and an O(tenants) audit-head comparison.
-- Full hash-chain verification is a scheduled job, not a scrape.
CREATE OR REPLACE FUNCTION ops_health_metrics() RETURNS TABLE (metric text, value numeric)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT 'outbox_pending_events', count(*)::numeric
    FROM outbox WHERE published_at IS NULL AND dead_at IS NULL
  UNION ALL
  SELECT 'outbox_oldest_pending_age_seconds',
         COALESCE(extract(epoch FROM now() - min(created_at)), 0)::numeric
    FROM outbox WHERE published_at IS NULL AND dead_at IS NULL
  UNION ALL
  SELECT 'outbox_dead_letters', count(*)::numeric FROM outbox WHERE dead_at IS NOT NULL
  UNION ALL
  SELECT 'ledger_integrity_violations', count(*)::numeric FROM ledger_integrity_scan()
  UNION ALL
  -- Audit head disagrees with the log it summarises (truncation, deletion or
  -- an out-of-band rewrite of the last entry).
  SELECT 'audit_head_mismatches', count(*)::numeric
    FROM audit_heads h
    LEFT JOIN LATERAL (SELECT count(*) AS n, max(chain_no) AS last_no FROM audit_log l WHERE l.tenant_id = h.tenant_id) c ON true
    LEFT JOIN audit_log last ON last.tenant_id = h.tenant_id AND last.chain_no = c.last_no
   WHERE h.chain_len <> c.n OR h.head_hash IS DISTINCT FROM COALESCE(last.hash, repeat('0', 64))
  UNION ALL
  SELECT 'workflow_effect_failures', COALESCE(sum(effect_failures), 0)::numeric
    FROM workflow_instances WHERE status = 'ACTIVE'
  UNION ALL
  SELECT 'workflow_overdue_steps', count(*)::numeric
    FROM workflow_instances WHERE status = 'ACTIVE' AND escalated_at IS NOT NULL
  UNION ALL
  SELECT 'session_revocations_last_hour', count(*)::numeric
    FROM session_revocations WHERE created_at > now() - interval '1 hour'
  UNION ALL
  SELECT 'approval_attestations_last_hour', count(*)::numeric
    FROM approval_attestations WHERE recorded_at > now() - interval '1 hour'
  UNION ALL
  SELECT 'tenants', count(*)::numeric FROM tenants
$$;
REVOKE ALL ON FUNCTION ops_health_metrics() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ops_health_metrics() TO serk_monitor;
