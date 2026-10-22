-- 0031: root fix for R7-F9 (reviews 7, 8 and 9).
--
-- Until now the stock valuation state (stock_balances, stock_layers,
-- stock_consumptions) was writable by the tenant login and protected by a
-- trigger-depth check, which holds only while the login has no TEMP and no
-- CREATE privilege (the start-up posture check enforced that). Now:
--
--   * the tenant login holds no INSERT, UPDATE or DELETE on the three state
--     tables, and no EXECUTE on stk_receive / stk_consume;
--   * the four stock document trigger functions run SECURITY DEFINER (as the
--     schema owner), so only a stock document transaction can move stock;
--   * the depth guard stays as defence in depth.
--
-- A pg_temp trigger, a schema-level trigger or any direct statement by the
-- tenant login now fails with "permission denied" whatever the posture.
-- Row-level security is FORCEd on every table, so the owner still sees and
-- writes the current tenant's rows only.

REVOKE INSERT, UPDATE, DELETE ON stock_balances, stock_layers, stock_consumptions FROM serk_app;
REVOKE ALL ON FUNCTION stk_receive(uuid, uuid, numeric, numeric, numeric, text, uuid),
                       stk_consume(uuid, uuid, numeric, text, uuid) FROM PUBLIC, serk_app;

ALTER FUNCTION stock_receipts_guard() SECURITY DEFINER SET search_path = pg_catalog, public;
ALTER FUNCTION stock_issues_guard() SECURITY DEFINER SET search_path = pg_catalog, public;
ALTER FUNCTION stock_counts_guard() SECURITY DEFINER SET search_path = pg_catalog, public;
ALTER FUNCTION stock_transfers_guard() SECURITY DEFINER SET search_path = pg_catalog, public;
REVOKE ALL ON FUNCTION stock_receipts_guard(), stock_issues_guard(), stock_counts_guard(), stock_transfers_guard() FROM PUBLIC;
