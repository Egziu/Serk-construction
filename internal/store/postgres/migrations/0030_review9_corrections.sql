-- 0030: corrections from independent review 9 (migrations 0026-0029).
-- docs/security/INDEPENDENT_REVIEW_9_2026-10-22.md.
--
--   R9-F2/F5  budget: an inventory purchase stays committed on the ordering
--             cost code until its stock is issued to that same code (relief
--             capped at what that code's orders put away). Put-away no longer
--             releases budget, so the PR/PO gate limits stock purchases again;
--             stock lost in a count stays charged to the code that bought it.
--             Conservative residual: stock bought on one code and issued to
--             another is charged to both (JC-BUDGET-ORIGIN, ADR 0012).
--   R9-F1     earned value per activity from its latest approved progress.
--   R9-F4     planned value on a non-working status date.
--   R9-F3     status date bounded; holidays bounded; (kernel) statement timeout.
--   R9-F7     the database re-checks free float, the critical flag and the
--             late dates, not only ES/EF/LS/LF.
--   R9-F8     posture: advisory-lock functions checked for every tenant login.
--   R9-I1     progress approved in status-date order; actual starts not
--             before the schedule start.
--   R9-I2     designation only on APPROVED orders, by a procurement approver
--             who did not raise the order; the attestation names line and item.
--   R9-I3     variation lines only in the transaction that created the
--             variation.

-- R9-F2/F5 -----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION p2p_cost_position(p_cost_code uuid, p_exclude_pr uuid, p_exclude_po uuid,
  OUT budget numeric, OUT committed numeric, OUT reserved numeric, OUT actual_other numeric, OUT available numeric)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE put_away numeric; issued numeric;
BEGIN
  SELECT COALESCE(sum(i.amount), 0) INTO budget
    FROM boq_items i JOIN boq_versions v ON v.id = i.version_id
   WHERE i.tenant_id = current_tenant() AND i.cost_code_id = p_cost_code AND v.status = 'APPROVED';
  -- Commitment of a line: the order, or what was received if more.
  SELECT COALESCE(sum(greatest(l.amount, p2p_round(p2p_received_qty(l.po_id, l.line_no) * l.unit_price, o.currency))), 0),
         COALESCE(sum(CASE WHEN EXISTS (SELECT 1 FROM stock_items si WHERE si.inventory_account_id = l.account_id)
                           THEN p2p_put_away_value(l.po_id, l.line_no) ELSE 0 END), 0)
    INTO committed, put_away
    FROM po_lines l JOIN purchase_orders o ON o.id = l.po_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND o.status IN ('APPROVED', 'CLOSED')
     AND o.id IS DISTINCT FROM p_exclude_po;
  SELECT COALESCE(sum(l.est_amount), 0) INTO reserved
    FROM pr_lines l JOIN purchase_requisitions r ON r.id = l.pr_id
   WHERE l.tenant_id = current_tenant() AND l.cost_code_id = p_cost_code AND r.status = 'APPROVED'
     AND r.id IS DISTINCT FROM p_exclude_pr
     AND NOT EXISTS (SELECT 1 FROM rfqs q JOIN purchase_orders o ON o.rfq_id = q.id
                      WHERE q.pr_id = r.id AND o.status IN ('APPROVED', 'CLOSED'));
  -- Posted cost charged to the code (receipt journals are inside the
  -- commitment above).
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0),
         COALESCE(sum(CASE WHEN j.source_type = 'STK_ISSUE' THEN CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END ELSE 0 END), 0)
    INTO actual_other, issued
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id
   WHERE jl.tenant_id = current_tenant() AND jl.cost_code_id = p_cost_code AND j.status IN ('POSTED', 'REVERSED')
     AND j.source_type <> 'P2P_GRN';
  -- Stock issued to the code consumes the code's own inventory commitment
  -- first, but never more than the code's orders put away: the code bears
  -- commitment + max(0, issued - put away).
  committed := committed - least(greatest(issued, 0), put_away);
  available := budget - committed - reserved - actual_other;
END$$;

-- R9-F1/F4/F3 ---------------------------------------------------------------------
ALTER TABLE schedule_versions ADD CONSTRAINT schedule_versions_holidays_bounded CHECK (cardinality(holidays) <= 400);

CREATE OR REPLACE FUNCTION schedule_evm(p_project uuid, p_status date)
RETURNS TABLE (version_id uuid, bac numeric, pv numeric, ev numeric, ac numeric, sv numeric, cv numeric, spi numeric, cpi numeric, progress_date date)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE v schedule_versions; ccy char(3); n integer; pd date;
BEGIN
  SELECT * INTO v FROM schedule_versions WHERE project_id = p_project AND status = 'BASELINE' AND tenant_id = current_tenant();
  IF v.id IS NULL THEN
    RETURN;
  END IF;
  -- R9-F3: a status date within ten years of the planned finish.
  IF p_status < v.start_date - 3660 OR p_status > COALESCE(v.finish_date, v.start_date) + 3660 THEN
    RAISE EXCEPTION 'the status date % is outside the schedule horizon', p_status USING ERRCODE = 'check_violation';
  END IF;
  SELECT le.functional_currency INTO ccy FROM legal_entities le WHERE le.id = v.legal_entity_id;
  -- R9-F4: working days elapsed by the end of the status date (the start day
  -- counts once the status date has reached it, whatever the status date's
  -- own calendar).
  n := CASE WHEN p_status < v.start_date THEN 0
            ELSE schedule_offset(v, p_status) + CASE WHEN schedule_is_working(v, v.start_date) THEN 1 ELSE 0 END END;
  SELECT max(p.status_date) INTO pd FROM schedule_progress p WHERE p.version_id = v.id AND p.status = 'APPROVED' AND p.status_date <= p_status;
  version_id := v.id;
  progress_date := pd;
  SELECT COALESCE(sum(a.budget), 0),
         COALESCE(sum(p2p_round(a.budget * CASE WHEN a.duration = 0 THEN (CASE WHEN n > a.es THEN 1 ELSE 0 END)
                                               ELSE least(1, greatest(0, (n - a.es)::numeric / a.duration)) END, ccy)), 0)
    INTO bac, pv FROM schedule_activities a WHERE a.version_id = v.id;
  -- R9-F1: each activity at its latest approved percent complete at or
  -- before the status date (a report need not list every activity).
  SELECT COALESCE(sum(p2p_round(a.budget * COALESCE(lp.percent_complete, 0) / 100, ccy)), 0) INTO ev
    FROM schedule_activities a
    LEFT JOIN LATERAL (SELECT l.percent_complete FROM schedule_progress_lines l JOIN schedule_progress p ON p.id = l.progress_id
                        WHERE p.version_id = v.id AND p.status = 'APPROVED' AND p.status_date <= p_status AND l.activity_code = a.code
                        ORDER BY p.status_date DESC LIMIT 1) lp ON true
   WHERE a.version_id = v.id;
  SELECT COALESCE(sum(CASE WHEN jl.side = 'DEBIT' THEN jl.amount ELSE -jl.amount END), 0) INTO ac
    FROM journal_lines jl JOIN journals j ON j.id = jl.journal_id JOIN accounts acc ON acc.id = jl.account_id
   WHERE jl.tenant_id = current_tenant() AND jl.project_id = p_project AND acc.type = 'EXPENSE' AND j.status IN ('POSTED', 'REVERSED')
     AND (j.business_event_at AT TIME ZONE 'UTC')::date <= p_status;
  sv := ev - pv; cv := ev - ac;
  spi := CASE WHEN pv = 0 THEN NULL ELSE round(ev / pv, 4) END;
  cpi := CASE WHEN ac = 0 THEN NULL ELSE round(ev / ac, 4) END;
  RETURN NEXT;
END$$;

-- R9-F7 -----------------------------------------------------------------------------
-- The 0027 checks, plus free float, the critical flag and the late dates
-- (the same rules as pkg/schedule).
CREATE OR REPLACE FUNCTION schedule_assert_cpm(v schedule_versions) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE bad record; fin integer; target integer; cyclic boolean; minf integer;
BEGIN
  WITH RECURSIVE reach(origin, node, depth) AS (
    SELECT l.pred_code, l.succ_code, 1 FROM schedule_links l WHERE l.version_id = v.id
    UNION
    SELECT r.origin, l.succ_code, r.depth + 1 FROM reach r JOIN schedule_links l ON l.version_id = v.id AND l.pred_code = r.node
     WHERE r.depth < 10000 AND r.node <> r.origin)
  SELECT EXISTS (SELECT 1 FROM reach WHERE node = origin) INTO cyclic;
  IF cyclic THEN
    RAISE EXCEPTION 'the schedule network has a dependency cycle' USING ERRCODE = 'check_violation';
  END IF;
  SELECT max(ef) INTO fin FROM schedule_activities WHERE version_id = v.id;
  IF fin IS DISTINCT FROM v.finish_offset OR v.finish_date IS DISTINCT FROM schedule_date(v, greatest(fin - 1, 0)) THEN
    RAISE EXCEPTION 'the schedule finish (% / %) is not the latest early finish (%)', v.finish_offset, v.finish_date, fin USING ERRCODE = 'check_violation';
  END IF;
  target := CASE WHEN v.required_finish IS NULL THEN fin ELSE schedule_offset(v, v.required_finish) + 1 END;
  SELECT min(ls - es) INTO minf FROM schedule_activities WHERE version_id = v.id;
  SELECT a.code, a.es, a.ef, a.ls, a.lf INTO bad FROM schedule_activities a
   WHERE a.version_id = v.id AND (
         a.es IS NULL OR a.ef IS DISTINCT FROM a.es + a.duration OR a.lf IS DISTINCT FROM a.ls + a.duration
      OR a.total_float IS DISTINCT FROM a.ls - a.es
      OR a.es IS DISTINCT FROM greatest(0, COALESCE((
           SELECT max(CASE l.link_type WHEN 'FS' THEN p.ef + l.lag WHEN 'SS' THEN p.es + l.lag
                                       WHEN 'FF' THEN p.ef + l.lag - a.duration ELSE p.es + l.lag - a.duration END)
             FROM schedule_links l JOIN schedule_activities p ON p.version_id = v.id AND p.code = l.pred_code
            WHERE l.version_id = v.id AND l.succ_code = a.code), 0))
      OR a.lf IS DISTINCT FROM least(target, COALESCE((
           SELECT min(CASE l.link_type WHEN 'FS' THEN s.ls - l.lag WHEN 'SS' THEN s.ls - l.lag + a.duration
                                       WHEN 'FF' THEN s.lf - l.lag ELSE s.lf - l.lag + a.duration END)
             FROM schedule_links l JOIN schedule_activities s ON s.version_id = v.id AND s.code = l.succ_code
            WHERE l.version_id = v.id AND l.pred_code = a.code), target))
      -- free float: slack before the earliest successor moves (target - EF
      -- for an activity without successors)
      OR a.free_float IS DISTINCT FROM COALESCE((
           SELECT min(s.es - CASE l.link_type WHEN 'FS' THEN a.ef + l.lag WHEN 'SS' THEN a.es + l.lag
                                              WHEN 'FF' THEN a.ef + l.lag - s.duration ELSE a.es + l.lag - s.duration END)
             FROM schedule_links l JOIN schedule_activities s ON s.version_id = v.id AND s.code = l.succ_code
            WHERE l.version_id = v.id AND l.pred_code = a.code), target - a.ef)
      OR a.critical IS DISTINCT FROM (a.ls - a.es = minf AND minf <= 0)
      OR a.early_start IS DISTINCT FROM schedule_date(v, a.es)
      OR a.early_finish IS DISTINCT FROM schedule_date(v, CASE WHEN a.duration = 0 THEN a.es ELSE a.ef - 1 END)
      OR a.late_start IS DISTINCT FROM CASE WHEN a.ls >= 0 THEN schedule_date(v, a.ls) END
      OR a.late_finish IS DISTINCT FROM CASE WHEN a.ls >= 0 THEN schedule_date(v, CASE WHEN a.lf = a.ls THEN a.ls ELSE a.lf - 1 END) END)
   LIMIT 1;
  IF bad.code IS NOT NULL THEN
    RAISE EXCEPTION 'activity % does not satisfy the critical path equations (ES % EF % LS % LF %, floats, critical flag or dates)',
      bad.code, bad.es, bad.ef, bad.ls, bad.lf USING ERRCODE = 'check_violation';
  END IF;
END$$;

-- R9-I1 -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION schedule_progress_order() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.status = 'APPROVED' AND OLD.status = 'DRAFT' AND EXISTS (
       SELECT 1 FROM schedule_progress WHERE version_id = NEW.version_id AND status = 'APPROVED' AND status_date > NEW.status_date) THEN
    RAISE EXCEPTION 'progress is approved forward: a later status date is already approved' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER schedule_progress_xorder BEFORE UPDATE ON schedule_progress FOR EACH ROW EXECUTE FUNCTION schedule_progress_order();

CREATE OR REPLACE FUNCTION schedule_progress_lines_start() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.actual_start < (SELECT start_date FROM schedule_versions WHERE id = NEW.version_id) THEN
    RAISE EXCEPTION 'activity %: the actual start % is before the schedule start', NEW.activity_code, NEW.actual_start USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER schedule_progress_lines_xstart BEFORE INSERT ON schedule_progress_lines FOR EACH ROW EXECUTE FUNCTION schedule_progress_lines_start();

-- R9-F8 -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION serk_database_posture() RETURNS TABLE (issue text)
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  WITH tenant_logins AS (
    SELECT r.oid, r.rolname FROM pg_roles r
     WHERE r.rolcanlogin AND NOT r.rolsuper AND pg_has_role(r.oid, 'serk_app', 'MEMBER'))
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
$$;

-- R9-I2 -----------------------------------------------------------------------------
-- The 0028 function: only on an APPROVED order; the attestation names the
-- line and the item; held by a procurement approver.
CREATE OR REPLACE FUNCTION po_lines_stock_item() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE it stock_items; po purchase_orders;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.stock_item_id IS NOT DISTINCT FROM OLD.stock_item_id THEN
      RETURN NEW;
    END IF;
    IF OLD.stock_item_id IS NOT NULL OR NEW.stock_item_id IS NULL THEN
      RAISE EXCEPTION 'the stock item of a purchase order line is set once' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO po FROM purchase_orders WHERE id = NEW.po_id AND tenant_id = current_tenant();
    IF po.status IS DISTINCT FROM 'APPROVED' THEN
      RAISE EXCEPTION 'stock items are designated on an APPROVED purchase order (this one is %)', po.status USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM stock_receipts r JOIN grns g ON g.id = r.grn_id WHERE g.po_id = NEW.po_id AND r.po_line_no = NEW.line_no) THEN
      RAISE EXCEPTION 'purchase order line % already has stock put away', NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
    PERFORM approval_use('po.line.designate', 'purchase_order', NEW.po_id::text, NULL, ARRAY['po.approve'], false,
      'DESIGNATE:' || NEW.line_no || ':' || NEW.stock_item_id, NULL);
  END IF;
  IF NEW.stock_item_id IS NOT NULL THEN
    SELECT * INTO it FROM stock_items WHERE id = NEW.stock_item_id AND tenant_id = current_tenant();
    IF it.status IS DISTINCT FROM 'ACTIVE' OR it.legal_entity_id <> NEW.legal_entity_id OR it.inventory_account_id <> NEW.account_id
       OR lower(btrim(it.unit)) <> lower(btrim(NEW.unit)) THEN
      RAISE EXCEPTION 'purchase order line %: the stock item must be ACTIVE, of the entity, in the line''s unit, with the line''s account as its inventory account',
        NEW.line_no USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END$$;

-- R9-I3 -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION variation_lines_same_tx() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM contract_variations v WHERE v.id = NEW.variation_id
                   AND v.xmin::text = (pg_current_xact_id()::xid)::text) THEN
    RAISE EXCEPTION 'variation lines are recorded with their variation, in the same transaction' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER variation_lines_zsame_tx BEFORE INSERT ON variation_lines FOR EACH ROW EXECUTE FUNCTION variation_lines_same_tx();

REVOKE ALL ON FUNCTION schedule_progress_order(), schedule_progress_lines_start(), variation_lines_same_tx() FROM PUBLIC;
