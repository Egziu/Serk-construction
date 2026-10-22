-- 0019: decisions are made by people (governed AI).
--
-- Until now only payment approval and release required the platform-signed
-- principal.human marker (0014/0015). Found while testing Journey B: an
-- AI-kind principal could approve customer invoices and, by the same route,
-- any other decision (journals, purchase orders, IPC certification, period
-- close). From this migration on, every attestation for an action that is
-- not a draft action must carry principal.human, which the API signer adds
-- only when the identity provider asserted a human principal and which no
-- role can grant. The list of draft actions mirrors auth.IsDraftAction.

CREATE OR REPLACE FUNCTION approval_is_draft_action(p_action text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, public AS $$
  SELECT p_action ~ '\.(create|submit)$' OR p_action IN ('rfq.quote.record', 'bank.import', 'workflow.start')
$$;

CREATE OR REPLACE FUNCTION approval_attestations_human_decisions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT approval_is_draft_action(NEW.action) AND NOT ('principal.human' = ANY (NEW.perms)) THEN
    RAISE EXCEPTION '% is a decision reserved to principals the identity provider asserts are human (actor %)', NEW.action, NEW.actor
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END$$;

CREATE TRIGGER approval_attestations_human_decisions BEFORE INSERT ON approval_attestations
  FOR EACH ROW EXECUTE FUNCTION approval_attestations_human_decisions();

REVOKE ALL ON FUNCTION approval_is_draft_action(text), approval_attestations_human_decisions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approval_is_draft_action(text) TO serk_app;
