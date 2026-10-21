-- SERK Construction — migration 0004: reliable outbox delivery (SC-07, SC-11)
--
-- Delivery state for the relay: retry schedule, last error, and a
-- dead-letter marker after repeated failures. Content columns stay immutable
-- (outbox_guard from 0001). Consumers de-duplicate on event_id because
-- delivery is at-least-once (a relay crash after publishing but before
-- recording success re-delivers).

ALTER TABLE outbox
  ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN last_error      text,
  ADD COLUMN dead_at         timestamptz;

DROP INDEX IF EXISTS outbox_unpublished;
CREATE INDEX outbox_pending ON outbox (next_attempt_at, id) WHERE published_at IS NULL AND dead_at IS NULL;
CREATE INDEX outbox_aggregate ON outbox (tenant_id, aggregate_type, aggregate_id, id) WHERE published_at IS NULL;

-- A published or dead-lettered event cannot be silently "un-published";
-- only an explicit replay (dead -> pending) is allowed.
CREATE OR REPLACE FUNCTION outbox_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
    RAISE EXCEPTION 'outbox event % was already published', OLD.event_id USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'outbox attempt counter cannot decrease' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER outbox_delivery_guard BEFORE UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION outbox_delivery_guard();

-- Consumer-side de-duplication ledger.
CREATE TABLE processed_events (
  consumer     text NOT NULL CHECK (length(consumer) BETWEEN 1 AND 64),
  event_id     uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer, event_id)
);

REVOKE UPDATE ON outbox FROM serk_publisher;
GRANT UPDATE (published_at, attempts, next_attempt_at, last_error, dead_at) ON outbox TO serk_publisher;
GRANT SELECT, INSERT ON processed_events TO serk_publisher;
