// Package relay delivers transactional-outbox events to integration targets
// (SC-07, SC-11). Delivery is at-least-once: an event is marked published only
// after the target acknowledged it, so a crash in between re-delivers it and
// consumers de-duplicate on EventID (Consume / VerifyWebhook).
//
// Ordering: events of one aggregate are delivered strictly in commit order.
// An earlier undelivered event — including a dead-lettered one — holds back
// later events of the same aggregate until it is delivered or replayed.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is one outbox row as delivered.
type Event struct {
	ID            int64           `json:"-"`
	EventID       string          `json:"event_id"`
	TenantID      string          `json:"tenant_id"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	EventType     string          `json:"event_type"`
	SchemaVersion int             `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     time.Time       `json:"created_at"`
	Attempt       int             `json:"attempt"`
}

// Publisher delivers one event. It must return nil only once the target has
// durably accepted the event.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// Relay moves events from the outbox to a Publisher.
type Relay struct {
	DB             *pgxpool.Pool // logged in as a member of serk_publisher
	Pub            Publisher
	Batch          int
	MaxAttempts    int
	PublishTimeout time.Duration
	Log            *slog.Logger
	// TenantID, when set, restricts this relay to one tenant (per-tenant
	// relays for DEDICATED_DB deployments; isolation in tests).
	TenantID string

	crashBeforeCommit bool // test hook: simulate a crash after publishing
}

// Stats summarises one RunOnce.
type Stats struct{ Published, Retried, DeadLettered int }

func (r *Relay) defaults() {
	if r.Batch == 0 {
		r.Batch = 100
	}
	if r.MaxAttempts == 0 {
		r.MaxAttempts = 10
	}
	if r.PublishTimeout == 0 {
		r.PublishTimeout = 10 * time.Second
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
}

// Backoff is the retry delay after the n-th failed attempt: 2^n seconds,
// capped at one hour.
func Backoff(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	if d > time.Hour || d <= 0 {
		return time.Hour
	}
	return d
}

var errCrash = errors.New("relay: simulated crash before commit")

// RunOnce claims a batch of due events (skipping rows another relay holds),
// publishes them in id order and records the outcome in the same transaction.
func (r *Relay) RunOnce(ctx context.Context) (Stats, error) {
	r.defaults()
	var st Stats
	tx, err := r.DB.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return st, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// One active relay per database: concurrent relays could otherwise split
	// an aggregate's events (SKIP LOCKED) and deliver them out of order.
	// Standby replicas simply find the lock taken and return.
	var leader bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(727002)`).Scan(&leader); err != nil {
		return st, err
	}
	if !leader {
		return st, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT o.id, o.event_id::text, o.tenant_id::text, o.aggregate_type, o.aggregate_id, o.event_type, o.schema_version,
		       o.payload::text, o.created_at, o.attempts
		  FROM outbox o
		 WHERE o.published_at IS NULL AND o.dead_at IS NULL AND o.next_attempt_at <= now()
		   AND ($2::text = '' OR o.tenant_id = NULLIF($2, '')::uuid)
		   -- Hold back events queued behind an earlier event of the same
		   -- aggregate that is dead-lettered or waiting for its retry.
		   AND NOT EXISTS (SELECT 1 FROM outbox p
		                    WHERE p.tenant_id = o.tenant_id AND p.aggregate_type = o.aggregate_type
		                      AND p.aggregate_id = o.aggregate_id AND p.id < o.id AND p.published_at IS NULL
		                      AND (p.dead_at IS NOT NULL OR p.next_attempt_at > now()))
		 ORDER BY o.id
		 LIMIT $1
		 FOR UPDATE SKIP LOCKED`, r.Batch, r.TenantID)
	if err != nil {
		return st, err
	}
	var batch []Event
	for rows.Next() {
		var e Event
		var payload string
		if err := rows.Scan(&e.ID, &e.EventID, &e.TenantID, &e.AggregateType, &e.AggregateID, &e.EventType, &e.SchemaVersion, &payload, &e.CreatedAt, &e.Attempt); err != nil {
			rows.Close()
			return st, err
		}
		e.Payload = json.RawMessage(payload)
		e.Attempt++
		batch = append(batch, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}
	// Within the batch, a failure stops the rest of that aggregate.
	failedAggregates := map[string]bool{}
	for _, e := range batch {
		agg := e.TenantID + "/" + e.AggregateType + "/" + e.AggregateID
		if failedAggregates[agg] {
			// An earlier event of this aggregate failed in this batch: keep order.
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, r.PublishTimeout)
		perr := r.Pub.Publish(pctx, e)
		cancel()
		if perr == nil {
			if _, err := tx.Exec(ctx, `UPDATE outbox SET published_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1`, e.ID); err != nil {
				return st, err
			}
			st.Published++
			continue
		}
		failedAggregates[agg] = true
		msg := perr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if e.Attempt >= r.MaxAttempts {
			if _, err := tx.Exec(ctx, `UPDATE outbox SET attempts = attempts + 1, last_error = $2, dead_at = now() WHERE id = $1`, e.ID, msg); err != nil {
				return st, err
			}
			st.DeadLettered++
			r.Log.Error("outbox event dead-lettered", "event_id", e.EventID, "event_type", e.EventType, "attempts", e.Attempt, "err", msg)
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1`,
			e.ID, msg, Backoff(e.Attempt).Seconds()); err != nil {
			return st, err
		}
		st.Retried++
		r.Log.Warn("outbox delivery failed", "event_id", e.EventID, "attempt", e.Attempt, "err", msg)
	}
	if r.crashBeforeCommit {
		return st, errCrash
	}
	return st, tx.Commit(ctx)
}

// Run polls until ctx is cancelled.
func (r *Relay) Run(ctx context.Context, interval time.Duration) error {
	r.defaults()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		st, err := r.RunOnce(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			r.Log.Error("relay batch failed", "err", err)
		} else if st.Published+st.Retried+st.DeadLettered > 0 {
			r.Log.Info("relay batch", "published", st.Published, "retried", st.Retried, "dead_lettered", st.DeadLettered)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Replay returns a dead-lettered event to the queue (operator action).
func Replay(ctx context.Context, db *pgxpool.Pool, eventID string) error {
	tag, err := db.Exec(ctx, `UPDATE outbox SET dead_at = NULL, next_attempt_at = now() WHERE event_id = $1::uuid AND dead_at IS NOT NULL AND published_at IS NULL`, eventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("relay: event %s is not dead-lettered", eventID)
	}
	return nil
}

// Lag reports, within the relay's scope, the age of the oldest undelivered
// event, the pending count and the dead-letter count (for alerting).
func (r *Relay) Lag(ctx context.Context) (oldest time.Duration, pending, dead int, err error) {
	var age *float64
	err = r.DB.QueryRow(ctx, `SELECT extract(epoch FROM now() - min(created_at) FILTER (WHERE dead_at IS NULL))::float8,
		count(*) FILTER (WHERE dead_at IS NULL), count(*) FILTER (WHERE dead_at IS NOT NULL)
		FROM outbox WHERE published_at IS NULL AND ($1::text = '' OR tenant_id = NULLIF($1, '')::uuid)`, r.TenantID).Scan(&age, &pending, &dead)
	if age != nil {
		oldest = time.Duration(*age * float64(time.Second))
	}
	return
}

// Consume runs fn at most once per (consumer, event) inside tx: it records
// the event id first and skips fn when the event was already processed.
// It returns whether fn ran.
func Consume(ctx context.Context, tx pgx.Tx, consumer, eventID string, fn func() error) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO processed_events(consumer, event_id) VALUES ($1, $2::uuid) ON CONFLICT DO NOTHING`, consumer, eventID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	return true, fn()
}
