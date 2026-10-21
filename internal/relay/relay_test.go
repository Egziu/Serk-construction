package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

type recorder struct {
	mu     sync.Mutex
	got    []Event
	failOn map[string]bool // event types that fail
}

func (r *recorder) Publish(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failOn[e.EventType] {
		return errors.New("target unavailable")
	}
	r.got = append(r.got, e)
	return nil
}

type world struct {
	db     *testdb.Env
	pool   *pgxpool.Pool
	svc    *kernel.Service
	tenant string
	entity string
	acc    [2]string
	prep   auth.Principal
	appr   auth.Principal
	post   auth.Principal
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db := testdb.Setup(t)
	w := &world{db: db, tenant: uuid.NewString()}
	db.ProvisionTenant(t, w.tenant, "relay-test")
	err := db.AdminStore.WithTenant(db.Ctx, w.tenant, func(ctx context.Context, tx pgx.Tx) error {
		le, err := postgres.CreateLegalEntity(ctx, tx, w.tenant, "Relay PLC", "ET", "ETB", "")
		if err != nil {
			return err
		}
		w.entity = le
		if _, err := postgres.CreateFiscalPeriod(ctx, tx, w.tenant, le, "FY26", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
			return err
		}
		for i, code := range []string{"5000", "1000"} {
			typ := ledger.Expense
			if code == "1000" {
				typ = ledger.Asset
			}
			if w.acc[i], err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: w.tenant, LegalEntityID: le, Code: code, Name: code, Type: typ, Active: true}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = kernel.New(db.Router, auth.NewAuthorizer(nil, true)).UseApprovalSigner(attest.Signer{Master: testdb.ApprovalMaster})
	w.prep = auth.Principal{UserID: "prep", TenantID: w.tenant, Roles: []string{"accountant"}}
	w.appr = auth.Principal{UserID: "appr", TenantID: w.tenant, Roles: []string{"finance_manager"}}
	w.post = auth.Principal{UserID: "post", TenantID: w.tenant, Roles: []string{"controller"}}
	// A dedicated relay login, member of serk_publisher only.
	role := "serk_relay_t" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := db.Admin.Exec(db.Ctx, `CREATE ROLE `+role+` LOGIN INHERIT IN ROLE serk_publisher`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Admin.Exec(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1`, role)
		_, _ = db.Admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	u, _ := url.Parse(db.BaseDSN)
	u.User = url.User(role)
	w.pool, err = pgxpool.New(db.Ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.pool.Close)
	return w
}

// journal runs create -> approve -> post and returns the journal id
// (3 outbox events on one aggregate).
func (w *world) journal(t *testing.T, k string) string {
	t.Helper()
	res, err := w.svc.CreateJournal(w.db.Ctx, w.prep, ledger.Journal{LegalEntityID: w.entity, FunctionalCurrency: "ETB",
		BusinessEventAt: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), Description: "relay", SourceType: "MANUAL", IdempotencyKey: k,
		Lines: []ledger.Line{{LineNo: 1, AccountID: w.acc[0], Side: ledger.Debit, Amount: money.MustNew("1.00", "ETB")},
			{LineNo: 2, AccountID: w.acc[1], Side: ledger.Credit, Amount: money.MustNew("1.00", "ETB")}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.ApproveJournal(w.db.Ctx, w.appr, res.JournalID); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.PostJournal(w.db.Ctx, w.post, res.JournalID); err != nil {
		t.Fatal(err)
	}
	return res.JournalID
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func types(es []Event, agg string) []string {
	var out []string
	for _, e := range es {
		if e.AggregateID == agg {
			out = append(out, e.EventType)
		}
	}
	return out
}

func TestRelayDeliversInOrderExactlyOnceWhenHealthy(t *testing.T) {
	w := newWorld(t)
	j := w.journal(t, "r1")
	rec := &recorder{}
	r := &Relay{TenantID: w.tenant, DB: w.pool, Pub: rec, Log: quiet()}
	st, err := r.RunOnce(w.db.Ctx)
	if err != nil || st.Published != 3 {
		t.Fatalf("run: %+v %v", st, err)
	}
	if got := strings.Join(types(rec.got, j), ","); got != "journal.created,journal.approved,journal.posted" {
		t.Fatalf("order: %s", got)
	}
	st, _ = r.RunOnce(w.db.Ctx)
	if st.Published != 0 {
		t.Fatalf("re-delivered published events: %+v", st)
	}
	// The relay login is confined to the outbox.
	if _, err := w.pool.Exec(w.db.Ctx, `SELECT count(*) FROM journals`); err == nil {
		t.Fatal("relay role can read journals")
	}
	if _, err := w.pool.Exec(w.db.Ctx, `UPDATE outbox SET payload='{}' WHERE aggregate_id=$1`, j); err == nil {
		t.Fatal("relay role can rewrite event content")
	}
}

func TestRelayCrashAfterPublishRedeliversAndConsumerDedupes(t *testing.T) {
	w := newWorld(t)
	j := w.journal(t, "r2")
	rec := &recorder{}
	crashing := &Relay{TenantID: w.tenant, DB: w.pool, Pub: rec, Log: quiet(), crashBeforeCommit: true}
	if _, err := crashing.RunOnce(w.db.Ctx); !errors.Is(err, errCrash) {
		t.Fatalf("crash simulation: %v", err)
	}
	healthy := &Relay{TenantID: w.tenant, DB: w.pool, Pub: rec, Log: quiet()}
	if st, err := healthy.RunOnce(w.db.Ctx); err != nil || st.Published != 3 {
		t.Fatalf("redelivery: %+v %v", st, err)
	}
	if n := len(types(rec.got, j)); n != 6 {
		t.Fatalf("expected each event delivered twice (at-least-once), got %d deliveries", n)
	}
	// A consumer applying side effects through Consume runs each event once.
	applied := map[string]int{}
	for _, e := range rec.got {
		tx, err := w.pool.Begin(w.db.Ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Consume(w.db.Ctx, tx, "ledger-projection", e.EventID, func() error { applied[e.EventID]++; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(w.db.Ctx); err != nil {
			t.Fatal(err)
		}
	}
	for id, n := range applied {
		if n != 1 {
			t.Fatalf("event %s applied %d times", id, n)
		}
	}
	if len(applied) != 3 {
		t.Fatalf("applied %d distinct events", len(applied))
	}
}

func TestRelayRetryDeadLetterHeadOfLineAndReplay(t *testing.T) {
	w := newWorld(t)
	j := w.journal(t, "r3")
	rec := &recorder{failOn: map[string]bool{"journal.approved": true}}
	r := &Relay{TenantID: w.tenant, DB: w.pool, Pub: rec, Log: quiet(), MaxAttempts: 2}
	st, _ := r.RunOnce(w.db.Ctx)
	if st.Published != 1 || st.Retried != 1 {
		t.Fatalf("first run: %+v", st)
	}
	// Backoff: not due yet, and the later "posted" event is held back.
	st, _ = r.RunOnce(w.db.Ctx)
	if st.Published+st.Retried != 0 {
		t.Fatalf("retried before backoff or skipped order: %+v", st)
	}
	if _, err := w.db.Admin.Exec(w.db.Ctx, `UPDATE outbox SET next_attempt_at = now() WHERE aggregate_id = $1`, j); err != nil {
		t.Fatal(err)
	}
	st, _ = r.RunOnce(w.db.Ctx)
	if st.DeadLettered != 1 {
		t.Fatalf("not dead-lettered after max attempts: %+v", st)
	}
	if got := types(rec.got, j); len(got) != 1 {
		t.Fatalf("later event delivered past a dead-lettered one: %v", got)
	}
	oldest, pending, dead, err := r.Lag(w.db.Ctx)
	if err != nil || dead != 1 || pending != 1 || oldest <= 0 {
		t.Fatalf("lag: %v %d %d %v", oldest, pending, dead, err)
	}
	// Operator fixes the target and replays: order is preserved.
	var deadID string
	_ = w.db.Admin.QueryRow(w.db.Ctx, `SELECT event_id::text FROM outbox WHERE aggregate_id=$1 AND dead_at IS NOT NULL`, j).Scan(&deadID)
	rec.failOn = nil
	if err := Replay(w.db.Ctx, w.pool, deadID); err != nil {
		t.Fatal(err)
	}
	st, _ = r.RunOnce(w.db.Ctx)
	if st.Published != 2 {
		t.Fatalf("after replay: %+v", st)
	}
	if got := strings.Join(types(rec.got, j), ","); got != "journal.created,journal.approved,journal.posted" {
		t.Fatalf("order after replay: %s", got)
	}
	if err := Replay(w.db.Ctx, w.pool, deadID); err == nil {
		t.Fatal("replayed a delivered event")
	}
	if _, err := w.pool.Exec(w.db.Ctx, `UPDATE outbox SET published_at = NULL WHERE event_id=$1::uuid`, deadID); err == nil {
		t.Fatal("published event was un-published")
	}
}

func TestWebhookSignedDeliveryAndReceiverChecks(t *testing.T) {
	w := newWorld(t)
	w.journal(t, "r4")
	secret := []byte("webhook-signing-secret-0123456789abcdefABCDEF")
	recv := &Receiver{Secret: secret}
	var mu sync.Mutex
	var accepted []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		e, err := recv.Verify(req.Header, body)
		if err != nil && !errors.Is(err, ErrReplay) {
			rw.WriteHeader(401)
			return
		}
		mu.Lock()
		if err == nil {
			accepted = append(accepted, e.EventType)
		}
		mu.Unlock()
		rw.WriteHeader(204) // a replay is acknowledged but not re-applied
	}))
	defer srv.Close()
	r := &Relay{TenantID: w.tenant, DB: w.pool, Pub: WebhookPublisher{URL: srv.URL, Secret: secret}, Log: quiet()}
	if st, err := r.RunOnce(w.db.Ctx); err != nil || st.Published != 3 {
		t.Fatalf("webhook delivery: %+v %v", st, err)
	}
	if len(accepted) != 3 {
		t.Fatalf("receiver accepted %v", accepted)
	}
	// Receiver checks: tamper, wrong secret, stale, replay.
	e := Event{EventID: uuid.NewString(), EventType: "x"}
	pub := WebhookPublisher{Secret: secret}
	body := []byte(`{"event_id":"` + e.EventID + `","event_type":"x"}`)
	h := http.Header{}
	now := time.Now()
	h.Set("X-Serk-Event-Id", e.EventID)
	h.Set("X-Serk-Timestamp", strconv.FormatInt(now.Unix(), 10))
	h.Set("X-Serk-Signature", "v1="+Signature(pub.Secret, now.Unix(), body))
	r2 := &Receiver{Secret: secret}
	if _, err := r2.Verify(h, body); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Verify(h, body); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
	if _, err := (&Receiver{Secret: secret}).Verify(h, append(body[:len(body)-1:len(body)-1], ' ', '}')); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered body accepted: %v", err)
	}
	if _, err := (&Receiver{Secret: []byte("another-secret-0123456789abcdefABCDEF00")}).Verify(h, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret accepted: %v", err)
	}
	late := &Receiver{Secret: secret, Now: func() time.Time { return now.Add(10 * time.Minute) }}
	if _, err := late.Verify(h, body); !errors.Is(err, ErrStale) {
		t.Fatalf("stale delivery accepted: %v", err)
	}
}

func TestBackoff(t *testing.T) {
	if Backoff(1) != 2*time.Second || Backoff(5) != 32*time.Second || Backoff(40) != time.Hour {
		t.Fatalf("backoff: %v %v %v", Backoff(1), Backoff(5), Backoff(40))
	}
}
