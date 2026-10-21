package relay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// WebhookPublisher POSTs events as JSON with an HMAC-SHA256 signature over
// "<timestamp>.<body>" so receivers can authenticate the sender and reject
// replays (signed timestamp window + event-id de-duplication).
type WebhookPublisher struct {
	URL    string
	Secret []byte
	Client *http.Client
	Now    func() time.Time
}

// Signature computes the hex HMAC of "<unix timestamp>.<body>".
func Signature(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Publish implements Publisher; any non-2xx response is a failure.
func (w WebhookPublisher) Publish(ctx context.Context, e Event) error {
	if len(w.Secret) < 32 {
		return errors.New("webhook: signing secret must be at least 32 bytes")
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	ts := now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Serk-Event-Id", e.EventID)
	req.Header.Set("X-Serk-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Serk-Signature", "v1="+Signature(w.Secret, ts, body))
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Receiver verifies incoming webhooks: signature, timestamp window and
// event-id replay. Seen ids are kept for the window (bounded memory); a
// durable receiver should also use Consume in its own database.
type Receiver struct {
	Secret []byte
	Window time.Duration // default 5 minutes
	Now    func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// Errors returned by Verify.
var (
	ErrBadSignature = errors.New("webhook: bad signature")
	ErrStale        = errors.New("webhook: timestamp outside the accepted window")
	ErrReplay       = errors.New("webhook: event already received")
)

// Verify authenticates a request body and returns the decoded event.
func (r *Receiver) Verify(h http.Header, body []byte) (Event, error) {
	window := r.Window
	if window == 0 {
		window = 5 * time.Minute
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	ts, err := strconv.ParseInt(h.Get("X-Serk-Timestamp"), 10, 64)
	if err != nil {
		return Event{}, ErrBadSignature
	}
	want := "v1=" + Signature(r.Secret, ts, body)
	if !hmac.Equal([]byte(want), []byte(h.Get("X-Serk-Signature"))) {
		return Event{}, ErrBadSignature
	}
	age := now().Sub(time.Unix(ts, 0))
	if age > window || age < -time.Minute {
		return Event{}, ErrStale
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil || e.EventID == "" || e.EventID != h.Get("X-Serk-Event-Id") {
		return Event{}, ErrBadSignature
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	for id, t := range r.seen {
		if now().Sub(t) > window {
			delete(r.seen, id)
		}
	}
	if _, dup := r.seen[e.EventID]; dup {
		return e, ErrReplay
	}
	r.seen[e.EventID] = now()
	return e, nil
}
