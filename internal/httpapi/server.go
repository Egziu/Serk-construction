// Package httpapi exposes the financial kernel over a versioned REST API.
// Contract: api/openapi.yaml.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

const (
	maxBodyBytes   = 1 << 20 // 1 MiB; journals with thousands of lines still fit
	requestTimeout = 15 * time.Second
)

// Config for the server.
type Config struct {
	Verifier      TokenVerifier
	Kernel        *kernel.Service
	Store         interface{ Ping(context.Context) error }
	Logger        *slog.Logger
	RatePerMinute int // per-principal command budget; 0 = default 300
}

// Server is the HTTP handler.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	limiter *limiter
}

// New builds the handler tree.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = 300
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), limiter: newLimiter(cfg.RatePerMinute)}
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /readyz", s.readyz)
	s.mux.Handle("POST /v1/journals", s.authed(s.createJournal))
	s.mux.Handle("GET /v1/journals/{id}", s.authed(s.getJournal))
	s.mux.Handle("POST /v1/journals/{id}/approve", s.authed(s.approveJournal))
	s.mux.Handle("POST /v1/journals/{id}/post", s.authed(s.postJournal))
	s.mux.Handle("POST /v1/journals/{id}/reverse", s.authed(s.reverseJournal))
	s.mux.Handle("POST /v1/fx/sources", s.authed(s.registerSource))
	s.mux.Handle("POST /v1/fx/sources/{id}/approve", s.authed(s.approveSource))
	s.mux.Handle("POST /v1/fx/policies", s.authed(s.proposePolicy))
	s.mux.Handle("POST /v1/fx/policies/{id}/approve", s.authed(s.decidePolicy(true)))
	s.mux.Handle("POST /v1/fx/policies/{id}/reject", s.authed(s.decidePolicy(false)))
	s.mux.Handle("POST /v1/fx/snapshots", s.authed(s.recordSnapshot))
	s.mux.Handle("POST /v1/fx/snapshots/{id}/approve", s.authed(s.approveSnapshot))
	s.mux.Handle("POST /v1/fx/snapshots/{id}/reject", s.authed(s.rejectSnapshot))
	s.mux.Handle("POST /v1/fx/snapshots/{id}/withdraw", s.authed(s.withdrawSnapshot))
	s.mux.Handle("POST /v1/fx/convert", s.authed(s.convert))
	s.mux.Handle("POST /v1/periods/{id}/close", s.authed(s.closePeriod))
	s.mux.Handle("POST /v1/periods/{id}/reopen", s.authed(s.reopenPeriod))
	return s
}

// ServeHTTP applies the cross-cutting middleware chain.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rid := r.Header.Get("X-Request-ID")
	if rid == "" || len(rid) > 64 {
		rid = uuid.NewString()
	}
	w.Header().Set("X-Request-ID", rid)
	// Security headers (ASVS V14.4): the API never serves HTML.
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	ctx, cancel := context.WithTimeout(kernel.WithRequestID(r.Context(), rid), requestTimeout)
	defer cancel()
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	s.mux.ServeHTTP(rec, r.WithContext(ctx))
	s.cfg.Logger.Info("http", "rid", rid, "method", r.Method, "path", r.URL.Path, "status", rec.status, "ms", time.Since(start).Milliseconds())
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }

type ctxKey int

const principalKey ctxKey = 1

func principalFrom(ctx context.Context) auth.Principal {
	p, _ := ctx.Value(principalKey).(auth.Principal)
	return p
}

// authed verifies the bearer token, applies rate limiting and injects the principal.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="serk"`)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "bearer token required")
			return
		}
		p, err := s.cfg.Verifier.Verify(strings.TrimPrefix(hdr, "Bearer "), time.Now())
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="serk", error="invalid_token"`)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "invalid token")
			return
		}
		if !s.limiter.allow(p.TenantID + "/" + p.UserID) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "command budget exceeded")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Store.Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "not_ready", "database unreachable")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

type lineDTO struct {
	AccountID    string       `json:"account_id"`
	Side         string       `json:"side"`
	Amount       money.Money  `json:"amount"`
	TxnAmount    *money.Money `json:"txn_amount,omitempty"`
	FXSnapshotID string       `json:"fx_snapshot_id,omitempty"`
	AppliedRate  string       `json:"applied_rate,omitempty"` // read-only; ignored on input
	ProjectID    string       `json:"project_id,omitempty"`
	CostCodeID   string       `json:"cost_code_id,omitempty"`
	Memo         string       `json:"memo,omitempty"`
}

type journalDTO struct {
	ID                 string    `json:"id,omitempty"`
	LegalEntityID      string    `json:"legal_entity_id"`
	ProjectID          string    `json:"project_id,omitempty"`
	FunctionalCurrency string    `json:"functional_currency"`
	Status             string    `json:"status,omitempty"`
	BusinessEventAt    time.Time `json:"business_event_at"`
	Description        string    `json:"description"`
	SourceType         string    `json:"source_type"`
	SourceRef          string    `json:"source_ref,omitempty"`
	IdempotencyKey     string    `json:"idempotency_key"`
	Lines              []lineDTO `json:"lines"`
	CreatedBy          string    `json:"created_by,omitempty"`
	ApprovedBy         string    `json:"approved_by,omitempty"`
	PostedBy           string    `json:"posted_by,omitempty"`
	ReversalOf         string    `json:"reversal_of,omitempty"`
	ReversedBy         string    `json:"reversed_by,omitempty"`
	Version            int       `json:"version,omitempty"`
}

func toDomain(d journalDTO) ledger.Journal {
	j := ledger.Journal{LegalEntityID: d.LegalEntityID, ProjectID: d.ProjectID, FunctionalCurrency: money.Currency(d.FunctionalCurrency),
		BusinessEventAt: d.BusinessEventAt, Description: d.Description, SourceType: d.SourceType, SourceRef: d.SourceRef, IdempotencyKey: d.IdempotencyKey}
	for i, l := range d.Lines {
		j.Lines = append(j.Lines, ledger.Line{LineNo: i + 1, AccountID: l.AccountID, Side: ledger.Side(l.Side), Amount: l.Amount, TxnAmount: l.TxnAmount,
			FXSnapshotID: l.FXSnapshotID, ProjectID: l.ProjectID, CostCodeID: l.CostCodeID, Memo: l.Memo})
	}
	return j
}

func fromRecord(r postgres.JournalRecord) journalDTO {
	d := journalDTO{ID: r.ID, LegalEntityID: r.LegalEntityID, ProjectID: r.ProjectID, FunctionalCurrency: string(r.FunctionalCurrency), Status: string(r.Status),
		BusinessEventAt: r.BusinessEventAt, Description: r.Description, SourceType: r.SourceType, SourceRef: r.SourceRef, IdempotencyKey: r.IdempotencyKey,
		CreatedBy: r.CreatedBy, ApprovedBy: r.ApprovedBy, PostedBy: r.PostedBy, ReversalOf: r.ReversalOf, ReversedBy: r.ReversedBy, Version: r.Version}
	for _, l := range r.Lines {
		ld := lineDTO{AccountID: l.AccountID, Side: string(l.Side), Amount: l.Amount, TxnAmount: l.TxnAmount, FXSnapshotID: l.FXSnapshotID,
			ProjectID: l.ProjectID, CostCodeID: l.CostCodeID, Memo: l.Memo}
		if l.TxnAmount != nil {
			ld.AppliedRate = l.AppliedRate.String()
		}
		d.Lines = append(d.Lines, ld)
	}
	return d
}

func (s *Server) createJournal(w http.ResponseWriter, r *http.Request) {
	var d journalDTO
	if !decode(w, r, &d) {
		return
	}
	res, err := s.cfg.Kernel.CreateJournal(r.Context(), principalFrom(r.Context()), toDomain(d))
	if err != nil {
		s.fail(w, err)
		return
	}
	status := http.StatusCreated
	if res.Replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"id": res.JournalID, "replayed": res.Replayed})
}

func (s *Server) getJournal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "journal not found")
		return
	}
	rec, err := s.cfg.Kernel.GetJournal(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, fromRecord(rec))
}

func (s *Server) approveJournal(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, s.cfg.Kernel.ApproveJournal)
}

func (s *Server) postJournal(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, s.cfg.Kernel.PostJournal)
}

func (s *Server) transition(w http.ResponseWriter, r *http.Request, fn func(context.Context, auth.Principal, string) error) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "journal not found")
		return
	}
	if err := fn(r.Context(), principalFrom(r.Context()), id); err != nil {
		s.fail(w, err)
		return
	}
	rec, err := s.cfg.Kernel.GetJournal(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, fromRecord(rec))
}

func (s *Server) reverseJournal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "journal not found")
		return
	}
	var body struct {
		IdempotencyKey  string    `json:"idempotency_key"`
		Reason          string    `json:"reason"`
		BusinessEventAt time.Time `json:"business_event_at"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := s.cfg.Kernel.ReverseJournal(r.Context(), principalFrom(r.Context()), id, body.IdempotencyKey, body.Reason, body.BusinessEventAt)
	if err != nil {
		s.fail(w, err)
		return
	}
	status := http.StatusCreated
	if res.Replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"id": res.JournalID, "replayed": res.Replayed, "reversal_of": id})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body exceeds limit")
			return false
		}
		if errors.Is(err, money.ErrInvalidAmount) || errors.Is(err, money.ErrUnknownCurrency) {
			writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
			return false
		}
		writeErr(w, http.StatusBadRequest, "malformed_json", "body is not valid JSON for this endpoint")
		return false
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest, "malformed_json", "unexpected trailing data")
		return false
	}
	return true
}

// fail maps domain errors to HTTP without leaking internals. Authorization
// failures on a specific resource are reported as 404 so that existence of
// another tenant's data is never confirmed; permission failures on the
// caller's own tenant are 403.
func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, kernel.ErrNotFound), errors.Is(err, auth.ErrTenantMismatch):
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, auth.ErrStepUpRequired):
		// RFC 9470 step-up authentication challenge.
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", error_description="recent multi-factor authentication required", max_age=600`)
		writeErr(w, http.StatusUnauthorized, "step_up_required", "recent multi-factor authentication required")
	case errors.Is(err, auth.ErrUnauthenticated):
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
	case errors.Is(err, auth.ErrSoD):
		writeErr(w, http.StatusConflict, "segregation_of_duties", err.Error())
	case errors.Is(err, auth.ErrForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "insufficient permission")
	case errors.Is(err, postgres.ErrIdempotencyConflict):
		writeErr(w, http.StatusConflict, "idempotency_conflict", "idempotency key already used with a different command")
	case errors.Is(err, postgres.ErrVersionConflict):
		writeErr(w, http.StatusConflict, "version_conflict", "journal was modified concurrently; reload and retry")
	case errors.Is(err, ledger.ErrBadTransition), errors.Is(err, ledger.ErrNotPosted), errors.Is(err, ledger.ErrAlreadyReversed),
		errors.Is(err, fx.ErrSnapshotState), errors.Is(err, kernel.ErrClosePrerequisite):
		writeErr(w, http.StatusConflict, "invalid_state", uuidRe.ReplaceAllString(err.Error(), "<id>"))
	case errors.Is(err, fx.ErrRateMissing), errors.Is(err, fx.ErrRateStale), errors.Is(err, fx.ErrRateNotYetKnown), errors.Is(err, postgres.ErrNoFXPolicy):
		writeErr(w, http.StatusUnprocessableEntity, "fx_exception", err.Error())
	case errors.Is(err, kernel.ErrReasonRequired), errors.Is(err, fx.ErrPolicyInvalid):
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
	case errors.Is(err, ledger.ErrUnbalanced), errors.Is(err, ledger.ErrBadLine), errors.Is(err, ledger.ErrTooFewLines), errors.Is(err, postgres.ErrLineRejected),
		errors.Is(err, ledger.ErrMissingIdempotencyKey), errors.Is(err, money.ErrUnknownCurrency), errors.Is(err, money.ErrCurrencyMismatch),
		errors.Is(err, fx.ErrSameCurrency), isValidation(err):
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
	case errors.Is(err, postgres.ErrInvariant):
		// Database-level refusal (balance, period, immutability). Only the
		// trigger's reason survives; identifiers are stripped from the message.
		writeErr(w, http.StatusConflict, "invariant_violation", "the database refused the change: "+trimPG(err))
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "timeout", "request timed out")
	default:
		s.cfg.Logger.Error("internal", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func isValidation(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "ledger:") || strings.HasPrefix(msg, "fx:") || strings.HasPrefix(msg, "money:")
}

var uuidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

func trimPG(err error) string {
	msg := strings.TrimPrefix(err.Error(), postgres.ErrInvariant.Error()+": ")
	if i := strings.Index(msg, " (SQLSTATE"); i > 0 {
		msg = msg[:i]
	}
	msg = uuidRe.ReplaceAllString(msg, "<id>")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// ---------------------------------------------------------------------------
// Fixed-window per-principal rate limiter (in-process). A shared store is
// the documented next step for multi-replica deployments.
// ---------------------------------------------------------------------------

type limiter struct {
	mu     sync.Mutex
	limit  int
	window map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

func newLimiter(limit int) *limiter { return &limiter{limit: limit, window: map[string]*bucket{}} }

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.window[key]
	if b == nil || now.After(b.reset) {
		if len(l.window) > 10_000 { // bound memory under key churn: drop only expired windows
			for k, v := range l.window {
				if now.After(v.reset) {
					delete(l.window, k)
				}
			}
		}
		b = &bucket{reset: now.Add(time.Minute)}
		l.window[key] = b
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// Listen runs the server with hardened timeouts until ctx is cancelled.
func Listen(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", addr)
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func parseDecimal(s string) (decimal.Decimal, error) {
	return decimal.NewFromString(strings.TrimSpace(s))
}
