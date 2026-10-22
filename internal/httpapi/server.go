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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/obs"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/webui"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
	"github.com/serk-group/serk-construction/pkg/workflow"
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
	Abuse         AbuseConfig
	// Metrics receives the API's counters and histograms; nil creates a
	// private registry (expose it with Server.Metrics().Handler()).
	Metrics *obs.Registry
}

// serverMetrics are the API's own instruments (GATEA-11).
type serverMetrics struct {
	requests   *obs.CounterVec
	latency    *obs.HistogramVec
	authFail   *obs.CounterVec
	revoked    *obs.CounterVec
	sessionErr *obs.CounterVec
	refusals   *obs.CounterVec
	internal   *obs.CounterVec
}

func newServerMetrics(r *obs.Registry) serverMetrics {
	return serverMetrics{
		requests:   r.Counter("serk_http_requests_total", "HTTP requests by route pattern, method and status code.", "route", "method", "code"),
		latency:    r.Histogram("serk_http_request_duration_seconds", "HTTP request latency by route pattern.", obs.DefaultLatencyBuckets, "route"),
		authFail:   r.Counter("serk_auth_failures_total", "Rejected credentials before authentication succeeded, by reason.", "reason"),
		revoked:    r.Counter("serk_revoked_session_uses_total", "Requests presenting a revoked session."),
		sessionErr: r.Counter("serk_session_check_errors_total", "Session revocation checks that failed (requests refused with 503)."),
		refusals: r.Counter("serk_db_authority_refusals_total",
			"Changes the database refused for lack of verified approval evidence or privilege, by kind.", "kind"),
		internal: r.Counter("serk_internal_errors_total", "Requests that ended in an unclassified internal error."),
	}
}

// Server is the HTTP handler.
type Server struct {
	cfg       Config
	mux       *http.ServeMux
	principal *windowLimiter // per authenticated principal
	preauth   *windowLimiter // per client IP, before any token work
	authFail  *windowLimiter // invalid credentials per client IP, with lockout
	inflight  chan struct{}
	m         serverMetrics
}

// Metrics returns the registry holding the API's instruments.
func (s *Server) Metrics() *obs.Registry { return s.cfg.Metrics }

// New builds the handler tree.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = 300
	}
	cfg.Abuse.defaults()
	if cfg.Metrics == nil {
		cfg.Metrics = obs.NewRegistry()
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), m: newServerMetrics(cfg.Metrics),
		principal: newWindowLimiter(cfg.RatePerMinute, time.Minute, 0),
		preauth:   newWindowLimiter(cfg.Abuse.PreAuthPerMinute, time.Minute, 0),
		authFail:  newWindowLimiter(cfg.Abuse.AuthFailuresPerMinute, time.Minute, cfg.Abuse.AuthFailureBlock),
		inflight:  make(chan struct{}, cfg.Abuse.MaxInFlight)}
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
	s.mux.Handle("POST /v1/workflow/definitions", s.authed(s.proposeWorkflowDefinition))
	s.mux.Handle("GET /v1/workflow/definitions", s.authed(s.listWorkflowDefinitions))
	s.mux.Handle("POST /v1/workflow/definitions/{id}/publish", s.authed(s.decideWorkflowDefinition(true)))
	s.mux.Handle("POST /v1/workflow/definitions/{id}/reject", s.authed(s.decideWorkflowDefinition(false)))
	s.mux.Handle("POST /v1/workflow/definitions/{id}/simulate", s.authed(s.simulateWorkflow))
	s.mux.Handle("POST /v1/workflow/instances", s.authed(s.startWorkflow))
	s.mux.Handle("GET /v1/workflow/instances", s.authed(s.listWorkflowInstances))
	s.mux.Handle("GET /v1/workflow/instances/{id}", s.authed(s.getWorkflowInstance))
	s.mux.Handle("POST /v1/workflow/instances/{id}/approve", s.authed(s.decideWorkflow(true)))
	s.mux.Handle("POST /v1/workflow/instances/{id}/reject", s.authed(s.decideWorkflow(false)))
	s.mux.Handle("POST /v1/workflow/instances/{id}/cancel", s.authed(s.cancelWorkflow))
	s.mux.Handle("GET /v1/workflow/tasks", s.authed(s.workflowTasks))
	s.mux.Handle("GET /v1/workflow/metrics", s.authed(s.workflowMetrics))
	s.mux.Handle("POST /v1/identity/sessions/revoke", s.authed(s.revokeSessions))
	s.mux.Handle("POST /v1/identity/logout", s.authed(s.logout))
	s.registerP2P()
	s.registerAR()
	// Operations console: static assets only; it has no authority of its own.
	s.mux.Handle("GET /console/", webui.Handler())
	s.mux.Handle("GET /{$}", http.RedirectHandler("/console/", http.StatusFound))
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
	// W3C Trace Context: continue the caller's trace or start one; the
	// trace id is on every log line and echoed so a proxy or OpenTelemetry
	// collector can correlate.
	traceID, _, ok := obs.ParseTraceparent(r.Header.Get("traceparent"))
	if !ok {
		traceID = obs.NewTraceID()
	}
	h.Set("traceparent", obs.Traceparent(traceID, obs.NewSpanID()))
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	holder := &principalHolder{}
	ctx, cancel := context.WithTimeout(kernel.WithRequestID(context.WithValue(r.Context(), holderKey, holder), rid), requestTimeout)
	defer cancel()
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	req := r.WithContext(ctx)
	s.mux.ServeHTTP(rec, req)
	route := req.Pattern // set by ServeMux on match; bounded cardinality
	if route == "" {
		route = "unmatched"
	}
	elapsed := time.Since(start)
	s.m.requests.Inc(route, r.Method, strconv.Itoa(rec.status))
	s.m.latency.Observe(elapsed.Seconds(), route)
	attrs := []any{"rid", rid, "trace_id", traceID, "method", r.Method, "route", route, "status", rec.status, "ms", elapsed.Milliseconds()}
	if holder.p != nil {
		attrs = append(attrs, "tenant", holder.p.TenantID, "sub", holder.p.UserID)
	}
	s.cfg.Logger.Info("http", attrs...)
}

// principalHolder lets the outer middleware log who acted without parsing
// the token twice.
type principalHolder struct{ p *auth.Principal }

const holderKey ctxKey = 2

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

// authed applies pre-authentication abuse controls, verifies the bearer
// token, applies the per-principal budget and injects the principal.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, s.cfg.Abuse.TrustedProxies).String()
		// SC-13: everything below happens before any token parsing.
		if s.authFail.blocked(ip) {
			w.Header().Set("Retry-After", "300")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many failed authentication attempts")
			return
		}
		if !s.preauth.hit(ip) {
			s.cfg.Logger.Warn("security", "event", "preauth_rate_limited", "ip", ip)
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "request budget exceeded")
			return
		}
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
		default:
			w.Header().Set("Retry-After", "5")
			writeErr(w, http.StatusServiceUnavailable, "overloaded", "server busy")
			return
		}
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") || len(hdr) > 8192 {
			s.authFailure(ip, "missing_or_oversized")
			w.Header().Set("WWW-Authenticate", `Bearer realm="serk"`)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "bearer token required")
			return
		}
		p, err := s.cfg.Verifier.Verify(strings.TrimPrefix(hdr, "Bearer "), time.Now())
		if err != nil {
			s.authFailure(ip, "invalid_token")
			w.Header().Set("WWW-Authenticate", `Bearer realm="serk", error="invalid_token"`)
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "invalid token")
			return
		}
		// GATEA-07: shared revocation list, consulted on every request so a
		// revocation is effective on all replicas at once. Fail closed.
		if s.cfg.Kernel != nil {
			if err := s.cfg.Kernel.CheckSession(r.Context(), p); err != nil {
				if errors.Is(err, kernel.ErrSessionRevoked) {
					s.m.revoked.Inc()
					s.cfg.Logger.Warn("security", "event", "revoked_session_used", "tenant", p.TenantID, "sub", p.UserID)
					w.Header().Set("WWW-Authenticate", `Bearer realm="serk", error="invalid_token", error_description="session revoked"`)
					writeErr(w, http.StatusUnauthorized, "session_revoked", "session revoked; authenticate again")
					return
				}
				s.m.sessionErr.Inc()
				s.cfg.Logger.Error("security", "event", "session_check_failed", "err", err)
				w.Header().Set("Retry-After", "5")
				writeErr(w, http.StatusServiceUnavailable, "unavailable", "session verification unavailable")
				return
			}
		}
		if !s.principal.hit(p.TenantID + "/" + p.UserID) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "command budget exceeded")
			return
		}
		if hd, ok := r.Context().Value(holderKey).(*principalHolder); ok {
			pp := p
			hd.p = &pp
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
	if !canonicalUUID(id) {
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
	if !canonicalUUID(id) {
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
	if !canonicalUUID(id) {
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
	case errors.Is(err, kernel.ErrSessionRevoked):
		writeErr(w, http.StatusUnauthorized, "session_revoked", "session revoked; authenticate again")
	case errors.Is(err, kernel.ErrBudgetExceeded):
		writeErr(w, http.StatusConflict, "budget_exceeded", err.Error())
	case errors.Is(err, postgres.ErrUnknownDocType):
		writeErr(w, http.StatusNotFound, "not_found", "unknown document type")
	case errors.Is(err, kernel.ErrInvalidInput):
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
	case errors.Is(err, auth.ErrUnauthenticated):
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
	case errors.Is(err, kernel.ErrWorkflowRequired):
		writeErr(w, http.StatusConflict, "workflow_required", err.Error())
	case errors.Is(err, kernel.ErrSubjectChanged):
		writeErr(w, http.StatusConflict, "subject_changed", err.Error())
	case errors.Is(err, kernel.ErrWorkflowState):
		writeErr(w, http.StatusConflict, "invalid_state", uuidRe.ReplaceAllString(err.Error(), "<id>"))
	case errors.Is(err, workflow.ErrInvalid), errors.Is(err, workflow.ErrConditionCurrency):
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
	case errors.Is(err, auth.ErrSoD):
		writeErr(w, http.StatusConflict, "segregation_of_duties", err.Error())
	case errors.Is(err, auth.ErrForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "insufficient permission")
	case errors.Is(err, postgres.ErrIdempotencyConflict):
		writeErr(w, http.StatusConflict, "idempotency_conflict", "idempotency key already used with a different command")
	case errors.Is(err, postgres.ErrVersionConflict):
		writeErr(w, http.StatusConflict, "version_conflict", "the record was modified concurrently; reload and retry")
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
		if msg := err.Error(); strings.Contains(msg, "attestation") || strings.Contains(msg, "approval record") {
			s.m.refusals.Inc("attestation")
		} else if strings.Contains(msg, "privilege:") {
			s.m.refusals.Inc("privilege")
		}
		// Database-level refusal (balance, period, immutability). Only the
		// trigger's reason survives; identifiers are stripped from the message.
		writeErr(w, http.StatusConflict, "invariant_violation", "the database refused the change: "+trimPG(err))
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "timeout", "request timed out")
	default:
		s.m.internal.Inc()
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

// authFailure counts an invalid credential and logs a security event without
// any token material.
func (s *Server) authFailure(ip, reason string) {
	s.m.authFail.Inc(reason)
	s.authFail.hit(ip)
	if s.authFail.blocked(ip) {
		s.cfg.Logger.Warn("security", "event", "auth_lockout", "ip", ip, "reason", reason)
		return
	}
	s.cfg.Logger.Info("security", "event", "auth_failure", "ip", ip, "reason", reason)
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

// revokeSessions kills every token of a subject issued up to now (termination,
// role removal, suspected compromise, or "log out everywhere" for oneself).
func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Subject string `json:"subject"`
		Reason  string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return
	}
	cutoff, err := s.cfg.Kernel.RevokeSessions(r.Context(), principalFrom(r.Context()), body.Subject, body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subject": body.Subject, "revoked_before": cutoff.UTC().Format(time.RFC3339Nano)})
}

// logout revokes exactly the presented token (its jti).
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Kernel.Logout(r.Context(), principalFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
