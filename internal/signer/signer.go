// Package signer is the isolated approval signer (R-SIGNER). It runs as its
// own process (cmd/serk-signer) with its own secret, reachable from the API
// only over a unix socket. It signs an approval attestation only when the
// person's own bearer token, which the API forwards, supports every claim:
//
//   - the token verifies against the same identity provider the API uses;
//   - tenant and actor are the token's;
//   - MFA is claimed only if the token carries a fresh multi-factor login;
//   - the permissions are exactly what the token's roles grant (plus the
//     platform marker principal.human for a human principal);
//   - a decision (non-draft action) is signed only for a human principal.
//
// What this closes: a compromised API process or a leaked API configuration
// can no longer sign approvals for arbitrary actors. What it does not close:
// while a person is logged in, a compromised API can still obtain signatures
// in that person's name for the lifetime of their token (the signer cannot
// tell a forwarded request from a genuine one). Every issuance is logged
// here, outside the API, so such abuse is at least visible. Whoever controls
// this process or its secret still controls approvals; the secret belongs in
// an HSM/KMS, which Keyring abstracts and is not available here.
package signer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/serk-group/serk-construction/internal/obs"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// TokenVerifier is satisfied by httpapi.HS256Verifier and httpapi.JWKSVerifier.
type TokenVerifier interface {
	Verify(token string, now time.Time) (auth.Principal, error)
}

// Keyring produces signatures. FileKeyring holds the secret in memory
// (loaded from a file or secret store); an HSM/KMS implementation would
// never expose the secret to this process at all.
type Keyring interface {
	KeyID() string
	// Sign returns the hex HMAC-SHA256 of canonical under the tenant's key.
	Sign(tenant, canonical string) (string, error)
}

// FileKeyring derives per-tenant keys from a master secret held in memory.
type FileKeyring struct {
	Master []byte
	ID     string
}

func (k FileKeyring) KeyID() string {
	if k.ID == "" {
		return "v1"
	}
	return k.ID
}

func (k FileKeyring) Sign(tenant, canonical string) (string, error) {
	if len(k.Master) < 32 {
		return "", errors.New("signer: master secret must be at least 32 bytes")
	}
	m := hmac.New(sha256.New, attest.TenantKey(k.Master, tenant))
	m.Write([]byte(canonical))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// Config of the signer service.
type Config struct {
	Verifier TokenVerifier
	Keyring  Keyring
	Authz    *auth.Authorizer
	Logger   *slog.Logger
	Metrics  *obs.Registry
	// PerActorPerMinute bounds issuances per (tenant, actor); default 120.
	PerActorPerMinute int
	TTL               time.Duration
	Now               func() time.Time
}

// Server handles POST /v1/sign.
type Server struct {
	cfg     Config
	mu      sync.Mutex
	windows map[string]*window
	issued  *obs.CounterVec
	refused *obs.CounterVec
}

type window struct {
	n   int
	end time.Time
}

// New builds the handler.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = obs.NewRegistry()
	}
	if cfg.PerActorPerMinute <= 0 {
		cfg.PerActorPerMinute = 120
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Authz == nil {
		cfg.Authz = auth.NewAuthorizer(nil, true)
	}
	return &Server{cfg: cfg, windows: map[string]*window{},
		issued:  cfg.Metrics.Counter("serk_signer_issued_total", "Approval attestations issued, by draft/decision.", "kind"),
		refused: cfg.Metrics.Counter("serk_signer_refusals_total", "Sign requests refused, by reason.", "reason")}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/sign" {
		s.reply(w, http.StatusNotFound, "", "not found")
		return
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") || len(hdr) > 8192 {
		s.refuse(w, http.StatusUnauthorized, "no_token", "bearer token required")
		return
	}
	now := s.cfg.Now()
	p, err := s.cfg.Verifier.Verify(strings.TrimPrefix(hdr, "Bearer "), now)
	if err != nil {
		s.refuse(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	var req attest.SignRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		s.refuse(w, http.StatusBadRequest, "malformed", "malformed request")
		return
	}
	a, reason, err := s.issue(p, req.Claims, now)
	if err != nil {
		s.cfg.Logger.Warn("signer", "event", "refused", "reason", reason, "tenant", p.TenantID, "sub", p.UserID,
			"actor_claimed", req.Claims.Actor, "action", req.Claims.Action, "err", err.Error())
		s.refuse(w, http.StatusForbidden, reason, err.Error())
		return
	}
	kind := "decision"
	if auth.IsDraftAction(a.Action) {
		kind = "draft"
	}
	s.issued.Inc(kind)
	// The issuance log is the independent record of every approval signed.
	s.cfg.Logger.Info("signer", "event", "issued", "tenant", a.Tenant, "actor", a.Actor, "action", a.Action,
		"subject_type", a.SubjectType, "subject_id", a.SubjectID, "ctx", a.Context, "mfa", a.MFA, "kid", a.KeyID, "nonce", a.Nonce, "exp", a.ExpiresAt)
	writeJSON(w, http.StatusOK, attest.SignResponse{Attestation: &a})
}

func (s *Server) refuse(w http.ResponseWriter, code int, reason, msg string) {
	s.refused.Inc(reason)
	s.reply(w, code, reason, msg)
}

func (s *Server) reply(w http.ResponseWriter, code int, reason, msg string) {
	if reason != "" {
		msg = reason + ": " + msg
	}
	writeJSON(w, code, attest.SignResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// issue checks the claims against the verified principal and signs them.
func (s *Server) issue(p auth.Principal, c attest.Claims, now time.Time) (attest.Attestation, string, error) {
	if c.Tenant != p.TenantID || c.Actor != p.UserID {
		return attest.Attestation{}, "actor_mismatch", fmt.Errorf("the claims name another tenant or actor than the token")
	}
	if c.Action == "" || c.SubjectType == "" || c.SubjectID == "" || c.SubjectHash == "" ||
		len(c.Action) > 100 || len(c.SubjectType) > 60 || len(c.SubjectID) > 200 || len(c.SubjectHash) > 200 || len(c.Context) > 400 {
		return attest.Attestation{}, "malformed", fmt.Errorf("incomplete or oversized claims")
	}
	if p.Kind != auth.KindHuman && !auth.IsDraftAction(c.Action) {
		return attest.Attestation{}, "not_human", fmt.Errorf("%s is a decision reserved to human principals", c.Action)
	}
	var authTime int64
	if !p.AuthTime.IsZero() {
		authTime = p.AuthTime.Unix()
	}
	if c.AuthTime != authTime {
		return attest.Attestation{}, "auth_time", fmt.Errorf("auth_time does not match the token")
	}
	if c.MFA && !(p.MFA && authTime > 0) {
		return attest.Attestation{}, "mfa", fmt.Errorf("the token carries no multi-factor login")
	}
	// Permissions: exactly those the token's roles grant, plus the platform
	// marker for a human principal; nothing a role cannot grant.
	allowed := map[string]bool{}
	for _, perm := range s.cfg.Authz.Permissions(p) {
		allowed[string(perm)] = true
	}
	if p.Kind == auth.KindHuman {
		allowed[auth.ReservedPermissionPrefix+"human"] = true
	}
	// Scope and session markers (R10-F1/F2): the project markers and the
	// tenant-scope marker must be ones the token grants; the session and iat
	// markers must be exactly the token's (the database checks revocation
	// against them, so a forged or blank session would evade a logout).
	markers, err := s.cfg.Authz.ScopeMarkers(p)
	if err != nil {
		return attest.Attestation{}, "malformed", err
	}
	want := map[string]bool{}
	for _, m := range markers {
		allowed[m] = true
		if strings.HasPrefix(m, auth.ReservedPermissionPrefix+"session:") || strings.HasPrefix(m, auth.ReservedPermissionPrefix+"iat:") {
			want[m] = true
		}
	}
	for _, perm := range c.Perms {
		if !allowed[perm] {
			return attest.Attestation{}, "permission", fmt.Errorf("permission %q is not granted by the token", perm)
		}
		delete(want, perm)
	}
	if len(want) > 0 {
		return attest.Attestation{}, "session", fmt.Errorf("the claims do not carry the token's session and issue time")
	}
	if !s.allow(p.TenantID+"/"+p.UserID, now) {
		return attest.Attestation{}, "rate_limited", fmt.Errorf("issuance rate exceeded for this actor")
	}
	ttl := s.cfg.TTL
	if ttl <= 0 || ttl > attest.MaxTTL {
		ttl = 2 * time.Minute
	}
	perms := append([]string(nil), c.Perms...)
	sort.Strings(perms)
	if perms == nil {
		perms = []string{}
	}
	t := now.UTC()
	c.V, c.KeyID, c.Perms = attest.Version, s.cfg.Keyring.KeyID(), perms
	c.IssuedAt, c.ExpiresAt, c.Nonce = t.Unix(), t.Add(ttl).Unix(), uuid.NewString()
	if strings.ContainsRune(c.Tenant+c.Actor+c.Action+c.SubjectType+c.SubjectID+c.SubjectHash+c.Context+strings.Join(perms, ""), '\x1f') {
		return attest.Attestation{}, "malformed", fmt.Errorf("separator in a field")
	}
	sig, err := s.cfg.Keyring.Sign(c.Tenant, c.Canonical())
	if err != nil {
		return attest.Attestation{}, "keyring", err
	}
	return attest.Attestation{Claims: c, Sig: sig}, "", nil
}

func (s *Server) allow(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.windows[key]
	if w == nil || now.After(w.end) {
		if len(s.windows) > 50_000 {
			for k, x := range s.windows {
				if now.After(x.end) {
					delete(s.windows, k)
				}
			}
		}
		w = &window{end: now.Add(time.Minute)}
		s.windows[key] = w
	}
	w.n++
	return w.n <= s.cfg.PerActorPerMinute
}

// Listen serves on a unix socket with mode 0660 until ctx is cancelled.
func Listen(ctx context.Context, socket string, h http.Handler, log *slog.Logger) error {
	return listenUnix(ctx, socket, h, log)
}
