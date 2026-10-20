package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// Token verification for the vertical slice: HS256 JWTs issued by the
// SERK identity service with a shared secret. The verifier uses only the
// standard library and constant-time comparison. OIDC federation (RS256/JWKS)
// is the documented next step (see docs/NEXT.md) and plugs in behind the same
// TokenVerifier interface.

// Claims is the verified token payload.
type Claims struct {
	Subject   string   `json:"sub"`
	TenantID  string   `json:"tid"`
	Roles     []string `json:"roles"`
	Projects  []string `json:"projects,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
}

// TokenVerifier turns a bearer token into a principal.
type TokenVerifier interface {
	Verify(token string, now time.Time) (auth.Principal, error)
}

// HS256Verifier verifies HMAC-SHA256 tokens.
type HS256Verifier struct {
	Secret   []byte
	Issuer   string
	Audience string
}

var (
	errMalformed = errors.New("token: malformed")
	errSignature = errors.New("token: bad signature")
	errExpired   = errors.New("token: expired")
	errClaims    = errors.New("token: invalid claims")
)

// Verify checks structure, algorithm, signature, time window, issuer and
// audience, then maps claims to a principal.
func (v HS256Verifier) Verify(token string, now time.Time) (auth.Principal, error) {
	if len(v.Secret) < 32 {
		return auth.Principal{}, errors.New("token: verifier secret must be at least 32 bytes")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return auth.Principal{}, errMalformed
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return auth.Principal{}, errMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil || hdr.Alg != "HS256" {
		return auth.Principal{}, errMalformed // "none" and any other alg are rejected
	}
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || subtle.ConstantTimeCompare(want, got) != 1 {
		return auth.Principal{}, errSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return auth.Principal{}, errMalformed
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return auth.Principal{}, errMalformed
	}
	ts := now.Unix()
	if c.ExpiresAt == 0 || ts >= c.ExpiresAt || c.IssuedAt > ts+60 {
		return auth.Principal{}, errExpired
	}
	if c.Issuer != v.Issuer || c.Audience != v.Audience || c.Subject == "" || c.TenantID == "" {
		return auth.Principal{}, errClaims
	}
	return auth.Principal{UserID: c.Subject, TenantID: c.TenantID, Roles: c.Roles, ProjectIDs: c.Projects}, nil
}

// Sign issues a token; used by tests and the development issuer command.
func (v HS256Verifier) Sign(c Claims) (string, error) {
	if len(v.Secret) < 32 {
		return "", errors.New("token: secret must be at least 32 bytes")
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := hdr + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
