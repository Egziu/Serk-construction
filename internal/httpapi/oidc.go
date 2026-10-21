package httpapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/serk-group/serk-construction/pkg/auth"
)

// JWKSVerifier verifies OIDC access tokens signed by an external identity
// provider (Keycloak, Entra ID, Okta, Auth0, ...) with RS256 or ES256 keys
// published at a JWKS endpoint. Only the standard library is used.
//
// Security properties: algorithm allow-list (no "none", no HMAC — prevents
// key-confusion), kid-pinned key lookup, key type/curve/size checks, issuer
// and audience checks, exp/nbf/iat/auth_time with 60 s skew, rate-limited
// JWKS refresh on unknown kid (key rotation without restart).
type JWKSVerifier struct {
	Issuer   string
	Audience string
	JWKSURL  string
	// Claim names (defaults: tid, roles, projects).
	TenantClaim, RolesClaim, ProjectsClaim string
	Client                                 *http.Client

	mu          sync.RWMutex
	keys        map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

var (
	errAlg     = errors.New("token: algorithm not allowed")
	errUnknown = errors.New("token: unknown signing key")
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseJWK(k jwk) (any, error) {
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("key %s not for signatures", k.Kid)
	}
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64(k.E)
		if err != nil {
			return nil, err
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			return nil, fmt.Errorf("rsa key %s too weak", k.Kid)
		}
		return pub, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %s", k.Crv)
		}
		x, err := b64(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("ec key %s not on curve", k.Kid)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %s", k.Kty)
}

// Refresh fetches the JWKS document.
func (v *JWKSVerifier) Refresh(ctx context.Context) error {
	c := v.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]any{}
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		if pub, err := parseJWK(k); err == nil {
			keys[k.Kid] = pub
		}
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable signing keys")
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, time.Now()
	v.mu.Unlock()
	return nil
}

func (v *JWKSVerifier) key(kid string) (any, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := time.Since(v.fetchedAt) > time.Hour
	v.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	// Unknown kid (rotation) or stale set: refresh, at most once a minute.
	v.mu.Lock()
	canTry := time.Since(v.lastAttempt) > time.Minute
	if canTry {
		v.lastAttempt = time.Now()
	}
	v.mu.Unlock()
	if canTry {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = v.Refresh(ctx)
		cancel()
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errUnknown
}

// Verify implements TokenVerifier.
func (v *JWKSVerifier) Verify(token string, now time.Time) (auth.Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return auth.Principal{}, errMalformed
	}
	hb, err := b64(parts[0])
	if err != nil {
		return auth.Principal{}, errMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return auth.Principal{}, errMalformed
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return auth.Principal{}, errAlg
	}
	key, err := v.key(hdr.Kid)
	if err != nil {
		return auth.Principal{}, err
	}
	sig, err := b64(parts[2])
	if err != nil {
		return auth.Principal{}, errMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
			return auth.Principal{}, errSignature
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return auth.Principal{}, errSignature
		}
	default:
		return auth.Principal{}, errAlg
	}
	pb, err := b64(parts[1])
	if err != nil {
		return auth.Principal{}, errMalformed
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pb, &raw); err != nil {
		return auth.Principal{}, errMalformed
	}
	var c Claims
	_ = json.Unmarshal(pb, &c) // standard claims (sub, iss, exp, iat, nbf, amr, auth_time)
	str := func(name string) string {
		var s string
		_ = json.Unmarshal(raw[name], &s)
		return s
	}
	strs := func(name string) []string {
		var s []string
		_ = json.Unmarshal(raw[name], &s)
		return s
	}
	tenantClaim, rolesClaim, projClaim := v.TenantClaim, v.RolesClaim, v.ProjectsClaim
	if tenantClaim == "" {
		tenantClaim = "tid"
	}
	if rolesClaim == "" {
		rolesClaim = "roles"
	}
	if projClaim == "" {
		projClaim = "projects"
	}
	c.TenantID, c.Roles, c.Projects = str(tenantClaim), strs(rolesClaim), strs(projClaim)
	// aud may be a string or an array (RFC 7519 §4.1.3).
	audOK := str("aud") == v.Audience
	for _, a := range strs("aud") {
		audOK = audOK || a == v.Audience
	}
	if err := c.validTimes(now); err != nil {
		return auth.Principal{}, err
	}
	if c.Issuer != v.Issuer || !audOK || c.Subject == "" || c.TenantID == "" {
		return auth.Principal{}, errClaims
	}
	return c.principal(), nil
}
