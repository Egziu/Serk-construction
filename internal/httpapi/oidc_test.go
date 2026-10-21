package httpapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type idp struct {
	mu   sync.Mutex
	keys []map[string]string
	srv  *httptest.Server
	hits int
}

func newIDP(t *testing.T) *idp {
	i := &idp{}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.hits++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": i.keys})
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (i *idp) addRSA(kid string, k *rsa.PrivateKey) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append(i.keys, map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())})
}

func (i *idp) addEC(kid string, k *ecdsa.PrivateKey) {
	i.mu.Lock()
	defer i.mu.Unlock()
	pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
	i.keys = append(i.keys, map[string]string{"kty": "EC", "kid": kid, "crv": "P-256", "x": enc(pad(k.X.Bytes())), "y": enc(pad(k.Y.Bytes()))})
}

func signJWT(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	body := enc(h) + "." + enc(p)
	d := sha256.Sum256([]byte(body))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(body))
		sig = m.Sum(nil)
	case nil:
		sig = nil
	}
	return body + "." + enc(sig)
}

func stdClaims(now time.Time) map[string]any {
	return map[string]any{"iss": "https://id.serk.test/realms/serk", "aud": "serk-construction", "sub": "user-1", "tid": "tenant-1",
		"roles": []string{"accountant"}, "projects": []string{"p1"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"amr": []string{"pwd", "otp"}, "auth_time": now.Unix()}
}

func TestJWKSVerifier(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p := newIDP(t)
	p.addRSA("rsa-1", rsaKey)
	p.addEC("ec-1", ecKey)
	p.addRSA("weak", weak)
	v := &JWKSVerifier{Issuer: "https://id.serk.test/realms/serk", Audience: "serk-construction", JWKSURL: p.srv.URL}
	now := time.Now()

	pr, err := v.Verify(signJWT(t, "RS256", "rsa-1", rsaKey, stdClaims(now)), now)
	if err != nil || pr.UserID != "user-1" || pr.TenantID != "tenant-1" || !pr.MFA || len(pr.ProjectIDs) != 1 {
		t.Fatalf("RS256: %+v %v", pr, err)
	}
	if _, err := v.Verify(signJWT(t, "ES256", "ec-1", ecKey, stdClaims(now)), now); err != nil {
		t.Fatalf("ES256: %v", err)
	}
	arr := stdClaims(now)
	arr["aud"] = []string{"other", "serk-construction"}
	if _, err := v.Verify(signJWT(t, "RS256", "rsa-1", rsaKey, arr), now); err != nil {
		t.Fatalf("aud array: %v", err)
	}

	bad := map[string]string{}
	c := stdClaims(now)
	c["iss"] = "https://evil"
	bad["wrong issuer"] = signJWT(t, "RS256", "rsa-1", rsaKey, c)
	c = stdClaims(now)
	c["aud"] = "other-app"
	bad["wrong audience"] = signJWT(t, "RS256", "rsa-1", rsaKey, c)
	c = stdClaims(now)
	c["exp"] = now.Add(-time.Minute).Unix()
	bad["expired"] = signJWT(t, "RS256", "rsa-1", rsaKey, c)
	c = stdClaims(now)
	delete(c, "tid")
	bad["no tenant"] = signJWT(t, "RS256", "rsa-1", rsaKey, c)
	bad["alg none"] = signJWT(t, "none", "rsa-1", nil, stdClaims(now))
	// Key confusion: HS256 "signed" with the RSA public modulus as the secret.
	bad["HS256 key confusion"] = signJWT(t, "HS256", "rsa-1", rsaKey.N.Bytes(), stdClaims(now))
	bad["RS256 header on EC key"] = signJWT(t, "RS256", "ec-1", rsaKey, stdClaims(now))
	bad["weak 1024-bit key ignored"] = signJWT(t, "RS256", "weak", weak, stdClaims(now))
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad["signed by unknown key, known kid"] = signJWT(t, "RS256", "rsa-1", other, stdClaims(now))
	good := signJWT(t, "RS256", "rsa-1", rsaKey, stdClaims(now))
	parts := []byte(good)
	parts[len(parts)/2] ^= 0x01
	bad["tampered"] = string(parts)
	for name, tok := range bad {
		if _, err := v.Verify(tok, now); err == nil {
			t.Errorf("accepted: %s", name)
		}
	}

	// Rotation: a new kid triggers one refresh (rate-limited) and then verifies.
	rotated, _ := rsa.GenerateKey(rand.Reader, 2048)
	p.addRSA("rsa-2", rotated)
	v.mu.Lock()
	v.lastAttempt = time.Time{}
	v.mu.Unlock()
	if _, err := v.Verify(signJWT(t, "RS256", "rsa-2", rotated, stdClaims(now)), now); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	hits := p.hits
	for i := 0; i < 20; i++ { // unknown kids must not hammer the IdP
		_, _ = v.Verify(signJWT(t, "RS256", "nope", rotated, stdClaims(now)), now)
	}
	if p.hits > hits+1 {
		t.Fatalf("JWKS refresh not rate limited: %d fetches", p.hits-hits)
	}
}
