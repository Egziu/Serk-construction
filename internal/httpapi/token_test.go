package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testVerifier = HS256Verifier{Secret: []byte("0123456789abcdef0123456789abcdef-test-secret"), Issuer: "serk-id", Audience: "serk-construction"}

func claims(now time.Time) Claims {
	return Claims{Subject: "u1", TenantID: "t1", Roles: []string{"accountant"}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction"}
}

func TestTokenRoundTrip(t *testing.T) {
	now := time.Now()
	tok, err := testVerifier.Sign(claims(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := testVerifier.Verify(tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "u1" || p.TenantID != "t1" || len(p.Roles) != 1 {
		t.Fatalf("bad principal %+v", p)
	}
}

func TestTokenRejections(t *testing.T) {
	now := time.Now()
	good, _ := testVerifier.Sign(claims(now))
	parts := strings.Split(good, ".")

	// Tampered payload keeps old signature.
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","tid":"OTHER","roles":["controller"],"iat":1,"exp":9999999999,"iss":"serk-id","aud":"serk-construction"}`)) + "." + parts[2]
	if _, err := testVerifier.Verify(tampered, now); err == nil {
		t.Fatal("tampered token accepted")
	}
	// alg=none attack.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."
	if _, err := testVerifier.Verify(none, now); err == nil {
		t.Fatal("alg=none accepted")
	}
	// Expired.
	if _, err := testVerifier.Verify(good, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired token accepted")
	}
	// Wrong audience / issuer.
	other := HS256Verifier{Secret: testVerifier.Secret, Issuer: "serk-id", Audience: "other-app"}
	if _, err := other.Verify(good, now); err == nil {
		t.Fatal("wrong audience accepted")
	}
	// Different key.
	wrongKey := HS256Verifier{Secret: []byte("ffffffffffffffffffffffffffffffffffffffff"), Issuer: "serk-id", Audience: "serk-construction"}
	if _, err := wrongKey.Verify(good, now); err == nil {
		t.Fatal("foreign signature accepted")
	}
	// Weak secret refused on both sides.
	weak := HS256Verifier{Secret: []byte("short"), Issuer: "x", Audience: "y"}
	if _, err := weak.Sign(claims(now)); err == nil {
		t.Fatal("weak secret signed")
	}
	if _, err := weak.Verify(good, now); err == nil {
		t.Fatal("weak secret verified")
	}
	if _, err := testVerifier.Verify("a.b", now); err == nil {
		t.Fatal("malformed accepted")
	}
}

func TestIsMFA(t *testing.T) {
	cases := map[string]struct {
		amr  []string
		want bool
	}{
		"explicit mfa":               {[]string{"mfa"}, true},
		"pwd+otp":                    {[]string{"pwd", "otp"}, true},
		"pwd+hwk":                    {[]string{"pwd", "hwk"}, true},
		"pwd+pin (both knowledge)":   {[]string{"pwd", "pin"}, false},
		"otp+sms (both possession)":  {[]string{"otp", "sms"}, false},
		"pwd only":                   {[]string{"pwd"}, false},
		"pwd+geo (geo not a factor)": {[]string{"pwd", "geo"}, false},
		"none":                       {nil, false},
	}
	for name, c := range cases {
		if got := IsMFA(c.amr); got != c.want {
			t.Errorf("%s: IsMFA(%v)=%v want %v", name, c.amr, got, c.want)
		}
	}
}

func TestTokenTimeClaims(t *testing.T) {
	now := time.Now()
	c := claims(now)
	c.NotBefore = now.Add(10 * time.Minute).Unix()
	tok, _ := testVerifier.Sign(c)
	if _, err := testVerifier.Verify(tok, now); err == nil {
		t.Fatal("token used before nbf")
	}
	c = claims(now)
	c.AMR, c.AuthTime = []string{"pwd", "otp"}, now.Add(-time.Minute).Unix()
	tok, _ = testVerifier.Sign(c)
	p, err := testVerifier.Verify(tok, now)
	if err != nil || !p.MFA || p.AuthTime.IsZero() {
		t.Fatalf("mfa claims not mapped: %+v %v", p, err)
	}
	c.AuthTime = now.Add(time.Hour).Unix()
	tok, _ = testVerifier.Sign(c)
	if _, err := testVerifier.Verify(tok, now); err == nil {
		t.Fatal("future auth_time accepted")
	}
}

func TestClientIPAndLimiter(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:4000", "1.2.3.4", "203.0.113.9"},             // untrusted peer: header ignored (spoof)
		{"10.0.0.5:4000", "198.51.100.7", "198.51.100.7"},          // trusted proxy
		{"10.0.0.5:4000", "6.6.6.6, 198.51.100.7", "198.51.100.7"}, // right-most untrusted hop
		{"10.0.0.5:4000", "198.51.100.7, 10.0.0.9", "198.51.100.7"},
		{"10.0.0.5:4000", "garbage", "10.0.0.5"},
	}
	for _, c := range cases {
		if got := clientIP(mk(c.remote, c.xff), trusted).String(); got != c.want {
			t.Errorf("clientIP(%s, %q)=%s want %s", c.remote, c.xff, got, c.want)
		}
	}
	now := time.Unix(1_700_000_000, 0)
	l := newWindowLimiter(3, time.Minute, 5*time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.hit("ip") {
			t.Fatal("under limit refused")
		}
	}
	if l.hit("ip") || !l.blocked("ip") {
		t.Fatal("lockout not started")
	}
	now = now.Add(2 * time.Minute) // new window, still locked
	if l.hit("ip") {
		t.Fatal("lockout ignored in next window")
	}
	now = now.Add(5 * time.Minute)
	if !l.hit("ip") {
		t.Fatal("lockout never expired")
	}
	if !l.hit("other") {
		t.Fatal("keys not independent")
	}
}
