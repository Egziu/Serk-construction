package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stagingServer(sl *StagingLogin) *Server {
	return New(Config{Verifier: testVerifier, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Staging: sl})
}

func TestStagingLoginDisabledByDefault(t *testing.T) {
	h := stagingServer(nil)
	for _, r := range []*http.Request{httptest.NewRequest("GET", "/staging/personas", nil),
		httptest.NewRequest("POST", "/staging/token", strings.NewReader(`{}`))} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s without staging login: %d", r.Method, r.URL.Path, w.Code)
		}
	}
}

func TestStagingLoginIssuesPersonaTokens(t *testing.T) {
	const tenant = "5e4c0000-0000-4000-8000-00000000de30"
	h := stagingServer(&StagingLogin{Passphrase: []byte("a-long-staging-passphrase"), Signer: testVerifier, Tenant: tenant, Projects: []string{"p1"}})
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/staging/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"passphrase":"wrong-passphrase-here","persona":"u-cfo"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong passphrase: %d", w.Code)
	}
	if w := post(`{"passphrase":"a-long-staging-passphrase","persona":"u-root"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unknown persona: %d", w.Code)
	}
	for persona, scoped := range map[string]bool{"u-site-engineer": true, "u-cfo": false} {
		w := post(`{"passphrase":"a-long-staging-passphrase","persona":"` + persona + `"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", persona, w.Code, w.Body)
		}
		var out struct{ Token string }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		p, err := testVerifier.Verify(out.Token, time.Now())
		if err != nil {
			t.Fatalf("%s: issued token does not verify: %v", persona, err)
		}
		if p.UserID != persona || p.TenantID != tenant || !p.MFA || p.Kind != "human" || (len(p.ProjectIDs) == 1) != scoped {
			t.Errorf("%s: principal %+v", persona, p)
		}
	}
	// Repeated wrong passphrases lock the client out like failed tokens.
	locked := false
	for i := 0; i < 40 && !locked; i++ {
		locked = post(`{"passphrase":"guess-guess-guess-`+string(rune('a'+i%26))+`","persona":"u-cfo"}`).Code == http.StatusTooManyRequests
	}
	if !locked {
		t.Error("passphrase guessing is not rate limited")
	}
}
