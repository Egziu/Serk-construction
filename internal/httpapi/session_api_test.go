package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func (e *env) tokenAt(user, jti string, iat time.Time, roles ...string) string {
	tok, err := testVerifier.Sign(Claims{Subject: user, TenantID: e.tenant, Roles: roles, IssuedAt: iat.Unix(), ExpiresAt: iat.Add(time.Hour).Unix(),
		Issuer: "serk-id", Audience: "serk-construction", TokenID: jti})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

// GATEA-07: revoking a subject on one replica is effective on every replica at
// the next request; logout kills exactly one token; re-authentication works.
func TestAPISessionRevocationAcrossReplicas(t *testing.T) {
	e := newEnv(t)
	// A second, independent API replica on the same database.
	replicaB := httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: 50}))
	t.Cleanup(replicaB.Close)
	onB := func(tok string) int {
		req, _ := http.NewRequest(http.MethodGet, replicaB.URL+"/v1/workflow/tasks", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	past := time.Now().Add(-5 * time.Minute)
	victim := e.tokenAt("u-leaver", "jti-leaver-1", past, "finance_manager")
	admin := e.tokenAt("u-secadmin", "jti-admin", past, "security_admin")
	if code, _ := e.do("GET", "/v1/workflow/tasks", victim, nil); code != 200 {
		t.Fatalf("baseline on A: %d", code)
	}
	if code := onB(victim); code != 200 {
		t.Fatalf("baseline on B: %d", code)
	}
	// Only identity.revoke_sessions may revoke others.
	if code, out := e.do("POST", "/v1/identity/sessions/revoke", victim, map[string]any{"subject": "u-secadmin", "reason": "retaliation"}); code != 403 {
		t.Fatalf("non-admin revoked another user: %d %v", code, out)
	}
	if code, out := e.do("POST", "/v1/identity/sessions/revoke", admin, map[string]any{"subject": "u-leaver", "reason": "employment terminated"}); code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	code, out := e.do("GET", "/v1/workflow/tasks", victim, nil)
	if errObj, _ := out["error"].(map[string]any); code != 401 || errObj["code"] != "session_revoked" {
		t.Fatalf("revoked token on A: %d %v", code, out)
	}
	if code := onB(victim); code != 401 {
		t.Fatalf("revoked token still accepted on replica B: %d", code)
	}
	// Re-authentication (a token issued after the cut-off) is accepted.
	again := e.tokenAt("u-leaver", "jti-leaver-2", time.Now().Add(2*time.Second), "finance_manager")
	if code := onB(again); code != 200 {
		t.Fatalf("new token after revocation: %d", code)
	}

	// Logout revokes only the presented token.
	s1 := e.tokenAt("u-user", "jti-s1", past, "accountant")
	s2 := e.tokenAt("u-user", "jti-s2", past, "accountant")
	if code, out := e.do("POST", "/v1/identity/logout", s1, nil); code != 204 {
		t.Fatalf("logout: %d %v", code, out)
	}
	if code := onB(s1); code != 401 {
		t.Fatalf("logged-out token accepted on B: %d", code)
	}
	if code := onB(s2); code != 200 {
		t.Fatalf("other session killed by logout: %d", code)
	}
}
