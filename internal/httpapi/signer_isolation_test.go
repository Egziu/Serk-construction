package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/signer"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// R-SIGNER: the API holds no signing secret. Approvals are signed by the
// separate signer, which re-verifies the person's own token.

// startSigner runs the signer on a unix socket and returns the socket path
// and the issuance log.
func startSigner(t *testing.T) (string, *bytes.Buffer) {
	t.Helper()
	dir, err := os.MkdirTemp("", "serk-signer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	var logBuf bytes.Buffer
	h := signer.New(signer.Config{Verifier: testVerifier, Keyring: signer.FileKeyring{Master: testdb.ApprovalMaster},
		Logger: slog.New(slog.NewJSONHandler(&logBuf, nil)), PerActorPerMinute: 1000})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = signer.Listen(ctx, sock, h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return sock, &logBuf
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("signer did not start")
	return "", nil
}

// signerEnv is newEnv with the kernel issuing through the remote signer and
// no master secret in the API process.
func signerEnv(t *testing.T) (*env, string, *bytes.Buffer) {
	t.Helper()
	e := newEnv(t)
	sock, logBuf := startSigner(t)
	e.svc = kernel.New(e.db.Router, auth.NewAuthorizer(nil, true)).UseApprovalSigner(&attest.Remote{Socket: sock})
	e.srv.Close()
	e.srv = httptest.NewServer(New(Config{Verifier: testVerifier, Kernel: e.svc, Store: e.db.Router,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: 1000}))
	t.Cleanup(e.srv.Close)
	return e, sock, logBuf
}

func TestSignerIsolation_JournalLifecycleThroughRemoteSigner(t *testing.T) {
	e, _, logBuf := signerEnv(t)
	prep, appr, post := e.token("u-prep", "accountant"), e.token("u-appr", "finance_manager"), e.token("u-post", "controller")
	code, out := e.do("POST", "/v1/journals", prep, e.journalBody("rs-1", "250.00"))
	if code != 201 && code != 200 {
		t.Fatalf("create through the remote signer: %d %v", code, out)
	}
	jid := out["id"].(string)
	if code, out := e.do("POST", "/v1/journals/"+jid+"/approve", appr, nil); code != 200 {
		t.Fatalf("approve through the remote signer: %d %v", code, out)
	}
	if code, out := e.do("POST", "/v1/journals/"+jid+"/post", post, nil); code != 200 {
		t.Fatalf("post through the remote signer: %d %v", code, out)
	}
	// Every issuance is in the signer's own log, outside the API.
	log := logBuf.String()
	for _, want := range []string{`"event":"issued"`, `"actor":"u-appr"`, `"action":"journal.approve"`, `"actor":"u-post"`, `"action":"journal.post"`} {
		if !strings.Contains(log, want) {
			t.Errorf("signer issuance log lacks %s", want)
		}
	}
}

// A compromised API process (or anyone holding the socket) sends the signer
// claims the token does not support: refused, and logged.
func TestSignerIsolation_CompromisedAPICannotForge(t *testing.T) {
	e, sock, logBuf := signerEnv(t)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	ask := func(token string, c attest.Claims) (int, attest.SignResponse) {
		t.Helper()
		body, _ := json.Marshal(attest.SignRequest{Claims: c})
		req, _ := http.NewRequest("POST", "http://signer/v1/sign", bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out attest.SignResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	acct := e.token("u-prep", "accountant")
	// A token the identity provider did not mark as human (no pkind).
	now0 := time.Now()
	unasserted, _ := testVerifier.Sign(Claims{Subject: "u-prep", TenantID: e.tenant, Roles: []string{"accountant"}, IssuedAt: now0.Unix(),
		ExpiresAt: now0.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction"})
	base := attest.Claims{Tenant: e.tenant, Actor: "u-prep", Action: "journal.create", SubjectType: "journal", SubjectID: "x", SubjectHash: "h",
		Perms: tokenMarkers(t, acct, "journal.create")}
	if st, out := ask(acct, base); st != 200 || out.Attestation == nil {
		t.Fatalf("a legitimate draft claim refused: %d %v", st, out.Error)
	}
	cases := []struct {
		name string
		tok  string
		c    attest.Claims
		want string
	}{
		{"no token", "", base, "no_token"},
		{"another actor", acct, func() attest.Claims { c := base; c.Actor = "u-cfo"; return c }(), "actor_mismatch"},
		{"another tenant", acct, func() attest.Claims { c := base; c.Tenant = "00000000-0000-4000-8000-000000000009"; return c }(), "actor_mismatch"},
		{"permission the roles do not grant", acct, func() attest.Claims {
			c := base
			c.Perms = tokenMarkers(t, acct, "journal.create", "payment.approve")
			return c
		}(), "permission"},
		{"no session markers (0035)", acct, func() attest.Claims { c := base; c.Perms = []string{"journal.create"}; return c }(), "session"},
		{"another session's markers (0035)", acct, func() attest.Claims {
			c := base
			c.Perms = []string{"journal.create", "principal.scope:tenant", "principal.session:-", "principal.iat:1"}
			return c
		}(), "permission"},
		{"a project the token does not list (0035)", acct, func() attest.Claims {
			c := base
			c.Perms = append(tokenMarkers(t, acct, "journal.create"), "principal.project:11111111-1111-4111-8111-111111111111")
			return c
		}(), "permission"},
		{"platform marker for an unasserted principal", unasserted, func() attest.Claims { c := base; c.Perms = []string{"principal.human"}; return c }(), "permission"},
		{"a decision by an unasserted token", unasserted, func() attest.Claims { c := base; c.Action = "journal.approve"; return c }(), "not_human"},
		{"a decision by an AI token", func() string {
			t, _ := testVerifier.Sign(Claims{Subject: "u-prep", TenantID: e.tenant, Roles: []string{"accountant"}, IssuedAt: now0.Unix(),
				ExpiresAt: now0.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", Kind: "ai"})
			return t
		}(), func() attest.Claims { c := base; c.Action = "journal.approve"; return c }(), "not_human"},
		{"MFA claimed without MFA", acct, func() attest.Claims { c := base; c.MFA = true; return c }(), "mfa"},
		{"auth_time invented", acct, func() attest.Claims { c := base; c.AuthTime = time.Now().Unix(); return c }(), "auth_time"},
		{"oversized context", acct, func() attest.Claims { c := base; c.Context = strings.Repeat("x", 500); return c }(), "malformed"},
	}
	for _, tc := range cases {
		st, out := ask(tc.tok, tc.c)
		if st == 200 || out.Attestation != nil || !strings.HasPrefix(out.Error, tc.want) {
			t.Errorf("%s: %d %q (want refusal %s)", tc.name, st, out.Error, tc.want)
		}
	}
	// A human token with MFA signs a decision; its perms must still match.
	now := time.Now()
	human, _ := testVerifier.Sign(Claims{Subject: "u-appr", TenantID: e.tenant, Roles: []string{"finance_manager"}, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", Kind: "human", AMR: []string{"pwd", "otp"}, AuthTime: now.Unix() - 5})
	dec := attest.Claims{Tenant: e.tenant, Actor: "u-appr", Action: "journal.approve", SubjectType: "journal", SubjectID: "x", SubjectHash: "h",
		Perms: tokenMarkers(t, human, "journal.approve", "principal.human"), MFA: true, AuthTime: now.Unix() - 5}
	if st, out := ask(human, dec); st != 200 || out.Attestation == nil || !out.Attestation.MFA {
		t.Errorf("a human MFA decision claim refused: %d %v", st, out.Error)
	}
	if !strings.Contains(logBuf.String(), `"reason":"actor_mismatch"`) {
		t.Errorf("forgery attempts are not in the signer log")
	}
}

// Without a person's credential in the request context (background work,
// or a kernel call made outside a request) the remote signer signs nothing.
func TestSignerIsolation_NoBearerNoSignature(t *testing.T) {
	e, _, _ := signerEnv(t)
	prep := e.token("u-prep", "accountant")
	code, out := e.do("POST", "/v1/journals", prep, e.journalBody("bg-1", "250.00"))
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	p := auth.Principal{Kind: auth.KindHuman, UserID: "u-appr", TenantID: e.tenant, Roles: []string{"finance_manager"}}
	err := e.svc.ApproveJournal(context.Background(), p, out["id"].(string))
	if err == nil || !strings.Contains(err.Error(), "no end-user credential") {
		t.Errorf("a kernel approval without a bearer in context was signed: %v", err)
	}
}

// The API process holds no usable secret: a local Signer with no master
// fails closed.
func TestSignerIsolation_APIWithoutSecretFailsClosed(t *testing.T) {
	if _, err := (attest.Signer{}).Sign(attest.Claims{Tenant: "t", Actor: "a"}); err == nil {
		t.Error("a signer without a master secret signed")
	}
	// A signer that returns altered claims is not trusted for them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req attest.SignRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		c := req.Claims
		c.Perms = append(c.Perms, "payment.approve")
		c.V, c.KeyID, c.Nonce, c.ExpiresAt = 1, "v1", "n", time.Now().Add(time.Minute).Unix()
		_ = json.NewEncoder(w).Encode(attest.SignResponse{Attestation: &attest.Attestation{Claims: c, Sig: "00"}})
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	sock := filepath.Join(dir, "evil.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(ln, srv.Config.Handler) }()
	t.Cleanup(func() { ln.Close() })
	r := &attest.Remote{Socket: sock}
	ctx := attest.WithBearer(context.Background(), "tok")
	if _, err := r.Issue(ctx, attest.Claims{Tenant: "t", Actor: "a", Action: "x", SubjectType: "s", SubjectID: "i", SubjectHash: "h", Perms: []string{"p"}}); err == nil || !strings.Contains(err.Error(), "altered") {
		t.Errorf("widened claims from the signer were accepted: %v", err)
	}
}

// tokenMarkers returns perms plus the scope, session and issue-time markers
// the signer derives from tok (0035): what an honest API sends.
func tokenMarkers(t *testing.T, tok string, perms ...string) []string {
	t.Helper()
	p, err := testVerifier.Verify(tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := auth.NewAuthorizer(nil, true).ScopeMarkers(p)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]string{}, perms...), m...)
}
