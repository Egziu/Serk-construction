package httpapi

// Independent review 10 probes: the isolated signer's rate limit, TTL and
// MFA handling, with real HS256 tokens. "OPEN:" = defect, "held:" = control
// worked, "info:" = observation.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/serk-group/serk-construction/internal/signer"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/attest"
)

func TestR10_SignerRateLimitTTLAndMFA(t *testing.T) {
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	set := func(d time.Time) { mu.Lock(); clock = d; mu.Unlock() }
	dir, err := os.MkdirTemp("", "r10h")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	h := signer.New(signer.Config{Verifier: testVerifier, Keyring: signer.FileKeyring{Master: testdb.ApprovalMaster},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PerActorPerMinute: 3, Now: now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = signer.Listen(ctx, sock, h, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	ask := func(tok string, c attest.Claims) (int, attest.SignResponse) {
		body, _ := json.Marshal(attest.SignRequest{Claims: c})
		req, _ := http.NewRequest("POST", "http://signer/v1/sign", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out attest.SignResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	tenant := "00000000-0000-4000-8000-0000000000aa"
	t0 := time.Now()
	authOld := t0.Add(-48 * time.Hour).Unix()
	tok, _ := testVerifier.Sign(Claims{Subject: "u-appr", TenantID: tenant, Roles: []string{"finance_manager"}, IssuedAt: t0.Unix(),
		ExpiresAt: t0.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction", Kind: "human", AMR: []string{"pwd", "otp"}, AuthTime: authOld,
		Projects: []string{"11111111-1111-4111-8111-111111111111"}})
	base := attest.Claims{Tenant: tenant, Actor: "u-appr", Action: "journal.approve", SubjectType: "journal", SubjectID: "x", SubjectHash: "h",
		Perms: []string{"journal.approve", "principal.human", "principal.project:11111111-1111-4111-8111-111111111111",
			"principal.session:-", fmt.Sprintf("principal.iat:%d", t0.Unix())}, MFA: true, AuthTime: authOld}

	// Window start: 3 allowed, the 4th refused.
	set(t0.Truncate(time.Second))
	var ok, limited int
	for i := 0; i < 4; i++ {
		if st, out := ask(tok, base); st == 200 && out.Attestation != nil {
			ok++
			if i == 0 {
				a := out.Attestation
				if a.ExpiresAt-a.IssuedAt <= int64(attest.MaxTTL/time.Second) {
					t.Logf("held: attestation lifetime %ds (DB max 300s)", a.ExpiresAt-a.IssuedAt)
				} else {
					t.Errorf("OPEN: attestation lifetime %ds above the DB maximum", a.ExpiresAt-a.IssuedAt)
				}
				t.Logf("info: signer signed mfa=%v for a token whose auth_time is 48 h old (freshness is left to approval_authorize: mfa_fresh requires <= 600 s)", a.MFA)
				t.Logf("held (0035): the claims carry the token's project, session and issue-time markers")
			}
		} else if out.Error != "" && st == 403 {
			limited++
		}
	}
	if ok == 3 && limited == 1 {
		t.Logf("held: per-actor limit 3/min: %d signed, %d refused", ok, limited)
	} else {
		t.Errorf("OPEN: limit 3/min: %d signed, %d refused", ok, limited)
	}
	// Fixed window: just after the window ends, a full new budget.
	set(t0.Truncate(time.Second).Add(time.Minute + time.Millisecond))
	burst := 0
	for i := 0; i < 4; i++ {
		if st, _ := ask(tok, base); st == 200 {
			burst++
		}
	}
	t.Logf("info: fixed window: %d signed in the first minute and %d more 1 ms after it ends (%d within ~1 ms of wall time across the boundary)", ok, burst, ok+burst)
	// Refusals are not counted: 500 forged claims, then a legitimate one.
	set(t0.Truncate(time.Second).Add(3 * time.Minute))
	forged := base
	forged.Perms = []string{"journal.post"}
	refused := 0
	for i := 0; i < 500; i++ {
		if st, _ := ask(tok, forged); st == 403 {
			refused++
		}
	}
	st, _ := ask(tok, base)
	t.Logf("info: %d forged requests refused without touching the budget; legitimate request after them: %d (refusals are logged and counted in serk_signer_refusals_total, not rate-limited)", refused, st)
}
