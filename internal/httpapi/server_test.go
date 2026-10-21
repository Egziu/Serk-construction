package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

type env struct {
	t        *testing.T
	srv      *httptest.Server
	tenant   string
	entity   string
	accounts map[string]string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testdb.Setup(t)
	ctx := db.Ctx
	e := &env{t: t, tenant: uuid.NewString(), accounts: map[string]string{}}
	db.ProvisionTenant(t, e.tenant, "api-test")
	err := db.AdminStore.WithTenant(ctx, e.tenant, func(ctx context.Context, tx pgx.Tx) error {
		le, err := postgres.CreateLegalEntity(ctx, tx, e.tenant, "SERK ET", "ET", "ETB", "")
		if err != nil {
			return err
		}
		e.entity = le
		if _, err := postgres.CreateFiscalPeriod(ctx, tx, e.tenant, le, "FY26", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
			return err
		}
		for _, a := range []struct{ code, typ string }{{"1000", "ASSET"}, {"5000", "EXPENSE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: e.tenant, LegalEntityID: le, Code: a.code, Name: a.code, Type: ledger.AccountType(a.typ), Active: true})
			if err != nil {
				return err
			}
			e.accounts[a.code] = id
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := kernel.New(db.Router, auth.NewAuthorizer(nil, true))
	h := New(Config{Verifier: testVerifier, Kernel: svc, Store: db.Router, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RatePerMinute: 50})
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) token(user string, roles ...string) string {
	now := time.Now()
	tok, err := testVerifier.Sign(Claims{Subject: user, TenantID: e.tenant, Roles: roles, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Issuer: "serk-id", Audience: "serk-construction"})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if s, ok := body.(string); ok {
			buf.WriteString(s)
		} else {
			_ = json.NewEncoder(&buf).Encode(body)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) journalBody(key string, credit string) map[string]any {
	return map[string]any{
		"legal_entity_id": e.entity, "functional_currency": "ETB", "business_event_at": "2026-10-15T09:00:00Z",
		"description": "API test", "source_type": "MANUAL", "idempotency_key": key,
		"lines": []map[string]any{
			{"account_id": e.accounts["5000"], "side": "DEBIT", "amount": map[string]string{"amount": "250.00", "currency": "ETB"}},
			{"account_id": e.accounts["1000"], "side": "CREDIT", "amount": map[string]string{"amount": credit, "currency": "ETB"}},
		},
	}
}

func TestAPIFullLifecycle(t *testing.T) {
	e := newEnv(t)
	prep, appr, ctrl := e.token("prep", "accountant"), e.token("appr", "finance_manager"), e.token("ctrl", "controller")

	st, out := e.do("POST", "/v1/journals", prep, e.journalBody("k-"+uuid.NewString(), "250.00"))
	if st != 201 {
		t.Fatalf("create: %d %v", st, out)
	}
	id := out["id"].(string)

	if st, out := e.do("POST", "/v1/journals/"+id+"/post", ctrl, nil); st != 409 || out["error"].(map[string]any)["code"] != "invalid_state" {
		t.Fatalf("post before approve: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/journals/"+id+"/approve", prep, nil); st != 403 {
		t.Fatalf("accountant approve: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/journals/"+id+"/approve", appr, nil); st != 200 || out["status"] != "APPROVED" {
		t.Fatalf("approve: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/journals/"+id+"/post", ctrl, nil); st != 200 || out["status"] != "POSTED" {
		t.Fatalf("post: %d %v", st, out)
	}
	st, out = e.do("POST", "/v1/journals/"+id+"/reverse", ctrl, map[string]any{"idempotency_key": "r-" + uuid.NewString(), "reason": "test", "business_event_at": "2026-10-16T00:00:00Z"})
	if st != 201 {
		t.Fatalf("reverse: %d %v", st, out)
	}
	rid := out["id"].(string)
	e.do("POST", "/v1/journals/"+rid+"/approve", appr, nil)
	if st, out := e.do("POST", "/v1/journals/"+rid+"/post", e.token("ctrl2", "controller"), nil); st != 200 {
		t.Fatalf("post reversal: %d %v", st, out)
	}
	if st, out := e.do("GET", "/v1/journals/"+id, prep, nil); st != 200 || out["status"] != "REVERSED" || out["reversed_by"] != rid {
		t.Fatalf("original after reversal: %d %v", st, out)
	}
}

func TestAPIRejections(t *testing.T) {
	e := newEnv(t)
	prep := e.token("prep", "accountant")

	if st, _ := e.do("POST", "/v1/journals", "", e.journalBody("x", "250.00")); st != 401 {
		t.Fatalf("no token: %d", st)
	}
	if st, _ := e.do("POST", "/v1/journals", "garbage.token.here", e.journalBody("x", "250.00")); st != 401 {
		t.Fatalf("bad token: %d", st)
	}
	// Unbalanced -> 422 validation.
	if st, out := e.do("POST", "/v1/journals", prep, e.journalBody("k-"+uuid.NewString(), "249.99")); st != 422 || out["error"].(map[string]any)["code"] != "validation" {
		t.Fatalf("unbalanced: %d %v", st, out)
	}
	// Excess precision is a 422 validation error, never rounded.
	if st, out := e.do("POST", "/v1/journals", prep, e.journalBody("k-"+uuid.NewString(), "250.001")); st != 422 || out["error"].(map[string]any)["code"] != "validation" {
		t.Fatalf("excess precision: %d %v", st, out)
	}
	// Unknown field -> 400 (strict decoding).
	b := e.journalBody("k-"+uuid.NewString(), "250.00")
	b["tenant_id"] = "11111111-1111-1111-1111-111111111111" // attempt to choose a tenant
	if st, _ := e.do("POST", "/v1/journals", prep, b); st != 400 {
		t.Fatalf("unknown field accepted: %d", st)
	}
	// Malformed JSON and wrong content type.
	if st, _ := e.do("POST", "/v1/journals", prep, `{"legal_entity_id":`); st != 400 {
		t.Fatalf("malformed json: %d", st)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/journals", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+prep)
	req.Header.Set("Content-Type", "text/plain")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 415 {
		t.Fatalf("content type: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// Oversized body.
	big := e.journalBody("k-big", "250.00")
	big["description"] = strings.Repeat("x", maxBodyBytes+10)
	if st, _ := e.do("POST", "/v1/journals", prep, big); st != 413 {
		t.Fatalf("oversized: %d", st)
	}
	// Idempotent replay -> 200 with same id; conflict -> 409.
	k := "k-" + uuid.NewString()
	st1, o1 := e.do("POST", "/v1/journals", prep, e.journalBody(k, "250.00"))
	st2, o2 := e.do("POST", "/v1/journals", prep, e.journalBody(k, "250.00"))
	if st1 != 201 || st2 != 200 || o1["id"] != o2["id"] || o2["replayed"] != true {
		t.Fatalf("replay: %d %v / %d %v", st1, o1, st2, o2)
	}
	mod := e.journalBody(k, "250.00")
	mod["description"] = "changed"
	if st, out := e.do("POST", "/v1/journals", prep, mod); st != 409 || out["error"].(map[string]any)["code"] != "idempotency_conflict" {
		t.Fatalf("idempotency conflict: %d %v", st, out)
	}
	// Unknown / foreign ids -> 404 without leaking.
	if st, _ := e.do("GET", "/v1/journals/"+uuid.NewString(), prep, nil); st != 404 {
		t.Fatalf("unknown id: %d", st)
	}
	if st, _ := e.do("GET", "/v1/journals/not-a-uuid", prep, nil); st != 404 {
		t.Fatalf("bad id: %d", st)
	}
	// Security headers present.
	resp, _ = http.Get(e.srv.URL + "/healthz")
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Request-ID") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers missing: %v", resp.Header)
	}
	resp.Body.Close()
}

func TestAPIRateLimit(t *testing.T) {
	e := newEnv(t)
	tok := e.token("spammer", "accountant")
	var last int
	for i := 0; i < 60; i++ {
		last, _ = e.do("GET", "/v1/journals/"+uuid.NewString(), tok, nil)
		if last == 429 {
			break
		}
	}
	if last != 429 {
		t.Fatalf("rate limit never triggered (last %d)", last)
	}
}

func TestAPIFXMakerCheckerFlow(t *testing.T) {
	e := newEnv(t)
	treas, fm, prep := e.token("treas", "treasury_officer"), e.token("fm", "finance_manager"), e.token("prep", "accountant")
	hash := "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	code := func(out map[string]any) any { return out["error"].(map[string]any)["code"] }

	if st, out := e.do("POST", "/v1/fx/sources", treas, map[string]any{"source_id": "NBE", "source_type": "CENTRAL_BANK", "description": "NBE"}); st != 201 {
		t.Fatalf("register source: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/fx/sources/NBE/approve", fm, map[string]any{}); st != 200 {
		t.Fatalf("approve source: %d %v", st, out)
	}
	st, out := e.do("POST", "/v1/fx/policies", treas, map[string]any{"legal_entity_id": e.entity, "rate_type": "OFFICIAL",
		"source_priority": []string{"NBE"}, "max_staleness_hours": 720})
	if st != 201 {
		t.Fatalf("propose policy: %d %v", st, out)
	}
	pol := out["policy_id"].(string)
	if st, out := e.do("POST", "/v1/fx/policies/"+pol+"/approve", fm, map[string]any{"reason": "official NBE policy"}); st != 200 {
		t.Fatalf("approve policy: %d %v", st, out)
	}
	// The 0.1.0 self-approval field is rejected outright.
	snapBody := map[string]any{"source_id": "NBE", "source_type": "CENTRAL_BANK", "base_currency": "USD", "quote_currency": "ETB", "rate": "57.25",
		"rate_type": "OFFICIAL", "effective_from_utc": "2026-10-01T00:00:00Z", "published_at_utc": "2026-10-01T06:00:00Z", "source_document_hash": hash, "approve": true}
	if st, _ := e.do("POST", "/v1/fx/snapshots", treas, snapBody); st != 400 {
		t.Fatalf("legacy approve flag accepted: %d", st)
	}
	delete(snapBody, "approve")
	st, out = e.do("POST", "/v1/fx/snapshots", treas, snapBody)
	if st != 201 || out["status"] != "PENDING" {
		t.Fatalf("record: %d %v", st, out)
	}
	snap := out["snapshot_id"].(string)
	if st, _ := e.do("POST", "/v1/fx/snapshots", prep, snapBody); st != 403 {
		t.Fatalf("accountant recorded a rate: %d", st)
	}
	// Pending rate is not usable.
	convBody := map[string]any{"amount": map[string]string{"amount": "100.00", "currency": "USD"}, "target_currency": "ETB",
		"business_event_at": "2026-10-15T00:00:00Z", "legal_entity_id": e.entity}
	if st, out := e.do("POST", "/v1/fx/convert", prep, convBody); st != 422 || code(out) != "fx_exception" {
		t.Fatalf("pending rate used: %d %v", st, out)
	}
	if st, _ := e.do("POST", "/v1/fx/snapshots/"+snap+"/approve", treas, map[string]any{}); st != 403 {
		t.Fatalf("maker approved: %d", st)
	}
	if st, out := e.do("POST", "/v1/fx/snapshots/"+snap+"/approve", fm, map[string]any{}); st != 200 {
		t.Fatalf("checker approve: %d %v", st, out)
	}
	st, out = e.do("POST", "/v1/fx/convert", prep, convBody)
	if st != 200 || out["binding"] != true || out["snapshot_id"] != snap || out["to"].(map[string]any)["amount"] != "5725.00" {
		t.Fatalf("binding convert: %d %v", st, out)
	}
	// Out-of-tolerance rate: ordinary checker 403; CFO without MFA gets an RFC 9470 step-up challenge.
	snapBody["rate"], snapBody["effective_from_utc"], snapBody["published_at_utc"] = "63.00", "2026-10-08T00:00:00Z", "2026-10-08T06:00:00Z"
	_, out = e.do("POST", "/v1/fx/snapshots", treas, snapBody)
	jump := out["snapshot_id"].(string)
	if st, out := e.do("POST", "/v1/fx/snapshots/"+jump+"/approve", fm, map[string]any{"reason": "devaluation"}); st != 403 {
		t.Fatalf("ordinary checker approved variance exception: %d %v", st, out)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/fx/snapshots/"+jump+"/approve", strings.NewReader(`{"reason":"devaluation notice"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token("cfo", "cfo"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Fatalf("step-up challenge missing: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if st, out := e.do("POST", "/v1/fx/snapshots/"+jump+"/approve", e.mfaToken("cfo", "cfo"), map[string]any{"reason": "devaluation notice"}); st != 200 || out["variance_exception"] != true {
		t.Fatalf("MFA exception approval: %d %v", st, out)
	}
}

// mfaToken issues a token asserting a fresh multi-factor login.
func (e *env) mfaToken(user string, roles ...string) string {
	now := time.Now()
	tok, err := testVerifier.Sign(Claims{Subject: user, TenantID: e.tenant, Roles: roles, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Issuer: "serk-id", Audience: "serk-construction", AMR: []string{"pwd", "otp"}, AuthTime: now.Unix()})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}
