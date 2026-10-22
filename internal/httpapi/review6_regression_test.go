package httpapi

// Independent review 6 probes over HTTP (Journey B routes, 0018/0019).
// "held:" when the control holds, t.Errorf "OPEN:" when it does not.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func (e *env) r6tokKind(user, kind string, projects []string, mfa bool, roles ...string) string {
	now := time.Now()
	c := Claims{Subject: user, TenantID: e.tenant, Roles: roles, Projects: projects, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Issuer: "serk-id", Audience: "serk-construction", Kind: kind, TokenID: uuid.NewString()}
	if mfa {
		c.AMR, c.AuthTime = []string{"pwd", "otp"}, now.Unix()
	}
	t, err := testVerifier.Sign(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return t
}

func TestR6_API_JourneyB(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	controller, cfo := a.tok("u-controller", nil, false, "controller"), a.tok("u-cfo", nil, true, "cfo")
	finMgr := a.tok("u-finance-manager", nil, true, "finance_manager")
	arClerk := a.tok("u-ar-clerk", nil, false, "ar_clerk")
	commercial := a.tok("u-commercial", P, false, "commercial_manager")
	if err := a.db.AdminStore.WithTenant(a.db.Ctx, a.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, x := range []struct{ code, typ string }{{"1100", "ASSET"}, {"1150", "ASSET"}, {"2200", "LIABILITY"}, {"2300", "LIABILITY"}, {"4000", "REVENUE"}} {
			id, err := postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: a.tenant, LegalEntityID: a.entity, Code: x.code, Name: x.code, Type: ledger.AccountType(x.typ), Active: true})
			if err != nil {
				return err
			}
			a.accounts[x.code] = id
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pol := a.id("POST", "/v1/contract-policies", controller, map[string]any{"legal_entity_id": a.entity, "vat_rate": "0.15", "vat_base": "GROSS_LESS_ADVANCE",
		"ar_account_id": a.accounts["1100"], "retention_account_id": a.accounts["1150"], "advance_account_id": a.accounts["2200"],
		"revenue_account_id": a.accounts["4000"], "vat_output_account_id": a.accounts["2300"]})
	a.call(200, "POST", "/v1/contract-policies/"+pol+"/approve", cfo, nil)

	// 1. Principal kind over HTTP: a service / AI / kind-less token may create
	//    a customer (draft) but never approve one.
	for _, kind := range []string{"service", "ai", ""} {
		st, out := a.do("POST", "/v1/customers", a.r6tokKind("u-bot-"+kind, kind, nil, false, "ar_clerk"), map[string]any{"legal_entity_id": a.entity, "code": "BOT-" + kind + "X", "name": "Bot customer " + kind})
		t.Logf("info: customer create with pkind %q -> %d", kind, st)
		if st == 201 {
			cid := out["id"].(string)
			st2, out2 := a.do("POST", "/v1/customers/"+cid+"/approve", a.r6tokKind("u-bot-fm-"+kind, kind, nil, true, "finance_manager"), nil)
			if st2 == 200 {
				t.Errorf("OPEN: customer approved with pkind %q", kind)
			} else {
				t.Logf("held: customer approval with pkind %q -> %d %v", kind, st2, out2["error"])
			}
		}
	}
	cust := a.id("POST", "/v1/customers", arClerk, map[string]any{"legal_entity_id": a.entity, "code": "ERA", "name": "Ethiopian Roads Administration"})
	a.call(200, "POST", "/v1/customers/"+cust+"/approve", finMgr, nil)

	// 2. Contract terms that produce a negative amount due are accepted.
	ctr := a.id("POST", "/v1/contracts", commercial, map[string]any{"project_id": a.project, "customer_id": cust, "title": "R6 contract",
		"client_reference": "R6/2026/1", "signed_on": "2026-10-01", "retention_pct": "0.20", "advance_amount": "1000000", "advance_recovery_pct": "1",
		"lines": []map[string]any{{"line_no": 1, "description": "Bulk excavation", "unit": "m3", "quantity": "10000", "rate": "350"}}})
	a.call(200, "POST", "/v1/contracts/"+ctr+"/submit", commercial, nil)
	a.call(200, "POST", "/v1/contracts/"+ctr+"/approve", cfo, nil)
	t.Logf("info: contract with retention 20%% and advance recovery 100%% accepted and activated over HTTP (amount due of every IPC funded by the advance is negative; see kernel TestR6_01)")

	// 3. Visibility status parity for the new read routes.
	otherProj := "8c1d4c2e-0000-4000-8000-000000000001"
	qsB := a.tok("u-qs-b", []string{otherProj}, false, "quantity_surveyor")
	pmB := a.tok("u-pm-b", []string{otherProj}, false, "project_manager")
	random := uuid.NewString()
	st1, _ := a.do("GET", "/v1/contracts/"+ctr+"/position", qsB, nil)
	st2, _ := a.do("GET", "/v1/contracts/"+random+"/position", qsB, nil)
	if st1 == 200 || st1 != st2 {
		t.Errorf("OPEN: contract position other project %d vs nonexistent %d", st1, st2)
	} else {
		t.Logf("held: contract position: other project %d, nonexistent %d", st1, st2)
	}
	st1, _ = a.do("GET", "/v1/projects/"+a.project+"/profitability", pmB, nil)
	st2, _ = a.do("GET", "/v1/projects/"+random+"/profitability", pmB, nil)
	if st1 == 200 || st1 != st2 {
		t.Errorf("OPEN: profitability other project %d vs nonexistent %d", st1, st2)
	} else {
		t.Logf("held: profitability: other project %d, nonexistent %d", st1, st2)
	}
	st1, _ = a.do("GET", "/v1/entities/"+a.entity+"/ar-reconciliation", pmB, nil)
	if st1 == 200 {
		t.Errorf("OPEN: project-scoped PM runs the AR reconciliation")
	} else {
		t.Logf("held: project-scoped AR reconciliation -> %d", st1)
	}
	for _, typ := range []string{"contract", "customer_receipt", "money_in"} {
		st, out := a.do("GET", "/v1/p2p/"+typ, qsB, nil)
		if items, _ := out["items"].([]any); st == 200 && len(items) > 0 {
			t.Errorf("OPEN: other-project QS lists %d %s", len(items), typ)
		} else {
			t.Logf("held: other-project QS list %s -> %d (%d items)", typ, st, len(items))
		}
	}

	// 4. Malformed ids in bodies.
	st, out := a.do("POST", "/v1/receipts", arClerk, map[string]any{"statement_line_id": random, "allocations": []map[string]any{{"contract_id": "not-a-uuid", "amount": "1"}}})
	if st >= 500 {
		t.Errorf("OPEN (info): malformed allocation contract_id -> %d %v", st, out)
	} else {
		t.Logf("held: malformed allocation id -> %d %v", st, out["error"])
	}
	st, out = a.do("POST", "/v1/contracts", commercial, map[string]any{"project_id": a.project, "customer_id": "nope", "title": "R6 bad", "client_reference": "R6/2", "signed_on": "2026-10-01",
		"retention_pct": "0.05", "lines": []map[string]any{{"line_no": 1, "description": "x x", "unit": "m3", "quantity": "1", "rate": "1"}}})
	if st >= 500 {
		t.Errorf("OPEN (info): malformed customer_id -> %d %v", st, out)
	} else {
		t.Logf("held: malformed customer_id -> %d %v", st, out["error"])
	}
	st, out = a.do("POST", "/v1/contracts", commercial, map[string]any{"project_id": a.project, "customer_id": cust, "title": "R6 neg", "client_reference": "R6/3", "signed_on": "2026-10-01",
		"retention_pct": "-0.05", "lines": []map[string]any{{"line_no": 1, "description": "x x", "unit": "m3", "quantity": "-1", "rate": "1"}}})
	if st >= 500 || st == 201 {
		t.Errorf("OPEN (info): negative retention/quantity contract -> %d %v", st, out)
	} else {
		t.Logf("held: negative retention/quantity -> %d %v", st, out["error"])
	}
}
