package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

func day(m, d int) time.Time { return time.Date(2026, time.Month(m), d, 0, 0, 0, 0, time.UTC) }

// usdJournal: debit materials in USD at the given snapshot, credit AP in ETB.
func (f *fixture) usdJournal(k, usd, etb, snap string) ledger.Journal {
	return f.journal(k,
		fxLine(f.accounts["5000"], ledger.Debit, usd, etb, snap),
		ledger.Line{AccountID: f.accounts["2000"], Side: ledger.Credit, Amount: money.MustNew(etb, "ETB")})
}

// SC-02: the journal write path applies the entity's FX policy: effective
// date, staleness, rate type, admitted source, trust, and "the selected rate,
// not merely an approved one". Business event of the fixture is 2026-10-15.
func TestSC02_WritePathEnforcesFXPolicy(t *testing.T) {
	f := newFixture(t)
	// No policy yet: foreign-currency postings fail closed.
	f.mustRegisterSource(t, "NBE", "CENTRAL_BANK")
	early := f.snapshotFrom(t, "NBE", "CENTRAL_BANK", "USD", "ETB", "57.00", day(10, 1), fx.RateOfficial)
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, f.usdJournal(key("nopol"), "100.00", "5700.00", early)); !errors.Is(err, postgres.ErrNoFXPolicy) {
		t.Fatalf("FX line accepted without an approved policy: %v", err)
	}
	f.approvePolicy(t, fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 30 * 24 * time.Hour})

	stale := f.snapshotFrom(t, "NBE", "CENTRAL_BANK", "USD", "ETB", "55.00", day(8, 1), fx.RateOfficial)
	future := f.snapshotFrom(t, "NBE", "CENTRAL_BANK", "USD", "ETB", "57.10", day(10, 20), fx.RateOfficial)
	commercial := f.snapshotFrom(t, "NBE", "CENTRAL_BANK", "USD", "ETB", "57.40", day(10, 10), fx.RateCommercial)
	f.mustRegisterSource(t, "CBE", "COMMERCIAL_BANK")
	otherSource := f.snapshotFrom(t, "CBE", "COMMERCIAL_BANK", "USD", "ETB", "57.30", day(10, 12), fx.RateOfficial)
	current := f.snapshotFrom(t, "NBE", "CENTRAL_BANK", "USD", "ETB", "57.25", day(10, 5), fx.RateOfficial)

	for name, c := range map[string]struct{ snap, etb string }{
		"future-effective (10-20 > event 10-15)":      {future, "5710.00"},
		"stale (75 days > policy 30)":                 {stale, "5500.00"},
		"approved but older than the selected rate":   {early, "5700.00"},
		"wrong rate type (COMMERCIAL vs OFFICIAL)":    {commercial, "5740.00"},
		"trusted source not admitted by the policy":   {otherSource, "5730.00"},
		"selected rate but amount does not reconcile": {current, "5726.00"},
	} {
		_, err := f.svc.CreateJournal(f.ctx, f.prep, f.usdJournal(key("sc02"), "100.00", c.etb, c.snap))
		if !errors.Is(err, postgres.ErrLineRejected) {
			t.Errorf("SC-02 %s: accepted (err=%v)", name, err)
		}
		t.Logf("%-45s -> %v", name, err)
	}
	// The policy-selected rate posts and is bound with policy provenance.
	id := f.lifecycle(t, f.usdJournal(key("sc02-ok"), "100.00", "5725.00", current))
	rec, _ := f.svc.GetJournal(f.ctx, f.prep, id)
	if l := rec.Lines[0]; l.FXSnapshotID != current || l.FXPolicyID != f.fxPolicy || l.FXPolicyVersion != 1 || l.AppliedRate.String() != "57.25" {
		t.Fatalf("policy binding missing: %+v", l)
	}
	// /fx/convert with legal_entity_id returns exactly the binding selection.
	conv, err := f.svc.Convert(f.ctx, f.prep, ConvertRequest{Amount: money.MustNew("100.00", "USD"), Target: "ETB", EventAt: f.journal("x").BusinessEventAt, LegalEntityID: f.entity})
	if err != nil || conv.SnapshotID != current || !conv.Binding || conv.To.AmountString() != "5725.00" {
		t.Fatalf("binding convert: %+v %v", conv, err)
	}
}

// SC-02 defense in depth: raw SQL as the app role cannot bind an ineligible
// snapshot even with a valid policy id, and posting re-verifies eligibility.
func TestSC02_DatabaseRejectsIneligibleFXAndRechecksAtPost(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 30 * 24 * time.Hour, AllowInverse: false})
	future := f.snapshot(t, "USD", "ETB", "57.10", day(10, 20), true)
	stale := f.snapshot(t, "USD", "ETB", "55.00", day(8, 1), true)
	pending := f.snapshot(t, "USD", "ETB", "57.00", day(10, 2), false)
	inverse := f.snapshot(t, "ETB", "USD", "0.0175", day(10, 3), true)
	good := f.snapshot(t, "USD", "ETB", "57.25", day(10, 5), true)
	ins := `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency,txn_amount,txn_currency,
		fx_snapshot_id,applied_rate,fx_policy_id,fx_policy_version) VALUES ($1::uuid,$2::uuid,$3::uuid,1,$4::uuid,'DEBIT',$5::numeric,'ETB',100,'USD',$6::uuid,$7::numeric,$8,$9)`
	raw := func(amount, snap, rate string, policy any, version any) error {
		return f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			var jid string
			if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id,legal_entity_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by)
				VALUES ($1::uuid,$2::uuid,'ETB','2026-10-15T09:00:00Z','raw','MANUAL',$3,'h','a') RETURNING id::text`, f.tenant, f.entity, key("rawfx")).Scan(&jid); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, ins, jid, f.tenant, f.entity, f.accounts["5000"], amount, snap, rate, policy, version)
			return err
		})
	}
	for name, c := range map[string]struct {
		amount, snap, rate string
		pol                any
		ver                any
	}{
		"future-effective":            {"5710", future, "57.10", f.fxPolicy, 1},
		"stale":                       {"5500", stale, "55.00", f.fxPolicy, 1},
		"pending":                     {"5700", pending, "57.00", f.fxPolicy, 1},
		"inverse when policy forbids": {"5714.29", inverse, "57.142857142857", f.fxPolicy, 1},
		"no policy binding":           {"5725", good, "57.25", nil, nil},
		"wrong policy version":        {"5725", good, "57.25", f.fxPolicy, 7},
		"applied rate differs":        {"5800", good, "58.00", f.fxPolicy, 1},
		"amount does not reconcile":   {"6000", good, "57.25", f.fxPolicy, 1},
	} {
		err := raw(c.amount, c.snap, c.rate, c.pol, c.ver)
		if !errors.Is(err, postgres.ErrInvariant) {
			t.Errorf("SC-02 raw %s accepted (err=%v)", name, err)
		}
		t.Logf("raw %-28s -> %v", name, err)
	}
	if err := raw("5725", good, "57.25", f.fxPolicy, 1); err != nil {
		t.Fatalf("eligible raw line refused: %v", err)
	}
	// SQL function: knowledge cutoff before publication is refused.
	err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT fx_assert_eligible($1::uuid,$2::uuid,1,'USD','ETB',$3::uuid,'2026-10-15T09:00:00Z','2026-10-05T00:00:00Z')`, good, f.fxPolicy, f.entity)
		return err
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("published-after-cutoff accepted: %v", err)
	}
	// Re-check at post: the source is retired between approval and posting.
	res, err := f.svc.CreateJournal(f.ctx, f.prep, f.usdJournal(key("recheck"), "100.00", "5725.00", good))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ApproveJournal(f.ctx, f.appr, res.JournalID); err != nil {
		t.Fatal(err)
	}
	if err := f.rawAs(f.appr, "fx.source.retire", "fx_source", "NBE", "", `UPDATE fx_sources SET status='RETIRED' WHERE source_id='NBE'`); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PostJournal(f.ctx, f.post, res.JournalID); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("posted with a rate from a retired source: %v", err)
	}
}

// SC-03: maker/checker for rates, sources and policies; variance exceptions
// require fx.approve_exception, recent MFA and a reason.
func TestSC03_FXMakerChecker(t *testing.T) {
	f := newFixture(t)
	// Sources.
	if err := f.svc.RegisterFXSource(f.ctx, f.treasury, postgres.FXSource{SourceID: "NBE", SourceType: "CENTRAL_BANK", Description: "NBE", RequiresDocumentHash: true}); err != nil {
		t.Fatal(err)
	}
	both := auth.Principal{UserID: f.treasury.UserID, TenantID: f.tenant, Roles: []string{"treasury_officer", "finance_manager"}}
	if err := f.svc.ApproveFXSource(f.ctx, both, "NBE"); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("source maker approved own source: %v", err)
	}
	if err := f.svc.ApproveFXSource(f.ctx, f.treasury, "NBE"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("treasury approved a source: %v", err)
	}
	if err := f.rawExec(`INSERT INTO fx_sources(tenant_id,source_id,source_type,description,status,created_by,approved_by) VALUES ($1::uuid,'ROGUE','PROVIDER','x','APPROVED','a','b')`, f.tenant); err == nil {
		t.Fatal("source inserted pre-approved via raw SQL")
	}
	// Rates from an untrusted (still PENDING) source cannot even be recorded.
	if _, err := f.svc.RecordFXSnapshot(f.ctx, f.treasury, fx.Snapshot{SourceID: "NBE", SourceType: "CENTRAL_BANK", BaseCurrency: "USD", QuoteCurrency: "ETB",
		Rate: decimal.RequireFromString("57"), RateType: fx.RateOfficial, EffectiveFromUTC: day(10, 1), PublishedAtUTC: day(10, 1), SourceDocumentHash: docHash}); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("rate recorded from untrusted source: %v", err)
	}
	if err := f.svc.ApproveFXSource(f.ctx, f.appr, "NBE"); err != nil {
		t.Fatal(err)
	}
	// Document hash format is enforced for sources that require it.
	if _, err := f.svc.RecordFXSnapshot(f.ctx, f.treasury, fx.Snapshot{SourceID: "NBE", SourceType: "CENTRAL_BANK", BaseCurrency: "USD", QuoteCurrency: "ETB",
		Rate: decimal.RequireFromString("57"), RateType: fx.RateOfficial, EffectiveFromUTC: day(10, 1), PublishedAtUTC: day(10, 1), SourceDocumentHash: "trust-me"}); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("rate recorded without a valid document hash: %v", err)
	}
	// Rates: maker cannot approve own; raw SQL cannot create or self-approve.
	base := f.snapshot(t, "USD", "ETB", "57.25", day(10, 1), false)
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, both, base, ""); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("maker approved own rate: %v", err)
	}
	if err := f.rawExec(`UPDATE fx_snapshots SET approval_status='APPROVED', approved_by=created_by, decided_at=now() WHERE snapshot_id=$1::uuid`, base); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("raw self-approval accepted: %v", err)
	}
	if err := f.rawExec(`INSERT INTO fx_snapshots(tenant_id,source_id,source_type,base_currency,quote_currency,rate,rate_type,effective_from_utc,published_at_utc,
		source_document_hash,algorithm_version,approval_status,approved_by,created_by) VALUES ($1::uuid,'NBE','CENTRAL_BANK','USD','ETB',99,'OFFICIAL',now(),now(),$2,'v','APPROVED','x','y')`, f.tenant, docHash); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("raw pre-approved rate accepted: %v", err)
	}
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.appr, base, ""); err != nil {
		t.Fatal(err)
	}
	// Variance: +10% against a 5% tolerance.
	jump := f.snapshot(t, "USD", "ETB", "62.98", day(10, 8), false)
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.appr, jump, "devaluation"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("ordinary checker approved an out-of-tolerance rate: %v", err)
	}
	noMFA := f.cfo
	noMFA.MFA = false
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, noMFA, jump, "devaluation announced"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("exception approved without MFA: %v", err)
	}
	staleMFA := f.cfo
	staleMFA.AuthTime = time.Now().Add(-time.Hour)
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, staleMFA, jump, "devaluation announced"); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("exception approved with stale MFA: %v", err)
	}
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.cfo, jump, ""); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("exception approved without reason: %v", err)
	}
	if err := f.rawAs(f.cfo, "fx.snapshot.approve", "fx_snapshot", jump, "",
		`UPDATE fx_snapshots SET approval_status='APPROVED', approved_by='u-cfo', decided_at=now() WHERE snapshot_id=$1::uuid`, jump); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("raw out-of-tolerance approval without exception flags accepted: %v", err)
	}
	res, err := f.svc.ApproveFXSnapshot(f.ctx, f.cfo, jump, "NBE devaluation notice 2026/10")
	if err != nil || !res.VarianceException || res.Deviation == nil || res.Deviation.String() != "0.100087" {
		t.Fatalf("exception approval: %+v %v", res, err)
	}
	// Reject needs a reason and a different person; withdraw only unreferenced.
	r := f.snapshot(t, "USD", "ETB", "57.30", day(10, 9), false)
	if err := f.svc.RejectFXSnapshot(f.ctx, f.appr, r, ""); !errors.Is(err, ErrReasonRequired) {
		t.Fatalf("reject without reason: %v", err)
	}
	if err := f.svc.RejectFXSnapshot(f.ctx, f.appr, r, "typo in source document"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, f.appr, r, ""); !errors.Is(err, fx.ErrSnapshotState) {
		t.Fatalf("rejected rate approved: %v", err)
	}
	// Policies: maker/checker, approval retires the previous version.
	p1, _ := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 24 * time.Hour})
	if err := f.svc.DecideFXPolicy(f.ctx, both, p1.ID, true, "self approval attempt"); !errors.Is(err, auth.ErrForbidden) && !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("policy maker approved own policy: %v", err)
	}
	if err := f.svc.DecideFXPolicy(f.ctx, f.appr, p1.ID, true, "baseline"); err != nil {
		t.Fatal(err)
	}
	p2, _ := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}, MaxStaleness: 48 * time.Hour})
	if err := f.svc.DecideFXPolicy(f.ctx, f.cfo, p2.ID, true, "extend staleness window"); err != nil {
		t.Fatal(err)
	}
	if p2.Version != 2 {
		t.Fatalf("policy version %d", p2.Version)
	}
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		old, _ := postgres.GetFXPolicy(ctx, tx, p1.ID, false)
		if old.Status != "RETIRED" {
			t.Fatalf("previous policy %s", old.Status)
		}
		if _, err := tx.Exec(ctx, `UPDATE fx_policies SET max_staleness='999 days' WHERE id=$1::uuid`, p2.ID); err == nil {
			t.Fatal("approved policy content mutated")
		}
		return nil
	})
	// Unsafe policies are refused before reaching the database.
	if _, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, fx.Policy{RateType: fx.RateOfficial, SourcePriority: []string{"NBE"}}); !errors.Is(err, fx.ErrPolicyInvalid) {
		t.Fatalf("policy without staleness bound accepted: %v", err)
	}
}

// SC-07: every FX command emits its outbox event in the same transaction as
// its audit record; a refused command emits nothing.
func TestSC07_FXCommandsEmitAtomicOutboxEvents(t *testing.T) {
	f := newFixture(t)
	f.setupFX(t, fx.Policy{})
	ok := f.snapshot(t, "USD", "ETB", "57.25", day(10, 1), true)
	rej := f.snapshot(t, "USD", "ETB", "57.30", day(10, 2), false)
	_ = f.svc.RejectFXSnapshot(f.ctx, f.appr, rej, "wrong publication")
	both := auth.Principal{UserID: f.treasury.UserID, TenantID: f.tenant, Roles: []string{"treasury_officer", "finance_manager"}}
	failed := f.snapshot(t, "USD", "ETB", "57.35", day(10, 3), false)
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, both, failed, ""); err == nil {
		t.Fatal("self approval succeeded")
	}
	events := map[string][]string{}
	audits := map[string][]string{}
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, `SELECT aggregate_id, event_type FROM outbox WHERE aggregate_type IN ('fx_snapshot','fx_source','fx_policy') ORDER BY id`)
		for rows.Next() {
			var a, e string
			_ = rows.Scan(&a, &e)
			events[a] = append(events[a], e)
		}
		rows.Close()
		rows, _ = tx.Query(ctx, `SELECT aggregate_id, action FROM audit_log WHERE aggregate_type IN ('fx_snapshot','fx_source','fx_policy') ORDER BY chain_no`)
		for rows.Next() {
			var a, e string
			_ = rows.Scan(&a, &e)
			audits[a] = append(audits[a], e)
		}
		rows.Close()
		return nil
	})
	want := map[string][]string{
		ok:         {"fx.snapshot.recorded", "fx.snapshot.approved"},
		rej:        {"fx.snapshot.recorded", "fx.snapshot.rejected"},
		failed:     {"fx.snapshot.recorded"},
		"NBE":      {"fx.source.registered", "fx.source.approved"},
		f.fxPolicy: {"fx.policy.proposed", "fx.policy.approved"},
	}
	for agg, w := range want {
		if len(events[agg]) != len(w) || len(audits[agg]) != len(w) {
			t.Fatalf("%s: events %v audits %v want %v", agg, events[agg], audits[agg], w)
		}
		for i := range w {
			if events[agg][i] != w[i] {
				t.Fatalf("%s: events %v want %v", agg, events[agg], w)
			}
		}
	}
}

// SC-05 at the kernel boundary.
func TestSC05_ScopedPrincipalsCannotReachUnassignedJournals(t *testing.T) {
	f := newFixture(t)
	unassigned := f.balanced(key("unassigned"))
	unassigned.ProjectID = ""
	tenantWide := f.lifecycle(t, unassigned)
	scopedAcct := auth.Principal{UserID: "u-scoped", TenantID: f.tenant, Roles: []string{"accountant"}, ProjectIDs: []string{f.project}}
	if _, err := f.svc.GetJournal(f.ctx, scopedAcct, tenantWide); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("scoped principal read an unassigned journal: %v", err)
	}
	j := f.balanced(key("scoped-create"))
	j.ProjectID = ""
	if _, err := f.svc.CreateJournal(f.ctx, scopedAcct, j); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("scoped principal created an unassigned journal: %v", err)
	}
	if _, err := f.svc.CreateJournal(f.ctx, scopedAcct, f.balanced(key("scoped-ok"))); err != nil {
		t.Fatalf("scoped principal refused on own project: %v", err)
	}
	projAcct := auth.Principal{UserID: "u-pa", TenantID: f.tenant, Roles: []string{"project_accountant"}}
	if _, err := f.svc.CreateJournal(f.ctx, projAcct, f.balanced(key("pa-none"))); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("project accountant with no projects created a journal: %v", err)
	}
	if _, err := f.svc.GetJournal(f.ctx, f.prep, tenantWide); err != nil {
		t.Fatalf("tenant-wide accountant refused: %v", err)
	}
}

// helpers -------------------------------------------------------------------

func (f *fixture) mustRegisterSource(t *testing.T, id, typ string) {
	t.Helper()
	if err := f.svc.RegisterFXSource(f.ctx, f.treasury, postgres.FXSource{SourceID: id, SourceType: typ, Description: id, RequiresDocumentHash: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ApproveFXSource(f.ctx, f.appr, id); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) approvePolicy(t *testing.T, pol fx.Policy) {
	t.Helper()
	p, err := f.svc.ProposeFXPolicy(f.ctx, f.treasury, f.entity, postgres.PurposeTransaction, pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideFXPolicy(f.ctx, f.appr, p.ID, true, "policy approval"); err != nil {
		t.Fatal(err)
	}
	f.fxPolicy = p.ID
}

func (f *fixture) snapshotFrom(t *testing.T, src, typ string, base, quote money.Currency, rate string, eff time.Time, rt fx.RateType) string {
	t.Helper()
	id, err := f.svc.RecordFXSnapshot(f.ctx, f.treasury, fx.Snapshot{SourceID: src, SourceType: typ, BaseCurrency: base, QuoteCurrency: quote,
		Rate: decimal.RequireFromString(rate), RateType: rt, EffectiveFromUTC: eff, PublishedAtUTC: eff.Add(6 * time.Hour), SourceDocumentHash: docHash})
	if err != nil {
		t.Fatal(err)
	}
	cfo := f.cfo
	cfo.AuthTime = time.Now()
	if _, err := f.svc.ApproveFXSnapshot(f.ctx, cfo, id, "approved for test series"); err != nil {
		t.Fatalf("approve %s: %v", rate, err)
	}
	return id
}
