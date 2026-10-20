package fx

import (
	"errors"
	"testing"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func snap(id, src string, base, quote money.Currency, rate string, eff, pub string, st ApprovalStatus, rt RateType) Snapshot {
	return Snapshot{
		SnapshotID: id, TenantID: "t1", SourceID: src, SourceType: "CENTRAL_BANK",
		BaseCurrency: base, QuoteCurrency: quote, Rate: decimal.RequireFromString(rate),
		RateType: rt, EffectiveFromUTC: ts(eff), PublishedAtUTC: ts(pub), CapturedAtUTC: ts(pub),
		SourceDocumentHash: "sha256:abc", AlgorithmVersion: AlgorithmVersion, ApprovalStatus: st, CreatedBy: "u1",
	}
}

var usdEtb = []Snapshot{
	snap("s1", "NBE", "USD", "ETB", "56.5000", "2026-09-01T00:00:00Z", "2026-09-01T06:00:00Z", StatusApproved, RateOfficial),
	snap("s2", "NBE", "USD", "ETB", "57.1000", "2026-09-15T00:00:00Z", "2026-09-15T06:00:00Z", StatusApproved, RateOfficial),
	snap("s3", "NBE", "USD", "ETB", "58.0000", "2026-10-01T00:00:00Z", "2026-10-01T06:00:00Z", StatusPending, RateOfficial),
	snap("s4", "CBE", "USD", "ETB", "57.4000", "2026-09-15T00:00:00Z", "2026-09-15T08:00:00Z", StatusApproved, RateCommercial),
}

func TestSelectLatestEffectiveApproved(t *testing.T) {
	sel, err := Select(usdEtb, "USD", "ETB", ts("2026-09-20T10:00:00Z"), time.Time{}, Policy{RateType: RateOfficial})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Snapshot.SnapshotID != "s2" {
		t.Fatalf("want s2 got %s", sel.Snapshot.SnapshotID)
	}
	if sel.AlgorithmVersion != AlgorithmVersion || sel.DerivedInverse {
		t.Fatalf("bad selection metadata %+v", sel)
	}
}

func TestSelectNeverUsesPendingOrFutureRates(t *testing.T) {
	// Event on 2026-10-05: s3 (58.0) is effective but PENDING -> must fall back to s2.
	sel, err := Select(usdEtb, "USD", "ETB", ts("2026-10-05T00:00:00Z"), time.Time{}, Policy{RateType: RateOfficial})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Snapshot.SnapshotID != "s2" {
		t.Fatalf("pending snapshot used: %s", sel.Snapshot.SnapshotID)
	}
	// Event before any effective rate: explicit missing error, never a fabricated rate.
	_, err = Select(usdEtb, "USD", "ETB", ts("2026-08-01T00:00:00Z"), time.Time{}, Policy{})
	if !errors.Is(err, ErrRateMissing) {
		t.Fatalf("want ErrRateMissing got %v", err)
	}
}

func TestKnowledgeCutoffRespected(t *testing.T) {
	// Backdated entry: event 2026-09-15 03:00, but s2 was only published at 06:00.
	// With knowledge cutoff = event time, s2 is not yet knowable -> s1 (56.5)
	// is the rate valid and available at that moment.
	sel, err := Select(usdEtb, "USD", "ETB", ts("2026-09-15T03:00:00Z"), ts("2026-09-15T03:00:00Z"), Policy{RateType: RateOfficial})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Snapshot.SnapshotID != "s1" {
		t.Fatalf("knowledge cutoff ignored: got %s", sel.Snapshot.SnapshotID)
	}
	// Posting later (cutoff after publication) legitimately picks s2.
	sel, err = Select(usdEtb, "USD", "ETB", ts("2026-09-15T03:00:00Z"), ts("2026-09-20T00:00:00Z"), Policy{RateType: RateOfficial})
	if err != nil || sel.Snapshot.SnapshotID != "s2" {
		t.Fatalf("late posting should use s2: %v %v", sel.Snapshot.SnapshotID, err)
	}
	// Only a not-yet-published candidate exists -> specific exception.
	only := []Snapshot{usdEtb[1]}
	_, err = Select(only, "USD", "ETB", ts("2026-09-15T03:00:00Z"), ts("2026-09-15T03:00:00Z"), Policy{})
	if !errors.Is(err, ErrRateNotYetKnown) {
		t.Fatalf("want ErrRateNotYetKnown got %v", err)
	}
}

func TestSourcePriorityAndStaleness(t *testing.T) {
	// Prefer CBE commercial over NBE when policy says so.
	sel, err := Select(usdEtb, "USD", "ETB", ts("2026-09-20T00:00:00Z"), time.Time{}, Policy{SourcePriority: []string{"CBE", "NBE"}})
	if err != nil || sel.Snapshot.SnapshotID != "s4" {
		t.Fatalf("priority not honoured: %v %v", sel.Snapshot.SnapshotID, err)
	}
	// Unknown source excluded entirely.
	_, err = Select(usdEtb, "USD", "ETB", ts("2026-09-20T00:00:00Z"), time.Time{}, Policy{SourcePriority: []string{"BLOOMBERG"}})
	if !errors.Is(err, ErrRateMissing) {
		t.Fatalf("want missing got %v", err)
	}
	// Staleness: event 60 days after the last approved rate with 7-day max.
	_, err = Select(usdEtb, "USD", "ETB", ts("2026-11-14T00:00:00Z"), time.Time{}, Policy{MaxStaleness: 7 * 24 * time.Hour})
	if !errors.Is(err, ErrRateStale) {
		t.Fatalf("want stale got %v", err)
	}
}

func TestInverseDerivationOnlyWhenAllowed(t *testing.T) {
	_, err := Select(usdEtb, "ETB", "USD", ts("2026-09-20T00:00:00Z"), time.Time{}, Policy{})
	if !errors.Is(err, ErrRateMissing) {
		t.Fatalf("inverse must not be implicit: %v", err)
	}
	sel, err := Select(usdEtb, "ETB", "USD", ts("2026-09-20T00:00:00Z"), time.Time{}, Policy{AllowInverse: true, RateType: RateOfficial})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.DerivedInverse || sel.Snapshot.SnapshotID != "s2" {
		t.Fatalf("expected inverse of s2: %+v", sel)
	}
	// 1/57.1 at 12 dp = 0.017513134851
	if sel.AppliedRate.String() != "0.017513134851" {
		t.Fatalf("inverse rate %s", sel.AppliedRate)
	}
	conv, err := Convert(money.MustNew("5710.00", "ETB"), "USD", sel, money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if conv.To.AmountString() != "100.00" {
		t.Fatalf("inverse conversion %s", conv.To)
	}
}

func TestConvertIsExactAndBoundToSnapshot(t *testing.T) {
	sel, _ := Select(usdEtb, "USD", "ETB", ts("2026-09-20T00:00:00Z"), time.Time{}, Policy{RateType: RateOfficial})
	conv, err := Convert(money.MustNew("1234.56", "USD"), "ETB", sel, money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	// 1234.56 * 57.1 = 70493.376 -> 70493.38
	if conv.To.AmountString() != "70493.38" || conv.SnapshotID != "s2" || conv.AlgorithmVersion != AlgorithmVersion {
		t.Fatalf("bad conversion %+v", conv)
	}
	// Reject applying a USD/ETB selection to a KES amount.
	if _, err := Convert(money.MustNew("1", "KES"), "ETB", sel, money.RoundHalfEven); err == nil {
		t.Fatal("expected orientation guard error")
	}
	if _, err := Convert(money.MustNew("1", "ETB"), "ETB", sel, money.RoundHalfEven); !errors.Is(err, ErrSameCurrency) {
		t.Fatalf("want same-currency error got %v", err)
	}
}

func TestRemeasurementSigns(t *testing.T) {
	closing := Selection{Snapshot: snap("c1", "NBE", "USD", "ETB", "60", "2026-09-30T00:00:00Z", "2026-09-30T06:00:00Z", StatusApproved, RateClosing), AppliedRate: decimal.RequireFromString("60")}
	carrying := decimal.RequireFromString("57.1")
	// USD 1,000 receivable (asset) carried at 57.1, closing 60 -> gain 2,900 ETB.
	r, err := Remeasure(money.MustNew("1000", "USD"), "ETB", carrying, closing, MonetaryAsset, money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if r.GainLoss.AmountString() != "2900.00" {
		t.Fatalf("asset gain %s", r.GainLoss)
	}
	// Same exposure as a payable (liability) -> loss 2,900 ETB.
	r, err = Remeasure(money.MustNew("1000", "USD"), "ETB", carrying, closing, MonetaryLiability, money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if r.GainLoss.AmountString() != "-2900.00" {
		t.Fatalf("liability loss %s", r.GainLoss)
	}
	if _, err := Remeasure(money.MustNew("1", "USD"), "ETB", decimal.Zero, closing, MonetaryAsset, ""); err == nil {
		t.Fatal("expected carrying rate error")
	}
	if _, err := Remeasure(money.MustNew("1", "USD"), "ETB", carrying, closing, "EQUITY", ""); err == nil {
		t.Fatal("expected class error")
	}
}

func TestSnapshotValidate(t *testing.T) {
	good := usdEtb[0]
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Rate = decimal.Zero
	if err := bad.Validate(); err == nil {
		t.Fatal("zero rate accepted")
	}
	bad = good
	bad.QuoteCurrency = "USD"
	if err := bad.Validate(); err == nil {
		t.Fatal("same pair accepted")
	}
	bad = good
	bad.CapturedAtUTC = bad.PublishedAtUTC.Add(-time.Hour)
	if err := bad.Validate(); err == nil {
		t.Fatal("captured-before-published accepted")
	}
}

func TestDeterministicTieBreak(t *testing.T) {
	a := snap("zz", "NBE", "USD", "ETB", "1", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", StatusApproved, RateOfficial)
	b := snap("aa", "NBE", "USD", "ETB", "2", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", StatusApproved, RateOfficial)
	s1, _ := Select([]Snapshot{a, b}, "USD", "ETB", ts("2026-09-02T00:00:00Z"), time.Time{}, Policy{})
	s2, _ := Select([]Snapshot{b, a}, "USD", "ETB", ts("2026-09-02T00:00:00Z"), time.Time{}, Policy{})
	if s1.Snapshot.SnapshotID != s2.Snapshot.SnapshotID || s1.Snapshot.SnapshotID != "aa" {
		t.Fatalf("selection depends on input order: %s vs %s", s1.Snapshot.SnapshotID, s2.Snapshot.SnapshotID)
	}
}
