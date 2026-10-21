package evm

import (
	"errors"
	"testing"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

func d(s string) decimal.Decimal { return decimal.RequireFromString(s) }

func TestDeflateToBaseline(t *testing.T) {
	items := []CostItem{
		{Amount: money.MustNew("1000.00", "ETB"), Index: IndexPoint{d("100")}},
		{Amount: money.MustNew("1200.00", "ETB"), Index: IndexPoint{d("120")}}, // 20% inflation -> 1000 real
		{Amount: money.MustNew("1500.00", "ETB"), Index: IndexPoint{d("150")}}, // -> 1000 real
	}
	real, err := DeflateToBaseline(items, IndexPoint{d("100")}, "ETB", money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if real.AmountString() != "3000.00" {
		t.Fatalf("real AC %s", real)
	}
	if _, err := DeflateToBaseline(items, IndexPoint{d("0")}, "ETB", ""); !errors.Is(err, ErrBadIndex) {
		t.Fatal("zero baseline accepted")
	}
	items[1].Index.Value = d("-1")
	if _, err := DeflateToBaseline(items, IndexPoint{d("100")}, "ETB", ""); !errors.Is(err, ErrBadIndex) {
		t.Fatal("negative index accepted")
	}
}

func TestComputeAndZeroDenominatorPolicy(t *testing.T) {
	in := Input{
		Currency: "ETB", Basis: ConstantBaseline, Rounding: money.RoundHalfEven,
		Packages: []WorkPackage{
			{ID: "WP1", BAC: money.MustNew("100000.00", "ETB"), PlannedCompletion: d("0.5"), VerifiedCompletion: d("0.4")},
			{ID: "WP2", BAC: money.MustNew("50000.00", "ETB"), PlannedCompletion: d("0.2"), VerifiedCompletion: d("0.2")},
		},
		ActualCost: money.MustNew("55000.00", "ETB"),
	}
	r, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	// PV = 50000 + 10000 = 60000 ; EV = 40000 + 10000 = 50000
	if r.PV.AmountString() != "60000.00" || r.EV.AmountString() != "50000.00" {
		t.Fatalf("PV %s EV %s", r.PV, r.EV)
	}
	if r.CV.AmountString() != "-5000.00" || r.SV.AmountString() != "-10000.00" {
		t.Fatalf("CV %s SV %s", r.CV, r.SV)
	}
	if r.CPI == nil || r.CPI.String() != "0.909091" || r.SPI == nil || r.SPI.String() != "0.833333" {
		t.Fatalf("CPI %v SPI %v", r.CPI, r.SPI)
	}
	// Zero AC and zero PV: indices undefined, not infinite/zero.
	in.ActualCost = money.MustNew("0", "ETB")
	for i := range in.Packages {
		in.Packages[i].PlannedCompletion = decimal.Zero
	}
	r, err = Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if r.CPI != nil || r.SPI != nil {
		t.Fatal("zero denominators must yield nil indices")
	}
	in.Packages[0].VerifiedCompletion = d("1.5")
	if _, err := Compute(in); !errors.Is(err, ErrBadCompletion) {
		t.Fatal("completion >1 accepted")
	}
}

func TestBasisGuards(t *testing.T) {
	a := Result{Basis: Nominal}
	b := Result{Basis: ConstantBaseline}
	if err := Compare(a, b); !errors.Is(err, ErrBasisMismatch) {
		t.Fatal("cross-basis comparison allowed")
	}
	if _, err := Compute(Input{Currency: "ETB", Basis: "REAL?", ActualCost: money.MustNew("1", "ETB")}); !errors.Is(err, ErrBasisMismatch) {
		t.Fatal("unknown basis accepted")
	}
	if _, err := Compute(Input{Currency: "ETB", Basis: Nominal, ActualCost: money.MustNew("1", "USD")}); err == nil {
		t.Fatal("AC currency mismatch accepted")
	}
}

func TestCostToCost(t *testing.T) {
	p, err := CostToCostProgress(money.MustNew("250000", "ETB"), money.MustNew("1000000", "ETB"))
	if err != nil || p.String() != "0.25" {
		t.Fatalf("progress %s %v", p, err)
	}
	p, _ = CostToCostProgress(money.MustNew("1200000", "ETB"), money.MustNew("1000000", "ETB"))
	if !p.Equal(decimal.NewFromInt(1)) {
		t.Fatalf("overrun not capped: %s", p)
	}
	if _, err := CostToCostProgress(money.MustNew("1", "ETB"), money.MustNew("0", "ETB")); !errors.Is(err, ErrZeroDenominator) {
		t.Fatal("zero EAC accepted")
	}
	if _, err := CostToCostProgress(money.MustNew("1", "ETB"), money.MustNew("5", "USD")); err == nil {
		t.Fatal("currency mismatch accepted")
	}
}

// SC-09: under 50% inflation a project exactly on budget in real terms must
// show CPI = 1 and CV = 0 whichever correct conversion is used, and the
// mixed-basis computation that would report CPI = 0.67 is refused.
func TestSC09_InflationDoesNotMasqueradeAsOverrun(t *testing.T) {
	p0, pt := IndexPoint{d("100")}, IndexPoint{d("150")}
	wps := []WorkPackage{{ID: "STRUCTURE", BAC: money.MustNew("1000000.00", "ETB"), PlannedCompletion: d("0.5"), VerifiedCompletion: d("0.5")}}
	// Half the work done; it cost 500,000 at baseline prices = 750,000 nominal at Pt=150.
	nominalAC := money.MustNew("750000.00", "ETB")

	_, err := Compute(Input{Currency: "ETB", BudgetBasis: ConstantBaseline, Basis: Nominal, Packages: wps, ActualCost: nominalAC})
	if !errors.Is(err, ErrBasisMismatch) {
		t.Fatalf("mixed-basis CPI computed: %v", err)
	}

	realAC, err := DeflateToBaseline([]CostItem{{Amount: nominalAC, Index: pt}}, p0, "ETB", money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compute(Input{Currency: "ETB", BudgetBasis: ConstantBaseline, Basis: ConstantBaseline, Packages: wps, ActualCost: realAC,
		Provenance: Provenance{BaselineVersion: "BL-1", BaselineIndex: p0.Value, Method: "DEFLATE_ACTUALS"}})
	if err != nil {
		t.Fatal(err)
	}
	restated, err := RestateBudget(wps, p0, pt, money.RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compute(Input{Currency: "ETB", BudgetBasis: Nominal, Basis: Nominal, Packages: restated, ActualCost: nominalAC,
		Provenance: Provenance{BaselineVersion: "BL-1", BaselineIndex: p0.Value, CurrentIndex: pt.Value, Method: "RESTATE_BUDGET"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]Result{"deflated actuals": a, "restated budget": b} {
		if r.CPI == nil || !r.CPI.Equal(d("1")) || !r.CV.IsZero() {
			t.Errorf("%s: CPI %v CV %s (want 1 and 0)", name, r.CPI, r.CV)
		}
	}
	if a.Provenance.Method != "DEFLATE_ACTUALS" || b.Provenance.CurrentIndex.String() != "150" || a.AlgorithmVersion != "evm-v2" {
		t.Fatalf("provenance not carried: %+v %+v", a.Provenance, b.Provenance)
	}
	// A genuine overrun stays visible after conversion: 900,000 nominal = 600,000 real.
	over, _ := DeflateToBaseline([]CostItem{{Amount: money.MustNew("900000.00", "ETB"), Index: pt}}, p0, "ETB", money.RoundHalfEven)
	r, _ := Compute(Input{Currency: "ETB", BudgetBasis: ConstantBaseline, Basis: ConstantBaseline, Packages: wps, ActualCost: over})
	if r.CPI.String() != "0.833333" || r.CV.AmountString() != "-100000.00" {
		t.Fatalf("real overrun hidden: CPI %v CV %s", r.CPI, r.CV)
	}
	if _, err := RestateBudget(wps, IndexPoint{d("0")}, pt, money.RoundHalfEven); !errors.Is(err, ErrBadIndex) {
		t.Fatal("zero index accepted")
	}
}
