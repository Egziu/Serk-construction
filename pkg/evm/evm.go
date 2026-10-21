// Package evm implements Earned Value Management in both nominal and
// constant-purchasing-power bases (Pillar 1, §3.3).
//
// The package refuses to mix price bases: every input carries its PriceBasis
// and the calculator returns an error rather than a misleading number when
// bases are incompatible. Zero-denominator policy is explicit.
package evm

import (
	"errors"
	"fmt"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

// AlgorithmVersion is recorded on every result.
const AlgorithmVersion = "evm-v2"

// PriceBasis labels the measurement basis of an amount.
type PriceBasis string

const (
	// Nominal amounts are in the money of the day they were incurred.
	Nominal PriceBasis = "NOMINAL"
	// ConstantBaseline amounts are deflated to the baseline index P0.
	ConstantBaseline PriceBasis = "CONSTANT_BASELINE"
)

// IndexPoint is a price-index observation applicable to a cost.
type IndexPoint struct {
	Value decimal.Decimal // P_i
}

// CostItem is one nominal cost incurrence with its index at that time.
type CostItem struct {
	Amount money.Money
	Index  IndexPoint // P_i at incurrence
}

// Errors.
var (
	ErrBasisMismatch   = errors.New("evm: incompatible price bases")
	ErrZeroDenominator = errors.New("evm: zero denominator")
	ErrBadIndex        = errors.New("evm: price index must be positive")
	ErrBadCompletion   = errors.New("evm: completion must be within [0,1]")
)

// DeflateToBaseline computes AC_real,0 = Σ AC_nominal,i × P0 / Pi exactly,
// rounding only once at the end to the currency's minor units.
func DeflateToBaseline(items []CostItem, baseline IndexPoint, cur money.Currency, rounding money.RoundingPolicy) (money.Money, error) {
	if !baseline.Value.IsPositive() {
		return money.Money{}, fmt.Errorf("%w: baseline", ErrBadIndex)
	}
	acc := decimal.Zero
	for i, it := range items {
		if it.Amount.Currency() != cur {
			return money.Money{}, fmt.Errorf("evm: item %d currency %s != %s", i, it.Amount.Currency(), cur)
		}
		if !it.Index.Value.IsPositive() {
			return money.Money{}, fmt.Errorf("%w: item %d", ErrBadIndex, i)
		}
		// 20 guard digits before the single final rounding.
		acc = acc.Add(it.Amount.Amount().Mul(baseline.Value).DivRound(it.Index.Value, 20))
	}
	return money.New(acc, cur, rounding)
}

// WorkPackage is a baseline-budgeted scope element at a reporting date.
type WorkPackage struct {
	ID                 string
	BAC                money.Money     // budget at completion, baseline prices
	PlannedCompletion  decimal.Decimal // 0..1 at date t
	VerifiedCompletion decimal.Decimal // 0..1 at date t, from verified measurement
}

// Provenance records how amounts were brought to a common price basis.
type Provenance struct {
	BaselineVersion string          // approved budget baseline the BAC comes from
	BaselineIndex   decimal.Decimal // P0
	CurrentIndex    decimal.Decimal // Pt (for current-price restatement)
	IndexSeries     string          // e.g. "ET-CSA-CONSTRUCTION-INPUT"
	Method          string          // "DEFLATE_ACTUALS" | "RESTATE_BUDGET" | "NONE"
}

// Input bundles everything needed for one EVM computation.
type Input struct {
	Currency money.Currency
	// BudgetBasis is the price basis of every BAC (normally ConstantBaseline).
	BudgetBasis PriceBasis
	// Basis is the price basis of ActualCost. It must equal BudgetBasis
	// (SC-09): bring actuals to baseline prices with DeflateToBaseline, or
	// restate the budget at current prices with RestateBudget.
	Basis      PriceBasis
	Packages   []WorkPackage
	ActualCost money.Money
	Rounding   money.RoundingPolicy
	Provenance Provenance
}

// Result is the EVM output. Indices are nil when undefined by policy.
type Result struct {
	Basis              PriceBasis
	PV, EV, AC, CV, SV money.Money
	CPI, SPI           *decimal.Decimal
	Provenance         Provenance
	AlgorithmVersion   string
}

// Compute evaluates PV, EV, CV, SV, CPI and SPI.
//
// Basis policy (SC-09): PV and EV inherit the budget's price basis and AC
// must be expressed in that same basis; mixed inputs are refused rather than
// producing a precise but economically meaningless CPI. In an inflationary
// economy, comparing a baseline-priced EV with nominal actual cost would make
// an on-budget project look over budget.
//
// Zero-denominator policy: CPI is nil when AC = 0; SPI is nil when PV = 0.
func Compute(in Input) (Result, error) {
	if in.BudgetBasis == "" {
		in.BudgetBasis = ConstantBaseline
	}
	for _, b := range []PriceBasis{in.Basis, in.BudgetBasis} {
		if b != Nominal && b != ConstantBaseline {
			return Result{}, fmt.Errorf("%w: unknown basis %q", ErrBasisMismatch, b)
		}
	}
	if in.Basis != in.BudgetBasis {
		return Result{}, fmt.Errorf("%w: actual cost is %s but the budget is %s; deflate actuals (DeflateToBaseline) or restate the budget (RestateBudget) first",
			ErrBasisMismatch, in.Basis, in.BudgetBasis)
	}
	if in.ActualCost.Currency() != in.Currency {
		return Result{}, fmt.Errorf("%w: AC currency", ErrBasisMismatch)
	}
	pv, ev := decimal.Zero, decimal.Zero
	one := decimal.NewFromInt(1)
	for _, wp := range in.Packages {
		if wp.BAC.Currency() != in.Currency {
			return Result{}, fmt.Errorf("evm: package %s currency %s != %s", wp.ID, wp.BAC.Currency(), in.Currency)
		}
		for _, c := range []decimal.Decimal{wp.PlannedCompletion, wp.VerifiedCompletion} {
			if c.IsNegative() || c.GreaterThan(one) {
				return Result{}, fmt.Errorf("%w: package %s", ErrBadCompletion, wp.ID)
			}
		}
		pv = pv.Add(wp.BAC.Amount().Mul(wp.PlannedCompletion))
		ev = ev.Add(wp.BAC.Amount().Mul(wp.VerifiedCompletion))
	}
	PV, err := money.New(pv, in.Currency, in.Rounding)
	if err != nil {
		return Result{}, err
	}
	EV, err := money.New(ev, in.Currency, in.Rounding)
	if err != nil {
		return Result{}, err
	}
	CV, err := EV.Sub(in.ActualCost)
	if err != nil {
		return Result{}, err
	}
	SV, err := EV.Sub(PV)
	if err != nil {
		return Result{}, err
	}
	res := Result{Basis: in.Basis, PV: PV, EV: EV, AC: in.ActualCost, CV: CV, SV: SV, Provenance: in.Provenance, AlgorithmVersion: AlgorithmVersion}
	if !in.ActualCost.IsZero() {
		cpi := EV.Amount().DivRound(in.ActualCost.Amount(), 6)
		res.CPI = &cpi
	}
	if !PV.IsZero() {
		spi := EV.Amount().DivRound(PV.Amount(), 6)
		res.SPI = &spi
	}
	return res, nil
}

// Compare guards reports: it refuses to subtract or ratio two results of
// different bases.
func Compare(a, b Result) error {
	if a.Basis != b.Basis {
		return fmt.Errorf("%w: %s vs %s", ErrBasisMismatch, a.Basis, b.Basis)
	}
	return nil
}

// CostToCostProgress computes Progress = EligibleCostToDate / LatestEAC for
// percentage-of-completion revenue measurement. It is a measurement input to a
// policy-controlled close process, never an automatic posting.
func CostToCostProgress(eligibleCostToDate, latestEAC money.Money) (decimal.Decimal, error) {
	if eligibleCostToDate.Currency() != latestEAC.Currency() {
		return decimal.Zero, money.ErrCurrencyMismatch
	}
	if latestEAC.IsZero() || latestEAC.IsNegative() {
		return decimal.Zero, ErrZeroDenominator
	}
	if eligibleCostToDate.IsNegative() {
		return decimal.Zero, errors.New("evm: cost to date cannot be negative")
	}
	p := eligibleCostToDate.Amount().DivRound(latestEAC.Amount(), 8)
	if p.GreaterThan(decimal.NewFromInt(1)) {
		p = decimal.NewFromInt(1) // capped: cost overrun does not create >100% progress
	}
	return p, nil
}

// RestateBudget restates baseline-priced BACs at the current price level:
// BAC_t = BAC_0 × Pt / P0, rounded once per package. Completion percentages
// are unchanged. The result is a Nominal (current-price) budget suitable for
// comparison with nominal actual cost, with the indices recorded.
func RestateBudget(pkgs []WorkPackage, baseline, current IndexPoint, rounding money.RoundingPolicy) ([]WorkPackage, error) {
	if !baseline.Value.IsPositive() || !current.Value.IsPositive() {
		return nil, ErrBadIndex
	}
	out := make([]WorkPackage, len(pkgs))
	for i, wp := range pkgs {
		bac, err := money.New(wp.BAC.Amount().Mul(current.Value).DivRound(baseline.Value, 20), wp.BAC.Currency(), rounding)
		if err != nil {
			return nil, err
		}
		out[i] = wp
		out[i].BAC = bac
	}
	return out, nil
}
