package money

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/shopspring/decimal"
)

// RoundingPolicy is a named, versioned rounding rule. The policy identifier
// is recorded with every posted amount (LAW 06: provenance).
type RoundingPolicy string

const (
	// RoundHalfEven (banker's rounding) is the kernel default for
	// accounting postings: it is unbiased over many transactions.
	RoundHalfEven RoundingPolicy = "HALF_EVEN"
	// RoundHalfUp is the commercial/tax-authority rule most African tax
	// administrations prescribe for invoice-level rounding.
	RoundHalfUp RoundingPolicy = "HALF_UP"
	// RoundDown truncates toward zero; used by some customs tariff schedules.
	RoundDown RoundingPolicy = "DOWN"
	// RoundUp rounds away from zero; used for some fee schedules.
	RoundUp RoundingPolicy = "UP"
)

// DefaultRounding is the policy used when none is specified.
const DefaultRounding = RoundHalfEven

var (
	// ErrInvalidAmount is returned when an amount string cannot be parsed.
	ErrInvalidAmount = errors.New("money: invalid amount")
	// ErrUnknownRounding is returned for an unrecognised policy identifier.
	ErrUnknownRounding = errors.New("money: unknown rounding policy")
	// ErrNegativeNotAllowed is returned where a non-negative amount is required.
	ErrNegativeNotAllowed = errors.New("money: negative amount not allowed")
)

// Money is an exact monetary amount in a single currency, always quantised
// to the currency's minor units. The zero value is not valid; construct via
// New, Parse, or FromMinor.
type Money struct {
	amount   decimal.Decimal
	currency Currency
}

// ApplyRounding quantises d to `places` decimal places under the policy.
func ApplyRounding(d decimal.Decimal, places int32, policy RoundingPolicy) (decimal.Decimal, error) {
	switch policy {
	case "", RoundHalfEven:
		return d.RoundBank(places), nil
	case RoundHalfUp:
		return d.Round(places), nil // shopspring Round is half away from zero
	case RoundDown:
		return d.RoundDown(places), nil
	case RoundUp:
		return d.RoundUp(places), nil
	default:
		return decimal.Zero, fmt.Errorf("%w: %q", ErrUnknownRounding, policy)
	}
}

// New builds Money from an exact decimal, quantising under the policy.
func New(d decimal.Decimal, cur Currency, policy RoundingPolicy) (Money, error) {
	info, err := Lookup(cur)
	if err != nil {
		return Money{}, err
	}
	q, err := ApplyRounding(d, info.MinorUnits, policy)
	if err != nil {
		return Money{}, err
	}
	return Money{amount: q, currency: info.Code}, nil
}

// MustNew is New for literals in tests and configuration; panics on error.
func MustNew(s string, cur Currency) Money {
	m, err := Parse(s, cur, DefaultRounding)
	if err != nil {
		panic(err)
	}
	return m
}

// Parse parses a decimal string into Money.
func Parse(s string, cur Currency, policy RoundingPolicy) (Money, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Money{}, fmt.Errorf("%w: empty", ErrInvalidAmount)
	}
	d, err := decimal.NewFromString(s)
	if err != nil {
		return Money{}, fmt.Errorf("%w: %q", ErrInvalidAmount, s)
	}
	return New(d, cur, policy)
}

// FromMinor builds Money from an integer count of minor units (e.g. cents).
func FromMinor(minor int64, cur Currency) (Money, error) {
	info, err := Lookup(cur)
	if err != nil {
		return Money{}, err
	}
	return Money{amount: decimal.New(minor, -info.MinorUnits), currency: info.Code}, nil
}

// Zero returns a zero amount in the currency.
func Zero(cur Currency) (Money, error) {
	return FromMinor(0, cur)
}

// Amount returns the exact decimal value.
func (m Money) Amount() decimal.Decimal { return m.amount }

// Currency returns the currency code.
func (m Money) Currency() Currency { return m.currency }

// IsZero reports whether the amount is zero.
func (m Money) IsZero() bool { return m.amount.IsZero() }

// IsNegative reports whether the amount is below zero.
func (m Money) IsNegative() bool { return m.amount.IsNegative() }

// IsPositive reports whether the amount is above zero.
func (m Money) IsPositive() bool { return m.amount.IsPositive() }

// IsValid reports whether the value was constructed properly.
func (m Money) IsValid() bool { return m.currency != "" }

// String renders as "<amount> <CUR>" with fixed minor-unit scale.
func (m Money) String() string {
	info, err := Lookup(m.currency)
	if err != nil {
		return m.amount.String() + " " + string(m.currency)
	}
	return m.amount.StringFixed(info.MinorUnits) + " " + string(m.currency)
}

// AmountString renders only the fixed-scale amount.
func (m Money) AmountString() string {
	info, err := Lookup(m.currency)
	if err != nil {
		return m.amount.String()
	}
	return m.amount.StringFixed(info.MinorUnits)
}

// MinorInt64 returns the amount expressed in minor units.
func (m Money) MinorInt64() int64 {
	info, _ := Lookup(m.currency)
	return m.amount.Shift(info.MinorUnits).IntPart()
}

func (m Money) check(o Money) error {
	if m.currency != o.currency {
		return fmt.Errorf("%w: %s vs %s", ErrCurrencyMismatch, m.currency, o.currency)
	}
	return nil
}

// Add returns m + o. Both operands are already quantised, so no rounding occurs.
func (m Money) Add(o Money) (Money, error) {
	if err := m.check(o); err != nil {
		return Money{}, err
	}
	return Money{amount: m.amount.Add(o.amount), currency: m.currency}, nil
}

// Sub returns m - o.
func (m Money) Sub(o Money) (Money, error) {
	if err := m.check(o); err != nil {
		return Money{}, err
	}
	return Money{amount: m.amount.Sub(o.amount), currency: m.currency}, nil
}

// Neg returns -m.
func (m Money) Neg() Money { return Money{amount: m.amount.Neg(), currency: m.currency} }

// Abs returns |m|.
func (m Money) Abs() Money { return Money{amount: m.amount.Abs(), currency: m.currency} }

// Mul multiplies by an exact factor and re-quantises under the policy.
func (m Money) Mul(factor decimal.Decimal, policy RoundingPolicy) (Money, error) {
	return New(m.amount.Mul(factor), m.currency, policy)
}

// Div divides by an exact divisor and re-quantises under the policy.
func (m Money) Div(divisor decimal.Decimal, policy RoundingPolicy) (Money, error) {
	if divisor.IsZero() {
		return Money{}, errors.New("money: division by zero")
	}
	// 16 guard digits before quantisation keeps the result exact for any
	// realistic currency scale (max 6) and ratio magnitude.
	return New(m.amount.DivRound(divisor, 16), m.currency, policy)
}

// Cmp compares two amounts: -1, 0, +1.
func (m Money) Cmp(o Money) (int, error) {
	if err := m.check(o); err != nil {
		return 0, err
	}
	return m.amount.Cmp(o.amount), nil
}

// Equal reports whether both currency and amount match.
func (m Money) Equal(o Money) bool {
	return m.currency == o.currency && m.amount.Equal(o.amount)
}

// Allocate splits m across the given integer ratios using the largest-
// remainder method, guaranteeing that the parts sum exactly to m with no
// lost or invented minor units. Deterministic: ties are broken by index.
func (m Money) Allocate(ratios []int64) ([]Money, error) {
	if len(ratios) == 0 {
		return nil, errors.New("money: no allocation ratios")
	}
	var total int64
	for _, r := range ratios {
		if r < 0 {
			return nil, errors.New("money: negative allocation ratio")
		}
		total += r
	}
	if total == 0 {
		return nil, errors.New("money: allocation ratios sum to zero")
	}
	info, err := Lookup(m.currency)
	if err != nil {
		return nil, err
	}
	whole := m.amount.Shift(info.MinorUnits).IntPart() // minor units
	sign := int64(1)
	if whole < 0 {
		sign = -1
		whole = -whole
	}
	parts := make([]int64, len(ratios))
	rem := make([]int64, len(ratios))
	var distributed int64
	for i, r := range ratios {
		parts[i] = whole * r / total
		rem[i] = whole * r % total
		distributed += parts[i]
	}
	left := whole - distributed
	// Hand out the leftover minor units to the largest remainders first.
	for left > 0 {
		best := -1
		for i := range rem {
			if best == -1 || rem[i] > rem[best] {
				best = i
			}
		}
		parts[best]++
		rem[best] = -1
		left--
	}
	out := make([]Money, len(parts))
	for i, p := range parts {
		out[i] = Money{amount: decimal.New(sign*p, -info.MinorUnits), currency: m.currency}
	}
	return out, nil
}

// Sum adds a slice of amounts, all of which must share a currency.
func Sum(cur Currency, ms ...Money) (Money, error) {
	acc, err := Zero(cur)
	if err != nil {
		return Money{}, err
	}
	for _, m := range ms {
		acc, err = acc.Add(m)
		if err != nil {
			return Money{}, err
		}
	}
	return acc, nil
}

type jsonMoney struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

// MarshalJSON encodes as {"amount":"123.45","currency":"ETB"}.
func (m Money) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonMoney{Amount: m.AmountString(), Currency: string(m.currency)})
}

var plainDecimal = regexp.MustCompile(`^-?[0-9]{1,18}(\.[0-9]{1,6})?$`)

// ParseStrict parses an amount that must already be expressed in the
// currency's minor units: plain decimal notation only (no exponent, no
// leading '+'), and no more fractional digits than the currency allows.
// External input is never silently rounded.
func ParseStrict(s string, cur Currency) (Money, error) {
	if !plainDecimal.MatchString(s) {
		return Money{}, fmt.Errorf("%w: %q is not a plain decimal", ErrInvalidAmount, s)
	}
	info, err := Lookup(cur)
	if err != nil {
		return Money{}, err
	}
	if i := strings.IndexByte(s, '.'); i >= 0 && int32(len(s)-i-1) > info.MinorUnits {
		return Money{}, fmt.Errorf("%w: %q has more decimals than %s allows (%d)", ErrInvalidAmount, s, info.Code, info.MinorUnits)
	}
	return Parse(s, info.Code, RoundHalfEven)
}

// UnmarshalJSON decodes the canonical JSON form strictly (see ParseStrict).
func (m *Money) UnmarshalJSON(b []byte) error {
	var j jsonMoney
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	v, err := ParseStrict(j.Amount, Currency(j.Currency))
	if err != nil {
		return err
	}
	*m = v
	return nil
}
