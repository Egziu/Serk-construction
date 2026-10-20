package money

import (
	"encoding/json"
	"testing"

	"github.com/shopspring/decimal"
)

func TestParseQuantisesToMinorUnits(t *testing.T) {
	cases := []struct {
		in, cur, policy, want string
	}{
		{"100.005", "ETB", "HALF_EVEN", "100.00"}, // banker's: 0.005 -> even (0.00)
		{"100.015", "ETB", "HALF_EVEN", "100.02"},
		{"100.005", "ETB", "HALF_UP", "100.01"},
		{"100.019", "ETB", "DOWN", "100.01"},
		{"100.011", "ETB", "UP", "100.02"},
		{"1234.5", "UGX", "HALF_EVEN", "1234"}, // zero-decimal currency, 0.5 -> even
		{"1235.5", "UGX", "HALF_EVEN", "1236"},
		{"12.3456", "TND", "HALF_EVEN", "12.346"}, // three-decimal currency
	}
	for _, c := range cases {
		m, err := Parse(c.in, Currency(c.cur), RoundingPolicy(c.policy))
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if got := m.AmountString(); got != c.want {
			t.Errorf("Parse(%s %s %s)=%s want %s", c.in, c.cur, c.policy, got, c.want)
		}
	}
}

func TestUnknownCurrencyRejected(t *testing.T) {
	if _, err := Parse("1", "XXX", DefaultRounding); err == nil {
		t.Fatal("expected unknown currency error")
	}
	if _, err := New(decimal.NewFromInt(1), "ETB", "WEIRD"); err == nil {
		t.Fatal("expected unknown rounding policy error")
	}
}

func TestCurrencyMismatch(t *testing.T) {
	a := MustNew("10", "ETB")
	b := MustNew("10", "USD")
	if _, err := a.Add(b); err == nil {
		t.Fatal("expected mismatch")
	}
	if _, err := a.Cmp(b); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestArithmeticIsExact(t *testing.T) {
	// 0.1 + 0.2 must equal 0.3 exactly (fails in float64).
	a := MustNew("0.10", "USD")
	b := MustNew("0.20", "USD")
	s, _ := a.Add(b)
	if !s.Equal(MustNew("0.30", "USD")) {
		t.Fatalf("0.1+0.2 = %s", s)
	}
	// Multiply by an FX-rate-like factor with many decimals.
	m, err := MustNew("1000.00", "USD").Mul(decimal.RequireFromString("57.4321"), RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if m.AmountString() != "57432.10" {
		t.Fatalf("got %s", m.AmountString())
	}
	d, err := MustNew("100.00", "ETB").Div(decimal.NewFromInt(3), RoundHalfEven)
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountString() != "33.33" {
		t.Fatalf("got %s", d.AmountString())
	}
	if _, err := d.Div(decimal.Zero, RoundHalfEven); err == nil {
		t.Fatal("expected division by zero error")
	}
}

func TestAllocateConservesEveryMinorUnit(t *testing.T) {
	total := MustNew("100.00", "ETB")
	parts, err := total.Allocate([]int64{1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := Sum("ETB", parts...)
	if !sum.Equal(total) {
		t.Fatalf("allocation lost money: %v sum %s", parts, sum)
	}
	// largest remainder: 33.34, 33.33, 33.33
	if parts[0].AmountString() != "33.34" || parts[1].AmountString() != "33.33" || parts[2].AmountString() != "33.33" {
		t.Fatalf("unexpected split %v", parts)
	}
	neg := MustNew("-0.05", "USD")
	np, err := neg.Allocate([]int64{3, 7})
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := Sum("USD", np...)
	if !ns.Equal(neg) {
		t.Fatalf("negative allocation lost money: %v", np)
	}
	if _, err := total.Allocate([]int64{0, 0}); err == nil {
		t.Fatal("expected zero-ratio error")
	}
	if _, err := total.Allocate([]int64{-1, 2}); err == nil {
		t.Fatal("expected negative-ratio error")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	m := MustNew("1234.5", "KES")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"amount":"1234.50","currency":"KES"}` {
		t.Fatalf("got %s", b)
	}
	var back Money
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Equal(m) {
		t.Fatalf("round trip mismatch %s vs %s", back, m)
	}
	for _, bad := range []string{`"abc"`, `"100.005"`, `"1e3"`, `"+5"`, `"5."`, `" 5"`} {
		if err := json.Unmarshal([]byte(`{"amount":`+bad+`,"currency":"KES"}`), &back); err == nil {
			t.Fatalf("strict JSON accepted %s", bad)
		}
	}
	if err := json.Unmarshal([]byte(`{"amount":"1234","currency":"UGX"}`), &back); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"amount":"1234.5","currency":"UGX"}`), &back); err == nil {
		t.Fatal("fraction accepted for zero-decimal currency")
	}
}

func TestMinorAndRegister(t *testing.T) {
	m, _ := FromMinor(12345, "ETB")
	if m.AmountString() != "123.45" || m.MinorInt64() != 12345 {
		t.Fatalf("minor conversion wrong: %s", m)
	}
	if err := Register(CurrencyInfo{Code: "zzz", MinorUnits: 2, Name: "Test"}); err != nil {
		t.Fatal(err)
	}
	if !IsKnown("ZZZ") {
		t.Fatal("registered currency not found")
	}
	if err := Register(CurrencyInfo{Code: "TOOLONG", MinorUnits: 2}); err == nil {
		t.Fatal("expected invalid code error")
	}
	if err := Register(CurrencyInfo{Code: "ABC", MinorUnits: 9}); err == nil {
		t.Fatal("expected minor-unit range error")
	}
}
