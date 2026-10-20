package tax

import (
	"errors"
	"testing"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

func d(s string) decimal.Decimal { return decimal.RequireFromString(s) }
func day(y, m, dd int) time.Time { return time.Date(y, time.Month(m), dd, 0, 0, 0, 0, time.UTC) }

// Illustrative rule data for tests ONLY. Real rates are loaded from the
// approved jurisdiction configuration; nothing here asserts actual law.
func rules() []Rule {
	to := day(2026, 1, 1)
	return []Rule{
		{RuleID: "ET-VAT-OUT-2019", Jurisdiction: "ET", LegalAuthorityReference: "TEST-REF-1", TaxType: VATOutput,
			TaxableTransactionType: "ANY", TaxpayerClassification: "REGISTERED", Rate: d("0.15"),
			EffectiveFrom: day(2019, 1, 1), EffectiveTo: &to, TaxBaseDefinition: "NET",
			ExemptionConditions: []string{"EXPORT"}, ReviewStatus: ReviewApproved, ApprovedBy: "tax-lead"},
		{RuleID: "ET-VAT-OUT-2026", Jurisdiction: "ET", LegalAuthorityReference: "TEST-REF-2", TaxType: VATOutput,
			TaxableTransactionType: "ANY", TaxpayerClassification: "REGISTERED", Rate: d("0.16"),
			EffectiveFrom: day(2026, 1, 1), TaxBaseDefinition: "NET",
			ExemptionConditions: []string{"EXPORT"}, ReviewStatus: ReviewApproved, ApprovedBy: "tax-lead"},
		{RuleID: "ET-VAT-OUT-DRAFT", Jurisdiction: "ET", LegalAuthorityReference: "TEST-REF-3", TaxType: VATOutput,
			TaxableTransactionType: "ANY", TaxpayerClassification: "REGISTERED", Rate: d("0.99"),
			EffectiveFrom: day(2020, 1, 1), TaxBaseDefinition: "NET", ReviewStatus: ReviewDraft},
		{RuleID: "ET-WHT-SERVICES", Jurisdiction: "ET", LegalAuthorityReference: "TEST-REF-4", TaxType: Withholding,
			TaxableTransactionType: "CONSTRUCTION_SERVICE", TaxpayerClassification: "ANY", Rate: d("0.02"),
			EffectiveFrom: day(2019, 1, 1), TaxBaseDefinition: "NET",
			ThresholdAmount: ptr(money.MustNew("3000.00", "ETB")), Recoverability: NonRecoverable,
			ReviewStatus: ReviewApproved, ApprovedBy: "tax-lead"},
		{RuleID: "ET-VAT-IN-GROSS", Jurisdiction: "ET", LegalAuthorityReference: "TEST-REF-5", TaxType: VATInput,
			TaxableTransactionType: "ANY", TaxpayerClassification: "ANY", Rate: d("0.15"),
			EffectiveFrom: day(2019, 1, 1), TaxBaseDefinition: "GROSS", Recoverability: PartialRecovery, RecoveryRatio: d("0.5"),
			ReviewStatus: ReviewApproved, ApprovedBy: "tax-lead"},
		{RuleID: "KE-VAT-OUT", Jurisdiction: "KE", LegalAuthorityReference: "TEST-REF-6", TaxType: VATOutput,
			TaxableTransactionType: "ANY", TaxpayerClassification: "ANY", Rate: d("0.16"),
			EffectiveFrom: day(2019, 1, 1), TaxBaseDefinition: "NET", ReviewStatus: ReviewApproved, ApprovedBy: "tax-lead"},
	}
}

func ptr(m money.Money) *money.Money { return &m }

func TestRulesValidate(t *testing.T) {
	for _, r := range rules() {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", r.RuleID, err)
		}
	}
	bad := rules()[0]
	bad.Rate = d("1.5")
	if err := bad.Validate(); err == nil {
		t.Fatal("rate >1 accepted")
	}
	bad = rules()[0]
	bad.ApprovedBy = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("approved rule without approver accepted")
	}
	bad = rules()[0]
	bad.RoundingRule = "NOPE"
	if err := bad.Validate(); err == nil {
		t.Fatal("bad rounding accepted")
	}
}

func TestEffectiveDatingAndReviewStatus(t *testing.T) {
	q := Query{Jurisdiction: "ET", TaxType: VATOutput, TaxableTransactionType: "GOODS_SUPPLY", TaxpayerClassification: "REGISTERED"}
	q.EventAt = day(2025, 12, 31)
	r, err := Resolve(rules(), q)
	if err != nil || r.RuleID != "ET-VAT-OUT-2019" {
		t.Fatalf("2025 event: %v %v", r.RuleID, err)
	}
	q.EventAt = day(2026, 1, 1)
	r, err = Resolve(rules(), q)
	if err != nil || r.RuleID != "ET-VAT-OUT-2026" {
		t.Fatalf("2026 event: %v %v (draft rule must never win)", r.RuleID, err)
	}
	q.EventAt = day(2018, 6, 1)
	if _, err := Resolve(rules(), q); !errors.Is(err, ErrNoRule) {
		t.Fatalf("pre-effective event resolved: %v", err)
	}
	q.Jurisdiction = "UG"
	q.EventAt = day(2026, 6, 1)
	if _, err := Resolve(rules(), q); !errors.Is(err, ErrNoRule) {
		t.Fatal("foreign jurisdiction rule applied")
	}
}

func TestAmbiguityIsAnError(t *testing.T) {
	rs := rules()
	dup := rs[1]
	dup.RuleID = "ET-VAT-OUT-2026-DUP"
	rs = append(rs, dup)
	q := Query{Jurisdiction: "ET", TaxType: VATOutput, TaxableTransactionType: "GOODS_SUPPLY", TaxpayerClassification: "REGISTERED", EventAt: day(2026, 6, 1)}
	if _, err := Resolve(rs, q); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous config silently resolved: %v", err)
	}
}

func TestComputeNetBase(t *testing.T) {
	r, _ := Resolve(rules(), Query{Jurisdiction: "ET", TaxType: VATOutput, TaxableTransactionType: "GOODS_SUPPLY", TaxpayerClassification: "REGISTERED", EventAt: day(2026, 6, 1)})
	c, err := Compute(r, money.MustNew("1234.56", "ETB"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// 1234.56 * 0.16 = 197.5296 -> 197.53 (HALF_UP default)
	if c.Tax.AmountString() != "197.53" || c.Gross.AmountString() != "1432.09" || c.Exempt {
		t.Fatalf("%+v", c)
	}
	// Export exemption from attributes.
	c, err = Compute(r, money.MustNew("1234.56", "ETB"), []string{"EXPORT"})
	if err != nil || !c.Exempt || !c.Tax.IsZero() || c.ExemptionReason != "EXPORT" {
		t.Fatalf("exemption not applied: %+v %v", c, err)
	}
	if _, err := Compute(r, money.MustNew("-1", "ETB"), nil); err == nil {
		t.Fatal("negative base accepted")
	}
	draft := rules()[2]
	if _, err := Compute(draft, money.MustNew("1", "ETB"), nil); err == nil {
		t.Fatal("draft rule computed")
	}
}

func TestComputeGrossBaseIsExact(t *testing.T) {
	r, _ := Resolve(rules(), Query{Jurisdiction: "ET", TaxType: VATInput, TaxableTransactionType: "GOODS_SUPPLY", TaxpayerClassification: "REGISTERED", EventAt: day(2026, 6, 1)})
	c, err := Compute(r, money.MustNew("115.00", "ETB"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// base = 115/1.15 = 100.00; tax = 15.00; base + tax == gross exactly
	if c.Base.AmountString() != "100.00" || c.Tax.AmountString() != "15.00" {
		t.Fatalf("%+v", c)
	}
	sum, _ := c.Base.Add(c.Tax)
	if !sum.Equal(c.Gross) {
		t.Fatalf("base+tax %s != gross %s", sum, c.Gross)
	}
	if c.Recoverable.AmountString() != "7.50" || c.NonRecoverable.AmountString() != "7.50" {
		t.Fatalf("partial recovery wrong: %+v", c)
	}
	// Awkward gross where division rounds: 100.01 / 1.15 = 86.965... -> 86.97; tax = 13.04; sum stays exact.
	c, _ = Compute(r, money.MustNew("100.01", "ETB"), nil)
	sum, _ = c.Base.Add(c.Tax)
	if !sum.Equal(c.Gross) {
		t.Fatalf("gross extraction lost money: %+v", c)
	}
}

func TestThreshold(t *testing.T) {
	r, _ := Resolve(rules(), Query{Jurisdiction: "ET", TaxType: Withholding, TaxableTransactionType: "CONSTRUCTION_SERVICE", TaxpayerClassification: "UNREGISTERED", EventAt: day(2026, 6, 1)})
	c, _ := Compute(r, money.MustNew("2999.99", "ETB"), nil)
	if !c.Exempt || c.ExemptionReason != "BELOW_THRESHOLD" {
		t.Fatalf("threshold not applied: %+v", c)
	}
	c, _ = Compute(r, money.MustNew("3000.00", "ETB"), nil)
	if c.Exempt || c.Tax.AmountString() != "60.00" || !c.NonRecoverable.Equal(c.Tax) {
		t.Fatalf("at-threshold wrong: %+v", c)
	}
	if _, err := Compute(r, money.MustNew("3000.00", "USD"), nil); err == nil {
		t.Fatal("threshold currency mismatch accepted")
	}
}
