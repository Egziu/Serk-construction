// Package tax implements the VAT / WHT / local tax rules engine (Pillar 1,
// §3.5). Rules are data: jurisdiction-scoped, effective-dated, reviewed and
// approved records. No rate is hardcoded in this package.
package tax

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

// AlgorithmVersion is recorded on every computation.
const AlgorithmVersion = "tax-eval-v1"

// Type of tax.
type Type string

const (
	VATOutput          Type = "VAT_OUTPUT"
	VATInput           Type = "VAT_INPUT"
	Withholding        Type = "WHT"
	ImportDuty         Type = "IMPORT_DUTY"
	Excise             Type = "EXCISE"
	CustomsVAT         Type = "CUSTOMS_VAT"
	PayrollWithholding Type = "PAYROLL_WHT"
)

// ReviewStatus of a rule. Only APPROVED rules are evaluated.
type ReviewStatus string

const (
	ReviewDraft    ReviewStatus = "DRAFT"
	ReviewApproved ReviewStatus = "APPROVED"
	ReviewRetired  ReviewStatus = "RETIRED"
)

// Recoverability of input taxes.
type Recoverability string

const (
	FullyRecoverable Recoverability = "FULL"
	NonRecoverable   Recoverability = "NONE"
	PartialRecovery  Recoverability = "PARTIAL" // uses RecoveryRatio
)

// Rule mirrors the specification's required tax-rule fields.
type Rule struct {
	RuleID                  string
	Jurisdiction            string // ISO 3166-1 alpha-2, e.g. "ET"
	LegalAuthorityReference string // e.g. "Proclamation 1341/2024 Art. 7"
	TaxType                 Type
	TaxableTransactionType  string          // e.g. "GOODS_SUPPLY", "CONSTRUCTION_SERVICE"
	TaxpayerClassification  string          // e.g. "REGISTERED", "UNREGISTERED", "ANY"
	Rate                    decimal.Decimal // 0.15 for 15 %
	EffectiveFrom           time.Time
	EffectiveTo             *time.Time // nil = open-ended
	TaxBaseDefinition       string     // "NET" (exclusive), "GROSS" (inclusive)
	ExemptionConditions     []string   // attribute codes that exempt the transaction
	Recoverability          Recoverability
	RecoveryRatio           decimal.Decimal // for PARTIAL
	ThresholdAmount         *money.Money    // tax applies only at/above this base
	RoundingRule            money.RoundingPolicy
	ReviewStatus            ReviewStatus
	ApprovedBy              string
}

// Validate checks rule structure before it is stored.
func (r Rule) Validate() error {
	switch {
	case r.RuleID == "":
		return errors.New("tax: rule id required")
	case len(r.Jurisdiction) != 2:
		return errors.New("tax: jurisdiction must be ISO 3166-1 alpha-2")
	case r.LegalAuthorityReference == "":
		return errors.New("tax: legal authority reference required")
	case r.TaxType == "":
		return errors.New("tax: tax type required")
	case r.Rate.IsNegative() || r.Rate.GreaterThan(decimal.NewFromInt(1)):
		return errors.New("tax: rate must be within [0,1]")
	case r.EffectiveFrom.IsZero():
		return errors.New("tax: effective_from required")
	case r.EffectiveTo != nil && !r.EffectiveTo.After(r.EffectiveFrom):
		return errors.New("tax: effective_to must follow effective_from")
	case r.TaxBaseDefinition != "NET" && r.TaxBaseDefinition != "GROSS":
		return errors.New("tax: tax base must be NET or GROSS")
	case r.ReviewStatus == ReviewApproved && r.ApprovedBy == "":
		return errors.New("tax: approved rule needs approver")
	case r.Recoverability == PartialRecovery && (r.RecoveryRatio.IsNegative() || r.RecoveryRatio.GreaterThan(decimal.NewFromInt(1))):
		return errors.New("tax: recovery ratio must be within [0,1]")
	}
	if r.RoundingRule != "" {
		if _, err := money.ApplyRounding(decimal.Zero, 2, r.RoundingRule); err != nil {
			return err
		}
	}
	return nil
}

// Query describes the transaction being taxed.
type Query struct {
	Jurisdiction           string
	TaxType                Type
	TaxableTransactionType string
	TaxpayerClassification string
	EventAt                time.Time
	Attributes             []string // e.g. "EXPORT", "DONOR_FUNDED"
}

// Errors.
var (
	ErrNoRule    = errors.New("tax: no approved rule in force for the query")
	ErrAmbiguous = errors.New("tax: more than one approved rule in force; configuration conflict")
)

// Resolve finds the single approved rule in force for the query. An
// ambiguous configuration is an explicit error, never a silent choice.
func Resolve(rules []Rule, q Query) (Rule, error) {
	var hits []Rule
	for _, r := range rules {
		if r.ReviewStatus != ReviewApproved || r.Jurisdiction != q.Jurisdiction || r.TaxType != q.TaxType {
			continue
		}
		if r.TaxableTransactionType != "" && r.TaxableTransactionType != "ANY" && r.TaxableTransactionType != q.TaxableTransactionType {
			continue
		}
		if r.TaxpayerClassification != "" && r.TaxpayerClassification != "ANY" && r.TaxpayerClassification != q.TaxpayerClassification {
			continue
		}
		if q.EventAt.Before(r.EffectiveFrom) {
			continue
		}
		if r.EffectiveTo != nil && !q.EventAt.Before(*r.EffectiveTo) {
			continue
		}
		hits = append(hits, r)
	}
	if len(hits) == 0 {
		return Rule{}, ErrNoRule
	}
	if len(hits) > 1 {
		// Prefer the most specific rule (both filters set) only when that
		// removes all ambiguity; otherwise fail loudly.
		sort.Slice(hits, func(i, j int) bool { return specificity(hits[i]) > specificity(hits[j]) })
		if specificity(hits[0]) == specificity(hits[1]) {
			return Rule{}, fmt.Errorf("%w: %s and %s", ErrAmbiguous, hits[0].RuleID, hits[1].RuleID)
		}
	}
	return hits[0], nil
}

func specificity(r Rule) int {
	n := 0
	if r.TaxableTransactionType != "" && r.TaxableTransactionType != "ANY" {
		n++
	}
	if r.TaxpayerClassification != "" && r.TaxpayerClassification != "ANY" {
		n++
	}
	return n
}

// Computation is the reproducible tax result.
type Computation struct {
	RuleID           string
	Jurisdiction     string
	TaxType          Type
	Rate             decimal.Decimal
	Exempt           bool
	ExemptionReason  string
	Base             money.Money // net taxable base
	Tax              money.Money
	Gross            money.Money
	Recoverable      money.Money // for input taxes
	NonRecoverable   money.Money
	RoundingPolicy   money.RoundingPolicy
	AlgorithmVersion string
}

// Compute applies a resolved rule to an amount. When the rule's base is
// GROSS the amount is tax-inclusive and the tax is extracted; otherwise the
// amount is the net base and tax is added.
func Compute(r Rule, amount money.Money, attributes []string) (Computation, error) {
	if r.ReviewStatus != ReviewApproved {
		return Computation{}, errors.New("tax: rule is not approved")
	}
	if amount.IsNegative() {
		return Computation{}, money.ErrNegativeNotAllowed
	}
	cur := amount.Currency()
	rounding := r.RoundingRule
	if rounding == "" {
		rounding = money.RoundHalfUp // tax-authority convention unless the rule says otherwise
	}
	zero, _ := money.Zero(cur)
	c := Computation{RuleID: r.RuleID, Jurisdiction: r.Jurisdiction, TaxType: r.TaxType, Rate: r.Rate,
		RoundingPolicy: rounding, AlgorithmVersion: AlgorithmVersion, Tax: zero, Recoverable: zero, NonRecoverable: zero}

	for _, ex := range r.ExemptionConditions {
		for _, a := range attributes {
			if a == ex {
				c.Exempt, c.ExemptionReason = true, ex
				c.Base, c.Gross = amount, amount
				return c, nil
			}
		}
	}

	var base money.Money
	var err error
	if r.TaxBaseDefinition == "GROSS" {
		// base = gross / (1 + rate)
		base, err = amount.Div(decimal.NewFromInt(1).Add(r.Rate), rounding)
		if err != nil {
			return Computation{}, err
		}
		c.Gross = amount
	} else {
		base = amount
	}
	if r.ThresholdAmount != nil {
		if r.ThresholdAmount.Currency() != cur {
			return Computation{}, fmt.Errorf("tax: threshold currency %s != %s", r.ThresholdAmount.Currency(), cur)
		}
		if cmp, _ := base.Cmp(*r.ThresholdAmount); cmp < 0 {
			c.Exempt, c.ExemptionReason = true, "BELOW_THRESHOLD"
			c.Base, c.Gross = base, base
			if r.TaxBaseDefinition == "GROSS" {
				c.Gross = amount
			}
			return c, nil
		}
	}
	c.Base = base
	if r.TaxBaseDefinition == "GROSS" {
		c.Tax, err = amount.Sub(base) // exact remainder, no second rounding
	} else {
		c.Tax, err = base.Mul(r.Rate, rounding)
		if err == nil {
			c.Gross, err = base.Add(c.Tax)
		}
	}
	if err != nil {
		return Computation{}, err
	}
	switch r.Recoverability {
	case FullyRecoverable:
		c.Recoverable = c.Tax
	case PartialRecovery:
		c.Recoverable, err = c.Tax.Mul(r.RecoveryRatio, rounding)
		if err != nil {
			return Computation{}, err
		}
		c.NonRecoverable, _ = c.Tax.Sub(c.Recoverable)
	default:
		c.NonRecoverable = c.Tax
	}
	return c, nil
}
