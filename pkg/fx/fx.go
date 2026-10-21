// Package fx implements the Dual-Currency FX Shield (Pillar 1, §3.2).
//
// Rules enforced here:
//   - A rate is never invented. Selection either returns an approved snapshot
//     that was valid at the business event time AND available under the
//     knowledge cutoff, or it returns an explicit exception error.
//   - Every conversion is bound to the snapshot it used and to the algorithm
//     version, so it can be reproduced later (LAW 06).
//   - All arithmetic is exact decimal (LAW 06).
package fx

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/money"
)

// AlgorithmVersion is recorded on every conversion result so that changes to
// selection or rounding logic never silently alter historical calculations.
const AlgorithmVersion = "fx-select-v1"

// RateType distinguishes the economic nature of a quoted rate.
type RateType string

const (
	RateOfficial    RateType = "OFFICIAL"    // central bank reference rate
	RateCommercial  RateType = "COMMERCIAL"  // bank buying/selling mid
	RateContractual RateType = "CONTRACTUAL" // fixed in a contract
	RateClosing     RateType = "CLOSING"     // period-end remeasurement rate
	RateBudget      RateType = "BUDGET"      // management planning anchor
)

// ApprovalStatus of a snapshot. Only APPROVED snapshots may be used for posting.
type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "PENDING"
	StatusApproved ApprovalStatus = "APPROVED"
	StatusDisputed ApprovalStatus = "DISPUTED"
	StatusRejected ApprovalStatus = "REJECTED"
)

// Snapshot is an immutable observation of an exchange rate. Field set
// mirrors the specification's FX event model exactly.
type Snapshot struct {
	SnapshotID         string
	TenantID           string
	SourceID           string // e.g. "NBE", "CBE", "CONTRACT:PO-2026-0117"
	SourceType         string // CENTRAL_BANK | COMMERCIAL_BANK | CONTRACT | PROVIDER
	BaseCurrency       money.Currency
	QuoteCurrency      money.Currency
	Rate               decimal.Decimal // units of Quote per 1 unit of Base
	RateType           RateType
	EffectiveFromUTC   time.Time
	PublishedAtUTC     time.Time
	CapturedAtUTC      time.Time
	BusinessEventAtUTC time.Time // zero for market snapshots; set for contract-bound
	SourceDocumentHash string
	AlgorithmVersion   string
	ApprovalStatus     ApprovalStatus
	CreatedBy          string
}

// Validate checks structural integrity of a snapshot before it is stored.
func (s Snapshot) Validate() error {
	switch {
	case s.SnapshotID == "":
		return errors.New("fx: snapshot id required")
	case s.TenantID == "":
		return errors.New("fx: tenant id required")
	case s.SourceID == "":
		return errors.New("fx: source id required")
	case !money.IsKnown(s.BaseCurrency) || !money.IsKnown(s.QuoteCurrency):
		return fmt.Errorf("fx: unknown currency pair %s/%s", s.BaseCurrency, s.QuoteCurrency)
	case s.BaseCurrency == s.QuoteCurrency:
		return errors.New("fx: base and quote currency must differ")
	case !s.Rate.IsPositive():
		return errors.New("fx: rate must be positive")
	case s.EffectiveFromUTC.IsZero() || s.PublishedAtUTC.IsZero() || s.CapturedAtUTC.IsZero():
		return errors.New("fx: effective, published and captured timestamps required")
	case s.PublishedAtUTC.Before(s.EffectiveFromUTC.Add(-24 * time.Hour)):
		// A rate cannot be published more than a day before it becomes effective
		// under any central-bank practice we support; flag likely data error.
		return errors.New("fx: published_at implausibly precedes effective_from")
	case s.CapturedAtUTC.Before(s.PublishedAtUTC):
		return errors.New("fx: captured_at precedes published_at")
	}
	return nil
}

// Policy governs how a snapshot is chosen for a given business event.
type Policy struct {
	// RateType required for this accounting purpose.
	RateType RateType
	// SourcePriority lists acceptable source IDs in descending preference.
	// An empty list accepts any source.
	SourcePriority []string
	// MaxStaleness rejects a snapshot whose EffectiveFrom is older than this
	// relative to the business event (expired provider data). Zero disables.
	MaxStaleness time.Duration
	// AllowInverse permits deriving Base/Quote from an approved Quote/Base
	// snapshot. The derivation is explicitly flagged on the result.
	AllowInverse bool
	// InverseScale is the number of decimal places kept when inverting.
	// Defaults to 12.
	InverseScale int32
}

// ErrSnapshotState is returned when a decision does not fit the snapshot's
// current approval state.
var ErrSnapshotState = errors.New("fx: snapshot is not in a state that allows this decision")

// ErrPolicyInvalid is returned for a policy that would not fail closed.
var ErrPolicyInvalid = errors.New("fx: invalid policy")

// Validate requires a policy that cannot silently accept arbitrary rates:
// an explicit rate type, at least one admissible source and a finite
// maximum age (SC-02).
func (p Policy) Validate() error {
	switch {
	case p.RateType == "":
		return fmt.Errorf("%w: rate type required", ErrPolicyInvalid)
	case len(p.SourcePriority) == 0:
		return fmt.Errorf("%w: at least one admissible source required", ErrPolicyInvalid)
	case p.MaxStaleness <= 0:
		return fmt.Errorf("%w: a positive maximum staleness is required", ErrPolicyInvalid)
	case p.MaxStaleness > 400*24*time.Hour:
		return fmt.Errorf("%w: maximum staleness above 400 days", ErrPolicyInvalid)
	}
	seen := map[string]bool{}
	for _, s := range p.SourcePriority {
		if s == "" || seen[s] {
			return fmt.Errorf("%w: empty or duplicate source %q", ErrPolicyInvalid, s)
		}
		seen[s] = true
	}
	return nil
}

// Exception errors. These are the explicit, auditable outcomes required by
// the specification instead of fabricated rates.
var (
	ErrRateMissing     = errors.New("fx: no approved rate available for the pair under the policy")
	ErrRateStale       = errors.New("fx: only expired rate observations available")
	ErrRateNotYetKnown = errors.New("fx: rate was not published before the knowledge cutoff")
	ErrSameCurrency    = errors.New("fx: conversion between identical currencies needs no rate")
)

// Selection is the outcome of Select: the snapshot and how it was applied.
type Selection struct {
	Snapshot         Snapshot
	AppliedRate      decimal.Decimal // Quote per Base after any inversion
	DerivedInverse   bool
	AlgorithmVersion string
}

// Select chooses the authoritative snapshot for converting base->quote for a
// business event that occurred at eventAt, using only knowledge available at
// knowledgeCutoff. Candidates may contain any pairs/statuses; filtering is
// done here so the caller cannot accidentally bypass policy.
func Select(candidates []Snapshot, base, quote money.Currency, eventAt, knowledgeCutoff time.Time, p Policy) (Selection, error) {
	if base == quote {
		return Selection{}, ErrSameCurrency
	}
	if knowledgeCutoff.IsZero() {
		knowledgeCutoff = eventAt
	}
	type cand struct {
		s        Snapshot
		rate     decimal.Decimal
		inverse  bool
		priority int
	}
	var eligible []cand
	sawStale, sawFuturePublished := false, false

	priorityOf := func(src string) (int, bool) {
		if len(p.SourcePriority) == 0 {
			return 0, true
		}
		for i, id := range p.SourcePriority {
			if id == src {
				return i, true
			}
		}
		return 0, false
	}

	for _, s := range candidates {
		if s.ApprovalStatus != StatusApproved {
			continue
		}
		if p.RateType != "" && s.RateType != p.RateType {
			continue
		}
		direct := s.BaseCurrency == base && s.QuoteCurrency == quote
		inverse := p.AllowInverse && s.BaseCurrency == quote && s.QuoteCurrency == base
		if !direct && !inverse {
			continue
		}
		prio, ok := priorityOf(s.SourceID)
		if !ok {
			continue
		}
		if s.EffectiveFromUTC.After(eventAt) {
			continue // not yet effective at event time
		}
		if s.PublishedAtUTC.After(knowledgeCutoff) {
			sawFuturePublished = true
			continue // rate published after what we are allowed to know
		}
		if p.MaxStaleness > 0 && eventAt.Sub(s.EffectiveFromUTC) > p.MaxStaleness {
			sawStale = true
			continue
		}
		rate := s.Rate
		if inverse {
			scale := p.InverseScale
			if scale == 0 {
				scale = 12
			}
			rate = decimal.NewFromInt(1).DivRound(s.Rate, scale)
		}
		eligible = append(eligible, cand{s: s, rate: rate, inverse: inverse, priority: prio})
	}
	if len(eligible) == 0 {
		switch {
		case sawFuturePublished:
			return Selection{}, ErrRateNotYetKnown
		case sawStale:
			return Selection{}, ErrRateStale
		default:
			return Selection{}, ErrRateMissing
		}
	}
	// Deterministic ordering: source priority, direct before inverse,
	// latest effective, latest published, then snapshot id for total order.
	sort.SliceStable(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		if a.inverse != b.inverse {
			return !a.inverse
		}
		if !a.s.EffectiveFromUTC.Equal(b.s.EffectiveFromUTC) {
			return a.s.EffectiveFromUTC.After(b.s.EffectiveFromUTC)
		}
		if !a.s.PublishedAtUTC.Equal(b.s.PublishedAtUTC) {
			return a.s.PublishedAtUTC.After(b.s.PublishedAtUTC)
		}
		return a.s.SnapshotID < b.s.SnapshotID
	})
	best := eligible[0]
	return Selection{Snapshot: best.s, AppliedRate: best.rate, DerivedInverse: best.inverse, AlgorithmVersion: AlgorithmVersion}, nil
}

// Conversion is a reproducible record of one currency translation.
type Conversion struct {
	From             money.Money
	To               money.Money
	SnapshotID       string
	AppliedRate      decimal.Decimal
	DerivedInverse   bool
	RoundingPolicy   money.RoundingPolicy
	AlgorithmVersion string
}

// Convert applies A_target = A_source × R(source→target) exactly, then
// quantises to the target currency's minor units under the policy.
func Convert(amount money.Money, target money.Currency, sel Selection, rounding money.RoundingPolicy) (Conversion, error) {
	if amount.Currency() == target {
		return Conversion{}, ErrSameCurrency
	}
	if sel.Snapshot.SnapshotID == "" {
		return Conversion{}, errors.New("fx: selection has no snapshot")
	}
	// Guard the pair orientation so a wrong selection cannot be applied.
	want := sel.Snapshot.BaseCurrency == amount.Currency() && sel.Snapshot.QuoteCurrency == target
	if sel.DerivedInverse {
		want = sel.Snapshot.QuoteCurrency == amount.Currency() && sel.Snapshot.BaseCurrency == target
	}
	if !want {
		return Conversion{}, fmt.Errorf("fx: snapshot %s pair %s/%s does not convert %s->%s",
			sel.Snapshot.SnapshotID, sel.Snapshot.BaseCurrency, sel.Snapshot.QuoteCurrency, amount.Currency(), target)
	}
	out, err := money.New(amount.Amount().Mul(sel.AppliedRate), target, rounding)
	if err != nil {
		return Conversion{}, err
	}
	if rounding == "" {
		rounding = money.DefaultRounding
	}
	return Conversion{
		From: amount, To: out, SnapshotID: sel.Snapshot.SnapshotID, AppliedRate: sel.AppliedRate,
		DerivedInverse: sel.DerivedInverse, RoundingPolicy: rounding, AlgorithmVersion: AlgorithmVersion,
	}, nil
}

// ItemClass is the balance-sheet classification that fixes the sign of a
// remeasurement difference.
type ItemClass string

const (
	MonetaryAsset     ItemClass = "MONETARY_ASSET"
	MonetaryLiability ItemClass = "MONETARY_LIABILITY"
)

// Remeasurement is the IAS 21 period-end difference on a monetary item.
type Remeasurement struct {
	ForeignAmount    money.Money
	CarryingRate     decimal.Decimal
	ClosingRate      decimal.Decimal
	ClosingSnapshot  string
	Class            ItemClass
	GainLoss         money.Money // positive = gain to P&L, negative = loss
	AlgorithmVersion string
}

// Remeasure computes FXGainLoss = A_foreign × (R_closing − R_carrying) with
// the sign convention: for an asset a rising rate is a gain; for a liability
// a rising rate is a loss. The result is in the functional currency.
func Remeasure(foreign money.Money, functional money.Currency, carryingRate decimal.Decimal, closing Selection, class ItemClass, rounding money.RoundingPolicy) (Remeasurement, error) {
	if !carryingRate.IsPositive() {
		return Remeasurement{}, errors.New("fx: carrying rate must be positive")
	}
	if closing.Snapshot.SnapshotID == "" || !closing.AppliedRate.IsPositive() {
		return Remeasurement{}, errors.New("fx: closing selection required")
	}
	if class != MonetaryAsset && class != MonetaryLiability {
		return Remeasurement{}, fmt.Errorf("fx: unsupported item class %q", class)
	}
	delta := foreign.Amount().Mul(closing.AppliedRate.Sub(carryingRate))
	if class == MonetaryLiability {
		delta = delta.Neg()
	}
	gl, err := money.New(delta, functional, rounding)
	if err != nil {
		return Remeasurement{}, err
	}
	return Remeasurement{
		ForeignAmount: foreign, CarryingRate: carryingRate, ClosingRate: closing.AppliedRate,
		ClosingSnapshot: closing.Snapshot.SnapshotID, Class: class, GainLoss: gl, AlgorithmVersion: AlgorithmVersion,
	}, nil
}
