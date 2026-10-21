// Package workflow defines governed approval workflows: versioned, machine
// readable process definitions and the deterministic rules that route a
// subject through them.
//
// Governing principle (Law C / Law E of the engineering mandate): automation
// may route, remind, escalate and execute — it never authorizes. Every
// financially sensitive effect runs with the authority of the human who
// approved the step that triggers it, through the same kernel commands a
// user would call, so permissions, segregation of duties, step-up MFA and
// database invariants all still apply. Validate refuses definitions that
// would let an effect run without such a human gate.
package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/money"
)

// SoD references usable in Step.DistinctFrom.
const (
	RefInitiator      = "initiator"       // the person who started the instance
	RefSubjectCreator = "subject.creator" // the maker of the subject (journal preparer, rate maker...)
	RefStepPrefix     = "step:"           // every approver of an earlier step, e.g. "step:review"
)

// Definition is one version of a workflow.
type Definition struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Subject string `json:"subject"` // journal | fx_snapshot | fiscal_period
	// Mandatory: once published, direct API transitions of this subject type
	// are refused; they must go through an instance of this workflow.
	Mandatory bool `json:"mandatory"`
	// StartPermission is required to start an instance.
	StartPermission auth.Permission `json:"start_permission"`
	Steps           []Step          `json:"steps"`
	// OnReject runs (with the rejecting approver's authority) when a step is
	// rejected. Optional; must be non-sensitive. It does not run on expiry or
	// cancellation (no person decided those); the subject is then released
	// and can be routed again.
	OnReject string `json:"on_reject,omitempty"`
}

// Step is one approval stage.
type Step struct {
	ID         string          `json:"id"`
	Title      string          `json:"title"`
	Permission auth.Permission `json:"permission"`
	// Approvals is the quorum: this many DISTINCT eligible people must
	// approve (parallel approval). Default 1, max 5.
	Approvals    int      `json:"approvals,omitempty"`
	DistinctFrom []string `json:"distinct_from,omitempty"`
	RequireMFA   bool     `json:"require_mfa,omitempty"`
	// When restricts the step to subjects at or above an amount. One
	// threshold per currency; a subject in a currency without a threshold
	// cannot be routed (fail closed — never a silent FX conversion).
	When []Condition `json:"when,omitempty"`
	// SLA: after this long the task escalates to EscalateTo holders.
	SLA        string          `json:"sla,omitempty"`
	EscalateTo auth.Permission `json:"escalate_to,omitempty"`
	// ExpireAfter: the instance expires (OnReject runs) if the step is
	// still open after this long.
	ExpireAfter string `json:"expire_after,omitempty"`
	// Effect runs when the step's quorum is reached, with the authority of
	// the approver who completed the quorum.
	Effect string `json:"effect,omitempty"`
}

// Condition is an amount threshold in a currency.
type Condition struct {
	AmountGTE string         `json:"amount_gte"`
	Currency  money.Currency `json:"currency"`
}

// Action describes an executable effect for validation purposes.
type Action struct {
	Name      string
	Subject   string
	Sensitive bool // changes financial state or approval status
	// Permission the approver must hold for the effect (the kernel checks
	// it again at execution).
	Permission auth.Permission
}

// Catalog describes the effects and permissions the validator may accept.
type Catalog struct {
	Actions     map[string]Action
	Permissions map[auth.Permission]bool
	Subjects    map[string]bool
}

// ErrInvalid wraps every definition validation failure.
var ErrInvalid = errors.New("workflow: invalid definition")

var idRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,40}$`)
var keyRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{2,60}$`)
var durRe = regexp.MustCompile(`^([0-9]{1,4}h)?([0-9]{1,6}m)?([0-9]{1,8}s)?$`)

// Parse decodes and validates a definition strictly (unknown fields refused).
func Parse(b []byte, cat Catalog) (Definition, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var d Definition
	if err := dec.Decode(&d); err != nil {
		return Definition{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return d, d.Validate(cat)
}

// Validate enforces the structural rules and the control invariants.
func (d Definition) Validate(cat Catalog) error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if !keyRe.MatchString(d.Key) {
		bad("key %q must match %s", d.Key, keyRe)
	}
	if strings.TrimSpace(d.Title) == "" {
		bad("title required")
	}
	if !cat.Subjects[d.Subject] {
		bad("unknown subject %q", d.Subject)
	}
	if !cat.Permissions[d.StartPermission] {
		bad("unknown start_permission %q", d.StartPermission)
	}
	if len(d.Steps) == 0 || len(d.Steps) > 12 {
		bad("a workflow needs 1..12 steps")
	}
	seen := map[string]bool{}
	effects := map[string]bool{}
	var sensitiveSteps []string
	for i, s := range d.Steps {
		where := fmt.Sprintf("step %d (%s)", i+1, s.ID)
		if !idRe.MatchString(s.ID) {
			bad("%s: id must match %s", where, idRe)
		}
		if seen[s.ID] {
			bad("%s: duplicate id", where)
		}
		if !cat.Permissions[s.Permission] {
			bad("%s: unknown permission %q", where, s.Permission)
		}
		if s.Approvals < 0 || s.Approvals > 5 {
			bad("%s: approvals must be between 1 and 5 (omit for 1)", where)
		}
		for _, ref := range s.DistinctFrom {
			switch {
			case ref == RefInitiator || ref == RefSubjectCreator:
			case strings.HasPrefix(ref, RefStepPrefix) && seen[strings.TrimPrefix(ref, RefStepPrefix)]:
			default:
				bad("%s: distinct_from %q must be initiator, subject.creator or an EARLIER step", where, ref)
			}
		}
		if s.When != nil {
			if d.Subject != "journal" {
				bad("%s: amount thresholds apply only to subjects with an amount (journal)", where)
			}
			if len(s.When) == 0 || len(s.When) > 20 {
				bad("%s: when needs 1..20 thresholds", where)
			}
			curSeen := map[money.Currency]bool{}
			for _, c := range s.When {
				if !money.IsKnown(c.Currency) {
					bad("%s: when currency %q unknown", where, c.Currency)
					continue
				}
				if curSeen[c.Currency] {
					bad("%s: two thresholds for %s", where, c.Currency)
				}
				curSeen[c.Currency] = true
				// Bounded, exact, in the currency's minor units (also caps
				// the cost of every later comparison).
				if m, err := money.ParseStrict(c.AmountGTE, c.Currency); err != nil || m.IsNegative() {
					bad("%s: when amount_gte %q must be a plain non-negative amount in %s minor units", where, c.AmountGTE, c.Currency)
				}
			}
		}
		for name, v := range map[string]string{"sla": s.SLA, "expire_after": s.ExpireAfter} {
			if v == "" {
				continue
			}
			dur, err := time.ParseDuration(v)
			// Whole h/m/s units only: the database recomputes deadlines from
			// the same string, so both sides must read it identically.
			if !durRe.MatchString(v) || err != nil || dur < time.Minute || dur > 90*24*time.Hour {
				bad("%s: %s must be a duration like 90m or 24h between 1m and 2160h", where, name)
			}
		}
		if s.SLA != "" && !cat.Permissions[s.EscalateTo] {
			bad("%s: an SLA needs a known escalate_to permission", where)
		}
		if s.SLA != "" && s.ExpireAfter != "" {
			sla, _ := time.ParseDuration(s.SLA)
			exp, _ := time.ParseDuration(s.ExpireAfter)
			if exp <= sla {
				bad("%s: expire_after must be longer than sla", where)
			}
		}
		if s.Effect != "" {
			a, ok := cat.Actions[s.Effect]
			switch {
			case !ok:
				bad("%s: unknown effect %q", where, s.Effect)
			case a.Subject != d.Subject:
				bad("%s: effect %q applies to %s, not %s", where, s.Effect, a.Subject, d.Subject)
			case a.Sensitive && s.Permission != a.Permission:
				// The control invariant: a sensitive effect is executed with
				// the approver's own authority, so the step must be decided
				// by people who already hold exactly that permission.
				bad("%s: sensitive effect %q requires the step permission to be %q (got %q)", where, s.Effect, a.Permission, s.Permission)
			case a.Sensitive && s.When != nil:
				bad("%s: a sensitive effect cannot sit on a conditional step (it would be skipped below the threshold)", where)
			}
			if effects[s.Effect] {
				bad("%s: effect %q already runs at an earlier step", where, s.Effect)
			}
			effects[s.Effect] = true
			if ok && a.Sensitive {
				// Every approver counted for a sensitive effect must be
				// independent of the maker and of earlier sensitive steps;
				// otherwise "two approvals" may mean one independent person.
				need := append([]string{RefSubjectCreator}, sensitiveSteps...)
				for _, n := range need {
					if !contains(s.DistinctFrom, n) {
						bad("%s: a step with sensitive effect %q must list %q in distinct_from", where, s.Effect, n)
					}
				}
				sensitiveSteps = append(sensitiveSteps, RefStepPrefix+s.ID)
			}
		}
		seen[s.ID] = true
	}
	if d.Mandatory {
		// A mandatory workflow replaces the direct API path for its subject,
		// so it must perform every sensitive transition of that subject;
		// otherwise the missing transition would become impossible.
		var missing []string
		for name, a := range cat.Actions {
			if a.Subject == d.Subject && a.Sensitive && !effects[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			bad("a mandatory workflow must perform every sensitive transition of %s itself; missing %v", d.Subject, missing)
		}
	}
	if d.OnReject != "" {
		a, ok := cat.Actions[d.OnReject]
		switch {
		case !ok:
			bad("unknown on_reject effect %q", d.OnReject)
		case a.Sensitive:
			bad("on_reject effect %q is sensitive; rejection may only run non-sensitive compensation", d.OnReject)
		case a.Subject != d.Subject:
			bad("on_reject effect %q does not apply to %s", d.OnReject, d.Subject)
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%w:\n  - %s", ErrInvalid, strings.Join(errs, "\n  - "))
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Facts are server-derived attributes of the subject used for routing.
type Facts struct {
	Amount    *money.Money // nil when the subject has no amount
	ProjectID string
	CreatedBy string
}

// RouteStep is a step that applies to a particular subject.
type RouteStep struct {
	Step
	Index int // position in the definition
}

// ErrConditionCurrency is returned when a threshold step has no threshold in
// the subject's currency (no silent FX conversion; add a threshold).
var ErrConditionCurrency = errors.New("workflow: no threshold for the subject currency")

// Route returns the steps that apply to the subject, in order. A threshold
// step applies when the subject amount is at or above it; a subject without
// an amount never satisfies a threshold.
func (d Definition) Route(f Facts) ([]RouteStep, error) {
	var out []RouteStep
	for i, s := range d.Steps {
		if s.Approvals == 0 {
			s.Approvals = 1
		}
		if s.When != nil {
			if f.Amount == nil {
				continue
			}
			c, ok := s.threshold(f.Amount.Currency())
			if !ok {
				return nil, fmt.Errorf("%w: step %s has no threshold for %s", ErrConditionCurrency, s.ID, f.Amount.Currency())
			}
			if f.Amount.Amount().LessThan(decimal.RequireFromString(c.AmountGTE)) {
				continue
			}
		}
		out = append(out, RouteStep{Step: s, Index: i})
	}
	return out, nil
}

func (s Step) threshold(cur money.Currency) (Condition, bool) {
	for _, c := range s.When {
		if c.Currency == cur {
			return c, true
		}
	}
	return Condition{}, false
}

// SimulationStep explains one routed step for a dry run.
type SimulationStep struct {
	ID           string          `json:"id"`
	Title        string          `json:"title"`
	Permission   auth.Permission `json:"permission"`
	Approvals    int             `json:"approvals"`
	RequireMFA   bool            `json:"require_mfa"`
	DistinctFrom []string        `json:"distinct_from,omitempty"`
	SLA          string          `json:"sla,omitempty"`
	Effect       string          `json:"effect,omitempty"`
	Reason       string          `json:"reason"`
}

// Simulate is a side-effect-free dry run: which steps a subject with these
// facts would go through, and why.
func (d Definition) Simulate(f Facts) ([]SimulationStep, error) {
	route, err := d.Route(f)
	if err != nil {
		return nil, err
	}
	var out []SimulationStep
	for _, r := range route {
		reason := "always required"
		if r.When != nil {
			c, _ := r.threshold(f.Amount.Currency())
			reason = fmt.Sprintf("amount %s ≥ threshold %s %s", f.Amount, c.AmountGTE, c.Currency)
		}
		out = append(out, SimulationStep{ID: r.ID, Title: r.Title, Permission: r.Permission, Approvals: r.Approvals,
			RequireMFA: r.RequireMFA, DistinctFrom: r.DistinctFrom, SLA: r.SLA, Effect: r.Effect, Reason: reason})
	}
	return out, nil
}
