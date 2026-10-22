// Package schedule computes a project schedule by the critical path method
// (CPM) on a working-day calendar (GATED-02).
//
// Durations and lags are whole working days. Activity i with duration d
// occupies working days [ES, EF) where EF = ES + d; a milestone has d = 0.
// Dependencies are finish-to-start (FS), start-to-start (SS),
// finish-to-finish (FF) and start-to-finish (SF), each with a lag (negative
// = lead). The forward pass gives early dates, the backward pass late dates
// against the project finish (or a required finish), total float is LS - ES
// and free float is the slack before the earliest successor constraint.
//
// The package refuses rather than guesses: duplicate or unknown activities,
// self-links, duplicate links, cycles (reported with the cycle), negative
// durations and a required finish that the network cannot meet (reported as
// negative float, not hidden) are explicit.
package schedule

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// AlgorithmVersion is recorded with every computed schedule.
const AlgorithmVersion = "cpm-v1"

// LinkType is the kind of precedence relation.
type LinkType string

const (
	FS LinkType = "FS"
	SS LinkType = "SS"
	FF LinkType = "FF"
	SF LinkType = "SF"
)

// Activity is a unit of work.
type Activity struct {
	ID       string
	Duration int // working days, >= 0 (0 = milestone)
}

// Link says Succ depends on Pred.
type Link struct {
	Pred, Succ string
	Type       LinkType
	Lag        int // working days; negative is a lead
}

// Result holds the computed dates of one activity (working-day offsets from
// the project start, which is day 0).
type Result struct {
	ID                 string
	ES, EF, LS, LF     int
	TotalFloat         int
	FreeFloat          int
	Critical           bool
	Duration           int
	PredecessorsDriven []string // predecessors whose link sets ES (driving)
}

// Errors.
var (
	ErrInvalid = errors.New("schedule: invalid network")
	ErrCycle   = errors.New("schedule: dependency cycle")
)

// Network is a validated activity network.
type Network struct {
	acts  map[string]Activity
	order []string // insertion order, for stable output
	preds map[string][]Link
	succs map[string][]Link
}

// NewNetwork validates activities and links.
func NewNetwork(acts []Activity, links []Link) (*Network, error) {
	n := &Network{acts: map[string]Activity{}, preds: map[string][]Link{}, succs: map[string][]Link{}}
	if len(acts) == 0 {
		return nil, fmt.Errorf("%w: no activities", ErrInvalid)
	}
	for _, a := range acts {
		if a.ID == "" {
			return nil, fmt.Errorf("%w: activity without id", ErrInvalid)
		}
		if _, dup := n.acts[a.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate activity %q", ErrInvalid, a.ID)
		}
		if a.Duration < 0 {
			return nil, fmt.Errorf("%w: activity %q has a negative duration", ErrInvalid, a.ID)
		}
		n.acts[a.ID] = a
		n.order = append(n.order, a.ID)
	}
	seen := map[[2]string]bool{}
	for _, l := range links {
		if _, ok := n.acts[l.Pred]; !ok {
			return nil, fmt.Errorf("%w: link from unknown activity %q", ErrInvalid, l.Pred)
		}
		if _, ok := n.acts[l.Succ]; !ok {
			return nil, fmt.Errorf("%w: link to unknown activity %q", ErrInvalid, l.Succ)
		}
		if l.Pred == l.Succ {
			return nil, fmt.Errorf("%w: activity %q depends on itself", ErrInvalid, l.Pred)
		}
		switch l.Type {
		case FS, SS, FF, SF:
		default:
			return nil, fmt.Errorf("%w: link %s->%s has unknown type %q", ErrInvalid, l.Pred, l.Succ, l.Type)
		}
		k := [2]string{l.Pred, l.Succ}
		if seen[k] {
			return nil, fmt.Errorf("%w: duplicate link %s->%s", ErrInvalid, l.Pred, l.Succ)
		}
		seen[k] = true
		n.preds[l.Succ] = append(n.preds[l.Succ], l)
		n.succs[l.Pred] = append(n.succs[l.Pred], l)
	}
	return n, nil
}

// topo returns the activities in dependency order or the first cycle found.
func (n *Network) topo() ([]string, error) {
	const (
		white = iota
		grey
		black
	)
	colour := map[string]int{}
	var out []string
	var stack []string
	var visit func(id string) error
	visit = func(id string) error {
		colour[id] = grey
		stack = append(stack, id)
		succ := n.succs[id]
		ids := make([]string, 0, len(succ))
		for _, l := range succ {
			ids = append(ids, l.Succ)
		}
		sort.Strings(ids)
		for _, s := range ids {
			switch colour[s] {
			case grey:
				// Report the cycle from s back to s.
				i := len(stack) - 1
				for stack[i] != s {
					i--
				}
				cyc := append(append([]string{}, stack[i:]...), s)
				return fmt.Errorf("%w: %v", ErrCycle, cyc)
			case white:
				if err := visit(s); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		colour[id] = black
		out = append(out, id)
		return nil
	}
	ids := append([]string{}, n.order...)
	sort.Strings(ids)
	for _, id := range ids {
		if colour[id] == white {
			if err := visit(id); err != nil {
				return nil, err
			}
		}
	}
	// out is reverse topological order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// esFrom is the earliest start of succ implied by link l given pred's early dates.
func esFrom(l Link, predES, predEF, succDur int) int {
	switch l.Type {
	case FS:
		return predEF + l.Lag
	case SS:
		return predES + l.Lag
	case FF:
		return predEF + l.Lag - succDur
	default: // SF
		return predES + l.Lag - succDur
	}
}

// lfFrom is the latest finish of pred implied by link l given succ's late dates.
func lfFrom(l Link, succLS, succLF, predDur int) int {
	switch l.Type {
	case FS:
		return succLS - l.Lag
	case SS:
		return succLS - l.Lag + predDur
	case FF:
		return succLF - l.Lag
	default: // SF
		return succLF - l.Lag + predDur
	}
}

// Compute runs the forward and backward passes. requiredFinish < 0 means the
// project finish is the latest early finish; otherwise late dates are taken
// against it (an infeasible requirement shows as negative float).
func (n *Network) Compute(requiredFinish int) ([]Result, int, error) {
	order, err := n.topo()
	if err != nil {
		return nil, 0, err
	}
	res := map[string]*Result{}
	finish := 0
	for _, id := range order {
		a := n.acts[id]
		r := &Result{ID: id, Duration: a.Duration}
		// Activities start no earlier than the project start (day 0).
		r.ES = 0
		for _, l := range n.preds[id] {
			p := res[l.Pred]
			if es := esFrom(l, p.ES, p.EF, a.Duration); es > r.ES {
				r.ES = es
			}
		}
		for _, l := range n.preds[id] {
			p := res[l.Pred]
			if esFrom(l, p.ES, p.EF, a.Duration) == r.ES {
				r.PredecessorsDriven = append(r.PredecessorsDriven, l.Pred)
			}
		}
		sort.Strings(r.PredecessorsDriven)
		r.EF = r.ES + a.Duration
		if r.EF > finish {
			finish = r.EF
		}
		res[id] = r
	}
	target := finish
	if requiredFinish >= 0 {
		target = requiredFinish
	}
	for i := len(order) - 1; i >= 0; i-- {
		id := order[i]
		r := res[id]
		r.LF = target
		for _, l := range n.succs[id] {
			s := res[l.Succ]
			if lf := lfFrom(l, s.LS, s.LF, r.Duration); lf < r.LF {
				r.LF = lf
			}
		}
		r.LS = r.LF - r.Duration
		r.TotalFloat = r.LS - r.ES
	}
	minFloat := 0
	first := true
	for _, r := range res {
		if first || r.TotalFloat < minFloat {
			minFloat, first = r.TotalFloat, false
		}
	}
	for _, id := range order {
		r := res[id]
		// Critical: the least total float in the network (0 when the finish is
		// the network's own; negative when a required finish cannot be met).
		r.Critical = r.TotalFloat == minFloat && minFloat <= 0
		// Free float: slack before the earliest successor is delayed.
		ff := target - r.EF
		if len(n.succs[id]) > 0 {
			ff = int(^uint(0) >> 1)
			for _, l := range n.succs[id] {
				s := res[l.Succ]
				if slack := s.ES - esFrom(l, r.ES, r.EF, s.Duration); slack < ff {
					ff = slack
				}
			}
		}
		r.FreeFloat = ff
	}
	out := make([]Result, 0, len(order))
	for _, id := range n.order {
		out = append(out, *res[id])
	}
	return out, finish, nil
}

// Calendar maps working-day offsets to dates.
type Calendar struct {
	Start    time.Time             // the project start (day 0), a working day
	Weekdays map[time.Weekday]bool // working weekdays
	Holidays map[string]bool       // "2006-01-02" non-working dates
}

func (c Calendar) working(d time.Time) bool {
	return c.Weekdays[d.Weekday()] && !c.Holidays[d.Format("2006-01-02")]
}

// Validate refuses a calendar without working days or starting on a non-working day.
func (c Calendar) Validate() error {
	if len(c.Weekdays) == 0 {
		return fmt.Errorf("%w: the calendar has no working weekdays", ErrInvalid)
	}
	if !c.working(c.Start) {
		return fmt.Errorf("%w: the project starts on a non-working day (%s)", ErrInvalid, c.Start.Format("2006-01-02"))
	}
	return nil
}

// Date returns the date of working day `offset` (day 0 is Start). Negative
// offsets count backwards.
func (c Calendar) Date(offset int) time.Time {
	d := c.Start
	step := 1
	if offset < 0 {
		step, offset = -1, -offset
	}
	for offset > 0 {
		d = d.AddDate(0, 0, step)
		if c.working(d) {
			offset--
		}
	}
	return d
}

// FinishDate is the date of the last working day of an activity occupying
// [ES, EF): the working day EF-1, or the start date for a milestone.
func (c Calendar) FinishDate(es, ef int) time.Time {
	if ef == es {
		return c.Date(es)
	}
	return c.Date(ef - 1)
}

// Offset returns the working-day offset of a date (the number of working days
// from Start to d, counting d when it is after Start); non-working dates map
// to the next working day.
func (c Calendar) Offset(d time.Time) int {
	n := 0
	if d.Before(c.Start) {
		for x := c.Start; x.After(d); x = x.AddDate(0, 0, -1) {
			if c.working(x) && !x.Equal(c.Start) {
				n--
			}
		}
		return n
	}
	for x := c.Start.AddDate(0, 0, 1); !x.After(d); x = x.AddDate(0, 0, 1) {
		if c.working(x) {
			n++
		}
	}
	if !c.working(d) {
		n++
	}
	return n
}
