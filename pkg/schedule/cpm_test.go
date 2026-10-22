package schedule

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The hand-worked network (working days):
//
//	A(3) -> B(4) -> D(5) -> E(1);  A -> C(2) -> E
//	forward:  A 0-3, B 3-7, C 3-5, D 7-12, E 12-13; finish 13
//	backward: E 12-13, D 7-12, C 10-12, B 3-7, A 0-3
//	float:    A 0, B 0, C 7, D 0, E 0; critical A B D E; C free float 7
func textbook() ([]Activity, []Link) {
	return []Activity{{"A", 3}, {"B", 4}, {"C", 2}, {"D", 5}, {"E", 1}},
		[]Link{{"A", "B", FS, 0}, {"A", "C", FS, 0}, {"B", "D", FS, 0}, {"C", "E", FS, 0}, {"D", "E", FS, 0}}
}

func byID(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

func TestCPMTextbook(t *testing.T) {
	n, err := NewNetwork(textbook())
	if err != nil {
		t.Fatal(err)
	}
	rs, finish, err := n.Compute(-1)
	if err != nil {
		t.Fatal(err)
	}
	if finish != 13 {
		t.Fatalf("finish %d, want 13", finish)
	}
	want := map[string][7]int{ // ES EF LS LF TF FF critical(1/0)
		"A": {0, 3, 0, 3, 0, 0, 1}, "B": {3, 7, 3, 7, 0, 0, 1}, "C": {3, 5, 10, 12, 7, 7, 0},
		"D": {7, 12, 7, 12, 0, 0, 1}, "E": {12, 13, 12, 13, 0, 0, 1},
	}
	got := byID(rs)
	for id, w := range want {
		r := got[id]
		crit := 0
		if r.Critical {
			crit = 1
		}
		if [7]int{r.ES, r.EF, r.LS, r.LF, r.TotalFloat, r.FreeFloat, crit} != w {
			t.Errorf("%s: got ES %d EF %d LS %d LF %d TF %d FF %d crit %v, want %v", id, r.ES, r.EF, r.LS, r.LF, r.TotalFloat, r.FreeFloat, r.Critical, w)
		}
	}
	if d := got["E"].PredecessorsDriven; len(d) != 1 || d[0] != "D" {
		t.Errorf("E is driven by %v, want [D]", d)
	}
}

func TestCPMLinkTypesAndLags(t *testing.T) {
	// A(3); F(4) SS A +1 -> 1-5; G(2) FF F +0 -> EF 5, ES 3; H(2) FS A -1 (lead) -> 2-4;
	// M milestone SF from A +5 -> EF >= 0+5 -> ES 5.
	n, err := NewNetwork([]Activity{{"A", 3}, {"F", 4}, {"G", 2}, {"H", 2}, {"M", 0}},
		[]Link{{"A", "F", SS, 1}, {"F", "G", FF, 0}, {"A", "H", FS, -1}, {"A", "M", SF, 5}})
	if err != nil {
		t.Fatal(err)
	}
	rs, finish, err := n.Compute(-1)
	if err != nil {
		t.Fatal(err)
	}
	got := byID(rs)
	for id, w := range map[string][2]int{"F": {1, 5}, "G": {3, 5}, "H": {2, 4}, "M": {5, 5}} {
		if got[id].ES != w[0] || got[id].EF != w[1] {
			t.Errorf("%s: %d-%d, want %d-%d", id, got[id].ES, got[id].EF, w[0], w[1])
		}
	}
	if finish != 5 {
		t.Errorf("finish %d, want 5", finish)
	}
}

func TestCPMRequiredFinishShowsNegativeFloat(t *testing.T) {
	n, _ := NewNetwork(textbook())
	rs, finish, err := n.Compute(10)
	if err != nil {
		t.Fatal(err)
	}
	got := byID(rs)
	if finish != 13 || got["A"].TotalFloat != -3 || !got["A"].Critical || got["C"].TotalFloat != 4 || got["C"].Critical {
		t.Errorf("required finish 10: finish %d, A float %d critical %v, C float %d critical %v", finish, got["A"].TotalFloat, got["A"].Critical,
			got["C"].TotalFloat, got["C"].Critical)
	}
}

func TestCPMRefusesInvalidNetworks(t *testing.T) {
	for name, tc := range map[string]struct {
		acts  []Activity
		links []Link
		want  error
		text  string
	}{
		"empty":          {nil, nil, ErrInvalid, "no activities"},
		"duplicate":      {[]Activity{{"A", 1}, {"A", 2}}, nil, ErrInvalid, "duplicate activity"},
		"negative":       {[]Activity{{"A", -1}}, nil, ErrInvalid, "negative duration"},
		"unknown":        {[]Activity{{"A", 1}}, []Link{{"A", "Z", FS, 0}}, ErrInvalid, "unknown activity"},
		"self":           {[]Activity{{"A", 1}}, []Link{{"A", "A", FS, 0}}, ErrInvalid, "depends on itself"},
		"duplicate link": {[]Activity{{"A", 1}, {"B", 1}}, []Link{{"A", "B", FS, 0}, {"A", "B", SS, 0}}, ErrInvalid, "duplicate link"},
		"bad type":       {[]Activity{{"A", 1}, {"B", 1}}, []Link{{"A", "B", "XX", 0}}, ErrInvalid, "unknown type"},
	} {
		_, err := NewNetwork(tc.acts, tc.links)
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: %v", name, err)
		}
	}
	n, err := NewNetwork([]Activity{{"A", 1}, {"B", 1}, {"C", 1}}, []Link{{"A", "B", FS, 0}, {"B", "C", FS, 0}, {"C", "A", FS, 0}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.Compute(-1); !errors.Is(err, ErrCycle) || !strings.Contains(err.Error(), "[A B C A]") {
		t.Errorf("cycle: %v", err)
	}
}

func TestCalendarSixDayWeekWithHoliday(t *testing.T) {
	mon := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) // Monday
	c := Calendar{Start: mon, Weekdays: map[time.Weekday]bool{time.Monday: true, time.Tuesday: true, time.Wednesday: true,
		time.Thursday: true, time.Friday: true, time.Saturday: true}, Holidays: map[string]bool{"2026-11-11": true}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for off, want := range map[int]string{0: "2026-11-02", 5: "2026-11-07", 6: "2026-11-09", 8: "2026-11-12", -1: "2026-10-31"} {
		if got := c.Date(off).Format("2006-01-02"); got != want {
			t.Errorf("Date(%d) = %s, want %s", off, got, want)
		}
	}
	for d, want := range map[string]int{"2026-11-02": 0, "2026-11-07": 5, "2026-11-08": 6, "2026-11-09": 6, "2026-11-12": 8} {
		x, _ := time.Parse("2006-01-02", d)
		if got := c.Offset(x); got != want {
			t.Errorf("Offset(%s) = %d, want %d", d, got, want)
		}
	}
	// A 3-day activity starting on day 4 (Fri) finishes on Mon (day 6).
	if got := c.FinishDate(4, 7).Format("2006-01-02"); got != "2026-11-09" {
		t.Errorf("finish date %s", got)
	}
	bad := c
	bad.Start = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC) // Sunday
	if err := bad.Validate(); err == nil {
		t.Error("a calendar starting on Sunday was accepted")
	}
}
