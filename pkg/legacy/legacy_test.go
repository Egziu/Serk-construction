package legacy

import (
	"strings"
	"testing"
	"time"
)

func opts(dir string) Options {
	return Options{Dir: "testdata/" + dir, CutOver: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), MinorUnits: 2, APAccount: "2000", ARAccount: "1100"}
}

func TestCleanBundleHasNoExceptions(t *testing.T) {
	s := Validate(opts("clean"))
	if len(s.Exceptions) != 0 {
		t.Fatalf("exceptions on the clean bundle: %+v", s.Exceptions)
	}
	if !s.Balanced || s.TotalDebit != "6530000" || s.Payables != "920000" || s.Receivable != "1500000" {
		t.Errorf("summary: %+v", s)
	}
}

// Every planted defect is reported with its file, line and rule; nothing
// is silently accepted.
func TestDirtyBundleReportsEveryDefect(t *testing.T) {
	s := Validate(opts("dirty"))
	got := map[string]bool{}
	for _, e := range s.Exceptions {
		got[e.File+":"+itoa(e.Line)+":"+e.Rule] = true
		t.Logf("%s:%d %s %s", e.File, e.Line, e.Rule, e.Text)
	}
	for _, want := range []string{
		"accounts.csv:5:DUPLICATE",         // 2000 twice
		"accounts.csv:8:TYPE",              // COST
		"suppliers.csv:3:CODE",             // "sup 2"
		"suppliers.csv:3:NAME",             // empty
		"suppliers.csv:3:DUPLICATE",        // tax id reused
		"opening_balances.csv:2:PRECISION", // .005
		"opening_balances.csv:4:FK",        // account 1200 missing
		"opening_balances.csv:7:COSTCODE",  // expense without cost code
		"opening_balances.csv:8:FK",        // cost code 09-XXX
		"opening_balances.csv:8:ONESIDE",   // both sides
		"opening_balances.csv:0:BALANCE",   // unbalanced
		"open_payables.csv:3:FK",           // SUP-009
		"open_payables.csv:3:NUMBER",       // empty number
		"open_payables.csv:3:CUTOVER",      // after cut-over
		"open_payables.csv:3:SIGN",         // negative
		"open_payables.csv:0:CONTROL",      // total vs AP opening
		"open_receivables.csv:1:HEADER",    // amount column missing
	} {
		if !got[want] {
			t.Errorf("not reported: %s", want)
		}
	}
	if len(s.Exceptions) < 17 {
		t.Errorf("%d exceptions, want at least 17", len(s.Exceptions))
	}
	// A missing file is an exception too, never a pass.
	m := Validate(Options{Dir: "testdata/does-not-exist", CutOver: time.Now(), MinorUnits: 2})
	if len(m.Exceptions) == 0 || !strings.Contains(m.Exceptions[0].Text, "missing") {
		t.Errorf("missing bundle: %+v", m.Exceptions)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
