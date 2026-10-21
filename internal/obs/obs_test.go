package obs

import (
	"bytes"
	"strings"
	"testing"
)

func TestExpositionFormat(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("serk_test_total", "A test counter.", "route", "code")
	c.Inc("GET /v1/x/{id}", "200")
	c.Add(2, "GET /v1/x/{id}", "200")
	c.Inc(`we"ird\path`+"\n", "500")
	c.Add(-5, "GET /v1/x/{id}", "200") // negative increments are ignored
	c.Inc("only-one-label")            // wrong arity is ignored
	h := r.Histogram("serk_test_seconds", "A test histogram.", []float64{0.1, 1}, "route")
	for _, v := range []float64{0.05, 0.1, 0.5, 3} {
		h.Observe(v, "r")
	}
	r.Collect(func() []Sample {
		return []Sample{{Name: "serk_gauge", Help: "g", Value: 7}, {Name: "bad name!", Value: 1}}
	})
	var b bytes.Buffer
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE serk_test_total counter",
		`serk_test_total{route="GET /v1/x/{id}",code="200"} 3`,
		`serk_test_total{route="we\"ird\\path\n",code="500"} 1`,
		"# TYPE serk_test_seconds histogram",
		`serk_test_seconds_bucket{route="r",le="0.1"} 2`, // 0.05 and 0.1 (le is inclusive)
		`serk_test_seconds_bucket{route="r",le="1"} 3`,
		`serk_test_seconds_bucket{route="r",le="+Inf"} 4`,
		`serk_test_seconds_sum{route="r"} 3.65`,
		`serk_test_seconds_count{route="r"} 4`,
		"# TYPE serk_gauge gauge",
		"serk_gauge 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bad name") || strings.Contains(out, "only-one-label") {
		t.Errorf("invalid samples rendered:\n%s", out)
	}
}

func TestTraceparent(t *testing.T) {
	tid, pid, ok := ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok || tid != "4bf92f3577b34da6a3ce929d0e0e4736" || pid != "00f067aa0ba902b7" {
		t.Fatalf("%q %q %v", tid, pid, ok)
	}
	for _, bad := range []string{
		"", "garbage",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace id
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zero parent
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase is invalid
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // unknown version
	} {
		if _, _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if id := NewTraceID(); len(id) != 32 || id == NewTraceID() {
		t.Errorf("trace id %q", id)
	}
	if tp := Traceparent(strings.Repeat("a", 32), strings.Repeat("b", 16)); tp != "00-"+strings.Repeat("a", 32)+"-"+strings.Repeat("b", 16)+"-01" {
		t.Error(tp)
	}
}

func TestDBHealthWithoutPoolReportsDown(t *testing.T) {
	var up float64 = -1
	for _, s := range (DBHealth{}).Collector()() {
		if s.Name == "serk_db_health_up" {
			up = s.Value
		}
	}
	if up != 0 {
		t.Fatalf("serk_db_health_up = %v, want 0", up)
	}
}
