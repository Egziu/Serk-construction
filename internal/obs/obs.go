// Package obs is SERK's dependency-free observability core: counters and
// histograms rendered in the Prometheus text exposition format (0.0.4),
// collectors for externally sourced gauges (database health), and W3C Trace
// Context helpers so every log line carries a trace id that an OpenTelemetry
// collector or proxy can correlate.
//
// It deliberately has no third-party dependency: the build is reproducible
// from the pinned go.sum, and the exposition format is small and stable.
package obs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// Sample is one gauge value produced by a Collector.
type Sample struct {
	Name   string
	Help   string
	Labels map[string]string
	Value  float64
}

// Collector produces gauges at scrape time (e.g. from the database).
type Collector func() []Sample

// Registry holds metrics and collectors.
type Registry struct {
	mu         sync.Mutex
	counters   []*CounterVec
	histograms []*HistogramVec
	collectors []Collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

func mustName(n string) {
	if !nameRe.MatchString(n) {
		panic("obs: invalid metric name " + n)
	}
}

// CounterVec is a monotonically increasing counter with labels.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	vals       map[string]float64
	keys       map[string][]string
}

// Counter registers a counter vector.
func (r *Registry) Counter(name, help string, labels ...string) *CounterVec {
	mustName(name)
	c := &CounterVec{name: name, help: help, labels: labels, vals: map[string]float64{}, keys: map[string][]string{}}
	r.mu.Lock()
	r.counters = append(r.counters, c)
	r.mu.Unlock()
	return c
}

func key(vs []string) string { return strings.Join(vs, "\x00") }

// Add adds v (>= 0) for the label values (same order as declared).
func (c *CounterVec) Add(v float64, labelValues ...string) {
	if c == nil || v < 0 || len(labelValues) != len(c.labels) {
		return
	}
	k := key(labelValues)
	c.mu.Lock()
	c.vals[k] += v
	if _, ok := c.keys[k]; !ok {
		c.keys[k] = append([]string(nil), labelValues...)
	}
	c.mu.Unlock()
}

// Inc adds one.
func (c *CounterVec) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Value returns the current value (tests, alert drills).
func (c *CounterVec) Value(labelValues ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vals[key(labelValues)]
}

// HistogramVec is a cumulative-bucket histogram with labels.
type HistogramVec struct {
	name, help string
	labels     []string
	buckets    []float64
	mu         sync.Mutex
	series     map[string]*histSeries
}

type histSeries struct {
	labelValues []string
	counts      []uint64 // per bucket (non-cumulative), last = +Inf
	sum         float64
	count       uint64
}

// DefaultLatencyBuckets suit an HTTP API with a 15 s request timeout.
var DefaultLatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15}

// Histogram registers a histogram vector.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *HistogramVec {
	mustName(name)
	b := append([]float64(nil), buckets...)
	sort.Float64s(b)
	h := &HistogramVec{name: name, help: help, labels: labels, buckets: b, series: map[string]*histSeries{}}
	r.mu.Lock()
	r.histograms = append(r.histograms, h)
	r.mu.Unlock()
	return h
}

// Observe records v.
func (h *HistogramVec) Observe(v float64, labelValues ...string) {
	if h == nil || len(labelValues) != len(h.labels) || math.IsNaN(v) {
		return
	}
	k := key(labelValues)
	h.mu.Lock()
	s := h.series[k]
	if s == nil {
		s = &histSeries{labelValues: append([]string(nil), labelValues...), counts: make([]uint64, len(h.buckets)+1)}
		h.series[k] = s
	}
	i := sort.SearchFloat64s(h.buckets, v) // first bucket with upper bound >= v
	s.counts[i]++
	s.sum += v
	s.count++
	h.mu.Unlock()
}

// Collect registers a scrape-time collector.
func (r *Registry) Collect(c Collector) {
	r.mu.Lock()
	r.collectors = append(r.collectors, c)
	r.mu.Unlock()
}

func escLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func escHelp(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(v)
}

func labelStr(names, values []string, extra ...string) string {
	parts := make([]string, 0, len(names)+1)
	for i, n := range names {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, n, escLabel(values[i])))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, extra[i], escLabel(extra[i+1])))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func num(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// WriteTo renders every metric in the text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder
	r.mu.Lock()
	counters := append([]*CounterVec(nil), r.counters...)
	hists := append([]*HistogramVec(nil), r.histograms...)
	collectors := append([]Collector(nil), r.collectors...)
	r.mu.Unlock()

	for _, c := range counters {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", c.name, escHelp(c.help), c.name)
		c.mu.Lock()
		ks := make([]string, 0, len(c.vals))
		for k := range c.vals {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(&b, "%s%s %s\n", c.name, labelStr(c.labels, c.keys[k]), num(c.vals[k]))
		}
		c.mu.Unlock()
	}
	for _, h := range hists {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, escHelp(h.help), h.name)
		h.mu.Lock()
		ks := make([]string, 0, len(h.series))
		for k := range h.series {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			s := h.series[k]
			var cum uint64
			for i, ub := range h.buckets {
				cum += s.counts[i]
				fmt.Fprintf(&b, "%s_bucket%s %d\n", h.name, labelStr(h.labels, s.labelValues, "le", num(ub)), cum)
			}
			cum += s.counts[len(h.buckets)]
			fmt.Fprintf(&b, "%s_bucket%s %d\n", h.name, labelStr(h.labels, s.labelValues, "le", "+Inf"), cum)
			fmt.Fprintf(&b, "%s_sum%s %s\n", h.name, labelStr(h.labels, s.labelValues), num(s.sum))
			fmt.Fprintf(&b, "%s_count%s %d\n", h.name, labelStr(h.labels, s.labelValues), s.count)
		}
		h.mu.Unlock()
	}
	// Collector samples are grouped by name so each family gets one header.
	families := map[string][]Sample{}
	var order []string
	for _, c := range collectors {
		for _, s := range c() {
			if !nameRe.MatchString(s.Name) {
				continue
			}
			if _, ok := families[s.Name]; !ok {
				order = append(order, s.Name)
			}
			families[s.Name] = append(families[s.Name], s)
		}
	}
	sort.Strings(order)
	for _, n := range order {
		ss := families[n]
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", n, escHelp(ss[0].Help), n)
		for _, s := range ss {
			names := make([]string, 0, len(s.Labels))
			for k := range s.Labels {
				names = append(names, k)
			}
			sort.Strings(names)
			vals := make([]string, len(names))
			for i, k := range names {
				vals[i] = s.Labels[k]
			}
			fmt.Fprintf(&b, "%s%s %s\n", n, labelStr(names, vals), num(s.Value))
		}
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Handler serves the registry. Mount it on an internal-only listener.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = r.WriteTo(w)
	})
}

// ---------------------------------------------------------------------------
// W3C Trace Context (https://www.w3.org/TR/trace-context/)
// ---------------------------------------------------------------------------

var traceparentRe = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

// ParseTraceparent returns the trace id and parent span id of a valid
// version-00 traceparent header. All-zero ids are invalid per the spec.
func ParseTraceparent(h string) (traceID, parentID string, ok bool) {
	m := traceparentRe.FindStringSubmatch(strings.TrimSpace(h))
	if m == nil || m[1] == strings.Repeat("0", 32) || m[2] == strings.Repeat("0", 16) {
		return "", "", false
	}
	return m[1], m[2], true
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b)
}

// NewTraceID returns a random 16-byte trace id.
func NewTraceID() string { return randHex(16) }

// NewSpanID returns a random 8-byte span id.
func NewSpanID() string { return randHex(8) }

// Traceparent formats a sampled version-00 header.
func Traceparent(traceID, spanID string) string { return "00-" + traceID + "-" + spanID + "-01" }
