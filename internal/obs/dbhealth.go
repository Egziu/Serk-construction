package obs

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DBHealth scrapes ops_health_metrics() (migration 0011) through a monitoring
// login that holds EXECUTE on that one function and nothing else: aggregates
// only, no tenant data. Each metric m becomes the gauge serk_<m>. A failed
// scrape yields serk_db_health_up 0 (the alert on it is the fail-safe: no
// data must page, not look healthy).
type DBHealth struct {
	Pool    *pgxpool.Pool
	Timeout time.Duration
}

var dbHelp = map[string]string{
	"outbox_pending_events":             "Outbox events not yet delivered and not dead-lettered.",
	"outbox_oldest_pending_age_seconds": "Age of the oldest undelivered outbox event (relay lag).",
	"outbox_dead_letters":               "Outbox events that exhausted delivery retries.",
	"ledger_integrity_violations":       "Rows returned by ledger_integrity_scan() (must be 0).",
	"audit_head_mismatches":             "Tenants whose audit head disagrees with the audit log (must be 0).",
	"workflow_effect_failures":          "Effect failures on ACTIVE workflow instances.",
	"workflow_overdue_steps":            "ACTIVE workflow instances past their step SLA.",
	"session_revocations_last_hour":     "Session revocations recorded in the last hour.",
	"approval_attestations_last_hour":   "Verified approval attestations recorded in the last hour.",
	"tenants":                           "Provisioned tenants.",
}

// Collector returns the scrape-time collector.
func (d DBHealth) Collector() Collector {
	return func() []Sample {
		timeout := d.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		start := time.Now()
		out := []Sample{}
		up := 0.0
		if d.Pool != nil {
			rows, err := d.Pool.Query(ctx, `SELECT metric, value::float8 FROM ops_health_metrics()`)
			if err == nil {
				var got []Sample
				for rows.Next() {
					var m string
					var v float64
					if err = rows.Scan(&m, &v); err != nil {
						break
					}
					got = append(got, Sample{Name: "serk_" + m, Help: dbHelp[m], Value: v})
				}
				rows.Close()
				if err == nil && rows.Err() == nil {
					out, up = got, 1
				}
			}
		}
		out = append(out,
			Sample{Name: "serk_db_health_up", Help: "1 when the last database health scrape succeeded.", Value: up},
			Sample{Name: "serk_db_health_scrape_seconds", Help: "Duration of the database health scrape.", Value: time.Since(start).Seconds()})
		return out
	}
}
