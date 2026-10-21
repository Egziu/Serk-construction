# Observability and SLOs (GATEA-11)

Status: **partially implemented.** The signals, rules and alert drill below were executed against PostgreSQL 16. Not done yet: a real Prometheus/Alertmanager, routing to on-call, and an OpenTelemetry collector (see §5).

## 1. Signals

| Source | Metric | Notes |
|---|---|---|
| API, `internal/obs` | `serk_http_requests_total{route,method,code}` | `route` is the ServeMux **pattern** (e.g. `POST /v1/journals/{id}/approve`), never the raw path, so cardinality stays bounded and ids never leak into labels |
| | `serk_http_request_duration_seconds{route}` | histogram; buckets 5 ms – 15 s, where 15 s is the request timeout |
| | `serk_auth_failures_total{reason}` | counted before authentication succeeds: `missing_or_oversized` or `invalid_token` |
| | `serk_revoked_session_uses_total` | a revoked token was presented |
| | `serk_session_check_errors_total` | revocation check failed; the request was refused with 503 (fail closed) |
| | `serk_db_authority_refusals_total{kind}` | the **database** refused an authority change the API attempted: `attestation` or `privilege`. This should never happen in normal operation. |
| | `serk_internal_errors_total` | unclassified 500s |
| DB, `ops_health_metrics()` (0011) via the `serk_metrics` login | `serk_outbox_pending_events`, `serk_outbox_oldest_pending_age_seconds`, `serk_outbox_dead_letters` | relay health |
| | `serk_ledger_integrity_violations` | rows from `ledger_integrity_scan()`; must be 0 |
| | `serk_audit_head_mismatches` | audit head vs log; must be 0. This is a cheap O(tenants) check. A full hash-chain verify runs at period close (kernel) and should also run as a nightly job, which is NOT YET SCHEDULED. |
| | `serk_workflow_effect_failures`, `serk_workflow_overdue_steps` | workflow engine |
| | `serk_session_revocations_last_hour`, `serk_approval_attestations_last_hour`, `serk_tenants` | activity |
| | `serk_db_health_up`, `serk_db_health_scrape_seconds` | the scrape itself. **0 pages**, because no data must never look healthy. |

The `serk_metrics` login is a member of `serk_monitor`, which holds `EXECUTE` on `ops_health_metrics()` only. It cannot read any table or call the ledger scan directly. This is tested by `TestPrivileges_MonitorSeesAggregatesOnly` and the catalog invariants. The metric output contains **no tenant identifiers, amounts or names**.

`/metrics` is served only on `SERK_METRICS_LISTEN`. That must be a separate, internal listener: config refuses to let it equal `SERK_LISTEN`, and refuses a monitor DSN without a listener.

## 2. Logs and traces

- **Log format.** Every request emits one JSON log line with `rid`, `trace_id`, `method`, `route`, `status` and `ms`. Authenticated requests also include `tenant` and `sub`. Bearer tokens are never logged; this is tested.
- **Trace context.** The API follows W3C Trace Context. An incoming `traceparent` is continued; otherwise a new trace is started. The response carries `traceparent`, so a reverse proxy or OpenTelemetry collector can stitch spans.
- **Not yet built.** No OTLP exporter exists; that needs the OTel SDK, which is not in the pinned dependency set. Plan: add `go.opentelemetry.io/otel` after a dependency review, behind the same `trace_id`.

## 3. Proposed SLOs (not guarantees; need operations sign-off)

| SLO | Proposed objective | Indicator | Alert |
|---|---|---|---|
| Availability | 99.5 % of requests not 5xx, over 30 days | `serk_http_requests_total` | `SerkAvailabilitySLOBurn` (fast burn 14.4×) |
| Latency | p95 < 1 s for command endpoints, over 30 days | `serk_http_request_duration_seconds` | `SerkLatencySLO` |
| Event delivery | 99 % of outbox events delivered within 5 min | `serk_outbox_oldest_pending_age_seconds` | `SerkOutboxLagHigh` / `Critical` |
| Ledger integrity | 0 violations, always | `serk_ledger_integrity_violations` | `SerkLedgerIntegrityViolation` (page) |

The directive says not to assert 99.99 %. These objectives are deliberately modest, and they are **not measured yet**: no staging traffic exists (GATEA-08 BLOCKED).

## 4. Alert drill (executed)

Test: `internal/httpapi/metrics_drill_test.go`. Evidence: `docs/operations/evidence/alert-drill-2026-10-21.txt`.

The drill creates a fresh database and checks that **no alert fires on a healthy baseline**. It then induces real failures:

- relay stuck for one hour;
- a dead-lettered event;
- an out-of-band unbalanced POSTED journal;
- a truncated audit tail;
- the tenant's approval key deactivated, so the database itself refuses the next API approval (409);
- 25 invalid tokens;
- a revoked session presented.

The rules in `deploy/observability/prometheus-alerts.yml` are then evaluated on the scraped metrics. Exactly these alerts fired: `SerkApprovalRefusedAtDatabase`, `SerkAuditChainMismatch`, `SerkAuthFailureSpike`, `SerkLedgerIntegrityViolation`, `SerkOutboxDeadLetters`, `SerkOutboxLagCritical`, `SerkOutboxLagHigh` and `SerkRevokedSessionUsed`.

Finally, closing the monitor connection fires `SerkDBHealthScrapeFailing`.

## 5. What is NOT tested

- **Expression evaluation.** The drill evaluates the simple threshold and `increase()` rule expressions itself. A real Prometheus does not evaluate them, and the `for:` durations are not exercised. Alertmanager routing, paging and silencing are not tested.
- **SLO rules.** `SerkAvailabilitySLOBurn` and `SerkLatencySLO` use PromQL ratios and quantiles and are **NOT TESTED**.
- **Non-firing only.** `SerkWorkflowEffectFailures` and `SerkSessionCheckUnavailable` were evaluated only as *not firing*; their positive cases were not drilled.
- **Not implemented:** slow-query alerts, unusual tenant data-access alerts and an OTLP trace export. These are required by directive §3.1.
