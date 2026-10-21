# Data flow and approval boundaries (implemented, not target)

## Command path (every state change)

```
client ──TLS──▶ proxy ──▶ serk-api
                           │ 1 pre-auth limiter (per IP) → token verify (OIDC/JWKS) → lockout on failures
                           │ 2 principal: user, tenant (from token), roles, projects, MFA, auth_time
                           │ 3 kernel command: RBAC + project scope + SoD (+ step-up MFA)
                           ▼
                     Router ──login serk_t_<tenant>──▶ PostgreSQL
                           │ BEGIN; bind: current_tenant() must equal the token's tenant
                           │ domain writes ──▶ triggers re-check invariants (balance, FX eligibility,
                           │                    period, immutability, precision, workflow gate)
                           │ audit_log insert (hash chain, SECURITY DEFINER)
                           │ outbox insert (same transaction)
                           │ COMMIT  (deferred balance constraint fires here)
                           ▼
serk-relay ──login serk_relay (serk_publisher)──▶ outbox (all tenants, read + mark only)
     │ leader advisory lock; per-aggregate order; backoff 2^n s (≤1 h); dead-letter; replay
     ▼
webhook target (HMAC-SHA256 signature, timestamp, event id) ──▶ consumer dedupe (processed_events)
```

## Approval boundaries

| Transition | Who | Enforced in Go | Enforced in PostgreSQL |
|---|---|---|---|
| journal DRAFT→APPROVED | `journal.approve`, ≠ preparer | `approveJournalTx` | SoD CHECK; workflow gate when mandatory |
| journal APPROVED→POSTED | `journal.post`, ≠ preparer, ≠ approver (strict) | `postJournalTx` (content hash) | balance, period OPEN (`FOR SHARE`), FX eligibility, workflow gate |
| FX rate PENDING→APPROVED | `fx.approve`, ≠ maker; outside tolerance `fx.approve_exception` + MFA + reason | `approveFXSnapshotTx` | `fx_snapshots_guard` (maker≠checker, variance flags), workflow gate |
| FX source / policy / WBS version / workflow definition → approved | checker ≠ maker | kernel | guards with maker≠checker CHECKs |
| period OPEN→CLOSED/LOCKED | `period.close` | `closePeriodTx` (integrity scan, audit chain) | no approved-unposted journals; closing TB record; workflow gate |
| period CLOSED→OPEN | `period.reopen`, MFA, reason, ≠ closer | `ReopenPeriod` | reason + reopener ≠ closer |
| workflow step decision | step permission + scope, SoD set, MFA if required | `DecideWorkflow` | `workflow_decisions_guard` (open step, SoD set, MFA flag) |
| workflow effect | the approver who completes the quorum | `executeEffect` → same kernel functions | `workflow_effects_guard` (quorum, executor ∈ approvers); subject gate (same txid) |

## Workflow instance lifecycle

```
start (start_permission) ── facts loaded from the subject, route frozen, deadlines derived by DB
   │
   ▼
ACTIVE, step k open ──decision APPROVE (k)──▶ quorum reached? ──no──▶ wait
   │            │                                  │yes
   │            │                                  ▼
   │            │                      effect as decider (same txn) ──refused──▶ rollback; failure counted
   │            │                                  │ok
   │            │                                  ▼
   │            │                       advance (k+1) or COMPLETED
   │            ├─decision REJECT (reason)──▶ on_reject compensation (savepoint) ──▶ REJECTED
   │            ├─timer: SLA passed ──▶ ESCALATED (notify escalate_to; no authority)
   │            ├─timer: expiry passed ──▶ EXPIRED (no effect)
   │            └─admin cancel (reason) ──▶ CANCELLED (subject unchanged)
```

Timers: `serk-api` (with `SERK_SCHEDULER_DSN`) asks `workflow_due_tenants()`
as `serk_timer` (learns tenant ids only), then processes each tenant through
that tenant's own login with `FOR UPDATE SKIP LOCKED`.
