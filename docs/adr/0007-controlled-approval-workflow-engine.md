# ADR 0007 — Controlled-approval workflow engine: automation routes, people authorize

**Status:** Accepted · 2026-10-21

## Context
The master prompt (§07, Law C) requires a configurable, versioned workflow
engine with thresholds, SoD, parallel approvals, durable timers, escalation,
expiry, compensation, dry runs and an execution console — and forbids
unrestricted automation of payments or financial records. Building ERP
modules (BOQ, procurement, contracts) before this exists would give each module
its own ad-hoc approval logic.

## Decision
1. **Definitions are data, versioned and governed.** JSON definitions are
   parsed strictly (unknown fields refused) and validated against a catalog of
   effects and the role catalogue's permissions. They are proposed by
   `workflow.define`, published by a *different* person with `workflow.publish`
   and a fresh MFA; the database enforces immutability, maker≠checker and
   "one published version per key". Publishing v2 retires v1 (retirement is
   possible only that way). Instances of a superseded version can no longer
   act — they may be weaker than the version in force — and are cancelled and
   restarted; their recorded route and history are kept unchanged.
2. **Effects execute as the deciding human.** A step's effect (e.g.
   `journal.post`) runs, in the same transaction as the decision, through the
   same kernel function the direct API uses, with the decider's principal. So
   permissions, project scope, SoD, MFA step-up, variance exceptions and every
   database invariant apply unchanged. There is no system principal that can
   approve; the timer worker can only escalate (notify) and expire.
3. **The validator refuses control-weakening definitions:** a sensitive effect
   must sit on a step whose permission equals the effect's permission, must
   not be conditional (it would be skipped below a threshold), must not repeat,
   and must exclude the subject's maker and the approvers of every earlier
   sensitive step (so a quorum of N means N independent people); SoD
   references may only point to earlier steps; compensation (`on_reject`)
   must be non-sensitive; thresholds are exact amounts per currency (no
   silent FX); a *mandatory* definition must perform every sensitive
   transition of its subject.
4. **Mandatory workflows close the direct path in the database.** When a
   mandatory definition is published for a subject type, the gate triggers on
   `journals`, `fx_snapshots` and `fiscal_periods` refuse the sensitive
   transition unless the **same transaction** inserted a matching
   `workflow_effects` row executed by the person the transition names
   (`approved_by`, `posted_by`, `closed_by`) **and** belongs to an instance of
   that mandatory definition. That row can only be inserted when the open
   step has its quorum of distinct approvers recorded in the append-only
   `workflow_decisions`, which in turn enforce the step's SoD rules, MFA flag
   and expiry in SQL, independently of the Go code. While a mandatory
   definition governs a subject type, no other definition can start or act
   for it. Publishing/retiring and the gates serialise on an advisory lock.
   The database recomputes every new instance's route from the definition
   and verifies its facts against the subject, so application code cannot
   start an instance with fewer approvers, missing SoD rules or a skipped
   threshold step.
5. **Nothing is stranded.** A journal that is already APPROVED (rejection
   or cancellation after the approval step, expiry, or approval before the
   workflow was made mandatory) can be routed again; the route resumes after
   the definition's approval step and the earlier approver is excluded
   wherever the route refers to that step. Rejection compensation
   (`journal.cancel`) is open to holders of `journal.approve` or
   `journal.post`.
6. **Facts are server-derived and pinned.** Routing inputs (amount, currency,
   creator, project) are loaded from the stored subject, frozen with a
   fingerprint at start and re-checked at every decision; a changed subject
   invalidates the instance.
7. **Failure is all-or-nothing and visible.** If the kernel refuses an effect
   (e.g. a period with unposted journals), the decision is rolled back and the
   failure is counted on the instance (`effect_failures`, `last_error`,
   history `EFFECT_FAILED`, outbox `workflow.effect_failed`) for the console.
8. **Timers are durable.** Deadlines are derived by the database from the
   frozen route. Workers claim due instances with `FOR UPDATE SKIP LOCKED`;
   state lives only in PostgreSQL, so restarts lose nothing. A
   `serk_scheduler` login learns only which tenants have due work.

## Consequences
+ Every future module (procurement awards, IPC certification, variations,
  payment release) plugs in as new subjects/effects and inherits the same
  guarantees instead of re-implementing approvals.
+ Adversarial tests prove forged trails are refused by the database
  (`TestWorkflow_DatabaseRefusesForgedTrail`).
− The database cannot see end-user permissions or MFA; those are enforced in
  Go. A compromised application process can still assert them (THREAT_MODEL).
− Period reopen, period lock-after-close and FX withdrawal (APPROVED→
  DISPUTED) are not workflow effects: reopen keeps its own MFA + reason +
  SoD control; lock and withdrawal only reduce what can be done.
− Metrics count instances, not subjects (a rejected-then-restarted journal
  counts once per instance).
− Not yet built: delegation/out-of-office, business calendars for SLAs,
  designer UI, idempotency keys on start (one ACTIVE instance per subject is
  enforced instead), per-step notification channels beyond outbox events.
