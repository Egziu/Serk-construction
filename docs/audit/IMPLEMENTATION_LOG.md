# Implementation log — remediation/gate-a

Each entry: what changed, why, how it was tested, what remains. Test results
are from real runs (Go 1.24.7, PostgreSQL 16.15, `-race`, fresh database,
empty module cache with `GOFLAGS=-mod=readonly`, no `go.work`).

## 1. Baseline (commit a754814)
See `BASELINE.md`. 61/61 tests passed on the untouched code while seven audit
findings were exploitable; live reproductions recorded for SC-01, SC-04,
SC-08 and SC-14 before any change.

## 2. Ledger integrity — SC-01, SC-14 (commit 3bec626, migration 0002)
- **Changed:** `journal_lines_guard` now checks the OLD and NEW journal (both
  must be DRAFT, both locked `FOR SHARE`); line identity columns immutable;
  balance asserted for OLD and NEW journals; `UPDATE` privilege on
  `journal_lines` narrowed to `memo` (column grants on every kernel table);
  currency minor-unit enforcement; `ledger_integrity_scan()`;
  `migration_exceptions` records legacy violations instead of rewriting them
  (released migration 0001 untouched).
- **Tested:** `TestSC01_*` attack as the tenant role *and* as the schema owner
  (trigger, not just privilege); `TestSC14_*` ETB/UGX/TND.
- **Remains:** superuser trigger bypass is detectable, not preventable.

## 3. FX correctness and control — SC-02, SC-03, SC-07 (3bec626)
- **Changed:** trusted-source registry and versioned entity FX policies, both
  maker/checker; snapshots born PENDING; variance gate with exception
  permission + MFA + reason; lines bind policy id/version and DB-time selection
  instant; `fx_assert_eligible()` at insert and post; FX commands emit outbox
  events through the common `record()` path.
- **Tested:** `TestSC02_*` (future-effective, unpublished-at-cutoff, stale,
  wrong type, untrusted source, wrong entity, re-check at post),
  `TestSC03_FXMakerChecker`, `TestSC07_*`, API flow incl. RFC 9470 challenge.

## 4. Concurrency — SC-08 (3bec626)
- **Changed:** `FOR SHARE` on the covering period at post and on snapshots at
  line insert/post; close locks the period first.
- **Tested:** six controlled-interleaving tests. **Mutation check:** the
  `FOR SHARE` clauses were removed one at a time (`mut_journals_guard.sql`,
  `mut_fx_assert_eligible.sql`); the corresponding tests failed; one test
  initially passed against a mutant because the kernel path held `FOR UPDATE`
  — a raw-SQL variant was added (`TestSC08_RawFXWithdrawalWaitsForInFlightLine`).

## 5. Tenancy — SC-04, SC-05 (commit 72ced9b, migration 0003)
- **Changed:** per-tenant LOGIN roles, `current_tenant()` from `session_user`,
  Router with HMAC-derived credentials and dedicated tier, fail-closed binding,
  explicit `scope.tenant_wide`.
- **Tested:** hostile SQL as tenant A (`set_config`, `SET ROLE`, functions,
  sequences, audit verification), misrouting, dedicated tier, scope matrix.
  **Mutation check:** reverting `current_tenant()` to the GUC makes
  `TestSC04_CompromisedTenantCredentialCannotReachOtherTenant` fail.
- **Remains:** API-process compromise (THREAT_MODEL T-4).

## 6. Deployment, supply chain, abuse, analytics — SC-06, SC-09, SC-10, SC-12, SC-13; OIDC (commit 1e92384, migrations 0004–0005)
- Fail-closed configuration; production compose; relay with leader lock,
  ordering, backoff, dead-letter, replay, signed webhooks, consumer dedupe;
  OIDC JWKS verifier with MFA by `amr` factor categories; pre-auth abuse
  controls; EVM v2 basis rules; WBS/cost codes; `go.sum` with provenance; CI
  pinned by SHA with `sum.golang.org` re-derivation, govulncheck, SBOM.
- **Remains:** CI and Docker not executed here; 4 `go.sum` hashes awaiting
  `sum.golang.org` comparison in CI.

## 7. Controlled-approval workflow engine (commits e0a1167, e2c19a5, migration 0006)
**Why now:** procurement, contracts and certification all need approvals;
building them first would give each module its own approval logic. Decision
recorded in ADR 0007.

- **Changed:**
  - `pkg/workflow`: strict definition parser, validator (control invariants),
    deterministic threshold routing (no cross-currency comparison), dry-run.
  - Migration 0006: definitions (immutable, maker/checker, one published per
    key, one mandatory per subject), instances (frozen facts/route,
    DB-derived deadlines, one ACTIVE per subject), append-only decisions /
    effects / history, SQL SoD (`workflow_excluded`) and MFA flag check,
    quorum check before effects, gate triggers on journals / FX snapshots /
    fiscal periods requiring an effect in the **same transaction**,
    `serk_scheduler` + `workflow_due_tenants()`.
  - Kernel: approve/post/cancel/close/FX-approve/FX-reject refactored into
    transaction-scoped functions shared by the API and workflow effects;
    `ProposeWorkflowDefinition`, `DecideWorkflowDefinition` (MFA),
    `SimulateWorkflow`, `StartWorkflow`, `DecideWorkflow` (quorum, SoD, MFA,
    subject-drift check, effect as decider, failure recording),
    `CancelWorkflow`, `RunWorkflowTimers`/`RunDueWorkflowTimers`, console
    queries and metrics.
  - API: 13 endpoints under `/v1/workflow`; error codes `workflow_required`,
    `subject_changed`; OpenAPI 0.2.0.
  - `serk-api` runs the timer loop when `SERK_SCHEDULER_DSN` is configured.
  - New permission `approval.high_value` (CFO role).
- **Tested (all pass):** 11 kernel integration tests, 2 validator tests,
  1 HTTP test:
  mandatory path closure (API and raw SQL), small vs high-value routing,
  2-of-N executive quorum with MFA, SoD in Go and SQL, forged-trail attacks
  (12 raw-SQL attacks), rejection with compensation, effect failure rollback
  and console visibility, reopen-then-reclose with a stale effect, subject
  drift, durable/idempotent timers via a fresh service and the scheduler
  login, definition governance (maker/checker, MFA, versioning, frozen route,
  one mandatory per subject), concurrent deciders (exactly one effect), FX
  variance controls through the workflow, tenant isolation, full HTTP console.
- **Mutation checks** (each control removed, suite re-run):

  | Mutant | Result |
  |---|---|
  | quorum check removed from `workflow_effects_guard` | killed |
  | same-transaction (`txid`) check removed from the gate | **survived** → added reopen-then-reclose attack → killed |
  | subject-drift comparison removed in Go | **survived** (DB immutability made it unreachable) → added drift test with triggers bypassed → killed |
  | MFA check removed in Go | killed |
  | Go SoD check removed | killed |
  | SQL SoD ignores `step:` references | killed |
  | SQL MFA-flag check removed | **survived** → added raw decision without MFA → killed |
  | escalation guard removed | killed |

- **Bug found by the new tests before release:** the FX gate trigger used
  `NEW.id` (column is `snapshot_id`) — R-04 in the register.

## 8. Evidence re-run
`docs/audit/evidence/gate-a-after.sh` replays the audit's raw-SQL attacks as a
tenant's own login against the migrated schema; output in `GATE-A-after.txt`
(SC-01 refused by privilege and, for the superuser, by trigger; SC-04 zero
foreign rows after `set_config`; SC-14 refused; mandatory workflow gate and
forged effect refused).

## 9. Independent review of the workflow engine and its disposition (commit a40566d)
An independent reviewer (separate agent, no access to the author's
reasoning, threat model: end users, compromised application SQL, concurrency,
tenancy, definition authors) reviewed commit e2c19a5 and reproduced nine
exploits against a separate database. Every reproduction was turned into a
regression test (`internal/kernel/workflow_review_test.go`) that **fails on
e2c19a5 and passes after the fix** (verified by running the new tests against
the old code: 10/10 failed).

| # | Sev. | Finding | Fix | Test |
|---|---|---|---|---|
| R1 | HIGH | A non-mandatory definition (or an instance started before) satisfied the mandatory gate through the normal API. | Gate requires the effect's instance to belong to the published mandatory definition; `workflow_assert_governing()` in instance/decision/effect guards; Go `assertGoverning` and start check. | `TestReview_R1_*` |
| R2 | HIGH | Application SQL could insert an instance with a weakened route or false facts and then satisfy the gate. | `workflow_check_start()` recomputes the route from the definition and verifies facts against the subject row. | `TestReview_R2_*` |
| R3 | HIGH | One UPDATE retired the mandatory definition, without actor. | Retirement only inside the publish of the next version (`pg_trigger_depth`), also for the schema owner. | `TestReview_R3_*`, `TestWorkflow_DatabaseRefusesForgedTrail` |
| R4 | HIGH | Rejection at the post step / expiry / cancel stranded an APPROVED journal and blocked period close. | Resume APPROVED journals after the approval step with the earlier approver excluded (Go + SQL); cancel compensation open to `journal.post` holders. | `TestReview_R4_*` |
| R5 | MEDIUM | An expired step could still be approved before the timer ran. | Expiry checked in Go and SQL. | `TestReview_R5_*` |
| R6 | — | Superseded version instance still acted (variant of R1). | Same as R1. | `TestReview_R6_*`, `TestWorkflow_DefinitionGovernance` (changed: superseded instances are cancelled and restarted) |
| R7 | MEDIUM | A quorum could include the maker. | Validator: sensitive steps must exclude `subject.creator` and earlier sensitive steps. | `TestReview_R7_*`, validator cases |
| R8 | HIGH | Raw approval racing a mandatory version switch passed the gate (snapshot/EPQ gap). | Advisory lock: exclusive in the definitions guard, shared (then fresh read, VOLATILE) in gates and governing checks. | `TestReview_R8_*` |
| R9 | LOW | Finished instances' end details rewritable. | Finished instances fully immutable; end details only with the end. | `TestReview_R9_*` |
| R10 | LOW | Validator gaps: threshold DoS via huge exponent, cross-currency deadlock, thresholds on amount-less subjects, fractional durations. | Per-currency threshold list parsed as exact money; journal-only; whole-unit durations shared with SQL. | validator cases |
| R11 | LOW | Raw PostgreSQL errors in `last_error`; out-of-scope existence probes; misleading conflict text; tasks limited to newest 500. | `consoleError`; not-found for out-of-scope; generic text; SQL-filtered task query, oldest first. | `TestReview_R11_*` |
| R12 | LOW/INFO | Timer interval overflow; one failing instance rolled back the batch; body hash never verified; reopen/withdraw not in catalog; metrics per instance. | Interval ≤ 3600 s; per-instance savepoints; canonical hash verified on every use; the last two documented in ADR 0007. | config test, suite |

Not changed, by decision: a database CHECK that `posted_by ≠ approved_by`
(strict SoD is a deployment setting enforced in Go; under a mandatory workflow
the definition-verified route already makes SQL exclude the approver from the
post step); conditional steps after the last sensitive effect (harmless).

**Mutation checks of the new controls** (control removed, suite re-run): gate
lock → R8 fails; start check → R2 fails; governing check in the decision
guard → R1 fails; Go governing check → R1, R6, governance fail; retirement
depth check → R3 and forged-trail fail; SQL expiry check → R5 fails; final
freeze → R9 fails; Go resume exclusion → R4 fails (SQL exclusion still
refuses independently).

## 10. Second independent review (re-verification of a40566d) and disposition
A second, separate reviewer re-tested every fix against a live database.
Verdict: R1, R2, R5, R6, R7, R8, R9, R10, R12 closed; R3 not closed, R4 and
R11 partial; five new defects. All were fixed and turned into regression
tests (`internal/kernel/workflow_reverify_test.go`); the five defect tests
fail on a40566d and pass now (RV-2 is a race and RV-7 an equivalence check,
both passing before and after).

| # | Sev. | Finding | Fix |
|---|---|---|---|
| RV-6 | HIGH | R3 bypass: a tenant login raised `pg_trigger_depth()` with a temporary trigger and retired the mandatory definition. | The application role has **no UPDATE privilege** on `workflow_definitions`; status changes only inside `workflow_decide_definition()` (owner rights, transaction-local marker), which retires a version only while publishing its successor and refuses to publish an older draft over a newer version. `TEMPORARY` revoked from PUBLIC. |
| RV-1 | HIGH | After resume only the completing approver was excluded; another member of the approval quorum could post alone. | When a route refers to a step it does not contain, the journal's approver **and every approver of earlier instances of the same subject** are excluded — in Go and SQL. |
| RV-3 | MEDIUM | Another tenant could block this tenant's gate (and the relay) through advisory locks, which ignore RLS. | Gate serialisation moved to an RLS-protected lock row per (tenant, subject); `pg_*advisory*` functions revoked from PUBLIC (granted to `serk_publisher` and the owner; `deploy/02-restrict-advisory-locks.sql` when migrations do not run as superuser). |
| RV-4 | LOW-MED | CancelWorkflow ignored project scope. | Out-of-scope → not found. |
| RV-2 | LOW | Start vs publish could deadlock (definition row share lock taken before the gate lock). | Gate lock first everywhere; definition row locks removed (the gate lock makes them unnecessary); 40P01/40001 mapped to a retryable conflict. |
| RV-5 | LOW | Effect insert and step advance accepted after expiry (tenant SQL only). | Expiry checked in the effects guard and on advance. |

Accepted / documented (not changed): non-sensitive gating steps are not
forced to exclude the maker (only sensitive steps are); an instance that can
no longer act blocks new starts on its subject until cancelled or expired;
resuming skips pre-approval steps for journals approved outside the current
version; `now()` is transaction start time. The database still cannot verify
end-user identity (T-3a).
