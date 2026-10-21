# Threat model — financial kernel and workflow engine (as implemented)

Scope: what exists in this repository at the commit this file ships with —
the Go API (`serk-api`), the PostgreSQL 16 schema (migrations 0001–0006), the
outbox relay (`serk-relay`), the migrator and the workflow timers. ERP modules
not yet built are out of scope. Method: STRIDE per trust boundary, then the
attacker profiles the audit asked us to test. "Tested" means an automated test
in this repository attacks the control; "designed" means it is not yet tested.

## Assets
A1 posted ledger and its history · A2 approval evidence (who approved what,
with what authority) · A3 FX rates and policies · A4 tenant separation ·
A5 workflow definitions (they *are* the control configuration) · A6 audit
chain and outbox · A7 secrets (tenant-credential secret, webhook secret,
OIDC trust) · A8 availability of approvals and posting.

## Trust boundaries
B1 internet → TLS proxy → API · B2 API → PostgreSQL (per-tenant login) ·
B3 relay → PostgreSQL (`serk_publisher`) and → webhook target ·
B4 timer worker → PostgreSQL (`serk_scheduler`, then per-tenant login) ·
B5 operator/migrator → PostgreSQL (schema owner) · B6 IdP → API (JWKS).

## Attacker profiles and results

| # | Attacker | Can | Cannot (enforced by) | Status |
|---|---|---|---|---|
| T-1 | Unauthenticated internet client | send requests | get past pre-auth limits, invalid-token lockout, strict JSON, body caps (SC-13) | tested |
| T-2 | Authenticated user acting within roles | anything their roles allow | self-approve (Go SoD + DB CHECK), post what they approved (strict SoD), reach other projects/tenants (SC-05, SC-04), approve out-of-tolerance FX without exception permission + MFA + reason (SC-03), bypass a mandatory workflow (DB gate), decide a step twice, decide a step whose SoD excludes them (Go **and** SQL) | tested |
| T-3 | Arbitrary SQL as **one tenant's** DB login (compromised credential, injection) | read/write that tenant's rows within column grants | read other tenants (SC-04); move/alter posted lines (SC-01); post into closed periods; use ineligible FX (SC-02); approve a journal/rate/period under a mandatory workflow without a recorded quorum, in the same transaction, on an instance of that mandatory definition; start an instance whose route or facts differ from the definition and the subject; use an optional or superseded definition; retire a definition other than by publishing its successor through the decide function (no UPDATE privilege; temporary objects revoked — publishing under invented names is T-3a); block another tenant's gate or the relay (no advisory locks; RLS-protected gate rows); race a version switch; decide expired, out-of-order or SoD-excluded steps; alter finished instances; push deadlines; edit published definitions | tested (`TestSC04_*`, `TestSC01_*`, `TestWorkflow_DatabaseRefusesForgedTrail`, `TestReview_R1…R9`, `TestReverify_RV1…RV6`, `GATE-A-after.txt`) |
| T-3a | same, but fabricating identities | insert decisions in the names of people who never decided, with `mfa=true`, if those names satisfy the (now definition-verified) SoD rules and quorum; the database has no knowledge of end-user identity or permissions | — | **residual**: the forged trail must still have the full number of distinct, SoD-eligible names the definition requires; detection via the audit chain (decisions without matching API audit entries). Mitigation path: signed decision assertions (IdP-issued, verified in SQL) — NEXT #2 |
| T-4 | Compromise of the **API process** | the tenant-credential derivation secret → every tenant role; OIDC trust; assert any principal | alter posted history (triggers), forge a consistent audit chain silently (hash chain verification), mark outbox rows sent (no `serk_publisher` membership) | **residual**: confidentiality and integrity of new transactions for all tenants. Mitigation path: per-tenant vault secrets, dedicated DB tier, process isolation |
| T-5 | Workflow definition author (process owner) | propose definitions | publish them (maker≠checker + MFA, DB-enforced); propose a definition with a sensitive effect on a step decided by people lacking that effect's permission, a conditional sensitive step, a sensitive compensation, forward SoD references, unknown permissions/effects, or a mandatory definition that omits a sensitive transition (validator) | tested (`TestValidatorRefusesUnsafeDefinitions`, `TestWorkflow_DefinitionGovernance`) |
| T-6 | Concurrency abuser (races two approvals / close vs post / withdraw vs line) | send parallel requests | double-execute an effect (instance row lock + unique effect per step), post into a closing period, use a rate being withdrawn (SC-08 locks) | tested (`TestWorkflow_ConcurrentDecisionsExecuteTheEffectOnce`, `TestSC08_*`, mutation-verified) |
| T-7 | Schema owner / superuser | everything, including disabling triggers | silently: the audit chain and `ledger_integrity_scan()` detect tampering after the fact | designed + integrity scan tested |
| T-8 | Webhook receiver impersonator / replayer | send forged or replayed events to consumers | pass HMAC verification, timestamp window, event-id replay check | tested (relay tests) |
| T-9 | Timer worker / automation | escalate and expire | approve, post, close or reject anything (no code path; `system:workflow-timer` holds no roles; DB requires an approver's decision for every effect) | tested (`TestWorkflow_TimersEscalateOnceAndExpire`) |

## STRIDE summary of the workflow engine

| Threat | Control | Where |
|---|---|---|
| Spoofing an approver | Principal from verified token; DB requires decider ∈ approvers of the step for the effect row | `DecideWorkflow`, `workflow_effects_guard` |
| Tampering with definitions/route/decisions/history | Immutable definitions; column grants exclude route/facts/deadlines; decisions/effects/history append-only | 0006 grants + triggers |
| Repudiation | Every decision, effect, escalation, expiry and cancellation is audited (hash chain) and emitted as an outbox event | `record()` |
| Information disclosure | RLS on all workflow tables; instance reads filtered by project scope; scheduler learns tenant ids only; error messages strip identifiers | 0006, `GetWorkflowInstance`, `trimPG` |
| Denial of service | One ACTIVE instance per subject; bounded list sizes; timers batch-limited; SKIP LOCKED | indexes, `DueWorkflowInstances` |
| Elevation of privilege | Effects run as the decider through kernel commands (no system principal); validator invariants; mandatory gate in DB | ADR 0007 |

## Known gaps (not mitigated in this release)
- No session revocation list; tokens are valid until expiry.
- Rate limits are per process.
- No external penetration test; no ASVS L2 assessment by a third party.
- Docker images and CI workflow have not been executed in this environment.
- Backups/PITR are not configured or drilled.
