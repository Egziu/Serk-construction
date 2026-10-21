> **Provenance.** Verbatim report of the second independent review agent (re-verification of migration 0010). Probes preserved as `internal/kernel/attestation_reverify_test.go` (one query adjusted to tolerate zero rows when the attack is refused). Disposition: `docs/security/ADVERSARIAL_RESULTS.md` §7.

# Re-verification of migration 0010 (attestation hardening), 2026-10-21

Reviewer: second independent re-verifier. I did not write 0007 or 0010.
Code under review: commit 32a220e, copied to `review2/repo`. The working tree also contained an untracked `0011_ops_metrics.sql` from concurrent work, so it was migrated too. It touches no attestation objects.
Database: `serk_review2` on the local throwaway cluster (port 5433).
Probes: `review2/zz_reverify_test.go`, which is also at `repo/internal/kernel/zz_reverify_test.go` in the copy. Each probe asserts the secure behaviour. `OPEN:` means a gap; `held:` means the control resisted.
Raw outputs: `full_suite.txt`, `all_packages.txt`, `probes_run1.txt`, `probes_run2.txt`, `probes_q6.txt`, `probes_q3b.txt`, `probes_final.txt`.
Nothing was written to /home/claude/serk-construction.

## Q1: authority_frozen coverage

Checked: every `*_attest` trigger in 0010, together with the 0001/0002/0005/0006 guards and the column grants. Trigger order is alphabetical, so attest runs before guard and before transition.

- **journals**: same-status, DRAFT->APPROVED, APPROVED->POSTED, ->CANCELLED, POSTED->REVERSED and the fallback all freeze the columns not set by the transition. Timestamps are DB time. Covered.
- **fiscal_periods**: same-status is frozen. CLOSE/LOCK allows only `closed_by`. REOPEN allows only `reopened_by`/`reopen_reason`. LOCKED is terminal (guard). Covered. One by-design exception: on CLOSED->LOCKED, `closed_by` is replaced by the locker. Probe `TestReverify_Q1_LockRewritesClosedBy`: `period: LOCKED closed_by=u-controller-2; records: CLOSE/u-poster, LOCK/u-controller-2`. It is attested and the close record keeps the original closer, so this is Info.
- **wbs_versions, fx_sources, fx_policies**: every branch freezes. Covered.
- **workflow_instances**: not touched by 0010. The 0006 guard and the 0007 attest still hold. Actual output:
  `held: tenant login sets ended_by on an ACTIVE instance without ending it: ... end details are recorded only when the instance ends`
  `held: tenant login cancels with an invented ended_by: ... workflow.cancel ... requires a verified approval attestation for u-wf-admin`
- **fx_snapshots: NOT covered.** `fx_snapshots_attest` (0010:397-420) freezes only `approver_mfa`/`variance_exception`, and only when the status is unchanged. The APPROVED->DISPUTED guard (0002) checks only `decision_reason`. Probe `TestReverify_Q1_FXSnapshotAuthorityOnTransition`, actual output:
  ```
  before: approved_by=u-approver rejected_by=NULL decided_at=2026-10-21 23:53:11.39853+03 mfa=f exc=f
  OPEN: withdraw (genuine fx.snapshot.withdraw attestation) rewrites approved_by/rejected_by/decided_at/approver_mfa/variance_exception
  after: status=DISPUTED approved_by=u-forged-approver rejected_by=u-forged-rejecter decided_at=2001-01-01 00:00:00+03 mfa=t exc=t
  OPEN: reject (genuine attestation) also sets approver_mfa=true/variance_exception=true on a REJECTED snapshot
  after reject: status=REJECTED mfa=t exc=t
  ```
  **Conclusion: still open for fx_snapshots (finding M-1).** All other tables: closed.

## Q2: approval_use()

- **Single use.** Consumption has a primary key on the nonce, and `approval_in_tx` filters out consumed rows. Actual output:
  `held: evidence consumed inside a released savepoint is reused: ... requires a verified approval attestation for u-approver`.
  With ROLLBACK TO SAVEPOINT, the consumption rolls back together with the transition, so the evidence can be used once more. Only one transition survives: `rollback-to-savepoint then reuse: err=<nil> consumptions=1 status=APPROVED`. That is acceptable.
- **Live hash re-check.** Actual output:
  `held: wbs.decide APPROVED evidence still valid after a node was added in the same tx: ... wbs_version ... changed after the approval was attested`.
  The journal case is covered by the existing Q2 test. The `workflow_definition_body` skip is sound: its subject id is the SQL digest, which the trigger recomputes from `NEW.body`.
- **Direct calls by the tenant login (new issue).** `approval_use` is granted to `serk_app` and takes a caller-chosen `p_used_for`. Any evidence the tenant holds in the transaction can therefore be consumed under any label. Two checks trust that label: `fiscal_period_close_record` (0010:282-283) and the REVERSED check (0010:229-230). Actual output:
  ```
  close record: close actor=u-poster linked attestation: action=journal.approve actor=u-approver subject=journal:14b14820-...
  OPEN: close record linked to unrelated evidence via a forged consumption marker
  after tx1: J=POSTED R=POSTED
  OPEN: J marked REVERSED in a later tx with a forged consumption marker (unrelated evidence)
  final: J=REVERSED
  ```
  Finding L-1.
- **Cross-tenant.** The tenant cannot INSERT into `approval_consumptions` (`permission denied for table approval_consumptions`). Tenant 2 sees 0 rows. Evidence lookup is scoped by txid and current_tenant. Nonces come only from signed attestations, so another tenant cannot pre-claim them. I found no way to deny service to another tenant.

## Q3: fiscal_period_close_record

- Direct call: `held: ... period close records are written only by the period transition`.
- The tenant cannot create code that would run at trigger depth 1 or more. Actual output: `permission denied for schema public`, `permission denied to create temporary tables`, `must be owner of table wbs_versions` (DISABLE TRIGGER).
- The only caller is `fiscal_periods_transition`, with `(OLD.id, NEW.status)`. `fiscal_periods_attest` always runs first and requires real `period.close`/`period.reopen` evidence with ctx = target.
- **No forged close record was possible.** The attestation link in the record can be redirected (L-1).
- **Side effect:** close, reopen and close again in one transaction fails. Actual output: `err=store: database invariant violated: fiscal_period_closes_attestation_key`. This fails safe and is not a kernel flow (L-2).

## Q4: Deferred successor checks

Actual output:
```
held: supersede v1, approve v2 inside a savepoint, roll the savepoint back, commit: ... superseding a WBS version requires an approved successor at commit
held: SET CONSTRAINTS ALL IMMEDIATE then supersede without approved successor: ... requires an approved successor at commit
held: retire p1 + approve p2 + REJECT p2 in the same tx: ... illegal fx policy transition APPROVED -> REJECTED
```
`SET CONSTRAINTS ... DEFERRED` is a no-op and DISABLE TRIGGER is refused. The one-approved partial unique indexes mean the approved row at commit must be the attested successor.

**Conclusion: closed.**

## Q5: workflow_history_attest and workflow_effects_attest

- **Effects: bound adequately.** The check covers instance, actor, `step:APPROVE`, and the guard's quorum/approver check. Existing HardeningControls probes pass.
- **History: not bound.** Actual output:
  ```
  OPEN: COMPLETED history entry by an invented 'system:' actor, no evidence
  OPEN: DECIDED history entry for u-cfo with no evidence, actor spelled 'system:u-cfo'
  OPEN: DECIDED history entry for u-approver on instance W using u-approver's evidence for an unrelated journal
  history of W: STARTED/u-preparer, COMPLETED/system:kernel, DECIDED/system:u-cfo, DECIDED/u-approver
  ```
  **Conclusion: M3 is still open for history (finding M-2).**

## Q6: Canonical message, Go vs SQL

Go `Canonical` and SQL `approval_canonical` match field for field. Both sort with byte order (`sort.Strings` and `COLLATE "C"`). Strict shape removes separator, dropped-field and type confusion. Actual output, with a fresh attestation each time:
```
v as 1.0: err=... malformed field v
v as 1e0: err=<nil>
auth_time as -0: err=<nil>
duplicate ctx key with a different first value: err=<nil> stored=ctx=''
perms duplicated element: err=... bad signature
unicode escape in actor: err=<nil>
```
Every accepted variant decodes to exactly the signed values, so the meaning cannot change. The JSON transport is malleable (Info) but not ambiguous.

**Conclusion: closed.**

## Q7: Legitimate flows

- Full kernel suite: `ok .../internal/kernel 15.431s`, 88 PASS, 0 FAIL, exit 0 (`full_suite.txt`).
- `go test ./... -skip TestReverify_Q`: all packages `ok` (`all_packages.txt`).
- `go vet ./internal/kernel`: clean.
- The only breakage found is L-2.

## Findings

| # | Sev | Where | Finding | Fix |
|---|---|---|---|---|
| M-1 | Medium | 0010:397-420 (`fx_snapshots_attest`); 0002 `fx_snapshots_guard` DISPUTED and REJECTED branches | The fx_snapshots authority columns are not frozen across transitions. Any genuine withdraw lets the tenant login rewrite `approved_by`, `rejected_by`, `decided_at`, `approver_mfa` and `variance_exception`. A reject lets it set `approver_mfa`/`variance_exception` to true. No ledger effect (DISPUTED rates have no lines), but the approval record is falsified. This is the same class as H1/H2. | Use `authority_frozen` with cols `[approved_by, rejected_by, decided_at, approver_mfa, variance_exception]`. Allowed sets: APPROVED = `{approved_by, decided_at, approver_mfa, variance_exception}`; REJECTED = `{rejected_by, decided_at}`, and force mfa/exception to false; DISPUTED = `{}` (`decision_reason` only). |
| M-2 | Medium | 0010:481-484 (`workflow_history_attest`) | The `actor NOT LIKE 'system:%'` exemption lets the tenant write any authority-kind entry without evidence. Non-system entries accept any evidence of that actor in the transaction (any action, any subject, consumed or not). A history row can name a person or decision that never happened. | Exempt only the exact `system:workflow-timer` actor and only the kinds EXPIRED/ESCALATED. Bind each kind to its evidence for this instance (DECIDED: a `workflow_decisions` row or `workflow.decide` evidence for `instance_id` with ctx `step:decision`; STARTED: `workflow.start`; CANCELLED: `workflow.cancel`). Better still, emit history only from definer triggers and revoke INSERT. |
| L-1 | Low | 0010:139-172 (caller-supplied `p_used_for`, EXECUTE granted to `serk_app`); consumers at 0010:229-230 and 0010:282-283 | The tenant can forge consumption markers with any evidence it holds in the transaction. Effects: (a) the `fiscal_period_closes.attestation` link points to unrelated evidence; (b) a POSTED journal can be marked REVERSED in a later transaction without the reversal's posting attestation (the reversal itself was genuinely posted). | Do not trust `used_for` labels. Look up the consumed evidence by content: `action='period.close'`/`'period.reopen'`, `subject_id=period`, `ctx=target`, actor = closer/reopener; `action='journal.post'`, `subject_id=reversed_by`. Alternatively, derive `used_for` inside `approval_use` and drop the parameter. Use `ORDER BY used_at DESC` with STRICT semantics. |
| L-2 | Low | 0010:282-290 | A second close in one transaction (close, reopen, close) picks the already-linked consumption and fails on `fiscal_period_closes_attestation_key`. Fails safe, not a kernel flow. | Same lookup fix as L-1, excluding nonces already referenced by `fiscal_period_closes`. |
| L-3 | Low | 0010:467-474 (`workflow_definitions_attest`); 0006 `workflow_definitions_guard` | The `body_hash` column is still caller-supplied and unchecked. Actual: `stored: v7 body_hash=sha256:00000000 digest=sha256:bbb776fc`. Go `parseStored` rejects the mismatch at publish (fails closed), but the stored and audited hash can be false. The tenant also picks `version` freely. | Have SQL compute or verify the stored hash (for example a `body_digest` column = `workflow_body_digest(body)`) and make Go compare against it. Include the version in ctx if it matters. |
| I-1 | Info | 0010:255-259 | CLOSED->LOCKED replaces `closed_by` with the locker (attested; the close record keeps the original). | Add a `locked_by` column and keep `closed_by` frozen. |
| I-2 | Info | 0010:56-124 | Non-canonical JSON (`1e0`, `-0`, duplicate keys, `\u` escapes) is accepted with the same meaning. | Optional: compare the input text with its canonical re-serialisation. |
| I-3 | Info | 0007/0010 design | Evidence registered in a rolled-back transaction or savepoint leaves no nonce row. A captured signed JSON could be replayed within its TTL (5 min or less). This predates 0010. It requires the JSON, which is not stored before commit. | Accept, or record nonces in an autonomous/committed store. |

## Disposition of 0010's claims

| Finding | Status | Notes |
|---|---|---|
| H1 | Closed | |
| H2 | Closed | For journals/WBS/fx_sources/fx_policies; not fx_snapshots (M-1) |
| M1 | Closed | |
| M2 | Closed | Single use and SQL digest; residual L-3 |
| M3 | Partly open | Close records and effects closed; history open (M-2); close-record linkage forgeable (L-1) |
| M4 | Closed | Residual L-1: labels forgeable by direct call |
| L1 | Closed | |
| L3 | Closed | |
