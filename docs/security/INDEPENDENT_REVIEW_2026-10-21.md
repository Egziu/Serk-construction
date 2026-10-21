> **Provenance.** Verbatim report written by an independent review agent that did
> not author migration 0007. It was given read-only access plus a disposable
> database. Its probe tests are preserved as
> `internal/kernel/attestation_review_test.go`. Disposition of every finding:
> `docs/security/ADVERSARIAL_RESULTS.md` §6. Raw outputs:
> `docs/security/evidence/independent-review-{before,after}.txt`.

# Independent review: approval attestation (GATEA-APPROVAL-01)

Scope: migrations 0001–0008 (focus on 0007/0008), `pkg/attest/attest.go`, `internal/store/postgres/attestrepo.go`, `internal/kernel/{kernel,period,fx,wbs,workflow}.go`, and `docs/security/APPROVAL_ATTESTATION_DESIGN.md`. Reviewed at HEAD `81ab48b`.

Database: `serk_review` on `/tmp:5433`, freshly created. Tests were run with the commands in the brief.

Regression tests: `zz_review_test.go`, in the same scratch directory as this report. Each test asserts the **secure** behaviour, so `GAP CONFIRMED` means the attack succeeded. Raw outputs are `test-output.txt` (gap tests) and `test-output-2.txt` (INSERT test and the existing provenance/attestation suites).

> **Working-tree note.** While this review ran, another process changed the tree:
> - it committed the two docs;
> - it modified `kernel.go`, `httpapi/*` and `pkg/auth/auth.go`;
> - it added `0009_session_revocation.sql`, `sessions*.go` and `session_api_test.go`.
>
> The only change to code under review is a `checkSessionTx` call at the top of `authorize()`. It does not affect any finding. My tests ran against that tree, so 0009 was applied, but **0009 was not reviewed**.
>
> I removed `zz_review_test.go` afterwards. `git status --short` now lists only that other process's files; none of the entries are mine.

---

## Q1. Are all status transitions and authority columns covered (INSERT and UPDATE without a status change)?

**What I checked**

- Every `*_attest` trigger, together with the `*_guard` / `*_transition` triggers that follow it (they fire in name order).
- The column-level UPDATE grants, read from the live catalog.

**INSERT in a non-initial status: covered.** Run as the tenant login with no attestation (`TestReview_Q1_InsertInNonInitialStatus`), every one of these was refused:

- a journal born APPROVED, or born DRAFT with `posted_by`;
- a period born CLOSED, or born OPEN with `reopened_by`;
- an FX source, FX policy or FX snapshot born APPROVED;
- a WBS version born APPROVED;
- a workflow definition born PUBLISHED.

```
covered: tenant login: journal born APPROVED: ... journals are created DRAFT without approval fields
covered: tenant login: period born CLOSED: ... fiscal periods are created OPEN
covered: tenant login: fx snapshot born APPROVED: ... fx snapshots are recorded PENDING; ...
covered: tenant login: wbs version born APPROVED: ... WBS versions are created DRAFT
covered: tenant login: workflow definition born PUBLISHED: ... workflow.define ... requires a verified approval attestation
--- PASS: TestReview_Q1_InsertInNonInitialStatus
```

**Status transitions: covered.** Every guard-legal transition maps to an attest branch, and the existing suites pass: `TestApprovalProvenance_*` and `TestAttestation_*` all PASS in `test-output-2.txt`.

Two branches enforce no attestation, by design:

- `workflow_instances` → REJECTED / EXPIRED / COMPLETED. These are derived from attested decisions, or from deadlines enforced by the guard.
- `fiscal_periods` CLOSED → LOCKED. This reuses `period.close`; see Q2.

**UPDATE of authority columns without a status change: gap.** Each `*_attest` trigger returns early when the status is unchanged (0007:244-246, 272-274, 289, 302, 352). The deeper guards freeze some of these columns but not all of them. `TestReview_Q1_AuthorityColumnsWithoutStatusChange` showed the following:

```
GAP CONFIRMED: tenant login rewrites closed_by/closed_at of a CLOSED period
closed_by now: u-someone-else
GAP CONFIRMED: closer reopens own close after closed_by was rewritten (SoD bypass)
GAP CONFIRMED: tenant login inserts a forged fiscal_period_closes record (actor u-cfo, REOPEN)
GAP CONFIRMED: tenant login rewrites approved_by/approved_at of an APPROVED WBS version
wbs approved_by now: u-forged-checker
GAP CONFIRMED: tenant login writes posted_by/posted_at on an APPROVED journal (no status change)
--- FAIL: TestReview_Q1_AuthorityColumnsWithoutStatusChange
```

How each column is protected after its row leaves the initial state:

| Column(s) | Protection |
|---|---|
| `journals.approved_by` / `approved_at` | Frozen by `journals_guard` once not DRAFT. |
| `journals.posted_by` / `posted_at` | Frozen once POSTED; writable while APPROVED. Low impact, because posting overwrites them. |
| `fx_sources` / `fx_policies.approved_*` | Frozen once not PENDING. |
| `fx_snapshots` decision columns | Frozen by `fx_snapshots_guard` (0002:401-406) and `fx_snapshots_attest`. |
| `workflow_definitions.decided_*` | No UPDATE grant, and the guard refuses. |
| `workflow_instances.ended_*` | Refused by `workflow_instances_guard` (0006:480). |
| `fiscal_periods.closed_by` / `closed_at` / `reopened_by` / `reopen_reason` | **Not frozen.** |
| `wbs_versions.approved_by` / `approved_at` | **Not frozen.** |

**Conclusion: gap** (findings H1, H2, M3).

## Q2. Can one registered record count for another row, subject, actor or step in the same transaction?

**What I checked**

- `approval_in_tx` matches on (txid, tenant, action, subject_type, subject_id, actor). Evidence is never consumed.
- `ctx` is checked only for `workflow.start`, `workflow.decide` and `workflow.decide_definition`.
- `subject_hash` is compared only inside `approval_authorize`, never again when a trigger uses the evidence.
- `txid_current()` returns the top-level xid, so evidence registered in a savepoint counts for the whole transaction. A `ROLLBACK TO` removes it. I found no extra issue specific to savepoints.

**Already covered:**

- another row of the same type (the subject_id must match);
- another actor;
- another workflow step or outcome (`TestAttestation_DecisionBoundToStepAndOutcome` passes).

**Test results** (`TestReview_Q2_InTransactionBinding`):

```
GAP CONFIRMED: journal.approve evidence still valid after lines were added in the same tx
journal status APPROVED, lines 5
GAP CONFIRMED: WBS v1 SUPERSEDED while successor v2 is REJECTED (same wbs.decide evidence)
approved WBS versions for project: 0
GAP CONFIRMED: FX policy v1 RETIRED while successor v2 is REJECTED (same fx.policy.decide evidence)
approved TRANSACTION policies for entity: 0
GAP CONFIRMED: one workflow.define evidence inserts two definitions whose body does not hash to body_hash
--- FAIL: TestReview_Q2_InTransactionBinding
```

Found by code reading, not tested:

- **Close and lock carry identical claims.** `period.close` uses `ctx=""` for both close and lock (period.go:74), so evidence for a close also authorises LOCK.
- **The decision is not in the evidence.** `wbs.decide` and `fx.policy.decide` sign identical claims for approve and reject (wbs.go:56, fx.go:111). The evidence row therefore cannot show which decision was made.
- **Actor-less checks.** `journal.cancel`, `fx.source.retire` and `fx.snapshot.withdraw` use `p_actor = NULL`.

These issues need statements running inside a transaction that holds genuine evidence. The threat model in design §3 includes "SQL injection in a tenant session", which an injection into an API transaction would match. **Conclusion: gap** (M1, M2, M4).

## Q3. Is the canonical message unambiguous?

**What I checked**

- `Claims.Canonical()` in Go against `approval_canonical()` in SQL.
- **Field order:** identical.
- **Perms ordering:** Go `sort.Strings` and SQL `COLLATE "C"` both sort bytewise on UTF-8, so they agree.
- **Go side:** `Sign` refuses U+001F in actor, action, subject_id, subject_hash, ctx and perms. It does not check tenant, kid or subject_type (server-controlled), and it does not refuse `,` inside a perm.
- **SQL side, three problems:**
  1. It accepts U+001F inside any field.
  2. `concat_ws` **drops NULL fields**. A missing `ctx` or `auth_time` removes a separator, so a missing field differs from an empty one.
  3. Perms are joined with `,`, so `["a,b"]` and `["a","b"]` produce the same string.

  JSON types are not enforced: `v` may be `1` or `"1"`, `mfa` may be `"t"`, and `perms` elements may be numbers.

**Test** (`TestReview_Q3_CanonicalAmbiguity`). I took a genuinely signed `journal.approve` attestation with `ctx=""`, `perms=["journal.approve"]` and `auth_time=0`, then re-encoded it as `ctx="\x1fjournal.approve"`, `perms=["0"]` with `auth_time` omitted. Both encodings produce the same canonical string, and the original signature was accepted:

```
GAP CONFIRMED: re-parsed attestation accepted with the original signature; evidence row: "ctx='\x1fjournal.approve' perms={0} auth_time=NULL"
```

I found no re-parse that gains authority. The characters are fixed, `subject_hash` must match the live subject, `iat`, `exp` and `auth_time` must parse as bigint, and the nonce must match the regex. Even so, the meaning of a signed message can be changed. **Conclusion: gap, no exploit found** (L1).

## Q4. Does `approval_subject_hash` cover every field that changes business meaning?

**What I checked:** each branch at 0007:83-133, compared against the table columns and the UPDATE grants.

| Subject | Business fields omitted | Can they change after signing? |
|---|---|---|
| journal | `applied_rate`, `fx_policy_id` / `_version`, `fx_selected_at`; `status` | No. Lines are insert-only (no DELETE, memo UPDATE revoked), so any change adds text. |
| fx_snapshot | `published_at_utc` (knowledge cutoff), `created_by`, `algorithm_version`, `business_event_at_utc` | No. Frozen by the guard. |
| fx_source | `description` | No. Frozen. |
| fiscal_period | `name`, **`reopen_reason`** (the reopen justification) | Yes. `reopen_reason` is set in the same UPDATE and is not bound. |
| wbs_version | node `parent_id`; cost code `name`, `valid_from`, **`valid_to`**, **`status`**; the code-to-node mapping; `description` | Yes. `cost_codes.status` and `valid_to` are UPDATE-granted and change freely, both in DRAFT and after approval. |
| workflow_instance | `route`, facts other than the fingerprint | No. Immutable by guard. |
| workflow_definition_body | Returns `p_id` itself, so the hash check is vacuous. `body` is never hashed in SQL. | Yes. See Q2 and M2. |

The serialisation uses `|`, `,`, `;` and `=` without escaping (memo, description and names are free text), and `concat_ws` drops NULLs.

`authorize()` computes the hash in the same transaction immediately before signing (kernel.go:56). The hash therefore binds "content at signing time", not "content the human reviewed". For journals the command-hash check makes up for this; for WBS, FX and periods nothing does.

**Conclusion: partial.** No hash collision is exploitable today, because the tables are append-only and the omitted columns are immutable. That safety depends on those constraints rather than on the hash. A test was not needed beyond Q2. (L2, I1)

## Q5. Time checks, nonce scope, tenant scoping in the SECURITY DEFINER function

- **Time.** `now_s := extract(epoch FROM now())` is the transaction start (0007:155). Expiry, `iat` skew and MFA freshness are all measured against it. Evidence carries no expiry when it is later used. `TestReview_Q5_ExpiryUsesTransactionStart`: the attestation had `exp = now+3s`; the transaction ran `pg_sleep(5)`, then authorised and approved.

  ```
  GAP CONFIRMED: attestation accepted after its exp (wall clock) because now() is the tx start
  ```

  This is the documented R-CLOCK risk, now confirmed. The same rule has a functional side effect: a transaction that waits on locks for more than 60 s rejects fresh attestations with "not yet valid".
- **Nonce.** It is a global primary key, so it is unique across tenants. It is enforced at registration, not at use; see Q2. A rollback frees the nonce, which design §5 documents. The regex permits non-canonical UUID hyphenation, but the nonce string is inside the signature, so this has no effect.
- **Tenant scoping.** Covered.
  - `t := current_tenant()` derives from `session_user`.
  - The key lookup, the hash function and the evidence row are all scoped to `t`.
  - Tables use FORCE RLS.
  - `search_path` is pinned to `pg_catalog, public`.
  - `serk_app` has no CREATE on `public` and no TEMP (catalog query, plus the passing test `TestAttestation_TenantLoginCannotReachKeysOrEscalate`).
- **Minor.**
  - The HMAC is compared with text `<>`, which is not constant-time. This is impractical to exploit.
  - Malformed numeric fields raise 22P02/22003 instead of 42501.

**Conclusion: tenant scoping covered; time gap (L3).**

## Q6. Are any grants broader than needed?

**What I checked:** the live catalog for `serk_app` (column UPDATE grants, table grants, EXECUTE).

| Grant | Problem |
|---|---|
| `INSERT ON fiscal_period_closes` (0002:283) | The trigger runs as invoker, so this grant lets the tenant forge close, lock and reopen records (confirmed in Q1). Same pattern: `INSERT ON workflow_history` (0006:607) allows forged `DECIDED` entries; `audit_log` INSERT is by design. |
| `UPDATE(closed_by, closed_at, reopen_reason, reopened_by) ON fiscal_periods` | Not frozen; see H1. `closed_at` is set by the trigger, so its grant is unnecessary. |
| `UPDATE(approved_by, approved_at) ON wbs_versions` | Not frozen after approval; see H2. |
| `UPDATE(approver_mfa) ON fx_snapshots` | Always overwritten from the evidence by the trigger, so it is unnecessary. |
| `approved_at` / `posted_at` (journals), `decided_at` (fx_snapshots) | Approval timestamps are supplied by the caller, not set by the database. |
| `INSERT ON workflow_effects` | Effects need no attestation. They do need a quorum of attested decisions and must be executed by an approver. By reading only: after quorum, the tenant login could record an effect in its own transaction and advance the step without the subject transition, which wastes the step. Not tested. |
| pgcrypto / btree_gist functions | 224 extension functions remain EXECUTE-able (0008 excludes extension members). They are harmless but broader than needed. |

`approval_require`, `approval_in_tx`, `approval_canonical` and `approval_subject_hash` are EXECUTE-granted. These are invoker functions that the triggers need, so the grant is acceptable.

**Conclusion: gap** (H1, H2, M3, L4).

---

## Findings (ranked)

### High

**H1. Fiscal-period authority columns can be rewritten after close, which defeats the close/reopen segregation of duties.**

- Location: 0007:272-274 (early return), 0002:280 (grant), 0002:174-218 (`fiscal_periods_transition` does not freeze), 0002:203 (SoD check reads `OLD.closed_by`), period.go:113 (the API's SoD check reads the same column).
- Confirmed by test: the closer reopened their own close.
- Fix:
  - When `NEW.status = OLD.status`, refuse any change to `closed_by`, `closed_at`, `reopened_by` and `reopen_reason`. Do this in `fiscal_periods_attest` or the guard.
  - Revoke `UPDATE(closed_at)`.
  - Better still, base SoD on the immutable close record, written by a definer function (see M3).

**H2. `wbs_versions.approved_by` / `approved_at` can be rewritten after approval.**

- Location: 0005:90-110 (no freeze), 0005:163 (grant), 0007:352.
- Confirmed by test.
- Fix: in `wbs_versions_guard`, add `IF OLD.status <> 'DRAFT' AND row(NEW.approved_by, NEW.approved_at) IS DISTINCT FROM row(OLD.approved_by, OLD.approved_at) THEN RAISE`. Also make every `*_attest` trigger refuse changes to authority columns when the status is unchanged; that is a general rule, not a per-table patch.

### Medium

**M1. Evidence is not bound to the decision, and supersede/retire accept any sibling decision.**

- Location: 0007:302-314 and 352-362 (and `ctx` is unused there), 0007:275-276 (close and lock share one action); Go call sites wbs.go:56, fx.go:111, period.go:74 all pass `ctx=""`.
- Confirmed by test: rejecting the successor retired or superseded the current version, leaving 0 approved versions.
- Fix:
  - Sign `ctx = target status` (APPROVED/REJECTED, CLOSED/LOCKED) and check `r.ctx = NEW.status`.
  - For RETIRED and SUPERSEDED, require evidence with `ctx='APPROVED'`, plus a deferred constraint trigger that verifies at commit that the successor is APPROVED.

**M2. `workflow.define` evidence binds a caller-supplied `body_hash`, not the body.**

- Location: 0007:121-122, 372-378; 0006:30.
- Confirmed by test: one piece of evidence inserted two rows with bodies that do not match the hash.
- Fix:
  - Compute the hash in SQL from the stored body, e.g. `'sha256:' || encode(sha256(convert_to(NEW.body::text,'UTF8')),'hex')`, and have Go hash the same canonical text.
  - Make the evidence single-use.

**M3. Tenant-forgeable evidence tables.**

- Location: 0002:283 (`fiscal_period_closes`), 0006:607 (`workflow_history`).
- Confirmed by test for `fiscal_period_closes`.
- Fix: write `fiscal_period_closes` from a SECURITY DEFINER helper called by the transition trigger, revoke INSERT, and treat `workflow_history` as non-authoritative (or the same approach).

**M4. Subject content is checked only when evidence is registered (TOCTOU within the transaction), and evidence is reusable within the transaction.**

- Location: 0007:204-230.
- Confirmed by test: lines were added after `authorize`, and the journal was still approved.
- Fix:
  - In `approval_require`, recompute `approval_subject_hash` over the pre-transition content (excluding `status`) and compare it with `r.subject_hash`.
  - Mark evidence consumed: add a `used_at` / `used_for` column set by the definer, or a tx-local consumed set. Then one record authorises exactly one transition.

### Low

**L1. The SQL canonical form can be re-parsed.**

- Location: 0007:138-145, 164-170.
- Confirmed by test: an alternative parse was accepted; no escalation found.
- Fix:
  - Require exactly the expected keys with the right JSON types (all present, perms as an array of strings).
  - Reject U+001F and `,` in every field in SQL, and reject `,` in perms in Go.
  - Replace `concat_ws` with an explicit, NULL-intolerant `||` join, or use a length-prefixed encoding.

**L2. Fragile subject-hash serialisation.**

- Location: 0007:83-133.
- Problems: unescaped separators, dropped NULLs, missing columns (`reopen_reason`; WBS `valid_to`, `status`, `name`, `valid_from`, `parent`; FX `published_at_utc`).
- Safe today only because the tables are immutable or append-only.
- Fix: hash a canonical `jsonb` built with `jsonb_build_object` and ordered `jsonb_agg`, including every business column.

**L3. Expiry and MFA freshness use the transaction start (R-CLOCK), and evidence never expires during the transaction.**

- Location: 0007:155, 179, 186.
- Confirmed by test.
- Fix: use `clock_timestamp()` in `approval_authorize`, and check `r.expires_at > clock_timestamp()` in `approval_require`.

**L4. Approval timestamps are supplied by the caller, and some UPDATE grants are unnecessary.**

- Location: 0002:280-281, 706; the related grants are `approver_mfa` and `closed_at`.
- Fix: set `approved_at`, `posted_at`, `decided_at` and `closed_at` in triggers, and revoke the unneeded column grants.

**L5. `workflow_effects` needs no attestation** (analysis only, not tested). It could let the tenant waste a step after quorum. Fix: require the evidence of the subject transition in the same transaction, or insert effects only from a definer function.

### Info

**I1. The hash binds content at signing time, not at review time.** `authorize()` reads the hash in the same transaction just before signing, so it does not prove what the approver saw. Consider letting clients pass the expected version or hash, which the API checks.

**I2. Actor-less evidence.**
- `journal.cancel`, `fx.source.retire` and `fx.snapshot.withdraw` use `p_actor NULL`.
- There is no `cancelled_by` or `rejected_by` column for journals or FX policies.
- The evidence row is the only record of who acted.

**I3. Smaller items.**
- The HMAC comparison is not constant-time.
- `Sign` does not check tenant, kid or subject_type for U+001F.
- The 60 s `iat` skew rule can refuse attestations in long-waiting transactions.

## Not checked

- 0009 and the other files that changed during the review.
- The HTTP layer, and where the Go principal's MFA and auth_time come from (R-MFA-SOURCE).
- Concurrency: two transactions racing on one nonce, and lock ordering.
- `workflow_effects` misuse (analysis only).
- Every path in `workflow.go` beyond the `authorize` call sites, decide/execute and reject.
- DEDICATED_DB mode.
- Grants of the relay, timer and health roles beyond what is described above.
- The pgcrypto `search_path` hijack, beyond the existing test that CREATE on `public` is denied.
