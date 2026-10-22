# Independent review 12: site operations and offline sync (0037)

Scope: `git diff 888e629 87ea637` (commit 87ea637, detached checkout `wt-r12`). That covers migration 0037, `internal/kernel/site.go`, `internal/httpapi/site_handlers.go`, the auth permissions and roles, the p2p registration and the console screens.
Method: I read the code adversarially and ran probes against PostgreSQL 16 in non-superuser owner mode (`serk_r12a`, owner `serk_owner_t`, advisory-lock restriction applied). Probe sources and raw outputs are in this directory. I did not rely on comments, the ADR or test names.

## Verdict

**I found no Critical or High defects.** The main invariants held under probing:
- No unattested content change.
- No edit after submission.
- No approval of your own diary.
- No escape from project scope.
- No sync from a revoked or foreign device.
- Retries are applied exactly once.
- The console inserts untrusted data only as text.

**Two Medium defects should be fixed before the gate (R12-F1, R12-F2):**
- A leaked tenant credential can forge the offline command log and permanently disable any field device.
- Any engineer can lock a project's diary days, and nobody can remove the lock.

Five Low and three Info items follow.

## Findings

| ID | Sev | Finding | Evidence | Suggested fix |
|---|---|---|---|---|
| R12-F1 | **Medium** | OPEN: a leaked tenant credential can **forge `site_sync_commands` rows and burn any device's sequence**. The guard trusts the free `actor` column; it only checks that `actor` equals the device owner. So raw SQL can insert an `APPLIED` row naming any diary of the owner, with `seq = 2^63-1`. Then `UPDATE site_devices SET last_seq = 2^63-1, last_sync_at = '2001-01-01'` passes. The guard's "moves only with a recorded command" check is satisfied by the forged row. After that the owner's device cannot sync any command, and the device list shows the fake last-sync time. This undermines the command log as evidence, and it is a targeted DoS on every field device in the tenant. | `0037:290-306` (actor taken from NEW), `0037:147-156` (`last_sync_at` unchecked; `last_seq` needs only *a* row). Probe `TestZZR12_ForgedCommandLogBurnsDevice`, `probe_kernel_run1.txt`: `ACCEPTED: forged APPLIED command (actor=owner) + last_seq=MaxInt64 + fake last_sync_at`, then `Error:sequence 1 is not after the device's last sequence 9223372036854775807`, and the list shows `last_seq=9223372036854775807 last_sync_at=2001-01-01`. | Bind log rows to evidence written in the same transaction, e.g. require `approval_consumed_in_tx` for an APPLIED row, or an attested `site.sync` marker. Derive `actor` from the session or attestation, not from the column. Cap `seq` (see F3). Set `last_sync_at := now()` in the guard rather than accepting it from the caller. |
| R12-F2 | **Medium** | OPEN: **diary-day squatting with no remedy**. The partial unique index allows one non-REJECTED diary per project and day. A DRAFT can only become SUBMITTED; only the author can revise or submit it; and an empty draft (no lines, notes under 5 characters) cannot even be submitted. So one engineer (or a stolen device) can create empty DRAFTs for every day in the 60-day window and for tomorrow, in every project in scope. Colleagues are then refused, and a project manager cannot reject a DRAFT. No API or DB path withdraws or cancels it. | `0037:81`, `0037:213-241` (no DRAFT exit except SUBMITTED), `0037:222-226`. Probe `TestZZR12_DraftSquatting`: `empty DRAFT diaries created by one engineer for consecutive days: 61`; colleague: `the project already has diary SDY-2026-000001 for 2026-10-22`; PM reject: `illegal status transition: document is DRAFT`; author submit: `a submitted diary records labour, equipment or notes`. | Add an attested DRAFT→WITHDRAWN/CANCELLED transition (by the author, or by a site.diary.approve holder in scope with a reason) and exclude it from the index. Alternatively make uniqueness bind only SUBMITTED/APPROVED, or let the PM reject a stale DRAFT. |
| R12-F3 | Low | OPEN: the **device sequence has no upper bound or step limit**. One command with `seq = 2^63-1` permanently bricks the device, even when that command is invalid, because refused commands are recorded and still advance `last_seq`. A buggy client or a thief holding the token and key can do this; recovery requires MFA re-registration. | `site.go:612` (only `seq >= 1`), `site.go:682-697`, `0037:114`. Probe `TestZZR12_HugeSeqBurnsDevice`: an invalid op at MaxInt64 is `REJECTED ... diary_date is YYYY-MM-DD`, then seq 2 gets `sequence 2 is not after the device's last sequence 9223372036854775807`. | Require `seq <= last_seq + N` (a small window, e.g. 1000) in both the kernel and the guard, and do not advance `last_seq` for commands refused before parsing. |
| R12-F4 | Low | OPEN: **transient failures permanently consume an offline command**. Any non-domain error from `applyOp` (signer outage, DB timeout or reset, context cancel) is recorded as `REJECTED "refused"`, so a retry of the same op replays the refusal. A failure at commit (e.g. a deferred attestation that expired while waiting on a lock) returns "retry" without recording, but the batch keeps going. Later ops then advance `seq` past the failed one, which can never be applied: out-of-order application, contrary to "applies in order". | `site.go:665-669, 676-697, 554-556, 703-719`. Probe `TestZZR12_TransientFailureConsumesCommand` with a signer returning `connection reset by peer`: the first try gives `REJECTED ... Error:refused`; after recovery the retry gives `REJECTED Replayed:true Error:refused`, and the next op in the batch is `APPLIED`. | Record only deterministic domain refusals (ErrInvalidInput, ErrForbidden, ErrNotFound, check_violation). Return "retry" for everything else and **stop the batch** at the first not-processed op. |
| R12-F5 | Low | OPEN: **the creation and revision attestations can be decoupled from the committed content.** The attestation triggers are only `DEFERRABLE INITIALLY DEFERRED`. Inside the attested transaction, `SET CONSTRAINTS site_diary_attested IMMEDIATE` consumes the attestation early. Lines inserted afterwards still pass the xmin "written in this tx" check, so the committed version differs from the attested hash. This breaks the ADR claim that "every content change is covered by the header's attestation". It needs an attestation-holding code path, such as a compromised API; the later approval still hashes the real content. | `0037:263-264`, `0037:181-185, 275-286`. Probe `TestZZR12_SetConstraintsImmediate`: `ACCEPTED: revision attested, constraint fired IMMEDIATE, then an extra line`; `attested hash=45aa87… committed hash=b75219… lines(v2)=2`. | Make the attestation triggers `NOT DEFERRABLE`, or have the lines guard refuse once the revision's attestation is consumed in this tx (`approval_consumed_in_tx(...)` IS NOT NULL ⇒ refuse). Alternatively re-verify at commit that the consumed attestation's `subject_hash` equals the final `approval_subject_hash`. |
| R12-F6 | Low | OPEN: **maker-checker on rejection is enforced only in Go.** The reject branch calls `approval_use(..., NULL actor, ...)`, the `site_diary_maker_checker` CHECK covers only `approved_by`, and no `rejected_by` column exists. An author holding both roles, with an attestation in the transaction, can reject their own diary at DB level. The row also does not say who rejected it. | `0037:233-238, 79`. Probe `TestZZR12_DBRejectOwnDiary`: the kernel refuses (`segregation of duties violation`), but `ACCEPTED: DB: author-attested REJECT of own diary` gives `status=REJECTED reason="self-rejected"`. | Add a `rejected_by` column, pass it as the attestation actor, and extend the CHECK to `COALESCE(approved_by, rejected_by) <> created_by`. |
| R12-F7 | Low | OPEN: **device registration is uncapped, and listing is capped at 500 without paging.** One person registered 50 devices in 212 ms. `ListDevices` returns the newest 500 only, and the console offers Revoke only from that list. A user can therefore push older (e.g. stolen) devices out of the security administrator's console view. | `site.go:382-414` (no count or rate), `site.go:475-476` (`LIMIT 500`), `app.js` `renderDevices`. Probe `TestZZR12_RegisterManyDevices`: `devices registered by one person in 212ms: 50 (listed ACTIVE: 50)`. | Cap ACTIVE devices per person (e.g. 5) in the guard; page or filter the list (by user, ACTIVE first). |
| R12-F8 | Info | Payload digest is not canonical. Whitespace is normalised, but key order and escape spelling are not, so a client that re-serialises a queued command gets "already used with a different command". This is fail-safe: I found no case where two different commands collide. Duplicate and case-variant keys are accepted (Go takes the last, case-insensitively), which differs from JSON.parse. The digest also excludes `seq` and `client_time`, so a replay with a different seq is answered from the log. | `site.go:597-607, 723-724`. Probes: the key-reordered and `O`-escaped variants of the same command are `REJECTED ... different command`; whitespace gives `Replayed:true`; `"notes":"FIRST VALUE","Notes":…` stored the last value; seq 999 and client_time −80d gives `Replayed:true`, `last_seq` 1 (`probe_kernel_digest_run2.txt`, `compact_probe_output.txt`). | Document that clients must resend the stored bytes, or hash a canonical re-encoding of the decoded struct. Reject duplicate and case-variant keys. |
| R12-F9 | Info | The xmin check is fragile. A legitimate header revision written inside a subtransaction (pgx nested tx or savepoint) makes the line insert fail, because xmin is the sub-XID. The comparison of 32-bit xmin with `txid_current() % 2^32` could in theory match a frozen row exactly 2^32 XIDs later. | `0037:181-185`. Probe `TestZZR12_XminCorners`: `REFUSED: legit revision written inside a subtransaction`. | Mark "header written in this tx" explicitly instead, e.g. a tx-local table or a `pg_current_xact_id()`-stamped column set by the header trigger. |
| R12-F10 | Info | The generic `/v1/p2p/site_diary/{id}` detail exposes `client_ref`, `origin_device_id` and `client_created_at` to every project reader. I found no exploit: revise and submit require the author (probe: peer gets `not permitted`). Wrong device keys get 403 with no lockout (40 tries, then success); the key is 256-bit, so this is negligible. | `0037:396-400` via `p2prepo.go:108`. Probes `TestZZR12_SyncCrossUserAndScope`, `TestZZR12_WrongDeviceKeyNoLockout` (`probe_http_run1.txt`). | Optionally project out device fields and count device-key failures in `authFailure`. |

## Held controls (probed)

- held: lines without an attested header write are refused after `SELECT … FOR NO KEY UPDATE`, after `INSERT … ON CONFLICT DO UPDATE … WHERE false`, and after a refused header update rolled back to a savepoint (`TestZZR12_XminCorners`).
- held: from the baseline `TestOffline_DatabaseRules` (raw tenant SQL), the following are all refused:
  - unattested revision, creation and submit;
  - content change without a version step;
  - future date;
  - foreign-device origin;
  - key replacement;
  - sequence move without a command;
  - unattested revoke;
  - DELETE on the command log;
  - commands for a foreign or revoked device;
  - reactivating a revoked device;
  - editing an approved diary.
- held: exactly-once under 8 concurrent identical retries. Two different commands with the same seq: one wins. Revocation racing a sync: nothing is recorded after it (`TestSync_ConcurrentRetriesApplyOnce`).
- held: a peer cannot revise or submit another author's diary via sync (`not permitted`); a diary for an out-of-scope project is refused (`not permitted`).
- held: self-approval and self-rejection are refused in the kernel; the approved_by maker-checker CHECK holds; an AI principal is refused; an approver outside the project gets not-found (baseline lifecycle test).
- held: a revoked device and a revoked session cannot sync; device registration requires fresh MFA; only the SHA-256 of the key is stored; the register response is `no-store` (baseline HTTP test).
- held: in the console, `h()` builds every node with `createTextNode` or `setAttribute`. There is no innerHTML, outerHTML, insertAdjacentHTML or document.write in `app.js`. Device labels, user ids and the secret render as text.
- held: device credentials travel in headers and are not logged by the server middleware (`server.go:225-300`). The audit payload holds only the id and label.

## Not tested

- XID wraparound (theoretical, F9). Superuser-mode DB run (only owner mode was used).
- The remote signer (R-SIGNER) process itself; F4 was simulated with a failing `attest.Issuer`.
- Per-principal request budget versus the amplification of 100 ops × 400 lines × signer calls per request.
- Browser and e2e runs of the console screens (`e2e/console_site.mjs`); the review was static plus `h()` analysis.
- Time-zone edge cases of `current_date` versus device and server dates.

## Files

- `zz_review12_site_test.go`: kernel probes, `TestZZR12_*`; removed from the checkout.
- `zz_review12_site_api_test.go`: HTTP probe; removed from the checkout.
- `compactprobe/`: `json.Compact` behaviour.
- `probe_kernel_run1.txt`, `probe_kernel_digest_run2.txt`, `probe_http_run1.txt`, `compact_probe_output.txt`, `baseline_site_tests.txt`: raw outputs.

---

## Resolution (delivering team, 2026-10-23): applied to migration 0037 before the module was merged

The module was reviewed on a working branch (commit 87ea637), and the fixes went into **0037 itself before it entered the main line**. 0037 had never been part of a committed release, so no migration in the main line was edited. The reviewer's probes are preserved under `docs/security/evidence/independent-review-12-*`. The regression tests in `internal/kernel/review12_regression_test.go` assert the fixed behaviour. These fixes are **AI-verified only and have not been re-reviewed**.

| ID | Resolution | Proof after the fix |
|---|---|---|
| R12-F1 | Every command-log row is attested by the device owner for that device and op id (`site.sync.create`, checked by the insert guard through `approval_use`). The actor column alone proves nothing. The last-sync time is set by the server only when the sequence moves. | `TestR12_CommandLogForgeryAndSequenceBound`: a forged row naming the owner is refused (`requires a verified approval attestation`), so is a forged row with seq 2^63−1, and so is a fake last-sync time. |
| R12-F2 | The author can withdraw a DRAFT (CANCELLED, reason required, attested). A project manager can reject a DRAFT that holds a project day (reason required). Both free the day. Console actions: Cancel (author) and Reject (approver). | `TestR12_DraftDayRelease`: an empty DRAFT is rejected by the PM, after which a colleague records the day; a peer's cancellation is refused; the author's cancellation frees the day again. |
| R12-F3 | The sequence may advance by at most 1000 per command, checked in the kernel and the guard. A refused jump is not recorded. | `TestR12_CommandLogForgeryAndSequenceBound`: seq 2^63−1 refused (`jumps more than 1000`); the device continues at sequence 1. |
| R12-F4 | Only refusals on the merits are recorded: validation, scope or permission, a database rule or a version conflict. Temporary failures (signer, database, timeout, revoked session) record nothing and return `retry: true`, and **the rest of the batch waits**. | `TestR12_TransientFailureIsRetried`: during a signer outage both commands return retry and 0 rows are logged; after recovery the same batch applies both, in order. |
| R12-F5 | The lines guard refuses lines once the creation or revision attestation has been consumed in the transaction, so `SET CONSTRAINTS … IMMEDIATE` cannot attest first and add lines afterwards. | `TestR12_SetConstraintsImmediate`: refused (`diary lines are written before the revision is attested`). |
| R12-F6 | New `rejected_by` column, carried as the attestation actor, with CHECK `rejected_by <> created_by`. A rejection must name its person. | `TestR12_DraftDayRelease`: a self-rejection with a valid attestation is refused by the CHECK, and so is a rejection that names nobody. |
| R12-F7 | At most 5 active devices per person; revoke one to add another. Two registrations racing each other can overshoot by one, because advisory locks are closed to tenant logins and this is a flood limit, not a security boundary. The device list shows ACTIVE devices first. | `TestR12_DeviceCap`: the sixth active device is refused; after a revocation, registration succeeds. |
| R12-F8 | The digest is computed over a canonical re-encoding: decoded with numbers kept exact, then re-marshalled with sorted keys and standard escaping. Payloads that repeat a key, including case-insensitively, are refused, so two readings can never share a digest. | `TestR12_DigestCanonicalAndDuplicateKeys`: a reordered, re-spaced, re-escaped copy is recognised as the same command; exact and case-variant duplicate keys are refused. |
| R12-F9 | **Accepted, documented.** The kernel never writes a revision inside a savepoint, so the savepoint case refuses (fails closed). The 32-bit xmin comparison could only match a frozen row 2^32 transactions later. Even then the row must be a DRAFT of the right version, and the unattested change would be covered by the submission and approval hashes. Registered as Info. | — |
| R12-F10 | **Accepted, documented.** `client_ref` and `origin_device_id` are not secrets. Every device action also needs the 256-bit key and the owner's token. | — |

**Full suites with the fixes** (fresh databases, Go 1.26.10 `-race`, PostgreSQL 16): non-superuser owner **357 PASS, 0 FAIL, 0 SKIP** (`docs/testing/evidence/full-suite-site-operations-nonsuperuser-fresh-db.txt`); superuser owner, shuffled, **357 PASS, 0 FAIL, 0 SKIP** (`docs/testing/evidence/full-suite-site-operations-superuser-shuffled-fresh-db.txt`). Both include `TestConsoleBrowserSite` and the six `TestR12_*` regression tests.
