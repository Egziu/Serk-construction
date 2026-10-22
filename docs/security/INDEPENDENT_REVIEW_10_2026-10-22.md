# Independent review 10: isolated approval signer, stock state definer, bank numbers at rest, quantity-correction credit notes, non-superuser owner, GATEA-13 tooling, encrypted offsite drill (commits fa48c8a, 8027230, 2e0c9a2) at commit 2e0c9a2

Independent review. Every claim below comes either from a probe that was run against disposable databases (PostgreSQL 16 on /tmp:5433, Go 1.26.10, `-race`) or from a file:line citation. The databases were:
- `serk_r10s` (fresh, non-superuser owner `serk_owner_t`, deploy/02 applied): the existing suite;
- `serk_r10b` (non-superuser owner): probe development;
- `serk_r10c` (fresh, non-superuser owner, deploy/02 applied): final probe run;
- `serk_r10a` (fresh, superuser owner `postgres`): final probe run in superuser mode.

The `postgres` database and the other existing databases were not used. All data is synthetic. No existing file was modified. `deploy/drills/pitr_offsite_encrypted_drill.sh` was read, not run.

- Probes: `zz_review10_kernel_test.go` (package `kernel`, 11 tests) and `zz_review10_httpapi_test.go` (package `httpapi`, 1 test), all named `TestR10_*`. Copies are in this directory; the files were deleted from the repository tree after the run.
- Raw probe output: `probes-final-nonsuperuser-serk_r10c.txt` (final, non-superuser), `probes-final-superuser-serk_r10a.txt` (final, superuser), `probes-kernel-nonsu-run1.txt` and `probes-httpapi-nonsu.txt` (development runs on `serk_r10b`).
- Existing suite: `full-suite-r10-nonsuperuser.txt` (`go test -race -count=1 -p 1 -v ./internal/kernel ./internal/httpapi -skip TestR10_` on fresh `serk_r10s`, non-superuser owner, before any probe file existed). Result: **kernel 219 PASS, httpapi 37 PASS (top-level tests), 0 FAIL, 0 SKIP**; both packages `ok`. The commit message's "323" counts more packages; only these two were run here.

Convention: `OPEN:` (t.Errorf) means a defect was observed; `held:` (t.Logf) means the control worked; `info:` is an observation.

## Verdict

**Not ready to sign off. Four Medium defects need a decision or a fix first. None is Critical or High.** Nothing in this review shows the system is secure or production-ready; it shows what held and what did not under the probes listed.

What holds under attack:
- **Signer, honest path.** Through the remote signer an honest API refused a token from another project, and refused a revoked token (kernel `checkSessionTx`). Tenant, actor, perms, `principal.human`, MFA and `auth_time` checks held (existing `TestSignerIsolation_CompromisedAPICannotForge` PASS). Attestation lifetime 120 s (DB maximum 300 s); per-actor limit 3/min refused the 4th request.
- **0031.** The tenant login and `serk_app` hold no INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER on `stock_balances`, `stock_layers`, `stock_consumptions`. Direct writes, `stk_receive`, `stk_consume` and calling a guard directly were all refused.
- **0032.** The tenant login cannot UPDATE `supplier_bank_accounts` at all (digest, suffix, plaintext, ciphertext all refused); a raw approval needs an attestation. Ciphertext, row binding, other-key refusal and conversion pass in the existing suite.
- **0033.** A raw edit of a DRAFT correction was refused. An IPC prepared before a correction was refused as stale after it. After 60 t certified, a 10 t correction and 20 t more verified, `ipc_compute` gave this = 1,960,000 (20 t), which matches the hand figure.
- **0034.** In a tenant session calling an owner-rights function, `serk_maintenance_session()` was false and journals of 1 tenant were visible. It stayed false even after a tenant login was granted `serk_monitor`. SET ROLE, SET SESSION AUTHORIZATION, self-GRANT, deleting the tenant's `tenant_db_roles` row, reading `approval_keys` and calling the ops functions were all refused. Monitor, scheduler and health logins could not read tenant tables directly.

The defects:
- **The signer does not check project scope.** A compromised API (or anyone who can reach the socket) obtained a signed `measure.verify` for a project the token does not list. The database accepted it, and the measurement became VERIFIED.
- **The signer does not check session revocation, and neither does `approval_authorize()`.** A compromised API approved a journal with a token issued 10 minutes before the person's sessions were revoked.
- **Approval tables can be shadowed through `pg_temp` (conditional).** With TEMP granted, a tenant session shadowed `approval_attestations` and approved a journal with no signature at all. The posture check reports TEMP, so production refuses to start in that state.
- **`p2p_account_digest()` is an offline guessing oracle.** A leaked tenant credential recovered a full 13-digit account number from the stored digest and suffix: 100,000 guesses in one statement took 1.75 s, nothing was written and nothing was audited.

Smaller items:
- Through owner-rights functions the owner sees every tenant's `outbox` and `workflow_instances` rows. This is latent today.
- `attest.Remote` compares only the length of perms.
- The posture check ignores `log_parameter_max_length_on_error`.
- The drill's integrity checks use an unauthenticated manifest.
- `validate-constraints` applies MATCH SIMPLE semantics to MATCH FULL foreign keys.
- The legacy validator never checks the types of the control accounts.

## Findings

| ID | Severity | Finding |
|---|---|---|
| R10-F1 | Medium | The signer ignores the token's project scope. The token lists only project `e403d345…`; the compromised API claimed project `769bedda…`. The signer signed `measure.verify`, `approval_authorize()` accepted it, and the measurement became `VERIFIED` by `u-site-other`. |
| R10-F2 | Medium | Session revocation (GATEA-07) is not enforced by the signer or by `approval_authorize()`. A token issued 10 min before the revocation cut-off still got `journal.approve` signed and accepted: the journal became `APPROVED`. |
| R10-F3 | Medium (conditional) | `approval_use()` is SECURITY DEFINER with `search_path = pg_catalog, public`, so `pg_temp` is searched first for relations. With TEMP granted to the tenant login, the tenant created `pg_temp.approval_attestations` and `approval_consumptions` (granted to PUBLIC) and approved a journal with 0 real attestations. This happened in both owner modes. The posture check reports the TEMP grant. |
| R10-F4 | Medium | `p2p_account_digest(text)` is EXECUTE for `serk_app`; `account_digest` and `account_last4` are tenant-readable. 100,000 guesses took 1.75 s (57,195/s) and recovered `1000…4321` with nothing written or audited. All 9 unknown digits of a 13-digit number would take about 4.9 h in a single session. This is a stronger oracle than R5-F3, which needs one audited API call per guess. |
| R10-F5 | Low (latent) | The owner is a member of `serk_publisher` with INHERIT. Policies `publisher_read`/`publisher_mark` (USING true) on `outbox` and `owner_timer_scan` (USING true) on `workflow_instances` apply to the owner in any session. An owner-rights function called by a tenant saw outbox rows of 7 tenants (106 rows). No current tenant-callable definer reads those tables without a tenant filter. |
| R10-F6 | Low | `attest.Remote` compares only `len(Perms)`. A response with perms `[payment.approve]` (sent: `[journal.approve]`), kid `other-kid`, nonce `not-a-uuid`, lifetime 86,400 s and sig `zz` was accepted. |
| R10-F7 | Low | `serk_database_posture()` checks `log_parameter_max_length` only. With `log_parameter_max_length_on_error = -1`, the posture was clean. The plaintext account number is a bound parameter of `p2p_account_digest($1)`. |
| R10-F8 | Low | Encrypted offsite drill. The SHA-256 manifest lives in the same offsite store and is unsigned, and age does not authenticate the sender (the recipient key is public). Anyone who can write the offsite store can substitute a base backup or WAL segment, and both restore-time checks would pass. |
| R10-F9 | Low | `validate-constraints` applies MATCH SIMPLE to every FK. A MATCH FULL FK with row `(1, NULL)` was reported with 0 violators. `--apply` then aborted with SQLSTATE 23503, and that violator was never ledgered. |
| R10-F10 | Low | `serk-import validate` never checks the types of the control accounts. A bundle with AP control 2000 typed ASSET and AR control 1100 typed EQUITY was reported clean (0 exceptions). |
| R10-I1 | Info | Signer limits. The window is fixed: 3 + 3 were signed within about 1 ms across the boundary. Refusals are not rate-limited: 500 forged requests were refused and the next legitimate request was signed. MFA freshness is left to the database: the signer signed `mfa=true` with `auth_time` 48 h old. The limiter is per process. |
| R10-I2 | Info | Quantity corrections in reporting. After a 10 t correction, `ar_contract_position.measured_value` is net of the correction (6,860,000) but `certified_gross` is gross of it (5,880,000). `retention_held` stays at 5% of 60 t (294,000). Totals over the job reconcile (see the evidence). |
| R10-I3 | Info | Weak points of the drill as evidence: the bank marker cannot occur in the database since 0032; `pg_verifybackup` output is suppressed and `|| true`; the verdict accepts a non-clean `ledger_integrity_scan` (the recorded evidence shows `UNBALANCED_POSTED` at the target); a plaintext base tar is written to the primary's disk; a partially copied segment blocks archiving forever; the recorded run is at migrations 1–32. |
| R10-I4 | Info | Bank digest. The 0032 trigger checks only the digest's form (0032:46–48), not that it matches the ciphertext. Approval subject text and the bank snapshot bind the digest, not the ciphertext (0032:62–63, 81–82, 111). Ciphertext cannot change after insert (held). |
| R10-I5 | Info | Legacy validator. A UTF-8 BOM on `accounts.csv` produced 7 exceptions, starting with HEADER, so it fails closed. Duplicate keys are joined with `/`, which the code alphabet allows, so false duplicates are possible (legacy.go:285, 311). |
| R10-I6 | Info | With the PG15+ default public schema owner `pg_database_owner` (if `ALTER SCHEMA public OWNER` in deploy/01 is skipped), `serk_maintenance_session()` and the posture's owner exclusion (0034:33, 62–63) no longer recognise the owner. Both fail closed. |

---

### R10-F1 (Medium): the signer signs decisions outside the token's project scope

**Evidence** (`TestR10_SignerIgnoresProjectScope`; the signer runs on a unix socket with an IdP stub that maps `tok-other` to site_engineer `u-site-other`, ProjectIDs = [another project]):
```
held: honest API, token scope [e403d345-…]: refused (store: not found)
OPEN: compromised API (principal claims project 769bedda; the token lists only e403d345): the signer signed measurement.verify and the database accepted it: status VERIFIED verified_by u-site-other
info: signer issuance log: {"event":"issued",…,"actor":"u-site-other","action":"measure.verify","subject_type":"measurement",…,"ctx":"VERIFIED",…}
```
The same result appears in superuser mode (`serk_r10a`). With real HS256 tokens (`TestR10_SignerRateLimitTTLAndMFA`) the signer signed for a token whose `projects` claim was `[1111…]`.

**Cause.**
- `signer.issue` (internal/signer/signer.go:189–247) compares tenant, actor, kind, `auth_time`, MFA and perms. It never reads `p.ProjectIDs`, and the claims carry no project.
- `approval_authorize()` (0010_attestation_hardening.sql:56–124) has no notion of project scope.
- Scope is enforced only in the API's kernel (`loadDoc`), which is exactly the component the signer is meant to distrust.

**Why it matters.**
- ADR 0015 says the signer "signs only claims that token supports" and closes "a compromised API … cannot grant permissions a role lacks".
- Project scope is part of what the token supports (SC-05). A compromised API, or anyone holding the socket, can turn any live token of a project-scoped approver into decisions on every project of the tenant. The roles affected include site engineer, project manager and commercial manager (IPC certification, credit approval).

**Fix.**
- Have the signer resolve the subject's project and refuse when the token is not tenant-wide and does not list it. That means a read-only lookup by the signer, or the database binding a project into the subject hash and the signer comparing it with the token.
- Alternatively, carry the token's project list in the claims and have `approval_use()` check the subject's project against it.

### R10-F2 (Medium): revoked sessions still obtain signed approvals

**Evidence** (`TestR10_SignerIgnoresRevocation`; `u-approver` token issued 10 min before `RevokeSessions` of that subject):
```
held: the API middleware check refuses the revoked token (cut-off 2026-10-22T22:16:18+03:00)
held: honest API with the revoked token: refused (kernel: session revoked)
OPEN: compromised API, revoked token (iat 10 min before the revocation cut-off): the signer signed journal.approve and approval_authorize() accepted it; journal 7bc62e76 is APPROVED
```

**Cause.**
- Revocation is checked by the API middleware (internal/httpapi/server.go: `CheckSession`) and by `checkSessionTx` inside `authorize` (internal/kernel/kernel.go:71–73), both in the API process.
- The signer has no database and no revocation list (signer.go:141–152).
- `approval_authorize()` does not call `session_is_revoked`, and the attestation carries neither `jti` nor `iat` (0010:56–124; attest.go Claims).

**Why it matters.**
- GATEA-07 revocation exists to end a stolen or compromised session immediately.
- ADR 0015 accepts that a compromised API can act "while a person is logged in". After 0015 it can keep acting after the person is logged out, until the token expires. The signer's issuance log is the only trace.

**Fix.**
- Put the token's `jti` and `iat` into the signed claims (the signer copies them from the verified token).
- Have `approval_authorize()` refuse when `session_is_revoked(actor, jti, iat)` is true. It runs in the tenant's transaction, so the revocation list is available.

### R10-F3 (Medium, conditional): `pg_temp` shadows the approval evidence inside SECURITY DEFINER functions

**Evidence** (`TestR10_PgTempShadowsApprovalEvidence`; TEMP granted to the tenant login by the superuser connection to simulate the posture failure, then revoked):
```
held: posture reports TEMP for serk_t_e883150f… (production would refuse to start)
OPEN: with TEMP granted, a tenant session approved journal 6ae8b1cf with no signature: pg_temp.approval_attestations shadowed the real table inside approval_use(); real attestations for it: 0
```
The same result appears in superuser mode. With a non-superuser owner the tenant must first `GRANT ALL ON pg_temp.approval_attestations, pg_temp.approval_consumptions TO PUBLIC`. Without that grant the first attempt failed with "permission denied for table approval_attestations", which proves the shadow table was the one resolved.

**Cause.**
- PostgreSQL searches `pg_temp` first for relations whenever `search_path` does not name it.
- `approval_use()` (0012:29–32, SECURITY DEFINER, `search_path = pg_catalog, public`) calls `approval_in_tx()` (0010:127–134), which reads `approval_attestations` and `approval_consumptions` unqualified.
- The same applies to the 0031 stock guards and `stk_consume` (0021:221 ff.; 0024:138, 171: `FROM stock_balances` unqualified). The 0031 header's "whatever the posture" (0031:14–15) is therefore not accurate. The stock path itself was not executed.

**Why it matters.**
- This bypasses the attestation requirement (GATEA-APPROVAL-01) for every approval-guarded transition, with only the tenant credential.
- It is conditional on TEMP. Production refuses to start while `serk_database_posture()` reports it, but that check runs only at start-up. A database created later, or a grant made at run time, is not re-checked.
- This is the same conditional class as R7-F9, with wider impact.

**Fix.**
- Pin `pg_temp` last in every SECURITY DEFINER and trigger function (`SET search_path = pg_catalog, public, pg_temp`), as the PostgreSQL documentation recommends.
- Or schema-qualify every relation (`public.approval_attestations`).
- Add a catalog test that every `prosecdef` function's `proconfig` ends with `pg_temp`.

### R10-F4 (Medium): the keyed digest is an offline oracle for the full account number

**Evidence** (`TestR10_BankDigestOracle`; the attacker holds only the tenant login, with no API and no data key; known: 13 digits, bank prefix 1000, suffix from `account_last4`):
```
OPEN: tenant login recovered the full account number 1000…4321 from account_digest + account_last4 with 100,000 p2p_account_digest() guesses in one statement (1.75 s, 57195 guesses/s; 10^9 = all 9 unknown digits of a 13-digit number ≈ 4.9 h single session); nothing written, nothing audited
info: R5-F3 path for comparison: 1 guess per API request (… duplicate … cannot be registered …), audit rows for the two guesses: 3
```
Superuser mode: 1.65 s, 60,637 guesses/s.

**Cause.**
- `p2p_account_digest(text)` is SECURITY DEFINER and granted to `serk_app` (0017:12–26). The API needs it because it has the database compute the digest (`kernel/p2p.go:1861`).
- The digest and the last 4 characters are stored in tenant-readable columns (0032:14–17, 25–28).

**Why it matters.**
- 0032's stated goal is that "a leaked tenant credential, a database export or a backup … yields no account numbers" (0032:7–8). R5-F3 was accepted as a residual on the promise that R-BANK-AT-REST is "the full fix (uniqueness on a keyed digest, no oracle at all)" (ISSUE_REGISTER R5-F3).
- Bank account numbers have little entropy beyond the bank prefix and the displayed suffix. Recovery takes seconds to hours per number and leaves no audit trace.
- An export or backup alone is not enough, because it lacks `approval_keys`' use through the function. A live tenant credential is enough.

**Fix.**
- Compute the digest in the API with a key the database never holds (for example HMAC under a subkey of `SERK_BANK_DATA_KEY`), and revoke EXECUTE on `p2p_account_digest` from `serk_app`.
- If the database must compute it, gate the function behind the attestation for the create action (one digest per attested creation) and audit each call.
- Reconsider storing `account_last4` beside the digest.

### R10-F5 (Low, latent): the owner's inherited platform-role policies are not tenant-scoped

**Evidence** (`TestR10_OwnerMaintenance`, non-superuser owner; a scratch owner-rights function, such as a future migration might add, was created by the superuser connection and granted to `serk_app`):
```
info: schema owner serk_owner_t (superuser false) holds the privileges of serk_publisher: true
info: policies … that apply to the owner in ANY session: [outbox:publisher_mark TO serk_publisher USING true outbox:publisher_read TO serk_publisher USING true workflow_instances:owner_timer_scan TO serk_owner_t USING true]
held: serk_maintenance_session() is false for a tenant session calling an owner-rights function
held: journals through the owner function: 1 tenant(s)
OPEN: tenant session through an owner-rights function saw outbox rows of 7 tenants (106 rows) …
```

**Cause.**
- deploy/01-schema-owner.sql:23 grants `serk_publisher` (and the other platform roles) to the owner WITH ADMIN OPTION. With PG16 defaults this is also INHERIT.
- Policies `publisher_read` and `publisher_mark` (0003_tenant_identity.sql:82–83) and `owner_timer_scan` (0006_workflow.sql:635) are USING (true).

**Why it matters.**
- 0034 (lines 37–41) and ADR 0016 state that a tenant calling an owner-rights function "still matches only its own tenant". For `outbox` (read and UPDATE) and `workflow_instances` it does not.
- Today no tenant-callable definer touches those tables. The catalog search found only `workflow_due_tenants` and `ops_health_metrics`, neither executable by `serk_app`. `approval_subject_hash` filters by tenant explicitly.
- The privilege test `TestPrivileges_OwnerMaintenancePolicyEverywhere` would not catch a future regression.

**Fix.**
- Grant the platform roles to the owner `WITH ADMIN OPTION, INHERIT FALSE, SET FALSE`.
- Rewrite `owner_timer_scan` to use `serk_maintenance_session()`.
- Add a catalog test that no policy other than `tenant_isolation` and `owner_maintenance` applies to the owner.

### R10-F6 (Low): `attest.Remote` checks the returned claims only partially

**Evidence** (`TestR10_RemoteComparesPermsByLengthOnly`, fake signer on a unix socket):
```
OPEN: Remote accepted a response with perms [payment.approve] (sent [journal.approve]), kid "other-kid", nonce "not-a-uuid", lifetime 86400s, sig "zz"
```

**Cause.** `pkg/attest/remote.go:110–114` compares `len(got.Perms) != len(c.Perms)` and never compares `V`, `KeyID`, `IssuedAt`/`ExpiresAt` bounds, `Nonce` form or `Sig` form.

**Why it matters.**
- The database still verifies the signature, the lifetime (≤ 300 s) and the nonce, so a widened attestation must still carry a valid HMAC. In practice only the holder of the signing key can exploit this.
- However, ADR 0015 ("`attest.Remote` refuses an attestation whose claims differ from what it sent, so a signer cannot widen them") and the existing test (which appends a perm and so changes the length) overstate the check.

**Fix.** Compare the sorted perm lists element by element. Check `V == 1`, `ExpiresAt-IssuedAt ≤ MaxTTL`, the UUID form of the nonce and the hex form of the signature.

### R10-F7 (Low): the posture check ignores on-error parameter logging

**Evidence** (`TestR10_BankRowRules`):
```
info: server log_parameter_max_length=-1 log_parameter_max_length_on_error=0 (posture checks only the first)
OPEN: posture is clean with log_parameter_max_length_on_error = -1 (bound parameters, including the plaintext number passed to p2p_account_digest, are logged in full on error)
```

**Cause.** 0034:82–83 checks only `log_parameter_max_length`. The plaintext number travels as `$1` of `SELECT p2p_account_digest($1)` (`kernel/p2p.go:1861`).

**Fix.** Also require `log_parameter_max_length_on_error = 0`. Better: stop sending the plaintext (see R10-F4).

### R10-F8 (Low): the offsite integrity check does not authenticate the objects

**Evidence** (citation; the script was not run):
- archive_push appends `sha256(ciphertext)` to `$OFFSITE/MANIFEST.sha256` in the same store (drill.sh:91–95, 120).
- The restore checks objects against that manifest (drill.sh:181, 191–194).
- Objects are encrypted to an age X25519 recipient, whose public key is on the primary and in `recipient.txt` (drill.sh:73–76). age gives confidentiality only: anyone with the recipient key can produce a valid ciphertext.

**Why it matters.**
- Someone with write access to the offsite store (the threat an offsite copy is meant to survive) can replace `base.tar.age` or a WAL segment and the manifest line. The "manifest verified" restore would then accept a forged ledger.
- The recorded PASS (docs/…/pitr-offsite-encrypted-drill-2026-10-22.txt) does not test this.

**Fix.**
- Sign the manifest (or each object) with a key that exists only on the primary (for example `ssh-keygen -Y sign` or minisign) and verify the signature on the recovery host before decrypting.
- And/or use object-lock/WORM storage. Ship PostgreSQL's `backup_manifest` too and run `pg_verifybackup` on the restored base.

### R10-F9 (Low): `validate-constraints` mis-handles MATCH FULL foreign keys

**Evidence** (`TestR10_ValidateConstraintsMatchFull`; scratch tables in the disposable database):
```
info: report-only: r10_child r10_fk_full violators=0
OPEN: MATCH FULL FK with a half-NULL row (1, NULL) reported with 0 violators …
info: report-only: r10_chk r10_chk_pos violators=1
info: --apply run: 3 reports, error: validate r10_fk_full: ERROR: … violates foreign key constraint "r10_fk_full" (SQLSTATE 23503)
info: migration_exceptions rows for the r10 constraints: 1
```

**Cause.**
- `internal/store/postgres/constraints.go:79–84` always skips rows with any NULL FK column (MATCH SIMPLE) and never reads `confmatchtype`.
- An error in `--apply` returns at line 117, so constraints sorted after it are not processed.
- A CHECK on a column named `"a, b"` was handled correctly (1 violator ledgered).

**Fix.**
- For `confmatchtype = 'f'`, report rows where some but not all FK columns are NULL, or where all are non-NULL and unmatched.
- Continue past a failed VALIDATE and report it, rather than aborting.

### R10-F10 (Low): the legacy validator never checks control-account types

**Evidence** (`TestR10_LegacyBundle`): the clean testdata bundle with `2000,Accounts payable,ASSET` and `1100,Accounts receivable,EQUITY`:
```
OPEN: bundle with the AP control account typed ASSET and the AR control account typed EQUITY is reported clean (control-account type is never checked)
```

**Cause.** `pkg/legacy/legacy.go:181–185` checks only that the control codes exist. `apOpening`/`arOpening` (lines 277–282) take the sign by convention whatever the account type.

**Fix.** Require AP control = LIABILITY and AR control = ASSET (and refuse a cost code on them).

### R10-I1 (Info): signer limits

`TestR10_SignerRateLimitTTLAndMFA` (real HS256 tokens, injected clock):
```
held: attestation lifetime 120s (DB max 300s)
held: per-actor limit 3/min: 3 signed, 1 refused
info: fixed window: 3 signed in the first minute and 3 more 1 ms after it ends (6 within ~1 ms …)
info: 500 forged requests refused without touching the budget; legitimate request after them: 200
info: signer signed mfa=true for a token whose auth_time is 48 h old (freshness is left to approval_authorize: mfa_fresh requires <= 600 s)
```

- The window is fixed and in memory per process (signer.go:249–266), so several signer replicas multiply the budget.
- Refusals are counted in a metric only.
- MFA freshness is decided by `approval_authorize()` (0010: `fresh := … now_s - at <= 600`). That is correct for actions that need MFA.

### R10-I2 (Info): quantity corrections, ordering and reporting

`TestR10_QuantityCorrectionOrderings`:
```
held: raw edit of a DRAFT correction: … permission denied for table customer_credit_notes
held: IPC 2 prepared before the correction is stale after it: … IPC IPC-2026-000002 is stale …
info: ar_contract_position after 60 t certified, 20 t verified (IPC 2 stale) and an approved 10 t correction: measured_value 6860000.00 (70 t, net of the correction), certified_gross 5880000.000000 (60 t, gross of the correction), retention_held 294000.000000 (5% of 60 t), credited_total 1127000.000000
info: ipc_compute after the correction: cumulative 6860000.00 previous 4900000.000000 this 1960000.000000
```

- No re-billing or double deduction was found.
- A correction shifts both cumulative and previous by q × rate (0033:57–64), so a certificate's `this_gross` is unchanged. The stale check refuses a prepared IPC anyway (0018:563–571).
- Retention (5% of the over-measured work) and advance recovery stay as certified. By hand, total revenue over the job = Σ this_gross − Σ correction net, which equals the true work. Retention and advance are timing only.
- Credit VAT is on the full net (0022:88). Totals net to (true gross − total recovery) × rate.
- In the position report, `certified_gross` is not net of corrections while `measured_value` is, so "certified > measured" can appear (60 t certified, 50 t measured net of the correction).

### R10-I3 (Info): drill evidence quality

All by citation:
- `MARK_BANK` cannot be in the database since 0032 (drill.sh:131), so its absence offsite proves nothing.
- The positive control checks one marker in the primary's base files only (drill.sh:171).
- `pg_verifybackup … 2>/dev/null | … || true` (drill.sh:118): the result is discarded, and `backup_manifest` is not shipped offsite.
- The verdict requires `SCAN == SCAN_TARGET` (drill.sh:255), not a clean scan. The recorded run shows `UNBALANCED_POSTED:b0f178f7…` at both target and restore and still reports PASS.
- `pg_basebackup -Ft` writes a plaintext `base.tar` to the primary's disk before encryption (drill.sh:117–121).
- If `cp` is interrupted, `test ! -f $OFFSITE/$name.age` (drill.sh:92) makes every retry fail, so WAL accumulates on the primary.
- The evidence file shows `schema_migrations 1-32`, which is before 0033/0034.

### R10-I4 (Info): bank digest not bound to the ciphertext

- The 0032 trigger checks only `^hmac:[0-9a-f]{64}$` (0032:46–48).
- Approval subject text and `p2p_bank_snapshot` use `account_digest` and null out `account_number_enc` (0032:62–63, 81–82, 111).
- A creator path that supplies a digest of a different number than the ciphertext would bypass duplicate detection, and approval would not bind the encrypted number. Only the API computes both today, and the raw tenant insert still needs an attestation.
- After insert, the ciphertext is immutable: the probe's tenant UPDATEs were refused for lack of the privilege.

### R10-I5 (Info): legacy validator false positives

- A BOM on `accounts.csv` gives 7 exceptions (HEADER, then FK cascades).
- Keys `r[0]+"/"+r[1]` (legacy.go:285, 311) collide, because `/` is a legal code character (codeForm, legacy.go:68). Only false duplicates result.

### R10-I6 (Info): `pg_database_owner`

On PG15+, a database created without `ALTER SCHEMA public OWNER TO <owner>` has `nspowner = pg_database_owner`. Both `serk_maintenance_session()` (0034:33) and the posture's owner exclusion (0034:62–63) key on that, so maintenance and start-up fail closed. Seen in `serk_r10a`: "schema owner pg_database_owner".

## Held (with executed evidence)

| Area | Attempt | Result |
|---|---|---|
| Signer | Honest API with a token for another project / a revoked token | refused (`store: not found`; `kernel: session revoked`) |
| Signer | Other actor, tenant, unpermitted perm, marker for an unasserted principal, decision by an unasserted or AI token, invented MFA, invented auth_time, oversized ctx | refused (existing `TestSignerIsolation_CompromisedAPICannotForge`, PASS in the suite) |
| Signer | Lifetime; per-actor limit | 120 s; 3/min, 4th refused |
| Signer | Kernel call without a bearer | refused (existing `TestSignerIsolation_NoBearerNoSignature`, PASS) |
| 0031 | INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER on state tables (catalog), raw INSERT, UPDATE, DELETE, `stk_receive`, `stk_consume`, direct guard call | all refused: permission denied |
| 0031/R7-F9 | TEMP granted to the tenant login | posture reports it |
| 0032 | Tenant UPDATE of digest, suffix, plaintext, or plaintext with ciphertext cleared | permission denied |
| 0032 | Raw approve of a bank account | refused: needs an attestation |
| 0032 | Ciphertext only, row binding, other key, no key, legacy conversion and posture | existing `TestBankAtRest_*` PASS (non-superuser) |
| 0033 | Raw edit of a DRAFT correction; certifying an IPC prepared before the correction | refused; refused as stale |
| 0033 | Over-correction, missing line, mispriced raw correction; 60 + 70 − 10 = 120 t | existing `TestCreditQuantityCorrection_NoDoubleDeduction` PASS |
| 0034 | `serk_maintenance_session()` in a tenant session via an owner-rights function; journals visible | false; 1 tenant |
| 0034 | Tenant login granted `serk_monitor` | still false; 1 tenant |
| 0034 | SET ROLE serk_monitor, SET SESSION AUTHORIZATION owner, GRANT serk_monitor to itself, DELETE tenant_db_roles, read approval_keys, call `ops_health_metrics`, `serk_bank_plaintext_rows`, `serk_maintenance_session` | all refused |
| 0034 | Monitor, scheduler and health logins reading journals, supplier_bank_accounts, audit_log, outbox directly | refused (`current_tenant` not executable) |
| 0034 | Publisher login reading journals, bank accounts, audit_log | refused. It reads `outbox` across 7 tenants by design (0003:82). |
| GATEA-13 | CHECK on a quoted column name `"a, b"` | 1 violator counted and ledgered |
| Suite | Non-superuser owner, fresh DB | kernel 219, httpapi 37 PASS; 0 FAIL; 0 SKIP |

## Not tested

- The drill (`pitr_offsite_encrypted_drill.sh`) was not executed. R10-F8 and R10-I3 are by citation.
- The OIDC/JWKS path of the signer, its key rotation, and the docker-compose production profile (socket volume permissions, UID sharing). Probes used HS256 or an IdP stub.
- The `pg_temp` shadow of the stock state tables inside the 0031 guards. It is reasoned from the same mechanism and cited, not executed.
- A concurrent race between correction approval and IPC certification (only the sequential order was probed); concurrent verification.
- Bank-key rotation (`Previous` keys) and the converter on large or partially converted data.
- Area 5 in superuser mode: the scratch-function probe does not apply there (owner `pg_database_owner`; superuser definers bypass RLS anyway).
- Supply chain, HSM/KMS and the edge proxy draft.

## Files (in this directory)

- `REVIEW_10.md`: this report
- `zz_review10_kernel_test.go`, `zz_review10_httpapi_test.go`: the probes (deleted from the repository)
- `probes-final-nonsuperuser-serk_r10c.txt`, `probes-final-superuser-serk_r10a.txt`: final probe output
- `probes-kernel-nonsu-run1.txt`, `probes-httpapi-nonsu.txt`: development runs
- `full-suite-r10-nonsuperuser.txt`: the existing suite (non-superuser owner, fresh `serk_r10s`)
- `full-suite.txt`, `full-suite-nonsuperuser-owner.txt`: left by the earlier, stopped review attempt (not used for this report)

---

## Resolution (delivering team, 2026-10-22): migration 0035, signer, drill and tooling changes

The delivering team wrote these fixes, not the reviewer. They are **AI-verified with executed tests. They have not been independently re-reviewed.**
- The reviewer's probes are kept as regression tests in `internal/kernel/review10_regression_test.go` and `internal/httpapi/review10_regression_test.go`, as copies of `zz_review10_*`. The originals are saved under `docs/security/evidence/independent-review-10-probes-*.go.txt`.
- Where a fix changed a probe's premise, the probe now asserts the fixed behaviour. The rate-limit probe's claims carry the token's scope, session and issue-time markers, as the signer now requires. The owner-maintenance probe reports a superuser object owner as information, because RLS cannot bind a superuser; the posture check now refuses that configuration in production.
- Raw output before the fixes: `docs/security/evidence/independent-review-10-before-{nonsuperuser,superuser}.txt`. After: `independent-review-10-after-{nonsuperuser,superuser}.txt`.

**ID note.** The register already used `R10-F1` for the non-superuser-owner defect found by the first, interrupted run of this review (closed by 0034). That entry is renamed `R10-P1`. The IDs below are the reviewer's.

| ID | Resolution | Proof after the fix |
|---|---|---|
| R10-F1 | Every attestation now carries signed scope markers: `principal.scope:tenant`, or one `principal.project:<id>` per project the token lists. The signer signs only the token's own markers (`auth.Authorizer.ScopeMarkers`). `approval_authorize()` maps the subject to its project with `serk_subject_project()`, the same mapping as the kernel's `docProject`. It refuses a subject outside the markers. A mapped subject without a project counts as tenant-wide: only tenant scope may decide it (fail closed). | `TestR10_SignerIgnoresProjectScope` PASS in both owner modes: the signer refuses the forged marker (`permission "principal.project:…" is not granted by the token`). `TestAttestationMarkers_DatabaseEnforcesSessionAndScope` PASS: a correctly signed attestation (as a leaked key would make it) is refused by the database for another project's marker or no scope marker, and accepted for its own project or tenant scope. |
| R10-F2 | Attestations carry `principal.session:<jti or ->` and `principal.iat:<unix>`, exactly one of each. The signer requires them to equal the token's (refusal reason `session`). `approval_authorize()` calls `session_is_revoked(actor, session, iat)` and refuses a revoked session. | `TestR10_SignerIgnoresRevocation` PASS: refused end to end by the signer. `TestAttestationMarkers_DatabaseEnforcesSessionAndScope` PASS: in the database a signed attestation with an issue time before the revocation is refused, so is one with an unknown issue time (`iat 0`, fail closed), and one issued after the revocation is accepted. Missing or duplicated session markers are refused. |
| R10-F3 | Every public function's pinned `search_path` now ends with `pg_temp`, rewritten in place for all of them. A privilege-test invariant refuses any future function whose pinned path does not name `pg_temp` last, and any SECURITY DEFINER function without a pinned path. | `TestR10_PgTempShadowsApprovalEvidence` PASS: with TEMP granted, the shadow tables are ignored and the approval is refused. `TestPrivileges_*` PASS. |
| R10-F4 | The digest is computed in the API: `datakey.Digest` (HKDF + HMAC-SHA-256 with `SERK_BANK_DIGEST_KEY`, prefix `hkey:`). That key is required alongside the data key and must differ from every other secret. `p2p_account_digest()` is revoked from PUBLIC and `serk_app`. The trigger refuses new `hmac:` digests. `serk-migrate encrypt-bank-accounts` re-digests rows written between 0032 and 0035, the only change the trigger admits to encrypted details, and only in a maintenance session. The posture check reports any remaining `hmac:` rows. | `TestR10_BankDigestOracle` PASS: the tenant credential can no longer call the digest function. `TestBankAtRest_LegacyDigestRedigested` PASS: posture reports the row, the converter re-digests it, the reveal still works, a second run converts 0 rows, and a combined digest/suffix change is refused. |
| R10-F5 | `deploy/01-schema-owner.sql` grants the platform roles to the owner `WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`. The posture check reports an owner that inherits any platform role. `owner_timer_scan` now admits maintenance sessions only. | `TestR10_OwnerMaintenance` PASS (non-superuser): through an owner-rights function a tenant session sees outbox rows of 1 tenant. |
| R10-F6 | `attest.Remote` checks every returned field against what was sent: the exact sorted perms, version, key id (length), nonce (UUID form), signature (64 hex characters), TTL ≤ `MaxTTL`, and issue/expiry times within a few seconds of the API's clock. | `TestR10_RemoteComparesPermsByLengthOnly` PASS: the forged response is refused. |
| R10-F7 | The posture check also reports `log_parameter_max_length_on_error ≠ 0`. | `TestR10_BankRowRules` PASS. |
| R10-F8 | Each offsite object is signed with Ed25519 (the key exists only on the primary) over name and SHA-256. The recovery host verifies the signature with a pinned public key **before** decrypting. The drill forges a base backup and a WAL segment and requires both to be refused. | Drill PASS: `docs/operations/evidence/pitr-offsite-signed-drill-2026-10-22.txt`. Forged base refused before decryption, even though the manifest digests still verify. Forged WAL: 2 signature refusals, then `recovery ended before configured recovery target was reached`. Details in `docs/operations/BACKUP_PITR_RESTORE_PROOF.md` §6. |
| R10-F9 | `ValidateConstraints` reads `confmatchtype`. Under MATCH FULL, a partially NULL key counts as a violator. `VALIDATE` runs inside a savepoint: a refusal is recorded (violators −1 and the server's message) instead of aborting the run. `serk-migrate` treats any non-zero count as a failure (exit 3). | `TestR10_ValidateConstraintsMatchFull` PASS. |
| R10-F10 | The legacy validator checks control-account types: the AP control must be LIABILITY and the AR control ASSET (exception kind `CONTROL`, e.g. `AP control account 2000 is ASSET, want LIABILITY`). | `TestR10_LegacyBundle` and `TestControlTypesAndBOM` PASS. |
| R10-I1 | **Documented, open.** The per-actor window is fixed and kept in memory per signer process. Refusals are counted in `serk_signer_refusals_total` but not rate-limited. MFA freshness is decided by `approval_authorize()` (600 s), which is the authority. With several signer replicas the budget multiplies. A shared limiter (as in 0029) is staging work. | Registered OPEN (Info). |
| R10-I2 | **Documented.** `ar_contract_position.certified_gross` is gross of quantity corrections and `measured_value` is net of them, so "certified > measured" can appear after a correction. Retention and advance recovery stay as certified (timing only). Totals over the job reconcile, as the reviewer showed by hand. A `certified_net` column for reporting is a product decision for the commercial owner. | Registered OPEN (Info, product). |
| R10-I3 | Drill rewritten: no plaintext base tar on disk (`pg_basebackup -D -` streamed into age); `backup_manifest` shipped and `pg_verifybackup` output reported and enforced; idempotent archive pushes (`.part` + rename, existing object accepted only if its signature verifies, manifest line replaced); real markers with positive controls taken before the damage; a **clean** integrity scan required; run at migrations 1–35. | Same evidence file. Retry paths are exercised at its end. |
| R10-I4 | **Residual, documented.** The database cannot check that a digest matches the ciphertext without the key. Only the API writes both, the tenant credential cannot UPDATE the table, and a raw INSERT needs an attestation. Encrypted details are immutable, except the converter's one-way `hmac:`→`hkey:` digest change. | Registered (Info). |
| R10-I5 | The UTF-8 BOM is stripped. Duplicate keys are joined with U+001F, which no code can contain. | `TestControlTypesAndBOM` PASS. |
| R10-I6 | Fixed beyond the reviewer's ask. `serk_object_owner()` is the owner of `public.tenants`, the role that ran the migrations. It replaces the schema-owner lookups in `serk_maintenance_session()` and the posture check, so a `public` schema still owned by `pg_database_owner` no longer breaks maintenance. The posture check also reports tables owned by any other role, and an object owner that is a superuser or has BYPASSRLS. | `TestR10_OwnerMaintenance` PASS in both modes. Superuser mode logs the documented information line. |

**Executed evidence (full suites)**, Go 1.26.10 with `-race`, PostgreSQL 16:

| Owner mode | Database | Command | Result | Log |
|---|---|---|---|---|
| Non-superuser owner `serk_owner_t` (deploy/02 applied) | fresh `serk_full35n3` | `go test -race -count=1 -p 1 -v ./...` | **339 PASS, 0 FAIL, 0 SKIP** | `docs/testing/evidence/full-suite-review10-fixes-nonsuperuser-fresh-db.txt` |
| Superuser owner | fresh `serk_full35s3` | same, with `-shuffle=on` | **339 PASS, 0 FAIL, 0 SKIP** | `docs/testing/evidence/full-suite-review10-fixes-superuser-shuffled-fresh-db.txt` |

- Both runs include the 12 `TestR10_*` probes, `TestAttestationMarkers_DatabaseEnforcesSessionAndScope` and `TestBankAtRest_LegacyDigestRedigested`, plus the four browser journeys (A, B, C and planning).
- Two earlier attempts were stopped and do not count as evidence:
  - The first was stopped by the team to finish the legacy-digest conversion before the logs were taken.
  - The second showed 3 failures, all older tests that hand-sign attestations without the session markers 0035 now requires: `TestSignerIsolation_CompromisedAPICannotForge`, `TestAttestation_ReplaySubstitutionExpiryAndTampering` and `TestAttestation_MFAFreshnessIsVerifiedInSQL`. Their signing helpers now add the markers an honest signer adds. `TestSignerIsolation_CompromisedAPICannotForge` gained three refusal cases: no markers, another session's markers, and a project the token does not list.

**Not changed, by decision:**
- A project-scoped principal may still decide subjects that are not project-mapped at all, such as journals, as before. Their permission comes from the role. Scope only narrows project-mapped records.
- The signing key of the offsite chain is a secret on the primary. A compromised primary can sign. That is the reason for object-lock storage (GATEA-08, blocked on infrastructure).
