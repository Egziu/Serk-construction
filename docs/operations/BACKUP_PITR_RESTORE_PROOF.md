# Backup, restore and point-in-time recovery: proof (GATEA-09)

**Executed** on 2026-10-21 using `deploy/drills/pitr_drill.sh` against a disposable PostgreSQL 16.15 cluster that the script creates itself (initdb with data checksums).

- Raw output: `docs/operations/evidence/pitr-drill-2026-10-21.txt`.
- Two runs were made. The first ended FAIL because of a defect in the drill's own verdict rule (see §4). The second, recorded in the evidence file, is PASS.

## 1. Method

1. **Base backup before the schema exists.** The script runs `pg_basebackup -X stream` and then `pg_verifybackup`, both of which succeed, before migrations 0001–0008 are applied. The restore therefore has to replay every migration and every business transaction from archived WAL; nothing is pre-baked in the backup.
2. **Real SERK workload.** The kernel's own integration tests run against the primary:
   - posting with maker/checker approval;
   - attested approvals;
   - FX maker/checker;
   - outbox events;
   - a workflow-governed FX approval;
   - the SC-01 exploitation test, which deliberately plants one unbalanced posted journal as superuser.

   The result was 14 tenants, 7 journals, 29 approval evidence rows, 52 audit entries and 58 outbox events.
3. **Named restore point** `serk_drill_target`. A fingerprint (row count plus md5 of all rows) of 16 tables is taken at that moment, together with the integrity-scan result.
4. **Damage after the target.** More workload runs, and then a superuser `TRUNCATE journal_lines, journals CASCADE` simulates operator error. Posted journals on the primary drop from 3 to 0.
5. **Scenario A.** A fresh instance is restored from base backup plus archive to the restore point. It is checked for:
   - an identical fingerprint;
   - an integrity scan identical to the target;
   - every tenant's audit hash chain verifying;
   - migrations 1–8 present;
   - zero data-checksum failures.
6. **Scenario B.** A 1 Hz committed heartbeat runs for 25 s. The primary is then killed (`-m immediate`) and its `pg_wal` deleted, simulating loss of primary storage. A fresh instance is restored to the end of the archive, and the lost committed transactions are counted.

## 2. Results (from the evidence file)

| Check | Result |
|---|---|
| `pg_verifybackup` | backup successfully verified |
| Scenario A fingerprint, 16 tables, restored vs target | **IDENTICAL** |
| Posted journals, target vs restored (vs 0 on the damaged primary) | 3 / 3 |
| `ledger_integrity_scan()`, target vs restored | identical: the one planted `UNBALANCED_POSTED` row is still detected after restore |
| Audit chains failing verification | 0 of 14 |
| Migrations on the restored instance | 1–8 |
| Data-checksum failures | 0 |
| **RTO** (restore start → promoted / → verified) | 0.75 s / 0.90 s |
| **RPO**, scenario B (archive-only, `archive_timeout=10s`) | **6 committed transactions ≈ 6 s** of 1 Hz writes lost |

## 3. What this proves and what it does not

It **proves** that the backup and WAL-archive procedure restores a SERK database exactly, migrations included, to a named point in time. After restore, the ledger is identical, the audit chains verify and integrity detection still works. It also proves that archive-only recovery loses at most about `archive_timeout` seconds of commits.

It does **not** prove the following. Each stays open, and none may be claimed:

- **Representative RTO.** The base backup was 53 MB and the WAL archive held 6 segments. Production RTO grows with database size and WAL volume. It must be re-measured on a staging copy of production size (GATEA-08 is BLOCKED).
- **Offsite, encrypted, immutable retention.** The archive sat on the same disk as the primary. Required: an encrypted object store (for example S3 with Object Lock, or an equivalent in-region store for data residency), using a tool such as pgBackRest or WAL-G with checksum verification and retention policy. NOT IMPLEMENTED.
- **Near-zero RPO.** With archive-only recovery the RPO is bounded by `archive_timeout`. For a lower RPO, use `pg_receivewal` or a synchronous standby. NOT IMPLEMENTED, and the business must decide the target.
- **Scheduled backups, restore monitoring and alerting on archiver failure** (`pg_stat_archiver.failed_count`). NOT IMPLEMENTED (see OBSERVABILITY_SLOS when written).

**Proposed** targets, not guarantees, which need business sign-off per directive §3.1:

- RPO ≤ 5 minutes using archive-only recovery with `archive_timeout=60s`;
- RPO ≤ 10 s with WAL streaming;
- RTO ≤ 1 hour for a database up to 100 GB.

Every figure must be re-measured at staging scale before anyone signs.

## 4. Defect found in the drill itself

The first run reported FAIL. The verdict rule required the integrity scan to show zero violations, but the workload plants one violation on purpose, and that violation exists at the target. The rule was changed to require **equality with the target**, which is the stronger check: detection evidence must survive the restore. No product code changed.

## 5. Re-running

```bash
go test -c -o /tmp/kernel.test ./internal/kernel
DRILL_DIR=/var/lib/postgresql/drill LOAD_BIN=/tmp/kernel.test deploy/drills/pitr_drill.sh | tee pitr-drill.txt
```

The script refuses to run if `DRILL_DIR` exists, unless `DRILL_FORCE=1` is set. It creates its own cluster and never connects to any other.

## 5. Encrypted offsite drill (2026-10-22)

**Executed** with `deploy/drills/pitr_offsite_encrypted_drill.sh` against a disposable PostgreSQL 16.15 cluster the script creates. Raw output: `docs/operations/evidence/pitr-offsite-encrypted-drill-2026-10-22.txt`. Three runs were made: the first two ended early on defects in the drill script itself (a `pipefail` abort on a no-match `grep`, and a control that searched heap files before a checkpoint); the third, in the evidence file, is PASS.

### Method

- Every object leaving the primary is encrypted with `age` (X25519) to a recipient whose private key is never on the primary host: the base backup (`pg_basebackup -Ft` piped into `age`) and each archived WAL segment (`archive_command` encrypts, records a SHA-256 in a manifest, copies to the offsite store and verifies the copy before reporting success). The plaintext base backup is deleted the moment the encrypted object exists.
- Workload: all 32 migrations and kernel flows (posting with maker/checker, attested approvals, FX, outbox, Journey A procure-to-pay, a supplier bank account whose number is a known marker).
- Named restore point, fingerprints of 16 tables, then a superuser `TRUNCATE` of the ledger, a checkpoint, and the primary killed with its `pg_wal` deleted.
- A separate recovery host restores from the offsite store only: manifest verified, base decrypted, each WAL segment checked against the manifest and decrypted on the fly by `restore_command`.
- The same restore is attempted with a wrong private key.

### Results (from the evidence file)

| Check | Result |
|---|---|
| Marker strings (supplier name, journal description, bank number, restore-point name, `schema_migrations`) in the offsite store or the archive spool | 0 files for every marker |
| Control: supplier name in the dead primary's own heap files | 2 files (the plaintext exists; only the offsite copy lacks it) |
| Manifest (5 objects) | verified OK |
| Fingerprint, 16 tables, restored vs target | **IDENTICAL** |
| Posted journals, target vs restored (0 on the damaged primary) | 11 / 11 |
| `ledger_integrity_scan()`, target vs restored | identical (the planted `UNBALANCED_POSTED` row is still detected) |
| Audit chains failing verification | 0 of 16 tenants |
| Migrations on the restored instance | 1–32 |
| Data-checksum failures | 0 |
| Supplier bank accounts restored | 3 rows, 3 encrypted, 0 plaintext |
| RTO, restore start to promoted / verified | 1.06 s / 1.21 s (46 MB base, 5 WAL objects) |
| Restore with the wrong private key | refused: the base backup does not decrypt |

### What this proves and what it does not

- Proven: a backup chain can be kept offsite in a form that discloses nothing, and a fresh host can be rebuilt from it alone to an exact point in time, with the ledger's integrity and audit evidence intact. The bank data key (0032) is not in the backup, so bank account numbers in a restored database still need the API's key.
- Not proven: the real offsite medium (object storage with retention lock, cross-region copies), the retention and key-rotation schedule, restore at production data volume, and custody of the private key in a vault or HSM. These need staging infrastructure (GATEA-08) and a human-owned key ceremony. The RPO measurement of §2 (archive_timeout) applies unchanged.

## 6. Signed, encrypted offsite drill after review 10 (2026-10-22)

Independent review 10 found that the §5 drill authenticated nothing (R10-F8): the SHA-256 manifest sits in the same offsite store, and `age` provides confidentiality only, because anyone with the public recipient key can produce a valid ciphertext. Someone able to write the offsite store could therefore replace the base backup or a WAL segment, together with its manifest line, and both restore-time checks would pass. The review also listed weaknesses in the drill as evidence (R10-I3). The drill script was changed, and it was **executed** again on a disposable PostgreSQL 16.15 cluster. Raw output: `docs/operations/evidence/pitr-offsite-signed-drill-2026-10-22.txt`. That run is PASS, at migrations 1–35. An earlier run of the changed script failed on the drill's own control: the description marker was searched for after the TRUNCATE had replaced the ledger's files. The control now runs before the damage.

### What changed

| Item | Before (§5) | Now |
|---|---|---|
| Authenticity | Unsigned SHA-256 manifest in the offsite store | Each object is signed with Ed25519 over `serk-offsite-v1 / name / SHA-256`. The key exists only on the primary. The recovery host checks the signature against a public key pinned out of band, and does this **before** decrypting. A failed check refuses the base backup (`restore_command` fails for a WAL segment). |
| Forgery test | None | (a) Forged base backup: random bytes encrypted to the real recipient, with a matching manifest line. (b) Forged WAL segment: an older genuine segment re-encrypted under the name of the first segment needed after the base. Both must be refused. |
| Base backup on the primary | `pg_basebackup -Ft` wrote a plaintext `base.tar` to disk, which was then encrypted | `pg_basebackup -D - -Ft` streams straight into `age`. No plaintext file is written; the run reports 0 such files. |
| `pg_verifybackup` | Output discarded, `\|\| true` | PostgreSQL's `backup_manifest` travels inside the encrypted stream. `pg_verifybackup` runs on the recovery host, its output is in the report, and failure stops the restore. |
| Archive retries | `test ! -f` made every retry fail after an interrupted copy, so WAL would accumulate | Uploads go to `.part` and are renamed. An existing object is accepted only if its signature verifies. An unverifiable object is replaced, along with its manifest line. All three paths are exercised at the end of the evidence file. |
| Markers | The bank-number marker cannot be in the database since 0032, so its absence proved nothing | Supplier tax id, supplier name, journal description and `schema_migrations` each have a positive control in the primary's data files, taken before the damage. Separately, the bank number is shown to be absent from the primary's files as well as from the offsite store. |
| Verdict | `scan == scan at target` (a planted `UNBALANCED_POSTED` passed) | Requires a **clean** `ledger_integrity_scan()` at both the target and the restore. The workload no longer includes the test that deliberately fabricates a defect. |

### Results (from the evidence file)

| Check | Result |
|---|---|
| Plaintext base-backup files on the primary host | 0 |
| Markers in the offsite store or spool / controls in the primary's files before the damage | 0 / 1, 2, 1, 7 |
| Bank number anywhere on the primary or offsite | 0 files |
| Manifest digests; signatures | OK; 5 objects, 0 invalid |
| `pg_verifybackup` on the decrypted base | `backup successfully verified` |
| Fingerprint, 16 tables, restored vs target | **IDENTICAL** |
| `ledger_integrity_scan()` target / restored | none / none |
| Audit chains failing; data-checksum failures | 0 of 12 tenants; 0 |
| Migrations on the restored instance | 1–35 |
| RTO promoted / verified | 0.8 s / 1.0 s (47 MB base, 5 WAL objects) |
| Wrong private key | refused (does not decrypt) |
| Forged base backup (manifest digests still verify) | refused before decryption: `SIGNATURE INVALID for base.tar.age` |
| Forged WAL segment `…03` | 2 signature refusals logged. Recovery ended before the target: `FATAL: recovery ended before configured recovery target was reached`. |
| Archive retry paths: stale `.part`; lost acknowledgement; invalid signature on an existing object | rc 0 for each. One manifest line per object, digests OK, and the replaced object's signature is valid. |

### Still not proven

- The signing key on a real primary is a host secret. An attacker who controls the primary can sign forged objects. That threat is the reason for an *offsite* copy with object lock/WORM retention, and it needs the real storage (GATEA-08).
- The pinned public key, the age identity and their rotation need a human key ceremony; see the KEY_CUSTODY runbook.
- Production data volume, cross-region copies and the retention schedule are untested.
