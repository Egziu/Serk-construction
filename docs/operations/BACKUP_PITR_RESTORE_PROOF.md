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
