#!/usr/bin/env bash
# SERK Construction — backup and point-in-time-recovery drill (GATEA-09).
#
# Builds a DISPOSABLE PostgreSQL 16 primary with WAL archiving, takes a base
# backup BEFORE the schema exists (so the restore must replay every migration
# and every business transaction from WAL), loads real SERK workload through
# the kernel's own integration tests, marks a named restore point, then:
#
#   Scenario A (operator error): post-target workload + a superuser
#     TRUNCATE of the ledger; restore a FRESH instance to the restore point and
#     prove it is byte-identical (per-table fingerprints) to the state at the
#     target, the integrity scan is clean and every tenant's audit chain
#     verifies. Measures RTO.
#   Scenario B (primary lost): a 1 Hz committed heartbeat, then the primary is
#     killed and its pg_wal discarded; restore to the end of the archive and
#     measure how many committed seconds were lost (RPO) under the configured
#     archive_timeout.
#
# Never point this at a real cluster: it initdb's its own directories and
# refuses to run if they already exist and DRILL_FORCE is not set.
#
# Usage (as root, with the postgres OS user present):
#   DRILL_DIR=/var/lib/postgresql/drill LOAD_BIN=/path/kernel.test \
#     deploy/drills/pitr_drill.sh | tee report.txt
# LOAD_BIN is `go test -c -o kernel.test ./internal/kernel`.
set -euo pipefail

PGBIN=${PGBIN:-/usr/lib/postgresql/16/bin}
W=${DRILL_DIR:?set DRILL_DIR to a scratch directory owned by nobody else}
LOAD_BIN=${LOAD_BIN:?set LOAD_BIN to a compiled kernel test binary}
P1=${DRILL_PRIMARY_PORT:-5440}
P2=${DRILL_RESTORE_PORT:-5441}
ARCHIVE_TIMEOUT=${DRILL_ARCHIVE_TIMEOUT:-10}
SOCK=$W/sock
ARCH=$W/wal_archive

as_pg() { su postgres -s /bin/bash -c "$*"; }
psql1() { "$PGBIN/psql" -X -q -At -h "$SOCK" -p "$1" -U postgres -d "$2" -c "$3"; }
now() { date +%s.%N; }
secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

if [[ -e $W && -z ${DRILL_FORCE:-} ]]; then
  echo "refusing: $W exists (set DRILL_FORCE=1 to wipe a previous drill)" >&2; exit 2
fi
as_pg "$PGBIN/pg_ctl -D $W/primary stop -m immediate" >/dev/null 2>&1 || true
as_pg "$PGBIN/pg_ctl -D $W/restore_a stop -m immediate" >/dev/null 2>&1 || true
as_pg "$PGBIN/pg_ctl -D $W/restore_b stop -m immediate" >/dev/null 2>&1 || true
rm -rf "$W"; mkdir -p "$W" "$SOCK" "$ARCH"; chown -R postgres:postgres "$W"; chmod 0700 "$W"; chmod 0777 "$SOCK"

echo "### SERK PITR drill $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "### $("$PGBIN/postgres" --version); archive_timeout=${ARCHIVE_TIMEOUT}s; host $(uname -sr)"

# ---------------------------------------------------------------- primary ---
log "initdb primary (data checksums on)"
as_pg "$PGBIN/initdb -D $W/primary -U postgres --auth=trust --data-checksums -E UTF8 --locale=C.UTF-8" >/dev/null
cat >>"$W/primary/postgresql.conf" <<EOF
port = $P1
listen_addresses = ''
unix_socket_directories = '$SOCK'
wal_level = replica
archive_mode = on
archive_command = 'test ! -f $ARCH/%f && cp %p $ARCH/%f'
archive_timeout = ${ARCHIVE_TIMEOUT}s
max_wal_senders = 3
EOF
as_pg "$PGBIN/pg_ctl -D $W/primary -l $W/primary.log -w start" >/dev/null
psql1 "$P1" postgres "CREATE DATABASE serk"
psql1 "$P1" postgres "CREATE DATABASE drill_rpo"

log "base backup (before any schema exists)"
t0=$(now)
as_pg "$PGBIN/pg_basebackup -h $SOCK -p $P1 -U postgres -D $W/base -X stream -c fast"
as_pg "$PGBIN/pg_verifybackup $W/base" | sed 's/^/    /'
log "base backup took $(secs "$t0" "$(now)") s, size $(du -sh "$W/base" | cut -f1)"

# --------------------------------------------------------------- workload ---
DSN1="postgres://postgres@/serk?host=$SOCK&port=$P1"
log "workload phase 1 (migrations 0001-0008 + kernel flows: posting, approvals, FX, workflow, outbox)"
SERK_TEST_ADMIN_DSN=$DSN1 "$LOAD_BIN" -test.count=1 -test.timeout=600s \
  -test.run 'TestSC01_|TestSC03_|TestSC07_|TestAttestation_LegitimateTwoPersonFlow|TestWorkflow_FXApprovalKeepsVarianceControls|TestApprovalProvenance_DirectJournal' \
  | tail -1 | sed 's/^/    load: /'

TABLES="tenants legal_entities accounts fiscal_periods journals journal_lines fx_sources fx_policies fx_snapshots approval_attestations audit_log audit_heads outbox workflow_definitions workflow_instances workflow_decisions"
fingerprint() { # port -> one line per table: name rows md5
  for t in $TABLES; do
    psql1 "$1" serk "SELECT '$t', count(*), md5(COALESCE(string_agg(x::text, '|' ORDER BY x::text), '')) FROM $t x"
  done
}
psql1 "$P1" serk "SELECT pg_create_restore_point('serk_drill_target')" >/dev/null
TARGET_LSN=$(psql1 "$P1" serk "SELECT pg_current_wal_lsn()")
fingerprint "$P1" >"$W/fp_target.txt"
log "restore point 'serk_drill_target' at LSN $TARGET_LSN; fingerprint:"
sed 's/^/    /' "$W/fp_target.txt"
POSTED_AT_TARGET=$(psql1 "$P1" serk "SELECT count(*) FROM journals WHERE status='POSTED'")
# The integrity scan must give the SAME answer after restore as at the target
# (the SC-01 load deliberately plants one superuser-made exploitation so that
# detection evidence surviving the restore is itself exercised).
SCAN_TARGET=$(psql1 "$P1" serk "SELECT COALESCE(string_agg(rule || ':' || journal_id, ',' ORDER BY rule, journal_id), 'none') FROM ledger_integrity_scan()")
log "ledger_integrity_scan() at target: $SCAN_TARGET"

log "workload phase 2 (after the target) + simulated operator error: superuser TRUNCATE of the ledger"
SERK_TEST_ADMIN_DSN=$DSN1 "$LOAD_BIN" -test.count=1 -test.timeout=600s -test.run 'TestSC02_' | tail -1 | sed 's/^/    load: /'
psql1 "$P1" serk "TRUNCATE journal_lines, journals CASCADE" 2>&1 | sed 's/^/    truncate: /' || true
log "after the error: posted journals on primary = $(psql1 "$P1" serk "SELECT count(*) FROM journals WHERE status='POSTED'") (were $POSTED_AT_TARGET at target)"
psql1 "$P1" serk "SELECT pg_switch_wal()" >/dev/null
for _ in $(seq 1 60); do
  [[ $(psql1 "$P1" postgres "SELECT last_archived_wal = pg_walfile_name(pg_current_wal_lsn() - 1) FROM pg_stat_archiver") == t ]] && break; sleep 1
done
log "archive: $(ls "$ARCH" | wc -l) WAL files, failed_count=$(psql1 "$P1" postgres "SELECT failed_count FROM pg_stat_archiver")"

# -------------------------------------------------- scenario B: heartbeat ---
log "scenario B: 1 Hz committed heartbeat for 25 s, then the primary is killed and pg_wal lost"
psql1 "$P1" drill_rpo "CREATE TABLE hb(n int PRIMARY KEY, committed_at timestamptz NOT NULL DEFAULT clock_timestamp())"
for n in $(seq 1 25); do psql1 "$P1" drill_rpo "INSERT INTO hb(n) VALUES ($n)"; sleep 1; done
LAST_COMMITTED=$(psql1 "$P1" drill_rpo "SELECT max(n) || ' at ' || max(committed_at) FROM hb")
as_pg "$PGBIN/pg_ctl -D $W/primary stop -m immediate" >/dev/null
rm -rf "$W/primary/pg_wal"   # the disaster: primary storage gone; only base + archive survive
log "primary killed; last committed heartbeat on it: $LAST_COMMITTED"

restore() { # name port target-settings...
  local name=$1 port=$2; shift 2
  as_pg "cp -a $W/base $W/$name"
  rm -f "$W/$name/standby.signal"
  {
    echo "port = $port"
    echo "archive_mode = off"
    echo "restore_command = 'cp $ARCH/%f %p'"
    for s in "$@"; do echo "$s"; done
  } >>"$W/$name/postgresql.conf"
  as_pg "touch $W/$name/recovery.signal"
  as_pg "$PGBIN/pg_ctl -D $W/$name -l $W/$name.log -w -t 600 start" >/dev/null
  for _ in $(seq 1 600); do
    [[ $(psql1 "$port" postgres "SELECT pg_is_in_recovery()") == f ]] && return 0; sleep 0.2
  done
  echo "restore $name did not promote" >&2; return 1
}

# ------------------------------------------- scenario A: restore to target ---
log "scenario A: restore a fresh instance to 'serk_drill_target'"
tA=$(now)
restore restore_a "$P2" "recovery_target_name = 'serk_drill_target'" "recovery_target_action = 'promote'"
tA_up=$(now)
fingerprint "$P2" >"$W/fp_restored.txt"
SCAN=$(psql1 "$P2" serk "SELECT COALESCE(string_agg(rule || ':' || journal_id, ',' ORDER BY rule, journal_id), 'none') FROM ledger_integrity_scan()")
BAD_CHAINS=$(psql1 "$P2" serk "SELECT count(*) FROM tenants t WHERE audit_log_verify(t.id) <> 0")
TENANTS=$(psql1 "$P2" serk "SELECT count(*) FROM tenants")
POSTED_RESTORED=$(psql1 "$P2" serk "SELECT count(*) FROM journals WHERE status='POSTED'")
MIGR=$(psql1 "$P2" serk "SELECT string_agg(version::text, ',' ORDER BY version) FROM schema_migrations")
CHECKSUM_FAIL=$(psql1 "$P2" postgres "SELECT COALESCE(sum(checksum_failures), 0) FROM pg_stat_database")
tA_done=$(now)
as_pg "$PGBIN/pg_ctl -D $W/restore_a stop -m fast" >/dev/null

if diff -u "$W/fp_target.txt" "$W/fp_restored.txt" >"$W/fp.diff"; then FP=IDENTICAL; else FP=DIFFERENT; fi
echo
echo "== Scenario A result"
echo "fingerprint (16 tables) restored vs target : $FP"
[[ $FP == DIFFERENT ]] && sed 's/^/    /' "$W/fp.diff"
echo "posted journals at target / restored        : $POSTED_AT_TARGET / $POSTED_RESTORED"
echo "ledger_integrity_scan() at target          : $SCAN_TARGET"
echo "ledger_integrity_scan() restored            : $SCAN"
echo "tenants / audit chains failing verification : $TENANTS / $BAD_CHAINS"
echo "schema_migrations on restored instance      : $MIGR"
echo "data-checksum failures                      : $CHECKSUM_FAIL"
echo "RTO: restore start -> promoted              : $(secs "$tA" "$tA_up") s"
echo "RTO: restore start -> verified              : $(secs "$tA" "$tA_done") s"

# ------------------------------------------ scenario B: restore to latest ---
log "scenario B: restore a fresh instance to the end of the archive"
tB=$(now)
restore restore_b "$P2" "recovery_target_timeline = 'latest'" "recovery_target_action = 'promote'"
tB_up=$(now)
RECOVERED=$(psql1 "$P2" drill_rpo "SELECT COALESCE(max(n), 0) || ' at ' || COALESCE(max(committed_at)::text, '-') FROM hb")
LOST=$(( ${LAST_COMMITTED%% *} - ${RECOVERED%% *} ))
as_pg "$PGBIN/pg_ctl -D $W/restore_b stop -m fast" >/dev/null
echo
echo "== Scenario B result (archive-only recovery, archive_timeout=${ARCHIVE_TIMEOUT}s)"
echo "last committed heartbeat on lost primary    : $LAST_COMMITTED"
echo "last heartbeat on restored instance         : $RECOVERED"
echo "measured RPO                                : $LOST committed transactions = ~$LOST s of 1 Hz writes"
echo "RTO: restore start -> promoted              : $(secs "$tB" "$tB_up") s"
echo
if [[ $FP == IDENTICAL && $SCAN == "$SCAN_TARGET" && $BAD_CHAINS == 0 && $CHECKSUM_FAIL == 0 ]]; then
  echo "DRILL VERDICT: PASS (scenario A exact; scenario B RPO measured above)"
else
  echo "DRILL VERDICT: FAIL"; exit 1
fi
