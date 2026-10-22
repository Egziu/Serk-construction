#!/usr/bin/env bash
# SERK Construction: encrypted OFFSITE backup and point-in-time-recovery
# drill (GATEA-09, order item "encrypted offsite PITR").
#
# Extends deploy/drills/pitr_drill.sh. Every object that leaves the primary
# (the base backup tarball and each archived WAL segment) is encrypted with
# `age` to an X25519 recipient whose private key never touches the primary
# host; the offsite store holds ciphertext and a SHA-256 manifest only. A
# second, empty host (a fresh directory here) restores from the offsite copy
# alone, decrypting with the private key, to a named restore point, and the
# result is checked for identity with the primary at that point.
#
#   1. initdb a disposable primary; archive_command encrypts and copies each
#      segment to $OFFSITE (any rclone/S3 target in production; a directory
#      here), with a per-object SHA-256 recorded in the manifest.
#   2. base backup as an encrypted tar (pg_basebackup -Ft, piped to age).
#   3. real SERK workload (migrations 0001-00xx + kernel flows + a supplier
#      bank account, whose number is a known marker).
#   4. restore point; fingerprints; then damage (TRUNCATE of the ledger).
#   5. PROOF OF ENCRYPTION: the offsite store, and the primary's archive
#      spool, are searched for the marker strings (a supplier name, the bank
#      number, a journal description). None may appear.
#   6. restore on the second host from offsite only (manifest verified,
#      objects decrypted on the fly), to the restore point; verify
#      fingerprints, integrity scan, audit chains, checksums; measure RTO.
#   7. key hygiene: with a WRONG private key the restore must fail closed.
#
# Never point this at a real cluster: it initdb's its own directories and
# refuses to run if they already exist and DRILL_FORCE is not set.
#
# Usage (as root, with the postgres OS user present):
#   DRILL_DIR=/var/lib/postgresql/drill2 LOAD_BIN=/path/kernel.test \
#     deploy/drills/pitr_offsite_encrypted_drill.sh | tee report.txt
set -euo pipefail

PGBIN=${PGBIN:-/usr/lib/postgresql/16/bin}
W=${DRILL_DIR:?set DRILL_DIR to a scratch directory owned by nobody else}
LOAD_BIN=${LOAD_BIN:?set LOAD_BIN to a compiled kernel test binary}
P1=${DRILL_PRIMARY_PORT:-5450}
P2=${DRILL_RESTORE_PORT:-5451}
ARCHIVE_TIMEOUT=${DRILL_ARCHIVE_TIMEOUT:-10}
SOCK=$W/sock
SPOOL=$W/archive_spool          # on the primary host: ciphertext only, briefly
OFFSITE=$W/offsite              # the offsite store: ciphertext + manifest
KEYS=$W/offline_keys            # NOT on the primary host in production (vault/HSM)
HOST2=$W/host2                  # the recovery host

as_pg() { su postgres -s /bin/bash -c "$*"; }
psql1() { "$PGBIN/psql" -X -q -At -h "$SOCK" -p "$1" -U postgres -d "$2" -c "$3"; }
now() { date +%s.%N; }
secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

command -v age >/dev/null || { echo "age is required" >&2; exit 2; }
command -v age-keygen >/dev/null || { echo "age-keygen is required" >&2; exit 2; }
if [[ -e $W && -z ${DRILL_FORCE:-} ]]; then
  echo "refusing: $W exists (set DRILL_FORCE=1 to wipe a previous drill)" >&2; exit 2
fi
for d in primary host2/restore_a host2/restore_wrongkey; do
  as_pg "$PGBIN/pg_ctl -D $W/$d stop -m immediate" >/dev/null 2>&1 || true
done
rm -rf "$W"; mkdir -p "$W" "$SOCK" "$SPOOL" "$OFFSITE" "$KEYS" "$HOST2"
chown -R postgres:postgres "$W"; chmod 0700 "$W"; chmod 0777 "$SOCK"

echo "### SERK encrypted offsite PITR drill $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "### $("$PGBIN/postgres" --version); $(age --version 2>&1 | head -1); archive_timeout=${ARCHIVE_TIMEOUT}s; host $(uname -sr)"

# ------------------------------------------------------------------- keys ---
# The recipient (public) key is the only key material on the primary. The
# identity (private) key is generated here for the drill and then used ONLY
# by the recovery host; in production it lives in the vault/HSM.
age-keygen -o "$KEYS/backup.key" 2>/dev/null
RECIPIENT=$(grep -o 'age1[0-9a-z]*' "$KEYS/backup.key" | head -1)
age-keygen -o "$KEYS/wrong.key" 2>/dev/null
chown -R postgres:postgres "$KEYS"; chmod 0600 "$KEYS"/*.key
echo "$RECIPIENT" >"$W/recipient.txt"
log "backup recipient $RECIPIENT (private key kept off the primary)"

# -------------------------------------------------------------- primary ---
log "initdb primary (data checksums on); archive_command encrypts to the offsite store"
as_pg "$PGBIN/initdb -D $W/primary -U postgres --auth=trust --data-checksums -E UTF8 --locale=C.UTF-8" >/dev/null
cat >"$W/archive_push.sh" <<EOF
#!/usr/bin/env bash
# archive_command: encrypt the segment to the recipient, record its digest,
# copy to the offsite store. Fails (so PostgreSQL retries) unless the object
# is fully written and verified.
set -euo pipefail
src=\$1; name=\$2
tmp=$SPOOL/\$name.age.tmp
age -r $RECIPIENT -o "\$tmp" "\$src"
sum=\$(sha256sum "\$tmp" | cut -d' ' -f1)
test ! -f $OFFSITE/\$name.age
cp "\$tmp" $OFFSITE/\$name.age
cmp "\$tmp" $OFFSITE/\$name.age
printf '%s  %s\n' "\$sum" "\$name.age" >>$OFFSITE/MANIFEST.sha256
rm -f "\$tmp"
EOF
chmod 0755 "$W/archive_push.sh"
cat >>"$W/primary/postgresql.conf" <<EOF
port = $P1
listen_addresses = ''
unix_socket_directories = '$SOCK'
wal_level = replica
archive_mode = on
archive_command = '$W/archive_push.sh %p %f'
archive_timeout = ${ARCHIVE_TIMEOUT}s
max_wal_senders = 3
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
EOF
as_pg "$PGBIN/pg_ctl -D $W/primary -l $W/primary.log -w start" >/dev/null
psql1 "$P1" postgres "CREATE DATABASE serk"

# ---------------------------------------------------------- base backup ---
log "base backup as an encrypted tar (nothing leaves the host in plaintext)"
t0=$(now)
as_pg "$PGBIN/pg_basebackup -h $SOCK -p $P1 -U postgres -D $W/basetmp -Ft -X fetch -c fast" >/dev/null
as_pg "$PGBIN/pg_verifybackup -n $W/basetmp" 2>/dev/null | sed 's/^/    /' || true
age -r "$RECIPIENT" -o "$OFFSITE/base.tar.age" "$W/basetmp/base.tar"
printf '%s  base.tar.age\n' "$(sha256sum "$OFFSITE/base.tar.age" | cut -d' ' -f1)" >>"$OFFSITE/MANIFEST.sha256"
rm -rf "$W/basetmp"   # the plaintext base backup never persists on the primary
log "base backup took $(secs "$t0" "$(now)") s; offsite object $(du -sh "$OFFSITE/base.tar.age" | cut -f1)"

# --------------------------------------------------------------- workload ---
DSN1="postgres://postgres@/serk?host=$SOCK&port=$P1"
log "workload (all migrations + kernel flows incl. a supplier bank account)"
SERK_TEST_ADMIN_DSN=$DSN1 "$LOAD_BIN" -test.count=1 -test.timeout=900s \
  -test.run 'TestSC01_|TestSC03_|TestSC07_|TestAttestation_LegitimateTwoPersonFlow|TestApprovalProvenance_DirectJournal|TestBankAtRest_CiphertextOnlyInTheDatabase|TestJourneyA_BOQToBankReconciliationToGL' \
  | tail -1 | sed 's/^/    load: /'
# Marker strings that exist in the database and must not appear offsite.
MARK_BANK=1000987654321          # bank number recorded by TestBankAtRest (ciphertext in the DB since 0032)
MARK_SUPPLIER=$(psql1 "$P1" serk "SELECT name FROM suppliers ORDER BY created_at LIMIT 1")
MARK_DESC=$(psql1 "$P1" serk "SELECT description FROM journals WHERE description <> '' ORDER BY created_at LIMIT 1")
log "markers: supplier '$MARK_SUPPLIER', journal '$MARK_DESC', bank number ${MARK_BANK:0:4}…"

TABLES="tenants legal_entities accounts fiscal_periods journals journal_lines approval_attestations audit_log audit_heads outbox suppliers supplier_bank_accounts purchase_orders grns supplier_invoices payment_instructions"
fingerprint() {
  for t in $TABLES; do
    psql1 "$1" serk "SELECT '$t', count(*), md5(COALESCE(string_agg(x::text, '|' ORDER BY x::text), '')) FROM $t x"
  done
}
psql1 "$P1" serk "SELECT pg_create_restore_point('serk_offsite_target')" >/dev/null
TARGET_LSN=$(psql1 "$P1" serk "SELECT pg_current_wal_lsn()")
fingerprint "$P1" >"$W/fp_target.txt"
POSTED_AT_TARGET=$(psql1 "$P1" serk "SELECT count(*) FROM journals WHERE status='POSTED'")
SCAN_TARGET=$(psql1 "$P1" serk "SELECT COALESCE(string_agg(rule || ':' || journal_id, ',' ORDER BY rule, journal_id), 'none') FROM ledger_integrity_scan()")
PLAIN_BANK=$(psql1 "$P1" serk "SELECT serk_bank_plaintext_rows()")
log "restore point at LSN $TARGET_LSN; posted journals $POSTED_AT_TARGET; plaintext bank rows in the database: $PLAIN_BANK"

log "damage after the target: superuser TRUNCATE of the ledger"
psql1 "$P1" serk "TRUNCATE journal_lines, journals CASCADE" 2>&1 | sed 's/^/    truncate: /' || true
psql1 "$P1" serk "SELECT pg_switch_wal()" >/dev/null
for _ in $(seq 1 90); do
  [[ $(psql1 "$P1" postgres "SELECT last_archived_wal = pg_walfile_name(pg_current_wal_lsn() - 1) FROM pg_stat_archiver") == t ]] && break; sleep 1
done
log "archiver: $(ls "$OFFSITE" | grep -c '\.age$') encrypted objects offsite, failed_count=$(psql1 "$P1" postgres "SELECT failed_count FROM pg_stat_archiver")"
psql1 "$P1" serk "CHECKPOINT" >/dev/null   # so the control below can see the plaintext in the heap files
as_pg "$PGBIN/pg_ctl -D $W/primary stop -m immediate" >/dev/null
rm -rf "$W/primary/pg_wal"      # the disaster: the primary host is gone

# ----------------------------------------------- proof of encryption ---
echo
echo "== Proof that nothing left the primary in plaintext"
leak=0
for m in "$MARK_SUPPLIER" "$MARK_DESC" "$MARK_BANK" "serk_offsite_target" "schema_migrations"; do
  n=$( (grep -rlaF -- "$m" "$OFFSITE" "$SPOOL" 2>/dev/null || true) | wc -l)
  printf 'marker %-28s in offsite store or spool: %s file(s)\n' "'${m:0:26}'" "$n"
  [[ $n == 0 ]] || leak=1
done
# Control: the same markers ARE in the (now dead) primary's own data files.
ctrl=$( (grep -rlaF -- "$MARK_SUPPLIER" "$W/primary/base" 2>/dev/null || true) | wc -l)
echo "control: supplier marker in the primary's plaintext data files: $ctrl file(s) (expected > 0)"
echo "manifest: $(wc -l <"$OFFSITE/MANIFEST.sha256") objects; verification: $(cd "$OFFSITE" && sha256sum -c MANIFEST.sha256 --quiet && echo OK || echo FAILED)"

# ------------------------------------------- recovery host: restore ---
restore() { # dir port identity-file target-settings...
  local dir=$1 port=$2 ident=$3; shift 3
  mkdir -p "$dir"; chown postgres:postgres "$dir"; chmod 0700 "$dir"
  # Base backup: verify the manifest, decrypt, unpack. Plaintext exists only
  # on the recovery host.
  (cd "$OFFSITE" && sha256sum -c MANIFEST.sha256 --quiet)
  age -d -i "$ident" -o "$dir/base.tar" "$OFFSITE/base.tar.age" 2>/dev/null || return 9
  as_pg "tar -xf $dir/base.tar -C $dir" && rm -f "$dir/base.tar"
  rm -f "$dir/standby.signal"
  cat >"$dir/restore_fetch.sh" <<EOF
#!/usr/bin/env bash
# restore_command: fetch the encrypted segment from the offsite store, check
# it against the manifest, decrypt it into place.
set -euo pipefail
name=\$1; dst=\$2
test -f $OFFSITE/\$name.age || exit 1
want=\$(grep " \$name.age\$" $OFFSITE/MANIFEST.sha256 | cut -d' ' -f1)
got=\$(sha256sum $OFFSITE/\$name.age | cut -d' ' -f1)
[[ "\$want" == "\$got" ]] || { echo "manifest mismatch for \$name" >&2; exit 1; }
age -d -i $ident -o "\$dst" $OFFSITE/\$name.age
EOF
  chmod 0755 "$dir/restore_fetch.sh"
  {
    echo "port = $port"
    echo "unix_socket_directories = '$SOCK'"
    echo "archive_mode = off"
    echo "restore_command = '$dir/restore_fetch.sh %f %p'"
    for s in "$@"; do echo "$s"; done
  } >>"$dir/postgresql.conf"
  as_pg "touch $dir/recovery.signal"
  as_pg "$PGBIN/pg_ctl -D $dir -l $dir.log -w -t 600 start" >/dev/null
  for _ in $(seq 1 600); do
    [[ $(psql1 "$port" postgres "SELECT pg_is_in_recovery()" 2>/dev/null) == f ]] && return 0; sleep 0.2
  done
  echo "restore $dir did not promote" >&2; return 1
}

echo
log "recovery host: restore from the offsite store only, to 'serk_offsite_target'"
tA=$(now)
restore "$HOST2/restore_a" "$P2" "$KEYS/backup.key" "recovery_target_name = 'serk_offsite_target'" "recovery_target_action = 'promote'"
tA_up=$(now)
fingerprint "$P2" >"$W/fp_restored.txt"
SCAN=$(psql1 "$P2" serk "SELECT COALESCE(string_agg(rule || ':' || journal_id, ',' ORDER BY rule, journal_id), 'none') FROM ledger_integrity_scan()")
BAD_CHAINS=$(psql1 "$P2" serk "SELECT count(*) FROM tenants t WHERE audit_log_verify(t.id) <> 0")
TENANTS=$(psql1 "$P2" serk "SELECT count(*) FROM tenants")
POSTED_RESTORED=$(psql1 "$P2" serk "SELECT count(*) FROM journals WHERE status='POSTED'")
MIGR=$(psql1 "$P2" serk "SELECT min(version) || '-' || max(version) || ' (' || count(*) || ')' FROM schema_migrations")
CHECKSUM_FAIL=$(psql1 "$P2" postgres "SELECT COALESCE(sum(checksum_failures), 0) FROM pg_stat_database")
BANK_ROWS=$(psql1 "$P2" serk "SELECT count(*) || ' rows, ' || count(account_number_enc) || ' encrypted, ' || serk_bank_plaintext_rows() || ' plaintext' FROM supplier_bank_accounts")
tA_done=$(now)
as_pg "$PGBIN/pg_ctl -D $HOST2/restore_a stop -m fast" >/dev/null
if diff -u "$W/fp_target.txt" "$W/fp_restored.txt" >"$W/fp.diff"; then FP=IDENTICAL; else FP=DIFFERENT; fi

echo
echo "== Restore result"
echo "fingerprint ($(echo $TABLES | wc -w) tables) restored vs target  : $FP"
[[ $FP == DIFFERENT ]] && sed 's/^/    /' "$W/fp.diff"
echo "posted journals at target / restored         : $POSTED_AT_TARGET / $POSTED_RESTORED (0 on the damaged primary)"
echo "ledger_integrity_scan() target / restored    : $SCAN_TARGET / $SCAN"
echo "tenants / audit chains failing verification  : $TENANTS / $BAD_CHAINS"
echo "schema_migrations on restored instance       : $MIGR"
echo "data-checksum failures                       : $CHECKSUM_FAIL"
echo "supplier bank accounts restored              : $BANK_ROWS"
echo "RTO: restore start -> promoted               : $(secs "$tA" "$tA_up") s"
echo "RTO: restore start -> verified               : $(secs "$tA" "$tA_done") s"

# ------------------------------------------------ wrong key fails closed ---
echo
log "key hygiene: restore with a WRONG private key"
set +e
restore "$HOST2/restore_wrongkey" "$P2" "$KEYS/wrong.key" "recovery_target_name = 'serk_offsite_target'" "recovery_target_action = 'promote'"
rc=$?
set -e
as_pg "$PGBIN/pg_ctl -D $HOST2/restore_wrongkey stop -m immediate" >/dev/null 2>&1 || true
if [[ $rc == 9 ]]; then WRONG="refused (base backup does not decrypt)"; else WRONG="UNEXPECTED rc=$rc"; fi
echo "restore with the wrong key                   : $WRONG"

echo
if [[ $FP == IDENTICAL && $SCAN == "$SCAN_TARGET" && $BAD_CHAINS == 0 && $CHECKSUM_FAIL == 0 && $leak == 0 && $ctrl -gt 0 && $rc == 9 && $PLAIN_BANK == 0 ]]; then
  echo "DRILL VERDICT: PASS (restored from encrypted offsite copy only; no plaintext left the primary; wrong key refused)"
else
  echo "DRILL VERDICT: FAIL (fp=$FP scan_equal=$([[ $SCAN == "$SCAN_TARGET" ]] && echo yes || echo no) bad_chains=$BAD_CHAINS checksums=$CHECKSUM_FAIL leak=$leak ctrl=$ctrl wrongkey_rc=$rc plaintext_bank=$PLAIN_BANK)"; exit 1
fi
