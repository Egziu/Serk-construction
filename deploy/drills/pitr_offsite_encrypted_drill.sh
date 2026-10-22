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
#   8. AUTHENTICITY (R10-F8): every offsite object is signed (Ed25519) by a
#      key held only on the primary, over "name + SHA-256"; the recovery host
#      verifies the signature with the pinned public key BEFORE decrypting.
#      age gives confidentiality only (anyone with the public recipient can
#      encrypt), so an attacker with write access to the offsite store could
#      otherwise substitute a forged base backup or WAL segment and a matching
#      manifest line. The drill forges both and the restore must refuse.
#
# Changes after independent review 10 (R10-F8, R10-I3):
#   * per-object Ed25519 signatures; forged-object restores must fail;
#   * the base backup streams from pg_basebackup straight into age (no
#     plaintext tar on the primary's disk); PostgreSQL's backup_manifest
#     travels inside it and pg_verifybackup runs on the recovery host, with
#     its output in the report;
#   * archive_push is idempotent (an interrupted copy no longer wedges the
#     archiver): objects land under a .part name and are renamed atomically;
#   * markers that really are in the database (supplier tax id, supplier
#     name, journal description), each with a positive control in the
#     primary's own data files; the bank number is checked to be absent from
#     the primary's data files too (it is ciphertext in the database);
#   * after review 11 (R11-F4..F6): the signature also binds the cluster's
#     system identifier and the PLAINTEXT digest; an existing object with
#     different content is never accepted or overwritten; each base backup
#     has its own name and a signed inventory names it; the recovery host
#     verifies and decrypts one local copy and checks the plaintext digest;
#   * the verdict requires a CLEAN ledger_integrity_scan(), not merely the
#     same findings before and after (the workload no longer includes the
#     test that deliberately fabricates an unbalanced posted journal).
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
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
if [[ -e $W && -z ${DRILL_FORCE:-} ]]; then
  echo "refusing: $W exists (set DRILL_FORCE=1 to wipe a previous drill)" >&2; exit 2
fi
for d in primary host2/restore_a host2/restore_wrongkey host2/restore_forged_base host2/restore_forged_wal; do
  as_pg "$PGBIN/pg_ctl -D $W/$d stop -m immediate" >/dev/null 2>&1 || true
done
PRIMARY_KEYS=$W/primary_keys   # the signing key: on the primary only
rm -rf "$W"; mkdir -p "$W" "$SOCK" "$SPOOL" "$OFFSITE" "$KEYS" "$HOST2" "$PRIMARY_KEYS"
chown -R postgres:postgres "$W"; chmod 0700 "$W"; chmod 0777 "$SOCK"

echo "### SERK encrypted offsite PITR drill $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "### $("$PGBIN/postgres" --version); age $(age --version 2>&1 | head -1); $(openssl version); archive_timeout=${ARCHIVE_TIMEOUT}s; host $(uname -sr)"

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
# Signing key: generated on (and never leaving) the primary. Its public half
# is pinned on the recovery host out of band (vault / runbook), never read
# from the offsite store.
openssl genpkey -algorithm ed25519 -out "$PRIMARY_KEYS/sign.key" 2>/dev/null
openssl pkey -in "$PRIMARY_KEYS/sign.key" -pubout -out "$KEYS/sign.pub" 2>/dev/null
chown -R postgres:postgres "$PRIMARY_KEYS" "$KEYS"; chmod 0600 "$PRIMARY_KEYS/sign.key"
log "object signing key: Ed25519, public key $(openssl pkey -pubin -in "$KEYS/sign.pub" -outform DER 2>/dev/null | sha256sum | cut -c1-16)… pinned on the recovery host"
# Signed message (v2, after review 11): the cluster's system identifier,
# the object name, the SHA-256 of the ciphertext and of the plaintext:
#   serk-offsite-v2 \n SYSID \n NAME \n SHA256(cipher) \n SHA256(plain) \n
# The sidecar FILE.meta carries SYSID and SHA256(plain); FILE.sig the
# signature. Binding the plaintext digest lets the primary tell whether an
# existing offsite object holds THIS segment (R11-F4); binding the system
# identifier stops objects of another (or a rebuilt) cluster signed with the
# same key from standing in (R11-F4/F5); the recovery host checks the
# decrypted plaintext against the signed digest.
#
# sign_object NAME FILE PLAINSHA: writes FILE.meta and FILE.sig.
cat >"$W/sign_object.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
name=\$1; file=\$2; plain=\$3
sysid=\$(cat $W/sysid)
sum=\$(sha256sum "\$file" | cut -d' ' -f1)
printf '%s\n%s\n' "\$sysid" "\$plain" >"\$file.meta"
msg=\$(mktemp); trap 'rm -f "\$msg"' EXIT
printf 'serk-offsite-v2\n%s\n%s\n%s\n%s\n' "\$sysid" "\$name" "\$sum" "\$plain" >"\$msg"
openssl pkeyutl -sign -inkey $PRIMARY_KEYS/sign.key -rawin -in "\$msg" -out "\$file.sig"
echo "\$sum"
EOF
# verify_object NAME FILE: exit 0 only if FILE.sig is a valid signature of
# the pinned key over the v2 message for NAME, FILE's digest and the pinned
# system identifier; prints the signed plaintext digest. Runs wherever an
# object must be trusted (recovery host; primary for idempotent retries).
cat >"$W/verify_object.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
name=\$1; file=\$2
test -f "\$file" && test -f "\$file.sig" && test -f "\$file.meta" || { echo "unsigned or missing object \$name" >&2; exit 1; }
want=\$(cat $KEYS/sysid)
sysid=\$(sed -n 1p "\$file.meta"); plain=\$(sed -n 2p "\$file.meta")
[[ "\$sysid" == "\$want" && "\$plain" =~ ^[0-9a-f]{64}\$ ]] || { echo "OBJECT OF ANOTHER CLUSTER (\$name): refusing" >&2; exit 1; }
sum=\$(sha256sum "\$file" | cut -d' ' -f1)
msg=\$(mktemp); trap 'rm -f "\$msg"' EXIT
printf 'serk-offsite-v2\n%s\n%s\n%s\n%s\n' "\$sysid" "\$name" "\$sum" "\$plain" >"\$msg"
openssl pkeyutl -verify -pubin -inkey $KEYS/sign.pub -rawin -in "\$msg" -sigfile "\$file.sig" >/dev/null 2>&1 \
  || { echo "SIGNATURE INVALID for \$name: refusing to decrypt" >&2; exit 1; }
echo "\$plain"
EOF
chmod 0755 "$W/sign_object.sh" "$W/verify_object.sh"

# -------------------------------------------------------------- primary ---
log "initdb primary (data checksums on); archive_command encrypts to the offsite store"
as_pg "$PGBIN/initdb -D $W/primary -U postgres --auth=trust --data-checksums -E UTF8 --locale=C.UTF-8" >/dev/null
# The cluster's system identifier: signed into every object; pinned on the
# recovery host next to the public key (here: the same value in both places).
SYSID=$("$PGBIN/pg_controldata" "$W/primary" | awk -F: '/Database system identifier/ { gsub(/ /, "", $2); print $2 }')
[[ $SYSID =~ ^[0-9]+$ ]] || { echo "cannot read the system identifier" >&2; exit 1; }
echo "$SYSID" >"$W/sysid"; echo "$SYSID" >"$KEYS/sysid"; chown postgres:postgres "$W/sysid" "$KEYS/sysid"
log "cluster system identifier $SYSID (signed into every offsite object)"
cat >"$W/archive_push.sh" <<EOF
#!/usr/bin/env bash
# archive_command: encrypt the segment to the recipient, sign it (v2), copy
# object, metadata and signature to the offsite store under temporary names,
# verify, then rename into place.
#   - An existing object whose signature verifies for THIS cluster and whose
#     signed plaintext digest equals this segment's is accepted (a retry
#     after a lost acknowledgement).
#   - An existing, verifiable object with DIFFERENT content is never
#     overwritten and never accepted: the command fails and PostgreSQL keeps
#     the segment (R11-F4; PostgreSQL's archiving rule).
#   - An unverifiable object (partial upload, forgery, another cluster's) is
#     replaced.
set -euo pipefail
src=\$1; name=\$2
tmp=$SPOOL/\$name.age
psha=\$(sha256sum "\$src" | cut -d' ' -f1)
if [[ -f $OFFSITE/\$name.age ]] && have=\$($W/verify_object.sh "\$name.age" $OFFSITE/\$name.age 2>/dev/null); then
  if [[ "\$have" == "\$psha" ]]; then
    grep -q " \$name.age\\\$" $OFFSITE/MANIFEST.sha256 2>/dev/null || \
      printf '%s  %s\n' "\$(sha256sum $OFFSITE/\$name.age | cut -d' ' -f1)" "\$name.age" >>$OFFSITE/MANIFEST.sha256
    exit 0
  fi
  echo "archive: \$name.age already offsite with DIFFERENT content; refusing to overwrite or skip" >&2
  exit 1
fi
age -r $RECIPIENT -o "\$tmp" "\$src"
sum=\$($W/sign_object.sh "\$name.age" "\$tmp" "\$psha")
for x in "" .meta .sig; do cp "\$tmp\$x" $OFFSITE/\$name.age\$x.part; cmp "\$tmp\$x" $OFFSITE/\$name.age\$x.part; done
mv -f $OFFSITE/\$name.age.sig.part $OFFSITE/\$name.age.sig
mv -f $OFFSITE/\$name.age.meta.part $OFFSITE/\$name.age.meta
mv -f $OFFSITE/\$name.age.part $OFFSITE/\$name.age
# Replace any line left by an earlier, unverifiable upload of this name.
sed -i "/  \$name\\.age\$/d" $OFFSITE/MANIFEST.sha256 2>/dev/null || true
printf '%s  %s\n' "\$sum" "\$name.age" >>$OFFSITE/MANIFEST.sha256
rm -f "\$tmp" "\$tmp.sig" "\$tmp.meta"
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
log "base backup streamed from pg_basebackup straight into age (no plaintext tar on disk)"
t0=$(now)
# -D - writes one tar to stdout; WAL needed for consistency is fetched into
# it, and PostgreSQL's backup_manifest is embedded in the same stream.
# Each base backup has its own name (system identifier and time), so an older
# signed base cannot stand in for a newer one (R11-F5); a signed inventory
# names the base a restore must use. The plaintext digest is taken from the
# same stream (tee), so nothing is written in plaintext.
BASE="base_${SYSID}_$(date -u +%Y%m%dT%H%M%SZ).tar.age"
as_pg "$PGBIN/pg_basebackup -h $SOCK -p $P1 -U postgres -D - -Ft -X fetch -c fast" \
  | tee >(sha256sum | cut -d' ' -f1 >"$SPOOL/base.psha") | age -r "$RECIPIENT" -o "$SPOOL/$BASE"
[[ ${PIPESTATUS[0]} == 0 ]] || { echo "pg_basebackup failed" >&2; exit 1; }
for _ in $(seq 1 100); do [[ -s $SPOOL/base.psha ]] && break; sleep 0.1; done
chown postgres:postgres "$SPOOL/$BASE" "$SPOOL/base.psha"
sum=$(as_pg "$W/sign_object.sh $BASE $SPOOL/$BASE $(cat "$SPOOL/base.psha")")
mv "$SPOOL/$BASE" "$SPOOL/$BASE.sig" "$SPOOL/$BASE.meta" "$OFFSITE/"
printf '%s  %s\n' "$sum" "$BASE" >>"$OFFSITE/MANIFEST.sha256"
INV="inventory_${SYSID}_$(date -u +%Y%m%dT%H%M%SZ).txt"
printf 'serk-offsite-inventory-v1\nsystem_identifier=%s\nbase=%s\n' "$SYSID" "$BASE" >"$SPOOL/$INV"
chown postgres:postgres "$SPOOL/$INV"
as_pg "$W/sign_object.sh $INV $SPOOL/$INV $(sha256sum "$SPOOL/$INV" | cut -d' ' -f1)" >/dev/null
mv "$SPOOL/$INV" "$SPOOL/$INV.sig" "$SPOOL/$INV.meta" "$OFFSITE/"
rm -f "$SPOOL/base.psha"
PLAIN_ON_PRIMARY=$(find "$W" -maxdepth 3 \( -name base.tar -o -name backup_manifest \) | wc -l)
log "base backup $BASE took $(secs "$t0" "$(now)") s; offsite object $(du -sh "$OFFSITE/$BASE" | cut -f1); signed inventory $INV; plaintext base files left on the primary host: $PLAIN_ON_PRIMARY"

# --------------------------------------------------------------- workload ---
DSN1="postgres://postgres@/serk?host=$SOCK&port=$P1"
log "workload (all migrations + kernel flows incl. a supplier bank account)"
SERK_TEST_ADMIN_DSN=$DSN1 "$LOAD_BIN" -test.count=1 -test.timeout=900s \
  -test.run 'TestSC03_|TestSC07_|TestAttestation_LegitimateTwoPersonFlow|TestApprovalProvenance_DirectJournal|TestBankAtRest_CiphertextOnlyInTheDatabase|TestJourneyA_BOQToBankReconciliationToGL' \
  | tail -1 | sed 's/^/    load: /'
# Marker strings that exist in the database in plaintext and must not appear
# offsite; each has a positive control in the primary's own data files.
MARK_TIN=$(psql1 "$P1" serk "SELECT tax_id FROM suppliers WHERE tax_id IS NOT NULL ORDER BY created_at LIMIT 1")
MARK_SUPPLIER=$(psql1 "$P1" serk "SELECT name FROM suppliers ORDER BY created_at LIMIT 1")
MARK_DESC=$(psql1 "$P1" serk "SELECT description FROM journals WHERE description <> '' ORDER BY created_at LIMIT 1")
# The bank number recorded by TestBankAtRest is ciphertext in the database
# (0032): it must be absent from the primary's data files as well.
MARK_BANK=1000987654321
[[ -n $MARK_TIN && -n $MARK_SUPPLIER && -n $MARK_DESC ]] || { echo "workload produced no markers" >&2; exit 1; }
log "markers: supplier tax id '$MARK_TIN', supplier '$MARK_SUPPLIER', journal '$MARK_DESC'"

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
# Positive controls, taken BEFORE the damage (TRUNCATE gives the ledger new,
# empty files, so afterwards the old heap no longer exists): each marker must
# be present in the primary's own data files, so its absence offsite means
# something.
psql1 "$P1" serk "CHECKPOINT" >/dev/null
declare -A CTRL
for m in "$MARK_TIN" "$MARK_SUPPLIER" "$MARK_DESC" "schema_migrations"; do
  CTRL[$m]=$( (grep -rlaF -- "$m" "$W/primary/base" 2>/dev/null || true) | wc -l)
done

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
leak=0; ctrl=1
for m in "$MARK_TIN" "$MARK_SUPPLIER" "$MARK_DESC" "schema_migrations"; do
  n=$( (grep -rlaF -- "$m" "$OFFSITE" "$SPOOL" 2>/dev/null || true) | wc -l)
  c=${CTRL[$m]}
  printf 'marker %-28s offsite/spool: %s file(s); control (primary data files before the damage): %s file(s)\n' "'${m:0:26}'" "$n" "$c"
  [[ $n == 0 ]] || leak=1
  [[ $c -gt 0 ]] || ctrl=0
done
bank_primary=$( (grep -rlaF -- "$MARK_BANK" "$W/primary" "$OFFSITE" "$SPOOL" 2>/dev/null || true) | wc -l)
echo "bank number ${MARK_BANK:0:4}… anywhere on the primary or offsite (ciphertext in the database): $bank_primary file(s) (expected 0)"
[[ $bank_primary == 0 ]] || leak=1
echo "manifest: $(wc -l <"$OFFSITE/MANIFEST.sha256") objects; digests: $(cd "$OFFSITE" && sha256sum -c MANIFEST.sha256 --quiet && echo OK || echo FAILED)"
badsig=0
for o in "$OFFSITE"/*.age; do "$W/verify_object.sh" "$(basename "$o")" "$o" >/dev/null 2>&1 || badsig=$((badsig + 1)); done
echo "signatures: $(ls "$OFFSITE"/*.age | wc -l) objects, $badsig invalid"

# ------------------------------------------- recovery host: restore ---
restore() { # dir port identity-file target-settings...
  local dir=$1 port=$2 ident=$3; shift 3
  mkdir -p "$dir"; chown postgres:postgres "$dir"; chmod 0700 "$dir"
  # Base backup: verify the signature with the pinned key, then decrypt and
  # unpack; run pg_verifybackup against PostgreSQL's own backup_manifest.
  # Plaintext exists only on the recovery host.
  # The newest inventory that verifies names the base backup. Every object
  # is copied once to the recovery host, and the COPY is verified and then
  # decrypted (no second read of the store, R11-F6); the decrypted bytes
  # must match the signed plaintext digest.
  local inv base psha
  inv=$(ls "$OFFSITE" | grep -E '^inventory_[0-9]+_[0-9TZ]+\.txt$' | sort | tail -1)
  [[ -n $inv ]] || return 8
  cp "$OFFSITE/$inv" "$OFFSITE/$inv.sig" "$OFFSITE/$inv.meta" "$dir/" || return 8
  psha=$("$W/verify_object.sh" "$inv" "$dir/$inv") || return 8
  [[ $(sha256sum "$dir/$inv" | cut -d' ' -f1) == "$psha" ]] || return 8
  base=$(sed -n 's/^base=//p' "$dir/$inv")
  [[ $base =~ ^base_[0-9]+_[0-9TZ]+\.tar\.age$ ]] || return 8
  cp "$OFFSITE/$base" "$OFFSITE/$base.sig" "$OFFSITE/$base.meta" "$dir/" || return 8
  psha=$("$W/verify_object.sh" "$base" "$dir/$base") || return 8
  age -d -i "$ident" -o "$dir/base.tar" "$dir/$base" 2>/dev/null || return 9
  rm -f "$dir/$base" "$dir/$base.sig" "$dir/$base.meta" "$dir/$inv" "$dir/$inv.sig" "$dir/$inv.meta"
  [[ $(sha256sum "$dir/base.tar" | cut -d' ' -f1) == "$psha" ]] || return 8
  as_pg "tar -xf $dir/base.tar -C $dir" && rm -f "$dir/base.tar"
  if [[ -f $dir/backup_manifest ]]; then
    VERIFY_OUT=$(as_pg "$PGBIN/pg_verifybackup -n $dir" 2>&1) && VERIFY_RC=0 || VERIFY_RC=$?
    rm -f "$dir/backup_manifest"
  else
    VERIFY_OUT="no backup_manifest in the base backup"; VERIFY_RC=1
  fi
  [[ $VERIFY_RC == 0 ]] || { echo "pg_verifybackup: $VERIFY_OUT" >&2; return 7; }
  rm -f "$dir/standby.signal"
  cat >"$dir/restore_fetch.sh" <<EOF
#!/usr/bin/env bash
# restore_command: fetch the encrypted segment from the offsite store,
# verify its signature with the pinned key (the manifest alone is writable by
# whoever can write the store), decrypt it into place.
set -euo pipefail
name=\$1; dst=\$2
test -f $OFFSITE/\$name.age || exit 1
t=\$(mktemp -d $dir.fetch.XXXXXX); trap 'rm -rf "\$t"' EXIT
cp $OFFSITE/\$name.age $OFFSITE/\$name.age.sig $OFFSITE/\$name.age.meta "\$t/" || exit 1
psha=\$($W/verify_object.sh "\$name.age" "\$t/\$name.age") || exit 1
age -d -i $ident -o "\$t/plain" "\$t/\$name.age"
[[ \$(sha256sum "\$t/plain" | cut -d' ' -f1) == "\$psha" ]] || { echo "PLAINTEXT DIGEST MISMATCH for \$name" >&2; exit 1; }
mv "\$t/plain" "\$dst"
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
    [[ $(psql1 "$port" postgres "SELECT pg_is_in_recovery()" 2>/dev/null) == f ]] && return 0
    as_pg "$PGBIN/pg_ctl -D $dir status" >/dev/null 2>&1 || { echo "restore $dir: server stopped during recovery" >&2; return 1; }
    sleep 0.2
  done
  echo "restore $dir did not promote" >&2; return 1
}

echo
log "recovery host: restore from the offsite store only, to 'serk_offsite_target'"
tA=$(now)
restore "$HOST2/restore_a" "$P2" "$KEYS/backup.key" "recovery_target_name = 'serk_offsite_target'" "recovery_target_action = 'promote'"
tA_up=$(now)
VERIFY_A=$VERIFY_OUT
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
echo "pg_verifybackup on the decrypted base backup : $VERIFY_A"
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

# ------------------------------------- forged objects are refused (F8) ---
# The attacker can write the offsite store and knows the public recipient,
# so can produce valid age ciphertexts and matching manifest lines, but not
# signatures.
echo
log "authenticity: forged base backup (valid age ciphertext + manifest line, no valid signature)"
FORGE=$W/forge; mkdir -p "$FORGE"; cp -a "$OFFSITE" "$FORGE/orig"
head -c 65536 /dev/urandom | age -r "$RECIPIENT" -o "$OFFSITE/$BASE"
sed -i "s/^[0-9a-f]*  $BASE\$/$(sha256sum "$OFFSITE/$BASE" | cut -d' ' -f1)  $BASE/" "$OFFSITE/MANIFEST.sha256"
MANIFEST_OK=$(cd "$OFFSITE" && sha256sum -c MANIFEST.sha256 --quiet 2>/dev/null && echo yes || echo no)
set +e
restore "$HOST2/restore_forged_base" "$P2" "$KEYS/backup.key" "recovery_target_name = 'serk_offsite_target'" "recovery_target_action = 'promote'" 2>"$W/forged_base.err"
rc_fb=$?
set -e
as_pg "$PGBIN/pg_ctl -D $HOST2/restore_forged_base stop -m immediate" >/dev/null 2>&1 || true
echo "forged base: manifest digests still verify    : $MANIFEST_OK"
echo "forged base: restore                          : $([[ $rc_fb == 8 ]] && echo "refused before decryption ($(head -1 "$W/forged_base.err"))" || echo "UNEXPECTED rc=$rc_fb")"
rm -rf "$OFFSITE"; cp -a "$FORGE/orig" "$OFFSITE"

log "authenticity: forged WAL segment (the first segment after the base backup, needed to reach the target)"
BASESEG=$(ls "$OFFSITE" | grep -E '^[0-9A-F]{24}\.[0-9A-F]{8}\.backup\.age$' | head -1 | cut -c1-24)
SEG=$(ls "$OFFSITE" | grep -E '^[0-9A-F]{24}\.age$' | sort | awk -v b="$BASESEG" '$0 > b ".age" { print; exit }')
SEGNAME=${SEG%.age}
[[ -n $BASESEG && -n $SEG ]] || { echo "cannot locate the segment after the base backup" >&2; exit 1; }
# A structurally valid but different segment: an older one renamed.
OLD=$(ls "$OFFSITE" | grep -E '^[0-9A-F]{24}\.age$' | sort | head -1)
age -d -i "$KEYS/backup.key" "$OFFSITE/$OLD" | age -r "$RECIPIENT" -o "$OFFSITE/$SEG"
sed -i "s/^[0-9a-f]*  $SEG\$/$(sha256sum "$OFFSITE/$SEG" | cut -d' ' -f1)  $SEG/" "$OFFSITE/MANIFEST.sha256"
set +e
restore "$HOST2/restore_forged_wal" "$P2" "$KEYS/backup.key" "recovery_target_name = 'serk_offsite_target'" "recovery_target_action = 'promote'" 2>/dev/null
rc_fw=$?
set -e
as_pg "$PGBIN/pg_ctl -D $HOST2/restore_forged_wal stop -m immediate" >/dev/null 2>&1 || true
REFUSED_LOG=$(grep -c "SIGNATURE INVALID for $SEG" "$HOST2/restore_forged_wal.log" 2>/dev/null || true)
REACHED=$(grep -c "recovery stopping at restore point \"serk_offsite_target\"" "$HOST2/restore_forged_wal.log" 2>/dev/null || true)
echo "forged WAL $SEGNAME: signature refusals logged : $REFUSED_LOG; target reached: $([[ $REACHED -gt 0 ]] && echo yes || echo no); restore rc=$rc_fw"
FW_OK=no; [[ $REFUSED_LOG -gt 0 && $REACHED == 0 && $rc_fw != 0 ]] && FW_OK=yes
rm -rf "$OFFSITE"; cp -a "$FORGE/orig" "$OFFSITE"

# ------------------------------- archive_push retry and collision paths ---
echo
log "archive_push: retry, collision and foreign-object paths (R11-F4)"
head -c 16777216 /dev/urandom >"$W/seg_a"; head -c 16777216 /dev/urandom >"$W/seg_b"; chown postgres:postgres "$W/seg_a" "$W/seg_b"
NA=0000000100000000000000E0; NB=0000000100000000000000E1
echo junk >"$OFFSITE/$NA.age.part"; chown postgres:postgres "$OFFSITE/$NA.age.part"
set +e
as_pg "$W/archive_push.sh $W/seg_a $NA"; rc_part=$?
as_pg "$W/archive_push.sh $W/seg_a $NA"; rc_ack=$?
before=$(sha256sum "$OFFSITE/$NA.age" | cut -d' ' -f1)
as_pg "$W/archive_push.sh $W/seg_b $NA" 2>"$W/collision.err"; rc_col=$?
after=$(sha256sum "$OFFSITE/$NA.age" | cut -d' ' -f1)
# An object planted for NB, validly signed but for ANOTHER cluster (same key).
cp "$W/sysid" "$W/sysid.real"; echo 7000000000000000001 >"$W/sysid"
age -r "$RECIPIENT" -o "$OFFSITE/$NB.age" "$W/seg_a"; chown postgres:postgres "$OFFSITE/$NB.age"
as_pg "$W/sign_object.sh $NB.age $OFFSITE/$NB.age $(sha256sum "$W/seg_a" | cut -d' ' -f1)" >/dev/null
cp "$W/sysid.real" "$W/sysid"
as_pg "$W/archive_push.sh $W/seg_b $NB"; rc_foreign=$?
nb_plain=$("$W/verify_object.sh" "$NB.age" "$OFFSITE/$NB.age" 2>/dev/null)
set -e
echo "stale partial upload present                 : rc=$rc_part"
echo "repeated push after a lost acknowledgement   : rc=$rc_ack, manifest lines $(grep -c " $NA.age\$" "$OFFSITE/MANIFEST.sha256")"
echo "different segment under an existing name     : rc=$rc_col ($(head -1 "$W/collision.err")); offsite object unchanged: $([[ $before == "$after" ]] && echo yes || echo NO)"
echo "planted object signed for another cluster    : rc=$rc_foreign; replaced by this segment: $([[ $nb_plain == "$(sha256sum "$W/seg_b" | cut -d' ' -f1)" ]] && echo yes || echo NO)"
PUSH_OK=no
[[ $rc_part == 0 && $rc_ack == 0 && $rc_col != 0 && $before == "$after" && $rc_foreign == 0 && $nb_plain == "$(sha256sum "$W/seg_b" | cut -d' ' -f1)" ]] && PUSH_OK=yes

echo
if [[ $PUSH_OK == yes && $FP == IDENTICAL && $SCAN == none && $SCAN_TARGET == none && $BAD_CHAINS == 0 && $CHECKSUM_FAIL == 0 && $leak == 0 && $ctrl == 1 && $rc == 9 && $PLAIN_BANK == 0 \
      && $badsig == 0 && $rc_fb == 8 && $FW_OK == yes && $PLAIN_ON_PRIMARY == 0 ]]; then
  echo "DRILL VERDICT: PASS (restored from the signed, encrypted offsite copy only; clean integrity scan; no plaintext left the primary; wrong key, forged base and forged WAL refused; archive collisions refused)"
else
  echo "DRILL VERDICT: FAIL (fp=$FP scan=$SCAN scan_target=$SCAN_TARGET bad_chains=$BAD_CHAINS checksums=$CHECKSUM_FAIL leak=$leak ctrl=$ctrl wrongkey_rc=$rc plaintext_bank=$PLAIN_BANK badsig=$badsig forged_base_rc=$rc_fb forged_wal=$FW_OK plain_base=$PLAIN_ON_PRIMARY push=$PUSH_OK)"; exit 1
fi
