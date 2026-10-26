#!/usr/bin/env bash
# SERK staging entrypoint for Railway (TEST ENVIRONMENT, SYNTHETIC DATA ONLY).
#
#  1. database roles and their passwords      (deploy/00-roles.sql, 01-schema-owner.sql)
#  2. migrations as the NON-superuser schema owner serk_owner (serk-migrate)
#  3. advisory-lock / TEMP restrictions       (deploy/02, as the administrator)
#  4. synthetic demo tenant                   (serk-seed, idempotent)
#  5. isolated approval signer on a unix socket, then the API (no signing key)
#
# Required variables: SERK_ADMIN_DSN, SERK_DB_HOST, SERK_DB_PORT, SERK_DB_NAME,
# SERK_TENANT_DB_SECRET, SERK_APPROVAL_SIGNING_KEY, SERK_TOKEN_SECRET,
# SERK_OWNER_PASSWORD, SERK_HEALTH_PASSWORD, SERK_TIMER_PASSWORD, SERK_RATELIMIT_PASSWORD,
# SERK_ABUSE_KEY, SERK_BANK_DATA_KEY, SERK_BANK_DIGEST_KEY, SERK_SEED_TENANT,
# SERK_STAGING_LOGIN_PASSPHRASE. Optional: SERK_SEED_TENANT_2 (+ _NAME) for a
# second synthetic company (e.g. Senselet Construction PLC).
set -euo pipefail

if [[ "${SERK_ENV:-}" != "staging" && "${SERK_ENV:-}" != "development" ]]; then
  echo "entrypoint: this image is for test environments only (SERK_ENV=staging|development)" >&2
  exit 2
fi
for v in SERK_ADMIN_DSN SERK_DB_HOST SERK_DB_PORT SERK_DB_NAME SERK_TENANT_DB_SECRET SERK_APPROVAL_SIGNING_KEY \
         SERK_TOKEN_SECRET SERK_OWNER_PASSWORD SERK_HEALTH_PASSWORD SERK_TIMER_PASSWORD SERK_RATELIMIT_PASSWORD SERK_SEED_TENANT; do
  if [[ -z "${!v:-}" ]]; then echo "entrypoint: $v is required" >&2; exit 2; fi
done
SSL="${SERK_DB_SSLMODE:-prefer}"
DB="${SERK_DB_HOST}:${SERK_DB_PORT}/${SERK_DB_NAME}?sslmode=${SSL}"

echo "entrypoint: waiting for PostgreSQL"
for i in $(seq 1 60); do
  if psql "$SERK_ADMIN_DSN" -qtAc 'SELECT 1' >/dev/null 2>&1; then break; fi
  [[ $i == 60 ]] && { echo "entrypoint: database unreachable" >&2; exit 1; }
  sleep 2
done

echo "entrypoint: roles"
psql "$SERK_ADMIN_DSN" -v ON_ERROR_STOP=1 -q -f /opt/serk/sql/00-roles.sql
psql "$SERK_ADMIN_DSN" -v ON_ERROR_STOP=1 -q -f /opt/serk/sql/01-schema-owner.sql
# The schema owner is not a superuser and has no BYPASSRLS, as in production.
psql "$SERK_ADMIN_DSN" -v ON_ERROR_STOP=1 -q -v owner="$SERK_OWNER_PASSWORD" \
  -v health="$SERK_HEALTH_PASSWORD" -v timer="$SERK_TIMER_PASSWORD" -v rl="$SERK_RATELIMIT_PASSWORD" <<'SQL'
ALTER ROLE serk_owner PASSWORD :'owner';
SELECT format('ALTER DATABASE %I OWNER TO serk_owner', current_database()) \gexec
ALTER SCHEMA public OWNER TO serk_owner;
-- Never write bound parameters (amounts, bank data) to the server log.
SELECT format('ALTER DATABASE %I SET log_parameter_max_length = 0', current_database()) \gexec
SELECT format('ALTER DATABASE %I SET log_parameter_max_length_on_error = 0', current_database()) \gexec
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER ROLE serk_health PASSWORD :'health';
ALTER ROLE serk_timer PASSWORD :'timer';
ALTER ROLE serk_ratelimit PASSWORD :'rl';
SQL

OWNER_DSN="postgres://serk_owner:${SERK_OWNER_PASSWORD}@${DB}"

echo "entrypoint: migrations (as serk_owner)"
SERK_ADMIN_DSN="$OWNER_DSN" serk-migrate

echo "entrypoint: advisory-lock and TEMP restrictions"
psql "$SERK_ADMIN_DSN" -v ON_ERROR_STOP=1 -q -f /opt/serk/sql/02-restrict-advisory-locks.sql

echo "entrypoint: synthetic demo tenant"
RUN=/tmp/serk
mkdir -p "$RUN" && chmod 0700 "$RUN"
export SERK_DB_BASE_DSN="postgres://${DB}"
SERK_ADMIN_DSN="$OWNER_DSN" serk-seed --out "$RUN/seed.env"
set -a; . "$RUN/seed.env"; set +a  # SERK_STAGING_TENANT, _PROJECTS, _COMPANIES

export SERK_HEALTH_DSN="postgres://serk_health:${SERK_HEALTH_PASSWORD}@${DB}"
export SERK_SCHEDULER_DSN="postgres://serk_timer:${SERK_TIMER_PASSWORD}@${DB}"
if [[ -n "${SERK_ABUSE_KEY:-}" ]]; then
  export SERK_ABUSE_DSN="postgres://serk_ratelimit:${SERK_RATELIMIT_PASSWORD}@${DB}"
fi
export SERK_LISTEN=":${PORT:-8080}"
export SERK_SIGNER_SOCKET="$RUN/signer.sock"

echo "entrypoint: approval signer"
# The signer holds the approval key; the API never receives it.
env -u SERK_ADMIN_DSN -u SERK_TENANT_DB_SECRET -u SERK_BANK_DATA_KEY -u SERK_BANK_DIGEST_KEY -u SERK_ABUSE_KEY \
    -u SERK_OWNER_PASSWORD -u SERK_HEALTH_PASSWORD -u SERK_TIMER_PASSWORD -u SERK_RATELIMIT_PASSWORD -u SERK_STAGING_LOGIN_PASSPHRASE \
    serk-signer &
SIGNER=$!
for i in $(seq 1 50); do [[ -S "$SERK_SIGNER_SOCKET" ]] && break; sleep 0.2; done
[[ -S "$SERK_SIGNER_SOCKET" ]] || { echo "entrypoint: signer did not start" >&2; exit 1; }

echo "entrypoint: API on $SERK_LISTEN (staging, synthetic data)"
env -u SERK_APPROVAL_SIGNING_KEY -u SERK_ADMIN_DSN -u SERK_OWNER_PASSWORD -u SERK_HEALTH_PASSWORD -u SERK_TIMER_PASSWORD -u SERK_RATELIMIT_PASSWORD \
    serk-api &
API=$!
trap 'kill -TERM $API $SIGNER 2>/dev/null' TERM INT
# If either process exits, stop the container so the platform restarts it.
set +e
wait -n $API $SIGNER
code=$?
kill -TERM $API $SIGNER 2>/dev/null
wait
exit $code
