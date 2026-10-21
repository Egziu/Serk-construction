# Incident response runbook

Scope: the alerts in `deploy/observability/prometheus-alerts.yml`. The steps below are engineering procedures for a **pre-production** system. Production on-call ownership, paging and escalation contacts are **not assigned** and require a human owner (Gate P).

General rules:

- **Preserve evidence before fixing.** Never edit posted ledger rows, audit rows, approval evidence or close records in place. Corrections go through reversals, additive migrations or documented exceptions (`migration_exceptions`).
- **Assume tampering until shown otherwise** for any integrity or authority alert.
- **Record a timeline** of who did what, when, with which `trace_id`/`rid`.

## ledger-integrity

**Alert:** `SerkLedgerIntegrityViolation` (`serk_ledger_integrity_violations > 0`).

1. Run `SELECT * FROM ledger_integrity_scan();` as the owner. Record each rule and `journal_id`.
2. Freeze affected periods. Do not reopen. Close or lock is refused anyway while violations exist: the kernel close prerequisite fails.
3. For each journal, compare:
   - `audit_log` entries for the aggregate, and run `audit_log_verify(tenant)`;
   - `approval_attestations` and `approval_consumptions` for its approvals (actor, time, txid).

   **No matching attestation and consumption** means the change came from outside the application (owner or superuser), i.e. scenario R-DBA. Escalate to security.
4. Check `pg_stat_activity` and the PostgreSQL logs (pgaudit, once installed) for sessions with `session_replication_role=replica` or `ALTER TABLE … DISABLE TRIGGER`.
5. Remediation:
   - if the change was malicious, restore from PITR to just before it (see `BACKUP_PITR_RESTORE_PROOF.md`); re-applying later legitimate transactions needs a finance sign-off;
   - otherwise, book a documented correcting journal.

## audit-chain

**Alert:** `SerkAuditChainMismatch`.

1. Run `SELECT t.id, audit_log_verify(t.id) FROM tenants t;` as the owner. A non-zero value is the first broken sequence number; `-1` means the head disagrees with the log.
2. Treat as tampering. Snapshot the database (`pg_basebackup`) **before** any change.
3. Compare with the off-host evidence copy. NOT YET IMPLEMENTED (R-DBA mitigation). Until then, compare with the most recent verified backup.

## outbox-lag

**Alerts:** `SerkOutboxLagHigh`, `SerkOutboxLagCritical`, `SerkOutboxDeadLetters`.

1. Is the relay running? Check the `serk-relay` logs.
2. Does it hold the leader lock? Advisory lock 727002 is held by exactly one relay.
3. Is the consumer webhook returning errors? Check `outbox.last_error` for the oldest pending events, as the owner.
4. Dead letters: after fixing the consumer, replay with the relay's replay command. Consumers deduplicate on `event_id`, so replay is safe.

## approval refused at database

**Alert:** `SerkApprovalRefusedAtDatabase`.

The API always checks before signing, so a refusal by the database means one of:

- a key mismatch (rotation done wrong, or an inactive key);
- a subject changed concurrently;
- **tampering**: someone altered state or keys underneath the API.

Steps:

1. Find the request: search the logs for `invariant_violation` around the alert time and take its `trace_id`.
2. Check `approval_keys` (owner only): is the tenant's active key the one the API signs with?
3. If the keys are fine, treat as a security incident.

## session check unavailable

**Alert:** `SerkSessionCheckUnavailable`.

All authenticated requests are refused with 503. This is fail-closed by design. Restore database connectivity for the API's tenant logins. **Do not** bypass the check.

## credential spike or revoked session used

**Alerts:** `SerkAuthFailureSpike`, `SerkRevokedSessionUsed`.

1. Identify the source IPs from the `auth_failure` and `revoked_session_used` log events. The per-IP lockout is automatic.
2. For a revoked session presented by a terminated user's token, check whether the IdP has disabled the account. Revoke again if new tokens appear (`POST /v1/identity/sessions/revoke`).
