# ADR 0014: Abuse limits shared across API replicas

Status: accepted by the delivering team (2026-10-22); awaiting human review. Migration 0029.

## Context

The pre-authentication controls (SC-13) are: requests per client address, invalid credentials per address with a lockout, and a per-principal budget. They were counted in each process, so N replicas allowed N times every limit, and a client locked out on one replica could continue on the others (GATEA-10). The order requires distributed abuse protection.

## Decision

- **Shared counters in PostgreSQL.** `abuse_counters` is an UNLOGGED table, keyed by scope and a 32-byte digest. It is reached only through `abuse_hit(scope, key, limit, window_s, block_s)` and `abuse_blocked(scope, key)`. Both are SECURITY DEFINER with a pinned search_path, and both run on the database clock, so every replica shares one clock. The lockout starts on the limit-th event, as in the in-process limiter.
- **A dedicated login.** Role `serk_abuse` may execute those two functions only. It has no table privileges and no tenant data. The production login is `serk_ratelimit`, configured as `SERK_ABUSE_DSN`.
- **No raw identifiers stored.** Keys are HMAC-SHA256(`SERK_ABUSE_KEY`, scope ‖ 0 ‖ client key). The key is at least 32 bytes and must differ from the tenant and approval secrets.
- **Production requires it.** The configuration refuses production without `SERK_ABUSE_DSN` and `SERK_ABUSE_KEY`, or with only one of them.
- **Failure mode.** Every event is also counted locally. If the shared store errors, or does not answer within 250 ms, the replica decides with its local limiter and increments `serk_abuse_store_errors_total{scope}`. That counter fires the `SerkAbuseLimitsDegraded` alert. The alternatives are worse:
  - failing open would turn a database incident into unlimited credential stuffing;
  - failing closed would turn it into an outage for every client.
- **Why UNLOGGED.** Counters are disposable. A crash resets them, which relaxes limits for at most one window. UNLOGGED keeps the counters out of WAL, replicas and backups.

## Consequences

- Each pre-authentication request costs up to two small database calls on a separate pool: the lockout check and the budget hit. An authenticated request adds a third, for the principal budget.
- The application limiter does not stop volumetric attacks. Edge limits at the proxy or WAF are still required and are not configured or load-tested here (no staging). GATEA-10 stays PARTIAL.
- A replica restart does not reset shared lockouts.

## Tests

- `TestSharedAbuse_LockoutAndBudgetsSpanReplicas`. Two or three API servers share one store, and the lockout, the pre-authentication budget and the principal budget are each enforced once across them. A control case with per-process replicas shows the original defect.
- `TestSharedAbuse_StoresDigestsOnly`, `TestSharedAbuse_RolePrivileges`, and `TestSharedAbuse_StoreFailureFallsBackToLocalLimits`.
- `TestPrivileges_CatalogInvariants`, which covers serk_abuse, and `TestProductionRequiresSharedAbuseLimits`.

## Addendum: independent review 9 (2026-10-22)

- **IPv6 (R9-F6).** An IPv6 client is counted per /64. A host usually controls a whole /64, so rotating addresses inside it no longer resets its budget or its lockout. IPv4 addresses still count individually.
- **Load (R9-I4, open).** Under thousands of concurrent calls, most shared-store calls exceeded the 250 ms timeout, and replicas fell back to their local limits. Pool sizing and the timeout need a load test on staging infrastructure.
