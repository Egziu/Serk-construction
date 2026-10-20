# ADR 0004 — Offline devices prepare commands; only the server commits financial state

**Status:** Accepted · 2026-10-20

## Context
LAW 05: financial transactions are never CRDT-merged. Field sites in Tigray and
elsewhere operate for days without connectivity.

## Decision
The kernel exposes idempotent commands keyed by a client-generated
`idempotency_key` plus a canonical command hash. An offline client stores the
command in its operation log and replays it when online; the server returns
the original result for identical replays and refuses key reuse with a
different payload. FX on offline-captured transactions is provisional until the
server selects an approved snapshot at posting time. CRDTs are reserved for
mergeable operational data (daily logs, photos, notes), which the field slice
(NEXT #11) will add.

## Consequences
+ Exactly-once financial effect regardless of retries; no divergent ledgers.
− Offline users see "pending" states until sync; UI must show this clearly.
