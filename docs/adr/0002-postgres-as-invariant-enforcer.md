# ADR 0002 — PostgreSQL enforces financial invariants, not only Go

**Status:** Accepted · 2026-10-20

## Context
LAW 03 requires integrity at the transaction boundary; application code can be
bypassed by a bug, a migration script, or an operator with SQL access.

## Decision
Every invariant the kernel relies on is implemented twice: in Go for fast,
explainable rejection, and in PostgreSQL (CHECK constraints, deferred
constraint triggers, BEFORE triggers, RLS with FORCE, composite tenant FKs)
so that no code path can commit a violating state. The application role never
holds DELETE on financial tables. The audit chain hash is computed by a
trigger.

## Consequences
+ Adversarial raw-SQL tests prove the database refuses unbalanced, tampered,
  cross-tenant and closed-period writes.
− Logic duplication must be kept in sync; the integration suite is the guard.
