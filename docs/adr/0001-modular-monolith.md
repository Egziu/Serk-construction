# ADR 0001 — Modular monolith for the authoritative core

**Status:** Accepted · 2026-10-20

## Context
The specification (§2.1) requires a deterministic, ACID financial core and
warns against premature microservices. Accounting invariants span accounts,
journals, periods and FX in one transaction.

## Decision
One Go binary (`serk-api`) hosts all authoritative domains as packages with
explicit boundaries (`pkg/<domain>` pure logic, `internal/kernel` commands,
`internal/store/postgres` persistence). Integration is event-driven through
the transactional outbox. Services are extracted only when a measured scaling,
isolation or team-ownership need appears; the AI layer and the outbox relay
are the first planned separate processes.

## Consequences
+ Cross-domain invariants are enforced in one database transaction.
+ Single deployment unit for small contractors; horizontal scaling by replicas.
− Shared release cadence until extraction; mitigated by package-level ownership.
