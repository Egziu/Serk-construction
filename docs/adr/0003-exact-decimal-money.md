# ADR 0003 — Exact decimal arithmetic via shopspring/decimal; NUMERIC in PostgreSQL

**Status:** Accepted · 2026-10-20

## Context
LAW 06 forbids floating point for authoritative money. Currency scales differ
(UGX 0, ETB 2, TND 3). FX rates need up to 12 significant decimals.

## Decision
`pkg/money.Money` wraps `decimal.Decimal` and is always quantised to the
currency's minor units under a named rounding policy (HALF_EVEN default for
postings, HALF_UP default for tax). Amounts cross the pgx boundary as text and
are stored as `numeric(24,6)`; rates as `numeric(24,12)`. Allocation uses the
largest-remainder method so splits sum exactly.

## Consequences
+ 0.1 + 0.2 = 0.3; reproducible rounding; policies recorded on results.
− Slightly more verbose code than native numbers; acceptable for a ledger.
