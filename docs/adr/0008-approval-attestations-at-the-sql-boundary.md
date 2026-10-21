# ADR 0008: Approval authority is proven by signed attestations verified in PostgreSQL

Status: accepted (migrations 0007, 0010 and 0012). Date: 2026-10-21.

## Context

Since 0.1.0, PostgreSQL has been the enforcer of financial invariants (ADR 0002). Approval *identity* was the exception: the SQL layer trusted names written by the caller (`approved_by`, `decided_by`, `mfa=true`). The 0.2.0 Gate A review showed that a leaked tenant database credential could therefore approve, post, publish and close in anyone's name (GATEA-APPROVAL-01, reproduced in `docs/security/evidence/approval-forgery-before.txt`).

## Decision

1. **The API process signs; the database verifies.**
   - The API is the only holder of the master approval secret.
   - For each authority transition, the API signs a short-lived (≤ 5 min), single-use attestation. It is bound to the tenant, actor, action, the live content hash of the subject, the decision context, the actor's permissions, and MFA plus `auth_time`.
   - PostgreSQL holds only the per-tenant derived HMAC key, readable by the owner only. It verifies the attestation in `approval_authorize()` and records it as evidence.
2. **Every authority transition is a trigger that consumes evidence.** The trigger requires that evidence:
   - was recorded in the same transaction;
   - matches exactly;
   - is unexpired and unconsumed;
   - and that the subject still hashes to the attested value.

   Authority columns are frozen outside the transition that sets them. Approval timestamps are database time.
3. **Separation of duties stays in the database.** The existing maker/checker, quorum and workflow guards still run after the attestation check. Tests reach them with genuine attestations, so both layers are exercised.
4. **Evidence is append-only, and its consumption is recorded.** The tenant login can read evidence but cannot write or consume it directly. `approval_use` runs only at trigger depth > 0.

## Consequences

- **Gained.** A compromised tenant database credential no longer grants authority. This is proven by the before/after suites and by two independent reviews, whose probes are kept as regression tests.
- **Cost.** One HMAC verification and one subject-hash query per authority transition. Every new authority-bearing table must add an `*_attest` trigger and a subject-hash branch. The privilege tests flag new grants, not missing triggers, so code review must catch the latter.
- **Not solved** (see `docs/security/APPROVAL_ATTESTATION_DESIGN.md` §3):
  - compromise of the API process or the secret (R-SIGNER);
  - owner or superuser actions (R-DBA);
  - IdP trust (R-MFA-SOURCE).

## Alternatives considered

- **SECURITY DEFINER transition functions as the only write path, with no attestation.** This narrows the surface but still trusts the caller's identity claims.
- **Asymmetric signatures (Ed25519) verified in SQL.** Preferred long term, so the database cannot forge. pgcrypto has no Ed25519 verify, so it needs a vetted extension or a verifier service. Deferred.
- **Verifying JWTs from the IdP directly in SQL.** This would put token parsing and JWKS rotation inside the database. Rejected.
