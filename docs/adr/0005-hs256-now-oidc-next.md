# ADR 0005 — HS256 tokens behind a TokenVerifier seam; OIDC federation next

**Status:** Accepted (interim) · 2026-10-20

## Context
The spec requires OIDC/OAuth 2.0 with MFA. The vertical slice needs working,
testable authentication without an identity provider in the build sandbox.

## Decision
`internal/httpapi.TokenVerifier` is the only authentication seam. The first
implementation is an HS256 verifier (standard library only, constant-time,
`alg=none` rejected, ≥32-byte secret). A JWKS/RS256 verifier with MFA claim
enforcement replaces it in NEXT #2 without touching handlers or the kernel.

## Consequences
+ Real authentication and authorisation tests today; zero third-party crypto.
− Shared secret must be rotated manually until OIDC lands; not for internet
  exposure beyond pilots.
