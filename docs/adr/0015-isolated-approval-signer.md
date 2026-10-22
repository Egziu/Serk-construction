# ADR 0015: Isolated approval signer

Status: accepted by the delivering team (2026-10-22); awaiting human review. Closes the process-isolation half of R-SIGNER; the HSM/KMS half stays open.

## Context

Approval attestations (ADR for migration 0007) are HMAC-signed by the API with a master secret. PostgreSQL verifies them with per-tenant derived keys that no application login can read. The weakness (R-SIGNER, High): whoever controls the API process or its configuration holds the master and can sign an approval for any actor, any action, with MFA asserted.

## Decision

- **A separate process, `serk-signer`, holds the secret.** In production the API's configuration refuses `SERK_APPROVAL_SIGNING_KEY` and requires `SERK_SIGNER_SOCKET`. The API's kernel issues attestations through `attest.Remote`; the in-process `attest.Signer` remains for development and tests.
- **The signer verifies the person, not the API.** Each request carries the person's own bearer token, which the API's middleware stores in the request context. The signer verifies it against the same identity provider the API uses and signs only claims that token supports:
  - tenant and actor are the token's;
  - `auth_time` equals the token's; MFA is claimed only if the token carries a fresh multi-factor login;
  - every permission is one the token's roles grant, plus `principal.human` only for a principal the IdP asserted human;
  - a decision (non-draft action) is signed only for a human principal.
- **The API checks what comes back.** `attest.Remote` refuses an attestation whose claims differ from what it sent, so a signer cannot widen them.
- **Transport is a unix socket** (mode 0660) on a volume shared by the two containers. The signer has no network listener and no database. The socket's file permission is the access control.
- **Every issuance and refusal is logged by the signer**, outside the API, with tenant, actor, action, subject and nonce. Metrics: `serk_signer_issued_total{kind}`, `serk_signer_refusals_total{reason}`.
- **Per-actor issuance rate limit** (default 120/min) bounds abuse of a stolen session.
- **`Keyring` abstracts the key.** `FileKeyring` holds the master in memory. An HSM/KMS keyring would keep the secret out of the process; it is not available here.
- Tenant provisioning (`serk-migrate provision-tenant`) still derives the per-tenant verification key from the master; it is an operator-side process, run with the secret and never resident.

## What this closes and what it does not

- Closed: a compromised API process, image or configuration cannot sign for people who are not logged in, cannot assert MFA a token lacks, cannot grant permissions a role lacks, and cannot sign a decision for a non-human principal.
- Not closed: while a person is logged in, a compromised API can obtain signatures in that person's name for the lifetime of their token. The signer cannot distinguish a forwarded request from a genuine one. Mitigations: short token lifetimes, the issuance log and the rate limit.
- Not closed: whoever controls the signer process or its secret controls approvals. That is the HSM/KMS half of R-SIGNER (blocked: no such service here).

## Tests

- `TestSignerIsolation_JournalLifecycleThroughRemoteSigner`: create, approve and post through the remote signer, with the issuance log.
- `TestSignerIsolation_CompromisedAPICannotForge`: ten forged claim shapes refused on the socket, and the one legitimate human MFA decision signed.
- `TestSignerIsolation_NoBearerNoSignature`, `TestSignerIsolation_APIWithoutSecretFailsClosed`.
- `TestSignerConfig`, `TestProductionRefusesWeakConfig` (key in the API refused), `TestProductionManifestKeepsSigningKeyOutOfTheAPI`.


## Addendum (2026-10-22, migration 0035, independent review 10)

Review 10 showed that the signer, which has no database, could not enforce two things the API enforces: the token's **project scope** (R10-F1) and **session revocation** (R10-F2). A compromised API could obtain and use signatures for projects outside the token and for revoked sessions.

- The signed perms now carry platform markers derived from the token by `auth.Authorizer.ScopeMarkers`:
  - `principal.scope:tenant`, or one `principal.project:<id>` per listed project;
  - `principal.session:<jti or ->`;
  - `principal.iat:<unix or 0>`.
- The signer accepts only markers the token grants, and requires the session and iat markers to equal the token's.
- The database checks them in `approval_authorize()`:
  - exactly one session marker and one iat marker;
  - `session_is_revoked()`, where an unknown issue time counts as revoked if an actor-wide cut-off exists;
  - the subject's project (`serk_subject_project()`, the kernel's `docProject` mapping) against the scope markers.
- The DB check means a leaked tenant key (or a compromised signer) still cannot approve outside the markers it signs. But whoever holds the key can sign any markers. The HSM/KMS half of R-SIGNER remains the control for that.
- `attest.Remote` now compares the signer's response field by field (R10-F6).
- Tests: `TestR10_SignerIgnoresProjectScope`, `TestR10_SignerIgnoresRevocation`, `TestAttestationMarkers_DatabaseEnforcesSessionAndScope`, `TestR10_RemoteComparesPermsByLengthOnly`.
