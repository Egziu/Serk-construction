# ADR 0010: One document visibility policy; bank account numbers masked except for an audited reveal

Status: accepted. It fixes IA-040-01, reported by the independent assessment of v0.4.0. Date: 2026-10-22.

## Context

v0.4.0 decided P2P document visibility in three places that disagreed:

- **List** (`ListP2PDocs`) used the principal's effective scope (`auth.ScopeOf`) and hid entity-level finance documents from project-scoped readers.
- **Detail** (`loadDocRead`) checked project scope only for project documents. Any `p2p.read` holder could fetch a payment instruction, a P2P policy or a company bank account by ID.
- **Mutation** (`loadDoc`) used `Has(scope.tenant_wide)`, not `ScopeOf`. A finance role restricted to a project list was still treated as tenant-wide for entity-level documents.

Detail responses also returned the raw `to_jsonb` row. That exposed full supplier and company bank account numbers, both on bank-account documents and inside the payee section of a payment instruction.

All of this was reproduced against PostgreSQL in `docs/security/evidence/ia-040-01-before.txt`. Five project-restricted principals read the entity-level documents by ID, a project-restricted finance manager passed the mutation scope check, the errors disclosed whether a document existed, and four responses carried full account numbers.

## Decision

1. **One policy.** `kernel.canSee` (in `internal/kernel/docscope.go`) is used by list (through `listScope`, applied inside the SQL query before `LIMIT`), by detail, by every mutation (through `visibleDoc`) and by the bank-detail reveal:
   - Project documents require the document's project to be in the principal's effective scope.
   - The supplier master (code, name, tax ID) is visible to any `p2p.read` holder, because project roles must recognise their suppliers.
   - Supplier bank accounts are visible with tenant-wide scope or with `supplier.manage` (the procurement officers who enter them). They are always masked.
   - Every other entity-level document (payment instructions, P2P policies, company bank accounts, bank statements, and any future type) requires tenant-wide scope.
   - Tenant-wide means `auth.ScopeOf`: the `scope.tenant_wide` entitlement **and** no project restriction.
2. **No existence disclosure.** An out-of-scope document returns exactly the same not-found error as a nonexistent one, in the kernel and over HTTP.
3. **Allowlisted read projections.**
   - Documents carrying bank details (supplier and company bank accounts, payment instructions including their payee) are returned through explicit field allowlists.
   - Account numbers appear only as `account_number_masked` (`****6789`), and the payee fingerprint `bank_snapshot` is not returned.
   - Every other document type passes through a scrubber that masks any `account_number` field, as defence in depth.
   - List labels already carried only the last four digits.
4. **Privileged reveal.** The full number is available only through `RevealBankAccount` (`POST /v1/p2p/{type}/{id}/reveal-bank-details`). It requires:
   - the new permission `bank.details.reveal`, held by `finance_manager` and `cfo`;
   - an MFA-fresh session (step-up, RFC 9470 challenge);
   - a stated purpose of at least 20 characters;
   - the same visibility policy as every other read.

   Each reveal writes an audit record and an outbox event containing the masked number, the purpose and the MFA time. They never contain the number itself.
5. **No leakage on the side.** Errors, logs and events do not carry full account numbers or bearer tokens. This is tested at the API level against the captured server log.

## Consequences

- A site engineer, storekeeper or project manager can no longer list or open supplier bank accounts. The console hides those screens from them; procurement and finance keep access.
- A finance user restricted to a project list is no longer treated as tenant-wide for payments and policies. A role with a project list is project-scoped everywhere (SC-05).
- New document types are tenant-wide-only by default (fail closed) until `docProject` and `canSee` say otherwise.
- **Not solved at this layer.** The tenant database runtime credential can still read `account_number` directly. That credential belongs to the API process itself (threat model T-3 and R-SIGNER). Column-level encryption or a separate vault for bank details is a recorded follow-up (R-BANK-AT-REST).

## Tests

- **Kernel** (`internal/kernel/ia04001_test.go` and `ia04001_reveal_test.go`):
  - five restricted principals denied each entity-level document by known ID;
  - list/detail parity;
  - nonexistent and out-of-scope IDs indistinguishable;
  - mutation scope;
  - masking for finance and procurement;
  - the reveal refused without the permission, without fresh MFA, without a purpose, and out of scope;
  - the reveal audited, with no number in the outbox.
- **HTTP** (`internal/httpapi/ia04001_api_test.go`): the same at the API boundary, including 404 parity, an error body that does not echo the number, and a server log free of numbers and tokens.
- **Browser** (`TestConsoleBrowserJourneyA`): a site engineer opening a payment by ID sees "Not found"; the finance manager sees `****6789` and performs an audited reveal.
- Evidence: `docs/security/evidence/ia-040-01-before.txt` (19 EXPOSED results) and `ia-040-01-after.txt` (0).

## Addendum: independent review 5 (2026-10-22)

The review (`docs/security/INDEPENDENT_REVIEW_5_2026-10-22.md`) found that the policy was not yet applied everywhere. Changes made in response:

- **Tenant-wide is decided in one place** (`Service.tenantWide`, which is `auth.ScopeOf(p).TenantWide`). Payment preparation, statement import, auto-reconciliation, the GL reconciliation, the journal worklist and `whoami` used `Has(scope.tenant_wide)` and now use it (F1).
- **Visibility before locks.** `visibleDoc` checks the type, resolves the project and applies `canSee` before `SELECT … FOR UPDATE`, so an out-of-scope caller never waits on a lock (F2).
- **Journals** read, approved or posted out of scope return not-found, like documents (F5).
- **Keyed digests instead of numbers in hashes (migration 0017).**
  - `p2p_account_digest` is an HMAC keyed with the tenant's approval key. It replaces the account number in `p2p_subject_text` (approval subject hashes) and `p2p_bank_snapshot` (payee fingerprints), so neither confirms a guessed number offline (F4).
  - It is the only `SECURITY DEFINER` function in the P2P schema. It is needed to read the owner-only key, has a pinned `search_path`, no `PUBLIC` execute and a read-only body; TestR3_11 asserts all three.
- **Reveal hardening.**
  - Requires `p2p.read` and tenant-wide scope (F6).
  - The purpose is 20–500 characters, counted as runes.
  - Refused attempts are audited as `bank.details.reveal_refused` (F7).
- **Masking.** `MaskAccount` shows at most four characters and never more than a third of the number, behind a fixed `****`. The supplier-bank audit uses it (F8).
- **Ids.** HTTP path ids must be canonical lowercase UUIDs; any other spelling is 404 before the kernel (F9).
- **Accepted residual (F3).**
  - A duplicate company account number is still refused, so a `bankacct.manage` holder can tell a right guess from a wrong one by registering it.
  - The refusal now returns the same generic invalid-input error as any other bad input and is audited as `bankacct.register_refused`. Each wrong guess leaves a PENDING account that a second person must approve.
  - Removing the oracle completely (uniqueness on a keyed digest, numbers out of the runtime credential's reach) belongs to R-BANK-AT-REST.


## Addendum (2026-10-22, migration 0035, independent review 10, R10-F4)

The 0017 keyed digest was computed **in the database** with the tenant's approval key. Any holder of the tenant credential could therefore call `p2p_account_digest()` as an offline oracle: 100,000 guesses took 1.75 s and recovered a full account number from its digest and last four digits. Changes:
- The digest is now computed in the API: `datakey.Digest`, HKDF + HMAC-SHA-256 under `SERK_BANK_DIGEST_KEY`, prefix `hkey:`. The database never holds that key.
- The database function is revoked from every runtime role, and new `hmac:` digests are refused.
- `serk-migrate encrypt-bank-accounts` re-digests the remaining rows. The posture check reports any that are left.
- Residual (R10-I4): the database cannot check that a digest matches its ciphertext. Only the API writes both, and encrypted details are immutable.
