# Key custody runbook (draft for the human key owners)

Status: written by the delivering team on 2026-10-22. Nothing in it has been executed against production infrastructure, because none exists. Every ceremony below needs named people.

## The keys

| Secret | Held by | Purpose | Derived material |
|---|---|---|---|
| `SERK_APPROVAL_SIGNING_KEY` | `serk-signer` only (and `serk-migrate provision-tenant`, run by an operator) | Signs approval attestations | Per-tenant HMAC keys installed in `approval_keys` (owner-only table) |
| `SERK_BANK_DATA_KEY` (+ `_PREVIOUS` during rotation) | `serk-api` only | Encrypts bank account numbers at rest (0032) | Per-tenant subkeys by HKDF |
| `SERK_BANK_DIGEST_KEY` (0035, R10-F4) | `serk-api` and `serk-migrate encrypt-bank-accounts` only; never the database | Keys the bank-account digest (`hkey:`) used for company-account uniqueness, approval subjects and payment snapshots | Per-tenant subkeys by HKDF |
| Offsite object signing key (Ed25519) | The primary host only (archive process) | Signs every offsite backup object (name and SHA-256) | Public half pinned on recovery hosts out of band |
| `SERK_TENANT_DB_SECRET` | `serk-api`, `serk-migrate` | Derives tenant database passwords | |
| `SERK_ABUSE_KEY` | `serk-api` | Keys the abuse counters | |
| Backup recipient (age X25519) | Public half on the primary; private half offline | Encrypts base backups and WAL | |

None of these may be the same value; the configuration refuses equal values where it can check.

## Custody (to be done)

1. Generate every key inside the vault or HSM, never on a developer machine. `openssl rand -hex 32` on the vault host is the minimum; an HSM-backed keyring behind `signer.Keyring` is the target for the approval key.
2. Record for each key: owner, backup custodian, creation date, rotation date, and where it is mounted (`*_FILE` paths in `deploy/docker-compose.prod.yml`).
3. The backup private key is never on the primary host and never in the same vault policy as the database credentials: a restore needs two people (database operator + key custodian).

## Rotation

- **Bank data key.** Set `SERK_BANK_DATA_KEY` to the new key with a new `SERK_BANK_DATA_KEY_ID`, move the old key to `SERK_BANK_DATA_KEY_PREVIOUS` with its id, restart. Old rows decrypt with the previous key; new rows use the new key. A re-encryption tool for old rows is not built; until it is, the previous key stays configured.
- **Bank digest key.** Not rotated in place: every stored digest, and so every approval subject and payment snapshot that binds one, depends on it. A rotation means re-digesting every row with a tool that does not exist yet. Rows written before 0035 carry a database-computed `hmac:` digest. Run `serk-migrate encrypt-bank-accounts` with `SERK_BANK_DATA_KEY` and `SERK_BANK_DIGEST_KEY` set; it re-digests them. Do this with no bank approval or payment in flight, since those are refused afterwards and must be prepared again. The posture check refuses production start while any `hmac:` row remains.
- **Offsite signing key.** Generate a new Ed25519 key on the primary and pin its public half on the recovery hosts *before* switching. Keep the old public key pinned for the retention period of the objects it signed. Verification must try the keys pinned for the object's date range, never a key read from the offsite store.
- **Approval signing key.** Install a new per-tenant key under a new key id (`approval_key_install`), start the signer with the new master and `SERK_SIGNER_KEY_ID`, then deactivate the old key id. Attestations live at most 5 minutes, so the overlap is short. The first key also keyed the database-computed bank digests of 0017–0034: it must remain installed, `active` or not, until `encrypt-bank-accounts` has re-digested every `hmac:` row (0035).
- **Backup recipient.** Generate a new identity, add its recipient to `archive_command` (age accepts several `-r`), keep the old private key for the retention period of the old backups.

## Evidence this runbook expects

- Vault audit log of key generation and every read.
- The signer's issuance log retained for the audit period.
- A dated restore drill using the offline private key, by the custodian, at least quarterly.
