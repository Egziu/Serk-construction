# Railway staging (TEST ENVIRONMENT, SYNTHETIC DATA)

This deploys SERK Construction to Railway **for testing only**. It is not a
production deployment and does not change the release decision (NO-GO,
`docs/release/GO_NO_GO.md`). Do not enter real people, suppliers, bank
accounts or money.

## What runs

One Railway service built from `deploy/railway/Dockerfile` (`railway.json`),
plus a Railway PostgreSQL service. `entrypoint.sh` on every start:

1. creates the platform roles (`deploy/00-roles.sql`) and a **non-superuser**
   schema owner `serk_owner` (`deploy/01-schema-owner.sql`), and sets the
   login passwords from variables;
2. runs `serk-migrate` as `serk_owner`;
3. applies `deploy/02-restrict-advisory-locks.sql` as the administrator;
4. runs `serk-seed` (idempotent) for one synthetic tenant: legal entity, two
   projects, fiscal periods to 2027, a chart of accounts, approved WBS and
   cost codes, approved P2P and contract policies, suppliers, a customer,
   stock items, project stores and a company bank account, every approval
   made by a distinct synthetic person through the kernel;
5. starts `serk-signer` on a unix socket and then `serk-api` **without** the
   approval signing key (the isolated-signer arrangement used in production,
   inside one container because Railway services cannot share a socket).

## Differences from production (why this is not production)

| Production requirement | This staging |
|---|---|
| OIDC identity provider with MFA and back-channel logout | HS256 tokens from the **staging persona sign-in** (`/staging/*`), refused in production by configuration |
| Signer in its own host/container, HSM/KMS key | Same container as the API; key in a Railway variable |
| `sslmode=verify-full` to the database | Railway private network, `sslmode=prefer` |
| Vault-managed secrets, rotation, encrypted PITR offsite backups | Railway variables; no backup policy configured |
| Edge WAF / TLS policy (deploy/Caddyfile, nginx-edge.conf) | Railway edge TLS |
| Metrics listener and alerting | Disabled |

## Variables (service "serk-staging")

Generated per environment, never committed: `SERK_TENANT_DB_SECRET`,
`SERK_APPROVAL_SIGNING_KEY`, `SERK_TOKEN_SECRET`, `SERK_ABUSE_KEY`,
`SERK_BANK_DATA_KEY`, `SERK_BANK_DIGEST_KEY`, `SERK_OWNER_PASSWORD`,
`SERK_HEALTH_PASSWORD`, `SERK_TIMER_PASSWORD`, `SERK_RATELIMIT_PASSWORD`,
`SERK_STAGING_LOGIN_PASSPHRASE`. References: `SERK_ADMIN_DSN=${{Postgres.DATABASE_URL}}`,
`SERK_DB_HOST=${{Postgres.PGHOST}}`, `SERK_DB_PORT=${{Postgres.PGPORT}}`,
`SERK_DB_NAME=${{Postgres.PGDATABASE}}`. Fixed: `SERK_ENV=staging`,
`SERK_SEED_TENANT=<uuid>`, `SERK_TRUSTED_PROXIES` (Railway edge range, optional).

## Testing

Open `https://<domain>/console/`, use **Test environment sign-in**, pick a
persona and enter the staging passphrase. Each persona holds one duty;
switch persona to approve what another prepared. Step-up actions (CFO,
treasury, device registration) need a sign-in made within 10 minutes.

To reset all data: delete and recreate the PostgreSQL service (or its
volume) and redeploy; the entrypoint rebuilds everything.
