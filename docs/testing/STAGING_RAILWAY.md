# Railway staging deployment: evidence (2026-10-25)

TEST ENVIRONMENT ONLY. Synthetic data. The release decision stays NO-GO
(`docs/release/GO_NO_GO.md`); nothing here is a production deployment or a
human sign-off.

## Deployed

| Item | Value |
|---|---|
| Railway project | `serk-construction-staging`, environment `staging` |
| Services | `serk-staging` (deploy/railway/Dockerfile), `Postgres` (Railway template, **PostgreSQL 18**) |
| Source | GitHub `Egziu/Serk-construction`, branch `main` |
| URL | `https://serk-staging-staging.up.railway.app/console/` |
| First deployment | `1748285c-…` at commit `2f851b3`: status SUCCESS (Railway `/readyz` health check passed) |

Deploy log of that deployment (Railway): migrations 0001–0037 applied as
`serk_owner`, deploy/02 applied, `serk-seed: synthetic tenant seeded`
(tenant `b00ca2e9-…`, projects P-001 and P-002), `signer listening`, API
listening on :8080 with `STAGING persona sign-in enabled`. No database
posture warning was logged.

## Tests executed

- Full race suite, Go 1.26.10 / PostgreSQL 16, fresh database
  `serk_full38b`: **360 PASS, 0 FAIL, 0 SKIP**
  (`evidence/full-suite-railway-staging-fresh-db.txt`). A first run on
  `serk_full38` failed 10 tests that connect as password-less test logins:
  the rebuilt local cluster used scram authentication for 127.0.0.1. With the
  disposable cluster's local `trust` restored, all passed. No code change.
- New tests: `TestStagingLoginConfig` (refused in production, with OIDC,
  without tenant, short or reused passphrase), `TestStagingLoginDisabledByDefault`,
  `TestStagingLoginIssuesPersonaTokens` (wrong passphrase 401, unknown
  persona 422, token verifies with the right tenant, scope and MFA claims,
  passphrase guessing locked out with 429).
- Local simulation of the Railway container (same entrypoint, fresh
  database, PostgreSQL 16): first boot and a restart (seed idempotent);
  `scripts/staging_smoke.py`: BOQ create, self-approval refused 403,
  approval by another persona through the isolated signer, PR create,
  submit, approval through the signer, auditor read: all PASS. Console
  persona sign-in checked in Chromium with no page errors; this found and
  fixed a pre-existing layout fault (signed-out page squeezed into the
  hidden navigation column). Console browser journeys A, B, C, planning
  and site re-run after the fix: PASS.

## Not verified here (open)

- The smoke script was **not** run against the Railway URL: this agent's
  network cannot reach `*.up.railway.app`. Run
  `python3 scripts/staging_smoke.py https://serk-staging-staging.up.railway.app <passphrase>`.
- Railway's database is PostgreSQL 18; the suite ran on 16. Migrations and
  the seed succeeded on 18, but the adversarial suite has not run on 18.
- Everything listed in `deploy/railway/README.md` under "Differences from
  production" remains a production blocker.
