# Checkpoint 0.7.0: audit actions, isolated signer, bank data at rest, signed offsite backups, reviews 10–12, site operations and offline capture

Order §13 format. Decision: **NO-GO** (`GO_NO_GO.md`, `GATE_STATUS.json`).

- Nothing has been deployed.
- No real funds, banks or external systems were touched.
- No security testing was done outside disposable local databases.
- All data is synthetic.
- The delivering agent cannot sign or authorise a release.
- "AI-verified" below means checked by executed tests and by independent *AI* reviewers. It is not a human sign-off.

## 1. Baseline

- Starting point: tag `v0.6.0-planning`. The independent engineering audit of v0.5.0/v0.6.0 is the input to this checkpoint.
- This checkpoint is tag `v0.7.0-site`. The exact commit is in `GATE_STATUS.json` (`source_commit`).

## 2. Source changes and migrations

| Commit | Migration | Content |
|---|---|---|
| `fa48c8a` | 0031, 0032 | **Isolated approval signer** (`serk-signer`, unix socket, re-verifies the person's token; ADR 0015). **Stock state written only by definer functions** (R7-F9 root fix). **Bank account numbers encrypted at rest** (AES-256-GCM in the API, bound to row and tenant). **Encrypted offsite PITR drill.** |
| `8027230` | 0033 | **Quantity-correction credit notes**: an over-certified quantity is credited and netted out of later certificates. Invoice-variance policy. **Legacy data validation tooling** (`serk-import validate`, `serk-migrate validate-constraints`). |
| `2e0c9a2` | 0034 | **Non-superuser schema owner** (managed PostgreSQL): `owner_maintenance` policies; edge proxy draft; key custody runbook (ADR 0016). |
| `de5810d` | 0035 | **Review 10 corrections.** Signed scope and session markers on every attestation, enforced by the signer and by `approval_authorize()`. `pg_temp` pinned last. Bank digest keyed by the API. Owner without inherited platform roles. Ed25519-signed offsite objects. |
| `888e629` | 0036 | **Review 11 corrections.** Posture check works through the health role (the harness now uses a real health login). Approval scope fails closed. `search_path` pinned on every function. Drill v2: system identifier and plaintext digest signed, collisions refused, per-backup names with a signed inventory, verify-and-decrypt of one local copy. |
| this checkpoint | 0037 | **Site operations and offline capture** (GATED-01, ADR 0017): field devices, site diaries and the offline sync API, including the review 12 fixes made before merge. |

All migrations 0031–0037 are additive. No committed migration file was edited. 0037 was changed only before it entered the main line (review 12).

## 3. Modules implemented and connected

**Trust boundary**
- The approval signing key is out of the API process: `serk-signer` signs only claims the person's own token supports.
- Its scope and session markers are re-checked by the database.
- Custody in an HSM/KMS is still open (R-SIGNER custody).

**Bank data**
- Account numbers are ciphertext in the database, exports and backups.
- The uniqueness and approval digest is keyed by the API.
- Revealing a number needs MFA, a stated purpose, and leaves an audit record.

**Backup and recovery**
- Encrypted, signed offsite PITR. Drill v2 PASS: exact restore, forged base and WAL refused, archive collisions refused.
- Production-scale and object-lock storage are open (GATEA-08).

**Journey B**
- Quantity corrections: 60 + 70 − 10 = 120 t is billed once.

**Legacy data**
- Bundle validation and constraint validation with an append-only exception ledger.
- No real legacy data has been seen (GATEA-13 PARTIAL).

**Site operations (new)**
- Field devices: registered with step-up MFA, the secret is shown once, at most 5 active per person, revocable by the owner or security administration.
- Daily site diaries: labour, equipment and notes, with versioned lines and optimistic concurrency.
- An idempotent offline command log with an attested row per command, a bounded sequence and a canonical digest.
- Conflicts are returned, never merged. Temporary failures are retried in order.
- A project manager approves; an AI principal is refused.
- Database, kernel, HTTP API and web console, including a browser journey.
- Not built: the native offline field app (the sync API is what it will use), photos and costing of hours.

**Domain status** (`docs/baseline/V040_INVENTORY.md`):
- Site operations moves from absent to **partial**.
- Absent: equipment, HR and payroll, QHSE, document and drawing control, BIM/IFC, analytics.

## 4. Security findings

**Independent AI reviews in this checkpoint, all corrected and AI-verified; none re-reviewed yet**

| Review | Scope | Findings | Fixed in |
|---|---|---|---|
| 10 | signer, 0031–0034, legacy tooling, offsite drill | 4 Medium, 6 Low, 6 Info (plus R10-P1 High, the non-superuser owner, from the partial run) | 0034, 0035, drill |
| 11 | 0035, markers, drill | **1 High (regression: production could not start)**, 3 Medium, 2 Low, 2 Info | 0036, harness, drill v2 |
| 12 | 0037 site operations | 2 Medium, 5 Low, 3 Info | inside 0037 before merge |

R11-F1 is worth naming. Review 10's fix made the posture check call a function that the health role could not execute. The test harness used the admin connection as its health connection, which hid this. In production the API would have refused to start. The harness now uses a real health-role login.

**Remaining (open or needing a human decision)**

| Item | Status |
|---|---|
| R-SIGNER (custody) | BLOCKED: HSM/KMS and a human key ceremony. |
| R-MFA-SOURCE / GATEA-02, -07 | BLOCKED: no real IdP. |
| GATEA-08, GATEA-11, GATEA-12 | BLOCKED: staging, TLS and vault; OTel; sum.golang.org/vuln.go.dev unreachable. |
| R11-F5 | PARTIAL: deleting the newest offsite inventory or WAL is not detectable from the store. Object lock and monitoring are needed. |
| R10-I1, R10-I2, R10-I4, R12-F9, R12-F10 | Open or accepted-residual (Info), each needing a named human owner. |
| R8-F5, R5-F3, JC-BUDGET-ORIGIN, R9-I4 | Unchanged from 0.6.0. |
| Not re-reviewed | The fixes for reviews 10–12 (0035, 0036, 0037) have not had an independent re-review. |

`REMEDIATION_REGISTER.yaml` is generated from `docs/audit/ISSUE_REGISTER.md`; its header gives the counts.

## 5. Tests executed (actual results)

Full race suite on Go 1.26.10 and PostgreSQL 16, on fresh disposable databases (`go test -race -count=1 -p 1 -v ./...`). From this checkpoint every step is run in **two owner modes**: a non-superuser owner (the managed-database shape) and a superuser owner with `-shuffle=on`.

| Point | Non-superuser owner | Superuser owner, shuffled | Logs |
|---|---|---|---|
| Non-superuser support (0034) | 323 PASS, 0 FAIL, 0 SKIP | 323 PASS, 0 FAIL, 0 SKIP | `docs/testing/evidence/full-suite-{nonsuperuser-owner,superuser-owner-shuffled}-fresh-db.txt` |
| Review 10 fixes (0035) | 339 PASS, 0 FAIL, 0 SKIP | 339 PASS, 0 FAIL, 0 SKIP | `docs/testing/evidence/full-suite-review10-fixes-*.txt` |
| Review 11 fixes (0036) | 345 PASS, 0 FAIL, 0 SKIP | 345 PASS, 0 FAIL, 0 SKIP | `docs/testing/evidence/full-suite-review11-fixes-*.txt` |
| Site operations (0037, with the review 12 fixes) | **357 PASS, 0 FAIL, 0 SKIP** | **357 PASS, 0 FAIL, 0 SKIP** | `docs/testing/evidence/full-suite-site-operations-*.txt` |

- Runs that failed were fixed before the runs recorded above:
  - an order-dependent ledger count under shuffle (review 11 step);
  - three older tests that hand-signed attestations without the new markers (review 10 step).
- Each failure is described in the review documents.
- **Browser journeys** (Playwright, Chromium) pass in every full run: A, B, C, planning and the **new site journey**. Each audits accessibility on every page and includes phone width (390 px) and the dark theme.
- **Drills**: encrypted, signed offsite PITR drill v2 PASS (`docs/operations/evidence/pitr-offsite-signed-drill-v2-2026-10-22.txt`).

## 6. Financial reconciliation evidence

- Unchanged from 0.6.0 for Journeys A, B and C, budget and planning (all reconciliations 0). The suites above re-ran them at every step.
- **Quantity correction** (`TestCreditQuantityCorrection_NoDoubleDeduction`): 60 t certified, a 10 t over-measurement credited, 70 t more measured. The next certificate bills 60 + 70 − 10 = 120 t cumulative, with no double deduction.
- **Restore**: the restored database is fingerprint-identical across 16 tables, with a clean ledger integrity scan and 12 of 12 audit chains verifying.
- Site diaries post nothing (LAW 05).

## 7. Release blockers

**Gate status** (`GATE_STATUS.json`): 12 PASS, 7 PARTIAL, 5 BLOCKED, 11 NOT TESTED (0.6.0: 12, 5, 5, 13).

| Gate | Status | Why |
|---|---|---|
| A | not passed | IdP step-up and revocation; signer key custody (HSM/KMS); staging with TLS and vault; OTel/Prometheus; official supply-chain checks; real legacy data; edge limits and multi-host load |
| B | not passed | Claims and daywork; manual accessibility audit; canonical entities |
| C | PASS (AI-verified) | No human finance sign-off |
| D | not passed | Planning and site operations are PARTIAL (no native field app); equipment and QHSE not built |
| E | not passed | Document control/BIM, payroll and multi-entity not built |
| F | not passed | No AI component built; decisions are human-only in Go and SQL |
| P | not passed | Pentest, load/soak, signed finance/tax/legal/data policies and GO/NO-GO: all need named humans |

## 8. Next executable action

1. Independent re-review of 0035–0037. An AI review can run now; a human review needs named reviewers.
2. Equipment and job cost (GATED-03): equipment register, hours from approved site diaries, maintenance, and cost allocation to project cost codes through DRAFT journals approved by finance.
3. QHSE (GATED-04): inspections, incidents and non-conformance with exception flows.
4. Infrastructure blockers need people and systems the agent does not have: IdP, HSM/KMS, staging, object-lock storage, CI with network access.
