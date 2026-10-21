# Checkpoint 0.4.0: Journey A (procure-to-pay), API, console and hardening

Directive §13 format. Decision: **NO-GO** (see `GO_NO_GO.md`). Nothing has been deployed. The agent cannot sign or authorise a release.

## 1. Baseline

- Baseline: `v0.3.0-gate-a-hardening`, then `a1f337c` (Journey A kernel and migration 0013).
- This checkpoint is tag `v0.4.0-journey-a`; the commit hash is in `docs/release/GATE_STATUS.json` (`source_commit`).
- The worktree was clean at commit; the full-suite evidence was produced on the same tree.

## 2. Files created and modified

**Database**
- `migrations/0014_p2p_hardening.sql`, which fixes review 3.
- `migrations/0015_p2p_hardening_2.sql`, which fixes review 4.
- Both are additive. No released migration was rewritten.

**Kernel** (`internal/kernel/p2p.go`, `kernel.go`)
- Creation attestations in the 6 create commands.
- A strict statement-file parser (`ParseStatement`) and its content digest (`ContentDigest`).
- `ImportBankStatement` now takes the raw file bytes.
- Lists, whoami, reference data and cost codes for the console.
- The `principal.human` marker when signing.

**Auth** (`pkg/auth/auth.go`)
- `Principal.Kind` (IdP `pkind`).
- The reserved `principal.` permission prefix: no role can grant it.
- New `bank_statement_officer` role; treasury no longer imports statements.
- Extended separation-of-duties conflict pairs.

**HTTP** (`internal/httpapi/p2p_handlers.go`, plus `server.go` and `token.go`)
- About 45 Journey A routes, including `GET /v1/identity/me`, `GET /v1/p2p-reference` and `GET /v1/projects/{id}/cost-codes`.
- Routes for the console.

**Console** (`internal/webui/`)
- Embedded and dependency-free, under a strict CSP.
- The access token is held in memory only.
- Worklists per role, document views with actions, forms for every Journey A step, the journal batch screen, bank import and reconciliation, and reports.

**Store** (`internal/store/postgres/p2prepo.go`)
- Project scope moved inside the list query (before `LIMIT`).
- Bank-statement worklist and reference data.

**Tests**
- `internal/httpapi/journey_a_api_test.go` and `console_browser_test.go`.
- `e2e/console_journey_a.mjs`.
- `internal/kernel/review3_regression_test.go`, `review4_regression_test.go` and `statement_parse_test.go`.
- Updated Journey A tests.

**Docs**
- ADR 0009.
- `docs/workflows/PROCESS_CATALOG.md` and `docs/testing/E2E_JOURNEY_A.md`.
- Independent reviews 3 and 4 with before/after evidence.
- The issue register, the regenerated privilege matrix (0001–0015), the GO/NO-GO record, and the gate status JSON and CSV.

## 3. Defects, fixes and residual risk

**Review 3** (independent AI agent, of a1f337c)
- 2 High: forged maker identity on master data; fabricated statement settles a payment.
- 3 Medium: journal tamper after binding; "human-only" checked by user-id regex; PO line posting to the bank GL account.
- 3 Low and 2 Info.
- All are fixed in 0014. All 14 probes now hold.

**Found during remediation**
- R3-X1: a successor policy could change the GRNI/AP accounts. Fixed.
- `ListDocs` applied project scope after `LIMIT`. Fixed.

**Review 4** (independent AI agent, re-verification of 0014)
- 2 Medium: quote lines appendable later without attestation; NULL reconciler bypass.
- 4 Low, 6 Info.
- All are fixed in 0015 except 2 Info items that are recorded as accepted or open. All 9 probes now hold.

**Browser audit defects found and fixed**
- The Sign out button was visible while signed out (CSS overrode `[hidden]`).
- Navigation contrast dropped during a CSS transition.
- "null" text was rendered in document views.

**Residual risks**
- R-BANKFEED, R-SPLIT-SUPPLIER, and collusion between two people.
- R-SIGNER, R-DBA and R-MFA-SOURCE (unchanged).
- R4-I4: canonical user ids from the IdP.

Full list: `docs/audit/ISSUE_REGISTER.md`.

## 4. Migrations and compatibility

- 0014 adds:
  - `journals.created_txid`, which fills existing rows with the migration's txid (fail-closed for any pre-existing P2P draft journal);
  - deferred constraint triggers and replaced function bodies (same signatures; grants kept).
- 0015 adds:
  - a `NOT VALID` `CHECK` on `bank_statement_lines`, so history is not rewritten;
  - column-level INSERT grants on `journals`, replacing the table-level grant.
- API change: `ImportBankStatement` takes the raw file. `POST /v1/bank-statements` takes the statement file as its body, and caller-supplied lines are no longer accepted separately.
- Role change: treasury no longer has `bank.import`.
- Tokens must carry `pkind=human` for payment approval and release. An IdP integration must emit it.

## 5. Tests actually executed

All tests were executed by the agent in this environment.

| Command | Environment | Result | Artifact |
|---|---|---|---|
| `SERK_TEST_ADMIN_DSN=<disposable> go test -race -count=1 -p 1 -timeout 1700s -v ./...` | Go 1.24.7, PostgreSQL 16.15, disposable DB `serk_full`, migrations 0001–0015 | **205 PASS, 0 FAIL, 0 SKIP**, 13 packages | `docs/testing/evidence/full-suite.log` |
| `TestConsoleBrowserJourneyA` (in the run above) | + Node, Playwright 1.56, Chromium 141 | PASS: 15 people, every automated accessibility audit clean | `docs/testing/evidence/console-journey-a.log`, `docs/testing/evidence/console/*.png` |
| Review 3 probes, before | reviewer's copy of a1f337c | 15 OPEN | `docs/security/evidence/independent-review-3-before.txt` |
| Review 3 probes, after (TestR3_*) | full run above | 14/14 PASS, 0 OPEN | `docs/security/evidence/independent-review-3-after.txt` |
| Review 4 probes, before | reviewer's copy with 0014 | 7 of 9 probes FAIL | `docs/security/evidence/independent-review-4-before.txt` |
| Review 4 probes, after (TestR4_*) | full run above | 9/9 PASS, 0 OPEN | `docs/security/evidence/independent-review-4-after.txt` |

**Not executed**
- Staging run.
- Real IdP.
- Bank feed.
- Load or soak testing.
- External pentest.
- Manual accessibility audit.
- CI on a trusted runner.
- Journey B.

## 6. Domain flows delivered

Journey A end to end:
- BOQ baseline;
- requisition with budget check;
- RFQ to 3 suppliers, technical and commercial evaluation, award;
- PO from the award;
- partial goods receipts;
- invoices with three-way match and price variance;
- AP approval;
- batch approve and post of journals;
- payments with dual MFA approval, released by a second officer;
- statement import by an independent officer;
- automatic reconciliation;
- subledger-to-GL reconciliation and the project cost report.

This works at kernel, HTTP and UI level. See `docs/workflows/PROCESS_CATALOG.md`.

## 7. Gate status

See `GATE_STATUS.json`.

**Gate A: NOT PASSED.** It has 6 PASS, 6 BLOCKED (IdP, staging, edge, observability, network supply chain) and 1 NOT TESTED.

**Gates B and C: NOT PASSED overall**, with these items:
- GATEB-02, GATEB-03, GATEB-04 and GATEC-01: PASS on executed evidence and two AI reviews, with no human sign-off.
- GATEB-07: PARTIAL.
- The other B and C items: NOT TESTED.

**Gates D, E, F and P:** not started or require humans.

**Critical/High issues open:** none from the reviews. Open High items are the platform risks R-SIGNER, R-MFA-SOURCE and GATEA-12.

## 8. Safety constraints and deployment authorization

- No deployment, no production credentials, no live data and no payment commands. Synthetic data only, on disposable databases.
- No AI principal can approve, release or post; payment authority additionally needs the IdP-asserted human marker.
- **Deployment authorization: NONE.** Production deployment and live financial operations require explicit authorization and independent human sign-off.

## 9. Next executable engineering task

**Journey B: measurement → IPC → AR → receipt** (GATEC-02)
- Migration 0016: contracts, BOQ-linked measurement sheets, IPC certification with retention and advance recovery, customer invoices and AR, receipts matched from the bank statement. Receipt matching reuses the reconciliation engine; customer receipts are currently left unmatched with the reason "money in: receipts are reconciled in Journey B".
- Kernel commands, API and console screens.
- An end-to-end test at three levels.
- An independent review.
