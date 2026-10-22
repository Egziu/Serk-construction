# Checkpoint 0.5.0: IA-040-01, Journey B, governed AI, supply chain

Order §13 format. Decision: **NO-GO** (`GO_NO_GO.md`, `GATE_STATUS.json`).

- Nothing has been deployed.
- No real funds, banks or external systems were touched.
- No security testing was done outside disposable local databases.
- The delivering agent cannot sign or authorise a release.

## 1. Baseline

- Starting point: tag `v0.4.0-journey-a` (`a3a3c4d`, `f868352`). Verified against the supplied ZIP and bundle: 200/200 files identical (`BASELINE_VERIFICATION_0.4.0.md`).
- This checkpoint is tag `v0.5.0-journey-b`; the exact commit is in `GATE_STATUS.json` (`source_commit`).

## 2. Source changes and migrations

| Commit | Content |
|---|---|
| `0dcf5d3` | **IA-040-01 (HIGH).** One visibility policy for list, detail, mutation and reveal; masked bank data; audited MFA reveal (ADR 0010). |
| `b23778d` | **R-SPLIT-SUPPLIER.** 0016: supplier-level exposure for dual payment approval. |
| `14a9af9` | **Review 5 fixes.** 0017: keyed bank digests, one tenant-wide rule, lock-free visibility. |
| `f29ebd8` | **Journey B kernel and API.** 0018 contract to cash; 0019 human-only decisions. |
| `297ab8f` | **Journey B console and browser E2E.** |
| `5d614e9` | **Order deliverables.** Inventory, dependency map, feature matrix, remediation register, threat model. |
| `38ce1a1` | **Supply chain.** Go 1.26.10, pgx 5.9.2, x/text 0.43.0, x/sync 0.24.0. |
| `b97220a` | **Review 6 fixes.** 0020. |

All migrations (0016–0020) are additive. No released or committed migration file was edited.

## 3. Modules implemented and connected

**Journey B:** contract policy → customer → contract → measurement → IPC → customer invoice → receipt from a money-in statement line → `AR_*` journals → AR, retention and advance reconciliation, bank reconciliation, project profitability.

- Connected to the same ledger, attestation, visibility and bank-statement machinery as Journey A.
- Delivered at all levels: database, kernel, API (`ar_handlers.go`) and console (Revenue section).

The domain status of the whole product is in `docs/baseline/V040_INVENTORY.md`: 30 domains, of which 10 are implemented, 10 partial and 10 absent.

## 4. Security findings

**Corrected, with executed before/after evidence**

| Finding | Severity | Evidence |
|---|---|---|
| IA-040-01 | High | 19 exposures before, 0 after |
| Review 5: F1, F2, F4–F9 | Medium/Low | F3 accepted residual |
| JB-AI-DECISIONS | High | Found while building: AI-kind principals could approve every non-payment decision; fixed in 0019 |
| SUPPLY-VULN-01 | High | 50 advisories in imported packages → 0 |
| Review 6: R6-F1 to F8 | 4 Medium, 2 Low, 2 Info | |
| JB-RECEIPT-BANK-RECON, JB-F9-REST | | |

**Remaining**

| Item | Status |
|---|---|
| R-SIGNER | High, open |
| R-BANKFEED | High, open |
| R-MFA-SOURCE | Real IdP step-up not integrated |
| R-BANK-AT-REST | Medium |
| R5-F3 | Accepted residual; needs a human risk owner |
| JB-CREDIT-NOTE | Medium, open |
| SUPPLY-ORIGIN-01 | Official sumdb/govulncheck blocked here |

The register (`REMEDIATION_REGISTER.yaml`, 92 items, 19 open) is generated from `docs/audit/ISSUE_REGISTER.md`.

## 5. Tests executed (actual results)

- **Full race suite** on Go 1.26.10 and PostgreSQL 16.15:
  - command: `SERK_TEST_ADMIN_DSN=<disposable> go test -race -count=1 -p 1 -v ./...`;
  - result: 243 top-level PASS, 0 FAIL, 0 SKIP, all 13 packages ok;
  - log: `docs/testing/evidence/full-suite-r6-fixes.txt`.
- **Both browser journeys ran**, with Playwright and Chromium:
  - Journey A: 15 people;
  - Journey B: 11 people and 12 audited pages, in light and dark themes and at 390 px.
- **Independent AI reviews 5 and 6.** Their probes are kept as regression tests: `TestR5_*` and `TestR6_*`.

## 6. Financial reconciliation evidence

Journey B (`docs/testing/E2E_JOURNEY_B.md`):

| Item | Value |
|---|---|
| IPC 1 amount due | 4,691,000 |
| IPC 2 amount due | 3,663,000 |
| AR | 1,663,000 |
| Retention | 432,000 |
| Advance | 0 |
| VAT output | −1,146,000 |
| Revenue on the project | −8,640,000 |
| Bank | 7,691,000 |

- Every AR check and the bank check show a difference of 0.
- Journey A reconciliations are unchanged (GRNI, AP and in-transit 0).

## 7. Release blockers

**Gate status** (`GATE_STATUS.json`): 11 PASS, 6 BLOCKED, 3 PARTIAL, 15 NOT TESTED.

| Gate | Status | Why |
|---|---|---|
| A | not passed | Real IdP step-up, isolated signer, staging with TLS and vault, distributed abuse protection, OTel and alerts, official supply-chain checks |
| B, D, E, F | not passed | Partial or not built |
| C | PASS | Only on AI-verified evidence, with no human finance sign-off |
| P | not passed | Pentest, load, legal, tax and data sign-off, GO/NO-GO: all require named humans |

## 8. Next executable action

**Journey C, stock valuation (GATEB-05):**

1. Stock items, warehouses, put-away from confirmed GRNs.
2. FIFO and WAC issues to project cost codes (`STK_*` journals).
3. Counts and adjustments with maker/checker.
4. Inventory-to-GL reconciliation.

**Then:** customer credit notes (JB-CREDIT-NOTE), variations and retention release.
