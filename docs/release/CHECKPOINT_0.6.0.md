# Checkpoint 0.6.0: Journey C, AR completion, variations, planning, shared abuse limits, reviews 7–9

Order §13 format. Decision: **NO-GO** (`GO_NO_GO.md`, `GATE_STATUS.json`).

- Nothing has been deployed.
- No real funds, banks or external systems were touched.
- No security testing was done outside disposable local databases.
- All data is synthetic.
- The delivering agent cannot sign or authorise a release.
- "AI-verified" below means checked by executed tests and by independent *AI* reviewers. It is not a human sign-off.

## 1. Baseline

- Starting point: tag `v0.5.0-journey-b`. The order's source ZIP was verified against it in checkpoint 0.5.0.
- This checkpoint is tag `v0.6.0-planning`. The exact commit is in `GATE_STATUS.json` (`source_commit`).

## 2. Source changes and migrations

| Commit | Migration | Content |
|---|---|---|
| `067e08d` | 0021 | **Journey C, stock valuation.** Stock items, warehouses, put-away from GRNs, FIFO/WAC issues to project cost codes, counts with maker-checker, inventory-to-GL reconciliation (ADR 0012). |
| `cc82225` | 0022 | **Customer credit notes** (JB-CREDIT-NOTE). |
| `03014e1` | 0023 | **Retention release.** |
| `9f66087` | 0024 | **Review 7 corrections** (stock valuation). |
| `8caddaa` | 0025 | **Stock transfers** between warehouses, with FIFO layers preserved. |
| `fa7ac3a` | 0026 | **Contract variations** (change orders). |
| `5b3663c` | 0027 | **Planning.** CPM schedule versions, baselines, progress, earned value (ADR 0013). |
| `cab78c3` | 0028 | **Review 8 corrections**: AR dates, posture check, PO line item designation. |
| `11dcff3` | 0029 | **Abuse limits shared across API replicas** (ADR 0014). |
| `652464d` | 0030 | **Review 9 corrections**: budget rule, EVM, CPM checks, IPv6 limits, designation, variation lines. |

All migrations 0021–0030 are additive. No committed migration file was edited.

## 3. Modules implemented and connected

- **Journey C:** purchase order → GRN → put-away (only on a line whose stock item a procurement approver has designated) → FIFO/WAC layers → transfer → issue to a project cost code (`STK_ISSUE`) → count adjustment (`STK_ADJUST`) → inventory, stock-balance and GL reconciliation. It shares Journey A's ledger, attestation and visibility machinery, and runs at database, kernel, API and console level.
- **Journey B, completed:** credit notes and retention release, both with dates checked against an open period, and variations that change effective contract quantities and revised contract value.
- **Planning:** CPM computed in Go and re-verified by the database, a maker-checker baseline, progress reports, and EVM (BAC, PV, EV, AC, SPI, CPI). Console pages: schedule, progress and earned value.
- **Platform:** pre-authentication and per-principal limits shared by all replicas.
- **Domain status** (`docs/baseline/V040_INVENTORY.md`): 30 domains, of which 11 are implemented, 12 partial and 7 absent.
  - Absent: site operations and offline capture, equipment, HR and payroll, QHSE, document and drawing control, BIM/IFC, analytics and executive reporting.
  - Partial, among others: multi-entity finance and consolidation, tax and localisation, governed AI (human-only decisions enforced; no AI component).

## 4. Security findings

**Corrected (AI-verified; awaiting independent human review)**

| Source | Findings | Notes |
|---|---|---|
| Review 7 (0021) | 4 Medium, 5 Low, 1 Info | Fixed in 0024. R7-F4 was superseded twice, by 0028 and then 0030. |
| Review 8 (0022–0025) | 3 Medium, 5 Low, 2 Info | Fixed in 0028, except R8-F5 (below). |
| Review 9 (0026–0029) | 3 Medium, 5 Low, 4 Info | Fixed in 0030 and the kernel, except R9-I4 (below). |
| Found while building | GATEA-10 | Per-replica limits are replaced by shared limits. |

**Remaining (open or needing a human decision)**

| Item | Status |
|---|---|
| R-SIGNER | High, open. The approval signing key is in the API process; an isolated HSM/KMS signer is needed. |
| R-MFA-SOURCE / GATEA-02, -07 | Blocked: no real IdP with step-up and back-channel logout. |
| GATEA-12 / SUPPLY-ORIGIN-01 | Blocked: sum.golang.org and vuln.go.dev are unreachable here. |
| R-BANKFEED, R-BANK-AT-REST | Open: no bank-signed feed, no column encryption. |
| R8-F5 | **Acceptance proposed, not in force.** Credit-note VAT is rounded per note. A named human tax/finance risk owner must accept it. |
| R5-F3 | Accepted residual; a named human risk owner is needed. |
| JC-BUDGET-ORIGIN | Open, Low. Cross-code stock consumption is counted on both codes. This is conservative: purchases are refused, never overspent. The CFO override is the interim relief. |
| R9-I4 | Open, Info. Under very high concurrency the shared limiter falls back to per-replica limits, as designed. Needs a staging load test. |
| R7-F9 residual | The trigger-depth guard relies on a clean posture, which production enforces at start-up. The root fix, SECURITY DEFINER stock writers, is not built. |
| JC-INVOICE-REVALUE, JB-CREDIT-QTY | Open, Low. |
| Not re-reviewed | The 0030 corrections have not had an independent re-review. |

`REMEDIATION_REGISTER.yaml` holds 132 items: 22 open and 2 accepted-residual, each needing a human owner. It is generated from `docs/audit/ISSUE_REGISTER.md`.

## 5. Tests executed (actual results)

- **Full race suite** on Go 1.26.10 and PostgreSQL 16, on fresh disposable databases (`go test -race -count=1 -p 1 -v ./...`):

  | Point | Database | Result | Log |
  |---|---|---|---|
  | After review 8 fixes | `serk_full28` | 291 PASS, 0 FAIL, 0 SKIP | `docs/testing/evidence/full-suite-review8-fixes-fresh-db.txt` |
  | After shared abuse limits | `serk_full29` | 296 PASS, 0 FAIL, 0 SKIP | `docs/testing/evidence/full-suite-abuse-fresh-db.txt` |
  | After review 9 fixes | `serk_full30b` | **308 PASS, 0 FAIL, 0 SKIP** | `docs/testing/evidence/full-suite-review9-fixes-fresh-db.txt` |

  - An intermediate run on `serk_full30` had 2 failures. Both were fixed before the `serk_full30b` run; see the review 9 resolution.
- **Browser journeys** (Playwright, Chromium) passed in every full run: A, B, C (including designation by the procurement manager and a transfer) and planning. Each audited pages for accessibility, and the runs include phone width (390 px) and dark theme.
- **Independent AI reviews 7, 8 and 9.** Their probes are kept as regression tests: `TestR7_*`, `TestR8_*` (16), `TestR9_*` (12). The probe output from before the fixes is in `docs/testing/evidence/`.

## 6. Financial reconciliation evidence

**Journey C** (`docs/testing/E2E_JOURNEY_C.md`)

| Item | Value |
|---|---|
| GL inventory | 922,550 |
| Stock + not yet put away | 875,050 + 47,500 = 922,550 |
| Project cost posted | 1,423,450 |
| Count surplus (5 bags at the last receipt cost 950) | 4,750 |

- Inventory vs GL, balances vs documents, FIFO layers vs balances, and stock balances vs GL all show a difference of 0.
- **Transfers:** moved at cost with no residue, through six fractional transfers and 21 fractional issues. Closing stock, layers, documents and GL are all 0.

**Journey B with credits and releases.** After partial payment, an exact credit, a release and a receipt: GL AR 0, retention 0, contract position open 0, and every AR reconciliation row 0.

**Budget** (`p2p_cost_position`, 0030):

| Case | Result |
|---|---|
| Order, receipt, put-away and a 10 t issue to the ordering code | Available unchanged; the cost is counted once. |
| A 5 t surplus issued to the code | Charged: 422,500. |
| A third purchase after put-away | Refused by the gate. |
| An 8,281,000 count shortage | Stays charged through the commitment. |

**Planning** (textbook network, `docs/testing/E2E_PLANNING.md`)

| Measure | Value |
|---|---|
| Finish | 2026-10-19 |
| BAC | 6,500,000 |
| PV | 4,700,000 |
| EV | 3,850,000 |
| SV | −850,000 |
| SPI | 0.8191 |

An independent hand computation matched, including SS/FF lags and holidays.

## 7. Release blockers

**Gate status** (`GATE_STATUS.json`): 12 PASS, 5 PARTIAL, 5 BLOCKED, 13 NOT TESTED.

| Gate | Status | Why |
|---|---|---|
| A | not passed | IdP step-up and revocation, isolated signer, staging with TLS and vault, OTel/Prometheus, official supply-chain checks, legacy data; edge abuse limits and multi-host load |
| B | not passed | Claims and daywork, manual accessibility audit, canonical entities |
| C | PASS (AI-verified) | No human finance sign-off |
| D, E | not passed | Field/offline, equipment, QHSE, documents/BIM, payroll and multi-entity are not built |
| F | not passed | No AI component built yet; decisions are human-only in Go and SQL |
| P | not passed | Pentest, load/soak, signed finance, tax, legal and data policies, and GO/NO-GO: all need named humans |

## 8. Next executable action

1. Independent re-review of migration 0030.
2. **Site and offline field capture (GATED-01):**
   - device-bound offline drafts with idempotent sync;
   - duplicate and conflict handling;
   - revocation of lost devices.

   Field capture covers daily site diaries, labour and equipment hours, and progress measurements submitted as drafts that a human approves.
3. Then equipment and job cost (GATED-03), and QHSE (GATED-04).
