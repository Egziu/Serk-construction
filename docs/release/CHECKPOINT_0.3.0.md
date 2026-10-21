# Checkpoint 0.3.0-gate-a-hardening (directive §13 format)

## 1. Baseline commit and worktree status

- **Input:** 0.2.0-gate-a at `ea3533c`. Its zip, bundle and SHA256SUMS were verified when the 0.2.0 package was produced.
- **This checkpoint:** tag `v0.3.0-gate-a-hardening` at `0e36a34`, with a clean worktree (`git status` empty).
- **Lineage:** `docs/baseline/REPO_INVENTORY.md` (generated).

## 2. Files created or modified (responsibility)

| Path | Responsibility |
|---|---|
| `internal/store/postgres/migrations/0007_approval_attestation.sql` | Attestation verification, evidence table and `*_attest` triggers |
| `internal/store/postgres/migrations/0010_attestation_hardening.sql` | Single-use evidence, authority-column freeze, decisions in `ctx`, deferred successor checks, definition digest, strict shape, wall-clock expiry (review 1) |
| `internal/store/postgres/migrations/0012_attestation_hardening_2.sql` | fx_snapshot freeze, history binding, trigger-only `approval_use`, lookup by attested fields, SQL `body_hash` (review 2) |
| `internal/store/postgres/migrations/0008_function_least_privilege.sql` | No PUBLIC EXECUTE; pinned `search_path` |
| `internal/store/postgres/migrations/0009_session_revocation.sql` | Revocation list; global default privileges |
| `internal/store/postgres/migrations/0011_ops_metrics.sql` | `serk_monitor` role; aggregate-only `ops_health_metrics()` |
| `pkg/attest/` | Attestation format, signer, verifier |
| `internal/kernel/{kernel,period,fx,wbs,workflow,sessions}.go` | Signing every authority transition; session checks; revocation and logout |
| `internal/httpapi/server.go` | Revocation middleware (fail closed), identity endpoints, metrics, trace context |
| `internal/obs/` | Prometheus exposition, DB health collector, W3C traceparent |
| `internal/config/`, `cmd/serk-api`, `cmd/serk-migrate`, `deploy/*` | Approval signing key, metrics listener, monitor DSN, roles |
| `deploy/drills/pitr_drill.sh` | Executable PITR drill |
| `deploy/observability/prometheus-alerts.yml` | Alert rules |
| `scripts/supply_chain_local.sh`, `.github/workflows/ci.yml` | Offline supply-chain checks; CI |
| `tools/gate_status.py`, `tools/inventory.sh` | Generated release status and inventory |
| Tests: `approval_provenance_test.go`, `approval_attestation_test.go`, `attestation_review_test.go`, `attestation_reverify_test.go`, `privilege_test.go`, `sessions_test.go`, `session_api_test.go`, `metrics_drill_test.go`, `obs_test.go` | Adversarial, positive and drill tests |
| `docs/security/*`, `docs/operations/*`, `docs/release/*`, `docs/adr/0008-*` | Evidence-backed documentation |

## 3. Defects reproduced and fixed, with residual risk

- **GATEA-APPROVAL-01 (Critical).** Reproduced on `ea3533c`: 6 forgeries succeeded. Fixed in 0007, 0010 and 0012.
- **Independent review 1:** 2 High, 4 Medium, 3 Low. All fixed.
- **Independent review 2:** 2 Medium, 3 Low. All fixed.
- **Own findings:** R-08 (memo edit), R-09 (cross-tenant hash in definer context), R-10 (no-op default privileges), and two unpinned `search_path` functions. All fixed.
- **Residual:** R-SIGNER (High), R-MFA-SOURCE (High), R-DBA (Medium), R-MAKER (Medium), IR-L2 (Low). See `docs/security/APPROVAL_ATTESTATION_DESIGN.md` §3.

## 4. Migrations and compatibility

- **Additive only.** 0007–0012 are new; no released migration was edited.
- **Compatibility:**
  - Workflow definitions stored before 0012 keep their Go-canonical hash, which is accepted on load.
  - `fiscal_period_closes.attestation` is NULL for legacy rows.
  - Existing tenants need their approval key installed: `serk-migrate provision-tenant` is idempotent and does this.
- **Configuration:**
  - **New required:** `SERK_APPROVAL_SIGNING_KEY`.
  - **New optional:** `SERK_METRICS_LISTEN`, `SERK_MONITOR_DSN`.
- **New cluster roles:** `serk_monitor`, `serk_metrics`.

## 5. Real tests

All of the following were **independently executed** in this environment; nothing is reported second-hand.

| Command | Environment | Result | Artifact |
|---|---|---|---|
| `go test -race -count=1 -p 1 -v ./...` | Go 1.24.7, PostgreSQL 16.15, fresh DB | PASS: 170 top-level tests, 0 FAIL, 0 SKIP | `docs/audit/evidence/final-test-run.log` |
| `go test ./internal/kernel -run 'ApprovalProvenance' -v` on `ea3533c` | same | FAIL as intended: 6 attacks succeed | `docs/security/evidence/approval-forgery-before.txt` |
| same suite after the fix | same | PASS: 40 denials | `approval-forgery-after.txt` |
| Reviewer 1 probes, before and after 0010 | same | 11 GAP lines before → 0 after | `independent-review-{before,after}.txt` |
| Reviewer 2 probes, before and after 0012 | same | 8 OPEN lines before → 0 after | `independent-reverify-{before,after}.txt` |
| `deploy/drills/pitr_drill.sh` | disposable cluster | PASS: exact restore; RTO 0.9 s; RPO 6 s | `docs/operations/evidence/pitr-drill-2026-10-21.txt` |
| Alert drill | fresh DB | PASS: 8 of 8 expected alerts; none on baseline | `docs/operations/evidence/alert-drill-2026-10-21.txt` |
| `scripts/supply_chain_local.sh` | offline | PASS for the offline part | `docs/release/evidence/supply-chain-local-2026-10-21.txt` |
| Mutation runs M1–M11 | same | all killed except M9, which is equivalent | IMPLEMENTATION_LOG §11 |

**About the reviews.** "Independent" means separate AI review agents with no authorship of the reviewed migration. They are **not** human sign-off.

## 6. Domain flows delivered end to end

None new in this checkpoint. By the directive's instruction this phase was security first. Journey A starts next.

## 7. Gate status and remaining critical/high issues

- **Gate A: NOT PASSED** (6 PASS / 6 BLOCKED / 1 NOT TESTED). Gates B–F: NOT TESTED. Gate P: NOT TESTED. **Decision: NO-GO.**
- **Source:** `docs/release/GATE_STATUS.json`.
- **Open High:**
  - R-SIGNER;
  - R-MFA-SOURCE;
  - GATEA-12: sumdb and govulncheck never run.

## 8. Safety constraints and deployment authorization

- **No deployment of any kind:** no production credentials, no payment commands, no live data.
- **No AI principal holds authority:** none exists, and the database accepts only attestations signed for authenticated human sessions.
- **Deployment authorization: NONE.**

## 9. Next executable task

Phase 1, Journey A, in the existing branch:

- **New entities:**
  - supplier master, with bank-detail change control;
  - versioned BOQ, approved as the project budget baseline;
  - PR → RFQ, with technical and commercial evaluation and award, → PO, each with budget and commitment checks;
  - GRN with partial deliveries;
  - supplier invoice with 3-way match and tolerances;
  - payment instruction, maker/checker with MFA and no execution;
  - bank statement import and auto-reconciliation.
- **Accounting:** each document generates a GL journal through the attested kernel. Results are reconciled in a project cost report against the GL.
- **Tests:** an E2E test through the HTTP API on PostgreSQL 16 (GATEB-02/03/04, GATEC-01).
