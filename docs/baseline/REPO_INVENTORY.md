# Repository inventory

Generated 2026-10-21T21:04:04Z at commit `4547924` by `tools/inventory.sh` from `git ls-files` and the Go toolchain. Nothing in this file is hand-counted.

## Baseline lineage

| Commit | Meaning |
|---|---|
| `ea3533c` | 0.2.0-gate-a as delivered (vulnerable to GATEA-APPROVAL-01) |
| `ff1aeca` | GATEA-APPROVAL-01: adversarial reproduction tests (fail on this commit: forged approvals succeed) |
| `eb8094d` | GATEA-APPROVAL-01: verified approval provenance at the SQL trust boundary |
| `1371d63` | GATEA-06: revoke PUBLIC EXECUTE on all schema functions, pin DEFINER search_path; catalog + live-attempt privilege tests |
| `81ab48b` | Security docs from live evidence; GATEA-09 PITR drill executed |
| `b314922` | GATEA-07 (server side): shared session revocation list checked per request and inside approvals; R-10 default privileges |
| `32a220e` | Independent review of approval attestation: 9 confirmed gaps fixed (0010) |
| `bae7eeb` | GATEA-11: metrics, trace context, DB health via aggregate-only monitor role, alert rules and executed alert drill |
| `8a2948b` | GATEA-12 (offline part): go mod verify, build-list CycloneDX SBOM, license review, secret scan; CI runs the same script |
| `74fb7d4` | Independent re-verification of 0010: 8 open probes closed (0012) |
| `4547924` | Checkpoint: GATE_STATUS.json (generated, evidence-checked), GO_NO_GO (NO-GO), REPO_INVENTORY, ADR 0008, readiness, implementation log, regenerated privilege matrix, final test log (170 PASS) |

## Size

| Kind | Files | Lines |
|---|---|---|
| Go (non-test) | 40 | 10230 |
| Go tests | 35 | 8012 |
| SQL migrations | 12 | 3736 |
| Markdown docs | 31 | 2194 |
| Shell / Python tooling | 5 | 568 |

## Packages

```
github.com/serk-group/serk-construction/cmd/serk-api
github.com/serk-group/serk-construction/cmd/serk-devtoken
github.com/serk-group/serk-construction/cmd/serk-migrate
github.com/serk-group/serk-construction/cmd/serk-relay
github.com/serk-group/serk-construction/internal/config
github.com/serk-group/serk-construction/internal/httpapi
github.com/serk-group/serk-construction/internal/kernel
github.com/serk-group/serk-construction/internal/obs
github.com/serk-group/serk-construction/internal/relay
github.com/serk-group/serk-construction/internal/store/postgres
github.com/serk-group/serk-construction/internal/testdb
github.com/serk-group/serk-construction/pkg/attest
github.com/serk-group/serk-construction/pkg/auth
github.com/serk-group/serk-construction/pkg/evm
github.com/serk-group/serk-construction/pkg/fx
github.com/serk-group/serk-construction/pkg/ledger
github.com/serk-group/serk-construction/pkg/money
github.com/serk-group/serk-construction/pkg/tax
github.com/serk-group/serk-construction/pkg/workflow
```

## Migrations (applied in order; released migrations are never rewritten)

| File | sha256 |
|---|---|
| `0001_kernel.sql` | `e71185d828e02d64…` |
| `0002_gate_a_integrity.sql` | `4865a91d680dec74…` |
| `0003_tenant_identity.sql` | `57ee975f8ef03c16…` |
| `0004_outbox_delivery.sql` | `de2d734e012c2542…` |
| `0005_wbs_cost_codes.sql` | `7073fe85bbdda0a2…` |
| `0006_workflow.sql` | `4ff10d718f53a02e…` |
| `0007_approval_attestation.sql` | `a1ad3fd966a9dc23…` |
| `0008_function_least_privilege.sql` | `e6c85f6115d6f7be…` |
| `0009_session_revocation.sql` | `7c289bc317dc3d44…` |
| `0010_attestation_hardening.sql` | `c1bc94f1b47e42dd…` |
| `0011_ops_metrics.sql` | `4439836ab7693b89…` |
| `0012_attestation_hardening_2.sql` | `5703032d30f1ec90…` |

## Tests

Top-level test functions: 170. Last full run: `docs/audit/evidence/final-test-run.log`.

## Direct dependencies

```
require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.2
	github.com/shopspring/decimal v1.4.0
)
require (
```
