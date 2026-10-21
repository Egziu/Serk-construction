# Security and supply-chain evidence (GATEA-12 and related)

Every row cites an artifact that exists in this repository. "BLOCKED" means the check needs something this environment does not have. The blocker is named, and nothing was simulated in its place.

## 1. Executed in this environment

| Control | Result | Evidence |
|---|---|---|
| `gofmt -l .` empty, `go vet ./...` clean | PASS | `docs/audit/evidence/final-test-run.log` (refreshed at packaging) |
| Full test suite, `-race`, against PostgreSQL 16.15 | PASS | same |
| `go mod verify` (module cache vs `go.sum`) | PASS | `evidence/supply-chain-local-2026-10-21.txt` |
| SBOM: CycloneDX 1.5 of the modules **compiled into binaries or tests** (`go list -deps -test`), with `go.sum` h1 hashes | PASS, 9 components | `evidence/sbom-local.cdx.json` |
| License review of the build list | PASS: MIT and BSD only, no copyleft | `evidence/supply-chain-local-2026-10-21.txt` |
| Secret scan of tracked files: private keys, cloud and GitHub/Slack/Stripe tokens, credentialed DSNs, long secret assignments | PASS, after explicit allow-listing of documented dev-only and CI-throwaway values and of `/run/secrets` paths | same |
| Database privilege invariants (catalog and live attempts) | PASS | `docs/security/DB_PRIVILEGE_MATRIX.md`, `TestPrivileges_*` |
| Adversarial approval-provenance suite, before and after the fix; independent review and fixes | PASS after fix | `docs/security/ADVERSARIAL_RESULTS.md` |

**Caveat on `go mod verify`.** It checks the module cache against `go.sum`. For the four modules whose `go.sum` lines were derived from source mirrors in an environment without sumdb access (`x/crypto`, `x/sync`, `x/text`, `yaml.v3`), see `docs/audit/evidence/SC-12-gosum-provenance.json`. The check is therefore circular. It proves consistency, not authenticity. Authenticity comes only from the sum.golang.org comparison below.

## 2. BLOCKED here (no network to proxy.golang.org, sum.golang.org or vuln.go.dev)

Probed on 2026-10-21: those three hosts were unreachable (connection refused by the sandbox egress allowlist).

| Control | Where it runs | Status |
|---|---|---|
| Cold-cache dependency resolution; `go.sum` reconciliation against sum.golang.org (closes SC-12's four unverified hashes) | `.github/workflows/ci.yml` job `supply-chain` | **BLOCKED / NOT RUN.** The workflow exists but has never executed; no CI runner is available to this delivery. |
| `govulncheck` | same job | **BLOCKED / NOT RUN** |
| CycloneDX via `cyclonedx-gomod` with licenses | same job | NOT RUN (the local SBOM above is the stand-in) |
| SAST beyond `go vet`, container and IaC scanning, dependency review | not yet configured | **NOT IMPLEMENTED** |
| Signed build provenance (SLSA), signed release artifacts, immutable image digests | not yet configured | **NOT IMPLEMENTED** |
| GitHub Actions SHA pins | pinned in `ci.yml` (resolved with `git ls-remote` in an earlier session) | pinned. The pins have **not** been re-verified in this session. |

## 3. Standards mapping (status, not certification)

This mapping records where each control lives. It is **not** a claim of compliance with any of these standards.

- OWASP ASVS 5.0:
  - V8 (authorization) maps to the attestation boundary and RLS;
  - V7 (session management) maps to the revocation list (GATEA-07);
  - V16 (security logging) maps to the structured logs, trace ids and security events.
- NIST SSDF SP 800-218:
  - PS.3 (archive and protect each release) maps to the bundle, SHA256SUMS and SBOM;
  - PW.7 (review code) maps to the independent reviews;
  - PW.8 (test executable code) maps to the adversarial suites;
  - RV.1 (identify vulnerabilities) maps to govulncheck, which is **BLOCKED**.
