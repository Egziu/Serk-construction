# Baseline verification of v0.4.0 (2026-10-22)

Executed in this environment against the artifacts supplied with the v0.4 engineering order.

| Check | Result |
|---|---|
| `sha256sum source.zip history.bundle` vs `ORIGINAL_SHA256SUMS.txt` | match (`76268ff4…`, `ac6c88e2…`) |
| `git bundle verify history.bundle` | OK, complete history; heads `remediation/gate-a` = f868352, tag `v0.4.0-journey-a` → f868352 (source commit a3a3c4d) |
| ZIP file list vs `git ls-tree -r v0.4.0-journey-a` | identical, 200 files |
| ZIP content vs tag, byte by byte (`cmp`) | 0 differences |
| Working tree before changes | clean (`git status` empty) |
| Checklist CSV hash difference | explained: `0a150594…` is the blank template uploaded with the first directive; `424e8c48…` is the generated checklist (see ISSUE_REGISTER IA-040-MANIFEST) |
| Baseline test claim (205 PASS) | reproduced on this runner at a3a3c4d before this checkpoint (`docs/testing/evidence/full-suite.log` of v0.4.0); after the IA-040-01 fix: 209 PASS, 0 FAIL, 0 SKIP |

Limitation: this verification and these test runs were performed by the same engineering agent that wrote the code. They are not an independent reproduction on a trusted CI runner (GATEA-12 remains BLOCKED).
