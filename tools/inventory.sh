#!/usr/bin/env bash
# Regenerates docs/baseline/REPO_INVENTORY.md from git and the Go toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."
count() { # label, git pathspecs..., [--exclude regex via EXCL env]
  local label=$1; shift
  local files; files=$(git ls-files -- "$@" | { if [[ -n ${EXCL:-} ]]; then grep -vE "$EXCL" || true; else cat; fi; })
  local n l; n=$(printf '%s\n' "$files" | grep -c . || true); l=$(printf '%s\n' "$files" | grep . | xargs -r cat | wc -l)
  echo "| $label | $n | $l |"
}
{
echo "# Repository inventory"
echo
echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) at commit \`$(git rev-parse --short HEAD)\` by \`tools/inventory.sh\` from \`git ls-files\` and the Go toolchain. Nothing in this file is hand-counted."
echo
echo "## Baseline lineage"
echo
echo "| Commit | Meaning |"
echo "|---|---|"
echo "| \`ea3533c\` | 0.2.0-gate-a as delivered (vulnerable to GATEA-APPROVAL-01) |"
git log --reverse --format='| `%h` | %s |' ea3533c..HEAD
echo
echo "## Size"
echo
echo "| Kind | Files | Lines |"
echo "|---|---|---|"
EXCL='_test\.go$' count "Go (non-test)" '*.go'
count "Go tests" '*_test.go'
count "SQL migrations" 'internal/store/postgres/migrations/*.sql'
count "Markdown docs" '*.md'
count "Shell / Python tooling" '*.sh' '*.py'
echo
echo "## Packages"
echo
echo '```'
go list ./...
echo '```'
echo
echo "## Migrations (applied in order; released migrations are never rewritten)"
echo
echo "| File | sha256 |"
echo "|---|---|"
for f in internal/store/postgres/migrations/*.sql; do echo "| \`$(basename "$f")\` | \`$(sha256sum "$f" | cut -c1-16)…\` |"; done
echo
echo "## Tests"
echo
echo "Top-level test functions: $(git ls-files -- '*_test.go' | xargs grep -h '^func Test' | wc -l). Last full run: \`docs/audit/evidence/final-test-run.log\`."
echo
echo "## Direct dependencies"
echo
echo '```'
sed -n '/^require (/,/^)/p' go.mod | head -6
echo '```'
} > docs/baseline/REPO_INVENTORY.md
