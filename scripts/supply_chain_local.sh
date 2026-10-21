#!/usr/bin/env bash
# SERK Construction — supply-chain checks that can run WITHOUT network access
# (GATEA-12, partial). Produces, under $OUT (default ./supply-chain-out):
#   go-mod-verify.txt   `go mod verify` against the module cache
#   sbom.cdx.json       CycloneDX 1.5 SBOM of the actual build list (go list -m)
#   licenses.txt        license file detected per module (from the module cache)
#   secret-scan.txt     pattern scan of tracked files for committed secrets
#   summary.txt         pass/fail per check
#
# What this script CANNOT do (needs network; run in CI): cold-cache resolution
# against proxy.golang.org, go.sum reconciliation with sum.golang.org,
# govulncheck (vuln.go.dev), container/IaC scanning, signed provenance.
set -uo pipefail
OUT=${OUT:-supply-chain-out}
mkdir -p "$OUT"
fail=0
say() { printf '%-28s %s\n' "$1" "$2" | tee -a "$OUT/summary.txt"; }
: >"$OUT/summary.txt"

# 1. go mod verify -----------------------------------------------------------
if go mod verify >"$OUT/go-mod-verify.txt" 2>&1; then
  say "go mod verify" "PASS ($(tail -1 "$OUT/go-mod-verify.txt"))"
else
  say "go mod verify" "FAIL (see go-mod-verify.txt)"; fail=1
fi

# 2. SBOM ---------------------------------------------------------------------
# The modules whose packages are compiled into the binaries or the tests
# (go list -deps -test), i.e. what actually ships or runs; `go list -m all`
# would also list graph-only modules that are never built.
go list -deps -test -f '{{with .Module}}{"Path":"{{.Path}}","Version":"{{.Version}}","Main":{{.Main}},"Dir":"{{.Dir}}"}{{end}}' ./... 2>"$OUT/modules.err" \
  | sort -u >"$OUT/modules.json" || { say "sbom" "FAIL (go list)"; fail=1; }
python3 -I - "$OUT/modules.json" go.sum "$(git rev-parse HEAD 2>/dev/null || echo unknown)" >"$OUT/sbom.cdx.json" <<'PY'
import json, sys, uuid, datetime
mods_path, sum_path, commit = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(mods_path).read()
dec, i, mods = json.JSONDecoder(), 0, []
while i < len(raw):
    while i < len(raw) and raw[i].isspace(): i += 1
    if i >= len(raw): break
    obj, i = dec.raw_decode(raw, i)
    mods.append(obj)
sums = {}
for line in open(sum_path):
    p = line.split()
    if len(p) == 3 and not p[1].endswith("/go.mod"):
        sums[(p[0], p[1])] = p[2]
main = next(m for m in mods if m.get("Main"))
comps = []
for m in mods:
    if m.get("Main"): continue
    c = {"type": "library", "bom-ref": f"pkg:golang/{m['Path']}@{m['Version']}", "name": m["Path"], "version": m["Version"],
         "purl": f"pkg:golang/{m['Path']}@{m['Version']}", "scope": "required" if not m.get("Indirect") else "optional"}
    h = sums.get((m["Path"], m["Version"]))
    if h:  # go.sum h1: is base64 SHA-256 of the module's dirhash
        c["properties"] = [{"name": "golang:go.sum:h1", "value": h}]
    comps.append(c)
bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
       "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "tools": [{"name": "scripts/supply_chain_local.sh"}],
                    "component": {"type": "application", "name": main["Path"], "version": commit,
                                  "bom-ref": f"pkg:golang/{main['Path']}@{commit}"}},
       "components": sorted(comps, key=lambda c: c["name"])}
print(json.dumps(bom, indent=1))
PY
n=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["components"]))' "$OUT/sbom.cdx.json" 2>/dev/null || echo 0)
[[ $n -gt 0 ]] && say "sbom (CycloneDX 1.5)" "PASS ($n components)" || { say "sbom" "FAIL"; fail=1; }

# 3. Licenses -----------------------------------------------------------------
: >"$OUT/licenses.txt"
python3 -I - "$OUT/modules.json" >>"$OUT/licenses.txt" <<'PY'
import json, os, re, sys
raw = open(sys.argv[1]).read(); dec, i = json.JSONDecoder(), 0
kinds = [("Apache-2.0", r"Apache License,?\s+Version 2\.0"), ("MIT", r"Permission is hereby granted, free of charge"),
         ("BSD-3-Clause", r"Neither the name of"), ("BSD-2-Clause", r"Redistributions in binary form must reproduce"),
         ("MPL-2.0", r"Mozilla Public License,? v(ersion)?\.? ?2\.0"), ("ISC", r"Permission to use, copy, modify, and/or distribute"),
         ("GPL", r"GNU GENERAL PUBLIC LICENSE"), ("LGPL", r"GNU LESSER GENERAL PUBLIC LICENSE"), ("AGPL", r"GNU AFFERO")]
while i < len(raw):
    while i < len(raw) and raw[i].isspace(): i += 1
    if i >= len(raw): break
    m, i = dec.raw_decode(raw, i)
    if m.get("Main"): continue
    d, found = m.get("Dir"), "NOT IN CACHE (not needed by the build)"
    if d and os.path.isdir(d):
        found = "NO LICENSE FILE FOUND"
        for f in sorted(os.listdir(d)):
            if re.match(r"(?i)^(licen[cs]e|copying)", f):
                txt = open(os.path.join(d, f), errors="replace").read()
                hits = [k for k, rx in kinds if re.search(rx, txt)]
                found = f"{f}: {', '.join(hits) or 'UNRECOGNISED'}"
                break
    print(f"{m['Path']}@{m['Version']}  {found}")
PY
if grep -qE "GPL|AGPL|UNRECOGNISED|NO LICENSE" "$OUT/licenses.txt"; then
  say "license review" "ATTENTION (copyleft/unknown present; see licenses.txt)"
else
  say "license review" "PASS (permissive only, for modules in the build)"
fi

# 4. Secret scan ----------------------------------------------------------------
# Patterns for credentials that must never be committed. Test fixtures and
# documented dev-only values are allow-listed explicitly, by file and value.
git ls-files -z | xargs -0 grep -nIE \
  -e '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'gh[pousr]_[A-Za-z0-9]{36,}' \
  -e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
  -e 'sk_live_[A-Za-z0-9]{20,}' \
  -e '(?i)postgres(ql)?://[^:/ ]+:[^@/ ]{8,}@' \
  -e '(SECRET|PASSWORD|TOKEN|SIGNING_KEY)[A-Z_]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9+/=_-]{24,}' \
  2>/dev/null | grep -vE '^(internal/.*_test\.go|deploy/docker-compose\.dev\.yml|deploy/01-dev-passwords\.sql|docs/|scripts/supply_chain_local\.sh):' \
  | grep -vE 'dev-only-|ci-only-throwaway-password|_FILE: /run/secrets/' \
  >"$OUT/secret-scan.txt" || true
if [[ -s $OUT/secret-scan.txt ]]; then
  say "secret scan" "FAIL ($(wc -l <"$OUT/secret-scan.txt") finding(s); see secret-scan.txt)"; fail=1
else
  say "secret scan" "PASS (no findings outside allow-listed test/dev fixtures)"
fi

say "cold-cache / sumdb / govulncheck" "BLOCKED here (no network); run .github/workflows/ci.yml"
exit $fail
