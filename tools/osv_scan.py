#!/usr/bin/env python3
"""Module-level vulnerability scan against the Go vulnerability database's
source data (github.com/golang/vulndb, data/osv/*.json).

For the Go toolchain version in use (standard library) and every module in the
build list (`go list -m all`), report each non-withdrawn advisory whose
affected SEMVER ranges include that version. For each hit, report whether any
affected package is imported by this repository's packages (`go list -deps`),
which approximates govulncheck's package-level analysis. govulncheck itself
also checks whether vulnerable *symbols* are reachable; this script does not,
so it errs towards false positives, never towards silence.

Usage: python3 tools/osv_scan.py <path to a vulndb checkout>
Exit status 1 if any advisory affects an imported package.
"""
import glob, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db = sys.argv[1]

def sv(v):
    v = v.lstrip("v").split("+")[0]
    main, _, pre = v.partition("-")
    nums = [int(x) for x in (main.split(".") + ["0", "0"])[:3]]
    return (nums, pre == "", pre)  # a pre-release sorts before its release

def cmp(a, b):
    A, B = sv(a), sv(b)
    if A[0] != B[0]:
        return -1 if A[0] < B[0] else 1
    if A[1] != B[1]:
        return -1 if not A[1] else 1
    return (A[2] > B[2]) - (A[2] < B[2])

def affected(version, ranges):
    for r in ranges:
        if r.get("type") != "SEMVER":
            continue
        intro, hit = None, False
        for e in r.get("events", []):  # events are ordered
            if "introduced" in e:
                intro = e["introduced"]
                if intro == "0" or cmp(version, intro) >= 0:
                    hit = True
            if "fixed" in e and hit and cmp(version, e["fixed"]) >= 0:
                hit = False
        if hit:
            return True
    return False

run = lambda *a: subprocess.check_output(a, cwd=ROOT, text=True)
gover = re.search(r"go(\d+\.\d+(?:\.\d+)?)", run("go", "version")).group(1)
mods = {"stdlib": gover, "toolchain": gover}
# Modules that supply at least one compiled package (incl. tests). Offline,
# `go list -m all` cannot load the full graph; these are the modules whose
# code can actually be in a binary or a test.
for line in run("go", "list", "-deps", "-test", "-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", "./...").splitlines():
    p = line.split()
    if len(p) == 2:
        mods[p[0]] = p[1]
imported = set(run("go", "list", "-deps", "-test", "./...").split())

hits, scanned = [], 0
for f in sorted(glob.glob(os.path.join(db, "data/osv/*.json"))):
    o = json.load(open(f))
    scanned += 1
    if o.get("withdrawn"):
        continue
    for a in o.get("affected", []):
        name = a.get("package", {}).get("name")
        if name not in mods or not affected(mods[name], a.get("ranges", [])):
            continue
        pkgs = [i.get("path") for i in a.get("ecosystem_specific", {}).get("imports", [])]
        used = sorted(p for p in pkgs if p in imported) if pkgs else ["(whole module)"] if name not in ("stdlib", "toolchain") else []
        hits.append((o["id"], name, mods[name], used, pkgs, o.get("summary", "")))

commit = subprocess.check_output(["git", "-C", db, "log", "-1", "--format=%H %cI"], text=True).strip()
print(f"vulndb source: github.com/golang/vulndb @ {commit}; {scanned} advisories scanned")
print(f"build list: go{gover} (stdlib/toolchain) + {len(mods) - 2} modules supplying packages: {', '.join(f'{m}@{v}' for m, v in sorted(mods.items()) if m not in ('stdlib', 'toolchain'))}")
print(f"{len(imported)} packages imported (incl. tests)")
used_hits = [h for h in hits if h[3]]
for h in hits:
    tag = "IMPORTED" if h[3] else "not imported"
    print(f"{tag:12} {h[0]} {h[1]}@{h[2]} affected packages: {', '.join(h[4]) or 'module'}; imported: {', '.join(h[3]) or '-'}; {h[5]}")
print(f"\n{len(hits)} advisories affect versions in the build list; {len(used_hits)} affect packages this repository imports.")
sys.exit(1 if used_hits else 0)
