#!/usr/bin/env python3
"""Independent check of go.sum against the modules' upstream source.

For every module version in go.sum, fetch the repository at that exact tag or
commit from its upstream host (GitHub; golang.org/x modules from the Go team's
official GitHub mirrors), rebuild the module file set the way the go command
does for a direct VCS fetch (`git archive`, minus nested modules and VCS
metadata), compute Go's "h1:" dirhash (SHA-256 over "sha256  path" lines) and
compare it with the go.sum line. Also checks every "/go.mod h1:" line.

This is NOT the official verification (sum.golang.org is a transparency log;
this script trusts the upstream host and the mirror). It is the strongest check
available when the module proxy, checksum database and vulnerability database
are unreachable. Usage: python3 tools/verify_gosum_origin.py <workdir>
"""
import base64, hashlib, io, os, re, subprocess, sys, tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
work = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gosum-origin"
os.makedirs(work, exist_ok=True)

def repo_of(mod):
    m = re.match(r"golang\.org/x/([a-z0-9]+)$", mod)
    if m:
        return f"https://github.com/golang/{m.group(1)}", ""
    if mod == "gopkg.in/yaml.v3":
        return "https://github.com/go-yaml/yaml", ""
    if mod == "gopkg.in/check.v1":
        return "https://github.com/go-check/check", ""
    m = re.match(r"(github\.com/[^/]+/[^/]+)(/v\d+)?$", mod)
    if m:
        return "https://" + m.group(1), (m.group(2) or "").lstrip("/")
    raise SystemExit(f"no upstream mapping for {mod}")

def rev_of(version):
    m = re.search(r"-\d{14}-([0-9a-f]{12})$", version)  # pseudo-version -> commit
    return m.group(1) if m else re.sub(r"\+incompatible$", "", version)

def fetch(url, rev, dest):
    if not os.path.isdir(dest):
        subprocess.run(["git", "init", "-q", dest], check=True)
        subprocess.run(["git", "-C", dest, "remote", "add", "origin", url], check=True)
    if re.fullmatch(r"[0-9a-f]{12}", rev):
        subprocess.run(["git", "-C", dest, "fetch", "-q", "--filter=blob:none", "origin"], check=True)
        full = subprocess.check_output(["git", "-C", dest, "rev-parse", rev + "^{commit}"], text=True).strip()
        return full
    subprocess.run(["git", "-C", dest, "fetch", "-q", "--depth=1", "origin", f"refs/tags/{rev}:refs/tags/{rev}"], check=True)
    return subprocess.check_output(["git", "-C", dest, "rev-parse", rev + "^{commit}"], text=True).strip()

def h1(files):  # files: {name: bytes}
    lines = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
    return "h1:" + base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()

def module_files(dest, commit, subdir, prefix):
    tar = subprocess.check_output(["git", "-C", dest, "archive", "--format=tar", commit])
    tf = tarfile.open(fileobj=io.BytesIO(tar))
    members = [m for m in tf.getmembers() if m.isfile()]
    names = [m.name for m in members]
    base = (subdir + "/") if subdir else ""
    # directories (below the module root) that are other modules
    nested = {os.path.dirname(n) + "/" for n in names if n.endswith("/go.mod") and n.startswith(base) and n != base + "go.mod"}
    out = {}
    for m in members:
        n = m.name
        if not n.startswith(base):
            continue
        rel = n[len(base):]
        if any(n.startswith(d) for d in nested):
            continue
        if re.search(r"(^|/)(\.git|\.hg|\.svn|\.bzr)/", rel):
            continue
        out[prefix + rel] = tf.extractfile(m).read()
    return out

sums = {}
for line in open(os.path.join(ROOT, "go.sum")):
    mod, ver, h = line.split()
    sums[(mod, ver)] = h
results, bad = [], 0
for (mod, ver), want in sorted(sums.items()):
    is_mod = ver.endswith("/go.mod")
    v = ver[:-len("/go.mod")] if is_mod else ver
    url, sub = repo_of(mod)
    dest = os.path.join(work, re.sub(r"[^a-zA-Z0-9]+", "_", url))
    try:
        commit = fetch(url, rev_of(v), dest)
        prefix = f"{mod}@{v}/"
        files = module_files(dest, commit, "", prefix)
        if sub and prefix + "go.mod" not in files:  # major version in a subdirectory
            files = module_files(dest, commit, sub, prefix)
        if is_mod:
            gm = files.get(prefix + "go.mod")
            # The go command hashes go.mod alone under the name "go.mod"
            # (modfetch: dirhash.Hash1([]string{"go.mod"}, ...)).
            if gm is None:  # modules without go.mod get a synthesized one
                gm = f"module {mod}\n".encode()
            got = h1({"go.mod": gm})
        else:
            got = h1(files)
        ok = got == want
    except subprocess.CalledProcessError as e:
        got, ok, commit = f"fetch failed: {e}", False, "-"
    bad += not ok
    results.append(f"{'MATCH   ' if ok else 'MISMATCH'} {mod} {ver} {url}@{commit[:12]} go.sum={want} origin={got}")
print("\n".join(results))
print(f"\n{len(results) - bad} of {len(results)} go.sum lines match the upstream source; {bad} do not.")
sys.exit(1 if bad else 0)
