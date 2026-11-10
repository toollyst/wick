#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Checks that the crates wick builds from git are the crates.io releases
upstream's Cargo.lock uses.

    tools/linux/check-dependency-sources.py CHECKOUTS_DIR [LOCKFILE...]

On Linux the compatibility crates (crates/compat) re-export the original
crate, taken from the release's git tag rather than from crates.io. For every
git dependency in lib/firecracker/Cargo.lock whose name and version upstream's
lockfile (patches/base) takes from crates.io, this downloads the crates.io
package and checks that it was published from the commit wick's lockfile
pins (.cargo_vcs_info.json) and that every packaged file, Cargo.toml.orig
included, is byte for byte the one in cargo's git checkout (CHECKOUTS_DIR,
`$CARGO_HOME/git/checkouts`). Every git dependency in the other LOCKFILEs
(tools/vhost-user-blk/Cargo.lock) must be one of lib/firecracker's, so that
the same check covers it. tools/check-dependencies.sh runs this script.
"""

import io
import json
import re
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "lib/firecracker"
# Files cargo writes when it packages a crate.
GENERATED = {"Cargo.toml", ".cargo_vcs_info.json", "Cargo.lock"}


def packages(lock):
    out = {}
    for block in lock.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)[1]
        version = re.search(r'^version = "([^"]+)"', block, re.M)[1]
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        out.setdefault((name, version), set()).add(source[1] if source else "path")
    return out


def fetch(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read()
        except OSError:
            if attempt == 2:
                raise
    return None


def main():
    checkouts = Path(sys.argv[1])
    base = (ROOT / "patches/base").read_text().strip()
    upstream = packages(
        subprocess.run(
            ["git", "-C", str(UPSTREAM), "show", f"refs/tags/{base}:Cargo.lock"],
            check=True, capture_output=True, text=True,
        ).stdout
    )
    wick = packages((UPSTREAM / "Cargo.lock").read_text())

    problems, checked = [], 0
    for (name, version), sources in sorted(wick.items()):
        for source in sorted(sources):
            if not source.startswith("git+"):
                continue
            if not any(s.startswith("registry+") for s in upstream.get((name, version), ())):
                continue
            sha = source.rsplit("#", 1)[1]
            data = fetch(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")
            tar = tarfile.open(fileobj=io.BytesIO(data))
            prefix = f"{name}-{version}/"
            files = {
                m.name[len(prefix):]: tar.extractfile(m).read()
                for m in tar.getmembers()
                if m.isfile()
            }
            vcs = json.loads(files.get(".cargo_vcs_info.json", b"{}"))
            published = vcs.get("git", {}).get("sha1")
            sub = vcs.get("path_in_vcs", "")
            roots = [
                d / sub
                for d in checkouts.glob(f"*/{sha[:7]}")
                if (d / sub / "Cargo.toml").exists()
                and re.search(rf'^name = "{re.escape(name)}"', (d / sub / "Cargo.toml").read_text(), re.M)
            ]
            what = f"{name} {version} ({source.split('#')[0]})"
            if published != sha:
                problems.append(f"{what}: crates.io release published from {published}, wick builds {sha}")
            if not roots:
                problems.append(f"{what}: no git checkout of {sha[:7]} in {checkouts}")
                continue
            git_root = roots[0]
            for rel, content in sorted(files.items()):
                if rel in GENERATED:
                    continue
                # Cargo.toml.orig is the manifest as written, Cargo.toml in git.
                path = git_root / ("Cargo.toml" if rel == "Cargo.toml.orig" else rel)
                if not path.exists():
                    problems.append(f"{what}: {rel} is in the crates.io package, not in git")
                elif path.read_bytes() != content:
                    problems.append(f"{what}: {rel} differs from the crates.io package")
            checked += 1
            n = len(set(files) - GENERATED)
            print(f"{what}: crates.io release = commit {sha[:12]}, {n} packaged files identical")

    if not checked:
        problems.append("no git dependency of wick replaces a crates.io release; is the lockfile right?")
    for other in sys.argv[2:]:
        for (name, version), sources in sorted(packages(Path(other).read_text()).items()):
            for source in sorted(s for s in sources if s.startswith("git+")):
                if source not in wick.get((name, version), ()):
                    problems.append(f"{other}: {name} {version} from {source} is not in lib/firecracker/Cargo.lock")
                else:
                    print(f"{other}: {name} {version} ({source.split('#')[0]}): as in lib/firecracker/Cargo.lock")
    for p in problems:
        print(f"PROBLEM: {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
