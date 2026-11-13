#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Checks and finishes the release SBOM that cargo-cyclonedx writes.

    tools/sbom.py IN OUT ROOT CARGO_LOCK [BINARY]

IN is cargo-cyclonedx's CycloneDX JSON for BINARY (default firecracker),
which it must describe. Every component must be in CARGO_LOCK: a crates.io
crate with the SHA-256 the lockfile records, a git crate at the commit it
pins, a path crate inside ROOT (the wick checkout). OUT is IN with ROOT's absolute path, which only says
where the build ran, replaced by `wick`, so that the same commit gives the
same SBOM on every machine. tools/package-release.sh runs it.
"""

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def lock_packages(text):
    out = {}
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)[1]
        version = re.search(r'^version = "([^"]+)"', block, re.M)[1]
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        out.setdefault((name, version), []).append(
            (source[1] if source else "path", checksum[1] if checksum else None)
        )
    return out


def main():
    src, dst, root, lock_path = sys.argv[1:5]
    binary = sys.argv[5] if len(sys.argv) > 5 else "firecracker"
    root = str(Path(root).resolve())
    bom = json.loads(Path(src).read_text())
    lock = lock_packages(Path(lock_path).read_text())

    problems = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
        problems.append(f"not CycloneDX 1.5: {bom.get('bomFormat')} {bom.get('specVersion')}")
    main_component = bom.get("metadata", {}).get("component", {})
    if main_component.get("name") != binary:
        problems.append(f"describes {main_component.get('name')!r}, not {binary}")
    components = bom.get("components", [])
    if not components:
        problems.append("no components")

    counts = {"crates.io": 0, "git": 0, "path": 0}
    for c in components:
        name, version, ref = c.get("name"), c.get("version"), c.get("bom-ref", "")
        what = f"{name} {version}"
        entries = lock.get((name, version), [])
        if not entries:
            problems.append(f"{what}: not in {lock_path}")
            continue
        if ref.startswith(CRATES_IO + "#"):
            want = {sum_ for source, sum_ in entries if source == CRATES_IO}
            have = {h["content"] for h in c.get("hashes", []) if h.get("alg") == "SHA-256"}
            if not want or not have or not have <= want:
                problems.append(f"{what}: SHA-256 {sorted(have)} is not Cargo.lock's {sorted(want)}")
            counts["crates.io"] += 1
        elif ref.startswith("git+"):
            commit = re.search(r"@([0-9a-f]{40})$", unquote(c.get("purl", "")))
            sources = [s for s, _ in entries if s.startswith(ref.split("#")[0] + "#")]
            if not commit or not sources or not any(s.endswith("#" + commit[1]) for s in sources):
                problems.append(f"{what}: {c.get('purl')} is not the commit Cargo.lock pins")
            counts["git"] += 1
        elif ref.startswith("path+file://"):
            if not ref[len("path+file://"):].startswith(root + "/") or ("path", None) not in entries:
                problems.append(f"{what}: path crate {ref} outside {root} or not a path crate in Cargo.lock")
            counts["path"] += 1
        else:
            problems.append(f"{what}: unknown source {ref}")

    for p in problems:
        print(f"PROBLEM: {p}", file=sys.stderr)
    if problems:
        return 1
    text = json.dumps(bom, indent=2, ensure_ascii=False).replace(root, "wick") + "\n"
    Path(dst).write_text(text)
    print(
        f"{dst}: {len(components)} components "
        f"({counts['crates.io']} crates.io, {counts['git']} git, {counts['path']} path), all as Cargo.lock pins them"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
