#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs upstream's integration tests (pytest, tests/integration_tests) the way
# upstream's `tools/devtool test` does: upstream's musl release build
# (tools/release.sh) and upstream's tools/test.sh in its development
# container, privileged, as root. Run it for plain upstream and for wick on
# the same machine, then compare with tools/linux/compare-integration-tests.py.
#
#   tools/linux/integration-tests.sh upstream|wick OUT [PYTEST ARGS...]
#
# The guest artifacts are a subset of upstream's CI set (PREFIX below): the
# 6.1 guest kernel (upstream's default, and its debug build) with the Amazon
# Linux and Ubuntu root file systems, prepared by upstream's
# tools/setup-ci-artifacts.sh; kernel-parametrized tests run for that kernel
# only. /srv is upstream's tmpfs, as devtool makes it. OUT gets the pytest
# JSON report (test-report.json), pytest's output (pytest.log) and
# upstream's test_results directory, and with WICK_IT_MEMDIAG=1
# memory-peaks.jsonl (below).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

S3="https://s3.amazonaws.com/spec.ccfc.min"
PREFIX="firecracker-ci/20261105-6ea6634994fa-0"
ARTIFACTS=(
    vmlinux-6.1.188 vmlinux-6.1.188.config
    amazonlinux-2023.squashfs amazonlinux-2023.manifest
    ubuntu-24.04.squashfs ubuntu-24.04.manifest
    # The debug build of the same kernel (test_gdb.py); setup-ci-artifacts.sh
    # also expects at least one *.debug.gz to unpack.
    debug/vmlinux-6.1.188 debug/vmlinux-6.1.188.config debug/vmlinux-6.1.188.debug.gz
)

[[ $# -ge 2 ]] || die "usage: $0 upstream|wick OUT [PYTEST ARGS...]"
which="$1"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
shift 2
arch="$(uname -m)"
echo "$arch" >"$out/arch"

case "$which" in
    upstream)
        base="$(upstream_base)"
        ensure_tag "$base"
        tree="$out/src"
        rm -rf "$tree"
        mkdir -p "$tree"
        # A plain export of the tag, outside the wick checkout.
        up archive "refs/tags/$base" | tar -x -C "$tree"
        echo "upstream $base exported to $tree"
        ;;
    wick)
        tree="$UPSTREAM_DIR"
        "$WICK_ROOT/tools/setup.sh"
        ;;
    *) die "usage: $0 upstream|wick OUT [PYTEST ARGS...]" ;;
esac

# Guest artifacts, shared by both runs (setup-ci-artifacts.sh adds the SSH
# key and the ext4 images once).
art="${WICK_CI_ARTIFACTS:-$(dirname "$out")/artifacts}/$arch"
mkdir -p "$art"
for name in "${ARTIFACTS[@]}"; do
    [[ -s "$art/$name" || -s "$art/$name.orig" || -s "$art/${name%.gz}" ]] && continue
    echo "downloading $name"
    mkdir -p "$(dirname "$art/$name")"
    curl -fsSL --retry 3 -o "$art/$name.part" "$S3/$PREFIX/$arch/$name"
    mv "$art/$name.part" "$art/$name"
done
art="$(cd "$art" && pwd)"

devctr() {
    "$WICK_ROOT/tools/linux/devctr.sh" -v "$out" -v "$art" -w "$tree" \
        --chown "$out" --chown "$art" --chown "$tree/build" "$@"
}
mkdir -p "$tree/build"
if [[ ! -e "$art/.setup-done" ]]; then
    devctr -- ./tools/setup-ci-artifacts.sh "$art"
    touch "$art/.setup-done"
fi
echo "$art" >"$tree/build/current_artifacts"

# Upstream's release build, as `devtool build --release` makes it.
devctr -- ./tools/release.sh --libc musl --profile release

# Upstream's test runner. test.sh copies the artifacts to /srv and runs
# pytest in tests/ (pytest.ini writes ../test_results/test-report.json).
rm -rf "$tree/test_results"
# Every selected test runs, those in tools/linux/integration-test-exclusions.txt
# too: the comparison expects them to fail on upstream here, and still
# requires wick to pass where upstream passes.
# WICK_IT_MEMDIAG=1: an informational run, never a counted one, that also
# loads tools/linux/integration/wick_memdiag.py (the VMM's own memory at its
# peak, by kind of mapping, in OUT/memory-peaks.jsonl).
runner=(./tools/test.sh)
if [[ "${WICK_IT_MEMDIAG:-}" == 1 ]]; then
    runner=(env "PYTHONPATH=$WICK_ROOT/tools/linux/integration"
        "WICK_MEMDIAG_OUT=$out/memory-peaks.jsonl" ./tools/test.sh -p wick_memdiag)
    rm -f "$out/memory-peaks.jsonl"
fi
set +e
devctr -- "${runner[@]}" "$@" 2>&1 | tee "$out/pytest.log"
status=${PIPESTATUS[0]}
set -e
echo "$status" >"$out/status"
rm -rf "$out/test_results"
[[ -d "$tree/test_results" ]] && cp -r "$tree/test_results" "$out/test_results"
cp "$tree/test_results/test-report.json" "$out/test-report.json" 2>/dev/null || true
echo "pytest exited with $status"
