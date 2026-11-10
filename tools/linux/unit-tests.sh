#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs upstream's unit tests the way upstream's CI does
# (tests/integration_tests/build/test_unittests.py, host_tools/cargo_build.py):
# in upstream's development container, as root, for the musl target, with
# RUST_TEST_THREADS=1, `cargo test --all --no-fail-fast` and then the same
# with `--examples`. Run it for pure upstream and for wick on the same
# machine, then compare the two with tools/linux/compare-unit-tests.py.
#
#   tools/linux/unit-tests.sh upstream OUT   plain upstream at patches/base
#   tools/linux/unit-tests.sh wick OUT       lib/firecracker (upstream + patches/)
#
# OUT gets the build's executable list (build.json), the test list
# (list.log), the results (run.log) and the same three for the examples.
# Tests named in tools/linux/unit-test-exclusions.txt are skipped in both
# runs; that file says why each one is there.
#
# The only difference from upstream's command: no --nocapture, so each test's
# result stays on its own line ("test <name> ... ok") for the comparison.
# Captured or not, a test's own output does not change what it does.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

exclusions="$WICK_ROOT/tools/linux/unit-test-exclusions.txt"

# --- inside the container ---------------------------------------------------
if [[ "${1:-}" == "--in-container" ]]; then
    tree="$2"
    out="$3"
    arch="$(uname -m)"
    target="$arch-unknown-linux-musl"
    cd "$tree"

    # host_tools/cargo_build.py: cargo_test() and get_rustflags(). An empty
    # RUSTFLAGS on x86_64 is upstream's too (it replaces .cargo/config.toml's
    # build.rustflags).
    rustflags=""
    [[ "$arch" == aarch64 ]] && rustflags="-C link-arg=-lgcc -C link-arg=-lfdt "
    export CARGO_TARGET_DIR="$out/target"
    export RUST_TEST_THREADS=1
    export RUST_BACKTRACE=1
    export RUSTFLAGS="$rustflags"

    skips=()
    while read -r a name; do
        [[ "$a" == all || "$a" == "$arch" ]] && skips+=(--skip "$name")
    done < <(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$exclusions")
    echo "excluded on $arch: $((${#skips[@]} / 2)) test(s)"

    echo "toolchain: $(rustc --version)"
    echo "$arch" >"$out/arch"
    grep -m1 '^model name' /proc/cpuinfo >"$out/cpu" || true
    for run in lib examples; do
        flags=(--target "$target" --all --no-fail-fast --locked)
        [[ "$run" == examples ]] && flags+=(--examples)
        log="$out/$run"
        # Build first: the JSON names the package of every test executable.
        cargo test "${flags[@]}" --no-run --message-format=json-render-diagnostics \
            >"$log.build.json" 2> >(tee "$log.build.log" >&2)
        cargo test "${flags[@]}" -- --list >"$log.list.log" 2>&1
        set +e
        cargo test "${flags[@]}" -- --exact "${skips[@]}" 2>&1 | tee "$log.run.log"
        status=${PIPESTATUS[0]}
        set -e
        echo "$status" >"$log.status"
        echo "cargo test ($run) exited with $status"
    done
    # The comparison decides; a failed build has already stopped the script.
    exit 0
fi

# --- on the host ------------------------------------------------------------
[[ $# -eq 2 ]] || die "usage: $0 upstream|wick OUT"
which="$1"
mkdir -p "$2"
out="$(cd "$2" && pwd)"

case "$which" in
    upstream)
        base="$(upstream_base)"
        ensure_tag "$base"
        tree="$out/src"
        rm -rf "$tree"
        mkdir -p "$tree"
        # A plain export of the tag, outside the wick checkout so that no
        # cargo configuration of wick's applies to it.
        up archive "refs/tags/$base" | tar -x -C "$tree"
        echo "upstream $base exported to $tree"
        ;;
    wick)
        tree="$UPSTREAM_DIR"
        "$WICK_ROOT/tools/setup.sh"
        ;;
    *) die "usage: $0 upstream|wick OUT" ;;
esac

"$WICK_ROOT/tools/linux/devctr.sh" -v "$out" -w "$tree" --chown "$out" -- \
    "$WICK_ROOT/tools/linux/unit-tests.sh" --in-container "$tree" "$out"
