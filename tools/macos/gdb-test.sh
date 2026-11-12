#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Firecracker's gdb stub on macOS, with upstream's aarch64 debug kernel and a
# gdb client: tools/macos/gdb-test.py says what it checks.
#
#   tools/macos/gdb-test.sh [--offline] [--gdb PATH]
#
# Builds Firecracker with the gdb feature as upstream's build_gdb does
# (tests/host_tools/cargo_build.py: a debug build, its own target directory,
# lib/firecracker/build/gdb), signs it with the Hypervisor.framework
# entitlement and runs the stage. --offline builds nothing and runs only the
# checks without a guest (gdb and the kernel files). Needs gdb
# (brew install gdb: it reads aarch64 Linux ELF files and connects to a
# remote stub; it does not debug macOS processes, which this does not ask).
# Results go to build/boot-test/<time> (tools/clean.sh keeps the newest).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "error: needs macOS on Apple silicon" >&2; exit 1; }

offline=0
for a in "$@"; do [[ "$a" == --offline ]] && offline=1; done
prepare_test_run "$ROOT/build/boot-test" 2
fc=()
if ((offline == 0)); then
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
    TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/gdb}"
    (cd "$ROOT/lib/firecracker" &&
        CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked -p firecracker --bin firecracker --features gdb)
    codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" "$TARGET_DIR/debug/firecracker"
    fc=(--firecracker "$TARGET_DIR/debug/firecracker")
fi

OUT="$ROOT/build/boot-test/$(date +%Y%m%d-%H%M%S)"
exec python3 -I "$ROOT/tools/macos/gdb-test.py" ${fc[@]+"${fc[@]}"} \
    --cache "$HOME/Library/Caches/wick/boot-test" --out "$OUT" "$@"
