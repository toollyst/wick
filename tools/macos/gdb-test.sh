#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Firecracker's gdb stub on macOS, with boot-test's guest (the CI Image; the
# guest's own addresses, as upstream's aarch64 debug kernel is a PE file
# Firecracker's loader refuses) and a gdb client: tools/macos/gdb-test.py says
# what it checks.
#
#   tools/macos/gdb-test.sh [--gdb PATH] [--lldb PATH | --no-lldb]
#
# Builds Firecracker with the gdb feature as upstream's build_gdb does
# (tests/host_tools/cargo_build.py: a debug build, its own target directory,
# lib/firecracker/build/gdb), signs it with the Hypervisor.framework
# entitlement and runs the stage. Needs gdb (brew install gdb: it connects to
# an aarch64 remote stub; it does not debug macOS processes, which this does
# not ask), the client that counts: without it the stage fails; the system's
# lldb, when there, runs the same checks as an additional client either way.
# Results go to build/boot-test/<time> (tools/clean.sh keeps the newest).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "error: needs macOS on Apple silicon" >&2; exit 1; }

prepare_test_run "$ROOT/build/boot-test" 2
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/gdb}"
(cd "$ROOT/lib/firecracker" &&
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked -p firecracker --bin firecracker --features gdb)
codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" "$TARGET_DIR/debug/firecracker"

OUT="$ROOT/build/boot-test/$(date +%Y%m%d-%H%M%S)"
exec python3 -I "$ROOT/tools/macos/gdb-test.py" --firecracker "$TARGET_DIR/debug/firecracker" \
    --cache "$HOME/Library/Caches/wick/boot-test" --out "$OUT" "$@"
