#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Checks overlay/vmm/ext/sandbox.rs's run-phase lists against what a running
# microVM asks the macOS kernel for.
#
#   tools/macos/sandbox-discovery.sh [--release] [stage...]
#
# Builds Firecracker with --cfg wick_sandbox_discovery in a target directory
# of its own (after narrow(), a system call, Mach trap or kernel MIG routine
# outside the run-phase lists is then allowed and reported instead of raising
# SIGSYS, and every operation no rule allows is allowed and reported) and runs
# tools/macos/boot-test.sh with it. It prints the calls and operations
# Firecracker processes made outside the lists (system calls by number), from
# the kernel's sandbox reports, and exits 1 if there were any. The discovery build is never
# installed or released: it is only ever under build/sandbox-discovery.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
start="$(date '+%Y-%m-%d %H:%M:%S')"
export CARGO_TARGET_DIR="$ROOT/build/sandbox-discovery"
export RUSTFLAGS="-Ccodegen-units=1 --cfg wick_sandbox_discovery"
status=0
"$ROOT/tools/macos/boot-test.sh" "$@" || status=$?
# The kernel writes its reports with a delay.
sleep 10
/usr/bin/log show --start "$start" --style compact --predicate 'sender == "Sandbox"' |
    sed -nE 's/.*firecracker\([0-9]+\) allow ([a-z*-]+) ?(.*)$/\1 \2/p' |
    sed -E 's#/private/tmp/wick-[a-z]+-[^/ ]+#<test dir>#g; s#'"$HOME"'#~#g' |
    sort -u > "$CARGO_TARGET_DIR/unlisted.txt"
if [[ -s "$CARGO_TARGET_DIR/unlisted.txt" ]]; then
    echo "outside the lists:"
    cat "$CARGO_TARGET_DIR/unlisted.txt"
    status=1
else
    echo "nothing outside the lists"
fi
exit "$status"
