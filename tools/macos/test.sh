#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Run Firecracker's unit tests on macOS with Hypervisor.framework available.
#
#   tools/macos/test.sh [cargo test arguments] [-- <name substring>]
#       (default: -p vmm --lib; cargo runs in lib/firecracker, so a
#       compatibility crate is --manifest-path ../../crates/compat/<crate>/Cargo.toml)
#
# Test binaries are signed with the hypervisor entitlement. Hypervisor.framework
# allows one VM per process, so every test runs in a process of its own (as
# cargo-nextest does): a test that keeps its VM alive cannot affect the next.
# Prints one line per test and a summary; the exit status is non-zero if any
# test failed. WICK_TEST_LOG=<file> keeps the output of failed tests there.
#
# The binaries are signed in place, in cargo's target directory, and stay
# signed until cargo links them again: tools/macos/check-unit-tests.py,
# which runs them unsigned as CI's runners do, then finds the tests that
# need Hypervisor.framework passing ("listed ... (no-hvf) passes"). Touch a
# source file of the crate (or rebuild) before an unsigned check.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENTITLEMENTS="$ROOT/tools/macos/hypervisor.entitlements"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"

cargo_args=()
filter=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--" ]]; then
        filter="${2:-}"
        break
    fi
    cargo_args+=("$1")
    shift
done
[[ ${#cargo_args[@]} -eq 0 ]] && cargo_args=(-p vmm --lib)

cd "$ROOT/lib/firecracker"
bins=()
while IFS= read -r bin; do
    bins+=("$bin")
done < <(cargo test --locked --no-run --message-format=json "${cargo_args[@]}" 2>/dev/null |
    python3 -I -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test") and msg.get("executable"):
        print(msg["executable"])
')
[[ ${#bins[@]} -gt 0 ]] || { echo "error: no test binaries built" >&2; exit 1; }

log="${WICK_TEST_LOG:-/dev/null}"
: >"$log"
passed=0
failed=0
ignored=0
failures=()
for bin in "${bins[@]}"; do
    codesign --force --sign - --entitlements "$ENTITLEMENTS" "$bin" 2>/dev/null
    while IFS= read -r line; do
        name="${line%: test}"
        [[ "$line" == *": test" ]] || continue
        [[ -n "$filter" && "$name" != *"$filter"* ]] && continue
        if out="$("$bin" --exact "$name" --test-threads=1 2>&1)"; then
            if grep -q "1 ignored" <<<"$out"; then
                ignored=$((ignored + 1))
                echo "test $name ... ignored"
            else
                passed=$((passed + 1))
                echo "test $name ... ok"
            fi
        else
            failed=$((failed + 1))
            failures+=("$name")
            echo "test $name ... FAILED"
            { echo "---- $name ----"; echo "$out"; } >>"$log"
        fi
    done < <("$bin" --list 2>/dev/null)
done

echo
echo "test result: $passed passed; $failed failed; $ignored ignored"
if [[ $failed -gt 0 ]]; then
    printf '  failed: %s\n' "${failures[@]}"
    exit 1
fi
