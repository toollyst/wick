#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The record-only features of kvm-ioctls (crates/compat/kvm-ioctls/Cargo.toml)
# are for CI's and a PC's records, never for a binary someone runs as wick:
#   whp-trace          prints each WHP call that grew its thread's stack
#                      (WHPTRACE lines);
#   whp-x2apic-record  makes the Windows partitions x2APICs on AMD hosts, as
#                      option E does, before the product turns them on.
# The release workflow and CI's Windows kit run this on what they ship.
#
#   tools/check-record-features.sh [--has <feature> <binary>]... [<binary>]...
#
# 1. No Cargo.toml of wick's tree or of lib/firecracker (its patches applied)
#    names one of them but kvm-ioctls', where each is defined, and that one
#    has no `default` set: so a plain `cargo build` cannot turn one on.
# 2. No binary given holds the line only a build with one of them has. A
#    binary given with `--has <feature>` must hold that feature's line, and
#    no other's: CI's x2APIC record build, which shows that the line is
#    found where it is.
# Fails naming the feature, and the file and line or the binary. Bash 3.2
# (macOS's): no associative arrays.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$WICK_ROOT"

FEATURES="whp-trace whp-x2apic-record"
# The line only a build with the feature has: src/whp/ffi.rs's trace line,
# src/whp/vm.rs's line of a whp-x2apic-record build.
mark() {
    case "$1" in
        whp-trace) echo 'WHPTRACE thread' ;;
        whp-x2apic-record) echo 'whp-x2apic-record build, never a release' ;;
        *) die "not a record-only feature: $1 ($FEATURES)" ;;
    esac
}
DEFINED="crates/compat/kvm-ioctls/Cargo.toml"

failed=0
fail() {
    echo "::error::$*" >&2
    failed=1
}

# The manifests: wick's tracked ones, and lib/firecracker's, tracked or new
# (a patch may add one), as paths from the root.
manifests() {
    (cd "$ROOT" && git ls-files -- '*Cargo.toml' ':!:lib/firecracker')
    if [[ -d "$UPSTREAM_DIR/.git" || -f "$UPSTREAM_DIR/.git" ]]; then
        (cd "$UPSTREAM_DIR" && git ls-files -co --exclude-standard -- '*Cargo.toml') | sed 's|^|lib/firecracker/|'
    fi
}

# 1. The manifests.
checked=0
while IFS= read -r file; do
    [[ -f "$ROOT/$file" ]] || continue
    checked=$((checked + 1))
    for feature in $FEATURES; do
        n=0
        while IFS= read -r text; do
            n=$((n + 1))
            [[ "$text" == *"$feature"* ]] || continue
            if [[ "$file" == "$DEFINED" ]]; then
                # Its definition (`name = []`) and comments only.
                [[ "$text" =~ ^[[:space:]]*# ]] && continue
                [[ "$text" =~ ^${feature}[[:space:]]*=[[:space:]]*\[\][[:space:]]*$ ]] && continue
            fi
            fail "$file:$n names kvm-ioctls' record-only feature $feature (never in a release): $text"
        done <"$ROOT/$file"
    done
done < <(manifests)
((checked > 0)) || fail "no Cargo.toml found under $ROOT"
if grep -n -E '^[[:space:]]*default[[:space:]]*=' "$ROOT/$DEFINED" >/dev/null; then
    fail "$DEFINED has a default feature set: a record-only feature must never be in one"
fi

# 2. The binaries: each with the features it must have (none but those).
bins=()
wants=()
while (($#)); do
    if [[ "$1" == --has ]]; then
        (($# >= 3)) || die "--has needs a feature and a binary"
        mark "$2" >/dev/null
        bins+=("$3")
        wants+=("$2")
        shift 3
    else
        bins+=("$1")
        wants+=("")
        shift
    fi
done
i=0
for bin in ${bins[@]+"${bins[@]}"}; do
    want=${wants[$i]}
    i=$((i + 1))
    [[ -f "$bin" ]] || { fail "$bin: no such binary"; continue; }
    for feature in $FEATURES; do
        line=$(mark "$feature")
        if LC_ALL=C grep -a -q -F "$line" "$bin"; then
            [[ "$feature" == "$want" ]] ||
                fail "$bin is a build with kvm-ioctls' record-only feature $feature ('$line' in it): never shipped"
        elif [[ "$feature" == "$want" ]]; then
            fail "$bin was to be a build with $feature and has not its line ('$line')"
        fi
    done
done
((failed == 0)) || exit 1
echo "check-record-features: $checked manifests, ${#bins[@]} binaries: no record-only feature but those asked for"
