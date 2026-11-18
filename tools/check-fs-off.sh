#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Host folder sharing (virtio-fs) is built only with Firecracker's `fs`
# feature (docs/design-fs.md row 18): a default build holds none of its code.
#
#   tools/check-fs-off.sh <binary without the feature>... [--has <binary>]...
#
# 1. No Cargo.toml of wick's tree or of lib/firecracker (its patches applied)
#    turns wick-ext's `fs` on by default: wick-ext's and Firecracker's
#    `default` sets do not name it.
# 2. No binary given holds a symbol of wick_ext::fs or of wick_fs_frame
#    (nm; a debug build's symbols). A binary given with `--has` must hold
#    both: one built with the code (CI gives wick-ext's test binary built
#    with the feature), so that the names searched for are the ones a build
#    with the feature has.
# Fails naming the manifest or the binary and a symbol found.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$WICK_ROOT"

failed=0
for manifest in "$ROOT/crates/ext/Cargo.toml" "$ROOT/lib/firecracker/src/firecracker/Cargo.toml"; do
    # The `default = [...]` line of [features], if any.
    if awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /^default[[:space:]]*=/' "$manifest" | grep -q '"\(wick-ext/\)\?fs"'; then
        echo "check-fs-off: $manifest turns fs on by default"
        failed=1
    fi
done

# Rust's legacy mangling names a path's crates and modules by length and
# name (_ZN8wick_ext2fs...), v0 likewise (_RNv...8wick_ext2fs...).
pattern='8wick_ext2fs|13wick_fs_frame'
has=0
for arg in "$@"; do
    if [[ "$arg" == --has ]]; then
        has=1
        continue
    fi
    [[ -f "$arg" ]] || die "no binary $arg"
    # Read once, then searched: `nm | grep -q` under pipefail fails when
    # grep stops at the first match and nm dies of SIGPIPE.
    symbols=$(nm "$arg" 2>/dev/null) || die "nm could not read $arg"
    found=$(grep -E -m1 "$pattern" <<<"$symbols" || true)
    if [[ $has -eq 1 ]]; then
        for part in 8wick_ext2fs 13wick_fs_frame; do
            if ! grep -q "$part" <<<"$symbols"; then
                echo "check-fs-off: $arg, built with fs, has no symbol matching $part: the check would find nothing"
                failed=1
            fi
        done
        has=0
    elif [[ -n "$found" ]]; then
        echo "check-fs-off: $arg, built without fs, holds $found"
        failed=1
    fi
done
[[ $failed -eq 0 ]] && echo "check-fs-off: ok"
exit $failed
