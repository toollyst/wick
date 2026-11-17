#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Measures how many extended attribute bytes default Linux file systems hold
# for one file beside wick-fsd's metadata record (docs/design-fs.md §4.2,
# Limits; §4.5): the input to DEFAULT_XATTR_BUDGET and XATTR_ENTRY_COST in
# crates/fs/fsd/src/limits.rs.
#
# For each file system (ext4, xfs and btrfs as mkfs makes them on a 1 GiB
# image, and tmpfs), on a fresh file with the 40-byte record
# `user.wick.stat` set, as wick-fsd stores them:
#   - one guest attribute `user.wick.x.user.v`: the largest value that fits;
#   - many guest attributes `user.wick.x.<n>` (n = 1, 2, ...), empty: how
#     many fit, the fewest bytes per attribute a guest can spend.
# Each is reported with what wick-fsd charges for it (XATTR_ENTRY_COST + the
# guest name + the value; the cost given as $1, default 32).
#
# Needs root (mkfs, mount -o loop) and setfattr (the attr package):
#   sudo tools/linux/xattr-budget.sh [cost]
set -euo pipefail

cost="${1:-32}"
[[ $(id -u) -eq 0 ]] || { echo "xattr-budget.sh: needs root (mkfs, mount)" >&2; exit 1; }
command -v setfattr >/dev/null || { echo "xattr-budget.sh: needs setfattr (the attr package)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'umount "$work/mnt" 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir "$work/mnt"
record="$(printf 'wkst\001\000\001\000' | od -An -tx1 | tr -d ' \n')$(printf '%064d' 0)"

# The largest value of one guest attribute beside the record, by bisection.
largest() {
    local f="$1" lo=0 hi=$((64 * 1024)) mid
    while ((lo < hi)); do
        mid=$(((lo + hi + 1) / 2))
        if setfattr -n user.wick.x.user.v -v "0x$(head -c "$mid" /dev/zero | od -An -tx1 -v | tr -d ' \n')" "$f" 2>/dev/null; then
            lo=$mid
        else
            hi=$((mid - 1))
        fi
        setfattr -x user.wick.x.user.v "$f" 2>/dev/null || true
    done
    echo "$lo"
}

# How many empty guest attributes with the shortest names fit.
count() {
    local f="$1" n=0 chars=0
    while ((n < 100000)) && setfattr -n "user.wick.x.$((n + 1))" -v "" "$f" 2>/dev/null; do
        n=$((n + 1))
        chars=$((chars + ${#n}))
    done
    echo "$n $chars"
}

measure() {
    local fs="$1" f="$work/mnt/f"
    : >"$f"
    setfattr -n user.wick.stat -v "0x$record" "$f"
    local big many chars
    big="$(largest "$f")"
    read -r many chars < <(count "$f")
    # wick-fsd's charge: cost + name + value per attribute (the guest's
    # name is what follows user.wick.x.).
    printf '%-6s one value: %6d bytes (charged %6d)   empty attributes: %5d (charged %6d)\n' \
        "$fs" "$big" $((cost + 6 + big)) "$many" $((many * cost + chars))
}

img="$work/img"
for fs in ext4 xfs btrfs; do
    mkfs="mkfs.$fs"
    command -v "$mkfs" >/dev/null || { echo "$fs: $mkfs not installed"; continue; }
    rm -f "$img"; truncate -s 1G "$img"
    case "$fs" in
        ext4) mkfs.ext4 -q -F "$img" ;;
        xfs) mkfs.xfs -q -f "$img" ;;
        btrfs) mkfs.btrfs -q -f "$img" >/dev/null ;;
    esac
    mount -o loop "$img" "$work/mnt"
    measure "$fs"
    [[ $fs == ext4 ]] && echo "       ($(dumpe2fs -h "$img" 2>/dev/null | grep -E '^(Block size|Inode size):' | tr -s ' ' | paste -sd, -))"
    umount "$work/mnt"
done
mount -t tmpfs -o size=64m tmpfs "$work/mnt"
measure tmpfs
umount "$work/mnt"
echo "kernel $(uname -r) $(uname -m); counts stop at 100000"
