#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Upstream's tools/setup-ci-artifacts.sh for macOS, as the user: an SSH key,
# each squashfs root file system again with the key in it, and an ext4 image
# made from it.
#
# Upstream runs it as root, so the extracted files keep their modes (every
# file in upstream's images is root's; mksquashfs -all-root). Here they are
# extracted as the user and made readable to be copied, and both images then
# get every file's mode as the original squashfs lists it, and root as owner
# (the key's files get upstream's modes).
#
#   tools/macos/integration/setup-artifacts.sh DIR
#
# Needs squashfs-tools and e2fsprogs (brew install squashfs e2fsprogs).
set -euo pipefail

dir="$1"
E2=/opt/homebrew/opt/e2fsprogs/sbin
# Upstream's devctr (Ubuntu 24.04) makes the 500 MiB image with 4 KiB blocks,
# the guest's page size, which an ext4 mounted with DAX needs (test_pmem.py's
# rootflags=dax); Homebrew's e2fsprogs gives an image under 512 MiB 1 KiB
# blocks ("EXT4-fs (pmem0): unsupported blocksize for DAX"). The test
# session's configuration (tools/macos/integration-tests.sh) is used here too.
export MKE2FS_CONFIG
MKE2FS_CONFIG="$(cd "$(dirname "$0")" && pwd)/mke2fs.conf"
for t in unsquashfs mksquashfs; do
    command -v "$t" >/dev/null || { echo "error: $t missing: brew install squashfs" >&2; exit 1; }
done
[[ -x "$E2/mkfs.ext4" && -x "$E2/debugfs" ]] || { echo "error: e2fsprogs missing: brew install e2fsprogs" >&2; exit 1; }

cd "$dir"
[[ -s id_rsa ]] || ssh-keygen -q -t rsa -b 2048 -f id_rsa -N ""
find . -name "*.debug.gz" -print0 | xargs -0 -n1 gunzip -f

# A Linux root file system has names that differ only in case
# (/usr/share/terminfo/a and A), and macOS volumes are case-insensitive by
# default: extract on a case-sensitive volume of its own.
vol=""
tree=""
remove_tree() {
    [[ -n "$tree" && -e "$tree" ]] || return 0
    chmod -R u+rwX "$tree"
    rm -rf "$tree"
}
detach() {
    remove_tree
    if [[ -n "$vol" ]]; then
        hdiutil detach -quiet "$vol"
        rmdir "$vol"
    fi
    rm -f "$dir/extract.sparseimage" "$dir/owners.pseudo" "$dir/owners.root" "$dir/owners.debugfs" "$dir/debugfs.err"
}
trap detach EXIT

# Owners and modes from `unsquashfs -lln`, plus the key's files:
#   owners.pseudo   mksquashfs -pf lines ("<path> m <mode> 0 0"), the root
#                   directory's mode apart (owners.root)
#   owners.debugfs  debugfs set_inode_field lines (mode with the file type, uid, gid)
owners() {
    python3 -I - "$1" <<'PY'
import re, stat, subprocess, sys

listing = subprocess.run(["unsquashfs", "-lln", sys.argv[1]], check=True,
                         capture_output=True, text=True).stdout.splitlines()
TYPES = {"-": stat.S_IFREG, "d": stat.S_IFDIR, "l": stat.S_IFLNK}
BITS = [(stat.S_IRUSR, "r"), (stat.S_IWUSR, "w"), (stat.S_IXUSR, "x"),
        (stat.S_IRGRP, "r"), (stat.S_IWGRP, "w"), (stat.S_IXGRP, "x"),
        (stat.S_IROTH, "r"), (stat.S_IWOTH, "w"), (stat.S_IXOTH, "x")]
entries = {}
for line in listing:
    m = re.match(r"^(\S{10}) (\d+)/(\d+) +\S+ \S+ \S+ squashfs-root(.*)$", line)
    if not m:
        sys.exit(f"cannot read the listing line {line!r}")
    perm, uid, gid, path = m.groups()
    if (uid, gid) != ("0", "0"):
        sys.exit(f"{path} is owned by {uid}/{gid}; upstream's images give every file to root")
    if perm[0] not in TYPES:
        sys.exit(f"{path}: file type {perm[0]!r}: only files, directories and links are kept")
    if perm[0] == "l":
        path = path.split(" -> ", 1)[0]
    mode = 0
    for i, (bit, ch) in enumerate(BITS):
        if perm[1 + i] in (ch, "s", "t"):
            mode |= bit
    for i, (special, chars) in enumerate(((stat.S_ISUID, "sS"), (stat.S_ISGID, "sS"), (stat.S_ISVTX, "tT"))):
        if perm[3 + 3 * i] in chars:
            mode |= special
    entries[path or "/"] = (TYPES[perm[0]], mode, int(uid), int(gid))
# What setup-ci-artifacts.sh adds as root with its umask (022).
entries.setdefault("/root/.ssh", (stat.S_IFDIR, 0o755, 0, 0))
entries["/root/.ssh/authorized_keys"] = (stat.S_IFREG, 0o644, 0, 0)
with open("owners.pseudo", "w") as p, open("owners.debugfs", "w") as d:
    for path, (kind, mode, uid, gid) in sorted(entries.items()):
        if '"' in path or "\n" in path:
            sys.exit(f"cannot name {path!r} to mksquashfs and debugfs")
        if path == "/":
            open("owners.root", "w").write(f"{mode:o}\n")
        else:
            # mksquashfs reads backslash escapes (systemd's unit names have "\\x2d").
            esc = path.replace("\\", "\\\\")
            p.write(f'"{esc}" m {mode:o} {uid} {gid}\n')
        d.write(f'sif "{path}" mode 0{kind | mode:o}\nsif "{path}" uid {uid}\nsif "{path}" gid {gid}\n')
PY
}

for squashfs in *.squashfs; do
    name="${squashfs%.squashfs}"
    # An image made before it had 4 KiB blocks is made again.
    if [[ -s "$squashfs.orig" && -s "$name.ext4" ]] &&
        [[ "$("$E2/dumpe2fs" -h "$name.ext4" 2>/dev/null | awk '/^Block size:/ { print $3 }')" == 4096 ]]; then
        continue
    fi
    echo "setting up $name"
    src="$squashfs"
    [[ -s "$squashfs.orig" ]] && src="$squashfs.orig"
    if [[ -z "$vol" ]]; then
        rm -f extract.sparseimage
        hdiutil create -quiet -size 4g -type SPARSE -fs "Case-sensitive APFS" -volname wick-extract extract.sparseimage
        vol="$(mktemp -d "$dir/extract.XXXX")"
        hdiutil attach -quiet -nobrowse -owners on -mountpoint "$vol" extract.sparseimage
    fi
    tree="$vol/root"
    remove_tree
    owners "$src"
    unsquashfs -q -no-xattrs -d "$tree" "$src" >/dev/null
    # Readable to be copied; the images get the listed modes back.
    chmod -R u+rwX "$tree"
    mkdir -p "$tree/root/.ssh"
    cp id_rsa.pub "$tree/root/.ssh/authorized_keys"
    rm -f "$name.id_rsa"  # found read-only (0400) when made again
    cp id_rsa "$name.id_rsa"
    [[ -s "$squashfs.orig" ]] || mv "$squashfs" "$squashfs.orig"
    mksquashfs "$tree" "$squashfs" -all-root -root-mode "$(cat owners.root)" -pf owners.pseudo \
        -noappend -comp zstd -quiet >/dev/null

    rm -f "$name.ext4"
    truncate -s 500M "$name.ext4"
    "$E2/mkfs.ext4" -q -F -d "$tree" "$name.ext4"
    "$E2/debugfs" -w -f owners.debugfs "$name.ext4" >/dev/null 2>debugfs.err
    if grep -v '^debugfs ' debugfs.err | grep -q .; then
        cat debugfs.err >&2
        exit 1
    fi
    "$E2/e2fsck" -fn "$name.ext4" >/dev/null
    remove_tree
done

