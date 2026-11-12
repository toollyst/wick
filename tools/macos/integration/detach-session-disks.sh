#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Detaches the disk images an integration test session attached and left
# attached (a test that failed before its own detach, a worker killed):
# bin/losetup's and wick_macos.small_tmpfs's RAM disks record each disk in
# SESSION/.attached/ and remove the record once detached.
#
#   tools/macos/integration/detach-session-disks.sh SESSION
#
# Exits 1 naming a disk that would not detach.
set -uo pipefail
session="$1"
failed=0
for a in "$session"/.attached/disk*; do
    [[ -e "$a" ]] || continue
    dev="/dev/${a##*/}"
    if hdiutil detach "$dev" >/dev/null 2>&1 || hdiutil detach -force "$dev" >/dev/null 2>&1; then
        rm -f "$a"
    # hdiutil's whole output first: under pipefail, grep -q's early exit
    # would fail the pipeline (SIGPIPE) for a disk still attached.
    elif info="$(hdiutil info 2>/dev/null)" && ! grep -qE "^$dev([[:space:]]|$)" <<<"$info"; then
        rm -f "$a" # gone already
    else
        echo "cannot detach $dev (attached by the session $session)" >&2
        failed=1
    fi
done
exit "$failed"
