#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The disks the harness attaches, without a VM: wick_macos.small_tmpfs (the
# tmpfs of test_snapshot_not_losing_dirty_pages.py: a RAM disk with an APFS
# volume), bin/fallocate on it, bin/losetup, and the session's end
# (detach-session-disks.sh, integration-tests.sh's EXIT trap) after a
# worker was killed with its disks attached.
#
#   tools/macos/integration/disks-selftest.sh
#
# Checks:
# - small_tmpfs: a volume of the asked size, mounted on the session's
#   directory, as the user; fallocate of 90% of its free space allocates it
#   (free space falls), then a write fails ENOSPC; on leaving it the disk
#   is detached and the mount point gone;
# - a process killed (SIGKILL) inside small_tmpfs, and one that made a
#   losetup device and was killed: both disks still attached and recorded,
#   then detached by detach-session-disks.sh, records gone;
# - losetup --find --show / --detach: a user-owned block device of the
#   file's size (DKIOCGETBLOCKCOUNT x DKIOCGETBLOCKSIZE);
# - losetup --detach of a device a process holds open: returns 0 at once
#   (Linux: lazy destruction, losetup(8)), the disk stays attached while it
#   is open and is detached, its record gone and its waiter ended, after the
#   last close.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
session="$(mktemp -d /tmp/wit-XXXX)"
fails=0
ok() { echo "ok: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
# hdiutil's whole output first: with pipefail, `hdiutil info | grep -q`
# fails when grep's early exit kills hdiutil with SIGPIPE (measured: 24 of
# 60 checks of the first of two attached disks reported it gone).
attached() {
    local info
    info="$(hdiutil info 2>/dev/null)"
    grep -qE "^$1([[:space:]]|$)" <<<"$info"
}
finish() {
    "$HERE/detach-session-disks.sh" "$session" >/dev/null 2>&1 || true
    rm -rf "$session"
}
trap finish EXIT

py() { WICK_IT_ROOT="$session" PATH="$HERE/bin:$PATH" python3 -I - "$HERE" "$session" "$@"; }

# The fixture's code, as wick_macos defines it, without pytest.
prelude='
import contextlib, errno, os, pathlib, re, shutil, subprocess, sys
here, SESSION_ROOT = sys.argv[1], sys.argv[2]
src = open(os.path.join(here, "wick_macos.py")).read()
exec(src[src.index("RAM_DISK_MIB = 512"):src.index("def _mount_tmpfs_small")])
'

py <<EOF || fail "small_tmpfs"
$prelude
with small_tmpfs("gw7", mib=128) as m:
    mounted = subprocess.run(["mount"], capture_output=True, text=True).stdout
    line = [l for l in mounted.splitlines() if f" on {os.path.realpath(m)} " in l]
    assert line and "mounted by" in line[0], f"not mounted: {m}"
    u = shutil.disk_usage(m)
    assert 100 << 20 < u.total <= 128 << 20, u
    want = round(u.free * 0.9)
    subprocess.check_call(["fallocate", "-l", str(want), str(m / "fill")])
    st = os.stat(m / "fill")
    assert st.st_size == want and st.st_blocks * 512 >= want, st
    assert shutil.disk_usage(m).free < u.free - want * 0.9
    try:
        with open(m / "more", "wb") as f:
            f.write(b"x" * u.free)
        raise AssertionError("no ENOSPC")
    except OSError as e:
        assert e.errno == errno.ENOSPC, e
    disk = [p.name for p in (pathlib.Path(SESSION_ROOT) / ".attached").iterdir()]
    assert len(disk) == 1, disk
    print("disk", disk[0], "volume", line[0].split()[0], "total MiB", u.total >> 20,
          "fallocate MiB", want >> 20)
assert not m.exists(), "mount point left"
assert not list((pathlib.Path(SESSION_ROOT) / ".attached").iterdir()), "record left"
out = subprocess.run(["hdiutil", "info"], capture_output=True, text=True).stdout
assert f"/dev/{disk[0]}\t" not in out and f"/dev/{disk[0]}\n" not in out, "disk left attached"
EOF
((fails)) || ok "small_tmpfs: mounted as the user, fallocate allocates, ENOSPC past it, detached on leaving"

# Killed inside small_tmpfs, and after a losetup.
img="$session/lo.img"
truncate -s 3m "$img"
# Started directly (not through py), so that $! is the Python process.
WICK_IT_ROOT="$session" PATH="$HERE/bin:$PATH" python3 -I - "$HERE" "$session" "$img" <<EOF &
$prelude
import time
dev = subprocess.check_output(["losetup", "--find", "--show", sys.argv[3]], text=True).strip()
print("losetup", dev, flush=True)
with small_tmpfs("gw8", mib=64) as m:
    print("ready", flush=True)
    time.sleep(600)
EOF
victim=$!
for _ in $(seq 300); do
    [[ $(ls "$session/.attached" 2>/dev/null | wc -l) -ge 2 && -d "$session/t8" ]] && mount | grep -q "$session/t8" && break
    sleep 0.2
done
disks=($(ls "$session/.attached"))
kill -KILL "$victim"
wait "$victim" 2>/dev/null || true
hdiutil info >"$session/info-after-kill"
left=0
for d in "${disks[@]}"; do attached "/dev/$d" && left=$((left + 1)); done
if ((${#disks[@]} == 2 && left == 2)); then
    ok "killed worker: ${disks[*]} still attached and recorded"
else
    fail "killed worker: recorded ${disks[*]:-none}, $left attached"
    grep -E "^(image-path|/dev/disk)" "$session/info-after-kill" | sed 's/^/    /'
fi
"$HERE/detach-session-disks.sh" "$session" || fail "detach-session-disks.sh failed"
left=0
for d in "${disks[@]}"; do attached "/dev/$d" && left=$((left + 1)); done
if ((left == 0)) && [[ -z "$(ls "$session/.attached")" ]]; then
    ok "session end: detach-session-disks.sh detached ${disks[*]}"
else
    fail "session end: $left still attached, records: $(ls "$session/.attached")"
fi
rmdir "$session/t8" 2>/dev/null || true

# losetup: a user-owned block device of the file's size.
dev="$(WICK_IT_ROOT="$session" "$HERE/bin/losetup" --find --show "$img")"
python3 -I - "$dev" <<'EOF' && ok "losetup: $dev, the user's, read-write, 3 MiB" || fail "losetup device"
import fcntl, os, struct, sys
fd = os.open(sys.argv[1], os.O_RDWR)
bs = struct.unpack("I", fcntl.ioctl(fd, 0x40046418, b"\0" * 4))[0]
n = struct.unpack("Q", fcntl.ioctl(fd, 0x40086419, b"\0" * 8))[0]
assert os.stat(sys.argv[1]).st_uid == os.getuid() and bs * n == 3 << 20, (bs, n)
EOF
WICK_IT_ROOT="$session" "$HERE/bin/losetup" --detach "$dev" && ! attached "$dev" && [[ ! -e "$session/.attached/${dev#/dev/}" ]] &&
    ok "losetup --detach: detached, record gone" || fail "losetup --detach"

# losetup --detach of a disk in use: detached on its last close.
dev="$(WICK_IT_ROOT="$session" "$HERE/bin/losetup" --find --show "$img")"
python3 -I -c 'import os, sys, time; fd = os.open(sys.argv[1], os.O_RDWR); print(flush=True); time.sleep(600)' "$dev" >"$session/holder" &
holder=$!
for _ in $(seq 50); do [[ -s "$session/holder" ]] && break; sleep 0.1; done
if WICK_IT_ROOT="$session" "$HERE/bin/losetup" --detach "$dev"; then
    sleep 2
    attached "$dev" && [[ -e "$session/.attached/${dev#/dev/}" ]] &&
        ok "losetup --detach of $dev in use: 0, still attached while open" ||
        fail "losetup --detach in use: the disk went while open"
    # Upstream's framework fails a test when a command line names the jail
    # (the image's path) after Firecracker was killed.
    waiter="$(pgrep -f "losetup-lazy-detach $dev " || true)"
    if [[ -n "$waiter" ]] && ! ps -ww -o args= -p "$waiter" | grep -qF "$img"; then
        ok "the waiter's command line does not name the image"
    else
        fail "waiter ${waiter:-none}: $(ps -ww -o args= -p "${waiter:-1}" | tr '\n' ' ' | cut -c1-200)"
    fi
else
    fail "losetup --detach of $dev in use: not 0"
fi
kill "$holder"; wait "$holder" 2>/dev/null || true
for _ in $(seq 100); do attached "$dev" || break; sleep 0.1; done
sleep 0.5
if ! attached "$dev" && [[ ! -e "$session/.attached/${dev#/dev/}" ]] && ! pgrep -f "losetup-lazy-detach $dev " >/dev/null; then
    ok "last close: $dev detached, record gone, waiter ended"
else
    fail "last close: attached $(attached "$dev" && echo yes || echo no), waiter $(pgrep -f "losetup-lazy-detach $dev " || echo none)"
fi

((fails == 0)) && echo "all passed" || { echo "$fails failed"; exit 1; }
