#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Linux's side of the guest-RAM record of a booted guest (GUESTRAM lines):
what upstream Firecracker's guest memory is resident and charged after the
guest's shell answered, and again after GUEST_WORK, for huge_pages "None"
and "Transparent". tools/windows/vmm-memory-record.py --boot prints the same
for Windows (VMMGUEST lines): the same kernel, root file system, boot
arguments, memory size, network interface and work.

  sudo tools/linux/guest-ram-record.py [--tap NAME] FIRECRACKER WORKDIR [VCPUS ...]
  sudo tools/linux/guest-ram-record.py --snapshot FIRECRACKER WORKDIR
  tools/linux/guest-ram-record.py --selftest

WORKDIR is tools/linux/boot-test.sh's --workdir (the kernel and rootfs are
there). VCPUS defaults to 1 2 16, vmm-memory-record.py's cases. --tap names
a TAP device for the guest's network interface (the Windows record has one);
without it the guest has none, and the lines say so.

For each case, the guest memory's mappings (the anonymous ones of at least
GUEST_MIB, /proc/PID/smaps): their Rss and AnonHugePages; the pages present
(/proc/PID/pagemap, bit 63) and the 64 KiB blocks and 2 MiB ranges they fall
in, the figures vmm-memory-record.py gives by commit grain on Windows; the
process's smaps_rollup Rss and AnonHugePages; and, run as root, the
memory.current and memory.stat anon of a cgroup of the case's own
(memory.max's count). The host's transparent_hugepage settings come first:
whether huge_pages "None" faults its guest memory in 4 KiB pages ("madvise",
"never") or 2 MiB ("always"), and each multi-size THP size's setting
(hugepages-<size>kB/enabled, Linux 6.8 and later): with all of them
"never", an anonymous fault is one 4 KiB page, the grain FIRSTTOUCH's
per-page cost on Windows is set against. A record: it fails only when a
guest does not boot to its shell.

With --snapshot it prints GUESTSNAP lines instead: what the host's reads of
guest memory for a snapshot charge, and what a restore from the snapshot's
file charges, as tools/windows/vmm-memory-record.py --snapshot prints
Windows' (VMMSNAP lines; the same guest, steps and work). One microVM of
SNAP_MIB with dirty page tracking, 1 vCPU and no network interface, driven
through its API socket: after the shell; after SNAP_WORK (64 MiB of tmpfs);
paused, after a full snapshot; resumed, after SNAP_MORE (128 pages of a
sparse tmpfs file); paused, after a diff snapshot. Then the page cache is
written back and dropped (so that the restore reads the file, as a restore
on a host that has not just written it does), a new Firecracker in a cgroup
of its own loads the full snapshot with the File backend, and the lines
follow the load and the restored guest's shell. Each line gives the guest
memory's mappings (the anonymous ones and the snapshot file's) with their
Rss and Anonymous, the smaps_rollup, and the cgroup's memory.current and
memory.stat anon and file (the page cache charged to it); a snapshot's line
gives how long the request took and the file's size and allocated bytes.
"""
import ast
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time

KERNEL = "vmlinux-6.1.188"
ROOTFS = "ubuntu-24.04.squashfs"
BOOT_ARGS = ("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro "
             "rootfstype=squashfs init=/bin/sh")
GUEST_MIB = 128
GUEST_MAC = "06:00:ac:10:00:02"
# What the guest does before the second line, word for word
# tools/windows/vmm-memory-record.py's GUEST_WORK (the selftest compares).
GUEST_WORK = ("mount -t tmpfs tmpfs /tmp; dd if=/dev/zero of=/tmp/dense bs=1M count=32 2>/dev/null; i=0; "
              "while [ $i -lt 32 ]; do dd if=/dev/zero of=/tmp/sparse bs=4096 count=1 seek=$((i*512)) "
              "conv=notrunc 2>/dev/null; i=$((i+1)); done; echo WICK-$((6*7))-WORKED")
# The snapshot record's guest and work, word for word vmm-memory-record.py's
# (the selftest compares): a guest of 1 GiB that touches 64 MiB, then 128
# pages more, one at each 64 KiB of a sparse file.
SNAP_MIB = 1024
SNAP_WORK = ("mount -t tmpfs tmpfs /tmp; dd if=/dev/zero of=/tmp/dense bs=1M count=64 2>/dev/null; "
             "echo WICK-$((6*7))-WORKED")
SNAP_MORE = ("i=0; while [ $i -lt 128 ]; do dd if=/dev/urandom of=/tmp/sparse bs=4096 count=1 seek=$((i*16)) "
             "conv=notrunc 2>/dev/null; i=$((i+1)); done; echo WICK-$((6*7))-MORE")
PAGE, GRANULE, HUGE = 4096, 64 << 10, 2 << 20
CGROUP = "/sys/fs/cgroup"


def read(path, default="(not read)"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default


def mthp_sizes(thp):
    """Each multi-size THP size's setting under the transparent_hugepage
    directory `thp` (hugepages-<size>kB/enabled, Linux 6.8 and later), in
    size order, as one text: a size "never" (or "inherit" of a top-level
    "never" or "madvise" without MADV_HUGEPAGE) leaves an anonymous fault
    one 4 KiB page, which FIRSTTOUCH's per-page comparison takes."""
    try:
        names = [n for n in os.listdir(thp) if re.fullmatch(r"hugepages-\d+kB", n)]
    except OSError:
        return "(no mTHP sizes: not read)"
    if not names:
        return "(no mTHP sizes: a kernel before 6.8)"
    names.sort(key=lambda n: int(n[len("hugepages-"):-len("kB")]))
    return ", ".join(f"{n[len('hugepages-'):]} {read(os.path.join(thp, n, 'enabled'))}" for n in names)


def guest_mappings(smaps):
    """The anonymous mappings of at least GUEST_MIB in an smaps text:
    (start, end, Rss KiB, AnonHugePages KiB, flags)."""
    out, current = [], None
    for line in smaps.splitlines():
        head = re.match(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ (\d+)\s*(.*)$", line)
        if head:
            start, end = int(head.group(1), 16), int(head.group(2), 16)
            name = head.group(5)
            anonymous = head.group(4) == "0" and (not name or name.startswith("[anon:"))
            current = [start, end, 0, 0, ""] if anonymous and end - start >= GUEST_MIB << 20 else None
            if current:
                out.append(current)
            continue
        if current is None:
            continue
        field = re.match(r"^(Rss|AnonHugePages):\s+(\d+) kB", line)
        if field:
            current[2 if field.group(1) == "Rss" else 3] = int(field.group(2))
        elif line.startswith("VmFlags:"):
            current[4] = line.split(":", 1)[1].strip()
    return [tuple(m) for m in out]


def present_counts(addresses):
    """The pages present and the 64 KiB blocks and 2 MiB ranges they fall in."""
    return {"pages": len(addresses), "blocks": len({a // GRANULE for a in addresses}),
            "ranges": len({a // HUGE for a in addresses})}


def present_pages(pid, start, end):
    """The addresses of [start, end) present in the process (pagemap bit 63)."""
    with open(f"/proc/{pid}/pagemap", "rb") as f:
        f.seek(start // PAGE * 8)
        raw = f.read((end - start) // PAGE * 8)
    return [start + i * PAGE for i in range(len(raw) // 8)
            if int.from_bytes(raw[i * 8:i * 8 + 8], "little") >> 63]


def rollup(pid):
    text = read(f"/proc/{pid}/smaps_rollup", "")
    fields = dict(re.findall(r"^(Rss|AnonHugePages):\s+(\d+) kB", text, re.M))
    return f"smaps_rollup Rss {fields.get('Rss', '?')} KiB, AnonHugePages {fields.get('AnonHugePages', '?')} KiB"


def cgroup_text(group, file=False):
    if not group:
        return "no cgroup of its own (not root)"
    stat = dict(line.split() for line in read(f"{group}/memory.stat", "").splitlines() if len(line.split()) == 2)
    current = read(f"{group}/memory.current", "")

    def kib(value):
        return int(value) // 1024 if value and value.isdigit() else "?"
    return (f"its cgroup's memory.current {kib(current)} KiB, anon {kib(stat.get('anon'))} KiB"
            + (f", file {kib(stat.get('file'))} KiB" if file else ""))


def guest_line(pid, group):
    parts = []
    for start, end, rss, huge, flags in guest_mappings(read(f"/proc/{pid}/smaps", "")):
        counts = present_counts(present_pages(pid, start, end))
        parts.append(f"mapping {start:#x}-{end:#x} ({(end - start) >> 20} MiB, flags {flags}): Rss {rss} KiB, "
                     f"AnonHugePages {huge} KiB; pages present {counts['pages']}, in 64 KiB blocks "
                     f"{counts['blocks']} and 2 MiB ranges {counts['ranges']}")
    if not parts:
        parts.append("no guest memory mapping found")
    return "; ".join(parts + [rollup(pid), cgroup_text(group)])


class Console:
    """The guest's serial console: Firecracker's standard input and the file
    its standard output goes to."""

    def __init__(self, proc, path):
        self.proc, self.path = proc, path

    def send(self, line):
        try:
            self.proc.stdin.write(line.encode() + b"\n")
            self.proc.stdin.flush()
        except OSError:
            pass

    def wait(self, pattern, seconds, again=None):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self.proc.poll() is None:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                if re.search(pattern, f.read()):
                    return True
            if again is not None:
                self.send(again)
            time.sleep(1)
        return False


def run_case(fc, workdir, work, huge, vcpus, tap, n):
    config = {"boot-source": {"kernel_image_path": os.path.join(workdir, KERNEL), "boot_args": BOOT_ARGS},
              "drives": [{"drive_id": "rootfs", "path_on_host": os.path.join(workdir, ROOTFS),
                          "is_root_device": True, "is_read_only": True}],
              "machine-config": {"vcpu_count": vcpus, "mem_size_mib": GUEST_MIB, "huge_pages": huge}}
    if tap:
        config["network-interfaces"] = [{"iface_id": "eth0", "host_dev_name": tap, "guest_mac": GUEST_MAC}]
    path = os.path.join(work, f"config-{n}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    group = None
    if os.geteuid() == 0 and os.path.exists(f"{CGROUP}/cgroup.controllers"):
        group = f"{CGROUP}/wick-guest-ram-{os.getpid()}-{n}"
        os.makedirs(group, exist_ok=True)

    def into_group():
        if group:
            with open(f"{group}/cgroup.procs", "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))

    tag = f"GUESTRAM huge_pages={huge} vcpus={vcpus} network={'yes' if tap else 'none'}"
    out = os.path.join(work, f"serial-{n}.txt")
    with open(out, "wb") as console_file:
        proc = subprocess.Popen([fc, "--no-api", "--config-file", path], stdin=subprocess.PIPE,
                                stdout=console_file, stderr=subprocess.STDOUT, preexec_fn=into_group)
    try:
        console = Console(proc, out)
        started = time.monotonic()
        if not console.wait(r"WICK-42-UP", 300, again="echo WICK-$((6*7))-UP"):
            with open(out, "r", encoding="utf-8", errors="replace") as f:
                tail = " | ".join(f.read().splitlines()[-6:])
            print(f"{tag}: no shell (exit {proc.poll()}): {tail}")
            return False
        print(f"{tag} after the shell ({time.monotonic() - started:.1f} s): {guest_line(proc.pid, group)}")
        started = time.monotonic()
        console.send(GUEST_WORK)
        if console.wait(r"WICK-42-WORKED", 120):
            print(f"{tag} after the work ({time.monotonic() - started:.1f} s): {guest_line(proc.pid, group)}")
        else:
            print(f"{tag} after the work: the guest did not finish it")
        return True
    finally:
        proc.kill()
        proc.wait()
        if group:
            for _ in range(50):
                try:
                    os.rmdir(group)
                    break
                except OSError:
                    time.sleep(0.1)


def snapshot_mappings(smaps, path):
    """The guest memory's mappings in an smaps text: the anonymous ones of at
    least GUEST_MIB and those of the file `path` (a restored guest's):
    (start, end, Rss KiB, Anonymous KiB, what)."""
    out, current = [], None
    for line in smaps.splitlines():
        head = re.match(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ (\d+)\s*(.*)$", line)
        if head:
            start, end = int(head.group(1), 16), int(head.group(2), 16)
            name = head.group(5).strip()
            anonymous = head.group(4) == "0" and (not name or name.startswith("[anon:"))
            if anonymous and end - start >= GUEST_MIB << 20:
                current = [start, end, 0, 0, "anonymous"]
            elif path and name == path:
                current = [start, end, 0, 0, f"of {os.path.basename(path)}"]
            else:
                current = None
            if current:
                out.append(current)
            continue
        if current is None:
            continue
        field = re.match(r"^(Rss|Anonymous):\s+(\d+) kB", line)
        if field:
            current[2 if field.group(1) == "Rss" else 3] = int(field.group(2))
    return [tuple(m) for m in out]


def snapshot_line(pid, group, path=None):
    parts = [f"mapping {start:#x}-{end:#x} ({(end - start) >> 20} MiB, {what}): Rss {rss} KiB, Anonymous {anon} KiB"
             for start, end, rss, anon, what in snapshot_mappings(read(f"/proc/{pid}/smaps", ""), path)]
    return "; ".join((parts or ["no guest memory mapping found"]) + [rollup(pid), cgroup_text(group, file=True)])


def api(sock, method, path, body=None, seconds=600):
    """One request to Firecracker's API socket: (HTTP status, body)."""
    args = ["curl", "-s", "-m", str(seconds), "-o", "-", "-w", " %{http_code}", "--unix-socket", sock,
            "-X", method, f"http://localhost{path}"]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(body)]
    out = subprocess.run(args, capture_output=True, text=True, check=False).stdout.rstrip()
    text, _, code = out.rpartition(" ")
    return (int(code) if code.isdigit() else 0), text


def api_ok(sock, method, path, body=None):
    status, text = api(sock, method, path, body)
    if not 200 <= status < 300:
        raise RuntimeError(f"{method} {path} -> {status} {text[:300]}")
    return text


def wait_api(sock, proc, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and proc.poll() is None:
        if api(sock, "GET", "/", seconds=2)[0] == 200:
            return True
        time.sleep(0.1)
    return False


def file_text(path):
    st = os.stat(path)
    return f"file {st.st_size >> 20} MiB, allocated {st.st_blocks * 512 >> 20} MiB"


def snapshot_case(fc, workdir, work):
    """The GUESTSNAP lines; False when a guest does not reach its shell."""
    tag = f"GUESTSNAP mem={SNAP_MIB} MiB vcpus=1"
    config = {"boot-source": {"kernel_image_path": os.path.join(workdir, KERNEL), "boot_args": BOOT_ARGS},
              "drives": [{"drive_id": "rootfs", "path_on_host": os.path.join(workdir, ROOTFS),
                          "is_root_device": True, "is_read_only": True}],
              "machine-config": {"vcpu_count": 1, "mem_size_mib": SNAP_MIB, "track_dirty_pages": True}}
    path = os.path.join(work, "snap-config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    full_mem, full_state = os.path.join(work, "full.mem"), os.path.join(work, "full.state")
    diff_mem, diff_state = os.path.join(work, "diff.mem"), os.path.join(work, "diff.state")
    root = os.geteuid() == 0 and os.path.exists(f"{CGROUP}/cgroup.controllers")
    groups = []

    def start(n, args):
        group = f"{CGROUP}/wick-guest-snap-{os.getpid()}-{n}" if root else None
        if group:
            os.makedirs(group, exist_ok=True)
            groups.append(group)

        def into_group():
            if group:
                with open(f"{group}/cgroup.procs", "w", encoding="utf-8") as f:
                    f.write(str(os.getpid()))
        sock, out = os.path.join(work, f"api-{n}.sock"), os.path.join(work, f"snap-serial-{n}.txt")
        with open(out, "wb") as console_file:
            proc = subprocess.Popen([fc, "--api-sock", sock] + args, stdin=subprocess.PIPE,
                                    stdout=console_file, stderr=subprocess.STDOUT, preexec_fn=into_group)
        return proc, Console(proc, out), sock, group, out

    def tail(out):
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            return " | ".join(f.read().splitlines()[-6:])

    procs = []
    try:
        proc, console, sock, group, out = start(1, ["--config-file", path])
        procs.append(proc)
        started = time.monotonic()
        if not wait_api(sock, proc) or not console.wait(r"WICK-42-UP", 300, again="echo WICK-$((6*7))-UP"):
            print(f"{tag}: no shell (exit {proc.poll()}): {tail(out)}")
            return False
        print(f"{tag} after the shell ({time.monotonic() - started:.1f} s): {snapshot_line(proc.pid, group)}")
        console.send(SNAP_WORK)
        if not console.wait(r"WICK-42-WORKED", 120):
            print(f"{tag} after the work: the guest did not finish it")
            return True
        print(f"{tag} after the work: {snapshot_line(proc.pid, group)}")
        api_ok(sock, "PATCH", "/vm", {"state": "Paused"})
        started = time.monotonic()
        api_ok(sock, "PUT", "/snapshot/create",
               {"snapshot_type": "Full", "snapshot_path": full_state, "mem_file_path": full_mem})
        took = time.monotonic() - started
        print(f"{tag} paused, after the full snapshot ({took:.2f} s; {file_text(full_mem)}): "
              f"{snapshot_line(proc.pid, group)}")
        api_ok(sock, "PATCH", "/vm", {"state": "Resumed"})
        console.send(SNAP_MORE)
        if not console.wait(r"WICK-42-MORE", 120):
            print(f"{tag} after the second work: the guest did not finish it")
            return True
        print(f"{tag} resumed, after the second work: {snapshot_line(proc.pid, group)}")
        api_ok(sock, "PATCH", "/vm", {"state": "Paused"})
        started = time.monotonic()
        api_ok(sock, "PUT", "/snapshot/create",
               {"snapshot_type": "Diff", "snapshot_path": diff_state, "mem_file_path": diff_mem})
        took = time.monotonic() - started
        print(f"{tag} paused, after the diff snapshot ({took:.2f} s; {file_text(diff_mem)}): "
              f"{snapshot_line(proc.pid, group)}")
        proc.kill()
        proc.wait()
        # The restore reads the file, not what the snapshot left in the cache.
        dropped = "page cache kept (not root)"
        if root:
            os.sync()
            with open("/proc/sys/vm/drop_caches", "w", encoding="utf-8") as f:
                f.write("1")
            dropped = "page cache written back and dropped first"
        proc, console, sock, group, out = start(2, [])
        procs.append(proc)
        if not wait_api(sock, proc):
            print(f"{tag} load: no API socket (exit {proc.poll()}): {tail(out)}")
            return False
        started = time.monotonic()
        api_ok(sock, "PUT", "/snapshot/load", {"snapshot_path": full_state, "resume_vm": True,
                                              "mem_backend": {"backend_type": "File", "backend_path": full_mem}})
        took = time.monotonic() - started
        print(f"{tag} restored, after the load ({took:.2f} s; {dropped}): {snapshot_line(proc.pid, group, full_mem)}")
        started = time.monotonic()
        if console.wait(r"WICK-42-UP", 60, again="echo WICK-$((6*7))-UP"):
            print(f"{tag} restored, after the shell ({time.monotonic() - started:.1f} s): "
                  f"{snapshot_line(proc.pid, group, full_mem)}")
        else:
            print(f"{tag} restored: no shell (exit {proc.poll()}): {tail(out)}")
        return True
    finally:
        for proc in procs:
            proc.kill()
            proc.wait()
        for group in groups:
            for _ in range(50):
                try:
                    os.rmdir(group)
                    break
                except OSError:
                    time.sleep(0.1)


def selftest():
    smaps = ("7f0000000000-7f0008000000 rw-p 00000000 00:00 0 \n"
             "Size:             131072 kB\nRss:                2048 kB\nAnonHugePages:      2048 kB\n"
             "VmFlags: rd wr mr mw me ac nr hg\n"
             "7f0008000000-7f0008001000 rw-p 00000000 00:00 0 \nRss: 4 kB\n"
             "7f0010000000-7f0018000000 r--p 00000000 08:01 123 /usr/lib/big\nRss: 8 kB\n")
    assert guest_mappings(smaps) == [(0x7f0000000000, 0x7f0008000000, 2048, 2048, "rd wr mr mw me ac nr hg")], \
        guest_mappings(smaps)
    assert present_counts([0, PAGE, GRANULE, HUGE + PAGE]) == {"pages": 4, "blocks": 3, "ranges": 2}
    windows = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "windows", "vmm-memory-record.py")
    with open(windows, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    theirs = [ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "GUEST_WORK" for t in node.targets)]
    assert theirs == [GUEST_WORK], "GUEST_WORK differs from vmm-memory-record.py's"
    for name, mine in (("SNAP_MIB", SNAP_MIB), ("SNAP_WORK", SNAP_WORK), ("SNAP_MORE", SNAP_MORE)):
        theirs = [ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
        assert theirs == [mine], f"{name} differs from vmm-memory-record.py's"
    assert "WICK-$((6*7))-MORE" in SNAP_MORE and "WICK-42-MORE" not in SNAP_MORE
    smaps += ("7f2000000000-7f2040000000 rw-p 00000000 08:01 77 /w/full.mem\nRss: 65536 kB\nAnonymous: 4096 kB\n"
              "7f3000000000-7f3040000000 rw-p 00000000 00:00 0 \nRss: 8 kB\nAnonymous: 8 kB\n")
    assert snapshot_mappings(smaps, "/w/full.mem") == [
        (0x7f0000000000, 0x7f0008000000, 2048, 0, "anonymous"),
        (0x7f2000000000, 0x7f2040000000, 65536, 4096, "of full.mem"),
        (0x7f3000000000, 0x7f3040000000, 8, 8, "anonymous")], snapshot_mappings(smaps, "/w/full.mem")
    assert [m[4] for m in snapshot_mappings(smaps, None)] == ["anonymous", "anonymous"]
    with tempfile.TemporaryDirectory() as thp:
        assert mthp_sizes(thp) == "(no mTHP sizes: a kernel before 6.8)"
        for size, setting in (("2048kB", "[always] inherit madvise never"), ("16kB", "always inherit madvise [never]"),
                              ("64kB", "always [inherit] madvise never")):
            os.mkdir(os.path.join(thp, "hugepages-" + size))
            with open(os.path.join(thp, "hugepages-" + size, "enabled"), "w", encoding="utf-8") as f:
                f.write(setting + "\n")
        os.mkdir(os.path.join(thp, "khugepaged"))
        assert mthp_sizes(thp) == ("16kB always inherit madvise [never], 64kB always [inherit] madvise never, "
                                   "2048kB [always] inherit madvise never"), mthp_sizes(thp)
    assert mthp_sizes("/nonexistent-thp") == "(no mTHP sizes: not read)"
    print("guest-ram-record.py: selftest ok")


def main(args):
    if args == ["--selftest"]:
        selftest()
        return
    if args[:1] == ["--snapshot"]:
        if len(args) != 3:
            sys.exit(__doc__)
        fc, workdir = os.path.abspath(args[1]), os.path.abspath(args[2])
        thp = "/sys/kernel/mm/transparent_hugepage"
        print(f"GUESTSNAP host: Linux {platform.release()}; transparent_hugepage enabled: {read(thp + '/enabled')}; "
              f"mTHP sizes: {mthp_sizes(thp)}; "
              f"{subprocess.run([fc, '--version'], capture_output=True, text=True).stdout.splitlines()[0]}")
        with tempfile.TemporaryDirectory(prefix="guest-snap-") as work:
            if not snapshot_case(fc, workdir, work):
                sys.exit("GUESTSNAP: a guest did not boot to its shell")
        return
    tap = None
    if args[:1] == ["--tap"]:
        tap, args = args[1], args[2:]
    if len(args) < 2:
        sys.exit(__doc__)
    fc, workdir = os.path.abspath(args[0]), os.path.abspath(args[1])
    counts = [int(a) for a in args[2:]] or [1, 2, 16]
    thp = "/sys/kernel/mm/transparent_hugepage"
    print(f"GUESTRAM host: Linux {platform.release()}; transparent_hugepage enabled: {read(thp + '/enabled')}; "
          f"defrag: {read(thp + '/defrag')}; mTHP sizes: {mthp_sizes(thp)}; overcommit_memory {read('/proc/sys/vm/overcommit_memory')}; "
          f"{subprocess.run([fc, '--version'], capture_output=True, text=True).stdout.splitlines()[0]}")
    ok, n = True, 0
    with tempfile.TemporaryDirectory(prefix="guest-ram-") as work:
        for huge in ("None", "Transparent"):
            for vcpus in counts:
                n += 1
                ok = run_case(fc, workdir, work, huge, vcpus, tap, n) and ok
    if not ok:
        sys.exit("GUESTRAM: a guest did not boot to its shell")


if __name__ == "__main__":
    main(sys.argv[1:])
