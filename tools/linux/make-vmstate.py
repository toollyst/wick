#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Makes one snapshot state file on Linux (KVM), for the other hosts' tests
of a snapshot made on another host OS.

Boots upstream's CI guest that tools/linux/boot-test.sh fetched, pauses it
and takes a full snapshot. The state file is kept (tens of kilobytes); the
memory file is removed unless SNAPSHOTDIR is given. CI uploads the state
file: a macOS (aarch64) host then checks that Firecracker refuses a state
made on Linux x86_64 (tools/macos/foreign-snapshot-test.py).

  tools/linux/make-vmstate.py FIRECRACKER WORKDIR OUTDIR [SNAPSHOTDIR]

WORKDIR is boot-test.sh's --workdir (the kernel and rootfs are there).
Writes OUTDIR/linux-<machine>.vmstate and OUTDIR/linux-<machine>.txt (the
Firecracker version and the host's kernel). Exits non-zero, with the
reason, if any step fails.

With SNAPSHOTDIR the whole snapshot is kept there as well, for a host of
the same architecture to restore (tools/windows/boot-test.ps1,
linux-snapshot): the state file, the memory file (128 MiB) and the text
file, which also has the root drive's size and SHA-256. The drive is named
in the state as Firecracker was given it, by its file name alone
(Firecracker runs in WORKDIR), so that a restore finds it in the directory
it runs in, on any host.
"""
import hashlib
import http.client
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time

KERNEL = "vmlinux-6.1.188"
ROOTFS = "ubuntu-24.04.squashfs"
BOOT_ARGS = ("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro "
             "rootfstype=squashfs init=/bin/sh")


class Api(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


def _wait_api(sock, proc, bound=10):
    """Waits until Firecracker's API answers a GET / with 200; returns None
    then, else why it did not. The socket's path does not say the API is
    there: the path exists from bind(2), the server accepts from listen(2),
    a connection in between is refused, and a Firecracker that ended leaves
    the path behind. This is its own step before the test's first request,
    which is made once. The process is looked at before every attempt."""
    start, last = time.monotonic(), "none made"
    while True:
        if proc.poll() is not None:
            return f"Firecracker ended (exit {proc.returncode}) before its API answered; last attempt: {last}"
        if time.monotonic() - start > bound:
            return f"no answer within {bound} s; last attempt: {last}"
        conn = Api(sock)
        try:
            conn.connect()
            conn.sock.settimeout(bound)
            conn.request("GET", "/")
            status = conn.getresponse().status
            return None if status == 200 else f"GET / -> {status}"
        except (FileNotFoundError, ConnectionRefusedError) as e:
            last = type(e).__name__
        except (OSError, http.client.HTTPException) as e:
            return f"GET /: {e!r}"
        finally:
            conn.close()
        time.sleep(0.02)


def call(sock, method, path, body):
    conn = Api(sock)
    conn.request(method, path, json.dumps(body), {"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    if resp.status not in (200, 204):
        sys.exit(f"make-vmstate: {method} {path} -> {resp.status} {data}")


def main():
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    fc, workdir, outdir = (os.path.abspath(p) for p in sys.argv[1:4])
    keep = os.path.abspath(sys.argv[4]) if len(sys.argv) == 5 else None
    kernel, rootfs = os.path.join(workdir, KERNEL), os.path.join(workdir, ROOTFS)
    for path in (fc, kernel, rootfs):
        if not os.path.exists(path):
            sys.exit(f"make-vmstate: {path} is missing (run tools/linux/boot-test.sh first)")
    os.makedirs(outdir, exist_ok=True)
    machine = platform.machine()
    state = os.path.join(outdir, f"linux-{machine}.vmstate")
    tmp = tempfile.mkdtemp(prefix="vmstate-")
    sock, mem = os.path.join(tmp, "api.sock"), os.path.join(tmp, "mem")
    with open(os.path.join(tmp, "console.txt"), "w") as console:
        proc = subprocess.Popen([fc, "--api-sock", sock], stdin=subprocess.DEVNULL, stdout=console,
                                stderr=subprocess.STDOUT, cwd=workdir)
        try:
            why = _wait_api(sock, proc)
            if why:
                sys.exit(f"make-vmstate: {why}")
            call(sock, "PUT", "/boot-source", {"kernel_image_path": kernel, "boot_args": BOOT_ARGS})
            call(sock, "PUT", "/drives/rootfs", {"drive_id": "rootfs", "path_on_host": ROOTFS, "is_root_device": True,
                                                "is_read_only": True})
            call(sock, "PUT", "/machine-config", {"vcpu_count": 1, "mem_size_mib": 128})
            call(sock, "PUT", "/actions", {"action_type": "InstanceStart"})
            # A guest that has run for a moment, as a snapshot's is.
            time.sleep(2)
            if proc.poll() is not None:
                sys.exit(f"make-vmstate: Firecracker exited with {proc.returncode} after the start")
            call(sock, "PATCH", "/vm", {"state": "Paused"})
            call(sock, "PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state,
                                                  "mem_file_path": mem})
            if keep and os.path.exists(mem):
                os.makedirs(keep, exist_ok=True)
                shutil.move(mem, os.path.join(keep, f"linux-{machine}.mem"))
        finally:
            proc.kill()
            proc.wait()
            if os.path.exists(mem):
                os.unlink(mem)
    size = os.path.getsize(state)
    if size == 0:
        sys.exit(f"make-vmstate: {state} is empty")
    version = subprocess.run([fc, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    text = f"{version}\nhost: {platform.platform()}\nstate: {os.path.basename(state)}, {size} bytes\n"
    with open(os.path.join(outdir, f"linux-{machine}.txt"), "w") as f:
        f.write(text)
    if keep:
        digest = hashlib.sha256()
        with open(rootfs, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        with open(state, "rb") as src, open(os.path.join(keep, f"linux-{machine}.vmstate"), "wb") as dst:
            dst.write(src.read())
        with open(os.path.join(keep, f"linux-{machine}.txt"), "w") as f:
            f.write(text + f"memory: linux-{machine}.mem, {os.path.getsize(os.path.join(keep, f'linux-{machine}.mem'))} bytes\n"
                    f"rootfs: {ROOTFS}, {os.path.getsize(rootfs)} bytes, sha256 {digest.hexdigest()}\n")
        print(f"make-vmstate: the whole snapshot is in {keep}")
    print(f"make-vmstate: {state}: {size} bytes ({version}, {platform.platform()})")


if __name__ == "__main__":
    main()
