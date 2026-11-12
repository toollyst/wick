# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Firecracker's gdb stub on macOS, with upstream's aarch64 CI kernel.

    tools/macos/gdb-test.sh [--gdb PATH]

Upstream's test_gdb_connects (tests/integration_tests/functional/test_gdb.py)
runs on x86_64 only ("GDB requires a vmlinux but we ship a uImage for ARM in
our CI"). Its aarch64 debug kernel cannot stand in: debug/vmlinux-6.1.188 is
a PE file without the arm64 Image header (no "ARM\\x64" magic at 0x38,
measured), which Firecracker's loader refuses (linux-loader 0.14.0
src/loader/pe/mod.rs: InvalidImageMagicNumber), and its .debug file has the
symbols of that build, not of a kernel Firecracker boots. So this test boots
the CI kernel every other test boots (vmlinux-6.1.188, an Image) and takes
the addresses from the guest itself, in a first boot without gdb: the
symbols from /proc/kallsyms (no KASLR: CONFIG_RANDOMIZE_BASE is not set, so
the next boot has the same), and the kernel's start through the linear map
from /proc/kcore (fs/proc/kcore.c: a KCORE_RAM segment's p_vaddr is the
linear map's address of its p_paddr; the KCORE_TEXT one's p_paddr is
_text's physical address). gdb then needs no symbol file. The checks are
those of the Windows gdb stage (tools/windows/boot-test.ps1, Stage-Gdb), on
aarch64:

- upstream's session: Firecracker waits for gdb; gdb connects to the stub's
  socket, a hardware breakpoint at start_kernel is hit (DBGBCR/DBGBVR,
  KVM_GUESTDBG_USE_HW) and the PC is start_kernel;
- what the stub reads through its address translation (its walk of the
  guest's TTBR1_EL1 tables, gdb/arch/aarch64.rs translate_gva) is the
  Image's: at start_kernel, through the kernel image's mapping, and, at a
  software breakpoint at rest_init (BRK, KVM_GUESTDBG_USE_SW_BP; gdb steps
  over it, KVM_GUESTDBG_SINGLESTEP), at _text through the linear map (the
  Image is the kernel from _text on: its header's text_offset is 0);
- the guest then boots on under gdb, and its shell answers.

gdb reaches the socket by its path (`target remote <path>`, as upstream's
test) if it can; otherwise through a TCP relay, and the summary says which.
The VM helpers are tools/macos/boot-test.py's; results go to OUT/gdb.
"""

import argparse
import base64
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("boot_test", os.path.join(HERE, "boot-test.py"))
bt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bt)
Failure, check = bt.Failure, bt.check

# Run in the guest (python3 of the CI rootfs) as root: the symbols, and the
# linear map's address of _text's physical address, from the kernel's own
# /proc/kallsyms and /proc/kcore program headers.
GUEST_ADDRESSES = r"""
import struct
want = {"start_kernel", "rest_init", "_text"}
syms = {}
for line in open("/proc/kallsyms"):
    a, _, n = line.split()[:3]
    if n in want:
        syms.setdefault(n, int(a, 16))
with open("/proc/kcore", "rb") as f:
    h = f.read(64)
    phoff, = struct.unpack_from("<Q", h, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", h, 0x36)
    f.seek(phoff)
    ph = f.read(phentsize * phnum)
loads = [struct.unpack_from("<IIQQQQQQ", ph, i * phentsize) for i in range(phnum)]
loads = [(v, p, m) for t, _, _, v, p, _, m, _ in loads if t == 1]
text_phys = next(p for v, p, m in loads if v == syms["_text"])
linear = next(v + text_phys - p for v, p, m in loads
              if v != syms["_text"] and p <= text_phys < p + m and v >= 0xffff000000000000)
print("WICK-ADDR", *(f"{n}={syms[n]:x}" for n in sorted(want)), f"text_phys={text_phys:x}", f"text_linear={linear:x}")
"""


def image_bytes(image, offset, n=16):
    """`n` bytes of the arm64 Image at `offset` from _text: the Image is the
    kernel from _text on when its header's text_offset is 0
    (Documentation/arch/arm64/booting.rst: magic "ARM\\x64" at 0x38,
    text_offset at 0x8)."""
    with open(image, "rb") as f:
        head = f.read(64)
        check(head[0x38:0x3C] == b"ARM\x64", f"{image}: no arm64 Image header")
        check(struct.unpack_from("<Q", head, 0x8)[0] == 0, f"{image}: text_offset is not 0")
        f.seek(offset)
        data = f.read(n)
    check(len(data) == n and any(data), f"{image} at {offset:#x}: {data.hex()} (no code there)")
    return data


def find_gdb(given):
    gdb = given or shutil.which("gdb") or shutil.which("gdb", path="/opt/homebrew/bin")
    check(gdb is not None, "no gdb: brew install gdb (it debugs aarch64 Linux targets through a remote stub), "
          "or pass --gdb")
    return gdb


def run_gdb(gdb, script, out):
    """gdb in batch mode with `script`, without a symbol file; its output
    (both streams) in `out`. Returns the process."""
    with open(out + ".gdb", "w") as f:
        f.write(script)
    log = open(out, "w")
    return subprocess.Popen([gdb, "-nx", "-batch", "-x", out + ".gdb"],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)


def text_of(out):
    with open(out, errors="replace") as f:
        return f.read()


def gdb_bytes(text, marker):
    """The bytes gdb's `x/16xb` printed on the two lines after `marker`."""
    at = text.find(marker + "\n")
    check(at >= 0, f"no {marker} in gdb's output:\n{text}")
    lines = text[at + len(marker) + 1:].splitlines()[:2]
    values = [int(v, 16) for line in lines for v in re.findall(r"0x([0-9a-f]{2})\b", line.split(":", 1)[-1])]
    check(len(values) == 16, f"gdb's x/16xb after {marker}: {lines}")
    return bytes(values)


class Relay:
    """A TCP port on 127.0.0.1 whose one connection is joined to the Unix
    socket `path`: for a gdb that does not reach a Unix socket by its path."""

    def __init__(self, path):
        self.path = path
        self.error = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.socks = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            tcp, _ = self.listener.accept()
            unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix.connect(self.path)
            self.socks += [tcp, unix]
            for a, b in ((tcp, unix), (unix, tcp)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()
        except OSError as e:
            self.error = str(e)

    @staticmethod
    def _pipe(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def stop(self):
        for s in [self.listener] + self.socks:
            s.close()


SESSION = """set pagination off
set confirm off
set architecture aarch64
target remote @TARGET@
hbreak *0x@start_kernel@
continue
printf "WICK-PC %lx\\n", $pc
printf "WICK-X1\\n"
x/16xb 0x@start_kernel@
break *0x@rest_init@
continue
printf "WICK-REST %lx\\n", $pc
printf "WICK-X2\\n"
x/16xb 0x@text_linear@
continue
"""


def guest_addresses(ctx):
    """A boot without gdb: the guest's addresses (GUEST_ADDRESSES)."""
    vm = ctx.vm("gdb-addresses", [], bt.config(ctx), api=False)
    vm.shell()
    with open(os.path.join(ctx.dir, "addresses.py"), "w") as f:
        f.write(GUEST_ADDRESSES)
    # The script over the serial console, on one line short of the tty's
    # 4095-byte line: python3 -c with the source compressed, in base64.
    packed = base64.b64encode(zlib.compress(GUEST_ADDRESSES.encode(), 9)).decode()
    _, out = vm.sh(f"python3 -c \"import base64, zlib; exec(zlib.decompress(base64.b64decode('{packed}')))\"",
                   timeout=60)
    m = re.search(r"WICK-ADDR (.*)$", out, re.M)
    check(m is not None, f"the guest's addresses: {out!r}")
    addr = {k: int(v, 16) for k, v in (kv.split("=") for kv in m.group(1).split())}
    vm.reboot()
    return addr


def stage_gdb(ctx):
    addr = guest_addresses(ctx)
    for name in ("start_kernel", "rest_init"):
        check(addr["_text"] < addr[name], f"{name} {addr[name]:#x} before _text {addr['_text']:#x}")
    file_bytes = {"start_kernel": image_bytes(ctx.kernel, addr["start_kernel"] - addr["_text"]),
                  "_text": image_bytes(ctx.kernel, 0)}
    sock = os.path.join(ctx.sock, "gdb.sock")
    vm = ctx.vm("gdb", [], bt.config(ctx, machine={"gdb_socket_path": sock}), api=False)
    # Firecracker waits for gdb before it runs the guest.
    deadline = time.time() + 30
    while not os.path.exists(sock):
        check(vm.proc.poll() is None and time.time() < deadline, f"no gdb socket at {sock} ({vm.exit_reason()})")
        time.sleep(0.05)
    session = SESSION
    for k, v in addr.items():
        session = session.replace(f"@{k}@", f"{v:x}")
    out = os.path.join(ctx.dir, "gdb-direct.txt")
    g = run_gdb(ctx.gdb, session.replace("@TARGET@", sock), out)
    direct, relay = False, None
    deadline = time.time() + 20
    while time.time() < deadline and g.poll() is None:
        if re.search(r"WICK-PC|Remote debugging using", text_of(out)):
            direct = True
            break
        time.sleep(0.2)
    try:
        if not direct:
            tail = " | ".join(text_of(out).strip().splitlines()[-2:])
            g.kill()
            g.wait()
            print(f"   gdb does not reach the Unix socket by its path ({tail}); through a TCP relay", flush=True)
            check(os.path.exists(sock), "the gdb socket went away after the direct attempt")
            relay = Relay(sock)
            out = os.path.join(ctx.dir, "gdb-relay.txt")
            g = run_gdb(ctx.gdb, session.replace("@TARGET@", f"127.0.0.1:{relay.port}"), out)
        done = re.compile(r"WICK-X2\n.*\n.*\n", re.M)
        deadline = time.time() + ctx.timeout
        while time.time() < deadline and g.poll() is None and not done.search(text_of(out)):
            time.sleep(0.2)
        text = text_of(out)
        shutil.copyfile(out, os.path.join(ctx.dir, "gdb-session.txt"))
        check(relay is None or relay.error is None, f"relay: {relay and relay.error}")
        start = addr["start_kernel"]
        check(re.search(rf"(Hardware assisted breakpoint|Breakpoint) 1, 0x0*{start:x}\b", text),
              f"the hardware breakpoint at start_kernel ({start:#x}) was not hit:\n{text}")
        m = re.search(r"^WICK-PC ([0-9a-f]+)$", text, re.M)
        check(m and int(m.group(1), 16) == start, f"the PC at the breakpoint is not start_kernel ({start:#x}):\n{text}")
        seen = gdb_bytes(text, "WICK-X1")
        check(seen == file_bytes["start_kernel"],
              f"start_kernel through the stub: {seen.hex()}, in the Image: {file_bytes['start_kernel'].hex()}")
        rest = addr["rest_init"]
        check(re.search(rf"Breakpoint 2, 0x0*{rest:x}\b", text),
              f"the software breakpoint at rest_init ({rest:#x}) was not hit:\n{text}")
        m = re.search(r"^WICK-REST ([0-9a-f]+)$", text, re.M)
        check(m and int(m.group(1), 16) == rest, f"the PC at the software breakpoint is not rest_init:\n{text}")
        seen = gdb_bytes(text, "WICK-X2")
        check(seen == file_bytes["_text"],
              f"_text through the linear map ({addr['text_linear']:#x}): {seen.hex()}, "
              f"in the Image: {file_bytes['_text'].hex()}")
        # gdb's last `continue`: the guest boots on under it.
        vm.shell()
        _, said = vm.sh("echo gdb-$((6*7))")
        check(said == "gdb-42", f"the guest under gdb: {said!r}")
    finally:
        if g.poll() is None:
            g.kill()
            g.wait()
        if relay:
            relay.stop()
    vm.kill()
    how = "by the socket's path" if direct else "through a TCP relay (this gdb does not reach a Unix socket by its path)"
    return (f"gdb {how}: hardware breakpoint at start_kernel, its bytes and _text's through the linear map as "
            "in the Image, software breakpoint at rest_init, the guest boots on")


class Context(bt.Context):
    def __init__(self, args):  # pylint: disable=super-init-not-called
        self.firecracker = args.firecracker
        self.out = args.out
        self.dir = os.path.join(args.out, "gdb")
        os.makedirs(self.dir, exist_ok=True)
        self.timeout = args.timeout
        self.gdb = find_gdb(args.gdb)
        self.kernel = bt.fetch(args.cache, bt.KERNEL)
        self.rootfs = bt.fetch(args.cache, bt.ROOTFS)
        # Unix socket paths must be shorter than 104 bytes; tools/clean.sh
        # knows boot-test's prefix.
        self.sock = tempfile.mkdtemp(prefix="wick-bt-", dir="/tmp")
        self.vms = []


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--firecracker", required=True, help="a Firecracker built with the gdb feature")
    p.add_argument("--gdb", help="the gdb client (default: gdb on PATH, else Homebrew's)")
    p.add_argument("--cache", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=int, default=300, help="seconds for the gdb session")
    args = p.parse_args()
    os.makedirs(args.out, exist_ok=True)
    bt.exit_on_signals()
    print("== gdb", flush=True)
    t0 = time.time()
    ctx = None
    try:
        ctx = Context(args)
        print(f"   gdb: {ctx.gdb}", flush=True)
        results = [("gdb", True, stage_gdb(ctx))]
    except Failure as e:
        results = [("gdb", False, str(e))]
    finally:
        if ctx is not None:
            ctx.cleanup()
            shutil.rmtree(ctx.sock, ignore_errors=True)
    ok, detail = results[0][1:]
    print(f"   {'PASS' if ok else 'FAIL'} ({time.time() - t0:.1f}s): {detail}", flush=True)
    sys.exit(1 if bt.summarize(args.out, results) else 0)


if __name__ == "__main__":
    main()
