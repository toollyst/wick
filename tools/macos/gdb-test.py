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
from /proc/iomem and /proc/kcore (GUEST_ADDRESSES says how; _text, which
neither lists, is _stext less the Image's offset of _stext). gdb then needs
no symbol file. The checks are
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
gdb is the client that counts, as in upstream's test. When the system's lldb
is there, a third boot runs the same checks with it as an additional client
(its own line in the summary): LLDB connects to a Unix socket by its path
(unix-connect://, lldb/source/Host/posix/ConnectionFileDescriptorPosix.cpp),
asks for a hardware breakpoint with Z1 when `breakpoint set -H` requires one
and a software one with Z0 (ProcessGDBRemote.cpp EnableBreakpointSite), and
reads registers with `g` when the stub has no `p` (ThreadGDBRemote.cpp), as
Firecracker's stub has not (gdbstub's SingleRegisterAccess is not
implemented in gdb/target.rs). The VM helpers are tools/macos/boot-test.py's;
results go to OUT/gdb.
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

# Run in the guest (python3 of the CI rootfs) as root, each address from its
# source:
# - _stext, start_kernel and rest_init: /proc/kallsyms;
# - _stext's physical address: /proc/iomem's "Kernel code", which starts at
#   __pa_symbol(_stext) (arm64 kernel/setup.c, request_standard_resources);
# - its linear map address: the /proc/kcore KCORE_RAM segment that holds it
#   (p_vaddr is the linear map's address of p_paddr, fs/proc/kcore.c), not
#   the kernel text's (KCORE_TEXT, p_paddr __pa_symbol(_text)), which holds
#   the same page at _stext's own address (measured: arm64 6.1 has both).
# _text is in neither: kallsyms keeps only the symbols from _stext on
# (measured on the CI kernel: its first is _stext, there is no _text), and
# kcore has a segment at _text only with CONFIG_ARCH_PROC_KCORE_TEXT. The host
# takes _text, its physical address and its linear map address as these less
# the Image's offset of _stext (`stext_offset`).
GUEST_ADDRESSES = r"""
import struct
want = {"start_kernel", "rest_init", "_stext"}
syms = {}
for line in open("/proc/kallsyms"):
    a, _, n = line.split()[:3]
    if n in want:
        syms.setdefault(n, int(a, 16))
code = [ln for ln in open("/proc/iomem") if ln.strip().endswith(": Kernel code")]
stext_phys = int(code[0].split("-")[0], 16)
with open("/proc/kcore", "rb") as f:
    h = f.read(64)
    phoff, = struct.unpack_from("<Q", h, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", h, 0x36)
    f.seek(phoff)
    ph = f.read(phentsize * phnum)
loads = [struct.unpack_from("<IIQQQQQQ", ph, i * phentsize) for i in range(phnum)]
loads = [(v, p, m) for t, _, _, v, p, _, m, _ in loads if t == 1]
linear = next(v + stext_phys - p for v, p, m in loads
              if p <= stext_phys < p + m and not v <= syms["_stext"] < v + m)
print("WICK-ADDR", *(f"{n}={syms[n]:x}" for n in sorted(want)), f"stext_phys={stext_phys:x}",
      f"stext_linear={linear:x}")
"""


def stext_offset(image):
    """_stext's offset in the arm64 Image from _text: the PE header's
    BaseOfCode, which arm64's efi-header.S sets to `efi_header_end - _head`
    (_head is _text; efi_header_end is at _stext, as the guest's kallsyms
    lists them)."""
    with open(image, "rb") as f:
        head = f.read(4096)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    check(head[pe:pe + 4] == b"PE\0\0", f"{image}: no PE header at {pe:#x}")
    check(struct.unpack_from("<H", head, pe + 24)[0] == 0x20B, f"{image}: not PE32+")
    return struct.unpack_from("<I", head, pe + 24 + 20)[0]


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


def find_tool(given, name, hint):
    tool = given or shutil.which(name) or shutil.which(name, path="/opt/homebrew/bin:/usr/bin")
    check(tool is not None, hint)
    return tool


def find_gdb(given):
    return find_tool(given, "gdb", "no gdb: brew install gdb (it debugs aarch64 Linux targets through a remote "
                     "stub), or pass --gdb")


def text_of(out):
    with open(out, errors="replace") as f:
        return f.read()


def client_bytes(text, marker, client):
    """The 16 bytes the client printed (gdb's `x/16xb`, lldb's `memory
    read`) on the first two lines after `marker` that start with an
    address."""
    at = text.find(marker + "\n")
    check(at >= 0, f"no {marker} in {client}'s output:\n{text}")
    lines = [ln for ln in text[at + len(marker) + 1:].splitlines() if re.match(r"\s*0x[0-9a-f]+.*:", ln)][:2]
    values = [int(v, 16) for line in lines for v in re.findall(r"0x([0-9a-f]{2})\b", line.split(":", 1)[-1])]
    check(len(values) == 16, f"{client}'s 16 bytes after {marker}: {lines}")
    return bytes(values)


class Gdb:
    """gdb in batch mode, without a symbol file (upstream's client)."""

    name = "gdb"
    script = """set pagination off
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
    connected = r"WICK-PC|Remote debugging using"
    hw_hit = r"(Hardware assisted breakpoint|Breakpoint) 1, 0x0*{:x}\b"
    sw_hit = r"Breakpoint 2, 0x0*{:x}\b"

    def __init__(self, path):
        self.path = path

    @staticmethod
    def target(sock=None, port=None):
        return sock if sock else f"127.0.0.1:{port}"

    def run(self, script, out):
        with open(out + ".gdb", "w") as f:
            f.write(script)
        log = open(out, "w")
        return subprocess.Popen([self.path, "-nx", "-batch", "-x", out + ".gdb"],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)


class Lldb:
    """The system's lldb in batch mode, without a target file (an additional
    client)."""

    name = "lldb"
    script = """settings set plugin.process.gdb-remote.packet-timeout 30
process connect --plugin gdb-remote @TARGET@
breakpoint set -H -a 0x@start_kernel@
process continue
script print("WICK-PC %x" % lldb.frame.GetPC())
script print("WICK-X1")
memory read -s1 -fx -c16 -l8 0x@start_kernel@
breakpoint set -a 0x@rest_init@
process continue
script print("WICK-REST %x" % lldb.frame.GetPC())
script print("WICK-X2")
memory read -s1 -fx -c16 -l8 0x@text_linear@
process continue
"""
    connected = r"WICK-PC|Process \d+ stopped"
    hw_hit = r"stop reason = breakpoint 1\.1.*\n(?:.*\n)*?.*0x0*{:x}\b"
    sw_hit = r"stop reason = breakpoint 2\.1.*\n(?:.*\n)*?.*0x0*{:x}\b"

    def __init__(self, path):
        self.path = path

    @staticmethod
    def target(sock=None, port=None):
        return f"unix-connect://{sock}" if sock else f"connect://127.0.0.1:{port}"

    def run(self, script, out):
        with open(out + ".lldb", "w") as f:
            f.write(script)
        log = open(out, "w")
        return subprocess.Popen([self.path, "--no-lldbinit", "--batch", "--source", out + ".lldb"],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)


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
    got = {k: int(v, 16) for k, v in (kv.split("=") for kv in m.group(1).split())}
    vm.reboot()
    offset = stext_offset(ctx.kernel)
    addr = {"_text": got["_stext"] - offset, "start_kernel": got["start_kernel"], "rest_init": got["rest_init"],
            "text_phys": got["stext_phys"] - offset, "text_linear": got["stext_linear"] - offset}
    print("   addresses: " + " ".join(f"{k}={v:#x}" for k, v in sorted(got.items()))
          + f"; the Image's _stext offset {offset:#x}", flush=True)
    return addr


def expected(ctx):
    """The guest's addresses (a boot without a client) and the Image's bytes
    the client must read through the stub."""
    addr = guest_addresses(ctx)
    for name in ("start_kernel", "rest_init"):
        check(addr["_text"] < addr[name], f"{name} {addr[name]:#x} before _text {addr['_text']:#x}")
    file_bytes = {"start_kernel": image_bytes(ctx.kernel, addr["start_kernel"] - addr["_text"]),
                  "_text": image_bytes(ctx.kernel, 0)}
    return addr, file_bytes


def session(ctx, client, addr, file_bytes):
    """A boot under `client` (Gdb or Lldb) with upstream's session and the
    Windows stage's checks; returns how the client connected."""
    name = client.name
    sock = os.path.join(ctx.sock, f"{name}.sock")
    vm = ctx.vm(name, [], bt.config(ctx, machine={"gdb_socket_path": sock}), api=False)
    # Firecracker waits for the client before it runs the guest.
    deadline = time.time() + 30
    while not os.path.exists(sock):
        check(vm.proc.poll() is None and time.time() < deadline, f"no gdb socket at {sock} ({vm.exit_reason()})")
        time.sleep(0.05)
    script = client.script
    for k, v in addr.items():
        script = script.replace(f"@{k}@", f"{v:x}")
    out = os.path.join(ctx.dir, f"{name}-direct.txt")
    g = client.run(script.replace("@TARGET@", client.target(sock=sock)), out)
    direct, relay = False, None
    deadline = time.time() + 20
    while time.time() < deadline and g.poll() is None:
        if re.search(client.connected, text_of(out)):
            direct = True
            break
        time.sleep(0.2)
    try:
        if not direct:
            tail = " | ".join(text_of(out).strip().splitlines()[-2:])
            g.kill()
            g.wait()
            print(f"   {name} does not reach the Unix socket by its path ({tail}); through a TCP relay", flush=True)
            check(os.path.exists(sock), "the gdb socket went away after the direct attempt")
            relay = Relay(sock)
            out = os.path.join(ctx.dir, f"{name}-relay.txt")
            g = client.run(script.replace("@TARGET@", client.target(port=relay.port)), out)
        done = re.compile(r"WICK-X2\n(?:.*\n)*?\s*0x[0-9a-f]+.*:.*\n(?:.*\n)*?\s*0x[0-9a-f]+.*:.*\n", re.M)
        deadline = time.time() + ctx.timeout
        while time.time() < deadline and g.poll() is None and not done.search(text_of(out)):
            time.sleep(0.2)
        text = text_of(out)
        shutil.copyfile(out, os.path.join(ctx.dir, f"{name}-session.txt"))
        check(relay is None or relay.error is None, f"relay: {relay and relay.error}")
        start = addr["start_kernel"]
        check(re.search(client.hw_hit.format(start), text),
              f"{name}: the hardware breakpoint at start_kernel ({start:#x}) was not hit:\n{text}")
        m = re.search(r"^WICK-PC ([0-9a-f]+)$", text, re.M)
        check(m and int(m.group(1), 16) == start,
              f"{name}: the PC at the breakpoint is not start_kernel ({start:#x}):\n{text}")
        seen = client_bytes(text, "WICK-X1", name)
        check(seen == file_bytes["start_kernel"],
              f"{name}: start_kernel through the stub: {seen.hex()}, in the Image: {file_bytes['start_kernel'].hex()}")
        rest = addr["rest_init"]
        check(re.search(client.sw_hit.format(rest), text),
              f"{name}: the software breakpoint at rest_init ({rest:#x}) was not hit:\n{text}")
        m = re.search(r"^WICK-REST ([0-9a-f]+)$", text, re.M)
        check(m and int(m.group(1), 16) == rest, f"{name}: the PC at the software breakpoint is not rest_init:\n{text}")
        seen = client_bytes(text, "WICK-X2", name)
        check(seen == file_bytes["_text"],
              f"{name}: _text through the linear map ({addr['text_linear']:#x}): {seen.hex()}, "
              f"in the Image: {file_bytes['_text'].hex()}")
        # The client's last continue: the guest boots on under it.
        vm.shell()
        _, said = vm.sh("echo gdb-$((6*7))")
        check(said == "gdb-42", f"the guest under {name}: {said!r}")
    finally:
        if g.poll() is None:
            g.kill()
            g.wait()
        if relay:
            relay.stop()
    vm.kill()
    how = ("by the socket's path" if direct
           else f"through a TCP relay (this {name} does not reach a Unix socket by its path)")
    return (f"{name} {how}: hardware breakpoint at start_kernel, its bytes and _text's through the linear map as "
            "in the Image, software breakpoint at rest_init, the guest boots on")


class Context(bt.Context):
    def __init__(self, args):  # pylint: disable=super-init-not-called
        self.firecracker = args.firecracker
        self.out = args.out
        self.dir = os.path.join(args.out, "gdb")
        os.makedirs(self.dir, exist_ok=True)
        self.timeout = args.timeout
        # gdb is the client that counts; without it the stage fails, and
        # lldb still runs (its result is printed, not counted).
        try:
            self.gdb = Gdb(find_gdb(args.gdb))
            self.no_gdb = None
        except Failure as e:
            self.gdb, self.no_gdb = None, str(e)
        lldb = None if args.no_lldb else (args.lldb or shutil.which("lldb", path="/usr/bin"))
        self.lldb = Lldb(lldb) if lldb else None
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
    p.add_argument("--lldb", help="the additional lldb client (default: /usr/bin/lldb)")
    p.add_argument("--no-lldb", action="store_true", help="without the additional lldb client")
    p.add_argument("--cache", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=int, default=300, help="seconds for each client's session")
    args = p.parse_args()
    os.makedirs(args.out, exist_ok=True)
    bt.exit_on_signals()
    results = []
    ctx = addr = None
    try:
        print("== gdb", flush=True)
        t0 = time.time()
        try:
            ctx = Context(args)
            print(f"   gdb: {ctx.gdb.path if ctx.gdb else 'none'}; lldb: {ctx.lldb.path if ctx.lldb else 'none'}",
                  flush=True)
            addr, file_bytes = expected(ctx)
            if ctx.gdb is None:
                raise Failure(ctx.no_gdb)
            results.append(("gdb", True, session(ctx, ctx.gdb, addr, file_bytes)))
        except Failure as e:
            results.append(("gdb", False, str(e)))
        print(f"   {'PASS' if results[-1][1] else 'FAIL'} ({time.time() - t0:.1f}s): {results[-1][2]}", flush=True)
        # lldb runs whatever gdb's result: an additional client's reading
        # of the same stub, once the guest's addresses are known.
        if addr is not None and ctx.lldb is not None:
            ctx.cleanup()
            print("== gdb-lldb (an additional client)", flush=True)
            t0 = time.time()
            try:
                results.append(("gdb-lldb", True, session(ctx, ctx.lldb, addr, file_bytes)))
            except Failure as e:
                results.append(("gdb-lldb", False, str(e)))
            print(f"   {'PASS' if results[-1][1] else 'FAIL'} ({time.time() - t0:.1f}s): {results[-1][2]}",
                  flush=True)
    finally:
        if ctx is not None:
            ctx.cleanup()
            shutil.rmtree(ctx.sock, ignore_errors=True)
    sys.exit(1 if bt.summarize(args.out, results) else 0)


if __name__ == "__main__":
    main()
