# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Checks the Windows integration harness without a VM (CI's windows job).

    python -I tools/windows/integration/selftest.py

- AF_UNIX for Python (wick_windows_unix): bind, listen, connect, accept,
  names, a round trip.
- A network's host side (wick_windows_net): a stand-in for Firecracker's
  endpoint (an AF_UNIX listener speaking its framing: each Ethernet frame
  after its length, 32-bit big-endian) and a stand-in guest behind it. The
  host side must answer the guest's ARP request and ICMP echo for the host's
  address, and carry a TCP connection from a forward to the guest's port:
  SYN out, bytes both ways, FIN.
- procps and the memory monitor's mappings (hosttools, wick_windows_mem) on
  this process; Windows paths as WSL names them.
- What a kill and a wait for an end wait for (wick_windows_proc): the jailer
  after Firecracker, the screen stand-in's child before the stand-in.
"""

import ipaddress
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wick_windows_unix  # noqa: E402

wick_windows_unix.install()

import hosttools  # noqa: E402
import wick_windows_mem  # noqa: E402
import wick_windows_net as net  # noqa: E402

FAILS = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        FAILS.append(what)


def unix_roundtrip(tmp):
    path = os.path.join(tmp, "s.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(path)
    conn, _ = srv.accept()
    cli.sendall(b"ping")
    check(conn.recv(4) == b"ping", "AF_UNIX: connect, accept, a round trip")
    check(srv.getsockname().endswith("s.sock"), "AF_UNIX: getsockname names the path")
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(os.path.join(tmp, "none.sock"))
        check(False, "AF_UNIX: connecting to no socket fails")
    except FileNotFoundError:
        check(True, "AF_UNIX: connecting to no socket is ENOENT")
    for s in (conn, cli, srv):
        s.close()


class Guest:
    """The guest behind a stand-in endpoint: frames in, frames out."""

    MAC = bytes.fromhex("060000000002")

    def __init__(self, path):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        self.listener.listen(1)
        self.conn = None
        self.frames = []
        self.cond = threading.Condition()
        # Set: the guest takes no frame (a VMM that does not read).
        self.hold = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.conn, _ = self.listener.accept()
        buf = b""
        while True:
            while self.hold.is_set():
                time.sleep(0.01)
            try:
                data = self.conn.recv(65536)
            except OSError:  # the host side closed the endpoint (cleanup)
                return
            if not data:
                return
            buf += data
            while len(buf) >= 4 and len(buf) >= 4 + struct.unpack("!I", buf[:4])[0]:
                n = struct.unpack("!I", buf[:4])[0]
                with self.cond:
                    self.frames.append(buf[4 : 4 + n])
                    self.cond.notify_all()
                buf = buf[4 + n :]

    def send(self, frame):
        self.conn.sendall(struct.pack("!I", len(frame)) + frame)

    def wait(self, pred, timeout=5):
        deadline = time.time() + timeout
        with self.cond:
            while True:
                for f in self.frames:
                    if pred(f):
                        self.frames.remove(f)
                        return f
                left = deadline - time.time()
                if left <= 0:
                    return None
                self.cond.wait(left)


def ip_packet(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src.packed, dst.packed)
    hdr = hdr[:10] + struct.pack("!H", net._csum(hdr)) + hdr[12:]  # pylint: disable=protected-access
    return hdr + payload


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", src.packed, dst.packed, 0, 6, len(tcp) + len(payload))
    c = net._csum(pseudo + tcp + payload)  # pylint: disable=protected-access
    return tcp[:16] + struct.pack("!H", c) + tcp[18:] + payload


def udp_datagram(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = struct.pack("!4s4sBBH", src.packed, dst.packed, 0, 17, 8 + len(payload))
    c = net._csum(pseudo + udp + payload) or 0xFFFF  # pylint: disable=protected-access
    return udp[:6] + struct.pack("!H", c) + payload


def network_programs(tmp, ns, g, host, guest, host_mac):
    """What a host program in the network needs (upstream's test_tap_offload,
    test_high_ingress_traffic, test_net_change_mac_address): UDP to the
    guest, the guest's connections to a program on the host, a transmit
    queue that drops, and the door a program reaches them through."""
    iface = ns.taps["tap0"]._iface  # pylint: disable=protected-access
    eth = host_mac + Guest.MAC + b"\x08\x00"

    def is_udp_to(port):
        return lambda f: f[12:14] == b"\x08\x00" and f[23] == 17 and f[36:38] == struct.pack("!H", port)

    # UDP through a forward, and the guest's answer.
    uport = ns.forward_udp(str(guest), 81)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(5)
    u.sendto(b"x", ("127.0.0.1", uport))
    d = g.wait(is_udp_to(81))
    check(d is not None and d[42:] == b"x" and d[26:30] == host.packed, "network: a datagram to a UDP forward reaches the guest from the host's address")
    if d is None:
        return
    pseudo = struct.pack("!4s4sBBH", host.packed, guest.packed, 0, 17, len(d) - 34)
    check(net._csum(pseudo + d[34:]) == 0, "network: its UDP checksum is right")  # pylint: disable=protected-access
    hport, = struct.unpack("!H", d[34:36])
    g.send(eth + ip_packet(guest, host, 17, udp_datagram(guest, host, 81, hport, b"pong")))
    try:
        answer = u.recvfrom(100)[0]
    except OSError as e:
        answer = e
    check(answer == b"pong", f"network: the guest's answer reaches the forward's sender: {answer!r}")
    # A datagram longer than the MTU leaves in fragments.
    u.sendto(b"z" * 3000, ("127.0.0.1", uport))
    parts = [g.wait(lambda f: f[12:14] == b"\x08\x00" and f[23] == 17 and f[26:30] == host.packed) for _ in range(3)]
    ok = all(p is not None for p in parts)
    flags = [struct.unpack("!H", p[20:22])[0] for p in parts] if ok else []
    check(ok and flags == [0x2000, 0x2000 | 185, 370] and sum(len(p) - 34 for p in parts) == 3008,
          f"network: a 3000-byte datagram is three fragments: {[hex(x) for x in flags]}")
    # UDP to a port of the host's nobody has: ICMP port unreachable.
    g.send(eth + ip_packet(guest, host, 17, udp_datagram(guest, host, 4000, 9, b"?")))
    r = g.wait(lambda f: f[12:14] == b"\x08\x00" and f[23] == 1 and f[34] == 3)
    check(r is not None and r[35] == 3, "network: UDP to a closed port of the host is answered with port unreachable")

    def connect_from_guest(port, gport, payload):
        """The guest opens a connection to host:port and sends `payload`;
        the SYN's answer."""
        g.send(eth + ip_packet(guest, host, 6, tcp_segment(guest, host, gport, port, 5000, 0, 0x02)))
        answer = g.wait(lambda f: f[23] == 6 and f[36:38] == struct.pack("!H", gport) and f[47] & 0x16)
        if answer is not None and answer[47] == 0x12:
            hseq, = struct.unpack("!I", answer[38:42])
            g.send(eth + ip_packet(guest, host, 6, tcp_segment(guest, host, gport, port, 5001, hseq + 1, 0x18, payload)))
        return answer

    # A port of the host's that a program listens on, and one nobody does.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    iface.listeners[4444] = ("127.0.0.1", srv.getsockname()[1])
    answer = connect_from_guest(4444, 40000, b"from guest")
    check(answer is not None and answer[47] == 0x12, "network: the guest's SYN to a listened port gets SYN|ACK")
    try:
        conn, _ = srv.accept()
        conn.settimeout(5)
        got = conn.recv(100)
        conn.sendall(b"to guest")
    except OSError as e:
        got = e
    check(got == b"from guest", f"network: the guest's bytes reach the program that listens: {got!r}")
    data = g.wait(lambda f: f[23] == 6 and f[54:] == b"to guest")
    check(data is not None, "network: the program's bytes reach the guest")
    answer = connect_from_guest(4445, 40001, b"")
    check(answer is not None and answer[47] & 0x04, "network: the guest's SYN to a port nobody listens on gets a reset")

    # A program in the network: Python with the door's sockets.
    env = dict(os.environ, WICK_NETNS_DOOR=ns.door_path.read_text(encoding="ascii"),
               PYTHONPATH=os.path.join(os.path.dirname(os.path.abspath(__file__)), "netns_site"))
    # upstream's host_tools/udp_offload.py: UDP_SEGMENT, then a datagram.
    code = ("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.setsockopt(17, 103, 1400)\ns.sendto(b'y' * 3000, ('192.168.0.2', 82))\n")
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60, check=False)
    sizes = [len(f) - 42 for f in (g.wait(is_udp_to(82)) for _ in range(3)) if f is not None]
    check(done.returncode == 0 and sizes == [1400, 1400, 200],
          f"network: a program's UDP_SEGMENT datagram reaches the guest in segments: {sizes} {done.stderr.strip()}")
    # upstream's test_net_config_space.py server: bound to the host's address.
    code = ("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.bind(('192.168.0.1', 4446))\n"
            "s.listen(1)\nprint('listening', flush=True)\nc, _ = s.accept()\nprint(c.recv(100).decode(), flush=True)\n")
    with subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as prog:
        first = prog.stdout.readline()
        answer = connect_from_guest(4446, 40002, b"hi host") if first == "listening\n" else None
        second = prog.stdout.readline() if answer is not None and answer[47] == 0x12 else ""
        try:
            prog.wait(10)
        except subprocess.TimeoutExpired:
            prog.kill()
        check(first == "listening\n" and second == "hi host\n",
              f"network: a program bound to the host's address takes the guest's connection: {first!r} {second!r} {prog.stderr.read().strip()}")
    deadline = time.time() + 5
    while 4446 in iface.listeners and time.time() < deadline:
        time.sleep(0.05)
    check(4446 not in iface.listeners, "network: what a program listened on ends with the program")
    # iperf3's arguments through a forward for TCP and UDP.
    both = ns.forward_both(str(guest), 5201)
    args = hosttools.iperf3_args(["-c", "192.168.0.2", "-u", "-V", "-b", "1000000000", "-t", "30"],
                                 lambda ip, port: both if (ip, port) == ("192.168.0.2", 5201) else 0)
    check(args == ["-c", "127.0.0.1", "-u", "-V", "-b", "1000000000", "-t", "30", "-p", str(both)], f"iperf3's arguments: {args}")
    u.sendto(b"i", ("127.0.0.1", both))
    check(g.wait(is_udp_to(5201)) is not None, "network: one port number leads to the guest's for UDP (and TCP)")

    # A transmit queue of 5 and a guest that takes nothing: frames are
    # dropped, and the interface works when the guest reads again.
    ns.taps["tap0"].set_tx_queue_len(5)
    g.hold.set()
    # Straight from the stack, 5.6 MB: more than the endpoint's socket
    # holds, and nothing is left in a socket of the test's afterwards.
    for _ in range(4000):
        iface.send_udp(guest, 30000, 81, b"q" * 1400)
    check(iface.tx_dropped > 0 and len(iface.tx_queue) <= 5,
          f"network: a full transmit queue drops ({iface.tx_dropped} dropped, {len(iface.tx_queue)} queued)")
    g.hold.clear()
    deadline = time.time() + 10
    while iface.tx_queue and time.time() < deadline:
        time.sleep(0.05)
    check(not iface.tx_queue, "network: the queue empties once the guest reads")
    echo = b"\x08\x00\x00\x00\x12\x35\x00\x01" + b"wick"
    echo = echo[:2] + struct.pack("!H", net._csum(echo)) + echo[4:]  # pylint: disable=protected-access
    g.send(eth + ip_packet(guest, host, 1, echo))
    reply = g.wait(lambda f: f[12:14] == b"\x08\x00" and f[23] == 1 and f[34] == 0 and f[38:40] == b"\x12\x35")
    check(reply is not None, "network: the interface answers after its queue was full")
    u.close()
    srv.close()


def network(tmp):
    os.environ["WICK_IT_ROOT"] = tmp
    host, guest = ipaddress.ip_address("192.168.0.1"), ipaddress.ip_address("192.168.0.2")
    ns = net.NetNs("selftest")
    ns.setup()
    g = Guest(str(ns.path / "tap0"))
    ns.add_tap("tap0", "192.168.0.1/30")
    deadline = time.time() + 5
    while g.conn is None and time.time() < deadline:
        time.sleep(0.05)
    check(g.conn is not None and ns.is_used(), "network: the host side connects to the endpoint")
    host_mac = ns.taps["tap0"]._iface.host_mac  # pylint: disable=protected-access
    # ARP for the host's address.
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, Guest.MAC, guest.packed, b"\0" * 6, host.packed)
    g.send(b"\xff" * 6 + Guest.MAC + b"\x08\x06" + arp)
    reply = g.wait(lambda f: f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02")
    check(reply is not None and reply[22:28] == host_mac, "network: ARP reply with the host's address")
    # ICMP echo.
    echo = b"\x08\x00\x00\x00\x12\x34\x00\x01" + b"wick"
    echo = echo[:2] + struct.pack("!H", net._csum(echo)) + echo[4:]  # pylint: disable=protected-access
    g.send(host_mac + Guest.MAC + b"\x08\x00" + ip_packet(guest, host, 1, echo))
    reply = g.wait(lambda f: f[12:14] == b"\x08\x00" and f[23] == 1)
    check(reply is not None and reply[34] == 0 and reply[42:46] == b"wick", "network: ICMP echo reply")
    # TCP through a forward to guest:22.
    port = ns.forward(str(guest), 22)
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    syn = g.wait(lambda f: f[23] == 6 and f[47] & 0x02)
    check(syn is not None, "network: a forward's connection sends a SYN to the guest")
    if syn is None:
        return
    sport, = struct.unpack("!H", syn[34:36])
    iss, = struct.unpack("!I", syn[38:42])
    gseq = 1000
    g.send(host_mac + Guest.MAC + b"\x08\x00" + ip_packet(guest, host, 6, tcp_segment(
        guest, host, 22, sport, gseq, iss + 1, 0x12)))
    g.wait(lambda f: f[23] == 6 and f[47] == 0x10)
    g.send(host_mac + Guest.MAC + b"\x08\x00" + ip_packet(guest, host, 6, tcp_segment(
        guest, host, 22, sport, gseq + 1, iss + 1, 0x18, b"SSH-2.0-selftest\r\n")))
    check(client.recv(100) == b"SSH-2.0-selftest\r\n", "network: the guest's bytes reach the forward")
    client.sendall(b"hello guest")
    data = g.wait(lambda f: f[23] == 6 and len(f) > 54)
    check(data is not None and data[54:65] == b"hello guest", "network: the forward's bytes reach the guest")
    client.close()
    fin = g.wait(lambda f: f[23] == 6 and f[47] & 0x01)
    check(fin is not None, "network: closing the forward sends a FIN")
    network_programs(tmp, ns, g, host, guest, host_mac)
    ns.cleanup()
    check(not ns.door_path.exists(), "network: the door goes with the network")


def host_tools():
    ps = hosttools.thread_name  # importable, and names a thread without one as ""
    check(isinstance(ps(0), str), "procps: a thread's name")
    check(hosttools.wsl_path("C:\\a\\b c") == "/mnt/c/a/b c" and hosttools.wsl_path("-qF") == "-qF",
          "e2fsprogs: Windows paths as WSL names them")
    with tempfile.TemporaryDirectory(prefix="wick-st-bin-") as d:
        d = pathlib.Path(d)
        (d / "firecracker.exe").write_bytes(b"")
        check(hosttools.windows_binary(d / "firecracker") == d / "firecracker.exe"
              and hosttools.windows_binary(d / "jailer") == d / "jailer",
              "binaries: Linux's name finds the .exe of a directory with only that (a test's own build)")
        (d / "firecracker").write_bytes(b"")
        check(hosttools.windows_binary(d / "firecracker") == d / "firecracker",
              "binaries: Linux's name where the file has it")
    check(hosttools.windows_cargo_args("--features gdb --target x86_64-unknown-linux-musl --all")
          == ("--features gdb --target x86_64-pc-windows-msvc --all", "x86_64-unknown-linux-musl")
          and hosttools.windows_cargo_args("--release -p firecracker") == ("--release -p firecracker", None),
          "cargo: a musl --target is the Windows target")
    import psutil  # pylint: disable=import-outside-toplevel

    wick_windows_mem.install()
    block = bytearray(8 << 20)
    maps = psutil.Process().memory_maps(grouped=False)
    mine = [m for m in maps if m.size >= len(block) and m.rss >= len(block) // 2]
    check(bool(mine), "memory_maps: an 8 MiB allocation, resident")
    check(all(m.rss == 0 for m in maps if m.path.lower().startswith(wick_windows_mem._SYSTEM)),  # pylint: disable=protected-access
          "memory_maps: the system's files count for nothing")
    del block


def _cmd(script):
    """cmd.exe running `script`, its pid's process and its Popen."""
    import subprocess  # pylint: disable=import-outside-toplevel

    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    return subprocess.Popen(f'"{comspec}" /d /s /c "{script}"')  # pylint: disable=consider-using-with


def _first_child(pid, name, timeout=10):
    import psutil  # pylint: disable=import-outside-toplevel

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [c for c in psutil.Process(pid).children() if c.name().lower() == name]
        if found:
            return found[0]
        time.sleep(0.02)
    raise RuntimeError(f"process {pid} started no {name}")


def _suspend(pid, resume=False):
    import ctypes  # pylint: disable=import-outside-toplevel

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
    ntdll = ctypes.WinDLL("ntdll")
    try:
        status = (ntdll.NtResumeProcess if resume else ntdll.NtSuspendProcess)(ctypes.c_void_p(h))
        assert status == 0, f"NTSTATUS {status & 0xFFFFFFFF:#x}"
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def _end_stand_in(proc, pid, limit, resume=None):
    """end_stand_in, whose stand-in ends by itself once its child has, as
    screen does on Linux, so that the kill finds it ended."""
    try:
        proc.end_stand_in(pid, 9, limit, resume)
    except ProcessLookupError:
        pass


def process_ends(tmp):
    """What wick_windows.py's os.kill and wait_process_termination wait for
    (wick_windows_proc), with cmd.exe as the jailer, Firecracker and the
    jailer's screen: a wait for the jail's Firecracker returns once its
    jailer, which runs on a moment after it, has ended; a screen stand-in
    ends only after what it started has."""
    import subprocess  # pylint: disable=import-outside-toplevel

    import wick_windows_proc as proc  # pylint: disable=import-outside-toplevel

    # The "jailer" runs on for about 2 s after its "Firecracker" ends.
    jailer = _cmd(f'"{os.environ.get("COMSPEC", "cmd.exe")}" /d /c ping -n 60 127.0.0.1 >nul & ping -n 3 127.0.0.1 >nul')
    fc = _first_child(jailer.pid, "cmd.exe")
    ping = _first_child(fc.pid, "ping.exe")
    after = proc.jail_after(fc.pid, firecracker="cmd.exe", jailer="cmd.exe")
    check([w for w, _ in after] == ["its jailer"], f"jail: the jailer is what ends after Firecracker ({[w for w, _ in after]})")
    proc.terminate(fc.pid, 9)
    fc.wait(10)
    check(jailer.poll() is None, "jail: the jailer runs on after Firecracker's end (what the wait is for)")
    try:
        proc.wait_all(after, 10, "Firecracker")
    finally:
        proc.close_all(after)
    check(jailer.poll() is not None, "jail: a wait for Firecracker returns once its jailer has ended")
    try:
        proc.terminate(fc.pid, 9)
        check(False, "jail: ending an ended process is ProcessLookupError")
    except ProcessLookupError:
        check(True, "jail: ending an ended process is ProcessLookupError")
    ping.kill()

    # A screen stand-in whose child runs about 2 s: its kill waits for it.
    log = os.path.join(tmp, "screen.log")
    stand_in = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, hosttools.__file__, "screen", log,
         os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "ping -n 3 127.0.0.1 >nul & echo child done"],
        stdin=subprocess.PIPE)
    child = _first_child(stand_in.pid, "cmd.exe")
    start = time.monotonic()
    _end_stand_in(proc, stand_in.pid, 20)
    took = time.monotonic() - start
    check(not child.is_running(), f"screen: the stand-in's kill returns once its child has ended ({took:.1f} s)")
    check(stand_in.wait(10) == 0, "screen: the stand-in ended by itself once its child had")
    with open(log, "rb") as f:
        check(b"child done" in f.read(), "screen: the child's last output is in the log")

    # A stopped stand-in, whose child writes past the pipe's buffer: resumed,
    # it copies the rest and the child ends.
    log = os.path.join(tmp, "screen-stopped.log")
    line = b"0123456789012345678901234567890123456789"
    stand_in = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, hosttools.__file__, "screen", log, os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c",
         f"ping -n 2 127.0.0.1 >nul & for /l %i in (1,1,4000) do @echo {line.decode()}"],
        stdin=subprocess.PIPE)
    child = _first_child(stand_in.pid, "cmd.exe")
    _suspend(stand_in.pid)
    _end_stand_in(proc, stand_in.pid, 30, resume=lambda: _suspend(stand_in.pid, resume=True))
    check(not child.is_running(), "screen: a stopped stand-in's kill resumes it and returns once its child has ended")
    stand_in.wait(10)
    with open(log, "rb") as f:
        # Whole lines: each line holds its first ten digits four times.
        lines = f.read().splitlines().count(line)
    check(lines == 4000, f"screen: a stopped stand-in copied all of its child's output ({lines} of 4000 lines)")


def main():
    with tempfile.TemporaryDirectory(prefix="wick-st-") as tmp:
        unix_roundtrip(tmp)
        network(tmp)
        host_tools()
        process_ends(tmp)
    if FAILS:
        print(f"{len(FAILS)} failed")
        return 1
    print("all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
