# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The integration tests' network without a VM.

    python3 tools/macos/integration/netns-selftest.py NETNS_SLIRP [NETNS_PRELOAD]

Starts a network's host side (netns-slirp) on a directory, adds interfaces
as the framework's TAPs, binds one in the directory as Firecracker does
(vmm::platform::net, a Unix datagram endpoint) and plays the guest: the
host side attaches to the endpoint, ARP and ICMP echo to the host address
get their answers, the interface shows used while bound and free once
closed, an endpoint bound again is attached to again (an update of the
device, a restore), a forward reaches only a guest address on an
interface's subnet, and the host side ends with its owner's pipe. With
NETNS_PRELOAD (netns-preload.dylib), host programs in the network too: a
TCP listener at the host address that the guest connects to, a UDP
exchange with the guest, and addresses off the network refused. CI runs it
on macOS runners, which have no Hypervisor.framework for the tests
themselves.
"""

import errno
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wick_macos_net import request  # noqa: E402  pylint: disable=wrong-import-position

GUEST_MAC = bytes.fromhex("0600c0a80002")
HOST_IP, GUEST_IP = "192.168.0.1", "192.168.0.2"


def check(cond, msg):
    if not cond:
        raise SystemExit(f"FAIL: {msg}")


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def endpoint(net, name):
    """Firecracker's side: an endpoint bound in the network, by its name in
    the directory (as the VMM binds it there); the host side's attach is
    its first datagram."""
    dev = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    cwd = os.getcwd()
    os.chdir(net)
    try:
        dev.bind(name)
    finally:
        os.chdir(cwd)
    dev.settimeout(3)
    data, peer = dev.recvfrom(64)
    check(data == b"" and peer == os.path.join(os.path.realpath(net), f".host-{name}"),
          f"attach to {name}: {data!r} from {peer!r}")
    return dev, peer


def frame_of(sock, ethertype, want, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        f = sock.recv(2048)
        if f[12:14] == ethertype and want(f):
            return f
    raise SystemExit(f"FAIL: no {ethertype.hex()} frame")


def ip_packet(proto, payload, src=GUEST_IP, dst=HOST_IP):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, socket.inet_aton(src),
                     socket.inet_aton(dst))
    return ip[:10] + struct.pack("!H", csum(ip)) + ip[12:] + payload


def l4(proto, header, data, src=GUEST_IP, dst=HOST_IP):
    """A TCP or UDP segment with its checksum (`header` with a zero one)."""
    seg = header + data
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, len(seg))
    off = 16 if proto == 6 else 6
    return seg[:off] + struct.pack("!H", csum(pseudo + seg)) + seg[off + 2:]


def tcp(sport, dport, seq, ack, flags, data=b""):
    return l4(6, struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0), data)


def program(preload, ctl, fwd, code):
    """A host program in the network, as tools/macos/integration/bin/ip runs one."""
    env = dict(os.environ, DYLD_INSERT_LIBRARIES=preload, WICK_NETNS_CTL=ctl, WICK_NETNS_FWD=fwd)
    return subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def programs(dev, host, host_mac, ctl, fwd, preload):
    """Host programs in the network (netns-preload): a listener the guest
    connects to, a UDP exchange with the guest, and what is not the
    network's refused as in a namespace."""
    def to_host(proto, seg):
        dev.sendto(host_mac + GUEST_MAC + b"\x08\x00" + ip_packet(proto, seg), host)

    srv = program(preload, ctl, fwd, f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(({HOST_IP!r}, 4444))
s.listen(1)
print("listening", s.getsockname(), flush=True)
c, a = s.accept()
print("data", c.recv(5).decode(), flush=True)
c.close()
s.close()
""")
    line = srv.stdout.readline()
    check(line.strip() == f"listening ('{HOST_IP}', 4444)", f"listener: {line!r} {srv.stderr.read() if not line else ''}")
    to_host(6, tcp(40000, 4444, 1000, 0, 0x02))  # SYN
    r = frame_of(dev, b"\x08\x00", lambda f: f[23] == 6 and f[34:36] == struct.pack("!H", 4444) and f[47] & 0x12 == 0x12)
    check(socket.inet_ntoa(r[26:30]) == HOST_IP and r[0:6] == GUEST_MAC, "SYN-ACK from the listener's address to the guest")
    server_seq = struct.unpack("!I", r[38:42])[0]
    check(struct.unpack("!I", r[42:46])[0] == 1001, "SYN-ACK acknowledges the SYN")
    to_host(6, tcp(40000, 4444, 1001, server_seq + 1, 0x18, b"hello"))  # ACK, PSH
    out, _ = srv.communicate(timeout=10)
    check("data hello" in out, f"the listener got the guest's data: {out!r}")
    check(request(ctl, f"gfwd {HOST_IP} 4444 {fwd}/x")[0] == 0, "the port of a listener gone is taken over")
    check(request(ctl, f"ungfwd {HOST_IP} 4444")[0] == 0, "ungfwd")

    udp = program(preload, ctl, fwd, f"""
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(5)
u.sendto(b"ping", ({GUEST_IP!r}, 5201))
d, a = u.recvfrom(64)
print("udp", d.decode(), a, flush=True)
for bad in (lambda: socket.socket().connect(("10.9.9.9", 1)), lambda: socket.socket().bind(("10.9.9.9", 1))):
    try:
        bad()
    except OSError as e:
        print("refused", e.errno, flush=True)
""")
    r = frame_of(dev, b"\x08\x00", lambda f: f[23] == 17 and f[36:38] == struct.pack("!H", 5201))
    check(socket.inet_ntoa(r[30:34]) == GUEST_IP and r[42:46] == b"ping", "the program's datagram reaches the guest")
    sport = struct.unpack("!H", r[34:36])[0]
    src = socket.inet_ntoa(r[26:30])
    pong = l4(17, struct.pack("!HHHH", 5201, sport, 8 + 4, 0), b"pong", src=GUEST_IP, dst=src)
    dev.sendto(host_mac + GUEST_MAC + b"\x08\x00" + ip_packet(17, pong, dst=src), host)
    out, err = udp.communicate(timeout=10)
    check(f"udp pong ('{GUEST_IP}', 5201)" in out, f"the guest's answer, from the guest's address: {out!r} {err!r}")
    check(f"refused {errno.ENETUNREACH}" in out and f"refused {errno.EADDRNOTAVAIL}" in out,
          f"off the network: ENETUNREACH and EADDRNOTAVAIL: {out!r}")


def main():
    helper = sys.argv[1]
    preload = sys.argv[2] if len(sys.argv) > 2 else None
    d = tempfile.mkdtemp(prefix="wns-", dir="/tmp")
    net, ctl, fwd = (os.path.join(d, n) for n in ("net", "ctl", "fwd"))
    os.mkdir(net)
    os.mkdir(fwd)
    p = subprocess.Popen([helper, net, ctl, fwd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        check(p.stdout.readline().strip() == "ready", "the host side did not start")
        check(request(ctl, "hello") == (0, "netns-slirp 1"), "hello")
        check(request(ctl, f"add tap0 {HOST_IP}/30") == (0, ""), "add tap0")
        check(request(ctl, "add tap0 10.0.0.1/30")[0] == 17, "a second tap0 is EEXIST")
        check(request(ctl, "add bare")[0] == 0, "a TAP without an address")
        check(request(ctl, "used tap0") == (0, "0"), "tap0 unused")
        check(request(ctl, "used tap9")[0] == 19, "a missing interface is ENODEV")
        dev, host = endpoint(net, "tap0")
        check(request(ctl, "used tap0") == (0, "1"), "tap0 used")
        arp = (b"\xff" * 6 + GUEST_MAC + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + GUEST_MAC
               + socket.inet_aton(GUEST_IP) + b"\0" * 6 + socket.inet_aton(HOST_IP))
        dev.sendto(arp, host)
        r = frame_of(dev, b"\x08\x06", lambda f: struct.unpack("!H", f[20:22])[0] == 2)
        check(socket.inet_ntoa(r[28:32]) == HOST_IP, "ARP reply for the host address")
        host_mac = r[6:12]
        icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
        icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, socket.inet_aton(GUEST_IP),
                         socket.inet_aton(HOST_IP))
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        dev.sendto(host_mac + GUEST_MAC + b"\x08\x00" + ip + icmp, host)
        r = frame_of(dev, b"\x08\x00", lambda f: f[23] == 1 and f[34] == 0)
        check(socket.inet_ntoa(r[26:30]) == HOST_IP, "echo reply from the host address")
        err, path = request(ctl, f"fwd {GUEST_IP} 22")
        check(err == 0 and path.startswith(fwd) and os.path.exists(path), f"forward: {err} {path}")
        check(request(ctl, "fwd 10.0.0.2 22")[0] == 51, "a forward off every subnet is ENETUNREACH")
        if preload:
            programs(dev, host, host_mac, ctl, fwd, preload)
        dev.close()
        os.unlink(os.path.join(net, "tap0"))
        check(request(ctl, "used tap0") == (0, "0"), "tap0 free once its endpoint closed")
        # Bound again (an update of the device, a restore): attached again.
        dev, host = endpoint(net, "tap0")
        dev.close()
        p.stdin.close()
        check(p.wait(10) == 0, "the host side ends with its owner's pipe")
    finally:
        if p.poll() is None:
            p.kill()
        shutil.rmtree(d, ignore_errors=True)
    print("netns self-test: OK")


if __name__ == "__main__":
    main()
