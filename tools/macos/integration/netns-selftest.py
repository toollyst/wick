# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The integration tests' network without a VM.

    python3 tools/macos/integration/netns-selftest.py NETNS_SLIRP

Starts a network's host side (netns-slirp) on a directory, adds interfaces
as the framework's TAPs, binds one in the directory as Firecracker does
(vmm::platform::net, a Unix datagram endpoint) and plays the guest: the
host side attaches to the endpoint, ARP and ICMP echo to the host address
get their answers, the interface shows used while bound and free once
closed, an endpoint bound again is attached to again (an update of the
device, a restore), a forward reaches only a guest address on an
interface's subnet, and the host side ends with its owner's pipe. CI runs it
on macOS runners, which have no Hypervisor.framework for the tests
themselves.
"""

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


def main():
    helper = sys.argv[1]
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
