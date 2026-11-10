# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Scenario tests of a macOS Firecracker build against upstream's CI guest.

Run through tools/macos/boot-test.sh, which builds and signs the binaries and
passes their paths. Every stage boots its own VM (or restores one) and checks
what the guest and the host see; the summary lists each stage as PASS or FAIL
with the reason, and the exit status is non-zero if any stage failed.
"""

import argparse
import hashlib
import http.client
import json
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
import traceback
import urllib.request

ASSETS = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261105-6ea6634994fa-0/aarch64"
KERNEL = "vmlinux-6.1.188"
ROOTFS = "ubuntu-24.04.squashfs"
BOOT_ARGS = "console=ttyS0 reboot=k panic=1 root=/dev/vda ro rootfstype=squashfs init=/bin/sh"

GUEST_MAC = "06:00:0a:00:00:02"
HOST_MAC = bytes.fromhex("02000a000001")
GUEST_IP = "10.0.0.2"
HOST_IP = "10.0.0.1"


class Failure(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Failure(what)


# ---------------------------------------------------------------- the VMM


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Vm:
    """A Firecracker process with its serial console on a pipe."""

    def __init__(self, ctx, name, args, config=None, api=True):
        self.ctx = ctx
        self.name = name
        self.log_path = os.path.join(ctx.out, f"{name}.log")
        self.api_sock = os.path.join(ctx.sock, f"{name}.api") if api else None
        cmd = [ctx.firecracker]
        if self.api_sock:
            cmd += ["--api-sock", self.api_sock]
        else:
            cmd += ["--no-api"]
        if config is not None:
            path = os.path.join(ctx.out, f"{name}.json")
            with open(path, "w") as f:
                json.dump(config, f, indent=1)
            cmd += ["--config-file", path]
        cmd += args
        self.buf = ""
        self.cond = threading.Condition()
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.pump = threading.Thread(target=self._pump, daemon=True)
        self.pump.start()
        self.seq = 0
        if self.api_sock:
            deadline = time.time() + 10
            while not os.path.exists(self.api_sock):
                if self.proc.poll() is not None or time.time() > deadline:
                    raise Failure(f"no API socket ({self.exit_reason()})")
                time.sleep(0.02)

    def _pump(self):
        while True:
            data = self.proc.stdout.read1(65536)
            if not data:
                break
            text = data.decode("utf-8", "replace").replace("\r", "")
            self.log.write(text)
            self.log.flush()
            with self.cond:
                self.buf += text
                self.cond.notify_all()
        with self.cond:
            self.cond.notify_all()

    def exit_reason(self):
        code = self.proc.poll()
        tail = "\n    ".join(self.buf.strip().splitlines()[-8:])
        state = "running" if code is None else f"exit {code}"
        return f"{state}; log {self.log_path}; last lines:\n    {tail}"

    def wait_for(self, pattern, timeout=30, start=0):
        """Waits for `pattern` in the output from offset `start`; returns the match."""
        rx = re.compile(pattern, re.M)
        deadline = time.time() + timeout
        with self.cond:
            while True:
                m = rx.search(self.buf, start)
                if m:
                    return m
                if self.proc.poll() is not None and not self.pump.is_alive():
                    raise Failure(f"waiting for /{pattern}/: VMM exited ({self.exit_reason()})")
                left = deadline - time.time()
                if left <= 0:
                    raise Failure(f"no /{pattern}/ within {timeout}s ({self.exit_reason()})")
                self.cond.wait(min(left, 0.5))

    def send(self, line):
        self.proc.stdin.write(line.encode() + b"\n")
        self.proc.stdin.flush()

    def shell(self, timeout=90):
        """Waits until the guest's shell answers on the serial console."""
        deadline = time.time() + timeout
        while True:
            mark = len(self.buf)
            try:
                self.send("echo READY-$((20+22))")
                self.wait_for(r"^READY-42$", 2, mark)
                break
            except Failure:
                if self.proc.poll() is not None or time.time() > deadline:
                    raise
        # A prompt printed after the tty echoed the next command, or a kernel
        # message, would land in the middle of command output.
        self.send("PS1=")
        self.sh("mount -t proc proc /proc; mount -t sysfs sys /sys; dmesg -n 1")

    def sh(self, cmd, timeout=60, ok=True):
        """Runs `cmd` in the guest's shell; returns (status, output)."""
        self.seq += 1
        tag = f"K{self.seq}Z"
        mark = len(self.buf)
        self.send(f"{cmd}; echo RC=$?:{tag}")
        m = self.wait_for(rf"^(.*?)RC=(\d+):{tag}$", timeout, mark)
        region = self.buf[mark : m.start(0)]
        echo = f"echo RC=$?:{tag}\n"  # the tty's echo of the command line
        at = region.find(echo)
        out = (region[at + len(echo) :] if at >= 0 else region) + m.group(1)
        rc = int(m.group(2))
        if ok and rc != 0:
            raise Failure(f"guest command failed ({rc}): {cmd}\n    {out.strip()}")
        return rc, out.strip()

    def api(self, method, path, body=None, expect=(200, 204)):
        conn = UnixHTTPConnection(self.api_sock)
        payload = json.dumps(body) if body is not None else None
        conn.request(method, path, payload, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        if resp.status not in expect:
            raise Failure(f"{method} {path} -> {resp.status} {data}")
        return json.loads(data) if data.strip() else None

    def wait_exit(self, timeout=30):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            raise Failure(f"VMM did not exit within {timeout}s ({self.exit_reason()})")

    def healthy(self):
        """Fails if the guest kernel logged a stall, a BUG or an oops."""
        _, out = self.sh(
            "dmesg | grep -E 'rcu: INFO|self-detected stall|soft lockup|hung_task|BUG:|Oops|WARNING:|Call trace' | head -5; true"
        )
        check(not out, f"guest kernel reports:\n    {out}")

    def reboot(self):
        """Checks the guest's health and resets it; Firecracker exits with status 0."""
        self.healthy()
        self.send("reboot -ff")
        code = self.wait_exit()
        check(code == 0, f"exit status {code} after guest reset ({self.exit_reason()})")

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.pump.join(5)
        self.log.close()


def config(ctx, vcpus=1, mem=256, drives=(), **extra):
    cfg = {
        "boot-source": {"kernel_image_path": ctx.kernel, "boot_args": BOOT_ARGS},
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": ctx.rootfs,
                "is_root_device": True,
                "is_read_only": True,
            }
        ]
        + list(drives),
        "machine-config": {"vcpu_count": vcpus, "mem_size_mib": mem},
    }
    for key, value in extra.items():
        if key == "machine":
            cfg["machine-config"].update(value)
        else:
            cfg[key.replace("_", "-")] = value
    return cfg


def md5(path, size=None):
    h = hashlib.md5()
    with open(path, "rb") as f:
        left = size
        while left is None or left > 0:
            chunk = f.read(1 << 20 if left is None else min(1 << 20, left))
            if not chunk:
                break
            h.update(chunk)
            if left is not None:
                left -= len(chunk)
    return h.hexdigest()


def random_file(path, size):
    with open(path, "wb") as f:
        f.write(os.urandom(size))


# ---------------------------------------------------------------- stages


def stage_boot(ctx):
    vm = ctx.vm("boot", [], config(ctx))
    vm.wait_for(r"Run /bin/sh as init process", 60)
    vm.shell()
    _, out = vm.sh("echo WICK-$((6*7))")
    check(out == "WICK-42", f"echo: {out!r}")
    _, arch = vm.sh("uname -m")
    check(arch == "aarch64", f"uname -m: {arch!r}")
    _, cpus = vm.sh("nproc")
    check(cpus == "1", f"nproc: {cpus!r}")
    _, mem = vm.sh("awk '/MemTotal/ {print $2}' /proc/meminfo")
    check(200_000 < int(mem) <= 262_144, f"MemTotal {mem} kB for 256 MiB")
    _, t0 = vm.sh("cat /proc/uptime")
    time.sleep(2)
    _, t1 = vm.sh("cat /proc/uptime")
    dt = float(t1.split()[0]) - float(t0.split()[0])
    check(1.5 < dt < 4, f"guest clock advanced {dt:.2f}s in 2s")
    vm.reboot()
    return f"init reached, serial in/out, clock, reset exits 0"


def stage_smp(ctx):
    vm = ctx.vm("smp", [], config(ctx, vcpus=2))
    vm.shell()
    _, online = vm.sh("cat /sys/devices/system/cpu/online")
    check(online == "0-1", f"online CPUs {online!r}")
    for cpu in (0, 1):
        _, out = vm.sh(f"taskset -c {cpu} sh -c 'echo $((cpu={cpu}+100))'")
        check(out == str(cpu + 100), f"taskset {cpu}: {out!r}")
    _, out = vm.sh("for c in 0 1; do taskset -c $c sh -c 'i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done' & done; wait; echo spun")
    check(out.endswith("spun"), f"parallel work: {out!r}")
    vm.reboot()
    return "2 vCPUs online, work runs on each"


def stage_block(ctx):
    data = os.path.join(ctx.out, "data.img")
    random_file(data, 8 << 20)
    sync_w = os.path.join(ctx.out, "sync.img")
    async_w = os.path.join(ctx.out, "async.img")
    for p in (sync_w, async_w):
        with open(p, "wb") as f:
            f.truncate(8 << 20)
    drives = [
        {"drive_id": "data", "path_on_host": data, "is_root_device": False,
         "is_read_only": True, "io_engine": "Async"},
        {"drive_id": "syncw", "path_on_host": sync_w, "is_root_device": False,
         "is_read_only": False, "io_engine": "Sync"},
        {"drive_id": "asyncw", "path_on_host": async_w, "is_root_device": False,
         "is_read_only": False, "io_engine": "Async"},
    ]
    vm = ctx.vm("block", [], config(ctx, vcpus=2, drives=drives))
    vm.shell()
    _, out = vm.sh("md5sum /dev/vdb")
    check(out.split()[0] == md5(data), f"guest md5 of the Async drive {out!r}")
    _, out = vm.sh("md5sum /usr/bin/bash")
    root_md5 = out.split()[0]
    vm.sh("dd if=/dev/vdb of=/dev/vdc bs=64k count=64 conv=fsync 2>/dev/null")
    vm.sh("dd if=/dev/vdb of=/dev/vdd bs=64k count=64 conv=fsync 2>/dev/null")
    rc, out = vm.sh("echo x | dd of=/dev/vdb 2>&1", ok=False)
    check(rc != 0, f"write to a read-only drive succeeded: {out!r}")
    vm.reboot()
    want = md5(data, 4 << 20)
    check(md5(sync_w, 4 << 20) == want, "Sync drive: host sees different data")
    check(md5(async_w, 4 << 20) == want, "Async drive: host sees different data")
    return f"Async read md5, Sync and Async writes reach the host, read-only enforced (root bash {root_md5[:8]})"


def guest_vsock_services(vm, uds):
    vm.sh("command -v socat >/dev/null")
    vm.sh("(socat -t 30 VSOCK-LISTEN:52,fork EXEC:cat >/dev/null 2>&1 &)")
    # The connection is refused (closed) until socat listens.
    deadline = time.time() + 10
    while True:
        try:
            vsock_connect(uds).close()
            return
        except Failure:
            if time.time() > deadline:
                raise
            time.sleep(0.2)


def vsock_connect(uds):
    """Connects to guest port 52 through the vsock device's Unix socket."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(uds)
    s.sendall(b"CONNECT 52\n")
    line = b""
    while not line.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            s.close()
            raise Failure(f"vsock handshake closed after {line!r}")
        line += b
    check(line.startswith(b"OK "), f"vsock handshake {line!r}")
    return s


def vsock_host_to_guest(uds, size):
    s = vsock_connect(uds)
    payload = os.urandom(size)
    # A host end that shuts down its write side closes the whole connection
    # (upstream behaviour), so the echo is read back by length.
    t = threading.Thread(target=s.sendall, args=(payload,), daemon=True)
    t.start()
    echo = bytearray()
    while len(echo) < size:
        b = s.recv(65536)
        if not b:
            break
        echo += b
    t.join()
    s.close()
    check(bytes(echo) == payload, f"vsock echo: {len(echo)} of {size} bytes, equal={bytes(echo) == payload}")


def vsock_guest_to_host(vm, uds):
    path = f"{uds}_53"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    srv.settimeout(30)
    got = {}

    def accept():
        try:
            c, _ = srv.accept()
            data = b""
            while True:
                b = c.recv(65536)
                if not b:
                    break
                data += b
            got["data"] = data
            c.close()
        except OSError as e:
            got["error"] = e

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    vm.sh("echo guest-to-host-$((6*7)) | socat -t 5 - VSOCK-CONNECT:2:53")
    t.join(30)
    srv.close()
    os.unlink(path)
    check(got.get("data") == b"guest-to-host-42\n", f"host received {got!r}")


def stage_vsock(ctx):
    uds = os.path.join(ctx.sock, "v.sock")
    cfg = config(ctx, vcpus=2, vsock={"guest_cid": 3, "uds_path": uds})
    vm = ctx.vm("vsock", [], cfg)
    vm.shell()
    guest_vsock_services(vm, uds)
    vsock_host_to_guest(uds, 4 << 20)
    vsock_guest_to_host(vm, uds)
    vm.reboot()
    return "host->guest CONNECT 4 MiB echo, guest->host <uds>_53"


# A host-side switch for the Unix datagram endpoint: answers ARP and ICMP echo
# for HOST_IP and echoes UDP port 7, checking every checksum the guest sent.


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Switch:
    def __init__(self, endpoint, path):
        self.endpoint = endpoint
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(path)
        self.sock.settimeout(0.2)
        self.path = path
        self.bad = []
        self.counts = {"arp": 0, "icmp": 0, "udp": 0}
        self.stop = False
        deadline = time.time() + 10
        while not os.path.exists(endpoint):
            check(time.time() < deadline, f"no network endpoint at {endpoint}")
            time.sleep(0.05)
        self.sock.sendto(b"", endpoint)  # attach
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def send(self, dst, ethertype, payload):
        self.sock.sendto(dst + HOST_MAC + struct.pack("!H", ethertype) + payload, self.endpoint)

    def run(self):
        while not self.stop:
            try:
                frame = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.handle(frame)
            except Exception as e:  # a malformed frame is a test failure
                self.bad.append(f"{e!r} in {frame[:64].hex()}")

    def handle(self, frame):
        dst, src, ethertype = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        body = frame[14:]
        host_ip = socket.inet_aton(HOST_IP)
        if ethertype == 0x0806:
            op = struct.unpack("!H", body[6:8])[0]
            if op == 1 and body[24:28] == host_ip:
                self.counts["arp"] += 1
                reply = body[:6] + struct.pack("!H", 2) + HOST_MAC + host_ip + body[8:18]
                self.send(src, 0x0806, reply)
            return
        if ethertype != 0x0800:
            return
        ihl = (body[0] & 0xF) * 4
        total = struct.unpack("!H", body[2:4])[0]
        ip = body[:total]
        if csum(ip[:ihl]) != 0:
            self.bad.append(f"IPv4 header checksum {ip[:ihl].hex()}")
            return
        if ip[16:20] != host_ip:
            return
        proto, s_ip = ip[9], ip[12:16]
        l4 = ip[ihl:]
        if proto == 1 and l4[0] == 8:
            if csum(l4) != 0:
                self.bad.append("ICMP checksum")
                return
            self.counts["icmp"] += 1
            icmp = b"\0\0\0\0" + l4[4:]
            icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
            self.send(src, 0x0800, self.ipv4(1, s_ip, icmp))
        elif proto == 17:
            sport, dport, length, ck = struct.unpack("!HHHH", l4[:8])
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, length)
            if ck == 0 or csum(pseudo + l4[:length]) != 0:
                self.bad.append(f"UDP checksum {ck:#x}")
                return
            if dport != 7:
                return
            self.counts["udp"] += 1
            data = l4[8:length]
            udp = struct.pack("!HHHH", 7, sport, 8 + len(data), 0) + data
            pseudo = ip[16:20] + s_ip + struct.pack("!BBH", 0, 17, len(udp))
            udp = udp[:6] + struct.pack("!H", csum(pseudo + udp) or 0xFFFF) + udp[8:]
            self.send(src, 0x0800, self.ipv4(17, s_ip, udp))

    def ipv4(self, proto, dst, payload):
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                          socket.inet_aton(HOST_IP), dst)
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        return hdr + payload

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.sock.close()
        os.unlink(self.path)


def guest_net_up(vm, ip):
    _, out = vm.sh("cat /sys/class/net/eth0/address")
    check(out == GUEST_MAC, f"guest MAC {out!r}")
    vm.sh(f"ip addr add {ip}/24 dev eth0 && ip link set eth0 up && ip link set lo up")


def stage_net(ctx):
    endpoint = os.path.join(ctx.sock, "n.ep")
    cfg = config(ctx, vcpus=2, network_interfaces=[
        {"iface_id": "eth0", "host_dev_name": endpoint, "guest_mac": GUEST_MAC}])
    vm = ctx.vm("net", [], cfg)
    switch = Switch(endpoint, os.path.join(ctx.sock, "n.sw"))
    try:
        vm.shell()
        guest_net_up(vm, GUEST_IP)
        _, out = vm.sh(f"ping -c 3 -i 0.3 -W 3 {HOST_IP}")
        check(" 0% packet loss" in out, f"ping: {out}")
        _, out = vm.sh(f"ping -c 2 -s 1400 -W 3 {HOST_IP}")
        check(" 0% packet loss" in out, f"ping -s 1400: {out}")
        _, out = vm.sh(f"echo udp-$((6*7)) | socat -t 3 - UDP:{HOST_IP}:7")
        check(out == "udp-42", f"UDP echo {out!r}")
        vm.reboot()
    finally:
        switch.close()
    check(not switch.bad, f"bad frames from the guest: {switch.bad[:3]}")
    c = switch.counts
    check(c["arp"] >= 1 and c["icmp"] >= 5 and c["udp"] >= 1, f"switch saw {c}")
    return f"Unix datagram endpoint: ARP, ICMP (1400 B), UDP echo, checksums valid ({c})"


def stage_vmnet(ctx):
    cfg = config(ctx, vcpus=2, network_interfaces=[
        {"iface_id": "eth0", "host_dev_name": "vmnet-shared", "guest_mac": GUEST_MAC}])
    vm = ctx.vm("vmnet", [], cfg)
    m = vm.wait_for(r"vmnet: network (\d+\.\d+\.\d+)\.(\d+)/24", 20)
    net, gw = m.group(1), f"{m.group(1)}.{m.group(2)}"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    vm.shell()
    guest_net_up(vm, f"{net}.77")
    deadline = time.time() + 15
    while True:  # the host's bridge address appears once the guest uses it
        try:
            srv.bind((gw, 0))
            break
        except OSError:
            check(time.time() < deadline, f"cannot bind the vmnet host address {gw}")
            vm.sh(f"ping -c 1 -W 1 {gw} >/dev/null", ok=False)
    srv.listen(1)
    srv.settimeout(30)
    port = srv.getsockname()[1]
    payload = os.urandom(8 << 20)

    def serve():
        c, _ = srv.accept()
        c.sendall(payload)
        c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    _, out = vm.sh(f"socat -u TCP:{gw}:{port} - | md5sum", timeout=60)
    t.join(10)
    check(out.split()[0] == hashlib.md5(payload).hexdigest(), f"TCP 8 MiB host->guest md5 {out!r}")
    # Guest to host: segmentation and checksum offload on the transmit side.
    got = {}

    def receive():
        c, _ = srv.accept()
        h, n = hashlib.md5(), 0
        while True:
            b = c.recv(1 << 16)
            if not b:
                break
            h.update(b)
            n += len(b)
        got["md5"], got["len"] = h.hexdigest(), n
        c.close()

    t = threading.Thread(target=receive, daemon=True)
    t.start()
    vm.sh("mount -t tmpfs tmpfs /tmp && head -c 8388608 /dev/urandom > /tmp/p")
    _, out = vm.sh(f"md5sum /tmp/p; socat -u FILE:/tmp/p TCP:{gw}:{port}", timeout=60)
    t.join(30)
    srv.close()
    check(got.get("md5") == out.split()[0], f"TCP 8 MiB guest->host: host got {got}, guest sent {out!r}")
    _, out = vm.sh(f"ping -c 2 -W 3 {gw}")
    check(" 0% packet loss" in out, f"ping gateway: {out}")
    vm.reboot()
    return f"vmnet-shared: TCP 8 MiB each way, ping {gw}"


def stage_snapshot(ctx, pci=False):
    tag = "psnap" if pci else "snap"
    extra = ["--enable-pci"] if pci else []
    uds = os.path.join(ctx.sock, f"{tag}.v")
    data = os.path.join(ctx.out, f"{tag}.img")
    random_file(data, 4 << 20)
    drives = [{"drive_id": "data", "path_on_host": data, "is_root_device": False,
               "is_read_only": True, "io_engine": "Async"}]
    cfg = config(ctx, vcpus=2, drives=drives, vsock={"guest_cid": 3, "uds_path": uds})
    vm = ctx.vm(f"{tag}1", extra, cfg)
    vm.shell()
    if pci:
        _, out = vm.sh("ls /sys/bus/pci/devices | wc -l")
        check(int(out) >= 3, f"{out} PCI devices for root, data and vsock")
    guest_vsock_services(vm, uds)
    vm.sh("A=before-$((6*7))")
    _, bash_md5 = vm.sh("md5sum /usr/bin/bash")
    ctx.bash_md5 = bash_md5
    state = os.path.join(ctx.out, f"{tag}.state")
    mem = os.path.join(ctx.out, f"{tag}.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
    vm.kill()
    os.unlink(uds)
    check(os.path.getsize(mem) == 256 << 20, f"memory file is {os.path.getsize(mem)} bytes")

    vm = ctx.vm(f"{tag}2", extra)
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": mem},
                                     "resume_vm": True})
    restored_checks(vm, bash_md5, data)
    vsock_host_to_guest(uds, 1 << 20)
    vm.reboot()
    return "Full snapshot, restore in a new process: shell state, block, vsock" + (" over PCI" if pci else "")


def restored_checks(vm, bash_md5, data):
    _, out = vm.sh("echo restored $A")
    check(out == "restored before-42", f"after restore: {out!r}")
    # The guest counter runs at host speed and agrees between the vCPUs.
    t0 = time.time()
    _, out = vm.sh("taskset -c 0 cat /proc/uptime; sleep 1; taskset -c 1 cat /proc/uptime")
    dt = time.time() - t0
    a, b = (float(line.split()[0]) for line in out.splitlines())
    check(0.9 < b - a <= dt + 0.1, f"guest clock advanced {b - a:.2f}s across vCPUs in {dt:.2f}s")
    _, out = vm.sh("md5sum /usr/bin/bash")
    check(out == bash_md5, f"root drive after restore: {out!r}")
    if data:
        _, out = vm.sh("echo 3 > /proc/sys/vm/drop_caches; md5sum /dev/vdb")
        check(out.split()[0] == md5(data), f"data drive after restore: {out!r}")


def stage_diff(ctx):
    cfg = config(ctx, vcpus=2, machine={"track_dirty_pages": True})
    vm = ctx.vm("diff1", [], cfg)
    vm.shell()
    vm.sh("A=before-$((6*7))")
    _, bash_md5 = vm.sh("md5sum /usr/bin/bash")
    base = os.path.join(ctx.out, "base.mem")
    diff = os.path.join(ctx.out, "diff.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full",
                                       "snapshot_path": os.path.join(ctx.out, "full.state"),
                                       "mem_file_path": base})
    vm.api("PATCH", "/vm", {"state": "Resumed"})
    vm.sh("B=second-$((7*7)); cat /usr/bin/* > /dev/null 2>&1; true")
    state = os.path.join(ctx.out, "diff.state")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Diff", "snapshot_path": state, "mem_file_path": diff})
    vm.kill()
    allocated = os.stat(diff).st_blocks * 512
    check(os.path.getsize(diff) == 256 << 20, f"diff file is {os.path.getsize(diff)} bytes")
    check(0 < allocated < 200 << 20, f"diff file allocates {allocated >> 20} MiB of 256 (holes lost?)")
    r = subprocess.run([ctx.snapshot_editor, "edit-memory", "rebase", "--memory-path", base,
                        "--diff-path", diff], capture_output=True, text=True)
    check(r.returncode == 0, f"snapshot-editor rebase: {r.returncode} {r.stderr.strip()}")
    vm = ctx.vm("diff2", [])
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": base},
                                     "resume_vm": True})
    restored_checks(vm, bash_md5, None)
    _, out = vm.sh("echo $B")
    check(out == "second-49", f"diff state after restore: {out!r}")
    vm.reboot()
    return f"Diff snapshot ({allocated >> 20} MiB allocated), snapshot-editor rebase, restore"


def stage_uffd(ctx):
    state = os.path.join(ctx.out, "snap.state")
    mem = os.path.join(ctx.out, "snap.mem")
    check(os.path.exists(state), "needs the snapshot stage's files")
    # The snapshot stage's drive and vsock paths are reused as they were.
    uds = os.path.join(ctx.sock, "snap.v")
    if os.path.exists(uds):
        os.unlink(uds)
    sock = os.path.join(ctx.sock, "uffd")
    log = open(os.path.join(ctx.out, "uffd-handler.log"), "w")
    handler = subprocess.Popen([ctx.uffd_handler, sock, mem], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while not os.path.exists(sock):
            check(handler.poll() is None and time.time() < deadline, f"uffd handler did not start ({handler.poll()})")
            time.sleep(0.05)
        vm = ctx.vm("uffd", [])
        vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                         "mem_backend": {"backend_type": "Uffd", "backend_path": sock},
                                         "resume_vm": True})
        restored_checks(vm, ctx.bash_md5, os.path.join(ctx.out, "snap.img"))
        vsock_host_to_guest(uds, 1 << 20)
        _, out = vm.sh("head -c 64m /dev/zero | md5sum")  # fresh pages after restore
        check(out.split()[0] == "7f614da9329cd3aebf59b91aadc30bf0", f"64 MiB of zeros: {out!r}")
        vm.reboot()
    finally:
        if handler.poll() is None:
            handler.terminate()
        handler.wait(5)
        log.close()
    return "restore with the Uffd backend served by uffd_on_demand_handler"


def stage_pci(ctx):
    return stage_snapshot(ctx, pci=True)


def stage_vhost_user(ctx):
    img = os.path.join(ctx.out, "vub.img")
    random_file(img, 8 << 20)
    want = md5(img)
    sock = os.path.join(ctx.sock, "vub")
    log = open(os.path.join(ctx.out, "vub.log"), "w")
    backend = subprocess.Popen([ctx.vub, sock, img], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while not os.path.exists(sock):
            check(backend.poll() is None and time.time() < deadline, f"vhost-user backend did not start ({backend.poll()})")
            time.sleep(0.05)
        drives = [{"drive_id": "vub", "socket": sock, "is_root_device": False}]
        vm = ctx.vm("vhost-user", [], config(ctx, vcpus=2, drives=drives))
        vm.shell()
        _, out = vm.sh("md5sum /dev/vdb")
        check(out.split()[0] == want, f"guest md5 over vhost-user {out!r}")
        vm.sh("echo vhost-user-$((6*7)) | dd of=/dev/vdb bs=512 seek=8 conv=fsync,notrunc 2>/dev/null")
        vm.reboot()
        with open(img, "rb") as f:
            f.seek(4096)
            check(f.read(14) == b"vhost-user-42\n", "guest write not in the backend's image")
    finally:
        if backend.poll() is None:
            backend.terminate()
        backend.wait(5)
        log.close()
    return "vhost-user-blk backend in another process: read md5, write reaches the image"


STAGES = {
    "boot": stage_boot,
    "smp": stage_smp,
    "block": stage_block,
    "vsock": stage_vsock,
    "net": stage_net,
    "vmnet": stage_vmnet,
    "snapshot": stage_snapshot,
    "diff": stage_diff,
    "uffd": stage_uffd,
    "pci": stage_pci,
    "vhost-user": stage_vhost_user,
}


# ---------------------------------------------------------------- driver


class Context:
    def __init__(self, args):
        self.firecracker = args.firecracker
        self.snapshot_editor = args.snapshot_editor
        self.uffd_handler = args.uffd_handler
        self.vub = args.vhost_user_blk
        self.out = args.out
        # Unix socket paths must be shorter than 104 bytes.
        self.sock = tempfile.mkdtemp(prefix="wick-bt-", dir="/tmp")
        self.kernel = fetch(args.cache, KERNEL)
        self.rootfs = fetch(args.cache, ROOTFS)
        self.vms = []
        self.bash_md5 = None

    def vm(self, *a, **kw):
        vm = Vm(self, *a, **kw)
        self.vms.append(vm)
        return vm

    def cleanup(self):
        for vm in self.vms:
            vm.kill()
        self.vms = []


def fetch(cache, name):
    path = os.path.join(cache, name)
    if not os.path.exists(path):
        os.makedirs(cache, exist_ok=True)
        print(f"downloading {name}", flush=True)
        tmp = path + ".part"
        with urllib.request.urlopen(f"{ASSETS}/{name}") as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        os.rename(tmp, path)
    return path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--firecracker", required=True)
    p.add_argument("--snapshot-editor", required=True)
    p.add_argument("--uffd-handler", required=True)
    p.add_argument("--vhost-user-blk", required=True)
    p.add_argument("--cache", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("stages", nargs="*", default=list(STAGES),
                   help=f"stages to run, in order (default: all): {', '.join(STAGES)}")
    args = p.parse_args()
    for s in args.stages:
        if s not in STAGES:
            p.error(f"unknown stage {s}")
    os.makedirs(args.out, exist_ok=True)
    ctx = Context(args)
    results = []
    try:
        for name in args.stages:
            print(f"== {name}", flush=True)
            t0 = time.time()
            try:
                detail = STAGES[name](ctx)
                results.append((name, True, detail))
            except Failure as e:
                results.append((name, False, str(e)))
            except Exception:
                results.append((name, False, traceback.format_exc()))
            finally:
                ctx.cleanup()
            ok, detail = results[-1][1:]
            print(f"   {'PASS' if ok else 'FAIL'} ({time.time() - t0:.1f}s): {detail}", flush=True)
    finally:
        ctx.cleanup()
        shutil.rmtree(ctx.sock, ignore_errors=True)
    print()
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail.splitlines()[0]}")
    failed = sum(not ok for _, ok, _ in results)
    print(f"\n{len(results) - failed} passed, {failed} failed; logs in {args.out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
