# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Scenario tests of a macOS Firecracker build against upstream's CI guest.

Run through tools/macos/boot-test.sh, which builds and signs the binaries and
passes their paths. Every stage boots its own VM (or restores one) and checks
what the guest and the host see; the summary lists each stage as PASS or FAIL
with the reason, and the exit status is non-zero if any stage failed.
"""

import argparse
import ctypes
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import signal
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
        # Diagnosis: extra Firecracker arguments for every VM of the run
        # (WICK_BOOT_TEST_FC_ARGS="--no-seccomp" tells a sandbox problem from
        # another one).
        cmd += os.environ.get("WICK_BOOT_TEST_FC_ARGS", "").split()
        self.buf = ""
        self.cond = threading.Condition()
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.pump = threading.Thread(target=self._pump, daemon=True)
        self.pump.start()
        # Registered at once, so a run stopped while it starts (a signal)
        # still kills it.
        ctx.vms.append(self)
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
    cpu_offline_online(vm, "smp")
    vm.reboot()
    return "2 vCPUs online, work runs on each; cpu1 offline and online 3 times (PSCI CPU_OFF, CPU_ON)"


# A CPU taken offline and back online (PSCI CPU_OFF, then CPU_ON, which KVM
# answers with a reset of the vCPU: arch/arm64/kvm/psci.c kvm_psci_vcpu_on,
# reset.c kvm_reset_vcpu), three times; work then runs on it. The guest
# command, for boot-test.ps1 to do the same:
CPU_OFFLINE_ONLINE = ("for i in 1 2 3; do echo 0 > /sys/devices/system/cpu/cpu1/online || echo off-failed; "
                      "echo 1 > /sys/devices/system/cpu/cpu1/online || echo on-failed; done; "
                      "taskset -c 1 sh -c 'i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; echo cpu1-ran'; "
                      "cat /sys/devices/system/cpu/online")


def cpu_offline_online(vm, what):
    _, out = vm.sh(CPU_OFFLINE_ONLINE, timeout=60)
    check(out.splitlines()[-2:] == ["cpu1-ran", "0-1"], f"{what}: cpu1 offline/online: {out!r}")


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
    # The drive's serial (VIRTIO_BLK_GET_ID): upstream's build_device_id, in
    # kvmtool's form, the opened file's st_dev, st_rdev and st_ino in decimal,
    # cut to the driver's 20 bytes.
    serials = {}
    for dev, path in (("vda", ctx.rootfs), ("vdb", data), ("vdc", sync_w), ("vdd", async_w)):
        st = os.stat(path)
        want = f"{st.st_dev}{st.st_rdev}{st.st_ino}"[:20]
        _, got = vm.sh(f"cat /sys/block/{dev}/serial")
        check(got == want, f"{dev} serial {got!r}, upstream's rule gives {want!r}")
        serials[dev] = got
    check(len(set(serials.values())) == len(serials), f"drive serials not distinct: {serials}")
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
    return (f"Async read md5, Sync and Async writes reach the host, read-only enforced, serials from "
            f"st_dev/st_rdev/st_ino (root bash {root_md5[:8]})")


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
        # The buffers of Firecracker's own endpoint (platform::net): macOS's
        # default receive buffer for a datagram socket is 4 KiB
        # (net.local.dgram.recvspace), and a frame the endpoint cannot send
        # without blocking is dropped, as a TAP drops one.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind(path)
        self.sock.settimeout(0.2)
        self.path = path
        self.bad = []
        self.counts = {"arp": 0, "icmp": 0, "udp": 0}
        self.sink = []  # (arrival time, bytes) of UDP datagrams to port 9 (discard)
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
            if dport == 9:
                self.sink.append((time.monotonic(), length - 8))
                return
            if dport != 7:
                return
            self.counts["udp"] += 1
            data = l4[8:length]
            udp = struct.pack("!HHHH", 7, sport, 8 + len(data), 0) + data
            pseudo = ip[16:20] + s_ip + struct.pack("!BBH", 0, 17, len(udp))
            udp = udp[:6] + struct.pack("!H", csum(pseudo + udp) or 0xFFFF) + udp[8:]
            self.send(src, 0x0800, self.ipv4(17, s_ip, udp))

    def flood(self, stop, size=1400):
        """Sends UDP datagrams of `size` bytes to the guest's port 9 until
        `stop` is set, as fast as the endpoint takes them; returns the bytes
        sent. A full endpoint (timeout, ENOBUFS) drops the datagram, as a TAP
        whose queue is full does."""
        guest_ip, sent = socket.inet_aton(GUEST_IP), 0
        guest_mac = bytes.fromhex(GUEST_MAC.replace(":", ""))
        data = b"\0" * size
        udp = struct.pack("!HHHH", 4000, 9, 8 + size, 0) + data
        pseudo = socket.inet_aton(HOST_IP) + guest_ip + struct.pack("!BBH", 0, 17, len(udp))
        udp = udp[:6] + struct.pack("!H", csum(pseudo + udp) or 0xFFFF) + udp[8:]
        frame = guest_mac + HOST_MAC + struct.pack("!H", 0x0800) + self.ipv4(17, guest_ip, udp)
        while not stop.is_set():
            try:
                self.sock.sendto(frame, self.endpoint)
                sent += size
            except (socket.timeout, OSError):
                time.sleep(0.001)
        return sent

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
        rates = net_rate_limiters(vm, switch)
        vm.reboot()
    finally:
        switch.close()
    check(not switch.bad, f"bad frames from the guest: {switch.bad[:3]}")
    c = switch.counts
    check(c["arp"] >= 1 and c["icmp"] >= 5 and c["udp"] >= 1, f"switch saw {c}")
    return f"Unix datagram endpoint: ARP, ICMP (1400 B), UDP echo, checksums valid ({c}); {rates}"


# 1 MiB/s: a bucket of 128 KiB refilled every 125 ms (upstream's token bucket:
# `size` bytes, `refill_time` ms, full at the start).
NET_LIMIT = {"bandwidth": {"size": 128 << 10, "refill_time": 125}}
NET_LIMIT_BPS = (128 << 10) * 1000 // 125


def net_tx_rate(vm, switch, total=3 << 20):
    """The rate at which `total` bytes the guest sends to the host's port 9
    reach the host (bytes per second, between the first and the last datagram)."""
    switch.sink = []
    vm.sh(f"head -c {total} /dev/zero | socat -b 1400 -u - UDP:{HOST_IP}:9", timeout=60)
    time.sleep(0.5)  # the last frames through the endpoint
    sink = list(switch.sink)
    check(len(sink) >= 2, f"the host got {len(sink)} datagrams of {total} bytes sent")
    got = sum(n for _, n in sink)
    return got, (got - sink[0][1]) / max(sink[-1][0] - sink[0][0], 1e-6)


def net_rx_rate(vm, switch, seconds=2):
    """The guest's receive rate (its rx_bytes over `seconds`) while the host
    floods it with UDP to port 9 (bytes per second)."""
    stop = threading.Event()
    sent = {}
    t = threading.Thread(target=lambda: sent.update(n=switch.flood(stop)), daemon=True)
    t.start()
    try:
        time.sleep(0.5)  # past the bucket's first, full, budget
        _, out = vm.sh("a=$(cat /sys/class/net/eth0/statistics/rx_bytes); S=$(date +%s%N); "
                       f"sleep {seconds}; b=$(cat /sys/class/net/eth0/statistics/rx_bytes); "
                       "echo $((b - a)) $(( ($(date +%s%N) - S) / 1000 ))")
    finally:
        stop.set()
        t.join(10)
    got, us = (int(x) for x in out.split())
    check(sent.get("n", 0) > got, f"host flood sent {sent.get('n')} bytes, guest counted {got}")
    return got / (us / 1e6)


def net_rate_limiters(vm, switch):
    """rx and tx bandwidth limiters set on the running device (PATCH): each
    direction runs at the limit, and without one at three times it or more."""
    mib = 1 << 20
    _, tx_free = net_tx_rate(vm, switch)
    rx_free = net_rx_rate(vm, switch)
    vm.api("PATCH", "/network-interfaces/eth0", {"iface_id": "eth0", "tx_rate_limiter": NET_LIMIT})
    tx_got, tx = net_tx_rate(vm, switch)
    vm.api("PATCH", "/network-interfaces/eth0", {"iface_id": "eth0", "rx_rate_limiter": NET_LIMIT,
                                                 "tx_rate_limiter": {"bandwidth": {"size": 0, "refill_time": 0}}})
    rx = net_rx_rate(vm, switch)
    vm.api("PATCH", "/network-interfaces/eth0", {"iface_id": "eth0",
                                                 "rx_rate_limiter": {"bandwidth": {"size": 0, "refill_time": 0}}})
    _, tx_after = net_tx_rate(vm, switch)
    summary = (f"tx {tx_free / mib:.1f} -> {tx / mib:.2f} MiB/s, rx {rx_free / mib:.1f} -> {rx / mib:.2f} MiB/s "
               f"at a 1 MiB/s limit; tx {tx_after / mib:.1f} MiB/s once removed")
    check(tx_got >= 1 << 20, f"throttled tx: only {tx_got} bytes reached the host ({summary})")
    check(0.5 * NET_LIMIT_BPS <= tx <= 1.25 * NET_LIMIT_BPS, f"tx limiter: {summary}")
    check(0.5 * NET_LIMIT_BPS <= rx <= 1.25 * NET_LIMIT_BPS, f"rx limiter: {summary}")
    check(tx_free >= 3 * NET_LIMIT_BPS and rx_free >= 3 * NET_LIMIT_BPS and tx_after >= 3 * NET_LIMIT_BPS,
          f"unthrottled rates not above the limit: {summary}")
    return summary


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
    # A restored vCPU taken offline and online (the case that found CPU_ON
    # not resetting the vCPU).
    cpu_offline_online(vm, "restored")
    vm.reboot()
    return ("Full snapshot, restore in a new process: shell state, block, vsock, cpu1 offline/online"
            + (" over PCI" if pci else ""))


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


def stage_hugepages(ctx):
    # docs/PORTING.md row 10. macOS gives user space no superpage on Apple
    # silicon (measured: libc test_no_host_superpages), so `huge_pages: 2M`
    # is what Firecracker sees of Linux's hugetlb: guest memory in whole,
    # 2 MiB-aligned huge pages on host pages, and a snapshot restored through
    # a userfaultfd handler that is faulted and filled 2 MiB at a time (the
    # snapshot's mappings carry the 2 MiB page size; the compatibility uffd
    # serves it: test_huge_page_ranges_fault_and_fill_whole_pages). With a
    # vhost-user device the memory is a huge page memfd, shared with the
    # backend (memfd test_hugetlb_memfd_maps_huge).
    vm = ctx.vm("huge-odd", [], config(ctx, mem=255, machine={"huge_pages": "2M"}))
    code = vm.wait_exit(15)
    vm.pump.join(5)  # the last lines of the console, drained after the exit
    check(code not in (None, 0), f"255 MiB on 2 MiB pages accepted: exit {code}")
    check("not a multiple of the configured page size" in vm.buf, f"the refusal does not name the page size: {vm.exit_reason()}")
    uds = os.path.join(ctx.sock, "huge.v")
    cfg = config(ctx, vcpus=2, machine={"huge_pages": "2M"}, vsock={"guest_cid": 3, "uds_path": uds})
    vm = ctx.vm("huge1", [], cfg)
    vm.shell()
    _, mem = vm.sh("awk '/MemTotal/ {print $2}' /proc/meminfo")
    check(200_000 < int(mem) <= 262_144, f"MemTotal {mem} kB for 256 MiB")
    vm.sh("mount -t tmpfs -o size=200m tmpfs /tmp && head -c 160m /dev/urandom > /tmp/f && md5sum /tmp/f > /tmp/a", 120)
    _, out = vm.sh("md5sum /tmp/f | cmp - /tmp/a && echo same", 60)
    check(out == "same", f"160 MiB in guest memory read back differently: {out!r}")
    vm.sh("A=before-$((6*7))")
    _, bash_md5 = vm.sh("md5sum /usr/bin/bash")
    state = os.path.join(ctx.out, "huge.state")
    mem_file = os.path.join(ctx.out, "huge.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem_file})
    vm.kill()
    if os.path.exists(uds):
        os.unlink(uds)
    check(os.path.getsize(mem_file) == 256 << 20, f"memory file is {os.path.getsize(mem_file)} bytes")
    sock = os.path.join(ctx.sock, "huge-uffd")
    log = open(os.path.join(ctx.out, "huge-uffd-handler.log"), "w")
    handler = subprocess.Popen([ctx.uffd_handler, sock, mem_file], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while not os.path.exists(sock):
            check(handler.poll() is None and time.time() < deadline, f"uffd handler did not start ({handler.poll()})")
            time.sleep(0.05)
        vm = ctx.vm("huge2", [])
        vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                         "mem_backend": {"backend_type": "Uffd", "backend_path": sock},
                                         "resume_vm": True})
        restored_checks(vm, bash_md5, None)
        # The 160 MiB in the restored guest's memory came through the handler.
        _, out = vm.sh("md5sum /tmp/f | cmp - /tmp/a && echo same", 120)
        check(out == "same", f"160 MiB after the uffd restore: {out!r}")
        _, out = vm.sh("head -c 64m /dev/zero | md5sum")
        check(out.split()[0] == "7f614da9329cd3aebf59b91aadc30bf0", f"64 MiB of zeros: {out!r}")
        vm.reboot()
    finally:
        if handler.poll() is None:
            handler.terminate()
        handler.wait(5)
        log.close()
    vhost_user_round(ctx, "huge-vub", {"huge_pages": "2M"})
    return "a 2 vCPU guest on 2 MiB pages boots and keeps 160 MiB written; an odd size is refused; a snapshot of it restores through the Uffd backend 2 MiB at a time; a vhost-user drive on a huge page memfd"


def stage_pci(ctx):
    return stage_snapshot(ctx, pci=True)


def stage_vhost_user(ctx):
    vhost_user_round(ctx, "vhost-user", {})
    return "vhost-user-blk backend in another process: read md5, write reaches the image"


def vhost_user_round(ctx, name, machine):
    """A guest (`machine` settings) with a vhost-user-blk drive served by the
    test backend: the guest reads the image's md5 and its write reaches the
    image. With a vhost-user device Firecracker backs guest memory with a
    memfd (shared with the backend)."""
    img = os.path.join(ctx.out, f"{name}.img")
    random_file(img, 8 << 20)
    want = md5(img)
    sock = os.path.join(ctx.sock, f"{name}.vub")
    log = open(os.path.join(ctx.out, f"{name}-backend.log"), "w")
    backend = subprocess.Popen([ctx.vub, sock, img], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 10
        while not os.path.exists(sock):
            check(backend.poll() is None and time.time() < deadline, f"vhost-user backend did not start ({backend.poll()})")
            time.sleep(0.05)
        drives = [{"drive_id": "vub", "socket": sock, "is_root_device": False}]
        vm = ctx.vm(name, [], config(ctx, vcpus=2, drives=drives, machine=machine))
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


def stage_devices(ctx):
    """Logger, metrics, MMDS, balloon, entropy and a rate limiter: what upstream
    configures beside the devices above (and the system calls they make)."""
    log = os.path.join(ctx.out, "devices.fc.log")
    metrics = os.path.join(ctx.out, "devices.metrics")
    for path in (log, metrics):
        open(path, "w").close()
    data = os.path.join(ctx.out, "devices.img")
    random_file(data, 4 << 20)
    endpoint = os.path.join(ctx.sock, "d.ep")
    drives = [{"drive_id": "data", "path_on_host": data, "is_root_device": False, "is_read_only": True,
               "rate_limiter": {"bandwidth": {"size": 1 << 20, "refill_time": 100}}}]
    cfg = config(ctx, vcpus=2, mem=512, drives=drives,
                 network_interfaces=[{"iface_id": "eth0", "host_dev_name": endpoint, "guest_mac": GUEST_MAC}],
                 mmds_config={"version": "V2", "network_interfaces": ["eth0"]},
                 balloon={"amount_mib": 0, "deflate_on_oom": True, "stats_polling_interval_s": 1},
                 entropy={}, logger={"log_path": log, "level": "Info"}, metrics={"metrics_path": metrics})
    vm = ctx.vm("devices", [], cfg)
    switch = Switch(endpoint, os.path.join(ctx.sock, "d.sw"))
    try:
        vm.shell()
        # Entropy device.
        _, out = vm.sh("head -c 64 /dev/hwrng | od -An -tx1 | wc -w")
        check(out == "64", f"64 bytes from virtio-rng: {out!r}")
        # Rate limiter: 4 MiB at 1 MiB per 100 ms takes at least ~300 ms.
        _, out = vm.sh("S=$(date +%s%N); dd if=/dev/vdb of=/dev/null bs=1M iflag=direct 2>/dev/null;"
                       " echo $(( ($(date +%s%N) - S) / 1000000 ))")
        check(int(out) >= 250, f"4 MiB read past a 10 MiB/s limiter in {out} ms")
        # MMDS (V2: a token, then the data).
        vm.api("PUT", "/mmds", {"wick": {"answer": "v42"}})
        guest_net_up(vm, GUEST_IP)
        vm.sh("ip route add 169.254.169.254 dev eth0")
        _, token = vm.sh("printf 'PUT /latest/api/token HTTP/1.1\\r\\nX-metadata-token-ttl-seconds: 60\\r\\n\\r\\n'"
                         " | socat -t 5 - TCP:169.254.169.254:80 | tail -1")
        check(len(token) > 20, f"MMDS token {token!r}")
        _, out = vm.sh(f"printf 'GET /wick/answer HTTP/1.1\\r\\nX-metadata-token: {token}\\r\\n\\r\\n'"
                       " | socat -t 5 - TCP:169.254.169.254:80 | tail -1")
        check(out == "v42", f"MMDS answer {out!r}")
        # Balloon: inflate by 64 MiB, statistics.
        vm.api("PATCH", "/balloon", {"amount_mib": 64})
        deadline = time.time() + 30
        while True:
            stats = vm.api("GET", "/balloon/statistics")
            if stats.get("actual_mib", 0) >= 64:
                break
            check(time.time() < deadline, f"balloon statistics {stats}")
            time.sleep(0.5)
        check(stats.get("actual_mib") == 64 and "free_memory" in stats, f"balloon statistics {stats}")
        vm.api("PATCH", "/balloon", {"amount_mib": 0})
        # Metrics, flushed on demand.
        vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
        with open(metrics) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        check(lines and "utc_timestamp_ms" in lines[-1] and lines[-1]["block"]["read_bytes"] >= 4 << 20,
              f"metrics: {len(lines)} lines")
        vm.reboot()
    finally:
        switch.close()
    # Lines of the VMM thread and of the API thread. Not the API thread's
    # "API server started": upstream starts that thread before it applies
    # the configuration file, which sets the logger up, so the line goes to
    # the file or, when the thread is first, to Firecracker's output (seen
    # once the sandbox's profile was compiled ahead: the thread got there
    # 30 ms before the logger was set up).
    with open(log) as f:
        text = f.read()
    check("Successfully started microvm that was configured from one single json" in text
          and "The API server received a Put request on \"/mmds\"" in text, "the logger writes to its file")
    return "virtio-rng, rate-limited block, MMDS V2 over the net endpoint, balloon inflate + statistics, logger and metrics files"


def phys_footprint(pid):
    """`pid`'s phys_footprint in bytes (proc_pid_rusage RUSAGE_INFO_V4): what
    the jailer's memory limit is checked against."""
    libc = ctypes.CDLL(None, use_errno=True)
    # rusage_info_v4: ri_uuid[16], then 64-bit counters; ri_phys_footprint is
    # the eighth (sys/resource.h).
    buf = (ctypes.c_uint8 * 512)()
    r = libc.proc_pid_rusage(pid, 4, buf)
    check(r == 0, f"proc_pid_rusage for {pid}: errno {ctypes.get_errno()}")
    return struct.unpack_from("<Q", buf, 16 + 7 * 8)[0]


def stage_balloon(ctx):
    """A balloon cycle on a guest restored from a memory file, then on a
    booted one: the guest and the host keep using the same pages, and the
    pages the balloon took leave the VMM's footprint and come back when the
    guest writes them again.

    Hypervisor.framework maps the physical pages behind a host range, not the
    host address, so a discard that replaced the pages (upstream's
    `discard_range` maps anonymous memory `MAP_FIXED` over file-backed guest
    memory; the libc's `MADV_DONTNEED` does the same for anonymous memory)
    left the guest on the old pages while the drive's reads went to the new
    ones: O_DIRECT reads of /dev/vda, whose buffers come from the pages the
    balloon gave back, read stale data (measured: 2 wrong checksums in 6
    reads). The backend now unmaps the range for the duration of the change
    (`libc::wick_guest`). The booted guest's cycle also measured, before the
    fix, a footprint that stayed at the guest's size: `MADV_FREE_REUSABLE`
    released nothing of pages mapped in stage 2."""
    disk = md5(ctx.rootfs, 64 << 20)
    balloon = {"amount_mib": 0, "deflate_on_oom": True, "stats_polling_interval_s": 1}
    cfg = config(ctx, vcpus=2, mem=512, balloon=balloon)

    def direct_reads(vm, n=6):
        """The O_DIRECT reads of the drive's first 64 MiB that read it wrong."""
        bad = []
        for i in range(n):
            _, out = vm.sh("dd if=/dev/vda bs=1M count=64 iflag=direct 2>/dev/null | md5sum")
            if out.split()[0] != disk:
                bad.append(i)
        return bad

    def actual(vm, mib, timeout=60):
        deadline = time.time() + timeout
        while True:
            stats = vm.api("GET", "/balloon/statistics")
            if stats.get("actual_mib") == mib:
                return
            check(time.time() < deadline, f"balloon at {stats.get('actual_mib')} MiB, wanted {mib}: {stats}")
            time.sleep(0.5)

    def cycle(vm, mib):
        vm.api("PATCH", "/balloon", {"amount_mib": mib})
        actual(vm, mib)
        vm.api("PATCH", "/balloon", {"amount_mib": 0})
        actual(vm, 0)

    # Pages the guest wrote and freed: what the balloon hands over is then
    # resident on the host, and so is what O_DIRECT reads land in.
    dirty = "mount -t tmpfs -o size=300m tmpfs /tmp 2>/dev/null; head -c 200m /dev/urandom > /tmp/f && rm /tmp/f"

    # A guest restored from a memory file: its memory is the file, mapped
    # private, and a discard replaces the range with anonymous memory.
    vm = ctx.vm("balloon1", [], cfg)
    vm.shell()
    check(not direct_reads(vm, 2), "O_DIRECT reads of /dev/vda before any balloon")
    vm.sh(dirty, 120)
    state = os.path.join(ctx.out, "balloon.state")
    mem = os.path.join(ctx.out, "balloon.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
    vm.kill()
    vm = ctx.vm("balloon2", [])
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": mem},
                                     "resume_vm": True})
    vm.shell()
    cycle(vm, 150)
    bad = direct_reads(vm)
    check(not bad, f"after a restore from file and a 150 MiB balloon cycle, O_DIRECT reads {bad} of /dev/vda read it wrong")
    vm.reboot()
    os.unlink(mem)

    # A booted guest: anonymous memory, and the footprint the jailer's limit
    # is checked against goes down by what the balloon took and up again
    # when the guest writes the pages again.
    vm = ctx.vm("balloon3", [], cfg)
    vm.shell()
    vm.sh(dirty, 120)
    before = phys_footprint(vm.proc.pid)
    vm.api("PATCH", "/balloon", {"amount_mib": 150})
    actual(vm, 150)
    inflated = phys_footprint(vm.proc.pid)
    check(before - inflated >= 100 << 20,
          f"footprint {before >> 20} MiB before a 150 MiB balloon, {inflated >> 20} MiB after")
    vm.api("PATCH", "/balloon", {"amount_mib": 0})
    actual(vm, 0)
    bad = direct_reads(vm)
    check(not bad, f"after a 150 MiB balloon cycle, O_DIRECT reads {bad} of /dev/vda read it wrong")
    vm.sh(dirty, 120)
    again = phys_footprint(vm.proc.pid)
    check(again - inflated >= 100 << 20,
          f"footprint {inflated >> 20} MiB while inflated, {again >> 20} MiB after the guest wrote 200 MiB again")
    vm.reboot()
    return (f"150 MiB balloon cycles: after a restore from file, O_DIRECT reads of /dev/vda match 6 of 6;"
            f" on a booted guest, footprint {before >> 20} -> {inflated >> 20} -> {again >> 20} MiB and reads match 6 of 6")


def children(pid):
    out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout
    return [int(p) for p in out.split()]


def sandbox_denies(pid, operation):
    """Whether the sandbox of `pid` denies `operation` (any path, any peer).

    sandbox_check carries out the rule's action: an operation that raises
    SIGSYS there (the default rule) ends the process checked. Only file
    operations, denied with an error, are checked this way."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.sandbox_check.restype = ctypes.c_int
    return lib.sandbox_check(pid, operation.encode(), 0) == 1


def sandboxed(pid):
    """Whether `pid` runs in a sandbox at all (sandbox_check, no operation)."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    lib.sandbox_check.restype = ctypes.c_int
    return lib.sandbox_check(pid, None, 0) == 1


def stage_no_seccomp(ctx):
    """Without --no-seccomp, Firecracker and its API process run in the
    Seatbelt profile (upstream's seccomp filters: vmm::ext::sandbox); with
    it, neither does, and the guest runs either way. The check is one the
    profile denies with an error, not SIGSYS (issuing a sandbox extension),
    so asking does not end the process."""
    results = []
    for flag in ([], ["--no-seccomp"]):
        vm = ctx.vm("no-seccomp" if flag else "seccomp", flag, config(ctx))
        vm.shell()
        _, out = vm.sh("echo guest-$((6*7))")
        check(out == "guest-42", f"guest {flag}: {out!r}")
        procs = [vm.proc.pid] + children(vm.proc.pid)
        state = [(sandboxed(p), sandbox_denies(p, "generic-issue-extension")) for p in procs]
        want = (not flag, not flag)
        check(all(st == want for st in state), f"{' '.join(flag) or 'default'}: (sandboxed, denies) of {procs}: {state}")
        vm.reboot()
        results.append(f"{len(procs)} processes {'not ' if flag else ''}sandboxed")
    return f"default: {results[0]}; --no-seccomp: {results[1]}; the guest runs in both"


def resident(pid):
    """`pid`'s resident size in bytes (proc_pidinfo PROC_PIDTASKINFO,
    pti_resident_size): what psutil's RSS reads on macOS."""
    libc = ctypes.CDLL(None, use_errno=True)
    buf = (ctypes.c_uint8 * 96)()  # struct proc_taskinfo
    n = libc.proc_pidinfo(pid, 4, ctypes.c_uint64(0), buf, 96)
    check(n == 96, f"proc_pidinfo PROC_PIDTASKINFO for {pid}: {n}, errno {ctypes.get_errno()}")
    return struct.unpack_from("<Q", buf, 8)[0]


# Guest hwcaps (Linux arch/arm64/kernel/cpufeature.c) of the ID register
# fields V1N1 (vmm/src/cpu_config/aarch64/static_cpu_templates/v1n1.rs)
# lowers: what a host has of them the guest loses under the template, and
# nothing else. Upstream's test_guest_cpu_features expects G2_FEATS under
# V1N1, which is a Neoverse V1 less these.
V1N1_HWCAPS = set(
    "sve svebf16 svei8mm dit sha3 sha512 sm3 sm4 asimdfhm flagm flagm2 rng "
    "dcpodp jscvt fcma ilrcpc i8mm bf16 ebf16 dgh uscat".split()
)


def guest_features(vm):
    """The guest's /proc/cpuinfo Features of every CPU, as one set, after
    checking all CPUs list the same and the kernel saw no variation between
    them (cpufeature.c's SANITY CHECK)."""
    _, out = vm.sh("grep Features /proc/cpuinfo")
    sets = [frozenset(line.split(":", 1)[1].split()) for line in out.splitlines()]
    check(len(sets) == 2 and sets[0] == sets[1], f"CPUs differ: {out!r}")
    _, out = vm.sh("dmesg | grep -iE 'sanity check|unexpected variation|will not boot' | head -3; true")
    check(not out, f"guest kernel: {out!r}")
    return set(sets[0])


def stage_cpu_templates(ctx):
    """CPU templates on the ID registers: the static V1N1 template and the
    same as a custom template through PUT /cpu-config take the features V1N1
    lowers from the guest, on every vCPU, and a restored snapshot keeps
    them; a template that raises a feature is refused."""
    cfg = config(ctx, vcpus=2)
    vm = ctx.vm("tmpl-none", [], cfg)
    vm.shell()
    host = guest_features(vm)
    vm.kill()
    check({"aes", "sha3", "asimdfhm"} <= host, f"this host's guest lacks aes, sha3 or asimdfhm: {sorted(host)}")
    want = host - V1N1_HWCAPS

    vm = ctx.vm("tmpl-static", [], config(ctx, vcpus=2, machine={"cpu_template": "V1N1"}))
    vm.shell()
    got = guest_features(vm)
    check(got == want, f"V1N1: lost {sorted(host - got)}, kept {sorted(got & V1N1_HWCAPS)}")
    # The template survives a snapshot (the ID registers are in it).
    state, mem = os.path.join(ctx.out, "tmpl.state"), os.path.join(ctx.out, "tmpl.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
    vm.kill()
    vm = ctx.vm("tmpl-restored", [])
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": mem},
                                     "resume_vm": True})
    # cpu1 offline and online again (PSCI CPU_ON resets it): Linux compares
    # each CPU that comes up with the boot CPU's ID registers and warns of a
    # difference (arch/arm64/kernel/smp.c secondary_start_kernel ->
    # cpuinfo.c cpuinfo_store_cpu -> cpufeature.c update_cpu_features,
    # "SANITY CHECK"), so none means cpu1 has the VM's values at boot, after
    # the restore and after its reset.
    cpu_offline_online(vm, "V1N1 restored")
    got = guest_features(vm)
    check(got == want, f"V1N1 restored: lost {sorted(host - got)}, kept {sorted(got & V1N1_HWCAPS)}")
    _, out = vm.sh("dmesg | grep -c 'SANITY CHECK'; true")
    check(out.splitlines()[-1] == "0", f"V1N1 restored: a CPU's ID registers differ from the boot CPU's: {out!r}")
    vm.kill()
    os.unlink(mem)

    custom = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lib", "firecracker",
                          "tests", "data", "custom_cpu_templates", "V1N1.json")
    with open(custom) as f:
        template = json.load(f)
    vm = ctx.vm("tmpl-custom", [])
    vm.api("PUT", "/boot-source", cfg["boot-source"])
    vm.api("PUT", "/drives/rootfs", cfg["drives"][0])
    vm.api("PUT", "/machine-config", cfg["machine-config"])
    vm.api("PUT", "/cpu-config", template)
    vm.api("PUT", "/actions", {"action_type": "InstanceStart"})
    vm.shell()
    got = guest_features(vm)
    check(got == want, f"custom V1N1: lost {sorted(host - got)}, kept {sorted(got & V1N1_HWCAPS)}")
    vm.kill()

    # Pointer authentication through a template's vcpu_features (PTRAUTH_ADDRESS
    # and _GENERIC, bits 5 and 6), the only way KVM shows it: the guest has
    # paca and pacg, which it lacks without; a snapshot of it restores, and
    # cpu1 comes back online after the restore with the boot CPU's ID registers.
    pac = {"kvm_capabilities": ["171", "172"], "vcpu_features": [{"index": 0, "bitmap": "0b11xxxxx"}]}
    check(not {"paca", "pacg"} & host, f"pointer authentication shown without vcpu_features: {sorted(host)}")
    vm = ctx.vm("tmpl-pac", [], config(ctx, vcpus=2, cpu_config=pac))
    vm.shell()
    got = guest_features(vm)
    check(got == host | {"paca", "pacg"}, f"PAC template: gained {sorted(got - host)}, lost {sorted(host - got)}")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
    vm.kill()
    vm = ctx.vm("tmpl-pac-restored", [])
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": mem},
                                     "resume_vm": True})
    cpu_offline_online(vm, "PAC restored")
    got = guest_features(vm)
    check(got == host | {"paca", "pacg"}, f"PAC restored: gained {sorted(got - host)}, lost {sorted(host - got)}")
    _, out = vm.sh("dmesg | grep -c 'SANITY CHECK'; true")
    check(out.splitlines()[-1] == "0", f"PAC restored: a CPU's ID registers differ from the boot CPU's: {out!r}")
    vm.kill()
    os.unlink(mem)

    # AES raised to 0b1111: no host has that; KVM refuses it (EINVAL).
    raise_aes = {"reg_modifiers": [{"addr": "0x603000000013c030", "bitmap": "0b" + "x" * 56 + "1111" + "x" * 4}]}
    vm = ctx.vm("tmpl-raise", [], config(ctx, vcpus=2, cpu_config=raise_aes), api=False)
    code = vm.wait_exit(30)
    check(code != 0 and "Invalid argument (os error 22)" in vm.buf, f"raised AES: exit {code}, {vm.exit_reason()}")
    return (f"V1N1 static, custom through PUT /cpu-config and restored: the guest loses "
            f"{len(host - want)} features ({' '.join(sorted(host - want))}), the same on both vCPUs, also after "
            f"cpu1's restart; pointer authentication only through vcpu_features, restored with cpu1's restart; "
            f"a raised feature refused")


def stage_memory_hotplug(ctx):
    """virtio-mem, as upstream's test_virtio_mem_hotplug_hotunplug
    (performance/test_hotplug_memory.py) checks it: the guest's driver gets
    the requested size (dmesg) and carries it out (MemTotal = base +
    plugged), the memory is usable, and an unplug back to 0 gives MemTotal
    back and leaves Firecracker with less resident. 512 MiB plugged into a
    512 MiB guest (a 1 GiB area, 128 MiB slots, 2 MiB blocks)."""
    cfg = config(ctx, vcpus=2, mem=512,
                 memory_hotplug={"total_size_mib": 1024, "slot_size_mib": 128, "block_size_mib": 2})
    cfg["boot-source"]["boot_args"] = BOOT_ARGS + " memhp_default_state=online_movable"
    vm = ctx.vm("memory-hotplug", [], cfg)
    vm.shell()
    _, out = vm.sh("dmesg | grep virtio_mem | head -3; true")
    check("virtio_mem" in out, f"the guest found no virtio-mem device: {out!r}")

    def mem_total():
        return int(vm.sh("awk '/MemTotal/ {print $2}' /proc/meminfo")[1]) // 1024

    base = mem_total()

    def plug(mib):
        vm.api("PATCH", "/hotplug/memory", {"requested_size_mib": mib})
        deadline = time.time() + 60
        while True:
            hp = vm.api("GET", "/hotplug/memory")
            if hp.get("plugged_size_mib") == mib:
                break
            check(time.time() < deadline, f"plugged_size_mib {hp} 60 s after asking for {mib} MiB")
            time.sleep(0.1)
        _, req = vm.sh("dmesg | grep virtio_mem | grep 'requested size' | tail -1")
        check(req and int(req.split(":")[-1].strip(), 0) == mib << 20, f"virtio_mem's requested size {req!r} for {mib} MiB")
        deadline = time.time() + 5
        while True:
            now = mem_total()
            if now == base + mib:
                return
            check(time.time() < deadline, f"MemTotal {now} MiB, {base} + {mib} expected")
            time.sleep(0.5)

    plug(512)
    # Memory past what the guest booted with, written and read back.
    # (The root file system is read-only: the tmpfs goes on /tmp.)
    _, out = vm.sh("mount -t tmpfs -o size=900m tmpfs /tmp && head -c 600m /dev/urandom > /tmp/f && "
                   "md5sum /tmp/f > /tmp/a && md5sum /tmp/f | cmp - /tmp/a && echo same", timeout=180)
    check(out == "same", f"600 MiB in a guest of {base} + 512 MiB read back differently: {out!r}")
    vm.sh("rm /tmp/f /tmp/a && umount /tmp")
    rss_plugged = resident(vm.proc.pid)
    plug(0)
    rss_unplugged = resident(vm.proc.pid)
    check(rss_unplugged < rss_plugged, f"resident {rss_plugged >> 20} -> {rss_unplugged >> 20} MiB after the unplug")
    plug(512)  # again, as upstream's test does
    vm.reboot()
    return (f"virtio-mem: MemTotal {base} -> {base + 512} MiB and back and again, 600 MiB written and read back "
            f"while plugged, resident {rss_plugged >> 20} -> {rss_unplugged >> 20} MiB at the unplug")


def stage_api_process(ctx):
    # On Linux the API thread has a filter of its own, narrower than the VMM
    # thread's. The macOS sandbox is per process, so the API server's HTTP
    # side is a process of its own (vmm::ext::api_process), sandboxed as that
    # filter: no files (sandbox_check; what raises SIGSYS there:
    # test_api_profile_* in ext::sandbox). Its end ends Firecracker as the API
    # thread's does on Linux (a panic, panic = "abort"), and Firecracker's end
    # ends it.
    vm = ctx.vm("api-process", [], config(ctx))
    vm.shell()
    kids = children(vm.proc.pid)
    check(len(kids) == 1, f"Firecracker's child processes: {kids}")
    api = kids[0]
    for op in ("file-read-data", "file-write-data"):
        check(sandbox_denies(api, op), f"the API process is allowed {op}")
        check(not sandbox_denies(vm.proc.pid, op), f"control: Firecracker is denied {op}")
    info = vm.api("GET", "/")
    check(info.get("state") == "Running", f"instance info through the API process: {info}")
    vm.api("PUT", "/nothing-here", {}, expect=(400,))
    os.kill(api, signal.SIGKILL)
    code = vm.wait_exit(15)
    check(code == -signal.SIGABRT, f"Firecracker after the API process was killed: exit {code}")
    check("The API server process ended" in vm.buf, "no panic message for the API process's end")

    vm = ctx.vm("api-process-2", [], config(ctx))
    vm.shell()
    kids = children(vm.proc.pid)
    check(len(kids) == 1, f"Firecracker's child processes: {kids}")
    vm.proc.kill()
    vm.wait_exit(15)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(kids[0], 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        raise Failure("the API process outlived Firecracker by 10s")
    return "API process sandboxed (no files), serves the API; each one's end ends the other"


def stage_restores(ctx, rounds=20):
    """One snapshot restored many times, each restore paused and snapshotted again.

    Catches races between vCPU threads at restore (Hypervisor.framework
    deadlocked when one vCPU was created while another made an interrupt
    pending, about one restore in fifteen) and at the pause before a snapshot
    (a vCPU kicked between two runs paused without its GIC state readable)."""
    uds = os.path.join(ctx.sock, "rs.v")
    cfg = config(ctx, vcpus=2, vsock={"guest_cid": 3, "uds_path": uds})
    vm = ctx.vm("rs0", [], cfg)
    vm.shell()
    guest_vsock_services(vm, uds)
    vm.sh("A=before-$((6*7))")
    state, mem = os.path.join(ctx.out, "rs.state"), os.path.join(ctx.out, "rs.mem")
    again_state, again_mem = os.path.join(ctx.out, "rs2.state"), os.path.join(ctx.out, "rs2.mem")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
    vm.kill()
    for i in range(rounds):
        if os.path.exists(uds):
            os.unlink(uds)
        vm = ctx.vm(f"rs{i + 1}", [])
        vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                         "mem_backend": {"backend_type": "File", "backend_path": mem},
                                         "resume_vm": True})
        try:
            _, out = vm.sh("echo restored $A", timeout=20)
        except Failure as e:
            raise Failure(f"restore {i + 1} of {rounds}: {e}") from None
        check(out == "restored before-42", f"restore {i + 1}: {out!r}")
        vm.api("PATCH", "/vm", {"state": "Paused"})
        vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": again_state,
                                           "mem_file_path": again_mem})
        vm.kill()
    for f in (mem, again_mem):
        os.unlink(f)
    return f"{rounds} restores of one snapshot, each paused and snapshotted again"


# ---------------------------------------------------------------- the command line and the tools


def fc_run(ctx, args, timeout=30):
    """Runs Firecracker to its end; returns (exit status, its output)."""
    r = subprocess.run([ctx.firecracker] + args, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


LOG_LINE = re.compile(r"^\S+ \[[^:\]]*:([^:\]]*)(?::[A-Z][a-z]+)?:([^:\]]+):(\d+)\] ", re.M)


def log_origins(text):
    """The source files of the lines of a log written with --show-log-origin."""
    return [m.group(2) for m in LOG_LINE.finditer(text)]


def read_metrics(path_or_text):
    text = path_or_text
    if os.path.exists(path_or_text):
        with open(path_or_text) as f:
            text = f.read()
    return [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]


class FifoReader:
    """Reads a FIFO into memory from when it is made, as upstream's
    docs/logger.md has an operator do (the reader may come after the writer)."""

    def __init__(self, path):
        os.mkfifo(path)
        self.path = path
        self.data = b""
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        import select
        fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            while not self.stop.is_set():
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    b = os.read(fd, 65536)
                    if b:
                        self.data += b
                    else:
                        time.sleep(0.05)  # no writer yet, or between writers
        finally:
            os.close(fd)

    def text(self, wait_for=None, timeout=10):
        deadline = time.time() + timeout
        while wait_for is not None and wait_for not in self.data.decode("utf-8", "replace"):
            if time.time() > deadline:
                break
            time.sleep(0.05)
        return self.data.decode("utf-8", "replace")

    def close(self):
        self.stop.set()
        self.thread.join(5)


def stage_cli(ctx):
    """Firecracker's own command line: exit codes, --module, the start time
    flags, the logger and metrics on FIFOs, --boot-timer."""
    done = []
    # Exit codes: upstream maps an argument parsing error to 153 (ArgParsing)
    # and an invalid --level to 152 (BadConfiguration); a configuration file
    # that does not parse is a generic error, 1 (main.rs, FcExitCode).
    good = os.path.join(ctx.out, "cli-good.json")
    with open(good, "w") as f:
        json.dump(config(ctx), f)
    bad = os.path.join(ctx.out, "cli-bad.json")
    with open(bad, "w") as f:
        f.write('{"boot-source": {"kernel_image_path": ')
    for args, want, text in ((["--no-such-flag"], 153, "ParseArguments"),
                             (["--api-sock"], 153, "ParseArguments"),
                             (["--no-api", "--config-file", good, "--level", "Bogus"], 152, "InvalidLogLevel"),
                             (["--no-api", "--config-file", bad], 1, "ParseFromJson")):
        code, out = fc_run(ctx, args)
        check(code == want and text in out, f"firecracker {' '.join(args)}: exit {code}, wanted {want}; {out.strip()[-300:]}")
    done.append("exit 153 for bad arguments, 152 for a bad --level, 1 for a bad configuration file")

    # --module: only log lines from modules under the filter are written.
    # file!() of a line names its crate's directory.
    crates = {"vmm": "src/vmm/", "firecracker": "src/firecracker/"}
    seen = {}
    for module in ("vmm", "firecracker", None):
        name = f"cli-module-{module or 'all'}"
        log = os.path.join(ctx.out, f"{name}.fc.log")
        metrics = os.path.join(ctx.out, f"{name}.metrics")
        args = ["--log-path", log, "--level", "Debug", "--show-log-origin", "--metrics-path", metrics]
        if module:
            args += ["--module", module]
        vm = ctx.vm(name, args, config(ctx))
        vm.shell()
        vm.api("GET", "/machine-config")
        vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
        vm.reboot()
        with open(log) as f:
            origins = log_origins(f.read())
        check(origins, f"--module {module}: no log lines with an origin in {log}")
        if module:
            stray = sorted({o for o in origins if not o.startswith(crates[module])})
            check(not stray, f"--module {module}: lines from {stray[:5]}")
        else:
            for crate, prefix in crates.items():
                check(any(o.startswith(prefix) for o in origins), f"no filter: no line from {crate}")
            # Without the start time flags the metrics stay 0.
            api = read_metrics(metrics)[-1]["api_server"]
            check(api["process_startup_time_us"] == 0 and api["process_startup_time_cpu_us"] == 0,
                  f"start time metrics without the flags: {api}")
        seen[module or "all"] = len(origins)
    done.append(f"--module keeps its crate's lines ({seen})")

    # --start-time-us is CLOCK_MONOTONIC in us (what the jailer passes),
    # --start-time-cpu-us the CPU time the process had at the exec,
    # --parent-cpu-time-us the jailer's: once the API server is up the
    # metrics hold the time since the start and the CPU time since then plus
    # the parent's (ProcessTimeReporter). The metrics go to a FIFO given on
    # the command line, the log to a FIFO given through the API.
    mfifo = FifoReader(os.path.join(ctx.sock, "m.fifo"))
    lfifo = FifoReader(os.path.join(ctx.sock, "l.fifo"))
    try:
        parent = 1000
        t0 = time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000
        vm = ctx.vm("cli-time", ["--start-time-us", str(t0), "--start-time-cpu-us", "0",
                                 "--parent-cpu-time-us", str(parent), "--metrics-path", mfifo.path])
        vm.api("PUT", "/logger", {"log_path": lfifo.path, "level": "Info"})
        vm.api("GET", "/machine-config")
        # Metrics are flushed on demand once the microVM runs.
        cfg = config(ctx)
        vm.api("PUT", "/boot-source", cfg["boot-source"])
        vm.api("PUT", "/drives/rootfs", cfg["drives"][0])
        vm.api("PUT", "/machine-config", cfg["machine-config"])
        vm.api("PUT", "/actions", {"action_type": "InstanceStart"})
        vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
        wall = time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000 - t0
        metrics = read_metrics(mfifo.text(wait_for="utc_timestamp_ms"))
        log = lfifo.text(wait_for='Get request on "/machine-config"')
        # The readers go away mid-run: Firecracker holds both FIFOs open
        # read-write and non-blocking (utils::open_file_nonblock, as on
        # Linux), so a write past a full pipe fails with EAGAIN rather than
        # raising SIGPIPE or blocking, and the microVM and the API go on.
        mfifo.close()
        lfifo.close()
        for _ in range(500):
            vm.api("GET", "/machine-config")
        vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
        vm.shell()
        _, out = vm.sh("echo after-$((6*7))")
        check(out == "after-42", f"guest after the FIFO readers went: {out!r}")
        vm.reboot()
    finally:
        mfifo.close()
        lfifo.close()
    check(metrics and "utc_timestamp_ms" in metrics[-1], f"no metrics through the FIFO: {mfifo.data[:200]!r}")
    check('The API server received a Get request on "/machine-config"' in log, f"no log lines through the FIFO: {log[:300]!r}")
    api = metrics[-1]["api_server"]
    start, cpu = api["process_startup_time_us"], api["process_startup_time_cpu_us"]
    check(0 < start <= wall, f"process_startup_time_us {start}, {wall} us since --start-time-us")
    check(parent < cpu < parent + wall * os.cpu_count(), f"process_startup_time_cpu_us {cpu} (parent {parent}, wall {wall})")
    done.append(f"start time metrics {start} us, {cpu} CPU us (of {wall} us); logger and metrics on FIFOs, "
                "and the microVM goes on once their readers went")

    # A log FIFO nobody ever reads: Firecracker opens it without a reader
    # (O_RDWR), and once the pipe is full each line is lost and counted in
    # logger.missed_log_count (logging.rs), as on Linux.
    unread = os.path.join(ctx.sock, "unread.fifo")
    os.mkfifo(unread)
    metrics = os.path.join(ctx.out, "cli-unread.metrics")
    vm = ctx.vm("cli-unread", ["--log-path", unread, "--level", "Debug", "--metrics-path", metrics], config(ctx))
    vm.shell()
    for _ in range(2000):
        vm.api("GET", "/machine-config")
    vm.api("PUT", "/actions", {"action_type": "FlushMetrics"})
    missed = read_metrics(metrics)[-1]["logger"]["missed_log_count"]
    check(missed > 0, f"logger.missed_log_count {missed} after 2000 requests logged to a FIFO nobody reads")
    _, out = vm.sh("echo unread-$((6*7))")
    check(out == "unread-42", f"guest with an unread log FIFO: {out!r}")
    vm.reboot()
    done.append(f"a log FIFO nobody reads: {missed} lines missed and counted, the microVM goes on")

    # --boot-timer: the guest's /usr/local/bin/init (upstream's rootfs
    # overlay) writes 123 to the boot timer device at the start of the MMIO
    # space (0x40000000 on aarch64) through /dev/mem, then runs /sbin/init;
    # upstream's test_boottime boots it so. Without the flag there is no device.
    timer = re.compile(r"Guest-boot-time =\s+(\d+) us\s+(\d+) ms,\s+(\d+) CPU us\s+(\d+) CPU ms")
    boot = config(ctx)
    boot["boot-source"]["boot_args"] = BOOT_ARGS.replace("init=/bin/sh", "init=/usr/local/bin/init")
    t0 = time.time()
    vm = ctx.vm("cli-boot-timer", ["--boot-timer", "--level", "Info"], boot)
    m = vm.wait_for(timer.pattern, 60)
    wall = (time.time() - t0) * 1e6
    us, cpu_us = int(m.group(1)), int(m.group(3))
    # Both are differences of two clock reads (boot_timer.rs, unsigned): a
    # read that fails leaves 0, and the difference wraps to near 2^64
    # (measured before the run phase allowed getrusage, the process CPU
    # clock's call here: 18446744073709538027 CPU us). The process's CPU time
    # since the build is at most its wall time on every host CPU.
    check(0 < us < wall and 0 < cpu_us < wall * os.cpu_count()
          and int(m.group(2)) == us // 1000 and int(m.group(4)) == cpu_us // 1000,
          f"Guest-boot-time {m.group(0)!r}; {wall:.0f} us since the start, {os.cpu_count()} host CPUs")
    # The guest goes on to /sbin/init (a denied call stopped the microVM here).
    vm.wait_for(r"systemd\[1\]|Welcome to", 60, m.end())
    check(vm.proc.poll() is None, f"Firecracker after the boot timer write: {vm.exit_reason()}")
    vm.kill()
    vm = ctx.vm("cli-no-boot-timer", ["--level", "Info"], boot)
    vm.wait_for(r"Run /usr/local/bin/init as init process", 60)
    vm.wait_for(r"systemd\[1\]|Welcome to", 60)  # past the init's write
    check(not timer.search(vm.buf), "Guest-boot-time without --boot-timer")
    vm.kill()
    done.append(f"--boot-timer: Guest-boot-time {us} us ({cpu_us} CPU us), none without it")
    return "; ".join(done)


def stage_tools(ctx):
    """rebase-snap and snapshot-editor's info-vmstate commands on snapshots of
    a 2 vCPU guest."""
    cfg = config(ctx, vcpus=2, machine={"track_dirty_pages": True})
    vm = ctx.vm("tools1", [], cfg)
    vm.shell()
    vm.sh("A=before-$((6*7))")
    _, bash_md5 = vm.sh("md5sum /usr/bin/bash")
    base = os.path.join(ctx.out, "tools-base.mem")
    diff = os.path.join(ctx.out, "tools-diff.mem")
    full_state = os.path.join(ctx.out, "tools-full.state")
    state = os.path.join(ctx.out, "tools-diff.state")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": full_state, "mem_file_path": base})
    vm.api("PATCH", "/vm", {"state": "Resumed"})
    vm.sh("B=second-$((7*7)); cat /usr/bin/* > /dev/null 2>&1; true")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Diff", "snapshot_path": state, "mem_file_path": diff})
    vm.kill()
    # The diff's memory file has holes where no page was dirtied (what
    # rebase-snap copies around, by SEEK_DATA and SEEK_HOLE).
    st = os.stat(diff)
    with open(diff, "rb") as f:
        hole = os.lseek(f.fileno(), 0, os.SEEK_HOLE)
    check(st.st_size == 256 << 20 and st.st_blocks * 512 < st.st_size and hole < st.st_size,
          f"diff memory file: {st.st_size} bytes, {st.st_blocks * 512} allocated, first hole at {hole}")

    # snapshot-editor info-vmstate: the version, the vCPU states and the
    # whole state (info.rs).
    def editor(*args):
        return subprocess.run([ctx.snapshot_editor, "info-vmstate", *args], capture_output=True, text=True)

    r = editor("version", "--vmstate-path", state)
    check(r.returncode == 0 and r.stdout.strip() == "v12.0.0", f"info-vmstate version: {r.returncode} {r.stdout!r} {r.stderr!r}")
    r = editor("vcpu-states", "--vmstate-path", state)
    check(r.returncode == 0, f"info-vmstate vcpu-states: {r.returncode} {r.stderr!r}")
    vcpus = re.split(r"^vcpu (\d+):$", r.stdout, flags=re.M)[1:]
    check([vcpus[i] for i in range(0, len(vcpus), 2)] == ["0", "1"], f"vcpu-states lists {vcpus[0::2]}")
    for i in (0, 1):
        body = vcpus[2 * i + 1]
        check("kvm_mp_state: 0x0" in body and f"mpidr: {0x80000000 + i:#x}" in body,
              f"vcpu {i}: {body.strip()[:200]!r}")
        # KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | regs.pc: a kernel address.
        pc = re.search(r"^0x6030000000100040 0x([0-9a-f]+)$", body, re.M)
        check(pc and pc.group(1).startswith("ffff"), f"vcpu {i}: PC {pc and pc.group(1)}")
    r = editor("vm-state", "--vmstate-path", state)
    check(r.returncode == 0 and "mem_size_mib: 256" in r.stdout and r.stdout.count("kvm_mp_state:") == 2
          and "device_states:" in r.stdout, f"info-vmstate vm-state: {r.returncode} {r.stdout[:300]!r} {r.stderr!r}")
    r = editor("version", "--vmstate-path", ctx.kernel)
    check(r.returncode != 0, f"info-vmstate version of a kernel image: {r.returncode} {r.stdout!r}")

    # A state file with another architecture's magic, then with a newer
    # version, is refused at the load with upstream's error (snapshot/mod.rs,
    # checked before the CRC), by snapshot-editor and by Firecracker, which
    # then ends as after any failed load. bitcode writes the header first: a
    # byte, the magic (8 bytes, little-endian), the version's length and text.
    with open(full_state, "rb") as f:
        raw = bytearray(f.read())
    check(raw[1:9] == struct.pack("<Q", 0x0710_1984_AAAA_0000) and raw[10:16] == b"12.0.0",
          f"state file header {raw[:16].hex()}")
    x86 = raw[:1] + struct.pack("<Q", 0x0710_1984_8664_0000) + raw[9:]
    newer = raw[:10] + b"99" + raw[12:]
    patched = os.path.join(ctx.out, "tools-patched.state")
    for what, data, error in (("x86_64 magic", x86, "Magic value does not match arch"),
                              ("version 99.0.0", newer, "Invalid data version")):
        with open(patched, "wb") as f:
            f.write(data)
        r = editor("version", "--vmstate-path", patched)
        check(r.returncode != 0 and error in r.stdout + r.stderr,
              f"info-vmstate of a state file with {what}: {r.returncode} {(r.stdout + r.stderr).strip()!r}")
        vm = ctx.vm(f"tools-{what.split()[0]}", [])
        reply = vm.api("PUT", "/snapshot/load", {"snapshot_path": patched,
                                                 "mem_backend": {"backend_type": "File", "backend_path": base}},
                       expect=(400,))
        check(error in reply.get("fault_message", ""), f"load of a state file with {what}: {reply}")
        code = vm.wait_exit(10)
        check(code != 0, f"Firecracker after a failed load ({what}): exit {code}")
    os.unlink(patched)

    # rebase-snap (deprecated for snapshot-editor edit-memory rebase): the
    # diff's data regions written over the base; both tools give the same file.
    other = os.path.join(ctx.out, "tools-base2.mem")
    shutil.copyfile(base, other)
    r = subprocess.run([ctx.rebase_snap, "--base-file", base, "--diff-file", diff], capture_output=True, text=True)
    check(r.returncode == 0, f"rebase-snap: {r.returncode} {r.stderr.strip()}")
    r = subprocess.run([ctx.snapshot_editor, "edit-memory", "rebase", "--memory-path", other, "--diff-path", diff],
                       capture_output=True, text=True)
    check(r.returncode == 0, f"snapshot-editor rebase: {r.returncode} {r.stderr.strip()}")
    check(md5(base) == md5(other), "rebase-snap and snapshot-editor rebase give different memory files")
    os.unlink(other)
    vm = ctx.vm("tools2", [])
    vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                     "mem_backend": {"backend_type": "File", "backend_path": base},
                                     "resume_vm": True})
    restored_checks(vm, bash_md5, None)
    _, out = vm.sh("echo $A $B")
    check(out == "before-42 second-49", f"after a rebase-snap restore: {out!r}")
    vm.reboot()
    return ("diff memory file has holes; info-vmstate version v12.0.0, vcpu-states (2 vCPUs, mpidr, PC), vm-state; "
            "a non-snapshot refused; another arch's magic or a newer version refused by snapshot-editor and the "
            "load; rebase-snap equals snapshot-editor rebase and restores")


# PV steal time (Arm DEN0057A), offered where Hypervisor.framework gives a
# vCPU's WFI time apart (hv_vcpu_get_wait_for_interrupt_time, macOS 27), as
# KVM offers it where it can account steal (pvtime.c
# kvm_arm_pvtime_supported). The guest's steal (/proc/stat, USER_HZ ticks)
# on its 2 vCPUs, each case PVTIME_CASE_S long: idle, then spinning, on the
# host as it is; spinning, then idle, while the host runs 2 spinning
# processes per CPU. Beside each: what the host's own scheduler took from a
# spinning process of its own over the same time (the control: what a
# vCPU thread loses to the host's other work, KVM's run delay), and the PV
# time kicker's exits and CPU time (its debug line, every 10 s). Then, the
# guest spinning under the host's spinners: a pause and resume loop, and a
# restore in a new process (upstream's performance test_pvtime_snapshot).
PVTIME_CASE_S = 12


def _off_cpu_ms(seconds):
    """A spinning process's wall time less its CPU time, in ms: what the
    host's scheduler kept from it (the control)."""
    code = ("import time\n"
            "w, c = time.monotonic(), time.thread_time()\n"
            f"while time.monotonic() - w < {seconds}: pass\n"
            "print(int(((time.monotonic() - w) - (time.thread_time() - c)) * 1000))\n")
    return subprocess.Popen([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, text=True)


def stage_pvtime(ctx):
    major = int(platform.mac_ver()[0].split(".")[0])
    vm = ctx.vm("pvtime", ["--level", "Debug"], config(ctx, vcpus=2))
    vm.shell()
    _, found = vm.sh("dmesg | grep -c 'stolen time PV' || true")
    if major < 27:
        check(found == "0", f"macOS {major}: the guest found PV time: {found!r}")
        vm.reboot()
        return f"macOS {major}: PV time not offered (no WFI figure before macOS 27), the guest uses none"
    check(found == "1", f"dmesg 'stolen time PV': {found!r}")
    _, hz = vm.sh("getconf CLK_TCK")

    def steal_ms():
        _, out = vm.sh("awk '/^cpu /{print $9}' /proc/stat")
        return int(out.strip().splitlines()[-1]) * 1000 // int(hz)

    kick_rx = re.compile(r"pvtime: (\d+) vCPU exits for steal time in ([\d.]+) s; "
                         r"the kicker's own CPU time ([\d.]+) ms")

    def case():
        start = len(vm.buf)
        control = _off_cpu_ms(PVTIME_CASE_S)
        s0 = steal_ms()
        time.sleep(PVTIME_CASE_S)
        stolen = steal_ms() - s0
        off = int(control.communicate()[0])
        lines = kick_rx.findall(vm.buf[start:])
        secs = sum(float(s) for _, s, _ in lines) or 1.0
        kicks = sum(int(k) for k, _, _ in lines) / secs
        cpu = sum(float(c) for _, _, c in lines) / secs
        return stolen, off, kicks, cpu

    def spin_guest():
        # Both vCPUs spinning; their pids kept in the shell, which keeps no
        # jobs from one command line to the next (and the root is read-only).
        vm.sh("SPIN=; for c in 0 1; do taskset -c $c sh -c 'while :; do :; done' & SPIN=\"$SPIN $!\"; done")

    results = {}
    results["idle guest"] = case()
    spin_guest()
    results["busy guest"] = case()
    hogs = [subprocess.Popen(["/usr/bin/yes"], stdout=subprocess.DEVNULL) for _ in range(2 * os.cpu_count())]
    try:
        results["busy guest, host spinners"] = case()
        vm.sh("kill $SPIN")
        results["idle guest, host spinners"] = case()
        spin_guest()
        # A pause and resume loop: no vCPU is in run() while paused, and
        # the steal goes on after it.
        s0 = steal_ms()
        for _ in range(20):
            vm.api("PATCH", "/vm", {"state": "Paused"})
            time.sleep(0.05)
            vm.api("PATCH", "/vm", {"state": "Resumed"})
            time.sleep(0.05)
        time.sleep(2)
        paused = steal_ms() - s0
        # Upstream's performance/test_pvtime_snapshot, with the host's
        # spinners for its two vCPUs pinned to one CPU (no CPU affinity on
        # macOS: row 8): the steal is kept by a restore in a new process
        # and goes on after it. The second between the reading and the pause
        # stands for upstream's ssh round trips there: steal is in USER_HZ
        # ticks (10 ms), and a pause right after the reading may come
        # before the next one.
        before = steal_ms()
        time.sleep(1)
        state, mem = (os.path.join(ctx.out, f"pvtime.{n}") for n in ("state", "mem"))
        vm.api("PATCH", "/vm", {"state": "Paused"})
        vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": state, "mem_file_path": mem})
        vm.kill()
        vm = ctx.vm("pvtime2", ["--level", "Debug"])
        vm.api("PUT", "/snapshot/load", {"snapshot_path": state,
                                         "mem_backend": {"backend_type": "File", "backend_path": mem},
                                         "resume_vm": True})
        after_snap = steal_ms()
        time.sleep(2)
        after_resume = steal_ms()
        os.unlink(state)
        os.unlink(mem)
    finally:
        for h in hogs:
            h.kill()
            h.wait()
    detail = "; ".join(
        f"{name}: steal {stolen} ms over {2 * PVTIME_CASE_S} s of vCPU time (control: a host spinner lost "
        f"{off} ms of {PVTIME_CASE_S} s), {kicks:.1f} kicks/s, kicker {cpu:.2f} ms CPU/s"
        for name, (stolen, off, kicks, cpu) in results.items()) + (
        f"; busy guest, host spinners: steal {paused} ms over 20 pauses and 2 s; "
        f"restore in a new process: {before} -> {after_snap} ms, {after_resume} ms 2 s later")
    check(paused > 0, f"no steal over 20 pauses and 2 s after: {detail}")
    check(before < after_snap < before + 10000, f"steal across the restore: {detail}")
    check(after_resume > after_snap, f"no steal after the restore: {detail}")
    busy, busy_hogs, idle_hogs = (results[k][0] for k in
                                  ("busy guest", "busy guest, host spinners", "idle guest, host spinners"))
    check(busy_hogs > 2000 * PVTIME_CASE_S // 5, f"too little steal under contention: {detail}")
    # The guest's steal on the host as it is follows what the host took from
    # its own spinner (both vCPUs: up to twice the control), plus 1 ms per
    # second per vCPU of granularity.
    control = results["busy guest"][1]
    check(busy <= 2 * control + 2 * PVTIME_CASE_S + 200, f"steal beyond the host's own load: {detail}")
    # An idle guest waits in WFI, where the kicker leaves it
    # (test_the_kicker_leaves_a_waiting_vcpu_alone). It wakes for its timer
    # ticks, and a wake-up the host's spinners hold off its CPU for 1 ms is
    # kicked (measured: about 100 kicks/s), but Hypervisor.framework counts
    # that time as the wait's, so the guest is given no steal for it, where
    # KVM counts the woken thread's run delay (docs/COMPATIBILITY.md, PV time).
    check(idle_hogs < 200, f"steal counted while the guest idled: {detail}")
    check(results["idle guest"][2] < 5, f"kicks while the guest idled: {detail}")
    vm.reboot()
    return detail


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
    "hugepages": stage_hugepages,
    "pci": stage_pci,
    "vhost-user": stage_vhost_user,
    "devices": stage_devices,
    "balloon": stage_balloon,
    "restores": stage_restores,
    "api-process": stage_api_process,
    "cli": stage_cli,
    "tools": stage_tools,
    "no-seccomp": stage_no_seccomp,
    "memory-hotplug": stage_memory_hotplug,
    "cpu-templates": stage_cpu_templates,
    "pvtime": stage_pvtime,
}


# ---------------------------------------------------------------- driver


class Context:
    def __init__(self, args):
        self.firecracker = args.firecracker
        self.snapshot_editor = args.snapshot_editor
        self.rebase_snap = args.rebase_snap
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
        return Vm(self, *a, **kw)

    def cleanup(self):
        for vm in self.vms:
            vm.kill()
        self.vms = []


def exit_on_signals():
    """SIGTERM and SIGHUP end the run as an error does, so that its cleanup
    (killing the VMs, removing temporary directories) still runs."""
    import signal

    def stop(signum, _frame):
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop)


def summarize(out, results):
    """Prints the results and writes them to <out>/summary.txt, whose last
    line, "N passed, M failed", tools/clean.sh reads. Returns the failures."""
    lines = [f"{'PASS' if ok else 'FAIL'}  {name}: {detail.splitlines()[0]}" for name, ok, detail in results]
    failed = sum(not ok for _, ok, _ in results)
    lines.append(f"{len(results) - failed} passed, {failed} failed")
    with open(os.path.join(out, "summary.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print()
    print("\n".join(lines[:-1]))
    print(f"\n{lines[-1]}; logs in {out}")
    return failed


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
    p.add_argument("--rebase-snap", required=True)
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
    exit_on_signals()
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
    failed = summarize(args.out, results)
    if not failed:
        # Snapshots and disk images take hundreds of MiB a run; kept only
        # when a stage failed, to look into.
        for name in os.listdir(args.out):
            if name.endswith((".mem", ".state", ".img")):
                os.unlink(os.path.join(args.out, name))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
