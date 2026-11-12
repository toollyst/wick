# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Network namespaces for upstream's framework on macOS.

Linux: `ip netns add`, a TAP device per interface in the namespace with the
host's address on it, `ip netns exec <ns> ssh ...` to reach the guest, and
the jailer's `--netns /var/run/netns/<ns>`. macOS has no network namespaces;
a network is a directory of endpoints (docs/PORTING.md row 6): the jailer's
`--netns` names it, and Firecracker makes its interfaces there. Here each
network's host side is a tools/macos/integration/netns-slirp process, whose
interfaces have the host's address on them as a TAP does on Linux.

What runs "in the namespace" on Linux: ssh and scp to the guest go through
the network's forwards (tools/macos/integration/bin/ip). Any other host
program cannot run inside a network that is a directory, so `check_output`
and the `ip` shim refuse it, naming the reason.
"""

import logging
import os
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

HELPER = os.environ.get("WICK_IT_NETNS_HELPER", "")
LOG = logging.getLogger("wick_macos_net")


def request(path, line):
    """One request to the network's host side at `path` (its control
    socket): (errno, text)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(path))
        s.sendall(line.encode() + b"\n")
        msg = b""
        while len(msg) < 6:
            more = s.recv(6 - len(msg))
            if not more:
                raise ConnectionError(f"{path}: short reply to {line!r}")
            msg += more
        err, n = struct.unpack("<iH", msg)
        text = b""
        while len(text) < n:
            more = s.recv(n - len(text))
            if not more:
                raise ConnectionError(f"{path}: short reply to {line!r}")
            text += more
        return err, text.decode()


def check(path, line):
    """A request that must succeed: its text."""
    err, text = request(path, line)
    if err:
        raise OSError(err, f"{os.strerror(err)}: network {path}: {line}")
    return text


class Tap:
    """An interface of the network (upstream: host_tools.network.Tap)."""

    def __init__(self, name, netns, ip=None):
        self._name = name
        self._netns = netns
        # As `ip tuntap add` with `ifconfig <tap> <ip> up` when there is an
        # address: without one, frames from the VMM go nowhere.
        check(netns.control, f"add {name} {ip}" if ip else f"add {name}")

    @property
    def name(self):
        """The interface's name, what the VMM opens."""
        return self._name

    @property
    def netns(self):
        """The network."""
        return self._netns

    def set_tx_queue_len(self, tx_queue_len):
        """Linux: `ip link set <tap> txqueuelen N`, the frames the host holds
        for the VMM before it drops more (test_high_ingress_traffic sets 5,
        so that a flood fills it). Here those frames wait in the VMM's
        endpoint, whose receive buffer the VMM sizes (vmm::platform::net,
        4 MiB): past it the host side drops them, as the TAP does past its
        queue. The length is recorded with the host side, which counts the
        frames it drops; the network's end logs both (`stats`), so a test's
        log shows whether its flood overflowed the queue."""
        check(self.netns.control, f"txqueuelen {self.name} {tx_queue_len}")
        self._tx_queue_len = tx_queue_len
        LOG.warning("%s: txqueuelen %s recorded: the queue is the VMM endpoint's receive buffer "
                    "(4 MiB), which the host side counts drops past", self.name, tx_queue_len)

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns.id}>"


@dataclass(repr=True)
class NetNs:
    """A network (upstream: host_tools.network.NetNs): a directory."""

    id: str
    taps: dict = field(init=False, default_factory=dict)
    _proc: object = field(init=False, default=None, repr=False)

    @property
    def path(self):
        """What the jailer's --netns names: the network's directory."""
        return Path(os.environ["WICK_IT_ROOT"]) / "netns" / self.id

    @property
    def control(self):
        """The host side's control socket."""
        return Path(os.environ["WICK_IT_ROOT"]) / "netns" / f"{self.id}.ctl"

    @property
    def forwards(self):
        """Where the host side makes its forwards."""
        return Path(os.environ["WICK_IT_ROOT"]) / "netns" / f"{self.id}.fwd"

    def cmd_prefix(self):
        """As on Linux; tools/macos/integration/bin/ip runs what it can."""
        return f"ip netns exec {self.id}"

    def check_output(self, cmd):
        """Linux: a command run in the namespace (`ip netns exec`)."""
        raise NotImplementedError(
            f"{cmd!r} in network namespace {self.id}: a macOS network is a directory of "
            "endpoints, a host program cannot run inside it (docs/PORTING.md row 6)"
        )

    def setup(self):
        """Creates the network."""
        if self._proc is not None:
            return
        if not HELPER:
            raise RuntimeError("WICK_IT_NETNS_HELPER is not set: run tools/macos/integration-tests.sh")
        self.path.mkdir(parents=True, exist_ok=True)
        self.forwards.mkdir(parents=True, exist_ok=True)
        # stdin is a pipe: the host side ends when this process closes it
        # (or dies).
        self._proc = subprocess.Popen(
            [HELPER, str(self.path), str(self.control), str(self.forwards)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        line = self._proc.stdout.readline()
        if line.strip() != "ready":
            self._proc.kill()
            raise RuntimeError(f"network {self.id}: {HELPER} did not start ({line!r})")

    def cleanup(self):
        """Removes the network."""
        for tap in self.taps.values():
            if getattr(tap, "_tx_queue_len", None) is not None and self._proc is not None:
                LOG.warning("%s: %s", tap.name, check(self.control, f"stats {tap.name}"))
        if self._proc is not None:
            self._proc.stdin.close()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        self.control.unlink(missing_ok=True)
        shutil.rmtree(self.path, ignore_errors=True)
        shutil.rmtree(self.forwards, ignore_errors=True)

    def add_tap(self, name, ip):
        """An interface in the network with the host's address `ip`."""
        if name not in self.taps:
            self.taps[name] = Tap(name, self, ip)
        return self.taps[name]

    def is_used(self):
        """Whether a VMM still holds one of the interfaces."""
        return any(check(self.control, f"used {tap}") == "1" for tap in self.taps)
