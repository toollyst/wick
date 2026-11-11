# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Networks for upstream's framework on Windows.

Linux: `ip netns add`, a TAP device per interface in the namespace with the
host's address on it, `ip netns exec <ns> ssh ...` to reach the guest, and
the jailer's `--netns /var/run/netns/<ns>`. Windows has no network
namespaces; a network is a directory of endpoints (docs/PORTING.md row 6):
the jailer's `--netns` names it, and Firecracker makes its interfaces
there, each an AF_UNIX stream socket carrying Ethernet frames, each after
its length as a 32-bit big-endian number (overlay/vmm/platform/windows/
net.rs). The host side of each interface is here: a user-space IP stack with
the host's address on it, as the TAP has on Linux, which answers ARP and
ICMP echo and carries TCP connections the host opens to the guest (what
macOS's tools/macos/integration/netns-slirp does with libslirp). The test
reaches the guest through a forward: a TCP listener on 127.0.0.1 that leads
to <guest>:<port>, what `ip netns exec <ns> ssh <guest>` does on Linux.
A host program cannot run inside a network that is a directory.
"""

import ipaddress
import os
import random
import shutil
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ETH_IP, ETH_ARP = 0x0800, 0x0806
PROTO_ICMP, PROTO_TCP = 1, 6
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS = 1400
WINDOW = 65535
RTO = 0.2


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _mac(text):
    return bytes(int(x, 16) for x in text.split(":"))


class _TcpFlow:
    """One TCP connection the host opened to the guest, relayed to `peer`
    (the accepted forward connection)."""

    def __init__(self, iface, guest, gport, peer):
        self.iface, self.guest, self.gport, self.peer = iface, guest, gport, peer
        self.hport = random.randint(20000, 60000)
        self.snd_nxt = self.snd_una = random.getrandbits(32)
        self.rcv_nxt = 0
        self.peer_window = MSS
        self.unacked = b""  # sent, not acknowledged
        self.pending = b""  # from the peer, not sent yet
        self.established = threading.Event()
        self.closed = False
        self.fin_sent = False
        self.peer_eof = False
        self.lock = threading.Lock()
        self.last_tx = 0.0

    def segment(self, flags, payload=b"", seq=None):
        seq = self.snd_nxt if seq is None else seq
        tcp = struct.pack("!HHIIBBHHH", self.hport, self.gport, seq & 0xFFFFFFFF, self.rcv_nxt & 0xFFFFFFFF,
                          5 << 4, flags, WINDOW, 0, 0)
        pseudo = struct.pack("!4s4sBBH", self.iface.host_ip.packed, self.guest.packed, 0, PROTO_TCP,
                             len(tcp) + len(payload))
        c = _csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
        self.iface.send_ip(self.guest, PROTO_TCP, tcp + payload)

    def start(self):
        with self.lock:
            self.segment(SYN)
            self.snd_nxt += 1
            self.last_tx = time.time()
        threading.Thread(target=self._from_peer, daemon=True).start()
        threading.Thread(target=self._timer, daemon=True).start()

    def _push(self):
        """Sends what the guest's window takes (lock held)."""
        if not self.established.is_set():
            return
        while self.pending and len(self.unacked) < self.peer_window:
            n = min(MSS, len(self.pending), self.peer_window - len(self.unacked))
            chunk, self.pending = self.pending[:n], self.pending[n:]
            self.segment(ACK | PSH, chunk)
            self.snd_nxt += len(chunk)
            self.unacked += chunk
            self.last_tx = time.time()
        if self.peer_eof and not self.pending and not self.fin_sent:
            self.segment(FIN | ACK)
            self.snd_nxt += 1
            self.fin_sent = True
            self.last_tx = time.time()

    def _from_peer(self):
        try:
            while not self.closed:
                data = self.peer.recv(65536)
                with self.lock:
                    if not data:
                        self.peer_eof = True
                        self._push()
                        return
                    self.pending += data
                    self._push()
                # Back-pressure: wait while much is queued.
                while not self.closed and len(self.pending) > 4 * WINDOW:
                    time.sleep(0.005)
        except OSError:
            self.close(reset=True)

    def _timer(self):
        while not self.closed:
            time.sleep(RTO / 2)
            with self.lock:
                if self.closed:
                    return
                if time.time() - self.last_tx < RTO:
                    continue
                if not self.established.is_set():
                    self.segment(SYN, seq=self.snd_una)
                    self.last_tx = time.time()
                elif self.unacked:
                    # Go-back-N from the oldest unacknowledged byte.
                    self.segment(ACK | PSH, self.unacked[:MSS], seq=self.snd_una)
                    self.last_tx = time.time()
                elif self.fin_sent and self.snd_una != self.snd_nxt:
                    self.segment(FIN | ACK, seq=self.snd_nxt - 1)
                    self.last_tx = time.time()

    def receive(self, seq, ack, flags, window, payload):
        with self.lock:
            if flags & RST:
                self.close_locked()
                return
            self.peer_window = max(window, 1)
            if not self.established.is_set():
                if flags & SYN and flags & ACK and ack == self.snd_nxt & 0xFFFFFFFF:
                    self.rcv_nxt = seq + 1
                    self.snd_una = self.snd_nxt
                    self.segment(ACK)
                    self.established.set()
                    self._push()
                return
            if flags & ACK:
                acked = (ack - self.snd_una) & 0xFFFFFFFF
                outstanding = (self.snd_nxt - self.snd_una) & 0xFFFFFFFF
                if 0 < acked <= outstanding:
                    data_acked = min(acked, len(self.unacked))
                    self.unacked = self.unacked[data_acked:]
                    self.snd_una = (self.snd_una + acked) & 0xFFFFFFFF
                    self.last_tx = time.time()
            if payload:
                if seq == self.rcv_nxt & 0xFFFFFFFF:
                    try:
                        self.peer.sendall(payload)
                    except OSError:
                        self.close_locked(reset=True)
                        return
                    self.rcv_nxt = (self.rcv_nxt + len(payload)) & 0xFFFFFFFF
                self.segment(ACK)
            if flags & FIN:
                if seq + len(payload) == self.rcv_nxt or (seq + len(payload)) & 0xFFFFFFFF == self.rcv_nxt:
                    self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF
                self.segment(ACK)
                try:
                    self.peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                if self.fin_sent:
                    self.close_locked()
            elif self.fin_sent and self.snd_una == self.snd_nxt and self.peer_eof:
                pass
            self._push()

    def close_locked(self, reset=False):
        if self.closed:
            return
        self.closed = True
        if reset:
            self.segment(RST | ACK)
        try:
            self.peer.close()
        except OSError:
            pass
        self.iface.flows.pop((self.hport, str(self.guest), self.gport), None)

    def close(self, reset=False):
        with self.lock:
            self.close_locked(reset)


class _Iface:
    """An interface of the network: the host's side of one endpoint."""

    def __init__(self, netns, name, ip):
        self.netns, self.name = netns, name
        iface = ipaddress.ip_interface(ip) if ip else None
        self.host_ip = iface.ip if iface else None
        self.network = iface.network if iface else None
        self.host_mac = bytes([0x06, 0x00]) + (self.host_ip.packed if self.host_ip else b"\0\0\0\1")
        self.neighbours = {}  # guest ip -> mac
        self.flows = {}
        self.conn = None
        self.send_lock = threading.Lock()
        self.stop = False
        self.ident = random.getrandbits(16)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @property
    def path(self):
        return self.netns.path / self.name

    def used(self):
        return self.conn is not None

    # -- the endpoint

    def _run(self):
        while not self.stop:
            if not self.path.exists():
                time.sleep(0.05)
                continue
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(self.path))
            except OSError:
                s.close()
                time.sleep(0.05)
                continue
            self.conn = s
            try:
                self._read(s)
            except OSError:
                pass
            finally:
                self.conn = None
                s.close()
                for flow in list(self.flows.values()):
                    flow.close()
            # The VMM went away; a new one binds the endpoint anew.
            time.sleep(0.05)

    def _read(self, s):
        buf = b""
        while not self.stop:
            data = s.recv(65536)
            if not data:
                return
            buf += data
            while len(buf) >= 4:
                n = struct.unpack("!I", buf[:4])[0]
                if len(buf) < 4 + n:
                    break
                frame, buf = buf[4 : 4 + n], buf[4 + n :]
                self._frame(frame)

    def _send_frame(self, frame):
        conn = self.conn
        if conn is None:
            return
        with self.send_lock:
            try:
                conn.sendall(struct.pack("!I", len(frame)) + frame)
            except OSError:
                pass

    # -- link and network layers

    def _frame(self, frame):
        if len(frame) < 14 or self.host_ip is None:
            return
        dst, src, kind = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        if dst not in (self.host_mac, b"\xff" * 6):
            return
        body = frame[14:]
        if kind == ETH_ARP and len(body) >= 28:
            op = struct.unpack("!H", body[6:8])[0]
            sha, spa, tpa = body[8:14], body[14:18], body[24:28]
            self.neighbours[ipaddress.ip_address(spa)] = sha
            if op == 1 and tpa == self.host_ip.packed:
                reply = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IP, 6, 4, 2, self.host_mac, self.host_ip.packed, sha, spa)
                self._send_frame(sha + self.host_mac + struct.pack("!H", ETH_ARP) + reply)
            return
        if kind != ETH_IP or len(body) < 20:
            return
        ihl = (body[0] & 0x0F) * 4
        total = struct.unpack("!H", body[2:4])[0]
        proto, srcip, dstip = body[9], ipaddress.ip_address(body[12:16]), ipaddress.ip_address(body[16:20])
        self.neighbours.setdefault(srcip, src)
        if dstip != self.host_ip:
            return
        payload = body[ihl:total]
        if proto == PROTO_ICMP and len(payload) >= 8 and payload[0] == 8:
            reply = b"\0\0" + b"\0\0" + payload[4:]
            reply = reply[:2] + struct.pack("!H", _csum(reply)) + reply[4:]
            self.send_ip(srcip, PROTO_ICMP, reply)
        elif proto == PROTO_TCP and len(payload) >= 20:
            sport, dport, seq, ack, off, flags, window = struct.unpack("!HHIIBBH", payload[:16])
            data = payload[(off >> 4) * 4 :]
            flow = self.flows.get((dport, str(srcip), sport))
            if flow is not None:
                flow.receive(seq, ack, flags, window, data)
            elif not flags & RST:
                # Nothing listens on the host side: a reset, as Linux's
                # stack answers a connection to a closed port.
                rst_seq = ack if flags & ACK else 0
                rst_ack = (seq + len(data) + (1 if flags & SYN else 0) + (1 if flags & FIN else 0)) & 0xFFFFFFFF
                tcp = struct.pack("!HHIIBBHHH", dport, sport, rst_seq, rst_ack, 5 << 4, RST | ACK, 0, 0, 0)
                pseudo = struct.pack("!4s4sBBH", self.host_ip.packed, srcip.packed, 0, PROTO_TCP, len(tcp))
                tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp)) + tcp[18:]
                self.send_ip(srcip, PROTO_TCP, tcp)

    def _resolve(self, ip, timeout=5.0):
        deadline = time.time() + timeout
        while ip not in self.neighbours:
            if time.time() > deadline:
                return None
            req = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IP, 6, 4, 1, self.host_mac, self.host_ip.packed, b"\0" * 6, ip.packed)
            self._send_frame(b"\xff" * 6 + self.host_mac + struct.pack("!H", ETH_ARP) + req)
            time.sleep(0.1)
        return self.neighbours[ip]

    def send_ip(self, dst, proto, payload):
        mac = self.neighbours.get(dst) or self._resolve(dst, 1.0)
        if mac is None:
            return
        self.ident = (self.ident + 1) & 0xFFFF
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), self.ident, 0x4000, 64, proto, 0,
                          self.host_ip.packed, dst.packed)
        hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
        self._send_frame(mac + self.host_mac + struct.pack("!H", ETH_IP) + hdr + payload)

    # -- forwards

    def connect(self, guest, port, peer):
        """A TCP connection from the host to guest:port, relayed to `peer`."""
        flow = _TcpFlow(self, guest, port, peer)
        self.flows[(flow.hport, str(guest), port)] = flow
        if self._resolve(guest) is None:
            flow.close()
            return
        flow.start()

    def close(self):
        self.stop = True
        for flow in list(self.flows.values()):
            flow.close()
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass


class Tap:
    """An interface of the network (upstream: host_tools.network.Tap)."""

    def __init__(self, name, netns, ip=None):
        self._name = name
        self._netns = netns
        # As `ip tuntap add` with `ip addr add <ip> dev <tap>`: without an
        # address, frames from the VMM go nowhere.
        self._iface = _Iface(netns, name, ip)

    @property
    def name(self):
        """The interface's name, what the VMM opens."""
        return self._name

    @property
    def netns(self):
        """The network."""
        return self._netns

    def set_tx_queue_len(self, tx_queue_len):
        """Linux: `ip link set <tap> txqueuelen N`."""
        raise NotImplementedError(
            f"{self.name}: txqueuelen {tx_queue_len}: an interface of a Windows network is a "
            "stream endpoint, it has no transmit queue to size (docs/PORTING.md row 6)"
        )

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns.id}>"


_NETWORKS = {}


@dataclass(repr=True)
class NetNs:
    """A network (upstream: host_tools.network.NetNs): a directory."""

    id: str
    taps: dict = field(init=False, default_factory=dict)
    _forwards: dict = field(init=False, default_factory=dict, repr=False)

    @property
    def path(self):
        """What the jailer's --netns names: the network's directory."""
        return Path(os.environ["WICK_IT_ROOT"]) / "netns" / self.id

    def cmd_prefix(self):
        """As on Linux: `ip netns exec <ns>` (the ssh substitute reads it)."""
        return f"ip netns exec {self.id}"

    def check_output(self, cmd):
        """Linux: a command run in the namespace (`ip netns exec`)."""
        raise NotImplementedError(
            f"{cmd!r} in network namespace {self.id}: a Windows network is a directory of "
            "endpoints, a host program cannot run inside it (docs/PORTING.md row 6)"
        )

    def setup(self):
        """Creates the network."""
        self.path.mkdir(parents=True, exist_ok=True)
        _NETWORKS[self.id] = self

    def cleanup(self):
        """Removes the network."""
        for tap in self.taps.values():
            tap._iface.close()  # pylint: disable=protected-access
        for listener, _ in self._forwards.values():
            listener.close()
        self._forwards.clear()
        _NETWORKS.pop(self.id, None)
        shutil.rmtree(self.path, ignore_errors=True)

    def add_tap(self, name, ip):
        """An interface in the network with the host's address `ip`."""
        if name not in self.taps:
            self.taps[name] = Tap(name, self, ip)
        return self.taps[name]

    def is_used(self):
        """Whether a VMM still holds one of the interfaces."""
        return any(t._iface.used() for t in self.taps.values())  # pylint: disable=protected-access

    def forward(self, guest_ip, port):
        """A TCP port on 127.0.0.1 that leads to guest_ip:port."""
        key = (str(guest_ip), port)
        if key in self._forwards:
            return self._forwards[key][1]
        guest = ipaddress.ip_address(guest_ip)
        iface = next((t._iface for t in self.taps.values()  # pylint: disable=protected-access
                      if t._iface.network and guest in t._iface.network), None)  # pylint: disable=protected-access
        if iface is None:
            raise OSError(f"network {self.id}: no interface has {guest_ip} in its subnet")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)

        def accept():
            while True:
                try:
                    peer, _ = listener.accept()
                except OSError:
                    return
                peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=iface.connect, args=(guest, port, peer), daemon=True).start()

        threading.Thread(target=accept, daemon=True).start()
        self._forwards[key] = (listener, listener.getsockname()[1])
        return self._forwards[key][1]


def network(netns_id):
    """The network named `netns_id`, if this session made it."""
    return _NETWORKS.get(netns_id)
