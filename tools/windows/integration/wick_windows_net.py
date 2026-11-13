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

A host program cannot run inside a network that is a directory. What
upstream's tests run there (`ip netns exec <ns> python3 ...`, `iperf3`) runs
on the host and reaches the network through its door, a TCP port on
127.0.0.1 named in <network>.door, one JSON line per request:

    {"op": "hosts"}                        the host's addresses and subnets
    {"op": "forward", "proto": "tcp"|"udp"|"both", "ip": guest, "port": n}
                                           a port on 127.0.0.1 that leads there
    {"op": "listen", "ip": host, "port": n, "to": m}
                                           connections the guest opens to
                                           host:n go to 127.0.0.1:m, while
                                           the door's connection stays open

tools/windows/integration/netns_site/sitecustomize.py makes a Python
program's sockets ask it (hosttools.py's `ip netns exec`). The stack here
sends UDP for a forward, answers a datagram nobody takes with ICMP port
unreachable (Linux: net/ipv4/udp.c, `__udp4_lib_rcv`), and takes the
guest's connections to a port that is listened on.

Frames to the guest wait in a queue of the interface's length, 500 unless
set (`Tap.set_tx_queue_len`), and a frame that finds it full is dropped: a
TAP's transmit queue (Linux drivers/net/tun.c: `tun_net_xmit` drops when
`ptr_ring_produce` on the queue's ring fails; `tun_setup` sets
`tx_queue_len` to `TUN_READQ_SIZE`, 500; a change resizes the ring).
"""

import collections
import ipaddress
import json
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
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
# An interface's MTU, and a TAP's transmit queue length (TUN_READQ_SIZE).
MTU = 1500
TX_QUEUE_LEN = 500
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

    def __init__(self, iface, guest, gport, peer, hport=None):
        self.iface, self.guest, self.gport, self.peer = iface, guest, gport, peer
        self.hport = hport or random.randint(20000, 60000)
        # What opens the connection from here: SYN, or SYN|ACK to a guest's SYN.
        self.opening = SYN
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

    def accept(self, seq):
        """The guest's SYN, sequence number `seq`, to a port that is
        listened on: SYN|ACK, and the connection is established by the
        guest's acknowledgement."""
        self.opening = SYN | ACK
        self.rcv_nxt = (seq + 1) & 0xFFFFFFFF
        self.start()

    def start(self):
        with self.lock:
            self.segment(self.opening)
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
                    self.segment(self.opening, seq=self.snd_una)
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
            if not self.established.is_set() and self.opening == SYN | ACK:
                if not (flags & ACK and not flags & SYN and ack == self.snd_nxt & 0xFFFFFFFF):
                    return
                # The guest's acknowledgement of the SYN|ACK; what it carries is handled below.
                self.snd_una = self.snd_nxt
                self.established.set()
            elif not self.established.is_set():
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
        self.stop = False
        # Frames to the guest: a TAP's transmit queue.
        self.tx_queue = collections.deque()
        self.tx_queue_len = TX_QUEUE_LEN
        self.tx_dropped = 0
        self.tx_ready = threading.Condition()
        # UDP: host port -> what takes a datagram (source address, source port, payload).
        self.udp = {}
        # TCP ports of the host's address that are listened on -> (address, port) on the host.
        self.listeners = {}
        threading.Thread(target=self._write, daemon=True).start()
        self.ident = random.getrandbits(16)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def paths(self):
        """Where the endpoint may be: in a jail's own directory of the
        network, <network>\\<id>\\<name> (the jailer gives each jail one),
        or in the network directory itself for a VMM not jailed. A jail that
        ended leaves its directory, and may leave its endpoint, which refuses
        a connection: the switch connects to the one that accepts."""
        found = sorted(p for p in self.netns.path.glob(f"*/{self.name}"))
        bare = self.netns.path / self.name
        return found + [bare] if bare.exists() else found

    def used(self):
        return self.conn is not None

    # -- the endpoint

    def _run(self):
        while not self.stop:
            s = None
            for path in self.paths():
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    s.connect(str(path))
                    break
                except OSError:
                    s.close()
                    s = None
            if s is None:
                time.sleep(0.05)
                continue
            self.conn = s
            try:
                self._read(s)
            except OSError:
                pass
            finally:
                self.conn = None
                with self.tx_ready:
                    self.tx_queue.clear()
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
        """Queues a frame for the guest; one that finds the queue full is
        dropped, as a TAP drops it."""
        if self.conn is None:
            return
        with self.tx_ready:
            if len(self.tx_queue) >= self.tx_queue_len:
                self.tx_dropped += 1
                return
            self.tx_queue.append(frame)
            self.tx_ready.notify()

    def _write(self):
        """Writes the queued frames to the endpoint, which takes them as
        fast as the VMM reads."""
        while not self.stop:
            with self.tx_ready:
                while not self.tx_queue and not self.stop:
                    self.tx_ready.wait(0.5)
                if self.stop:
                    return
                frame = self.tx_queue[0]
            conn = self.conn
            if conn is not None:
                try:
                    conn.sendall(struct.pack("!I", len(frame)) + frame)
                except OSError:
                    pass
            # The frame leaves the queue once it is written: a queue of N
            # holds N frames the VMM has not taken.
            with self.tx_ready:
                if self.tx_queue and self.tx_queue[0] is frame:
                    self.tx_queue.popleft()

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
        elif proto == PROTO_UDP and len(payload) >= 8:
            sport, dport, length = struct.unpack("!HHH", payload[:6])
            taker = self.udp.get(dport)
            if taker is not None:
                taker(srcip, sport, payload[8:length])
            else:
                # Nobody has the port: ICMP port unreachable with the
                # datagram's IP header and first 8 bytes, as Linux answers.
                quote = body[: ihl + 8]
                icmp = struct.pack("!BBHI", 3, 3, 0, 0) + quote
                icmp = icmp[:2] + struct.pack("!H", _csum(icmp)) + icmp[4:]
                self.send_ip(srcip, PROTO_ICMP, icmp)
        elif proto == PROTO_TCP and len(payload) >= 20:
            sport, dport, seq, ack, off, flags, window = struct.unpack("!HHIIBBH", payload[:16])
            data = payload[(off >> 4) * 4 :]
            flow = self.flows.get((dport, str(srcip), sport))
            if flow is not None:
                flow.receive(seq, ack, flags, window, data)
            elif flags & SYN and not flags & ACK and dport in self.listeners and self._accept(srcip, sport, dport, seq):
                pass
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
        """One IP packet to `dst`, in fragments when it is longer than the
        interface's MTU (a UDP datagram can be; TCP's segments are not)."""
        mac = self.neighbours.get(dst) or self._resolve(dst, 1.0)
        if mac is None:
            return
        self.ident = (self.ident + 1) & 0xFFFF
        room = (MTU - 20) & ~7
        pieces = [payload[i : i + room] for i in range(0, len(payload), room)] or [b""]
        for i, piece in enumerate(pieces):
            # Don't Fragment on what fits; More Fragments on all but the last piece.
            flags = 0x4000 if len(pieces) == 1 else (0x2000 if i + 1 < len(pieces) else 0) | (i * room // 8)
            hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(piece), self.ident, flags, 64, proto, 0,
                              self.host_ip.packed, dst.packed)
            hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
            self._send_frame(mac + self.host_mac + struct.pack("!H", ETH_IP) + hdr + piece)

    def send_udp(self, dst, sport, dport, payload):
        """A UDP datagram from the host's address."""
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        pseudo = struct.pack("!4s4sBBH", self.host_ip.packed, dst.packed, 0, PROTO_UDP, 8 + len(payload))
        c = _csum(pseudo + udp + payload) or 0xFFFF
        self.send_ip(dst, PROTO_UDP, udp[:6] + struct.pack("!H", c) + payload)

    def _accept(self, guest, gport, hport, seq):
        """The guest's SYN to a port that is listened on: a connection to
        the program that listens, relayed. False if the program is gone
        (the SYN is then answered with a reset, as a closed port's)."""
        try:
            peer = socket.create_connection(self.listeners[hport], timeout=5)
        except OSError:
            return False
        peer.settimeout(None)
        peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        flow = _TcpFlow(self, guest, gport, peer, hport=hport)
        self.flows[(hport, str(guest), gport)] = flow
        flow.accept(seq)
        return True

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
        with self.tx_ready:
            self.tx_ready.notify_all()
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
        """Linux: `ip link set <tap> txqueuelen N`. Here the length of the
        host side's queue of frames for the guest."""
        self._iface.tx_queue_len = int(tx_queue_len)

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns.id}>"


_NETWORKS = {}


@dataclass(repr=True)
class NetNs:
    """A network (upstream: host_tools.network.NetNs): a directory."""

    id: str
    taps: dict = field(init=False, default_factory=dict)
    _forwards: dict = field(init=False, default_factory=dict, repr=False)
    _door: object = field(init=False, default=None, repr=False)

    @property
    def path(self):
        """What the jailer's --netns names: the network's directory."""
        return Path(os.environ["WICK_IT_ROOT"]) / "netns" / self.id

    def cmd_prefix(self):
        """As on Linux: `ip netns exec <ns>` (the ssh substitute reads it)."""
        return f"ip netns exec {self.id}"

    @property
    def door_path(self):
        """The file that names the door's port, beside the network's directory."""
        return self.path.with_name(self.id + ".door")

    def check_output(self, cmd):
        """Linux: a command run in the namespace (`ip netns exec`). Here on
        the host, through the network's door (hosttools.py, `ip`)."""
        from framework import utils  # pylint: disable=import-outside-toplevel

        return utils.check_output(f"{self.cmd_prefix()} {cmd}")

    def setup(self):
        """Creates the network."""
        self.path.mkdir(parents=True, exist_ok=True)
        _NETWORKS[self.id] = self
        self._door = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._door.bind(("127.0.0.1", 0))
        self._door.listen(16)
        self.door_path.write_text(str(self._door.getsockname()[1]), encoding="ascii")
        threading.Thread(target=self._serve_door, args=(self._door,), daemon=True).start()

    def _iface_of(self, ip, host=False):
        """The interface whose subnet has `ip` (or whose host address it is)."""
        ip = ipaddress.ip_address(ip)
        for tap in self.taps.values():
            iface = tap._iface  # pylint: disable=protected-access
            if iface.network and (ip == iface.host_ip if host else ip in iface.network):
                return iface
        raise OSError(f"network {self.id}: no interface has {ip} {'as its address' if host else 'in its subnet'}")

    def _serve_door(self, door):
        while True:
            try:
                conn, _ = door.accept()
            except OSError:
                return
            threading.Thread(target=self._door_client, args=(conn,), daemon=True).start()

    def _door_client(self, conn):
        """One program's requests; what it listens on lasts while its
        connection does."""
        listened = []
        try:
            for line in conn.makefile("r", encoding="utf-8"):
                try:
                    reply = self._door_request(json.loads(line), listened)
                except (OSError, ValueError, KeyError) as e:
                    reply = {"error": str(e)}
                conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass
        finally:
            for iface, port in listened:
                iface.listeners.pop(port, None)
            conn.close()

    def _door_request(self, req, listened):
        if req["op"] == "hosts":
            ifaces = [t._iface for t in self.taps.values() if t._iface.network]  # pylint: disable=protected-access
            return {"hosts": [str(i.host_ip) for i in ifaces], "nets": [str(i.network) for i in ifaces]}
        if req["op"] == "forward":
            if req["proto"] == "tcp":
                return {"port": self.forward(req["ip"], int(req["port"]))}
            if req["proto"] == "udp":
                return {"port": self.forward_udp(req["ip"], int(req["port"]))}
            return {"port": self.forward_both(req["ip"], int(req["port"]))}
        if req["op"] == "listen":
            iface = self._iface_of(req["ip"], host=True)
            if int(req["port"]) in iface.listeners:
                raise OSError(f"{req['ip']}:{req['port']} is listened on already")
            iface.listeners[int(req["port"])] = ("127.0.0.1", int(req["to"]))
            listened.append((iface, int(req["port"])))
            return {"ok": True}
        raise ValueError(f"unknown request {req['op']!r}")

    def cleanup(self):
        """Removes the network."""
        for tap in self.taps.values():
            tap._iface.close()  # pylint: disable=protected-access
        for listener, _ in self._forwards.values():
            listener.close()
        self._forwards.clear()
        if self._door is not None:
            self._door.close()
            self.door_path.unlink(missing_ok=True)
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

    def forward(self, guest_ip, port, listener=None):
        """A TCP port on 127.0.0.1 that leads to guest_ip:port (`listener`:
        a socket bound to the port to use)."""
        key = (str(guest_ip), port)
        if key in self._forwards:
            return self._forwards[key][1]
        guest = ipaddress.ip_address(guest_ip)
        iface = self._iface_of(guest)
        if listener is None:
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

    def forward_udp(self, guest_ip, port, sock=None):
        """A UDP port on 127.0.0.1 that leads to guest_ip:port: a datagram
        sent to it goes to the guest from a port of the host's address
        that stands for its sender, and the guest's answers to that port
        come back to the sender."""
        key = ("udp", str(guest_ip), port)
        if key in self._forwards:
            return self._forwards[key][1]
        guest = ipaddress.ip_address(guest_ip)
        iface = self._iface_of(guest)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
        senders = {}

        def relay():
            while True:
                try:
                    data, sender = sock.recvfrom(65536)
                except ConnectionError:
                    # Windows reports a sender that went away on the socket
                    # that answered it (WSAECONNRESET); the port goes on.
                    continue
                except OSError:
                    return
                hport = senders.get(sender)
                if hport is None:
                    hport = random.randint(20000, 60000)
                    while hport in iface.udp:
                        hport = random.randint(20000, 60000)
                    senders[sender] = hport

                    def back(_ip, _sport, payload, sender=sender):
                        try:
                            sock.sendto(payload, sender)
                        except OSError:
                            pass

                    iface.udp[hport] = back
                iface.send_udp(guest, hport, port, data)

        threading.Thread(target=relay, daemon=True).start()
        self._forwards[key] = (sock, sock.getsockname()[1])
        return self._forwards[key][1]

    def forward_both(self, guest_ip, port):
        """One port number on 127.0.0.1 that leads to guest_ip:port for TCP
        and for UDP (iperf3 sends UDP to the port of its TCP connection)."""
        key = ("both", str(guest_ip), port)
        if key in self._forwards:
            return self._forwards[key][1]
        self._iface_of(guest_ip)
        # A number free for both: the system picks one for TCP, and UDP may
        # have it taken; then another is asked for.
        for _ in range(64):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(("127.0.0.1", 0))
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                udp.bind(("127.0.0.1", tcp.getsockname()[1]))
            except OSError:
                tcp.close()
                udp.close()
                continue
            # A forward of one protocol made before has another number.
            for old in ((str(guest_ip), port), ("udp", str(guest_ip), port)):
                if old in self._forwards:
                    self._forwards.pop(old)[0].close()
            local = self.forward(guest_ip, port, listener=tcp)
            self.forward_udp(guest_ip, port, sock=udp)
            self._forwards[key] = (tcp, local)
            return local
        raise OSError(f"network {self.id}: no port on 127.0.0.1 is free for both TCP and UDP")


def network(netns_id):
    """The network named `netns_id`, if this session made it."""
    return _NETWORKS.get(netns_id)
