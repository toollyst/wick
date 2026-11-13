# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A Python program "in" a Windows network (wick_windows_net.py).

Linux: `ip netns exec <ns> python3 ...` runs the program in the namespace,
where the TAP's address is the host's and the guest's is next to it.
Windows has no namespaces: the network is a user-space stack in the test
session's process, and the program runs on the host. hosttools.py's `ip
netns exec` starts it with this directory on PYTHONPATH and the network's
door in WICK_NETNS_DOOR, and Python imports this module at its start. It
makes the program's sockets ask the door:

- `bind` to the network's host address (TCP): the socket listens on
  127.0.0.1, and `listen` has the stack send the guest's connections to
  that address and port there;
- `connect` or `sendto` to an address in the network's subnets: through
  the stack's forward for it, a port on 127.0.0.1;
- `setsockopt(SOL_UDP, UDP_SEGMENT, n)`, which Windows does not have: kept,
  and a datagram longer than n is sent as datagrams of n bytes, what Linux
  makes of it (net/ipv4/udp.c, `udp_send_skb`: a payload above `gso_size`
  is segmented by it; here on the sender's side, as an interface without
  the offload has it done before the frame leaves).

Not done, and refused where it would be needed: UDP received on the host's
address (a `bind` of a datagram socket to it).
"""

import ipaddress
import json
import os
import socket

_DOOR = os.environ.get("WICK_NETNS_DOOR")
# The socket class as Python has it: the door itself is reached with it.
_Plain = socket.socket
SOL_UDP, UDP_SEGMENT = 17, 103


def _ask(request, keep=False):
    """One request to the door; with `keep`, the connection too (what it
    asked for lasts as long)."""
    conn = _Plain(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(30)
    conn.connect(("127.0.0.1", int(_DOOR)))
    conn.sendall((json.dumps(request) + "\n").encode())
    reply = json.loads(conn.makefile("r", encoding="utf-8").readline())
    if "error" in reply:
        conn.close()
        raise OSError(f"the network's door: {reply['error']}")
    if keep:
        return reply, conn
    conn.close()
    return reply


_NETWORK = None


def _network():
    global _NETWORK  # pylint: disable=global-statement
    if _NETWORK is None:
        reply = _ask({"op": "hosts"})
        _NETWORK = ({ipaddress.ip_address(h) for h in reply["hosts"]},
                    [ipaddress.ip_network(n) for n in reply["nets"]])
    return _NETWORK


def _address(address):
    """The IPv4 address of a socket address, or None."""
    try:
        return ipaddress.ip_address(address[0])
    except (ValueError, TypeError, IndexError):
        return None


class _Socket(socket.socket):
    """A socket whose addresses in the network go through the door."""

    _wick_listen = None
    _wick_kept = None
    _wick_gso = 0

    def _wick_forward(self, address):
        ip = _address(address)
        if self.family != socket.AF_INET or ip is None or ip in _network()[0] \
                or not any(ip in net for net in _network()[1]):
            return address
        proto = "udp" if self.type == socket.SOCK_DGRAM else "tcp"
        return ("127.0.0.1", _ask({"op": "forward", "proto": proto, "ip": str(ip), "port": address[1]})["port"])

    def bind(self, address):
        ip = _address(address)
        if self.family == socket.AF_INET and ip is not None and ip in _network()[0]:
            if self.type != socket.SOCK_STREAM:
                raise OSError(f"bind({address}): UDP on the network's host address is not done on Windows "
                              "(tools/windows/integration/netns_site/sitecustomize.py)")
            self._wick_listen = (str(ip), address[1])
            return super().bind(("127.0.0.1", 0))
        return super().bind(address)

    def listen(self, *args):
        super().listen(*args)
        if self._wick_listen is not None and self._wick_kept is None:
            ip, port = self._wick_listen
            _reply, self._wick_kept = _ask({"op": "listen", "ip": ip, "port": port, "to": self.getsockname()[1]},
                                           keep=True)

    def close(self):
        if self._wick_kept is not None:
            self._wick_kept.close()
            self._wick_kept = None
        super().close()

    def connect(self, address):
        return super().connect(self._wick_forward(address))

    def connect_ex(self, address):
        return super().connect_ex(self._wick_forward(address))

    def setsockopt(self, level, optname, *value):
        if level == SOL_UDP and optname == UDP_SEGMENT and self.type == socket.SOCK_DGRAM:
            self._wick_gso = int(value[0])
            return None
        return super().setsockopt(level, optname, *value)

    def sendto(self, data, *rest):
        address = self._wick_forward(rest[-1])
        size = self._wick_gso
        if not size or len(data) <= size:
            return super().sendto(data, *rest[:-1], address)
        for at in range(0, len(data), size):
            super().sendto(data[at : at + size], *rest[:-1], address)
        return len(data)


if _DOOR:
    socket.socket = _Socket
