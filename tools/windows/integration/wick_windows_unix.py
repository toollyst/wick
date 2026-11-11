# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""`socket.AF_UNIX` for Python on Windows.

Windows has AF_UNIX stream sockets (afunix.h), and CPython's socket module
creates them (WSASocketW takes the family), but its Windows build names no
AF_UNIX and cannot convert a path to a `sockaddr_un`: `connect`, `bind`,
`accept`, `getsockname` and `getpeername` with a path fail. Upstream's
framework talks to Firecracker's API socket, its vsock and its userfaultfd
handler's sockets through AF_UNIX, as on Linux. This module defines
`socket.AF_UNIX` and makes `socket.socket` of that family do those calls
through Winsock itself (ctypes); sending and receiving are CPython's.
"""

import ctypes
import errno
import os
import socket
from ctypes import wintypes

AF_UNIX = 1
UNIX_PATH_MAX = 108

_ws2 = ctypes.WinDLL("ws2_32", use_last_error=True)
_SOCKET = ctypes.c_uint64


class _SockaddrUn(ctypes.Structure):
    _fields_ = [("sun_family", ctypes.c_ushort), ("sun_path", ctypes.c_char * UNIX_PATH_MAX)]


_ws2.connect.argtypes = [_SOCKET, ctypes.c_void_p, ctypes.c_int]
_ws2.bind.argtypes = [_SOCKET, ctypes.c_void_p, ctypes.c_int]
_ws2.listen.argtypes = [_SOCKET, ctypes.c_int]
_ws2.accept.argtypes = [_SOCKET, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
_ws2.accept.restype = _SOCKET
_ws2.getsockname.argtypes = [_SOCKET, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
_ws2.getpeername.argtypes = [_SOCKET, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
_ws2.WSAGetLastError.restype = ctypes.c_int
_ws2.ioctlsocket.argtypes = [_SOCKET, ctypes.c_long, ctypes.POINTER(wintypes.ULONG)]
INVALID_SOCKET = (1 << 64) - 1

# Winsock errors as the errno values the framework tests for.
_WSA_ERRNO = {10035: errno.EAGAIN, 10061: errno.ECONNREFUSED, 10048: errno.EADDRINUSE,
              10049: errno.EADDRNOTAVAIL, 10054: errno.ECONNRESET, 10022: errno.EINVAL,
              10013: errno.EACCES, 10060: errno.ETIMEDOUT, 10056: errno.EISCONN,
              10057: errno.ENOTCONN, 10036: errno.EINPROGRESS}


def _error(what, path=None):
    code = _ws2.WSAGetLastError()
    num = _WSA_ERRNO.get(code, code)
    if code == 10061 or (what == "connect" and code in (10022, 10050)):
        num = errno.ENOENT if path is not None and not os.path.exists(path) else errno.ECONNREFUSED
    exc = {errno.ECONNREFUSED: ConnectionRefusedError, errno.ENOENT: FileNotFoundError,
           errno.EADDRINUSE: OSError, errno.EAGAIN: BlockingIOError}.get(num, OSError)
    return exc(num, f"{what}({path}): {os.strerror(num)} (WSA error {code})")


def _addr(path):
    path = os.fsencode(path)
    if len(path) >= UNIX_PATH_MAX:
        raise OSError(errno.ENAMETOOLONG, f"AF_UNIX path too long: {path!r}")
    a = _SockaddrUn()
    a.sun_family = AF_UNIX
    a.sun_path = path
    return a


def _name(fn, sock):
    a = _SockaddrUn()
    n = ctypes.c_int(ctypes.sizeof(a))
    if fn(sock.fileno(), ctypes.byref(a), ctypes.byref(n)) != 0:
        raise _error(fn.__name__)
    return os.fsdecode(a.sun_path)


_RealSocket = socket.socket


class UnixSocket(_RealSocket):
    """`socket.socket` whose AF_UNIX addresses are converted here."""

    def connect(self, address):
        if self.family != AF_UNIX:
            return super().connect(address)
        a = _addr(address)
        # A socket with a timeout is non-blocking underneath (CPython's
        # select loop): the connect itself blocks, as a local AF_UNIX
        # connect completes at once or fails.
        timeout = self.gettimeout()
        self.setblocking(True)
        try:
            if _ws2.connect(self.fileno(), ctypes.byref(a), ctypes.sizeof(a)) != 0:
                raise _error("connect", address)
        finally:
            self.settimeout(timeout)
        return None

    def connect_ex(self, address):
        if self.family != AF_UNIX:
            return super().connect_ex(address)
        try:
            self.connect(address)
            return 0
        except OSError as e:
            return e.errno

    def bind(self, address):
        if self.family != AF_UNIX:
            return super().bind(address)
        a = _addr(address)
        if _ws2.bind(self.fileno(), ctypes.byref(a), ctypes.sizeof(a)) != 0:
            raise _error("bind", address)
        return None

    def accept(self):
        if self.family != AF_UNIX:
            return super().accept()
        import select  # pylint: disable=import-outside-toplevel

        timeout = self.gettimeout()
        if timeout is not None:
            # CPython's accept honours the timeout with select; so does this.
            ready, _, _ = select.select([self], [], [], timeout)
            if not ready:
                raise TimeoutError("accept timed out")
        a = _SockaddrUn()
        n = ctypes.c_int(ctypes.sizeof(a))
        s = _ws2.accept(self.fileno(), ctypes.byref(a), ctypes.byref(n))
        if s == INVALID_SOCKET:
            raise _error("accept")
        conn = UnixSocket(AF_UNIX, socket.SOCK_STREAM, 0, fileno=s)
        conn.setblocking(True)
        return conn, os.fsdecode(a.sun_path)

    def getsockname(self):
        if self.family != AF_UNIX:
            return super().getsockname()
        return _name(_ws2.getsockname, self)

    def getpeername(self):
        if self.family != AF_UNIX:
            return super().getpeername()
        return _name(_ws2.getpeername, self)

    @property
    def family(self):
        f = super().family
        return AF_UNIX if int(f) == AF_UNIX else f


def install():
    """Defines socket.AF_UNIX and makes socket.socket this class."""
    socket.AF_UNIX = AF_UNIX
    socket.socket = UnixSocket
