# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""`fcntl` for upstream's test framework on Windows, which has none.

The framework imports it for one thing, the Nitro Enclaves device's ioctls
(framework/enclave.py), which no Windows host has: every call fails with
ENOSYS, as an ioctl on a device the host lacks fails on Linux (the enclave
backend then reports it unavailable). F_GETFL/F_SETFL with O_NONBLOCK, the
one descriptor flag a test may set, map to os.set_blocking.
"""

import errno
import os

F_GETFL = 3
F_SETFL = 4
O_NONBLOCK = 0o4000


def fcntl(fd, cmd, arg=0):
    """F_GETFL and F_SETFL's O_NONBLOCK; anything else fails with ENOSYS."""
    fd = fd if isinstance(fd, int) else fd.fileno()
    if cmd == F_GETFL:
        return 0 if os.get_blocking(fd) else O_NONBLOCK
    if cmd == F_SETFL:
        os.set_blocking(fd, not arg & O_NONBLOCK)
        return 0
    raise OSError(errno.ENOSYS, f"fcntl({cmd}): Windows has no fcntl")


def ioctl(fd, request, arg=0, mutate_flag=True):  # pylint: disable=unused-argument
    """No device ioctls on Windows."""
    raise OSError(errno.ENOSYS, f"ioctl({request:#x}): Windows has no ioctl")


def flock(fd, operation):  # pylint: disable=unused-argument
    """No advisory file locks."""
    raise OSError(errno.ENOSYS, "flock: Windows has no flock")


def lockf(fd, cmd, len_=0, start=0, whence=0):  # pylint: disable=unused-argument
    """No advisory file locks."""
    raise OSError(errno.ENOSYS, "lockf: Windows has no lockf")
