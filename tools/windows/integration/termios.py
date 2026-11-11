# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""`termios` for upstream's test framework on Windows, which has none.

Upstream's tests name Linux's terminal ioctls (test_serial_io: TIOCSTI on
Firecracker's terminal). Windows has no tty ioctls: Firecracker's console is
a pipe from the jailer (overlay/jailer/platform/windows/console.rs), and
`fcntl.ioctl` fails naming that (tools/windows/integration/fcntl.py). The
numbers are Linux's.
"""

TIOCSTI = 0x5412
TCGETS, TCSETS = 0x5401, 0x5402
TIOCGWINSZ, TIOCSWINSZ = 0x5413, 0x5414


class error(OSError):  # pylint: disable=invalid-name
    """termios.error."""
