#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A Nitro Enclave's configuration and start on Windows.

    python -I tools/windows/enclave-refusal-test.py FIRECRACKER.EXE

Runs tools/macos/enclave-refusal-test.py unchanged, with the same checks
in the same order, through the AF_UNIX sockets of
tools/windows/integration/wick_windows_unix.py (CPython's Windows build
cannot connect an AF_UNIX socket to a path). Needs no WHP: only the API
before a boot.

Firecracker drives an enclave only through Linux's nitro_enclaves driver,
by ioctls on /dev/nitro_enclaves (src/vmm/src/nitro_enclave). Windows has
no such device: the start opens that path as Linux's does and is refused
in the same place, with the same message up to the host's error. Where
Linux says "No such file or directory (os error 2)" (ENOENT), Windows
gives its error for a path whose directory \\dev does not exist on the
drive: "The system cannot find the path specified. (os error 3)"
(ERROR_PATH_NOT_FOUND).
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "integration"))

import wick_windows_unix  # pylint: disable=wrong-import-position

NO_DEVICE = (
    "Start microvm error: Enclave builder error: Failed to open /dev/nitro_enclaves: "
    "The system cannot find the path specified. (os error 3)"
)


class _TemporaryDirectory(tempfile.TemporaryDirectory):
    """A temporary directory removed when Firecracker is entirely gone.

    Firecracker's API server runs in a second process on Windows
    (vmm/ext/api_process.rs), which inherits the output file and exits when it
    reads the end of its link to Firecracker. That is 20 to 40 ms after
    Firecracker is killed and waited for (measured on Windows Server 2022, 5
    runs). On Linux the API thread dies with the process. The removal retries
    for 2 s, then fails as before."""

    def cleanup(self):
        self._finalizer.detach()
        deadline = time.monotonic() + 2
        while True:
            try:
                shutil.rmtree(self.name)
                return
            except PermissionError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)


def main():
    wick_windows_unix.install()
    path = os.path.join(HERE, "..", "macos", "enclave-refusal-test.py")
    spec = importlib.util.spec_from_file_location("enclave_refusal_test", path)
    test = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(test)
    # Windows' text for the missing device, measured; every other check is
    # the Linux one.
    test.NO_DEVICE = NO_DEVICE
    test.tempfile.TemporaryDirectory = _TemporaryDirectory
    test.main()


if __name__ == "__main__":
    main()
