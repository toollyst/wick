# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Rewrites a file in place without leaving its pages in the buffer cache.

    nocache-copy.py FILE

tools/macos/integration-tests.sh says why. The file keeps its mode and its
code signature (the bytes are the same).
"""

import fcntl
import os
import sys

F_NOCACHE = 48  # <sys/fcntl.h>


def main():
    path = sys.argv[1]
    tmp = path + ".nocache"
    mode = os.stat(path).st_mode & 0o7777
    src = os.open(path, os.O_RDONLY)
    dst = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        fcntl.fcntl(src, F_NOCACHE, 1)
        fcntl.fcntl(dst, F_NOCACHE, 1)
        while True:
            chunk = os.read(src, 1 << 20)
            if not chunk:
                break
            os.write(dst, chunk)
        os.fsync(dst)
    finally:
        os.close(src)
        os.close(dst)
    # The cached pages belong to the old file; a new inode starts uncached.
    os.replace(tmp, path)


if __name__ == "__main__":
    main()
