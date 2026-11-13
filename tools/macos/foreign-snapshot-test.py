#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A snapshot state file made on another host OS and architecture is refused.

    tools/macos/foreign-snapshot-test.py FIRECRACKER SNAPSHOT_EDITOR STATE

STATE is a snapshot's state file made by Firecracker on another host: CI's
linux-boot job makes one on Linux x86_64 with the same commit's build
(tools/linux/make-vmstate.py, the artifact linux-vmstate), and the macOS
job runs this test on it. On an aarch64 host such a state cannot be
restored, on Linux either: a state is the registers and devices of one
architecture. What is checked is how it is refused:

- PUT /snapshot/load: 400, upstream's error for a state file it cannot
  decode (src/vmm/src/persist.rs snapshot_state_from_file: the file is
  decoded, and its magic and version checked, before anything is built);
- Firecracker then exits with a status of its own, not by a signal, as
  after any failed load;
- snapshot-editor info-vmstate version refuses the file too.

Needs no VM and no guest (the refusal comes before a VM is made), so it
runs where Hypervisor.framework is missing. An aarch64 state made on Linux
is a different question (it could restore): not tested until there is an
aarch64 Linux host to make one.
Plain Python (no packages).
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

REFUSED = ("Load snapshot error: Failed to restore from snapshot: Failed to get snapshot state from file: "
           "Failed to load snapshot state from file: ")


class _Connection(http.client.HTTPConnection):
    """HTTP over Firecracker's API socket."""

    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        self.sock.connect(self._path)


def _wait_api(sock, proc, bound=10):
    """Waits until Firecracker's API answers a GET / with 200; returns None
    then, else why it did not. The socket's path does not say the API is
    there: the path exists from bind(2), the server accepts from listen(2),
    a connection in between is refused, and a Firecracker that ended leaves
    the path behind. This is its own step before the test's first request,
    which is made once. The process is looked at before every attempt."""
    start, last = time.monotonic(), "none made"
    while True:
        if proc.poll() is not None:
            return f"Firecracker ended (exit {proc.returncode}) before its API answered; last attempt: {last}"
        if time.monotonic() - start > bound:
            return f"no answer within {bound} s; last attempt: {last}"
        conn = _Connection(sock)
        try:
            conn.request("GET", "/")
            status = conn.getresponse().status
            return None if status == 200 else f"GET / -> {status}"
        except (FileNotFoundError, ConnectionRefusedError) as e:
            last = type(e).__name__
        except (OSError, http.client.HTTPException) as e:
            return f"GET /: {e!r}"
        finally:
            conn.close()
        time.sleep(0.02)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.split("\n\n")[1])
    firecracker, editor, state = (os.path.abspath(a) for a in sys.argv[1:])
    if not os.path.isfile(state) or os.path.getsize(state) == 0:
        sys.exit(f"FAIL: {state} is not a state file")
    failures = []

    def check(what, ok, got):
        print(f"{'ok  ' if ok else 'FAIL'} {what}: {got}")
        if not ok:
            failures.append(what)

    with tempfile.TemporaryDirectory(dir="/tmp") as work:
        sock = os.path.join(work, "api.sock")
        out_path = os.path.join(work, "out")
        with open(out_path, "wb") as log:
            proc = subprocess.Popen([firecracker, "--api-sock", sock], stdout=log, stderr=subprocess.STDOUT)
            try:
                why = _wait_api(sock, proc)
                if why:
                    with open(out_path, encoding="utf-8", errors="replace") as f:
                        sys.exit(f"FAIL: {why}: {f.read()[-2000:]}")
                conn = _Connection(sock)
                body = {"snapshot_path": state,
                        "mem_backend": {"backend_type": "File", "backend_path": os.path.join(work, "none.mem")}}
                conn.request("PUT", "/snapshot/load", json.dumps(body), {"Content-Type": "application/json"})
                resp = conn.getresponse()
                fault = (json.loads(resp.read() or b"{}")).get("fault_message", "")
                conn.close()
                check("PUT /snapshot/load: status", resp.status == 400, resp.status)
                check("PUT /snapshot/load: upstream's error for a state it cannot decode",
                      fault.startswith(REFUSED), repr(fault))
                try:
                    code = proc.wait(10)
                except subprocess.TimeoutExpired:
                    code = None
                # A status of its own: not still running, not 0, not a signal.
                check("Firecracker exits after the refused load", code is not None and code > 0, code)
            finally:
                proc.kill()
                proc.wait()
        r = subprocess.run([editor, "info-vmstate", "version", "--vmstate-path", state], capture_output=True,
                           text=True)
        check("snapshot-editor info-vmstate version refuses it", r.returncode > 0,
              f"{r.returncode} {(r.stdout + r.stderr).strip()[-300:]!r}")
    if failures:
        sys.exit(f"FAIL: {len(failures)} check(s): {', '.join(failures)}")
    print(f"foreign-snapshot-test: {os.path.basename(state)} ({os.path.getsize(state)} bytes) refused: "
          f"{fault[len(REFUSED):]}")


if __name__ == "__main__":
    main()
