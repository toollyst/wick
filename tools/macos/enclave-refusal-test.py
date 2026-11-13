#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A Nitro Enclave's configuration and start on a host without Nitro Enclaves.

    tools/macos/enclave-refusal-test.py FIRECRACKER

Needs no VM and no guest: it runs FIRECRACKER (its API only) and checks, by
status and fault text, what upstream's Firecracker does on a Linux host
without /dev/nitro_enclaves (src/vmm/src/rpc_interface.rs set_enclave_config
and start_microvm; src/vmm/src/nitro_enclave/enclave_builder.rs
build_and_boot_enclave, which opens the device after checking the
configuration and building the image):

- GET /enclave before any PUT: 400, "Enclave config error: No enclave has
  been configured" (EnclaveConfigError::NotConfigured);
- PUT /enclave before boot: 204, as on any host (the configuration is stored,
  not checked against the host); GET /enclave then returns it;
- InstanceStart: 400, "Start microvm error: Enclave builder error: Failed to
  open /dev/nitro_enclaves: No such file or directory (os error 2)", and the
  process lives on.

The kernel is a file of zeros: building the enclave image reads it, and the
device is opened before anything looks inside. A host with
/dev/nitro_enclaves is refused, not passed: the test is for hosts without it.
Plain Python (no packages), so any host's CI can run it.
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

NE_DEV = "/dev/nitro_enclaves"
NOT_CONFIGURED = "Enclave config error: No enclave has been configured"
NO_DEVICE = (
    "Start microvm error: Enclave builder error: Failed to open /dev/nitro_enclaves: "
    "No such file or directory (os error 2)"
)


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


def request(sock, method, path, body=None):
    """(status, parsed body or None) of one API request."""
    conn = _Connection(sock)
    try:
        payload = None if body is None else json.dumps(body)
        headers = {} if body is None else {"Content-Type": "application/json"}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, (json.loads(data) if data else None)
    finally:
        conn.close()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.split("\n\n")[1])
    firecracker = os.path.abspath(sys.argv[1])
    if os.path.exists(NE_DEV):
        sys.exit(f"FAIL: this host has {NE_DEV}; the test is for hosts without Nitro Enclaves")
    failures = []

    def check(what, got, want):
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} {what}: {got!r}" + ("" if ok else f" (want {want!r})"))
        if not ok:
            failures.append(what)

    with tempfile.TemporaryDirectory() as work:
        sock = os.path.join(work, "api.sock")
        kernel = os.path.join(work, "kernel")
        with open(kernel, "wb") as f:
            f.write(bytes(64 << 10))
        log = open(os.path.join(work, "out"), "wb")  # pylint: disable=consider-using-with
        proc = subprocess.Popen([firecracker, "--api-sock", sock], stdout=log, stderr=subprocess.STDOUT)
        try:
            why = _wait_api(sock, proc)
            if why:
                log.close()
                with open(os.path.join(work, "out"), encoding="utf-8", errors="replace") as f:
                    sys.exit(f"FAIL: {why}: {f.read()[-2000:]}")

            status, body = request(sock, "GET", "/enclave")
            check("GET /enclave before PUT: status", status, 400)
            check("GET /enclave before PUT: fault", (body or {}).get("fault_message"), NOT_CONFIGURED)

            status, _ = request(sock, "PUT", "/boot-source", {"kernel_image_path": kernel})
            check("PUT /boot-source: status", status, 204)
            status, _ = request(sock, "PUT", "/machine-config", {"vcpu_count": 2, "mem_size_mib": 256})
            check("PUT /machine-config: status", status, 204)
            status, _ = request(sock, "PUT", "/enclave", {"debug_mode": True})
            check("PUT /enclave: status", status, 204)
            status, body = request(sock, "GET", "/enclave")
            check("GET /enclave after PUT: status", status, 200)
            check("GET /enclave after PUT: debug_mode", (body or {}).get("debug_mode"), True)

            status, body = request(sock, "PUT", "/actions", {"action_type": "InstanceStart"})
            check("InstanceStart: status", status, 400)
            check("InstanceStart: fault", (body or {}).get("fault_message"), NO_DEVICE)
            check("Firecracker alive after the refused start", proc.poll(), None)
        finally:
            proc.kill()
            proc.wait()
            log.close()
    if failures:
        sys.exit(f"FAIL: {len(failures)} check(s): {', '.join(failures)}")
    print("enclave-refusal-test: all checks passed")


if __name__ == "__main__":
    main()
