#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A request in flight when the VMM ends: Firecracker answers it and exits
with the VMM's own error and exit code (patches/0050).

    tools/macos/api-vmm-ended-test.py FIRECRACKER

Needs no VM and no guest, on any host with FIFOs (CI runs it on Linux and
macOS). It starts FIRECRACKER with an API socket and a configuration file
whose root drive is a FIFO, so the build waits in the drive's open until a
writer comes. A client sends GET / meanwhile; once Firecracker's log says
the API thread received it (and has handed it to the VMM, which is busy
building), the test opens the FIFO, and the build goes on and fails: a
FIFO is no drive (upstream's block device seeks it, "Illegal seek"). The
VMM's ends of the API channels go with the failed build, before the kill
switch ends the API thread (upstream's src/firecracker/src/api_server_adapter.rs
run_with_api, v1.18.0 :252 to :273).

Checked: the client's answer is 500 with the patch's fault message;
Firecracker exits 1, the build's error (main.rs: RunWithApi is a generic
error), with "Error: RunWithApi(BuildFromJson(" on standard error and
"Firecracker exiting with error. exit_code=1" in its log; nothing
panicked. Upstream's Firecracker panics in the API thread there ("VMM
disconnected", api_server/mod.rs :225) and, built with panic=abort, ends
with SIGABRT before main prints why. Deterministic: the drive holds the
build until the request is in the VMM's channel. Plain Python (no
packages).
"""

import os
import socket
import subprocess
import sys
import tempfile
import threading

FAULT = "The VMM has ended and Firecracker is exiting; its log and standard error say why."
BOUND = 30


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    firecracker = sys.argv[1]
    # A short directory: the API socket's path must fit sun_path.
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="wick-ave-") as tmp:
        sock = os.path.join(tmp, "api.sock")
        fifo = os.path.join(tmp, "drive.fifo")
        kernel = os.path.join(tmp, "kernel")
        os.mkfifo(fifo)
        with open(kernel, "wb") as f:
            f.write(bytes(4096))
        config = os.path.join(tmp, "config.json")
        with open(config, "w") as f:
            f.write(
                '{"boot-source": {"kernel_image_path": "%s"}, '
                '"drives": [{"drive_id": "rootfs", "path_on_host": "%s", '
                '"is_root_device": true, "is_read_only": true}], '
                '"machine-config": {"vcpu_count": 1, "mem_size_mib": 128}}' % (kernel, fifo)
            )
        proc = subprocess.Popen(
            [firecracker, "--api-sock", sock, "--config-file", config],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        timed_out = []

        def bound():
            timed_out.append(True)
            proc.kill()

        timer = threading.Timer(BOUND, bound)
        timer.start()
        answer = []

        def client():
            # Connects once the socket is bound and listening; the GET then
            # waits in the API thread for the VMM.
            while proc.poll() is None:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    s.connect(sock)
                except OSError:
                    s.close()
                    continue
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data and FAULT.encode() in data:
                        break
                s.close()
                answer.append(data.decode(errors="replace"))
                return

        errs = []
        err_reader = threading.Thread(target=lambda: errs.append(proc.stderr.read().decode(errors="replace")))
        err_reader.start()
        client_thread = threading.Thread(target=client)
        client_thread.start()
        log = []
        released = False
        for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip("\n")
            log.append(line)
            if not released and 'received a Get request on "/"' in line:
                # The build goes on, and fails at the drive.
                os.close(os.open(fifo, os.O_WRONLY))
                released = True
        proc.wait()
        timer.cancel()
        client_thread.join(BOUND)
        err_reader.join(BOUND)
        log_text = "\n".join(log)
        err_text = errs[0] if errs else ""
        everything = f"exit {proc.returncode}\n--- log\n{log_text}\n--- stderr\n{err_text}\n--- answer\n{answer}"
        failures = []
        if timed_out:
            failures.append(f"Firecracker did not end within {BOUND} s")
        if not released:
            failures.append("the API thread never logged the GET")
        if not answer or not answer[0].startswith("HTTP/1.1 500") or FAULT not in answer[0]:
            failures.append("the client did not get the 500 with the fault message")
        if proc.returncode != 1:
            failures.append(f"exit {proc.returncode}, not the build error's 1")
        if "Error: RunWithApi(BuildFromJson(" not in err_text:
            failures.append("standard error does not give the build's error")
        if "Firecracker exiting with error. exit_code=1" not in log_text:
            failures.append("the log does not end with exit_code=1")
        if "panicked" in log_text or "panicked" in err_text:
            failures.append("Firecracker panicked")
        if failures:
            print("FAIL: " + "; ".join(failures) + "\n" + everything)
            sys.exit(1)
        print("PASS: the request in flight got 500 with the fault message; Firecracker exited 1 with "
              "the build's error on standard error, and nothing panicked")


if __name__ == "__main__":
    main()
