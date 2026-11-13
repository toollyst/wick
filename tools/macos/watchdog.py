#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Runs a command; if it is still running after LIMIT seconds, prints what
every process it started is doing, then kills them all and fails.

    python3 -I tools/macos/watchdog.py LIMIT [--out DIR] -- COMMAND [ARG...]

For a CI step that can hang: a job cancelled by its timeout keeps no log
(run 43442912128's macos-seatbelt jobs: GitHub had no log for the step at
all), so the step must end itself first, with the evidence in its own
output. LIMIT is well under the job's timeout and well over the step's
usual time.

At the limit it prints, for the command's process tree (its descendants by
parent pid, and the processes of its process group that were reparented):
- `ps` of each: pid, parent, state, elapsed time, command;
- `sample PID 1` of each but cargo's own processes: every thread's stack,
  symbolised (macOS's sample(1); no root needed for one's own processes),
  all sampled at once so that a large tree still fits (the log gets the
  stacks, --out's files the loaded images too);
then SIGKILLs the group and every process listed, and exits 124. With
--out, each sample is also kept as DIR/sample-PID.txt (a CI artifact).
Otherwise it exits with the command's status.
"""

import argparse
import os
import signal
import subprocess
import sys
import time


def processes():
    """{pid: (ppid, pgid, line)} of every process, from ps."""
    out = subprocess.run(
        ["/bin/ps", "-axww", "-o", "pid=,ppid=,pgid=,stat=,etime=,command="],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    procs = {}
    for line in out.splitlines():
        parts = line.split(None, 5)
        if len(parts) >= 5:
            procs[int(parts[0])] = (int(parts[1]), int(parts[2]), line.strip())
    return procs


def tree(root):
    """root and its descendants, and the processes still in root's group."""
    procs = processes()
    children = {}
    for pid, (ppid, _, _) in procs.items():
        children.setdefault(ppid, []).append(pid)
    found, todo = [], [root]
    while todo:
        pid = todo.pop()
        if pid in procs and pid not in found:
            found.append(pid)
            todo.extend(children.get(pid, []))
    found += [pid for pid, (_, pgid, _) in procs.items() if pgid == root and pid not in found]
    return [(pid, procs[pid][2]) for pid in found]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0], usage=__doc__.split("\n")[3].strip())
    ap.add_argument("limit", type=float, help="seconds")
    ap.add_argument("--out", help="a directory for each process's sample")
    argv = sys.argv[1:]
    if "--" not in argv or argv.index("--") == len(argv) - 1:
        ap.error("no command after --")
    args = ap.parse_args(argv[: argv.index("--")])
    command = argv[argv.index("--") + 1 :]

    start = time.monotonic()
    proc = subprocess.Popen(command, start_new_session=True)
    while proc.poll() is None and time.monotonic() - start < args.limit:
        time.sleep(1)
    if proc.poll() is not None:
        return proc.returncode

    found = tree(proc.pid)
    print(f"\n::error::watchdog: still running after {args.limit:.0f} s: {' '.join(command)}", flush=True)
    print(f"watchdog: load {os.getloadavg()}; {len(found)} processes:", flush=True)
    for _, line in found:
        print(f"  {line}", flush=True)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
    samples = {}
    for pid, line in found:
        name = line.split(None, 5)[5] if len(line.split(None, 5)) > 5 else ""
        if os.path.basename(name.split(" ")[0]) in ("cargo", "rustup"):
            continue
        samples[pid] = subprocess.Popen(
            ["/usr/bin/sample", str(pid), "1", "-mayDie"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    for pid, sampler in samples.items():
        try:
            text, _ = sampler.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            sampler.kill()
            text = "sample did not finish in 120 s"
        # The log gets the stacks; the list of loaded images stays in the file.
        print(f"\n===== sample of {pid} =====\n{text.split('Binary Images:')[0]}", flush=True)
        if args.out:
            with open(os.path.join(args.out, f"sample-{pid}.txt"), "w") as f:
                f.write(text)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for pid, _ in found:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.wait()
    return 124


if __name__ == "__main__":
    sys.exit(main())
