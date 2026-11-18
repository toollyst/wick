#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""wick-fsd's macOS profile lists against what a confined server asks the
kernel for while it serves the request tests (docs/design-fs.md §6.2).

    tools/macos/fs-server-report.py [--runs N] [--out FILE]    (default 3 runs)

Builds crates/fs with `--cfg wick_fsd_discovery` into a target directory of
its own (build/fs-discovery; the only place that sets the cfg, which
tools/check-tree.py holds). In that build `confine::macos::profile()` itself
ends with rules that allow and report what no list names, after the same
lists, so the profile measured is the product's with its kill actions
answered by a report instead; the server says each request it serves on
stderr with the time, and makes one control call no list names (task_info)
once confined. Then it runs the tests that serve requests from a confined
server (requests: every request kind, the error paths, 64 READs of 1 MiB, a
directory of 3000 entries; links; corpus; connection) N times, and reads
Seatbelt's reports of each server (`/usr/bin/log show`).

It prints the macOS build (sw_vers, the libraries' versions from the dyld
cache) and, over the runs, each call or operation reported that no list
names, with how many runs reported it, the tests and the requests in flight
(the server's last request before the report, by the time). Exits 1 if
there is any such line, if a test failed, if a test's servers were measured
in no run (their control's report not in the log in any: reports are lost,
so each test needs one run in which its server's control was reported),
or if no server ran.

Seatbelt's reports are lossy (docs/design-fs.md §6.2: lines are dropped as
the rate grows), and a listed call or an unfiltered one is never reported:
an empty union shows what the runs reached, not that the lists are complete.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
FS = ROOT / "crates" / "fs"
TARGET = ROOT / "build" / "fs-discovery"
# start.rs for its check that this build says it is a discovery build.
TESTS = ["requests", "links", "corpus", "connection", "start"]
LIBRARIES = ["libsystem_c", "libsystem_malloc", "libsystem_kernel", "libsystem_pthread", "libdyld"]
REPORT = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+).*?(?:(\d+) duplicate reports? for )?Sandbox: wick-fsd\((\d+)\) allow (.+)$"
)
SAID = re.compile(r"^wick-fsd: discovery: (.+) at (\d+)$")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def build_on_record():
    """The macOS build and the libraries' versions, as lines."""
    lines = []
    sw = run(["/usr/bin/sw_vers"]).stdout.split()
    lines.append("macOS: " + " ".join(sw))
    m = run(["/usr/sbin/sysctl", "-n", "hw.machine", "hw.memsize", "kern.osversion"]).stdout.split()
    lines.append("hw.machine, hw.memsize, kern.osversion: " + ", ".join(m))
    for lib in LIBRARIES:
        out = run(["dyld_info", "-load_commands", f"/usr/lib/system/{lib}.dylib"]).stdout
        v = re.search(r"cur-vers: (\S+)", out)
        lines.append(f"{lib}: {v.group(1) if v else 'not read (dyld_info)'}")
    return lines


def environment():
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(TARGET)
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " --cfg wick_fsd_discovery").strip()
    return env


def at_of(stamp):
    """The unified log's local time as microseconds since the epoch."""
    t = datetime.datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
    return int(time.mktime(t.timetuple())) * 1_000_000 + t.microsecond


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--out")
    ap.add_argument("--keep", help="a directory to keep each run's server pids and stderr in")
    a = ap.parse_args()
    out = []

    def say(line=""):
        print(line, flush=True)
        out.append(line)

    for line in build_on_record():
        say(line)
    env = environment()
    built = run(["cargo", "test", "--locked", "-p", "wick-fsd", "--no-run"] + sum((["--test", t] for t in TESTS), []),
                cwd=FS, env=env)
    if built.returncode != 0:
        say(built.stderr[-4000:])
        sys.exit("fs-server-report: the discovery build failed")
    version = run([str(TARGET / "debug" / "wick-fsd"), "--version"]).stdout.strip()
    say(f"the server built: {version}")
    if "discovery build" not in version:
        sys.exit("fs-server-report: the server built does not say it is a discovery build")
    start = run(["/bin/date", "+%Y-%m-%d %H:%M:%S"]).stdout.strip()
    servers = {}  # pid -> (run, test, [(at, what)]), each server confined
    refused = 0  # servers refused before the profile (connection.rs's wrong peer)
    failed = []
    with tempfile.TemporaryDirectory(prefix="wick-fs-report-") as scratch:
        tmp = a.keep or scratch
        Path(tmp).mkdir(parents=True, exist_ok=True)
        for n in range(1, a.runs + 1):
            d = Path(tmp) / f"run-{n}"
            d.mkdir()
            e = dict(env, WICK_FS_REPORT_DIR=str(d))
            # One test at a time, so that a report lost is one server's.
            # Measured here (macOS 27.2): the reports of the servers of the
            # first run's first seconds (about 9 s: connection, corpus and
            # links) were not in the log in 6 of 6 runs of this script, with
            # or without a pause or the test binaries started before; the
            # rest of the first run's and every later run's were. The cause
            # is not known; the control says which servers were measured.
            # The 20000 SETATTRs' test is left out: 5 ms a request would make
            # it 100 s, and every_request makes the same request.
            t = run(["cargo", "test", "--locked", "-p", "wick-fsd"] + sum((["--test", x] for x in TESTS), [])
                    + ["--", "--test-threads=1", "--skip", "test_a_confined_server_sets_times_to_now_again_and_again"],
                    cwd=FS, env=e)
            results = [l for l in t.stdout.splitlines() if l.startswith("test result") or " FAILED" in l]
            say(f"run {n}: exit {t.returncode}; " + "; ".join(results))
            if t.returncode != 0:
                failed.append(n)
                say(t.stdout[-3000:])
                say(t.stderr[-3000:])
            pids = (d / "pids").read_text().split("\n") if (d / "pids").exists() else []
            for line in filter(None, pids):
                pid, test = line.split(" ", 1)
                said = []
                f = d / f"{pid}.stderr"
                text = f.read_text(errors="replace") if f.exists() else ""
                if ": confined (Seatbelt profile" not in text:
                    refused += 1
                    continue
                for l in text.splitlines():
                    m = SAID.match(l)
                    if m:
                        said.append((int(m.group(2)), m.group(1)))
                servers[int(pid)] = (n, test, said)
        # The kernel writes its reports a moment later.
        time.sleep(10)
        log = run(["/usr/bin/log", "show", "--start", start, "--style", "compact", "--predicate", 'sender == "Sandbox"']).stdout
    # Each confined server's reports, in the log's order: (time, what).
    reports = {}
    for line in log.splitlines():
        m = REPORT.match(line)
        if m and int(m.group(3)) in servers:
            reports.setdefault(int(m.group(3)), []).append((at_of(m.group(1)), m.group(4).strip()))
    union = {}  # what -> {"runs": set, "tests": set, "requests": set}
    controls = set()
    for pid, seen in reports.items():
        n, test, said = servers[pid]
        # The control: the server's first MIG report, made right after it
        # said "control task_info". The log's clock and the server's differ
        # by some milliseconds (measured: the report 3 ms before the time
        # the server read just before the call), so the difference at the
        # control is the server's offset, applied to its other reports.
        control = next((i for i, (_, w) in enumerate(seen) if w.startswith("syscall-mig ")), None)
        said_control = next((t for t, w in said if w == "control task_info"), None)
        if control is None or said_control is None:
            offset = 0
        else:
            controls.add(pid)
            offset = seen[control][0] - said_control
        for i, (at, what) in enumerate(seen):
            if i == control:
                continue
            # On the log's clock, what the server said in the 4 ms before
            # the report's millisecond and in it, or else the last thing
            # before: a report's time moves by a few milliseconds against
            # the call (measured: by one request, 3 ms apart, in one of two
            # runs), so the request in flight is one of these.
            near = [w for t, w in said if at - 4000 <= t + offset <= at + 999]
            if not near:
                near = [w for t, w in said if t + offset < at - 4000][-1:] or ["before its first line"]
            names = {"start": "before the control (confining)", "control task_info": "after the control"}
            in_flight = " or ".join(dict.fromkeys(names.get(w, w) for w in near))
            u = union.setdefault(what, {"runs": set(), "tests": set(), "requests": set()})
            u["runs"].add(n)
            u["tests"].add(test)
            u["requests"].add(in_flight)
    say(f"confined servers: {len(servers)} over {a.runs} runs (and {refused} refused before the profile); "
        f"their control reported by {len(controls)}")
    # A server whose control is not in the log was not measured (its
    # reports lost); every test must be measured in at least one run.
    no_control = sorted(p for p in servers if p not in controls)
    if no_control:
        say(f"not measured, their control not reported: "
            f"{', '.join(f'{p} ({servers[p][1]}, run {servers[p][0]})' for p in no_control)}")
    for n in range(1, a.runs + 1):
        ran = [p for p in servers if servers[p][0] == n]
        lost = [p for p in ran if p not in controls]
        say(f"run {n}: {len(ran) - len(lost)} of {len(ran)} servers measured" + (f", lost: {len(lost)}" if lost else ""))
    tests = {t for _, t, _ in servers.values()}
    measured = {servers[p][1] for p in controls}
    never = sorted(tests - measured)
    say(f"tests measured in at least one run: {len(measured)} of {len(tests)}")
    if union:
        say(f"unlisted, the union over {a.runs} runs:")
        for what, u in sorted(union.items()):
            say(f"  allow {what}: {len(u['runs'])} of {a.runs} runs; tests {sorted(u['tests'])}; "
                f"in flight {sorted(u['requests'])}")
    else:
        say(f"unlisted, the union over {a.runs} runs: nothing")
    if a.out:
        Path(a.out).write_text("\n".join(out) + "\n")
    bad = []
    if failed:
        bad.append(f"tests failed in runs {failed}")
    if not servers:
        bad.append("no confined server ran")
    if never:
        bad.append(f"tests measured in no run (their control never reported): {never}")
    if union:
        bad.append(f"{len(union)} unlisted")
    if bad:
        sys.exit("fs-server-report: " + "; ".join(bad))
    print("fs-server-report: ok")


if __name__ == "__main__":
    main()
