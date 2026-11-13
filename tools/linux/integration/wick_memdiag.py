# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The VMM's own memory at its peak, by kind of mapping (informational).

A pytest plugin for upstream's integration tests, loaded only by an
informational run (tools/linux/integration-tests.sh with WICK_IT_MEMDIAG=1,
which passes `-p wick_memdiag`), never by a counted one. Upstream's
MemoryMonitor (tests/host_tools/memory.py) sums the resident size of every
mapping of the Firecracker process but guest memory, and stops sampling at
the first sample over its threshold, so the figure it reports is where the
memory was when it crossed, not its peak. Here the monitor's loop is the
same sum, sample for sample, and its outcome is unchanged (the same first
sample over the threshold is kept, the same figure reported); it goes on
sampling after that, and keeps, for each microVM, the highest sum and what
it was made of:

- binary text / binary data: the Firecracker executable's mappings, read-only
  (its code and constants) or writable (the release build is static, so
  there are no shared libraries); macOS splits its __TEXT and __DATA alike
- heap: [heap] (musl's brk)
- main stack: [stack]
- thread stacks: an anonymous mapping right above a no-access guard mapping
- kvm vcpu: the vCPUs' kvm_run pages (anon_inode:kvm-vcpu)
- anon other: other anonymous mappings (musl's mmapped allocations)
- file other: other file mappings
- vdso: [vdso], [vvar], [vsyscall]

Each microVM appends one JSON line to $WICK_MEMDIAG_OUT, with its number of
vCPUs (a vCPU has a thread, whose stack is among the thread stacks, and a
kvm_run mapping). The macOS harness
reports the same kinds (tools/macos/integration). Run as a program,
`wick_memdiag.py summary FILE` prints a Markdown table of a file.
"""

import json
import os
import sys
import threading
import time

KINDS = (
    "binary text",
    "binary data",
    "heap",
    "main stack",
    "thread stacks",
    "kvm vcpu",
    "anon other",
    "file other",
    "vdso",
)

CAVEAT = (
    "Informational. Linux CI is x86_64 with 4 KiB pages; the macOS figures are "
    "aarch64 with 16 KiB pages and aarch64 code, so the binary's and every touched "
    "page's cost differ by host as well as by Firecracker."
)

_lock = threading.Lock()
_current_test = {"nodeid": None}


def _range(addr):
    start, end = addr.split("-")
    return int(start, 16), int(end, 16)


def classify(maps, exe):
    """KiB per kind of `maps` (psutil memory_maps(grouped=False) entries that
    count: guest memory already left out). Guard mappings (no access) are
    read from `maps` too, before they are dropped as counting nothing."""
    kinds = dict.fromkeys(KINDS, 0)
    guard_ends = set()
    for m in maps:
        if m.perms.startswith("---"):
            guard_ends.add(_range(m.addr)[1])
    for m in maps:
        kib = m.rss // 1024
        path = m.path
        if exe and path == exe:
            kind = "binary data" if "w" in m.perms else "binary text"
        elif path == "[heap]":
            kind = "heap"
        elif path == "[stack]":
            kind = "main stack"
        elif path in ("[vdso]", "[vvar]", "[vsyscall]") or path.startswith("[vvar"):
            kind = "vdso"
        elif "kvm-vcpu" in path:
            kind = "kvm vcpu"
        elif not path:
            kind = "thread stacks" if _range(m.addr)[0] in guard_ends else "anon other"
        else:
            kind = "file other"
        kinds[kind] += kib
    return kinds


def _out_path():
    return os.environ.get("WICK_MEMDIAG_OUT", "../test_results/memory-peaks.jsonl")


def _record(entry):
    with _lock, open(_out_path(), "a", encoding="utf-8") as out:
        out.write(json.dumps(entry) + "\n")


def _run(self):
    """MemoryMonitor.run with the same sum and outcome, sampling on to the
    peak (see the module's description)."""
    import psutil  # pylint: disable=import-outside-toplevel

    guest_mem_bytes = self._vm.mem_size_bytes
    try:
        ps = psutil.Process(self._vm.firecracker_pid)
        exe = ps.exe()
    except (psutil.NoSuchProcess, FileNotFoundError):
        return
    test = _current_test["nodeid"]
    peak, peak_kinds, samples, first_over = 0, None, 0, None
    try:
        while not self._should_stop:
            try:
                mmaps = ps.memory_maps(grouped=False)
            except (psutil.NoSuchProcess, FileNotFoundError):
                break
            counted = [
                m
                for m in mmaps
                if "nitro_enclaves" not in m.path
                and not self.is_guest_mem(m.size, guest_mem_bytes)
            ]
            mem_total = sum(m.rss for m in counted)
            samples += 1
            if self._exceeded is None:
                # Upstream's outcome: the figure and the process of the first
                # sample over the threshold, kept from then on.
                self._current_rss = mem_total
                if mem_total > self.threshold:
                    self._exceeded = ps
                    first_over = mem_total
            if mem_total > peak:
                peak = mem_total
                guards = [m for m in mmaps if m.perms.startswith("---")]
                peak_kinds = classify(counted + guards, exe)
            time.sleep(self._period_s)
    finally:
        _record(
            {
                "test": test,
                "pid": ps.pid,
                "vcpus": getattr(self._vm, "vcpus_count", None),
                "peak_kib": peak // 1024,
                "kinds_kib": peak_kinds,
                "first_over_kib": None if first_over is None else first_over // 1024,
                "threshold_mib": self.threshold / (1 << 20),
                "samples": samples,
                "arch": os.uname().machine,
                "page_size": os.sysconf("SC_PAGE_SIZE"),
            }
        )


def pytest_configure(config):  # pylint: disable=unused-argument
    """Replaces the monitor's loop (upstream's tests/host_tools/memory.py)."""
    from host_tools import memory  # pylint: disable=import-outside-toplevel

    memory.MemoryMonitor.run = _run


def pytest_runtest_setup(item):
    """Names the test the microVMs started from now on belong to."""
    _current_test["nodeid"] = item.nodeid


def summary(path):
    """A Markdown table of the peaks in `path`, one row per microVM."""
    rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    lines = [
        "### The VMM's own memory at its peak, by kind (KiB)",
        "",
        CAVEAT,
        "",
        "| test | vcpus | peak | first over | " + " | ".join(KINDS) + " |",
        "|---|---:|---:|---:|" + "---:|" * len(KINDS),
    ]
    for r in rows:
        kinds = r["kinds_kib"] or {}
        test = (r["test"] or "?").split("::", 1)[-1]
        over = "" if r["first_over_kib"] is None else str(r["first_over_kib"])
        # A record without the count (the macOS harness's) leaves it empty.
        vcpus = "" if r.get("vcpus") is None else str(r["vcpus"])
        lines.append(
            f"| {test} | {vcpus} | {r['peak_kib']} | {over} | "
            + " | ".join(str(kinds.get(k, 0)) for k in KINDS)
            + " |"
        )
    if rows:
        lines += ["", f"{rows[0]['arch']}, page size {rows[0]['page_size']} bytes"]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "summary":
        sys.exit(f"usage: {sys.argv[0]} summary FILE")
    print(summary(sys.argv[2]))
