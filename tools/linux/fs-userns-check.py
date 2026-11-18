# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The verdict of CI's fs step "User-namespace path under an AppArmor
profile (Linux)" (docs/design-fs.md §6.1, row 20): wick-fsd's confined tests
run as the runner's user, an AppArmor profile granting the built wick-fsd
and confine_probe user namespaces, with WICK_FS_TEST_USERNS_GRANTED=1. Each
test binary's whole output is a log; this reads them all and fails when:

- a binary did not end well: no `test result: ok.` (libtest) or
  `confine_probe: N cases ok` line, a `test result: FAILED`, a panic, or the
  step's own `exit status N` line for a binary that exited non-zero;
- a test ran nothing confined (`ran nothing confined`), which under the
  grant means the user-namespace path was refused after all;
- any other `ran nothing` line is not one this step knows. The known ones
  are printed with why each is not a confined test left unconfined.

    python3 -I -B tools/linux/fs-userns-check.py LOG...
    python3 -I -B tools/linux/fs-userns-check.py --selftest
"""

import re
import sys

# The `ran nothing` lines a confined test binary prints under the grant
# that are not a confined test left unconfined, each with why.
KNOWN = [
    (
        "ran nothing: a stand-in for a sysctl is bound over /proc/sys as root",
        "test_the_refusal_names_the_restriction_it_reads binds a stand-in sysctl in a mount namespace and starts "
        "the server as 65534, which needs root; it is a refusal test, and the sudo step runs it",
    ),
    (
        "ran nothing: /proc/<pid>/fd of a server that is not dumpable needs root",
        "test_descriptors_it_was_started_with_are_closed reads the server's descriptors from outside, which a "
        "server that is not dumpable shows to root only; the server served, so its own read-back of its "
        "descriptors held, and the sudo step reads them",
    ),
    (
        "ran nothing: /proc/<pid>/root of a server that is not dumpable needs root",
        "test_outside_open_fails reads another process's /proc/<pid>/root, which a server that is not dumpable "
        "shows to root only; the server itself ran confined, and confine_probe opens the outside path from "
        "inside it",
    ),
    (
        "ran nothing: a server that is not root drops no ids",
        "the id drop is a step of a server started as root (--uid/--gid); the sudo step runs it",
    ),
    (
        "ran nothing for the bind mount: it needs root",
        "test_a_helper_step_that_fails_names_itself checks a test helper's report of its own failed step, not a "
        "confinement; its seccomp case ran, its bind-mount case needs root, and the sudo step runs it",
    ),
    (
        "ran nothing: user namespaces are not restricted here (or this is root)",
        "test_userns_restricted_refused checks the refusal of a restricted host, which the grant lifts; the "
        "Unit tests step runs it restricted",
    ),
]


def verdict(name, text):
    """(failures, notes) for one binary's log `text`."""
    fails, notes = [], []
    lines = text.splitlines()
    for line in lines:
        if "ran nothing confined" in line:
            fails.append(f"{name}: a test ran nothing confined under the grant: {line.strip()}")
        elif "ran nothing" in line:
            why = next((w for k, w in KNOWN if k in line), None)
            if why is None:
                fails.append(f"{name}: a `ran nothing` line this step does not know: {line.strip()}")
            else:
                notes.append(f"{name}: {line.strip()}\n    not a confined test left unconfined: {why}")
        if "panicked" in line or line.startswith("test result: FAILED"):
            fails.append(f"{name}: {line.strip()}")
        m = re.match(r"exit status (\d+)$", line.strip())
        if m:
            fails.append(f"{name}: exited with status {m.group(1)}")
    ok = any(line.startswith("test result: ok.") for line in lines) or any(
        re.match(r"confine_probe: \d+ cases ok$", line.strip()) for line in lines
    )
    if not ok:
        fails.append(f"{name}: no line saying the binary passed (`test result: ok.` or `confine_probe: N cases ok`)")
    return fails, notes


# Lines of CI run 44233741878's step (ubuntu-latest), the server binary
# under the grant, with the line of a test added since, and what
# confine_probe prints there.
SERVER = """running 23 tests
test test_a_guest_s_special_mode_bits_pass_the_filter ... ok
test test_confined_status ... ok
test test_outside_open_fails ... ran nothing: /proc/<pid>/root of a server that is not dumpable needs root (confine_probe checks it)
ok
test test_descriptors_it_was_started_with_are_closed ... ran nothing: /proc/<pid>/fd of a server that is not dumpable needs root (it served, so its own read-back of its descriptors held)
ok
test test_refused_without_id_drop ... ran nothing: a server that is not root drops no ids
ok
test test_the_child_s_id_drop ... ran nothing: a server that is not root drops no ids
ok
test test_userns_restricted_refused ... ran nothing: user namespaces are not restricted here (or this is root)
ok
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.39s
"""
PROBE = """wick-fsd: the confined server was killed by signal 31 (SIGSYS: a system call outside its seccomp list)
case open_by_handle_at: exit 159
case the outside canary by its host path: exit 0
confine_probe: 18 cases ok
"""


def selftest():
    cases = [
        ("the run's server log", SERVER, 0, 5),
        ("confine_probe passing (no libtest lines)", PROBE, 0, 0),
        (
            "confine_probe refused after all",
            "confine_probe: ran nothing confined: kernel.apparmor_restrict_unprivileged_userns = 1 (server.rs checks "
            "the refusal)\n",
            2,
            0,
        ),
        (
            "a confined test refused",
            SERVER.replace(
                "test_confined_status ... ok",
                "test_confined_status ... ran nothing confined: kernel.apparmor_restrict_unprivileged_userns = 1; "
                "refused at its user namespace, as it must: x\nok",
            ),
            1,
            5,
        ),
        ("an unknown ran nothing", SERVER + "test x ... ran nothing: something new\n", 1, 5),
        ("a failed binary", SERVER.replace("test result: ok.", "test result: FAILED.") + "exit status 101\n", 3, 5),
        ("a panic", PROBE + "thread 'main' panicked at x\n", 1, 0),
        ("an empty log", "", 1, 0),
    ]
    bad = 0
    for what, text, nfails, nnotes in cases:
        fails, notes = verdict("t", text)
        if (len(fails), len(notes)) != (nfails, nnotes):
            bad += 1
            print(f"selftest: {what}: {len(fails)} failures, {len(notes)} notes; expected {nfails}, {nnotes}")
            for f in fails:
                print(f"  {f}")
    if bad:
        return 1
    print(f"fs-userns-check: selftest ok ({len(cases)} cases)")
    return 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.strip().splitlines()[-2].strip(), file=sys.stderr)
        return 2
    fails, notes = [], []
    for path in argv:
        name = re.sub(r"^.*userns-|\.log$", "", path)
        with open(path, encoding="utf-8", errors="replace") as f:
            fl, nt = verdict(name, f.read())
        fails += fl
        notes += nt
    for n in notes:
        print(n)
    for f in fails:
        print(f"error: {f}")
    print(f"fs-userns-check: {len(argv)} logs, {len(fails)} failures, {len(notes)} known `ran nothing` lines")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
