#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The results of one test binary's run, as libtest's own process gave them.

    python3 -I tools/libtest-results.py --selftest

A test that runs its own test binary again as a child (the API process, the
sandbox's and the jail's children) can have the child's libtest lines in the
same output, between the parent's "test <name> ... " and its result: on
Windows the child writes to the same console (CI run 43881982686, where the
child's "api_process_child ... ok" came after the parent's "... ignored" for
that name, and the parent's own result for the test that ran it was in no
line); on macOS a failed parent prints the child's output in its failure
message (CI run 43897069273: the child's "endpoint_netns_drop_child ...
FAILED" and its own "test result:" line). Read line by line, a child's lines
stand for the parent's. So, within one binary's section:

- the first result of a name is the parent's (a child's comes after the
  parent began that test);
- a name in the parent's failures list, the one just before the section's
  last "test result:" line, failed, whatever a line said;
- a test the parent began with no result of its own passed, when that and the
  rest add up to the counts of that last "test result:" line;
- if they do not add up, the section is a named problem: its results cannot
  be told from what was written, and a test begun with no result of its own
  is left with none (the caller's "started, no result");
- a result word at the end of a begun line, after the test's own output
  ("test x ... printed ok", a word apart: "... a book" is none), is the
  test's, except on the last test line of a
  section with no "test result:" line (the process ended): there it may be
  the test's own output when the process died, so that test is left with
  none.

Used by tools/linux/compare-unit-tests.py (and so tools/ci-results.py) and
tools/macos/check-unit-tests.py; loaded by path (importlib), as the tools load
each other.
"""

import re
import sys

RESULT = re.compile(r"^test (.+?)(?: - should panic)? \.\.\. (ok|FAILED|ignored(?:, .*)?)$")
STARTED = re.compile(r"^test (.+?)(?: - should panic)? \.\.\. ?(.*)$")
# libtest's result word ends the line, after anything a test wrote to the
# terminal itself ("test x ... printed by the test ok"); a word, not the end of
# one: "test x ... a book" is no result. A result glued to a test's output
# ("HHok") is then read as none, and the test as begun; no CI log of this
# repository has one (job 133046993494's Linux unit log: the four begun lines
# with output end in "Hello, world!", their "ok" on a line of its own).
LATE_RESULT = re.compile(r"(?<![A-Za-z0-9_])(ok|FAILED|ignored(?:, .*)?)$")
SUMMARY = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def section_results(lines, name=lambda n: n):
    """({test: ok|FAILED|ignored}, (passed, failed, ignored) or None, problem
    or None) of one binary's section `lines`, the parent's (module doc).
    `name` maps libtest's name to the caller's (a doc test's line number)."""
    # Each of libtest's names mapped once: a child's repeat of a line is the
    # same test, and `name` may number what it has seen.
    mapped = {}

    def nm(raw):
        if raw not in mapped:
            mapped[raw] = name(raw)
        return mapped[raw]

    found = {}
    begun = []
    # The name whose result came late on the last test line read, if any.
    last_late = None
    for line in lines:
        m = RESULT.match(line)
        if m:
            found.setdefault(nm(m.group(1)), m.group(2).split(",")[0])
            last_late = None
            continue
        m = STARTED.match(line)
        if m:
            n = nm(m.group(1))
            late = LATE_RESULT.search(m.group(2))
            last_late = None
            if late:
                if n not in found:
                    found[n] = late.group(1).split(",")[0]
                    last_late = n
            else:
                begun.append(n)
    last = max((i for i, line in enumerate(lines) if SUMMARY.match(line)), default=None)
    if last is None:
        if last_late is not None:
            del found[last_late]
        return found, None, None
    # The parent's failures: "failures:", one indented name a line, a blank
    # line, then its summary.
    i = last - 1
    while i >= 0 and not lines[i].strip():
        i -= 1
    names = []
    while i >= 0 and lines[i].startswith("    ") and lines[i].strip():
        names.append(lines[i].strip())
        i -= 1
    if i >= 0 and lines[i].strip() == "failures:":
        for n in names:
            found[nm(n)] = "FAILED"
    counts = tuple(int(x) for x in SUMMARY.match(lines[last]).groups())
    passed = [n for n in begun if n not in found]
    n = {"ok": len(passed), "FAILED": 0, "ignored": 0}
    for r in found.values():
        n[r] += 1
    if (n["ok"], n["FAILED"], n["ignored"]) != counts:
        # The tests begun with no result of their own are left without one.
        return found, counts, (f"libtest counted {counts[0]} passed, {counts[1]} failed, {counts[2]} ignored, "
                               f"its lines {n['ok']}, {n['FAILED']}, {n['ignored']}")
    for t in passed:
        found[t] = "ok"
    return found, counts, None


def selftest():
    def run(text):
        return section_results(text.splitlines())

    plain = ("running 3 tests\ntest a::x ... ok\ntest a::y ... ignored, why\ntest a::z ... FAILED\n\n"
             "failures:\n\n---- a::z stdout ----\nboom\n\nfailures:\n    a::z\n\n"
             "test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
    assert run(plain) == ({"a::x": "ok", "a::y": "ignored", "a::z": "FAILED"}, (1, 1, 1), None), run(plain)
    # Windows: the child's lines in the same console. The parent listed the
    # child ignored; the parent's own result for the test that ran it is in
    # no line.
    child = ("running 3 tests\ntest a::api_child ... ignored\ntest a::test_serves ... \nrunning 1 test\n"
             "test a::api_child ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
             "2 filtered out; finished in 0.10s\n\ntest a::z ... ok\n\n"
             "test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s\n")
    assert run(child) == ({"a::api_child": "ignored", "a::test_serves": "ok", "a::z": "ok"}, (2, 0, 1), None), \
        run(child)
    # A test that runs itself as its child: the child's "ok" is the only
    # line of the name, and the parent's FAILED is in its failures list.
    itself = ("running 2 tests\ntest a::test_t ... \nrunning 1 test\ntest a::test_t ... ok\n\n"
              "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.10s\n\n"
              "test a::z ... ok\n\nfailures:\n\n---- a::test_t stdout ----\nthe child said ok\n\n"
              "failures:\n    a::test_t\n\n"
              "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s\n")
    assert run(itself) == ({"a::test_t": "FAILED", "a::z": "ok"}, (1, 1, 0), None), run(itself)
    # macOS: a failed parent prints its child's output, the child's failure
    # list and summary included, in its failure message.
    message = ("running 2 tests\ntest a::drop_child ... ignored, run by a::test_drop\ntest a::test_drop ... FAILED\n\n"
               "failures:\n\n---- a::test_drop stdout ----\nstdout:\nrunning 1 test\ntest a::drop_child ... FAILED\n\n"
               "failures:\n\n---- a::drop_child stdout ----\nboom\n\nfailures:\n    a::drop_child\n\n"
               "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n\n"
               "\nfailures:\n    a::test_drop\n\n"
               "test result: FAILED. 0 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s\n")
    assert run(message) == ({"a::drop_child": "ignored", "a::test_drop": "FAILED"}, (0, 1, 1), None), run(message)
    # A result after the test's own output, on its line.
    late = ("running 1 test\ntest a::w ... printed by the test ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
    assert run(late) == ({"a::w": "ok"}, (1, 0, 0), None), run(late)
    # The process ended in the last test, whose own output ended in a result
    # word: no summary, so that word is not taken; an earlier late one is.
    died = "running 3 tests\ntest a::v ... printed ok\ntest a::w ... ok\ntest a::x ... the child said ok\n"
    assert run(died) == ({"a::v": "ok", "a::w": "ok"}, None, None), run(died)
    # A result word is a word: "a book" ends in no result, so the test is
    # only begun, and in a section with no summary it keeps none.
    book = "running 2 tests\ntest a::b ... read a book\ntest a::c ... ok\n"
    assert run(book) == ({"a::c": "ok"}, None, None), run(book)
    # Lines that do not add up to the counts: a problem, with both counts.
    lost = "running 3 tests\ntest b::y ... ok\ntest b::v ... \n\ntest result: ok. 3 passed; 0 failed; 0 ignored;\n"
    assert run(lost) == ({"b::y": "ok"}, (3, 0, 0), "libtest counted 3 passed, 0 failed, 0 ignored, its lines 2, 0, 0"), \
        run(lost)
    print("libtest-results: selftest ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        selftest()
    else:
        sys.exit(__doc__.split("\n\n")[1])
