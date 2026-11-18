# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Every `static` lock of the compatibility libc's Windows modules, outside
their tests, is one of windows_stacklock.rs's (`ProbedMutex`,
`ProbedRwLock`): a `Mutex` or `RwLock` there would be taken without the
stack probe, which the stack reclaim at the memory limit relies on
(windows_stacklock.rs's module comment).

The same rule as libc's `test_wicks_memory_locks_are_all_probed`, which
runs only where the crate builds, on Windows: this reads the same source
text on any host, so a lock of another kind fails in CI's patches job and
in a landing check, before any Windows build (translate's `MOVE_HOOK`, a
`Mutex` under `cfg(any(test, feature = "wick-test-hooks"))`, first failed
in the windows job). A lock under `#[cfg(test)]` or `#[cfg(all(test, ...))]`
is the tests' own; one under `cfg(any(test, feature = ...))` is not, as it
is built into a build with that feature too.

    python3 -I tools/check-probed-locks.py [--selftest]
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "crates" / "compat" / "libc" / "src"


def unprobed_locks(file: str, text: str) -> list[str]:
    """The `static` locks `text` declares outside its tests that are not
    windows_stacklock.rs's, as `file:line: text` (libc's `unprobed_locks`)."""
    # By lines, which end at "\n" or "\r\n" alike: a checkout may have either.
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    tests = next(
        (i for i in range(len(lines) - 1) if lines[i] == "#[cfg(test)]" and lines[i + 1].startswith("mod tests")),
        len(lines),
    )
    bad = []
    in_test_item = False
    for n, line in enumerate(lines[:tests]):
        t = line.lstrip()
        if t.startswith("#[cfg(test)]") or t.startswith("#[cfg(all(test"):
            in_test_item = True
            continue
        other = t.replace("ProbedMutex<", "").replace("ProbedRwLock<", "")
        declares = (t.startswith("static ") or " static " in t) and ("Mutex<" in other or "RwLock<" in other)
        if declares and not in_test_item:
            bad.append(f"{file}:{n + 1}: {t}")
        if not t.startswith("#["):
            in_test_item = False
    return bad


def selftest() -> None:
    for case in [
        "static T: OnceLock<Mutex<HashMap<c_int, Entry>>> = OnceLock::new();",
        "    static L: std::sync::RwLock<u8> = std::sync::RwLock::new(0);",
        "pub(crate) static M: Mutex<()> = Mutex::new(());",
        # Built with a feature too: not the tests' own.
        '#[cfg(any(test, feature = "wick-test-hooks"))]\n'
        "pub(crate) static MOVE_HOOK: std::sync::Mutex<Option<fn()>> = std::sync::Mutex::new(None);",
    ]:
        assert len(unprobed_locks("case", case)) == 1, case
    assert not unprobed_locks("case", "static T: OnceLock<ProbedMutex<HashMap<c_int, Entry>>> = OnceLock::new();")
    assert not unprobed_locks("case", "#[cfg(test)]\nstatic M: Mutex<()> = Mutex::new(());")
    assert not unprobed_locks("case", "#[cfg(all(test, windows))]\nstatic M: Mutex<()> = Mutex::new(());")
    assert not unprobed_locks("case", "static H: AtomicUsize = AtomicUsize::new(0);")
    lf = "static A: Mutex<()> = Mutex::new(());\n\n#[cfg(test)]\nmod tests {\n    static B: Mutex<()> = Mutex::new(());\n}\n"
    assert unprobed_locks("lf", lf) == ["lf:1: static A: Mutex<()> = Mutex::new(());"]
    assert unprobed_locks("crlf", lf.replace("\n", "\r\n")) == ["crlf:1: static A: Mutex<()> = Mutex::new(());"]
    print("check-probed-locks: selftest passed")


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return 0
    if sys.argv[1:]:
        sys.exit("usage: check-probed-locks.py [--selftest]")
    files = sorted(SRC.glob("windows_*.rs"))
    if not files:
        sys.exit(f"check-probed-locks: no windows_*.rs in {SRC}")
    bad = [b for f in files for b in unprobed_locks(f.name, f.read_text(encoding="utf-8"))]
    for b in bad:
        print(f"error: a lock taken without the stack probe: {b}")
    print(f"check-probed-locks: {len(files)} modules, {len(bad)} errors")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
