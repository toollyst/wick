# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Linux host tools upstream's framework runs, on Windows.

procps (`ps`, `pgrep`, `pidof`): Linux's reads /proc; Git for Windows's
`ps` lists MSYS processes only, with options of its own. These are the
forms upstream's tests use, on Windows's processes and threads (psutil; a
thread's name is the description Rust's std gives it, SetThreadDescription):

    ps ax --no-headers -o pid,cmd -ww
    ps -T --no-headers -p PID          (PID SPID TTY TIME CMD per thread)
    pgrep NAME
    pidof NAME

`dmesg`: Windows's System log (below).

e2fsprogs (`mkfs.ext4`, `resize2fs`, `e2fsck`, `fsck.ext4`, `debugfs`),
util-linux's `sfdisk` and `blkid`, and `gcc` (upstream builds small static
Linux programs on the host and copies them into the guest: vsock_helper.c,
vmclock.c, ...): Windows has no tool that writes ext4 or a Linux partition
table on an image file, or that builds a Linux binary; these are the Linux
tools, run in
the WSL distribution the artifacts were prepared with (WICK_IT_WSL,
tools/windows/integration/setup-artifacts.ps1), on the same file
(C:\\x -> /mnt/c/x).

    python hosttools.py TOOL ARGS...
"""

import ctypes
import os
import pathlib
import re
import subprocess
import sys
from ctypes import wintypes

import psutil

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenThread.restype = wintypes.HANDLE
_k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.GetThreadDescription.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.LocalFree.argtypes = [ctypes.c_void_p]
THREAD_QUERY_LIMITED_INFORMATION = 0x800


def _name(p):
    """The name Linux gives a process: its executable's, without `.exe`."""
    try:
        name = p.name()
    except psutil.Error:
        return ""
    return name[:-4] if name.lower().endswith(".exe") else name


def thread_name(tid):
    """A thread's name (its description), or "" if it has none."""
    h = _k32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
    if not h:
        return ""
    try:
        text = ctypes.c_wchar_p()
        if _k32.GetThreadDescription(h, ctypes.byref(text)) < 0:
            return ""
        value = text.value or ""
        _k32.LocalFree(text)
        return value
    finally:
        _k32.CloseHandle(h)


def _cmdline(p):
    """A process's command line on one line, as procps prints it (a Windows
    command line may hold line breaks), or its name in brackets."""
    try:
        cmd = " ".join(p.cmdline())
    except psutil.Error:
        cmd = ""
    cmd = " ".join(cmd.split())
    return cmd or f"[{_name(p) or '?'}]"


def ps(args):
    """The two `ps` forms above."""
    headers = "--no-headers" not in args
    if "-T" in args:
        pid = int(args[args.index("-p") + 1])
        try:
            proc = psutil.Process(pid)
            threads = proc.threads()
        except psutil.Error:
            return 1
        if headers:
            print("    PID    SPID TTY          TIME CMD")
        main = _name(proc)
        for t in threads:
            name = thread_name(t.id) or main
            secs = int(t.user_time + t.system_time)
            print(f"{pid:7d} {t.id:7d} ?        {secs // 3600:02d}:{secs // 60 % 60:02d}:{secs % 60:02d} {name}")
        return 0
    if "-o" in args and args[args.index("-o") + 1] == "pid,cmd":
        if headers:
            print("    PID CMD")
        for p in psutil.process_iter():
            print(f"{p.pid:7d} {_cmdline(p)}")
        return 0
    print(f"ps {' '.join(args)}: only upstream's forms are provided (tools/windows/integration/procps.py)",
          file=sys.stderr)
    return 1


def _matching(name):
    return [p.pid for p in psutil.process_iter() if _name(p) == name]


def pgrep(args):
    """`pgrep NAME`: the pids whose name is NAME (procps matches a pattern
    against the name; upstream gives a name)."""
    pids = _matching(args[-1])
    for pid in pids:
        print(pid)
    return 0 if pids else 1


def pidof(args):
    """`pidof NAME`: the pids on one line."""
    pids = _matching(args[-1])
    if pids:
        print(" ".join(str(p) for p in pids))
    return 0 if pids else 1


def dmesg(_args):
    """Linux's kernel log: Windows's System log, where the kernel and the
    hypervisor write, newest first, in UTF-8 (wevtutil writes the console's
    code page)."""
    out = subprocess.run(["wevtutil", "qe", "System", "/c:200", "/rd:true", "/f:text", "/l:en-US"],
                         capture_output=True, check=False)
    sys.stdout.write(out.stdout.decode("oem", errors="replace").replace("\r\n", "\n").replace("\x00", ""))
    return out.returncode


E2FSPROGS = ("mkfs.ext4", "resize2fs", "e2fsck", "fsck.ext4", "debugfs", "sfdisk", "blkid", "gcc", "lscpu")


def socat(args):
    """`socat [-d...] UNIX-LISTEN:<path>[,fork][,backlog=N] exec:'/bin/cat'|STDOUT`,
    the host side of upstream's vsock tests: a listener on an AF_UNIX path
    (Windows's; WSL's socat cannot reach those sockets) that echoes what each
    connection sends, or writes it to standard output. With `fork`, every
    connection; without, the first one."""
    import socket  # pylint: disable=import-outside-toplevel
    import threading  # pylint: disable=import-outside-toplevel

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import wick_windows_unix  # pylint: disable=import-outside-toplevel

    wick_windows_unix.install()
    args = [a for a in args if not re.fullmatch(r"-d+", a)]
    if len(args) != 2 or not args[0].upper().startswith("UNIX-LISTEN:"):
        print(f"socat {' '.join(args)}: only UNIX-LISTEN:<path>[,opts] with exec:'/bin/cat' or STDOUT "
              "(tools/windows/integration/hosttools.py)", file=sys.stderr)
        return 2
    path, *opts = args[0].split(":", 1)[1].split(",")
    fork = "fork" in opts
    backlog = next((int(o.split("=")[1]) for o in opts if o.startswith("backlog=")), 5)
    target = args[1].strip("'\"").lower()
    echo = target.startswith("exec:") and target.split(":", 1)[1].strip("'\"") == "/bin/cat"
    if not echo and target != "stdout":
        print(f"socat: target {args[1]} is not taken", file=sys.stderr)
        return 2
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(backlog)
    out = sys.stdout.buffer

    def serve(conn):
        with conn:
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                if echo:
                    conn.sendall(data)
                else:
                    out.write(data)
                    out.flush()

    while True:
        conn, _ = listener.accept()
        if not fork:
            serve(conn)
            return 0
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
_DRIVE_PATH = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def wsl_path(arg):
    """A Windows path as WSL mounts it; any other argument as it is."""
    m = _DRIVE_PATH.match(arg)
    return f"/mnt/{m.group(1).lower()}/{m.group(2).replace(chr(92), '/')}" if m else arg


def e2fsprogs(tool, args):
    """e2fsprogs in WSL, on the Windows file."""
    distro = os.environ.get("WICK_IT_WSL", "Ubuntu-24.04")
    out = subprocess.run(["wsl.exe", "-d", distro, "-u", "root", "--", tool, *map(wsl_path, args)],
                         capture_output=True, check=False)
    sys.stdout.write(out.stdout.decode("utf-8", errors="replace"))
    sys.stderr.write(out.stderr.decode("utf-8", errors="replace"))
    return out.returncode


def procstatus(args):
    """`cat /proc/<pid>/status` for a Windows process (wick_windows_mem)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import wick_windows_mem  # pylint: disable=import-outside-toplevel

    try:
        sys.stdout.write(wick_windows_mem.proc_status(int(args[0])))
    except psutil.Error:
        print(f"cat: /proc/{args[0]}/status: No such file or directory", file=sys.stderr)
        return 1
    return 0


def screen(args):
    """`screen` as upstream runs Firecracker in it: `screen LOG CMD...` runs
    CMD with this process's standard input (the session's serial input) and
    its output on a pipe that this process copies to LOG. Stopping this
    process (SIGSTOP: suspended) stops the copying, and CMD's writes then
    find the pipe full, as a screen that is stopped leaves its terminal."""
    log, cmd = args[0], args[1:]
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # pylint: disable=consider-using-with
    with open(log, "ab", buffering=0) as out:
        while True:
            data = child.stdout.read1(4096)
            if not data:
                break
            out.write(data)
    return child.wait()


def iperf3_args(args, forward):
    """iperf3's arguments with its server, an address in a network, replaced
    by the forward for it: `-c <guest>` becomes `-c 127.0.0.1 -p <port>`,
    `forward(guest, port)` giving the port on 127.0.0.1 that leads to the
    guest's port (`-p`, or iperf3's 5201) for TCP and UDP both."""
    args = list(args)
    if "-c" not in args or args.index("-c") + 1 >= len(args):
        raise ValueError("iperf3 in a network: only a client (-c <address>) is run through a forward")
    port = 5201
    if "-p" in args:
        i = args.index("-p")
        port = int(args[i + 1])
        del args[i : i + 2]
    at = args.index("-c") + 1
    local = forward(args[at], port)
    args[at] = "127.0.0.1"
    return args + ["-p", str(local)]


def _door(netns, request):
    """One request to a network's door (wick_windows_net.py)."""
    import json  # pylint: disable=import-outside-toplevel
    import socket  # pylint: disable=import-outside-toplevel

    path = pathlib.Path(os.environ["WICK_IT_ROOT"]) / "netns" / (netns + ".door")
    with socket.create_connection(("127.0.0.1", int(path.read_text(encoding="ascii"))), timeout=30) as conn:
        conn.sendall((json.dumps(request) + "\n").encode())
        reply = json.loads(conn.makefile("r", encoding="utf-8").readline())
    if "error" in reply:
        raise OSError(f"network {netns}: {reply['error']}")
    return reply


def ip(args):
    """`ip netns exec <ns> <program> ...`: Linux runs the program in the
    network namespace. A Windows network is a directory of endpoints with
    its stack in the test session's process, so the program runs on the
    host and reaches the network through its door:

    - `python3`: this Python, its sockets asking the door
      (netns_site/sitecustomize.py);
    - `iperf3 -c <guest>`: the host's iperf3.exe, sent to the forward for
      the guest's port.

    Any other program, and any other `ip` command, is refused: there is no
    namespace to run it in and no link to configure."""
    import shutil  # pylint: disable=import-outside-toplevel

    if args[:2] != ["netns", "exec"] or len(args) < 4:
        print(f"ip {' '.join(args)}: on Windows only `ip netns exec <network> python3|iperf3 ...` is run "
              "(tools/windows/integration/hosttools.py)", file=sys.stderr)
        return 1
    netns, program, rest = args[2], args[3], args[4:]
    door = pathlib.Path(os.environ["WICK_IT_ROOT"]) / "netns" / (netns + ".door")
    if not door.exists():
        print(f"ip netns exec {netns}: no such network in this session ({door})", file=sys.stderr)
        return 1
    if program in ("python3", "python"):
        env = dict(os.environ)
        site = str(pathlib.Path(__file__).resolve().parent / "netns_site")
        env["PYTHONPATH"] = site + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["WICK_NETNS_DOOR"] = door.read_text(encoding="ascii")
        return subprocess.call([sys.executable, *rest], env=env)
    if program == "iperf3":
        exe = shutil.which("iperf3")
        if exe is None:
            print("ip netns exec: iperf3 is not on PATH: the test sends its traffic with the host's iperf3 "
                  "(tools/windows/README.md, the integration tests' needs)", file=sys.stderr)
            return 127
        try:
            rest = iperf3_args(rest, lambda guest, port: _door(
                netns, {"op": "forward", "proto": "both", "ip": guest, "port": port})["port"])
        except (ValueError, OSError) as e:
            print(f"ip netns exec {netns} iperf3: {e}", file=sys.stderr)
            return 1
        return subprocess.call([exe, *rest])
    print(f"ip netns exec {netns} {program}: a Windows network is a directory of endpoints, and only python3 "
          "and iperf3 are run through its door (tools/windows/integration/hosttools.py)", file=sys.stderr)
    return 1


TOOLS = ("ps", "pgrep", "pidof", "dmesg", "socat", "ip", *E2FSPROGS)

# Cargo: upstream's tests that build Firecracker themselves (test_fuzzing,
# test_gdb, test_instrumented_firecracker) build for Linux's musl target.
# Here they build for the Windows one, and find its output under the musl
# target's directory name (wick_windows.py links the two).
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
_MUSL_TARGET = re.compile(r"--target\s+(\S+-unknown-linux-musl)\b")


def windows_binary(path):
    """The file Windows has for the binary upstream names `path` (Linux's
    name, without an extension): `path` if it exists, else `path.exe` if that
    exists, else `path`, so a check that it exists fails as upstream's does."""
    path = pathlib.Path(path)
    exe = path.with_name(path.name + ".exe")
    return exe if not path.exists() and exe.exists() else path


def windows_cargo_args(cargo_args):
    """`cargo_args` with a Linux musl `--target` replaced by the Windows
    target, and the musl target's name (None if it had none)."""
    m = _MUSL_TARGET.search(cargo_args)
    if not m:
        return cargo_args, None
    return cargo_args[: m.start()] + f"--target {WINDOWS_TARGET}" + cargo_args[m.end():], m.group(1)


def main():
    tool, args = sys.argv[1], sys.argv[2:]
    # Linux's line ends; UTF-8, and what is not text escaped, so that the
    # output never fails on a character.
    sys.stdout.reconfigure(newline="\n", encoding="utf-8", errors="backslashreplace")
    sys.stderr.reconfigure(newline="\n", encoding="utf-8", errors="backslashreplace")
    if tool in E2FSPROGS:
        return e2fsprogs(tool, args)
    return {"ps": ps, "pgrep": pgrep, "pidof": pidof, "dmesg": dmesg, "socat": socat,
            "procstatus": procstatus, "screen": screen, "ip": ip}[tool](args)


if __name__ == "__main__":
    sys.exit(main())
