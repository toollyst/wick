# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Scenario tests of wick on Windows (Windows Hypervisor Platform) against
# upstream Firecracker's x86_64 CI guest; the Windows counterpart of
# tools/macos/boot-test.py. Every stage that needs a guest boots its own VM
# and checks what the guest and the host see (the parts marked "no guest"
# below boot none):
#
#   boot   1 vCPU: init, serial out and in (stdin is a pipe), CPU, memory,
#          guest clock, CPUID hypervisor bit; serial input still read after
#          30 s of silence and after a full receive FIFO; reset exits
#          Firecracker with 0
#   smp    2 vCPUs: AP start-up, work on each CPU, the clock agrees between
#          them; CPU 1 offline and online (INIT/SIPI) three times, then
#          working, after boot and after a snapshot restore
#   block  Async read-only drive (md5), Sync and Async writable drives (the
#          host sees the guest's writes), read-only enforced, each drive's
#          serial from its file
#   vsock  host -> guest CONNECT, 4 MiB echo; guest -> host <uds>_53
#   net    virtio-net over the Windows endpoint (Unix stream, 32-bit
#          big-endian length before each frame): a switch here answers ARP,
#          ICMP echo and UDP echo and checks every checksum the guest sends;
#          rx and tx rate limiters set while it runs hold it to 1 MiB/s
#   snapshot  full snapshot of a 2 vCPU guest (data drive, vsock) restored in
#          a new process: shell state, clock, drives, vsock
#   diff   diff snapshot with dirty page tracking (holes kept), merged by
#          snapshot-editor and restored
#   uffd   the snapshot stage's snapshot restored with the Uffd backend,
#          served by upstream's uffd_on_demand_handler
#   pci    the snapshot stage over virtio-pci with MSI-X (--enable-pci)
#   restores  one snapshot restored 20 times, each paused and snapshotted
#          again (vCPU races at restore and at the pause)
#   vhost-user  a vhost-user-blk drive served by tools/vhost-user-blk in
#          another process: read md5, a write reaches the image
#   hugepages  guest memory on 2 MiB large pages (needs "Lock pages in
#          memory" for this account)
#   devices  virtio-rng, a rate-limited drive, MMDS V2, the balloon and its
#          statistics, the logger's and the metrics' files
#   balloon  150 MiB balloon cycles on a guest restored from a memory file
#          and on a booted one: O_DIRECT reads of the drive read the file,
#          and the commit charge goes down and up again with the balloon
#   cli    Firecracker's command line: exit codes 152 and 153 (no guest),
#          --module, the start time flags, the logger and metrics on named
#          pipes, set before the microVM starts (a reader that never reads
#          and readers that go away included), --boot-timer
#   tools  rebase-snap and snapshot-editor rebase on sparse and dense
#          synthetic diff files (no guest), then on a diff snapshot;
#          info-vmstate; state files with another arch's magic or a newer
#          version refused at the load
#   no-seccomp  the mitigation profile on without --no-seccomp and off with
#          it, in Firecracker and its API process, before a boot (no guest)
#          and with a guest running
#   foreign-snapshot  (not in `all`: needs -ForeignState) a state file made
#          on another host is refused at the load (no guest)
#   cpu-templates  a custom CPU template through PUT /cpu-config: the CPUID
#          bits it clears are gone from the guest on every vCPU, also after
#          a restore; a template that changes a CPUID leaf the host lacks,
#          and one that changes an MSR the backend keeps nowhere (0x10a,
#          as T2S and T2CL do), are refused at the start
#   diff-nospace  (not in `all`: needs an elevated prompt, for diskpart) a
#          diff snapshot written to a volume without the room fails with
#          "not enough space on the disk" and leaves the guest as it was;
#          with the room made, the next diff snapshot succeeds and restores
#          with what the guest wrote before the failed one. Upstream's
#          test_diff_snapshot_works_after_error on a 512 MiB virtual disk
#          in place of its 512 MiB tmpfs
#   linux-snapshot  (not in `all`: needs -LinuxSnapshot) a whole snapshot
#          made on Linux x86_64 with KVM by tools/linux/make-vmstate.py, same
#          Firecracker version, same root drive file, loaded and resumed
#          here. A record of what a snapshot taken on the other host OS
#          does: restored (the guest's shell answers, its clock runs, the
#          drive is read) or refused, with Firecracker's error; the stage
#          fails when it is neither (a guest that resumed and does not
#          answer, a Firecracker that stays up after a refusal)
#   memory-hotplug  virtio-mem: the unplugged region not charged at the
#          boot, 512 MiB plugged, seen in MemTotal and used, then unplugged
#          (the commit charge and private working set go down) and plugged
#          again
#   gdb    (not in `all`: needs a Firecracker built with the gdb feature and
#          a gdb) upstream's debug kernel under gdb: a hardware breakpoint at
#          start_kernel, the kernel's bytes read through the stub's address
#          translation, a software breakpoint at rest_init, the guest boots
#
# Before each reset the guest kernel log must be free of stalls, BUGs, oopses
# and warnings.
#
#   powershell -ExecutionPolicy Bypass -File boot-test.ps1 `
#       [-Firecracker <firecracker.exe>] [-WorkDir <dir>] [-Stage boot,smp,...]
#       [-Except hugepages,...]
#
# `all` is every stage that needs nothing but this script and the kit; the
# others need an input or a setting (each says which) and are named. CI runs
# `-Stage all,diff-nospace -Except hugepages` (hugepages and the rest in
# steps of their own), so `all` is the same set on a PC and in CI.
#
# Needs: Windows 10 (1803 or later) or 11, x86_64, with "Windows Hypervisor
# Platform" turned on (optionalfeatures.exe, or as administrator:
#  Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform,
# then reboot), and internet access for the first run (kernel and rootfs from
# upstream's public CI bucket, about 145 MB, cached in -WorkDir). Nothing
# else is installed.
#
# Without -Firecracker it uses firecracker.exe next to this script, then
# lib\firecracker\build\cargo_target\{release,debug}\firecracker.exe.
#
# Prints PASS/FAIL per stage with the reason, lists what is not implemented on
# Windows yet, and writes every log (serial console, Firecracker log, VM
# config, guest kernel log) to <WorkDir>\results-<time>, zipped as
# results-<time>.zip next to it. Exit status 1 if any stage failed.

[CmdletBinding()]
param(
    [string]$Firecracker,
    [string]$WorkDir = (Join-Path $env:LOCALAPPDATA 'wick-boot-test'),
    # Stage names, comma-separated or as a list; `all` runs every stage that
    # needs no input or setting (not gdb, diff-nospace, linux-snapshot,
    # foreign-snapshot), and may be given with others.
    [string[]]$Stage = @('all'),
    # Stages to leave out of those -Stage names.
    [string[]]$Except = @(),
    [int]$TimeoutSec = 120,
    # For the foreign-snapshot stage: a snapshot state file made on another
    # host (the macOS boot test's snapshot stage makes an aarch64 one).
    [string]$ForeignState,
    # For the linux-snapshot stage (not part of `all`): the directory
    # tools/linux/make-vmstate.py kept a whole snapshot in (CI's artifact
    # linux-snapshot: linux-x86_64.vmstate, .mem and .txt).
    [string]$LinuxSnapshot,
    # For the gdb stage (not part of `all`): a Firecracker built with the
    # gdb feature (default: lib\firecracker\build\cargo_target\debug), and
    # a gdb that reads x86-64 Linux kernels (default: gdb-multiarch or gdb on
    # PATH, then MSYS2's in C:\msys64\{ucrt64,mingw64}\bin).
    [string]$GdbFirecracker,
    [string]$Gdb,
    # Checks the harness itself against stand-ins for Firecracker's sockets
    # (no WHP, no downloads) and exits.
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Firecracker, the jailer and the probes write UTF-8 (Rust's strings,
# Windows' error texts in them included, which are in the system's language);
# Windows PowerShell reads a file in the ANSI code page and a redirected
# stream in the console's unless told: on a Korean or Japanese Windows their
# text came out garbled.
$PSDefaultParameterValues['Get-Content:Encoding'] = 'UTF8'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

# Upstream's CI artifacts (resources/rebuild.sh builds them); the prefix is the
# one this kit was written against.
$S3 = 'https://s3.amazonaws.com/spec.ccfc.min'
$Prefix = 'firecracker-ci/20261105-6ea6634994fa-0/x86_64'
$KernelName = 'vmlinux-6.1.188'
$RootfsName = 'ubuntu-24.04.squashfs'

$BootArgs = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd ' +
    'root=/dev/vda ro rootfstype=squashfs init=/bin/sh'

# What upstream Firecracker does that wick does not do on Windows yet
# (docs/ROADMAP.md, "Platform status"); listed in the summary, not run.
# (The leading comma keeps a one-entry list a list of pairs.)
# The jailer has its own test, tools\windows\jailer-test.ps1.
$NotImplemented = @()

# --- helpers (C# 5: what Windows PowerShell 5.1 compiles) ---------------------

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Wick {
    // A failed check: the message is the reason the summary shows.
    public class Failure : Exception {
        public Failure(string message) : base(message) { }
    }

    // A Firecracker process: its serial console (stdout) and stderr collected
    // as they come and copied to a log file, its stdin a pipe.
    public class Vm {
        Process p;
        StringBuilder text = new StringBuilder();
        StreamWriter log;
        Thread outPump, errPump;
        int seq;
        static readonly Encoding NoBom = new UTF8Encoding(false);

        public Vm(string exe, string args, string logPath) {
            log = new StreamWriter(logPath, false, new UTF8Encoding(false));
            log.AutoFlush = true;
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = new UTF8Encoding(false);
            psi.StandardErrorEncoding = new UTF8Encoding(false);
            // Process.Start makes the stdin writer with the console's input
            // encoding and flushes its preamble at once: with a UTF-8 code
            // page (65001) the child's stdin would start with a byte order
            // mark, which the guest shell takes as part of the first command.
            Encoding saved = null;
            try {
                saved = Console.InputEncoding;
                if (saved.GetPreamble().Length > 0) Console.InputEncoding = NoBom;
            } catch (Exception) {
                saved = null; // no console: the default encoding has no preamble
            }
            try {
                p = Process.Start(psi);
            } finally {
                if (saved != null && saved.GetPreamble().Length > 0) {
                    try { Console.InputEncoding = saved; } catch (Exception) { }
                }
            }
            outPump = new Thread(Pump);
            outPump.IsBackground = true;
            outPump.Start(p.StandardOutput.BaseStream);
            errPump = new Thread(Pump);
            errPump.IsBackground = true;
            errPump.Start(p.StandardError.BaseStream);
        }

        void Pump(object o) {
            var s = (Stream)o;
            var buf = new byte[65536];
            var dec = Encoding.UTF8.GetDecoder();
            var chars = new char[65536];
            int n;
            try {
                while ((n = s.Read(buf, 0, buf.Length)) > 0) {
                    int c = dec.GetChars(buf, 0, n, chars, 0);
                    string t = new string(chars, 0, c).Replace("\r", "");
                    lock (text) {
                        text.Append(t);
                        try { log.Write(t); } catch (Exception) { }
                        Monitor.PulseAll(text);
                    }
                }
            } catch (IOException) {
            } catch (ObjectDisposedException) {
            }
            lock (text) { Monitor.PulseAll(text); }
        }

        public string Output { get { lock (text) { return text.ToString(); } } }
        public int Length { get { lock (text) { return text.Length; } } }
        public bool Exited { get { return p.HasExited; } }
        public int ExitCode { get { return p.ExitCode; } }

        public int Pid { get { return p.Id; } }
        public string ExitReason() {
            string state = p.HasExited ? "exit " + p.ExitCode : "running";
            var lines = Output.Trim().Split('\n');
            int from = Math.Max(0, lines.Length - 8);
            var tail = new StringBuilder();
            for (int i = from; i < lines.Length; i++) tail.Append("\n    ").Append(lines[i]);
            return state + "; last lines:" + tail.ToString();
        }

        // UTF-8 bytes straight to the pipe, whatever the console's code page.
        public void Send(string line) {
            var b = NoBom.GetBytes(line + "\n");
            try {
                p.StandardInput.BaseStream.Write(b, 0, b.Length);
                p.StandardInput.BaseStream.Flush();
            } catch (IOException) {
                throw new Failure("serial input closed: Firecracker " + ExitReason());
            }
        }

        // The first match of `pattern` in the output from offset `start`.
        public Match WaitFor(string pattern, int ms, int start) {
            var re = new Regex(pattern, RegexOptions.Multiline);
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            lock (text) {
                while (true) {
                    var m = re.Match(text.ToString(), Math.Min(start, text.Length));
                    if (m.Success) return m;
                    bool dead = p.HasExited && !outPump.IsAlive && !errPump.IsAlive;
                    if (dead) throw new Failure("waiting for /" + pattern + "/: Firecracker " + ExitReason());
                    var left = until - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero)
                        throw new Failure("no /" + pattern + "/ within " + (ms / 1000) + " s (" + ExitReason() + ")");
                    Monitor.Wait(text, left < TimeSpan.FromMilliseconds(250) ? left : TimeSpan.FromMilliseconds(250));
                }
            }
        }

        // Waits until the guest's shell answers on the serial console, then
        // keeps prompts and kernel messages out of command output.
        public void Shell(int ms) {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (true) {
                int mark = Length;
                try {
                    Send("echo READY-$((20+22))");
                    WaitFor("^READY-42$", 2000, mark);
                    break;
                } catch (Failure) {
                    if (p.HasExited || DateTime.UtcNow > until) throw;
                }
            }
            // A prompt printed after the tty echoed the next command, or a
            // kernel message, would land in the middle of command output.
            Send("PS1=");
            Sh("mount -t proc proc /proc; mount -t sysfs sys /sys; dmesg -n 1", 30000, true);
        }

        // Runs `cmd` in the guest's shell; returns its status and output.
        public int Sh(string cmd, int ms, bool mustSucceed, out string output) {
            seq++;
            string tag = "K" + seq + "Z";
            int mark = Length;
            Send(cmd + "; echo RC=$?:" + tag);
            var m = WaitFor("^(.*?)RC=(\\d+):" + tag + "$", ms, mark);
            string all = Output;
            string region = all.Substring(mark, m.Index - mark);
            // The tty's echo of the command line comes first.
            string echo = "echo RC=$?:" + tag + "\n";
            int at = region.IndexOf(echo, StringComparison.Ordinal);
            output = ((at >= 0 ? region.Substring(at + echo.Length) : region) + m.Groups[1].Value).Trim();
            int rc = int.Parse(m.Groups[2].Value);
            if (mustSucceed && rc != 0)
                throw new Failure("guest command failed (" + rc + "): " + cmd + "\n    " + output);
            return rc;
        }

        public string Sh(string cmd, int ms, bool mustSucceed) {
            string output;
            Sh(cmd, ms, mustSucceed, out output);
            return output;
        }

        public string Sh(string cmd) { return Sh(cmd, 60000, true); }

        // The guest's health patterns (tools/guest-health.txt, the x86_64
        // guest's and `all`), as grep's -e arguments; set by the script
        // before any stage (Read-GuestHealth).
        public static string HealthGrep;

        // Fails if the guest kernel's log has a line with any pattern of
        // tools/guest-health.txt, the file the Linux and macOS boot tests
        // read too, which names for each the source that prints it: a
        // stall, a BUG, an oops, a WARN()'s report ("WARNING: CPU: ...",
        // not any line with "WARNING:" in it, as the SRSO notice a guest
        // prints on an AMD Zen 3 host, which failed 16 stages on CI's EPYC
        // 7763 runner, run 43428124115), a stack dump, and the x86 reports
        // only a VMM's fault makes (an MSR refused, an unknown NMI, TSCs
        // apart, an interrupt nothing asked for, an AP not started).
        public void Healthy() {
            if (string.IsNullOrEmpty(HealthGrep)) throw new Failure("no guest health patterns read (tools/guest-health.txt)");
            string out1 = Sh("dmesg | grep -F " + HealthGrep + " | head -5; true");
            if (out1.Length > 0) throw new Failure("guest kernel reports:\n    " + out1);
        }

        // Checks the guest's health and resets it; Firecracker exits with 0.
        public void Reboot() {
            Healthy();
            Send("reboot -ff");
            if (!p.WaitForExit(30000)) throw new Failure("Firecracker did not exit within 30 s of the guest reset (" + ExitReason() + ")");
            p.WaitForExit();
            outPump.Join(5000);
            errPump.Join(5000);
            if (p.ExitCode != 0) throw new Failure("exit status " + p.ExitCode + " after the guest reset (" + ExitReason() + ")");
        }

        // After the exit: the last of the output, which the pumps may still
        // be reading.
        public void Drain(int ms) {
            outPump.Join(ms);
            errPump.Join(ms);
        }

        public void Kill() {
            try { if (!p.HasExited) p.Kill(); } catch (InvalidOperationException) { } catch (System.ComponentModel.Win32Exception) { }
            p.WaitForExit(5000);
            outPump.Join(2000);
            errPump.Join(2000);
            lock (text) { try { log.Dispose(); } catch (Exception) { } }
        }
    }

    // A Winsock AF_UNIX stream socket (Windows 10 1803 or later). Waits use
    // WSAPoll: a Winsock receive that times out leaves the socket unusable.
    public class USock : IDisposable {
        [StructLayout(LayoutKind.Sequential)]
        struct PollFd { public IntPtr fd; public short events; public short revents; }

        [DllImport("ws2_32.dll")] static extern int WSAStartup(ushort v, byte[] data);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern IntPtr socket(int af, int type, int proto);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int connect(IntPtr s, byte[] addr, int len);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int bind(IntPtr s, byte[] addr, int len);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int listen(IntPtr s, int backlog);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern IntPtr accept(IntPtr s, IntPtr addr, IntPtr len);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int send(IntPtr s, IntPtr buf, int len, int flags);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int recv(IntPtr s, IntPtr buf, int len, int flags);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int WSAPoll([In, Out] PollFd[] fds, uint n, int timeout);
        [DllImport("ws2_32.dll")] static extern int closesocket(IntPtr s);
        [DllImport("ws2_32.dll")] static extern int WSAGetLastError();

        const short POLLIN = 0x0300;   // POLLRDNORM | POLLRDBAND
        const short POLLHUP = 0x0002;
        const short POLLERR = 0x0001;
        static readonly IntPtr Invalid = new IntPtr(-1);
        static bool started;

        IntPtr s;
        public string Path;

        USock(IntPtr s, string path) { this.s = s; Path = path; }

        static void Start() {
            if (!started) { WSAStartup(0x0202, new byte[512]); started = true; }
        }

        static byte[] Addr(string path) {
            var addr = new byte[110];
            addr[0] = 1; // AF_UNIX
            var b = Encoding.UTF8.GetBytes(path);
            if (b.Length >= 108) throw new Failure("socket path too long (" + b.Length + " bytes, 107 at most): " + path);
            Array.Copy(b, 0, addr, 2, b.Length);
            return addr;
        }

        static IntPtr NewSocket() {
            Start();
            IntPtr s = socket(1, 1, 0);
            if (s == Invalid) throw new Failure("AF_UNIX socket: WSA error " + WSAGetLastError() + " (needs Windows 10 1803 or later)");
            return s;
        }

        public static USock Connect(string path) {
            IntPtr s = NewSocket();
            var a = Addr(path);
            if (connect(s, a, a.Length) != 0) {
                int e = WSAGetLastError();
                closesocket(s);
                throw new Failure("connect " + path + ": WSA error " + e);
            }
            return new USock(s, path);
        }

        public static USock Listen(string path) {
            if (File.Exists(path)) File.Delete(path);
            IntPtr s = NewSocket();
            var a = Addr(path);
            if (bind(s, a, a.Length) != 0 || listen(s, 4) != 0) {
                int e = WSAGetLastError();
                closesocket(s);
                throw new Failure("listen " + path + ": WSA error " + e);
            }
            return new USock(s, path);
        }

        // True when a read (or an accept) would not block; false on timeout.
        public bool Poll(int ms) {
            var fds = new PollFd[1];
            fds[0].fd = s;
            fds[0].events = POLLIN;
            int n = WSAPoll(fds, 1, ms);
            if (n < 0) throw new Failure("WSAPoll: WSA error " + WSAGetLastError());
            return n > 0 && (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
        }

        public USock Accept(int ms) {
            if (!Poll(ms)) throw new Failure("nobody connected to " + Path + " within " + (ms / 1000) + " s");
            IntPtr c = accept(s, IntPtr.Zero, IntPtr.Zero);
            if (c == Invalid) throw new Failure("accept " + Path + ": WSA error " + WSAGetLastError());
            return new USock(c, Path);
        }

        public void SendAll(byte[] data, int off, int len) {
            var h = GCHandle.Alloc(data, GCHandleType.Pinned);
            try {
                while (len > 0) {
                    int n = send(s, h.AddrOfPinnedObject() + off, Math.Min(len, 1 << 20), 0);
                    if (n <= 0) throw new Failure("send to " + Path + ": WSA error " + WSAGetLastError());
                    off += n;
                    len -= n;
                }
            } finally {
                h.Free();
            }
        }

        public void SendAll(byte[] data) { SendAll(data, 0, data.Length); }

        // Up to `len` bytes; 0 when the peer closed, -1 on timeout.
        public int Recv(byte[] buf, int off, int len, int ms) {
            if (!Poll(ms)) return -1;
            var h = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try {
                int n = recv(s, h.AddrOfPinnedObject() + off, len, 0);
                if (n < 0) {
                    int e = WSAGetLastError();
                    if (e == 10054 || e == 10053) return 0; // reset, aborted: closed
                    throw new Failure("recv from " + Path + ": WSA error " + e);
                }
                return n;
            } finally {
                h.Free();
            }
        }

        // Exactly `len` bytes, or a Failure.
        public void RecvExact(byte[] buf, int off, int len, int ms) {
            while (len > 0) {
                int n = Recv(buf, off, len, ms);
                if (n < 0) throw new Failure("no data from " + Path + " within " + (ms / 1000) + " s");
                if (n == 0) throw new Failure(Path + " closed with " + len + " bytes still expected");
                off += n;
                len -= n;
            }
        }

        public void Dispose() {
            if (s != Invalid) { closesocket(s); s = Invalid; }
        }
    }

    // A TCP listener on 127.0.0.1 whose one connection is relayed to a Unix
    // socket: for a gdb that cannot connect to a Unix socket path itself.
    public class Relay {
        System.Net.Sockets.TcpListener listener;
        volatile bool stopped;
        public int Port;
        public volatile string Error;
        public volatile bool Connected;

        public Relay(string uds) {
            listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            Port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var t = new Thread(() => Run(uds));
            t.IsBackground = true;
            t.Start();
        }

        void Run(string uds) {
            try {
                var client = listener.AcceptTcpClient();
                listener.Stop();
                var u = USock.Connect(uds);
                Connected = true;
                var stream = client.GetStream();
                var up = new Thread(() => {
                    var b = new byte[4096];
                    try {
                        int n;
                        while ((n = stream.Read(b, 0, b.Length)) > 0) u.SendAll(b, 0, n);
                    } catch (Exception) { }
                });
                up.IsBackground = true;
                up.Start();
                var buf = new byte[4096];
                while (!stopped) {
                    int n = u.Recv(buf, 0, buf.Length, 200);
                    if (n == 0) break;
                    if (n > 0) stream.Write(buf, 0, n);
                }
                client.Close();
                u.Dispose();
            } catch (Exception e) {
                if (!stopped) Error = e.Message;
            }
        }

        public void Stop() {
            stopped = true;
            try { listener.Stop(); } catch (Exception) { }
        }
    }

    // Firecracker's API: one HTTP/1.1 request per connection on its socket.
    public static class Api {
        public static string Call(string sock, string method, string path, string body, int ms, out int status) {
            using (var s = USock.Connect(sock)) {
                byte[] b = body == null ? new byte[0] : Encoding.UTF8.GetBytes(body);
                var head = new StringBuilder();
                head.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n");
                if (body != null) head.Append("Content-Type: application/json\r\nContent-Length: ").Append(b.Length).Append("\r\n");
                head.Append("\r\n");
                s.SendAll(Encoding.ASCII.GetBytes(head.ToString()));
                if (b.Length > 0) s.SendAll(b);
                var got = new MemoryStream();
                var chunk = new byte[16384];
                int headerEnd = -1, length = 0;
                while (headerEnd < 0 || got.Length < headerEnd + length) {
                    int n = s.Recv(chunk, 0, chunk.Length, ms);
                    if (n < 0) throw new Failure(method + " " + path + ": no answer within " + (ms / 1000) + " s");
                    if (n == 0) break;
                    got.Write(chunk, 0, n);
                    if (headerEnd < 0) {
                        string sofar = Encoding.ASCII.GetString(got.ToArray());
                        int at = sofar.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                        if (at >= 0) {
                            headerEnd = at + 4;
                            var m = Regex.Match(sofar.Substring(0, at), @"(?im)^content-length:\s*(\d+)");
                            if (m.Success) length = int.Parse(m.Groups[1].Value);
                        }
                    }
                }
                string all = Encoding.UTF8.GetString(got.ToArray());
                var sl = Regex.Match(all, @"^HTTP/1\.[01] (\d{3})");
                if (!sl.Success) throw new Failure(method + " " + path + ": not an HTTP answer: '" + all + "'");
                status = int.Parse(sl.Groups[1].Value);
                int bodyAt = all.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                return bodyAt >= 0 ? all.Substring(bodyAt + 4) : "";
            }
        }
    }

    // The process mitigation policies of a process (vmm::ext::sandbox's
    // profile): the flags word of each.
    public static class Mitigation {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetProcessMitigationPolicy(IntPtr process, int policy, out uint flags, IntPtr len);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);
        public static readonly string[] Names = { "ExtensionPoint", "ImageLoad", "Signature", "StrictHandle", "Win32k", "DynamicCode", "ChildProcess" };
        static readonly int[] Policies = { 6, 10, 8, 3, 4, 2, 13 };
        public static Dictionary<string, uint> Of(int pid) {
            IntPtr h = OpenProcess(0x400, false, pid); // PROCESS_QUERY_INFORMATION
            if (h == IntPtr.Zero) throw new Failure("cannot open pid " + pid + ": error " + Marshal.GetLastWin32Error());
            var m = new Dictionary<string, uint>();
            try {
                for (int i = 0; i < Names.Length; i++) {
                    uint flags;
                    if (!GetProcessMitigationPolicy(h, Policies[i], out flags, (IntPtr)4)) throw new Failure("mitigation " + Names[i] + " of pid " + pid + ": error " + Marshal.GetLastWin32Error());
                    m[Names[i]] = flags;
                }
            } finally { CloseHandle(h); }
            return m;
        }
    }

    // Large pages on this host: whether `bytes` of them can be had right
    // now (VirtualAlloc with MEM_LARGE_PAGES, under SeLockMemoryPrivilege),
    // so a guest that cannot get its memory is told apart from a Firecracker
    // bug: the host's physical memory fragments with uptime, and the
    // allocation then fails with ERROR_NO_SYSTEM_RESOURCES (1450) however
    // much is free.
    public static class LargePages {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);
        [DllImport("kernel32.dll")]
        static extern UIntPtr GetLargePageMinimum();
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupPrivilegeValueW(string system, string name, out long luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges p, uint len, IntPtr prev, IntPtr ret);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);
        // Pack = 4, as winnt.h packs TOKEN_PRIVILEGES: the LUID is at offset 4 (at 8 the privilege named is not the one meant: error 1300).
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        struct TokenPrivileges { public uint Count; public long Luid; public uint Attributes; }

        public static long Minimum() { return (long)(ulong)GetLargePageMinimum(); }

        // "" when `bytes` of large pages were allocated (and freed again),
        // else what failed.
        public static string Probe(long bytes) {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) return "OpenProcessToken: error " + Marshal.GetLastWin32Error(); // ADJUST_PRIVILEGES | QUERY
            try {
                var p = new TokenPrivileges();
                p.Count = 1;
                p.Attributes = 2; // SE_PRIVILEGE_ENABLED
                if (!LookupPrivilegeValueW(null, "SeLockMemoryPrivilege", out p.Luid)) return "LookupPrivilegeValue: error " + Marshal.GetLastWin32Error();
                if (!AdjustTokenPrivileges(token, false, ref p, 16, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                    return "enabling SeLockMemoryPrivilege: error " + Marshal.GetLastWin32Error();
            } finally { CloseHandle(token); }
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)bytes, 0x3000 | 0x20000000, 0x04); // MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE
            if (mem == IntPtr.Zero) {
                int err = Marshal.GetLastWin32Error();
                return "VirtualAlloc(MEM_LARGE_PAGES, " + (bytes >> 20) + " MiB) failed with error " + err +
                    (err == 1450 ? " (ERROR_NO_SYSTEM_RESOURCES: the host has no " + (bytes >> 20) + " MiB of contiguous large pages free; its physical memory is fragmented, a reboot defragments it)" : "");
            }
            VirtualFree(mem, UIntPtr.Zero, 0x8000); // MEM_RELEASE
            return "";
        }
    }

    public static class Util {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetCompressedFileSizeW(string path, out uint high);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetDiskFreeSpaceExW(string dir, out ulong toCaller, out ulong total, out ulong free);

        // Free bytes of the volume `dir` is on; any directory of it will do
        // (GetDiskFreeSpaceExW, lpDirectoryName: "does not have to specify
        // the root directory on a disk").
        public static long FreeSpace(string dir) {
            ulong toCaller, total, free;
            if (!GetDiskFreeSpaceExW(dir, out toCaller, out total, out free))
                throw new Failure("GetDiskFreeSpaceEx " + dir + ": error " + Marshal.GetLastWin32Error());
            return (long)toCaller;
        }

        // Bytes the file system allocates for `path` (sparse files: without holes).
        public static long Allocated(string path) {
            uint high;
            uint low = GetCompressedFileSizeW(path, out high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0)
                throw new Failure("GetCompressedFileSize " + path + ": error " + Marshal.GetLastWin32Error());
            return ((long)high << 32) | low;
        }

        public static string Md5(byte[] data, int len) {
            using (var md5 = MD5.Create()) return Hex(md5.ComputeHash(data, 0, len));
        }

        public static string Md5File(string path, long len) {
            using (var md5 = MD5.Create())
            using (var f = File.OpenRead(path)) {
                var buf = new byte[1 << 20];
                long left = len < 0 ? long.MaxValue : len;
                int n;
                while (left > 0 && (n = f.Read(buf, 0, (int)Math.Min(buf.Length, left))) > 0) {
                    md5.TransformBlock(buf, 0, n, null, 0);
                    left -= n;
                }
                md5.TransformFinalBlock(buf, 0, 0);
                return Hex(md5.Hash);
            }
        }

        static string Hex(byte[] h) {
            var sb = new StringBuilder();
            foreach (var b in h) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static byte[] Random(int size) {
            var b = new byte[size];
            using (var r = RandomNumberGenerator.Create()) r.GetBytes(b);
            return b;
        }

        public static void WriteRandom(string path, int size) {
            File.WriteAllBytes(path, Random(size));
        }

        public static void WriteZeros(string path, int size) {
            using (var f = File.Create(path)) f.SetLength(size);
        }
    }

    // vsock through Firecracker's Unix socket (upstream's convention).
    public static class Vsock {
        // CONNECT to guest `port`; the stream after the "OK <port>" line.
        public static USock Connect(string uds, int port) {
            var s = USock.Connect(uds);
            try {
                s.SendAll(Encoding.ASCII.GetBytes("CONNECT " + port + "\n"));
                var line = new StringBuilder();
                var one = new byte[1];
                while (!line.ToString().EndsWith("\n")) {
                    int n = s.Recv(one, 0, 1, 10000);
                    if (n <= 0) throw new Failure("vsock handshake " + (n == 0 ? "closed" : "timed out") + " after '" + line + "'");
                    line.Append((char)one[0]);
                }
                if (!line.ToString().StartsWith("OK ")) throw new Failure("vsock handshake answered '" + line.ToString().Trim() + "'");
                return s;
            } catch {
                s.Dispose();
                throw;
            }
        }

        // Connects until the guest listens (the connection is closed with no
        // "OK" while nothing listens), for up to `ms`.
        public static void WaitListening(string uds, int port, int ms) {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (true) {
                try {
                    Connect(uds, port).Dispose();
                    return;
                } catch (Failure) {
                    if (DateTime.UtcNow > until) throw;
                    Thread.Sleep(200);
                }
            }
        }

        // Sends `size` random bytes to the guest's echo service on `port` and
        // reads them back by length: a host end that shuts down its write
        // side closes the whole connection (upstream behaviour).
        public static void Echo(string uds, int port, int size) {
            var payload = Util.Random(size);
            using (var s = Connect(uds, port)) {
                Exception sendError = null;
                var sender = new Thread(delegate() {
                    try { s.SendAll(payload); } catch (Exception e) { sendError = e; }
                });
                sender.IsBackground = true;
                sender.Start();
                var echo = new byte[size];
                int got = 0;
                while (got < size) {
                    int n = s.Recv(echo, got, size - got, 30000);
                    if (n <= 0) break;
                    got += n;
                }
                sender.Join(30000);
                if (sendError != null) throw new Failure("vsock send: " + sendError.Message);
                if (got != size) throw new Failure("vsock echo: " + got + " of " + size + " bytes came back");
                for (int i = 0; i < size; i++)
                    if (echo[i] != payload[i]) throw new Failure("vsock echo differs at byte " + i + " of " + size);
            }
        }
    }

    // Accepts one connection on a Unix socket and collects what it sends.
    public class Collector {
        USock listener;
        Thread t;
        MemoryStream data = new MemoryStream();
        public string Error;

        public Collector(string path, int ms) {
            listener = USock.Listen(path);
            t = new Thread(delegate() {
                try {
                    using (var c = listener.Accept(ms)) {
                        var buf = new byte[65536];
                        int n;
                        while ((n = c.Recv(buf, 0, buf.Length, ms)) > 0) data.Write(buf, 0, n);
                        if (n < 0) Error = "timed out reading";
                    }
                } catch (Exception e) {
                    Error = e.Message;
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        public string Finish(int ms) {
            t.Join(ms);
            listener.Dispose();
            try { File.Delete(listener.Path); } catch (Exception) { }
            if (Error != null) throw new Failure(Error);
            return Encoding.ASCII.GetString(data.ToArray());
        }
    }

    // A host-side switch on the Windows network endpoint: a Unix stream with
    // each Ethernet frame preceded by its length (32-bit big-endian, QEMU's
    // -netdev stream framing). Answers ARP and ICMP echo for HostIp and
    // echoes UDP port 7, checking every checksum the guest sent.
    public class Switch {
        public static readonly byte[] HostMac = { 0x02, 0x00, 0x0a, 0x00, 0x00, 0x01 };
        public static readonly byte[] HostIp = { 10, 0, 0, 1 };

        USock conn;
        Thread t;
        volatile bool stop;
        object sendLock = new object();
        public List<string> Bad = new List<string>();
        public int Frames, Arp, Icmp, Udp;
        public string ReadError;
        // Set before the guest reboots: Firecracker exits and closes the
        // endpoint, which is then no error.
        public volatile bool Closing;

        public Switch(string endpoint, int ms) {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (true) {
                try {
                    conn = USock.Connect(endpoint);
                    break;
                } catch (Failure e) {
                    if (DateTime.UtcNow > until) throw new Failure("network endpoint " + endpoint + ": " + e.Message);
                    Thread.Sleep(100);
                }
            }
            t = new Thread(Run);
            t.IsBackground = true;
            t.Start();
        }

        public string Counts { get { return "frames " + Frames + ", arp " + Arp + ", icmp " + Icmp + ", udp " + Udp; } }

        void Run() {
            var hdr = new byte[4];
            try {
                while (!stop) {
                    int n = conn.Recv(hdr, 0, 1, 200);
                    if (n < 0) continue;
                    if (n == 0) { if (!stop && !Closing) ReadError = "the endpoint closed the connection"; return; }
                    conn.RecvExact(hdr, 1, 3, 5000);
                    int len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
                    if (len < 14 || len > 65536 + 22) {
                        lock (Bad) Bad.Add("frame length " + len);
                        return; // the stream cannot be resynchronised
                    }
                    var frame = new byte[len];
                    conn.RecvExact(frame, 0, len, 5000);
                    Frames++;
                    try {
                        Handle(frame);
                    } catch (Exception e) {
                        lock (Bad) Bad.Add(e.GetType().Name + " " + e.Message + " in " + HexHead(frame));
                    }
                }
            } catch (Exception e) {
                if (!stop && !Closing) ReadError = e.Message;
            }
        }

        static string HexHead(byte[] f) {
            var sb = new StringBuilder();
            for (int i = 0; i < Math.Min(f.Length, 64); i++) sb.Append(f[i].ToString("x2"));
            return sb.ToString();
        }

        static int Be16(byte[] b, int at) { return (b[at] << 8) | b[at + 1]; }

        static void Put16(byte[] b, int at, int v) { b[at] = (byte)(v >> 8); b[at + 1] = (byte)v; }

        static bool Eq(byte[] a, int at, byte[] b) {
            for (int i = 0; i < b.Length; i++) if (a[at + i] != b[i]) return false;
            return true;
        }

        // The Internet checksum of b[at..at+len] plus `sum`; 0 over data
        // that holds a correct checksum.
        public static int Csum(byte[] b, int at, int len, uint sum) {
            for (int i = 0; i + 1 < len; i += 2) sum += (uint)((b[at + i] << 8) | b[at + i + 1]);
            if (len % 2 == 1) sum += (uint)(b[at + len - 1] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
            return (int)(~sum & 0xffff);
        }

        static uint Pseudo(byte[] src, int srcAt, byte[] dst, int dstAt, int proto, int len) {
            uint s = 0;
            s += (uint)((src[srcAt] << 8) | src[srcAt + 1]) + (uint)((src[srcAt + 2] << 8) | src[srcAt + 3]);
            s += (uint)((dst[dstAt] << 8) | dst[dstAt + 1]) + (uint)((dst[dstAt + 2] << 8) | dst[dstAt + 3]);
            s += (uint)proto + (uint)len;
            return s;
        }

        void Send(byte[] dst, int dstAt, int ethertype, byte[] payload) {
            var frame = new byte[14 + payload.Length];
            Array.Copy(dst, dstAt, frame, 0, 6);
            Array.Copy(HostMac, 0, frame, 6, 6);
            Put16(frame, 12, ethertype);
            Array.Copy(payload, 0, frame, 14, payload.Length);
            var msg = new byte[4 + frame.Length];
            msg[0] = (byte)(frame.Length >> 24); msg[1] = (byte)(frame.Length >> 16);
            msg[2] = (byte)(frame.Length >> 8); msg[3] = (byte)frame.Length;
            Array.Copy(frame, 0, msg, 4, frame.Length);
            lock (sendLock) conn.SendAll(msg);
        }

        byte[] Ipv4(int proto, byte[] dst, int dstAt, byte[] payload) {
            var p = new byte[20 + payload.Length];
            p[0] = 0x45;
            Put16(p, 2, p.Length);
            Put16(p, 6, 0x4000);
            p[8] = 64;
            p[9] = (byte)proto;
            Array.Copy(HostIp, 0, p, 12, 4);
            Array.Copy(dst, dstAt, p, 16, 4);
            Put16(p, 10, Csum(p, 0, 20, 0));
            Array.Copy(payload, 0, p, 20, payload.Length);
            return p;
        }

        void Handle(byte[] f) {
            int ethertype = Be16(f, 12);
            const int B = 14; // start of the Ethernet payload
            if (ethertype == 0x0806) {
                int op = Be16(f, B + 6);
                if (op == 1 && Eq(f, B + 24, HostIp)) {
                    Arp++;
                    var reply = new byte[28];
                    Array.Copy(f, B, reply, 0, 6);          // hardware/protocol types, sizes
                    Put16(reply, 6, 2);                      // reply
                    Array.Copy(HostMac, 0, reply, 8, 6);     // sender: us
                    Array.Copy(HostIp, 0, reply, 14, 4);
                    Array.Copy(f, B + 8, reply, 18, 10);     // target: the asker
                    Send(f, 6, 0x0806, reply);
                }
                return;
            }
            if (ethertype != 0x0800) return;
            int ihl = (f[B] & 0xf) * 4;
            int total = Be16(f, B + 2);
            if (B + total > f.Length || total < ihl) { lock (Bad) Bad.Add("IPv4 length " + total + " in a " + f.Length + "-byte frame"); return; }
            if (Csum(f, B, ihl, 0) != 0) { lock (Bad) Bad.Add("IPv4 header checksum in " + HexHead(f)); return; }
            if (!Eq(f, B + 16, HostIp)) return;
            int proto = f[B + 9];
            int l4 = B + ihl;
            int l4len = total - ihl;
            if (proto == 1 && f[l4] == 8) {
                if (Csum(f, l4, l4len, 0) != 0) { lock (Bad) Bad.Add("ICMP checksum in " + HexHead(f)); return; }
                Icmp++;
                var icmp = new byte[l4len];
                Array.Copy(f, l4, icmp, 0, l4len);
                icmp[0] = 0; icmp[1] = 0; icmp[2] = 0; icmp[3] = 0;
                Put16(icmp, 2, Csum(icmp, 0, icmp.Length, 0));
                Send(f, 6, 0x0800, Ipv4(1, f, B + 12, icmp));
            } else if (proto == 17) {
                int sport = Be16(f, l4), dport = Be16(f, l4 + 2), ulen = Be16(f, l4 + 4), ck = Be16(f, l4 + 6);
                if (ulen < 8 || ulen > l4len) { lock (Bad) Bad.Add("UDP length " + ulen); return; }
                if (ck == 0 || Csum(f, l4, ulen, Pseudo(f, B + 12, f, B + 16, 17, ulen)) != 0) {
                    lock (Bad) Bad.Add("UDP checksum " + ck.ToString("x4") + " in " + HexHead(f));
                    return;
                }
                if (dport == 9) {
                    // The discard port: what the guest sends, timed (net
                    // rate limiters).
                    var sink = Sink;
                    if (sink != null) lock (sink) sink.Add(new long[] { Stopwatch.GetTimestamp(), ulen - 8 });
                    return;
                }
                if (dport != 7) return;
                Udp++;
                var udp = new byte[ulen];
                Array.Copy(f, l4, udp, 0, ulen);
                Put16(udp, 0, 7);
                Put16(udp, 2, sport);
                Put16(udp, 6, 0);
                int c = Csum(udp, 0, ulen, Pseudo(HostIp, 0, f, B + 12, 17, ulen));
                Put16(udp, 6, c == 0 ? 0xffff : c);
                Send(f, 6, 0x0800, Ipv4(17, f, B + 12, udp));
            }
        }

        // Datagrams the guest sent to the host's port 9 while set: each its
        // arrival (Stopwatch ticks) and its payload bytes.
        public volatile List<long[]> Sink;

        public static readonly byte[] GuestIp = { 10, 0, 0, 2 };
        Thread flooder;
        volatile bool flooding;
        long flooded;

        // Sends UDP datagrams of 1400 bytes to the guest's port 9 as fast as
        // the endpoint takes them, until StopFlood; returns at once.
        public void StartFlood(byte[] guestMac) {
            flooding = true;
            flooded = 0;
            flooder = new Thread(() => {
                var udp = new byte[8 + 1400];
                Put16(udp, 0, 9999);
                Put16(udp, 2, 9);
                Put16(udp, 4, udp.Length);
                int c = Csum(udp, 0, udp.Length, Pseudo(HostIp, 0, GuestIp, 0, 17, udp.Length));
                Put16(udp, 6, c == 0 ? 0xffff : c);
                var ip = Ipv4(17, GuestIp, 0, udp);
                try {
                    while (flooding) {
                        Send(guestMac, 0, 0x0800, ip);
                        Interlocked.Add(ref flooded, udp.Length - 8);
                    }
                } catch (Exception) { }
            });
            flooder.IsBackground = true;
            flooder.Start();
        }

        // Stops the flood; returns the payload bytes it sent.
        public long StopFlood() {
            flooding = false;
            if (flooder != null) flooder.Join(5000);
            return Interlocked.Read(ref flooded);
        }

        public void Close() {
            stop = true;
            flooding = false;
            t.Join(2000);
            conn.Dispose();
        }
    }

    // WHvGetCapability (WinHvPlatform.dll; Microsoft Learn, WHvGetCapability):
    // whether this host can run a WHP partition, asked the way wick does, and
    // for the host's line the capabilities a guest's clock and timer rest on.
    // One class: a second `Whp` in this Add-Type block does not compile.
    public static class Whp {
        [DllImport("WinHvPlatform.dll")]
        static extern int WHvGetCapability(int code, out long value, int size, out int written);

        // The value (its 8 bytes, unsigned), or null with `why` the HRESULT
        // or the exception.
        public static ulong? Capability(int code, out string why) {
            why = null;
            try {
                long v; int n;
                int hr = WHvGetCapability(code, out v, 8, out n);
                if (hr < 0) { why = string.Format("HRESULT 0x{0:x8}", hr); return null; }
                return unchecked((ulong)v);
            } catch (Exception e) { why = e.GetType().Name + ": " + e.Message; return null; }
        }

        // null when available, otherwise why not.
        public static string Unavailable() {
            try {
                long present;
                int written;
                int hr = WHvGetCapability(0, out present, 8, out written); // WHvCapabilityCodeHypervisorPresent
                if (hr != 0) return "WHvGetCapability failed: HRESULT 0x" + hr.ToString("x8");
                if (present == 0)
                    return "the Windows hypervisor is not running (virtualization off in the firmware, " +
                        "or no nested virtualization in a VM, or hypervisorlaunchtype off in bcdedit)";
                return null;
            } catch (DllNotFoundException) {
                return "WinHvPlatform.dll is missing: the Windows Hypervisor Platform feature is not turned on";
            } catch (EntryPointNotFoundException) {
                return "WinHvPlatform.dll has no WHvGetCapability (Windows too old)";
            }
        }
    }

    // -SelfTest: the helpers against stand-ins for Firecracker's sockets, so
    // the harness can be checked on any Windows host, without WHP.
    public static class SelfTest {
        static readonly byte[] GuestMac = { 0x06, 0x00, 0x0a, 0x00, 0x00, 0x02 };
        static readonly byte[] GuestIp = { 10, 0, 0, 2 };

        static void Check(bool ok, string what) { if (!ok) throw new Failure(what); }

        static void Put16(byte[] b, int at, int v) { b[at] = (byte)(v >> 8); b[at + 1] = (byte)v; }

        static byte[] Eth(int ethertype, byte[] payload) {
            var f = new byte[14 + payload.Length];
            for (int i = 0; i < 6; i++) f[i] = 0xff;
            Array.Copy(GuestMac, 0, f, 6, 6);
            Put16(f, 12, ethertype);
            Array.Copy(payload, 0, f, 14, payload.Length);
            return f;
        }

        static byte[] Ip(int proto, byte[] l4) {
            var p = new byte[20 + l4.Length];
            p[0] = 0x45; Put16(p, 2, p.Length); p[8] = 64; p[9] = (byte)proto;
            Array.Copy(GuestIp, 0, p, 12, 4);
            Array.Copy(Switch.HostIp, 0, p, 16, 4);
            Put16(p, 10, Switch.Csum(p, 0, 20, 0));
            Array.Copy(l4, 0, p, 20, l4.Length);
            return p;
        }

        static byte[] Udp(int sport, int dport, byte[] data, bool goodChecksum) {
            var u = new byte[8 + data.Length];
            Put16(u, 0, sport); Put16(u, 2, dport); Put16(u, 4, u.Length);
            Array.Copy(data, 0, u, 8, data.Length);
            uint pseudo = (uint)((10 << 8) + 0 + (0 << 8) + 2 + (10 << 8) + 0 + (0 << 8) + 1 + 17 + u.Length);
            int c = Switch.Csum(u, 0, u.Length, pseudo);
            Put16(u, 6, goodChecksum ? (c == 0 ? 0xffff : c) : (c ^ 0x5a5a));
            return u;
        }

        static void SendFrame(USock c, byte[] frame, bool trickle) {
            var msg = new byte[4 + frame.Length];
            msg[0] = (byte)(frame.Length >> 24); msg[1] = (byte)(frame.Length >> 16);
            msg[2] = (byte)(frame.Length >> 8); msg[3] = (byte)frame.Length;
            Array.Copy(frame, 0, msg, 4, frame.Length);
            if (!trickle) { c.SendAll(msg); return; }
            // One byte at a time: the switch must reassemble the stream.
            for (int i = 0; i < msg.Length; i++) { c.SendAll(msg, i, 1); if (i < 8) Thread.Sleep(20); }
        }

        static byte[] RecvFrame(USock c) {
            var hdr = new byte[4];
            c.RecvExact(hdr, 0, 4, 5000);
            int len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
            var f = new byte[len];
            c.RecvExact(f, 0, len, 5000);
            return f;
        }

        static int Be16(byte[] b, int at) { return (b[at] << 8) | b[at + 1]; }

        public static string SwitchTest(string dir) {
            string ep = Path.Combine(dir, "st.ep");
            var listener = USock.Listen(ep);
            var sw = new Switch(ep, 5000);
            try {
                using (var c = listener.Accept(5000)) {
                    // ARP who-has 10.0.0.1.
                    var arp = new byte[28];
                    Put16(arp, 0, 1); Put16(arp, 2, 0x0800); arp[4] = 6; arp[5] = 4; Put16(arp, 6, 1);
                    Array.Copy(GuestMac, 0, arp, 8, 6); Array.Copy(GuestIp, 0, arp, 14, 4);
                    Array.Copy(Switch.HostIp, 0, arp, 24, 4);
                    SendFrame(c, Eth(0x0806, arp), true);
                    var r = RecvFrame(c);
                    Check(Be16(r, 12) == 0x0806 && Be16(r, 20) == 2, "ARP reply expected");
                    for (int i = 0; i < 6; i++) Check(r[i] == GuestMac[i] && r[22 + i] == Switch.HostMac[i], "ARP reply addresses");
                    for (int i = 0; i < 4; i++) Check(r[28 + i] == Switch.HostIp[i] && r[38 + i] == GuestIp[i], "ARP reply IPs");

                    // ICMP echo, 1400 bytes of payload.
                    var icmp = new byte[8 + 1400];
                    icmp[0] = 8; Put16(icmp, 4, 0x1234); Put16(icmp, 6, 1);
                    for (int i = 8; i < icmp.Length; i++) icmp[i] = (byte)i;
                    Put16(icmp, 2, Switch.Csum(icmp, 0, icmp.Length, 0));
                    SendFrame(c, Eth(0x0800, Ip(1, icmp)), false);
                    r = RecvFrame(c);
                    Check(Be16(r, 12) == 0x0800 && r[23] == 1, "ICMP reply expected");
                    Check(Switch.Csum(r, 14, 20, 0) == 0, "reply IPv4 header checksum");
                    Check(r[34] == 0 && Switch.Csum(r, 34, r.Length - 34, 0) == 0, "ICMP echo reply checksum");
                    Check(r.Length == 14 + 20 + icmp.Length && r[34 + 100] == icmp[100], "ICMP reply payload");

                    // UDP echo on port 7.
                    var data = Encoding.ASCII.GetBytes("udp-42\n");
                    SendFrame(c, Eth(0x0800, Ip(17, Udp(40000, 7, data, true))), false);
                    r = RecvFrame(c);
                    Check(r[23] == 17 && Be16(r, 34) == 7 && Be16(r, 36) == 40000, "UDP reply ports");
                    uint pseudo = (uint)((10 << 8) + 1 + (10 << 8) + 2 + 17 + Be16(r, 38));
                    Check(Switch.Csum(r, 34, Be16(r, 38), pseudo) == 0, "UDP reply checksum");
                    Check(Encoding.ASCII.GetString(r, 42, data.Length) == "udp-42\n", "UDP reply data");

                    // A bad checksum is reported, not answered.
                    SendFrame(c, Eth(0x0800, Ip(17, Udp(40000, 7, data, false))), false);
                    // An IPv6 frame is ignored.
                    SendFrame(c, Eth(0x86dd, new byte[40]), false);
                    var until = DateTime.UtcNow.AddSeconds(5);
                    while (sw.Frames < 5 && DateTime.UtcNow < until) Thread.Sleep(20);
                    Check(sw.Frames == 5, "switch saw " + sw.Counts);
                    Check(sw.Bad.Count == 1 && sw.Bad[0].StartsWith("UDP checksum"), "bad-checksum report: " + string.Join("; ", sw.Bad.ToArray()));
                    Check(!c.Poll(300), "no reply to a frame with a bad checksum");
                    Check(sw.Arp == 1 && sw.Icmp == 1 && sw.Udp == 1, "switch counts " + sw.Counts);
                }
                return "switch: ARP, ICMP 1400 B, UDP echo, checksums, framing byte by byte, bad checksum reported (" + sw.Counts + ")";
            } finally {
                sw.Close();
                listener.Dispose();
                try { File.Delete(ep); } catch (Exception) { }
            }
        }

        public static string VsockTest(string dir) {
            string uds = Path.Combine(dir, "st.v");
            var listener = USock.Listen(uds);
            int connections = 0;
            var server = new Thread(delegate() {
                try {
                    while (true) {
                        var c = listener.Accept(30000);
                        connections++;
                        var line = new StringBuilder();
                        var one = new byte[1];
                        while (!line.ToString().EndsWith("\n") && c.Recv(one, 0, 1, 5000) == 1) line.Append((char)one[0]);
                        // The first two connections: nothing listens in the guest yet.
                        if (connections <= 2 || line.ToString() != "CONNECT 52\n") { c.Dispose(); continue; }
                        c.SendAll(Encoding.ASCII.GetBytes("OK 1073741824\n"));
                        var buf = new byte[65536];
                        int n;
                        while ((n = c.Recv(buf, 0, buf.Length, 5000)) > 0) c.SendAll(buf, 0, n);
                        c.Dispose();
                    }
                } catch (Exception) { }
            });
            server.IsBackground = true;
            server.Start();
            try {
                Vsock.WaitListening(uds, 52, 10000);
                Check(connections == 3, "connections until OK: " + connections);
                Vsock.Echo(uds, 52, 4 << 20);

                var collector = new Collector(uds + "_53", 10000);
                using (var g = USock.Connect(uds + "_53")) g.SendAll(Encoding.ASCII.GetBytes("guest-to-host-42\n"));
                string got = collector.Finish(10000);
                Check(got == "guest-to-host-42\n", "collector got '" + got + "'");
                return "vsock: retry until OK, 4 MiB echo by length; guest->host collector";
            } finally {
                listener.Dispose();
                try { File.Delete(uds); } catch (Exception) { }
            }
        }

        // Api.Call against a stand-in for Firecracker's API server, which
        // answers in two writes as micro_http may.
        public static string ApiTest(string dir) {
            string sock = Path.Combine(dir, "st.api");
            var listener = USock.Listen(sock);
            var requests = new List<string>();
            var server = new Thread(delegate() {
                try {
                    for (int i = 0; i < 2; i++) {
                        var c = listener.Accept(10000);
                        var req = new StringBuilder();
                        var buf = new byte[4096];
                        int n;
                        while (true) {
                            n = c.Recv(buf, 0, buf.Length, 5000);
                            if (n <= 0) break;
                            req.Append(Encoding.UTF8.GetString(buf, 0, n));
                            string r = req.ToString();
                            int end = r.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                            if (end < 0) continue;
                            var m = Regex.Match(r, @"(?im)^content-length:\s*(\d+)");
                            int len = m.Success ? int.Parse(m.Groups[1].Value) : 0;
                            if (Encoding.UTF8.GetByteCount(r) >= end + 4 + len) break;
                        }
                        lock (requests) requests.Add(req.ToString());
                        if (i == 0) {
                            c.SendAll(Encoding.ASCII.GetBytes("HTTP/1.1 204 \r\nServer: Firecracker API\r\n\r\n"));
                        } else {
                            string body = "{\"fault_message\":\"bad\"}";
                            c.SendAll(Encoding.ASCII.GetBytes("HTTP/1.1 400 \r\nContent-Type: application/json\r\nContent-Length: " + body.Length + "\r\n\r\n"));
                            Thread.Sleep(50);
                            c.SendAll(Encoding.ASCII.GetBytes(body));
                        }
                        c.Dispose();
                    }
                } catch (Exception) { }
            });
            server.IsBackground = true;
            server.Start();
            try {
                int status;
                string body = Api.Call(sock, "PATCH", "/vm", "{\"state\":\"Paused\"}", 10000, out status);
                Check(status == 204 && body == "", "204: " + status + " '" + body + "'");
                body = Api.Call(sock, "GET", "/", null, 10000, out status);
                Check(status == 400 && body == "{\"fault_message\":\"bad\"}", "400: " + status + " '" + body + "'");
                server.Join(5000);
                Check(requests.Count == 2, "requests: " + requests.Count);
                Check(requests[0].StartsWith("PATCH /vm HTTP/1.1\r\n") && requests[0].Contains("Content-Length: 18\r\n") && requests[0].EndsWith("{\"state\":\"Paused\"}"), "request: " + requests[0]);
                Check(!requests[1].Contains("Content-Length"), "GET with a body: " + requests[1]);
                return "Api: request with a body, status, body read by Content-Length across writes";
            } finally {
                listener.Dispose();
                try { File.Delete(sock); } catch (Exception) { }
            }
        }
    }
}
'@

# Named pipes and sparse files (System.Core: System.IO.Pipes).
Add-Type -ReferencedAssemblies System.Core -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Wick {
    // The reading end of a named pipe Firecracker writes its log or metrics
    // to (\\.\pipe\<name>): the Windows counterpart of a FIFO. The pipe
    // exists from here on; Firecracker connects to it as a client. With
    // `read` false nobody reads it (a reader that stalls). The pipe is
    // opened for overlapped I/O: on a handle opened for synchronous I/O
    // the system runs one request at a time (Microsoft Learn,
    // "Synchronous and Asynchronous I/O"), so Close's DisconnectNamedPipe
    // waited for the reading thread's ReadFile, which returns only when
    // the client writes. In the cli stage the log pipe's Close so waited
    // until Firecracker logged again: its "Failed to write metrics" once
    // the periodic metrics (every 60 s, ~5.6 KiB each) had filled the
    // metrics pipe's 64 KiB with no reader, about 13 minutes, after which
    // FlushMetrics was refused (would block), as on Linux with a FIFO
    // full. A PC's runs took 789 s there.
    public class PipeReader {
        NamedPipeServerStream s;
        StringBuilder text = new StringBuilder();
        Thread t;
        public readonly string Path;
        public PipeReader(string name, bool read, int buffer) {
            Path = @"\\.\pipe\" + name;
            s = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, buffer, buffer);
            t = new Thread(() => {
                try {
                    s.WaitForConnection();
                    if (!read) return;
                    var buf = new byte[65536];
                    int n;
                    while ((n = s.Read(buf, 0, buf.Length)) > 0) {
                        lock (text) text.Append(Encoding.UTF8.GetString(buf, 0, n));
                    }
                } catch (Exception) { }
            });
            t.IsBackground = true;
            t.Start();
        }
        public bool Connected { get { return s.IsConnected; } }
        public string Text { get { lock (text) return text.ToString(); } }
        // Waits until `pattern` is in what was read; false at the deadline.
        public bool WaitFor(string pattern, int ms) {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (DateTime.UtcNow < until) {
                if (System.Text.RegularExpressions.Regex.IsMatch(Text, pattern)) return true;
                Thread.Sleep(50);
            }
            return false;
        }
        public bool WaitConnected(int ms) {
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (!s.IsConnected && DateTime.UtcNow < until) Thread.Sleep(20);
            return s.IsConnected;
        }
        // The reader goes away while Firecracker still writes, at once:
        // a read the thread has pending ends with the pipe.
        public void Close() {
            try { if (s.IsConnected) s.Disconnect(); } catch (Exception) { }
            try { s.Dispose(); } catch (Exception) { }
            t.Join(2000);
        }
    }

    public static class Sparse {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inb, int inl, IntPtr outb, int outl, out int ret, IntPtr ov);
        const uint FSCTL_SET_SPARSE = 0x900C4;

        public static bool Is(string path) {
            return (File.GetAttributes(path) & FileAttributes.SparseFile) != 0;
        }
        // A file of `size` bytes with `data` at `at`: sparse (the rest is a
        // hole), or not (the rest is allocated zeros, as NTFS extends a file
        // not marked sparse).
        public static void Write(string path, long size, byte[] data, long at, bool sparse) {
            using (var f = new FileStream(path, FileMode.Create, FileAccess.ReadWrite)) {
                if (sparse) {
                    int r;
                    if (!DeviceIoControl(f.SafeFileHandle.DangerousGetHandle(), FSCTL_SET_SPARSE, IntPtr.Zero, 0, IntPtr.Zero, 0, out r, IntPtr.Zero))
                        throw new InvalidOperationException("FSCTL_SET_SPARSE " + path + ": error " + Marshal.GetLastWin32Error());
                }
                f.SetLength(size);
                f.Position = at;
                f.Write(data, 0, data.Length);
            }
        }
        // Bytes that differ between two files of the same length (-1: lengths differ).
        public static long Differ(string a, string b) {
            byte[] x = File.ReadAllBytes(a), y = File.ReadAllBytes(b);
            if (x.Length != y.Length) return -1;
            long n = 0;
            for (int i = 0; i < x.Length; i++) if (x[i] != y[i]) n++;
            return n;
        }
    }

    // What Firecracker gives a drive as its serial (VIRTIO_BLK_GET_ID) on
    // Windows: the file's volume serial number and NTFS file index as one
    // number, in 20 base-32 digits (vmm platform::fs::device_id).
    public static class DriveId {
        // BY_HANDLE_FILE_INFORMATION (fileapi.h): every FILETIME is two
        // DWORDs, so the structure is 52 bytes with no padding. (A `long`
        // for a FILETIME makes the CLR align it to 8 and read every field
        // after Attributes 4 bytes off.)
        [StructLayout(LayoutKind.Sequential)]
        struct Info {
            public uint Attributes;
            public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(IntPtr h, out Info info);

        // FILE_ID_INFO (winbase.h): a 64-bit volume serial number and a
        // 128-bit file id, the reference -SelfTest checks Of against.
        [StructLayout(LayoutKind.Sequential)]
        struct IdInfo {
            public ulong VolumeSerial;
            public ulong IdLow, IdHigh;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(IntPtr h, int infoClass, out IdInfo info, uint size);
        const int FileIdInfo = 0x12;

        static FileStream Open(string path) {
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }

        public static string Of(string path) {
            Info info;
            using (var f = Open(path)) {
                if (!GetFileInformationByHandle(f.SafeFileHandle.DangerousGetHandle(), out info))
                    throw new InvalidOperationException("GetFileInformationByHandle " + path + ": error " + Marshal.GetLastWin32Error());
            }
            return Encode(info.VolumeSerial, ((ulong)info.IndexHigh << 32) | info.IndexLow);
        }

        // The volume serial number and the file id from FILE_ID_INFO, for
        // the self-test (NTFS: the file index is the id's low 64 bits).
        public static ulong[] Reference(string path) {
            IdInfo info;
            using (var f = Open(path)) {
                if (!GetFileInformationByHandleEx(f.SafeFileHandle.DangerousGetHandle(), FileIdInfo, out info, (uint)Marshal.SizeOf(typeof(IdInfo))))
                    throw new InvalidOperationException("GetFileInformationByHandleEx " + path + ": error " + Marshal.GetLastWin32Error());
            }
            return new ulong[] { info.VolumeSerial, info.IdLow, info.IdHigh };
        }

        public static string Encode(ulong volume, ulong index) {
            const string digits = "0123456789abcdefghijklmnopqrstuv";
            var sb = new StringBuilder();
            for (int d = 19; d >= 0; d--) {
                int v = 0;
                for (int b = 4; b >= 0; b--) {
                    int bit = 5 * d + b;
                    ulong word = bit < 64 ? index >> bit : (bit < 128 ? volume >> (bit - 64) : 0);
                    v = (v << 1) | (int)(word & 1);
                }
                sb.Append(digits[v]);
            }
            return sb.ToString();
        }
    }

    public static class PipeSelfTest {
        // A client writes to the reader's pipe, as Firecracker's logger does.
        public static string Run() {
            var r = new PipeReader("wick-bt-self-" + System.Diagnostics.Process.GetCurrentProcess().Id, true, 4096);
            try {
                using (var c = new NamedPipeClientStream(".", r.Path.Substring(9), PipeDirection.InOut)) {
                    c.Connect(5000);
                    var b = Encoding.UTF8.GetBytes("line one\nline two\n");
                    c.Write(b, 0, b.Length);
                    c.Flush();
                    if (!r.WaitFor("line two", 5000)) throw new InvalidOperationException("pipe reader got '" + r.Text + "'");
                }
            } finally { r.Close(); }
            // Close while the reading thread waits for a client that writes
            // nothing: it returns at once, and the client's next write fails
            // (the pipe has gone), as Firecracker's does when its reader goes.
            r = new PipeReader("wick-bt-self-close-" + System.Diagnostics.Process.GetCurrentProcess().Id, true, 4096);
            using (var c = new NamedPipeClientStream(".", r.Path.Substring(9), PipeDirection.InOut)) {
                c.Connect(5000);
                Thread.Sleep(200);
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var closer = new Thread(() => r.Close());
                closer.IsBackground = true;
                closer.Start();
                if (!closer.Join(5000)) throw new InvalidOperationException("PipeReader.Close() still waits after 5 s for a client that writes nothing");
                long ms = sw.ElapsedMilliseconds;
                bool failed = false;
                try { var b = Encoding.UTF8.GetBytes("late\n"); c.Write(b, 0, b.Length); c.Flush(); } catch (System.IO.IOException) { failed = true; }
                if (!failed) throw new InvalidOperationException("a client's write after the reader's Close() did not fail");
                return "PipeReader: a client's writes are read; Close() with a silent client returns in " + ms + " ms and the client's next write fails";
            }
        }
    }
}
'@

# A step of a stage, with the time since the stage began ($StageClock), so
# a run says which of its steps took the time.
$script:StageClock = $null
function Write-Step([string]$msg) {
    $at = if ($script:StageClock) { '[{0:N1} s] ' -f $script:StageClock.Elapsed.TotalSeconds } else { '' }
    Write-Host "  - $at$msg"
}

function Get-Asset([string]$name) {
    $path = Join-Path $WorkDir $name
    if (-not (Test-Path $path)) {
        Write-Step "downloading $name"
        Invoke-WebRequest -UseBasicParsing -Uri "$S3/$Prefix/$name" -OutFile "$path.part"
        Move-Item "$path.part" $path -Force
    }
    return $path
}

function Find-Firecracker {
    if ($Firecracker) { return (Resolve-Path $Firecracker).Path }
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $candidates = @(
        (Join-Path $PSScriptRoot 'firecracker.exe'),
        (Join-Path $root 'lib\firecracker\build\cargo_target\release\firecracker.exe'),
        (Join-Path $root 'lib\firecracker\build\cargo_target\debug\firecracker.exe')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw "firecracker.exe not found; pass -Firecracker <path> (looked in: $($candidates -join ', '))"
}

function Fail([string]$why) { throw (New-Object Wick.Failure $why) }
function Check([bool]$ok, [string]$why) { if (-not $ok) { Fail $why } }

# A stage's summary: what its block returns, which must be one string. A
# PowerShell function returns every value a statement leaves uncaptured, so
# a second value is a result the stage dropped unread (Test-CpuOfflineOnline's
# count, once, which put a "0" before the cpu-templates summary). A
# stage runs in a scope below this function's and can read its variables,
# so they have names no stage uses.
function Get-StageSummary([scriptblock]$stageBlock) {
    $stageOut = @(& $stageBlock)
    if ($stageOut.Count -ne 1 -or $stageOut[0] -isnot [string]) {
        $shown = @($stageOut | Select-Object -First 4 | ForEach-Object { "[$(if ($null -eq $_) { 'null' } else { $_.GetType().Name })] '$_'" }) -join ', '
        Fail "script error: the stage returned $($stageOut.Count) values, not one summary: $shown"
    }
    return $stageOut[0]
}

# The Wick.Failure behind an error record (PowerShell wraps exceptions thrown
# by .NET methods in MethodInvocationException), or $null.
function Get-Failure($record) {
    $e = $record.Exception
    while ($e) {
        if ($e -is [Wick.Failure]) { return $e }
        $e = $e.InnerException
    }
    return $null
}

function Base-Config([int]$vcpus, [int]$mem = 256, [string]$bootArgs = $BootArgs) {
    return [ordered]@{
        'boot-source'    = [ordered]@{ kernel_image_path = $Kernel; boot_args = $bootArgs }
        'drives'         = @([ordered]@{ drive_id = 'rootfs'; path_on_host = $Rootfs; is_root_device = $true; is_read_only = $true })
        'machine-config' = [ordered]@{ vcpu_count = $vcpus; mem_size_mib = $mem }
    }
}

# Starts Firecracker for stage `$name` with `$config`; the VM is killed and its
# logs kept when the stage ends.
# `$config` may be $null (a VM restored through the API). With -Api the VM gets
# an API socket, returned as the `ApiSock` note property and waited for.
# -LogPath gives Firecracker another --log-path (a named pipe) than the
# stage's file.
# The patterns of tools/guest-health.txt for the guest `$arch`, read as the
# file's header says, by the rules tools/linux/boot-test.sh's guest_health
# and tools/macos/boot-test.py's read it with: a line that is empty or
# starts with '#' is a comment; any other is "<arch> <pattern>", <arch> one
# of all, x86_64, aarch64 (case counts), <pattern> the rest, not empty, no
# space at either end, and no tab, CR or single quote in the line. Any
# other line stops the run, naming it; so does a file with no pattern for
# `$arch`. The lines are split at LF alone, as the others split them (the
# repository keeps the file LF: .gitattributes).
function Read-GuestHealth([string]$path, [string]$arch) {
    Check (Test-Path -LiteralPath $path) "no $path, the guest's health patterns (the kit has it as tools\guest-health.txt)"
    $text = [IO.File]::ReadAllText($path, (New-Object Text.UTF8Encoding($false)))
    $patterns = @()
    $n = 0
    foreach ($line in $text.Split([char]10)) {
        $n++
        if ($line.Length -eq 0 -or $line[0] -ceq '#') { continue }
        $sp = $line.IndexOf(' ')
        $name = if ($sp -ge 0) { $line.Substring(0, $sp) } else { $line }
        $pattern = if ($sp -ge 0) { $line.Substring($sp + 1) } else { '' }
        if ($sp -lt 0 -or $pattern.Length -eq 0 -or $pattern -cne $pattern.Trim(' ') -or
            $line.IndexOfAny([char[]]@([char]9, [char]13, [char]39)) -ge 0 -or
            @('all', 'x86_64', 'aarch64') -cnotcontains $name) {
            Fail "${path}:${n}: not a comment or <arch> <pattern>: $($line -replace "`r", '\r' -replace "`t", '\t')"
        }
        if ($name -ceq 'all' -or $name -ceq $arch) { $patterns += $pattern }
    }
    Check ($patterns.Count -gt 0) "$path has no pattern for $arch"
    return ,$patterns
}

# A socket's path in $SockDir, for a name within the bound the start
# checked the directory against ($SockName bytes). Every caller passes a
# string constant, so the bound is the longest of them, read from this
# script (Get-SockNames); -SelfTest's socknames case holds them to that.
function Get-SockPath([string]$name) {
    Check ([Text.Encoding]::UTF8.GetByteCount($name) -le $SockName) "the socket name $name is longer than $SockName bytes, which the socket directory's bound assumes"
    return (Join-Path $SockDir $name)
}

# Start-Vm's API sockets are numbered, "<n>.api", n from 1 to $ApiSockMax,
# not named after their VM: a VM's name is made by its stage, in loops too,
# and has no bound of its own ('cli-module-firecracker.api', 26 bytes, was
# over the 24 assumed before). The VM's directory keeps its socket's path
# (api-sock.txt).
$ApiSockMax = 999
$script:ApiSockSeq = 0
function Get-ApiSockPath {
    $script:ApiSockSeq++
    Check ($script:ApiSockSeq -le $ApiSockMax) "more than $ApiSockMax API sockets in one run"
    return (Join-Path $SockDir "$($script:ApiSockSeq).api")
}

# The socket names the script `$path` uses: the argument of each
# Get-SockPath call, which must be a string constant, and the longest API
# socket name. Names = the names; Bad = the calls whose argument is not one
# string constant, each as "line N: text".
function Get-SockNames([string]$path) {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    if ($errors -and $errors.Count) { throw "${path}: does not parse: $($errors[0].Message)" }
    $calls = $ast.FindAll({
        param($a)
        $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Get-SockPath'
    }, $true)
    $names = @("$ApiSockMax.api")
    $bad = @()
    foreach ($c in $calls) {
        $given = @($c.CommandElements | Select-Object -Skip 1)
        if ($given.Count -eq 1 -and $given[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $names += $given[0].Value
        } else {
            $bad += "line $($c.Extent.StartLineNumber): $($c.Extent.Text)"
        }
    }
    return @{ Names = $names; Bad = $bad }
}

# The bound of `$names`: the most UTF-8 bytes of any.
function Get-SockBound([string[]]$names) {
    return [int]($names | ForEach-Object { [Text.Encoding]::UTF8.GetByteCount($_) } | Measure-Object -Maximum).Maximum
}

function Start-Vm([string]$name, $config, [string]$extra = '', [switch]$Api, [string]$LogPath = '') {
    $dir = Join-Path $Results $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if ($LogPath) {
        $logPath = $LogPath
    } else {
        $logPath = Join-Path $dir 'firecracker.log'
        # Firecracker opens the log file, it does not create it.
        New-Item -ItemType File -Force -Path $logPath | Out-Null
    }
    $fcArgs = "--log-path `"$logPath`" --level Debug --show-level --show-log-origin"
    if ($config) {
        $cfgPath = Join-Path $dir 'vm-config.json'
        $config | ConvertTo-Json -Depth 8 | Set-Content -Encoding ASCII $cfgPath
        $fcArgs += " --config-file `"$cfgPath`""
    }
    $sock = $null
    if ($Api) {
        $sock = Get-ApiSockPath
        Set-Content -Encoding UTF8 (Join-Path $dir 'api-sock.txt') $sock
        if (Test-Path $sock) { [IO.File]::Delete($sock) }
        $fcArgs += " --api-sock `"$sock`""
    } else {
        $fcArgs += ' --no-api'
    }
    if ($extra) { $fcArgs += " $extra" }
    $vm = New-Object Wick.Vm($Fc, $fcArgs, (Join-Path $dir 'console.txt'))
    $script:Vms += $vm
    if ($sock) {
        $until = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path $sock)) {
            if ($vm.Exited -or [DateTime]::UtcNow -gt $until) { Fail "no API socket ($($vm.ExitReason()))" }
            Start-Sleep -Milliseconds 20
        }
    }
    $vm | Add-Member -NotePropertyName ApiSock -NotePropertyValue $sock
    $vm | Add-Member -NotePropertyName LogPath -NotePropertyValue $logPath
    $vm | Add-Member -NotePropertyName StageName -NotePropertyValue $name
    return $vm
}

# One API request; fails unless the status is 2xx. Returns the body.
function Invoke-Api($vm, [string]$method, [string]$path, $body = $null) {
    Check ([bool]$vm.ApiSock) "$method $path`: the VM was started without -Api"
    $json = if ($null -ne $body) { $body | ConvertTo-Json -Depth 8 -Compress } else { $null }
    $status = 0
    $out = [Wick.Api]::Call($vm.ApiSock, $method, $path, $json, 120000, [ref]$status)
    # The body names which request it was (PUT /actions: the action).
    $sent = if ($null -ne $json -and $json.Length -le 200) { " $json" } else { '' }
    Check ($status -ge 200 -and $status -lt 300) "$method $path$sent -> $status $out"
    return $out
}

function Get-Fields([string]$out) { return @($out -split '\s+' | Where-Object { $_ }) }

# What a restored guest must still have: its shell state, a clock that runs at
# host speed on every vCPU, its root drive and (if given) its data drive.
function Test-Restored($vm, [string]$bashMd5, [string]$data) {
    $out = $vm.Sh('echo restored $A')
    Check ($out -eq 'restored before-42') "after restore: '$out'"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = $vm.Sh('taskset -c 0 cat /proc/uptime; sleep 1; taskset -c 1 cat /proc/uptime')
    $host_dt = $sw.Elapsed.TotalSeconds
    $lines = @($out -split "`n" | Where-Object { $_.Trim() })
    Check ($lines.Count -eq 2) "uptime on both CPUs after restore: '$out'"
    $a = [double]::Parse((Get-Fields $lines[0])[0], [Globalization.CultureInfo]::InvariantCulture)
    $b = [double]::Parse((Get-Fields $lines[1])[0], [Globalization.CultureInfo]::InvariantCulture)
    Check (($b - $a) -gt 0.9 -and ($b - $a) -le $host_dt + 0.1) ("guest clock advanced {0:N2} s across vCPUs in {1:N2} s after restore" -f ($b - $a), $host_dt)
    $out = $vm.Sh('md5sum /usr/bin/bash')
    Check ($out -eq $bashMd5) "root drive after restore: '$out', before '$bashMd5'"
    if ($data) {
        $out = $vm.Sh('echo 3 > /proc/sys/vm/drop_caches; md5sum /dev/vdb')
        $want = [Wick.Util]::Md5File($data, -1)
        Check ((Get-Fields $out)[0] -eq $want) "data drive after restore: '$out', host $want"
    }
}

# Waits for init and the shell; explains a Firecracker that never got there.
function Wait-Shell($vm) {
    try {
        $vm.WaitFor('Run /bin/sh as init process', $TimeoutSec * 1000, 0) | Out-Null
    } catch {
        $f = Get-Failure $_
        if (-not $f) { throw }
        $why = $f.Message
        if ($WhpUnavailable) { $why = "Windows Hypervisor Platform not available: $WhpUnavailable. Firecracker: $why" }
        elseif (-not $vm.Exited) { $why += "`n" + (Get-StuckState $vm) }
        Fail "kernel did not reach init: $why"
    }
    $vm.Shell(60000)
}

# What a guest that stopped before init was doing, for the failure's
# message. On CI's EPYC 9V45 runner (run 43435331370) every stage's guest
# stopped about 0.3 s into its boot, its log's timestamps standing still,
# the SMP ones at "Booting SMP configuration": a clock that stopped and an
# interrupt that was lost look the same from the console. So the VM, if it
# has an API socket, is paused and snapshotted twice a second apart, each
# state read with snapshot-editor (info-vmstate vm-state, kept as
# stuck-<n>-vm-state.txt in the stage's directory), and the message gets:
# the VM clock and the guest TSC between the two (kvm_clock_data's clock,
# and host_tsc, which the backend fills with the guest TSC at that clock);
# for each vCPU its RIP and whether it moved, RFLAGS.IF, mp_state (an AP
# INIT and SIPI never reached stays 1, UNINITIALIZED, or 2,
# INIT_RECEIVED), its local APIC's timer (LVT timer, 0x320: masked, mode;
# initial count, 0x380; current count, 0x390; divide, 0x3e0) and the
# highest vector in its IRR (0x200) and ISR (0x100): one pending, not in
# service, with IF set, is an interrupt the guest did not get. The guest's
# MSRs (TSC, TSC deadline, kvm-clock's) are not in snapshot-editor's
# print. Anything that fails here is said in the message instead.
function Get-StuckState($vm) {
    if (-not $vm.ApiSock) { return '  (no API socket: the stuck guest''s state was not read)' }
    $name = $vm.StageName
    $dir = Join-Path $Results $name
    $states = @()
    $ticks = @()
    try {
        $editor = Find-Tool 'snapshot-editor.exe'
        foreach ($k in 1, 2) {
            if ($k -eq 2) { Start-Sleep -Seconds 1 }
            $state = Join-Path $dir "stuck-$k.state"
            $mem = Join-Path $Scratch "$name-stuck-$k.mem"
            Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
            $ticks += [Diagnostics.Stopwatch]::GetTimestamp()
            Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
            Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Resumed' } | Out-Null
            Remove-Item -Force -LiteralPath $mem -ErrorAction SilentlyContinue
            $r = Invoke-Exe $editor @('info-vmstate', 'vm-state', '--vmstate-path', $state)
            Set-Content -Encoding UTF8 (Join-Path $dir "stuck-$k-vm-state.txt") $r[1]
            Check ($r[0] -eq 0) "snapshot-editor info-vmstate vm-state: exit $($r[0])"
            $states += ,(Read-VmStateDump $r[1])
        }
    } catch {
        return "  (the stuck guest's state was not read: $($_.Exception.Message))"
    }
    return (Format-StuckState $states[0] $states[1] (($ticks[1] - $ticks[0]) / [double][Diagnostics.Stopwatch]::Frequency))
}

# The fields Get-StuckState prints, from snapshot-editor's Debug print of a
# MicrovmState: Clock and Tsc (or $null), and Vcpus, each with Rip, Rflags,
# MpState and Lapic (the 1024 bytes of kvm_lapic_state), each $null where
# the print has none.
function Read-VmStateDump([string]$text) {
    $one = {
        param($pattern, $in)
        $m = [regex]::Match($in, $pattern)
        if ($m.Success) { [UInt64]::Parse($m.Groups[1].Value) } else { $null }
    }
    $clock = & $one '(?m)^\s*clock: (\d+),\s*$' $text
    $tsc = & $one '(?m)^\s*host_tsc: (\d+),\s*$' $text
    $vcpus = @()
    $parts = [regex]::Split($text, 'VcpuState \{')
    foreach ($part in ($parts | Select-Object -Skip 1)) {
        $lapic = $null
        $m = [regex]::Match($part, 'kvm_lapic_state \{\s*regs: \[([-\d,\s]*)\]')
        if ($m.Success) {
            $lapic = [byte[]]@($m.Groups[1].Value -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { [byte]([int]$_ -band 0xff) })
            if ($lapic.Length -ne 1024) { $lapic = $null }
        }
        $vcpus += ,@{
            Rip = & $one '(?m)^\s*rip: (\d+),' $part
            Rflags = & $one '(?m)^\s*rflags: (\d+),' $part
            MpState = & $one 'kvm_mp_state \{\s*mp_state: (\d+),' $part
            Lapic = $lapic
        }
    }
    return @{ Clock = $clock; Tsc = $tsc; Vcpus = $vcpus }
}

# The lines of Get-StuckState from two states `$a` and `$b` read
# `$seconds` apart on the host.
function Format-StuckState($a, $b, [double]$seconds) {
    $u32 = { param($l, $o) [BitConverter]::ToUInt32($l, $o) }
    $top = {
        param($l, $base)
        for ($i = 7; $i -ge 0; $i--) {
            $w = [BitConverter]::ToUInt32($l, $base + 0x10 * $i)
            for ($bit = 31; $bit -ge 0; $bit--) { if ($w -band ([UInt32]1 -shl $bit)) { return '0x{0:x2}' -f (32 * $i + $bit) } }
        }
        return 'none'
    }
    $lines = @()
    $clock = if ($null -ne $a.Clock -and $null -ne $b.Clock) { '{0:N1} ms' -f (([double]$b.Clock - [double]$a.Clock) / 1e6) } else { 'not in the print' }
    $tsc = if ($null -ne $a.Tsc -and $null -ne $b.Tsc) { '{0:N0} ticks' -f ([double]$b.Tsc - [double]$a.Tsc) } else { 'not in the print' }
    $lines += ('  stuck guest, two snapshots {0:N2} s apart: VM clock +{1}, guest TSC +{2}' -f $seconds, $clock, $tsc)
    for ($i = 0; $i -lt [math]::Max($a.Vcpus.Count, $b.Vcpus.Count); $i++) {
        $x = $a.Vcpus[$i]; $y = $b.Vcpus[$i]
        if (-not $x -or -not $y) { $lines += "  vCPU ${i}: in one state only"; continue }
        $rip = if ($null -ne $y.Rip) { '0x{0:x}' -f $y.Rip } else { '?' }
        $moved = if ($null -ne $x.Rip -and $null -ne $y.Rip) { if ($x.Rip -eq $y.Rip) { 'the same in both' } else { 'from 0x{0:x}' -f $x.Rip } } else { '?' }
        $intr = if ($null -ne $y.Rflags) { ($y.Rflags -shr 9) -band 1 } else { '?' }
        $line = "  vCPU ${i}: rip $rip ($moved), IF $intr, mp_state $($y.MpState)"
        if ($y.Lapic) {
            $lvt = & $u32 $y.Lapic 0x320
            $mode = @('one-shot', 'periodic', 'TSC-deadline', 'reserved')[[int](($lvt -shr 17) -band 3)]
            $masked = if ($lvt -band 0x10000) { 'masked' } else { 'unmasked' }
            $line += ('; LVT timer 0x{0:x} ({1}, {2}, vector 0x{3:x2}), initial count {4}, current {5} (first state {6}), divide 0x{7:x}; IRR highest {8}, ISR highest {9}' -f $lvt, $mode, $masked, ($lvt -band 0xff), (& $u32 $y.Lapic 0x380), (& $u32 $y.Lapic 0x390), $(if ($x.Lapic) { & $u32 $x.Lapic 0x390 } else { '?' }), (& $u32 $y.Lapic 0x3e0), (& $top $y.Lapic 0x200), (& $top $y.Lapic 0x100))
        } else {
            $line += '; no local APIC in the print'
        }
        $lines += $line
    }
    return ($lines -join "`n")
}

# The MSR accesses of a stage that exited to the backend for an MSR neither
# WHP nor the backend keeps (read as 0 or the write ignored, where KVM gives
# #GP(0): the Guest MSRs row of docs/COMPATIBILITY.md), from the backend's
# "an MSR the backend does not keep" lines on stderr: the record of which
# MSRs a Linux guest reaches that way (MSRREC). After the VM has exited.
function Get-UnkeptMsrs($vm) {
    $said = $vm.Output + "`n" + (Get-Content -Raw $vm.LogPath -ErrorAction SilentlyContinue)
    $seen = [ordered]@{}
    foreach ($m in [regex]::Matches($said, "vCPU \d+'s (RDMSR|WRMSR) of (0x[0-9a-f]+)(?: \((0x[0-9a-f]+)\))?")) {
        $key = "$($m.Groups[1].Value) $($m.Groups[2].Value)"
        if (-not $seen.Contains($key)) {
            $seen[$key] = if ($m.Groups[3].Success) { "$key ($($m.Groups[3].Value))" } else { $key }
        }
    }
    $more = if ($said -match 'MSR accesses the backend does not keep: those past them are not named') { ', and more not named' } else { '' }
    if ($seen.Count -eq 0) { return 'none' }
    return (@($seen.Values) -join ', ') + $more
}

# Saves the guest kernel log of a stage (for the report), best effort.
function Save-Dmesg($vm, [string]$name) {
    try {
        $out = $vm.Sh('dmesg', 60000, $false)
        Set-Content -Encoding UTF8 (Join-Path (Join-Path $Results $name) 'guest-dmesg.txt') $out
    } catch { }
}

function Get-Uptime($vm, [string]$cmd = 'cat /proc/uptime') {
    $out = $vm.Sh($cmd)
    return [double]::Parse(($out -split '\s+')[0], [Globalization.CultureInfo]::InvariantCulture)
}

# Runs a guest command whose output must be `$want`; `$what` names the case
# in the failure, also when the command never comes back (input not read).
function Test-SerialCommand($vm, [string]$cmd, [string]$want, [string]$what) {
    try {
        $out = $vm.Sh($cmd, 10000, $true)
    } catch {
        $f = Get-Failure $_
        if (-not $f) { throw }
        Fail "serial input $what`: $($f.Message)"
    }
    Check ($out -eq $want) "serial input $what`: '$out', want '$want'"
}

# The serial keeps reading its input (a pipe, non-blocking) in the cases
# where it reads the pipe empty while the writer is open. Linux's read gives
# EAGAIN there and the serial waits for input again (handle_ewouldblock); a
# read of 0 bytes is the end of the input, after which nothing typed
# reaches the guest.
#  - After 30 s with nothing typed: a command must still reach the shell.
#  - After a full receive FIFO (64 bytes, vm-superio): with the vCPU paused, a
#    line longer than the FIFO fills it and a second line arrives while it is
#    full, so the serial stops watching its input (ENOBUFS). Resumed, the
#    guest drains the FIFO; each drain reads more input, and the read that
#    finds it empty watches the input again (EAGAIN on Linux). A command
#    typed after that must reach the shell, and see both lines.
function Test-SerialInput($vm) {
    Start-Sleep -Seconds 30
    Test-SerialCommand $vm 'echo QUIET-$((6*7))' 'QUIET-42' 'after 30 s of silence'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    $vm.Send('A=' + ('L' * 100))
    Start-Sleep -Milliseconds 500
    $vm.Send('B=second')
    Start-Sleep -Milliseconds 500
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Resumed' } | Out-Null
    Test-SerialCommand $vm 'echo ${#A}:$B' '100:second' 'after a full receive FIFO'
}

# --- stages ---------------------------------------------------------------------

function Stage-Boot {
    $vm = Start-Vm 'boot' (Base-Config 1) -Api
    Wait-Shell $vm
    $out = $vm.Sh('echo WICK-$((6*7))')
    Check ($out -eq 'WICK-42') "serial echo: '$out'"
    $arch = $vm.Sh('uname -m')
    Check ($arch -eq 'x86_64') "uname -m: '$arch'"
    $cpus = $vm.Sh('nproc')
    Check ($cpus -eq '1') "nproc: '$cpus'"
    $mem = [int]$vm.Sh("awk '/MemTotal/ {print `$2}' /proc/meminfo")
    Check ($mem -gt 200000 -and $mem -le 262144) "MemTotal $mem kB for 256 MiB"
    $hv = $vm.Sh('grep -c -w hypervisor /proc/cpuinfo')
    Check ($hv -eq '1') "CPUID hypervisor bit: '$hv'"
    # The local timer in TSC-deadline mode, as on KVM: the guest does not
    # calibrate its APIC timer at boot.
    $deadline = $vm.Sh('grep -c "Clock Event Device: lapic-deadline" /proc/timer_list; true')
    Check ($deadline -eq '1') "local timer in TSC-deadline mode (/proc/timer_list): '$deadline' of 1 vCPU"
    $clock = $vm.Sh('cat /sys/devices/system/clocksource/clocksource0/current_clocksource')
    $t0 = Get-Uptime $vm
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds 2
    $t1 = Get-Uptime $vm
    $host_dt = $sw.Elapsed.TotalSeconds
    $dt = $t1 - $t0
    Check ($dt -gt 1.5 -and $dt -le $host_dt + 0.5) ("guest clock advanced {0:N2} s in {1:N2} s (clocksource {2})" -f $dt, $host_dt, $clock)
    Test-SerialInput $vm
    # Recorded: the guest's view of SRSO (Speculative Return Stack
    # Overflow, AMD Zen 1 to 4), which its CPUID leaf 0x80000021 and its
    # write of IA32_PRED_CMD's SBPB decide (arch/x86/kernel/cpu/bugs.c).
    $srso = $vm.Sh('cat /sys/devices/system/cpu/vulnerabilities/spec_rstack_overflow 2>/dev/null; dmesg | grep -m2 "Speculative Return Stack Overflow" | sed "s/^.*] //"; true')
    Save-Dmesg $vm 'boot'
    $vm.Reboot()
    $vm.Drain(2000)
    $msrs = Get-UnkeptMsrs $vm
    return ("init, serial in/out, x86_64, 1 CPU, $mem kB, hypervisor bit, clock {0:N2} s in {1:N2} s ($clock), serial input after 30 s of silence and after a full FIFO, reset exits 0; SRSO: {2}; MSRREC the MSRs the backend does not keep that the guest reached: {3}" -f $dt, $host_dt, (($srso -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' | '), $msrs)
}

# CPU 1 taken offline and back online three times, then work on it: on x86
# the guest parks the CPU (play_dead) and starts it again with INIT and
# SIPI, which WHP's local APIC handles in the hypervisor (KVM resets the
# vCPU at the INIT, kvm_vcpu_reset with init_event). An AP that does not
# come back as reset oopses here, as one did on Hypervisor.framework
# (PSCI CPU_ON). Any failed write, a stall, BUG, oops or warning fails.
function Test-CpuOfflineOnline($vm, [string]$when) {
    $out = $vm.Sh("for i in 1 2 3; do echo 0 > /sys/devices/system/cpu/cpu1/online || echo off-failed; echo 1 > /sys/devices/system/cpu/cpu1/online || echo on-failed; done; taskset -c 1 sh -c 'i=0; while [ `$i -lt 20000 ]; do i=`$((i+1)); done; echo cpu1-ran'; cat /sys/devices/system/cpu/online", 120000, $true)
    $lines = @($out -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Check ($lines.Count -eq 2 -and $lines[0] -eq 'cpu1-ran' -and $lines[1] -eq '0-1') "CPU 1 offline and online three times $when, then work on it: '$($lines -join ' | ')'"
    $vm.Healthy()
    # Recorded: a local timer interrupt for a CPU whose timer is not set up
    # (an interrupt KVM would not raise after the INIT, kvm_lapic_reset).
    $vm.Sh("dmesg | grep -c 'Spurious LAPIC timer interrupt'; true")
}

# tools/guest-counter-warp.py as its header says it is sent: its bytes as
# raw deflate (DeflateStream writes no zlib header), in base64.
function Get-GuestTool([string]$path) {
    Check (Test-Path -LiteralPath $path) "no $path (the kit has it as tools\$(Split-Path -Leaf $path))"
    $bytes = [IO.File]::ReadAllBytes($path)
    $ms = New-Object IO.MemoryStream
    $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Compress)
    $ds.Write($bytes, 0, $bytes.Length)
    $ds.Close()
    return [Convert]::ToBase64String($ms.ToArray())
}

# The two vCPUs' TSCs against each other, in the guest, by the kernel's
# warp check's algorithm (tools/guest-counter-warp.py): the guest kernel
# runs its own only when a CPU comes online, and not at all once the guest
# has TSC_ADJUST. Sent into the shell variable W 2000 characters at a time
# (a console line holds 4095 bytes). Fails naming the step and the ticks the
# TSC went back; returns the pass line's numbers.
function Test-CounterWarp($vm, [string]$when) {
    $b64 = $script:CounterWarp
    for ($i = 0; $i -lt $b64.Length; $i += 2000) {
        $piece = $b64.Substring($i, [Math]::Min(2000, $b64.Length - $i))
        $line = if ($i -eq 0) { "W=$piece" } else { "W=`$W'$piece'" }
        $vm.Sh($line) | Out-Null
    }
    $out = ''
    $rc = $vm.Sh("python3 -c `"import base64,zlib;exec(zlib.decompress(base64.b64decode('`$W'),-15))`" 0 1", 120000, $false, [ref]$out)
    $line = @($out -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'counter-warp: *' }) | Select-Object -Last 1
    Check ($rc -eq 0 -and $line -like 'counter-warp: pass: *') "the vCPUs' TSCs $when (tools/guest-counter-warp.py, exit $rc): $out"
    return ($line -replace '^counter-warp: pass: ', '')
}

function Stage-Smp {
    $vm = Start-Vm 'smp' (Base-Config 2) -Api
    Wait-Shell $vm
    $online = $vm.Sh('cat /sys/devices/system/cpu/online')
    Check ($online -eq '0-1') "online CPUs '$online'"
    $deadline = $vm.Sh('grep -c "Clock Event Device: lapic-deadline" /proc/timer_list; true')
    Check ($deadline -eq '2') "local timers in TSC-deadline mode (/proc/timer_list): '$deadline' of 2 vCPUs"
    foreach ($cpu in 0, 1) {
        $out = $vm.Sh("taskset -c $cpu sh -c 'echo `$((cpu=$cpu+100))'")
        Check ($out -eq "$($cpu + 100)") "taskset $cpu`: '$out'"
    }
    $out = $vm.Sh("for c in 0 1; do taskset -c `$c sh -c 'i=0; while [ `$i -lt 20000 ]; do i=`$((i+1)); done' & done; wait; echo spun")
    Check ($out.EndsWith('spun')) "parallel work: '$out'"
    # The guest clock runs at host speed and agrees between the vCPUs.
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = $vm.Sh('taskset -c 0 cat /proc/uptime; sleep 1; taskset -c 1 cat /proc/uptime')
    $host_dt = $sw.Elapsed.TotalSeconds
    $lines = @($out -split "`n" | Where-Object { $_.Trim() })
    Check ($lines.Count -eq 2) "uptime on both CPUs: '$out'"
    $a = [double]::Parse(($lines[0] -split '\s+')[0], [Globalization.CultureInfo]::InvariantCulture)
    $b = [double]::Parse(($lines[1] -split '\s+')[0], [Globalization.CultureInfo]::InvariantCulture)
    Check (($b - $a) -gt 0.9 -and ($b - $a) -le $host_dt + 0.1) ("guest clock advanced {0:N2} s across vCPUs in {1:N2} s" -f ($b - $a), $host_dt)
    $warp = Test-CounterWarp $vm 'after the boot'
    $spurious = Test-CpuOfflineOnline $vm 'after boot'
    # The same in a microVM restored from a snapshot, in a new process.
    $dir = Join-Path $Scratch 'smp'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $state = Join-Path $dir 'vm.state'
    $mem = Join-Path $dir 'vm.mem'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
    Save-Dmesg $vm 'smp'
    $vm.Kill()
    $vm = Start-Vm 'smp-restored' $null -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
        resume_vm     = $true
    }) | Out-Null
    $online = $vm.Sh('cat /sys/devices/system/cpu/online')
    Check ($online -eq '0-1') "online CPUs after restore '$online'"
    # Before CPU 1 goes offline and online, whose own TSC check would fail
    # first, in the guest health check.
    $warpRestored = Test-CounterWarp $vm 'after a snapshot restore'
    $spuriousRestored = Test-CpuOfflineOnline $vm 'after a snapshot restore'
    Save-Dmesg $vm 'smp-restored'
    $vm.Reboot()
    $vm.Drain(2000)
    $msrs = Get-UnkeptMsrs $vm
    Remove-Item $state, $mem -ErrorAction SilentlyContinue
    return "2 vCPUs online, work runs on each, clock agrees across vCPUs, TSCs agree (after boot: $warp; after the restore: $warpRestored), CPU 1 offline and online 3 times then working, after boot and after a snapshot restore (spurious LAPIC timer interrupts: $spurious, $spuriousRestored), reset exits 0; MSRREC the MSRs the backend does not keep that the restored guest reached: $msrs"
}

function Stage-Block {
    $dir = Join-Path $Results 'block'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $data = Join-Path $dir 'data.img'
    $syncW = Join-Path $dir 'sync.img'
    $asyncW = Join-Path $dir 'async.img'
    [Wick.Util]::WriteRandom($data, 8MB)
    [Wick.Util]::WriteZeros($syncW, 8MB)
    [Wick.Util]::WriteZeros($asyncW, 8MB)
    $cfg = Base-Config 2
    $cfg['drives'] += [ordered]@{ drive_id = 'data'; path_on_host = $data; is_root_device = $false; is_read_only = $true; io_engine = 'Async' }
    $cfg['drives'] += [ordered]@{ drive_id = 'syncw'; path_on_host = $syncW; is_root_device = $false; is_read_only = $false; io_engine = 'Sync' }
    $cfg['drives'] += [ordered]@{ drive_id = 'asyncw'; path_on_host = $asyncW; is_root_device = $false; is_read_only = $false; io_engine = 'Async' }
    $vm = Start-Vm 'block' $cfg
    Wait-Shell $vm
    # The drive's serial (VIRTIO_BLK_GET_ID): upstream builds it from the
    # file's st_dev, st_rdev and st_ino; on Windows from its volume serial
    # number and file index, in 20 base-32 digits (row of the drive's serial
    # in docs/COMPATIBILITY.md). Each must be what the file gives, and
    # distinct.
    $serials = @{}
    foreach ($d in @(@('vda', $Rootfs), @('vdb', $data), @('vdc', $syncW), @('vdd', $asyncW))) {
        $want = [Wick.DriveId]::Of($d[1])
        $got = $vm.Sh("cat /sys/block/$($d[0])/serial")
        Check ($got -eq $want) "$($d[0]) serial '$got', the file gives '$want'"
        $serials[$d[0]] = $got
    }
    Check (@($serials.Values | Sort-Object -Unique).Count -eq 4) "drive serials not distinct: $(($serials.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')"
    $want = [Wick.Util]::Md5File($data, -1)
    $out = $vm.Sh('md5sum /dev/vdb')
    Check ((($out -split '\s+')[0]) -eq $want) "guest md5 of the Async read-only drive '$out', host $want"
    $rootMd5 = (($vm.Sh('md5sum /usr/bin/bash')) -split '\s+')[0]
    $vm.Sh('dd if=/dev/vdb of=/dev/vdc bs=64k count=64 conv=fsync 2>/dev/null') | Out-Null
    $vm.Sh('dd if=/dev/vdb of=/dev/vdd bs=64k count=64 conv=fsync 2>/dev/null') | Out-Null
    $rc = 0
    $out = ''
    $rc = $vm.Sh('echo x | dd of=/dev/vdb conv=fsync 2>&1', 60000, $false, [ref]$out)
    Check ($rc -ne 0) "a write to the read-only drive succeeded: '$out'"
    Save-Dmesg $vm 'block'
    $vm.Reboot()
    $want4 = [Wick.Util]::Md5File($data, 4MB)
    Check ([Wick.Util]::Md5File($syncW, 4MB) -eq $want4) 'Sync drive: the host file does not hold what the guest wrote'
    Check ([Wick.Util]::Md5File($asyncW, 4MB) -eq $want4) 'Async drive: the host file does not hold what the guest wrote'
    return "Async read md5, Sync and Async writes reach the host file, read-only enforced, serials from the volume and file index (root bash $($rootMd5.Substring(0, 8)))"
}

function Stage-Vsock {
    $uds = Get-SockPath 'v.sock'
    if (Test-Path $uds) { Remove-Item $uds -Force }
    $cfg = Base-Config 2
    $cfg['vsock'] = [ordered]@{ guest_cid = 3; uds_path = $uds }
    $vm = Start-Vm 'vsock' $cfg
    Wait-Shell $vm
    $vm.Sh('command -v socat >/dev/null') | Out-Null
    $vm.Sh('(socat -t 30 VSOCK-LISTEN:52,fork EXEC:cat >/dev/null 2>&1 &)') | Out-Null
    # Connections are closed with no "OK" until socat listens.
    [Wick.Vsock]::WaitListening($uds, 52, 10000)
    [Wick.Vsock]::Echo($uds, 52, 4MB)
    # A guest's connection to host port 53 reaches "<uds_path>_53", the
    # socket Firecracker connects to (upstream's vsock docs), named here so
    # its bound is the script's.
    $port53 = Get-SockPath 'v.sock_53'
    Check ($port53 -eq "$($uds)_53") "the port 53 socket $port53 is not $($uds)_53"
    $collector = New-Object Wick.Collector($port53, 30000)
    $vm.Sh('echo guest-to-host-$((6*7)) | socat -t 5 - VSOCK-CONNECT:2:53') | Out-Null
    $got = $collector.Finish(30000)
    Check ($got -eq "guest-to-host-42`n") "host received '$got' on $port53"
    Save-Dmesg $vm 'vsock'
    $vm.Reboot()
    return 'host->guest CONNECT, 4 MiB echo; guest->host <uds>_53'
}

$GuestMac = '06:00:0a:00:00:02'

# 1 MiB/s: a bucket of 128 KiB refilled every 125 ms (upstream's token
# bucket: `size` bytes, `refill_time` ms, full at the start).
$NetLimit = [ordered]@{ bandwidth = [ordered]@{ size = 128KB; refill_time = 125 } }
$NetLimitBps = 128KB * 1000 / 125
$NoLimit = [ordered]@{ bandwidth = [ordered]@{ size = 0; refill_time = 0 } }

# The guest's interrupts since its boot (/proc/stat's intr total), as a
# shell expression.
$GuestInterrupts = '$(awk ''/^intr/ {print $2}'' /proc/stat)'

# The guest's eth0 tx_packets and tx_dropped, and its UDP SndbufErrors (the
# datagrams its own queue dropped: /proc/net/snmp's second Udp line, field
# 7), as a shell expression of three numbers.
$GuestTxCounts = '$(cat /sys/class/net/eth0/statistics/tx_packets) $(cat /sys/class/net/eth0/statistics/tx_dropped) $(awk ''/^Udp:/ {n++; if (n == 2) print $7}'' /proc/net/snmp)'

# The interrupts of eth0's own virtio device since the guest's boot, over
# all its CPUs, as a shell expression (-1 when /proc/interrupts has no line
# for it): virtio-mmio names its interrupt after the device, virtioN
# (drivers/virtio/virtio_mmio.c, vm_find_vqs), the last directory of the
# path /sys/class/net/eth0/device leads to.
$GuestNetIrq = '$(d=$(cd /sys/class/net/eth0/device && pwd -P); awk -v d="${d##*/}" ''BEGIN {s = -1} $NF == d {if (s < 0) s = 0; for (i = 2; i < NF; i++) if ($i ~ /^[0-9]+$/) s += $i} END {print s}'' /proc/interrupts)'

# The sum over the metrics lines Firecracker wrote to `path` past byte
# `from` of each of the "net" object's counters below (each line holds what
# a counter gained since the line before: SharedIncMetric's serialize,
# src/vmm/src/logger/metrics.rs), and of tap_write_agg.sum_us.
function Get-NetMetricsSince([string]$path, [long]$from) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $fs.Seek($from, 'Begin') | Out-Null
        $text = (New-Object IO.StreamReader($fs)).ReadToEnd()
    } finally { $fs.Close() }
    $sum = [ordered]@{ lines = 0; tx_queue_event_count = 0; tx_packets_count = 0; tx_bytes_count = 0; no_tx_avail_buffer = 0; tx_rate_limiter_throttled = 0; tx_fails = 0; tap_write_fails = 0; tap_write_us = 0 }
    foreach ($m in (Get-MetricsLines $text)) {
        if ($null -eq $m.net) { continue }
        $sum['lines'] += 1
        foreach ($k in @('tx_queue_event_count', 'tx_packets_count', 'tx_bytes_count', 'no_tx_avail_buffer', 'tx_rate_limiter_throttled', 'tx_fails', 'tap_write_fails')) { $sum[$k] += [long]$m.net.$k }
        $sum['tap_write_us'] += [long]$m.net.tap_write_agg.sum_us
    }
    return $sum
}

# The rate at which `total` bytes the guest sends to the host's port 9 reach
# the switch (bytes per second, between the first and the last datagram);
# returns the bytes, the rate, and the guest's interrupts a second while it
# sent (/proc/stat, over the send's own time).
#
# Each call also prints a NETTX record line, for the run-to-run spread of
# the unlimited rate (16-19 against 60-83 MiB/s on the PC at 87d0328, and
# 30-132 MiB/s in the macOS stage): where the time and the frames went.
# The guest's own time against the switch's span tells a guest that sent
# slowly from a host that took slowly; the datagrams the guest handed its
# driver against those the switch got tell frames dropped on the way (the
# endpoint drops a frame its connection cannot take: net.rs,
# Endpoint::send); the largest gap between two datagrams and the time in
# gaps over 1 ms tell one stall from a slow steady rate.
#
# The line also gives the interrupts of the guest's net device alone, and,
# when `metrics` is the VM's metrics file, what the VMM counted over the
# same send (a FlushMetrics before it and one after): the TX queue events
# it handled (each a wake of its event loop for one guest notification or
# more), the packets and bytes it wrote, the time those writes took, and
# its no-buffer, throttle and failure counts (tx_fails: a descriptor chain
# that did not load; tap_write_fails: a write the interface refused, the
# frame then dropped: device.rs, process_tx and write_to_mmds_or_tap).
# Packets to an event and
# device interrupts to a packet tell a guest that notifies and is
# interrupted once a packet (each notification an MMIO exit) from one that
# batches.
function Get-NetTxRate($vm, $switch, [int]$total = 3MB, [string]$metrics = '') {
    $from = -1
    if ($metrics) {
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $from = (Get-Item -LiteralPath $metrics).Length
    }
    $sink = New-Object 'System.Collections.Generic.List[long[]]'
    $switch.Sink = $sink
    $out = $vm.Sh("a=$GuestInterrupts; c=`"$GuestTxCounts`"; n=$GuestNetIrq; " + 'S=$(date +%s%N); ' + "head -c $total /dev/zero | socat -b 1400 -u - UDP:10.0.0.1:9; " +
        "b=$GuestInterrupts; " + 'echo $((b - a)) $(( ($(date +%s%N) - S) / 1000 )) $c ' + $GuestTxCounts + ' $n ' + $GuestNetIrq, 120000, $true)
    $f = Get-Fields $out
    $irq = [long]$f[0] / [math]::Max([long]$f[1] / 1e6, 1e-6)
    Start-Sleep -Milliseconds 500
    $switch.Sink = $null
    $vmm = $null
    if ($from -ge 0) {
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $vmm = Get-NetMetricsSince $metrics $from
    }
    $got = 0; $first = $null; $last = $null; $prev = $null
    $hz = [Diagnostics.Stopwatch]::Frequency
    $maxGap = 0; $longGaps = 0; $longTicks = 0
    foreach ($e in @($sink.ToArray())) {
        $got += $e[1]
        if ($null -eq $first) { $first = $e }
        if ($null -ne $prev) {
            $gap = $e[0] - $prev[0]
            if ($gap -gt $maxGap) { $maxGap = $gap }
            if ($gap -gt $hz / 1000) { $longGaps++; $longTicks += $gap }
        }
        $prev = $e; $last = $e
    }
    Check ($sink.Count -ge 2) "the host got $($sink.Count) datagrams of $total bytes sent"
    $secs = [math]::Max(($last[0] - $first[0]) / $hz, 1e-6)
    $rate = ($got - $first[1]) / $secs
    if ($f.Count -ge 10) {
        $line = '  NETTX {0:N1} MiB/s: guest sent {1:N0} bytes in {2:N1} ms ({3:N0} packets to its driver, {4:N0} dropped by the driver, {5:N0} by its queue; {6:N0} interrupts, {7} of its net device); switch got {8:N0} datagrams, {9:N0} bytes, over {10:N1} ms; largest gap {11:N2} ms, {12:N0} gaps over 1 ms for {13:N1} ms' -f `
            ($rate / 1MB), $total, ([long]$f[1] / 1e3), ([long]$f[5] - [long]$f[2]), ([long]$f[6] - [long]$f[3]), ([long]$f[7] - [long]$f[4]), [long]$f[0],
            $(if ([long]$f[8] -ge 0 -and [long]$f[9] -ge 0) { '{0:N0}' -f ([long]$f[9] - [long]$f[8]) } else { 'none found' }),
            $sink.Count, $got, ($secs * 1e3), ($maxGap * 1e3 / $hz), $longGaps, ($longTicks * 1e3 / $hz)
        if ($null -ne $vmm) {
            $line += '; VMM over {0} metrics lines: {1:N0} TX queue events, {2:N0} packets and {3:N0} bytes written in {4:N1} ms, {5:N0} without a buffer, {6:N0} throttled, {7:N0} descriptor chains that failed to load, {8:N0} writes that failed' -f `
                $vmm.lines, $vmm.tx_queue_event_count, $vmm.tx_packets_count, $vmm.tx_bytes_count, ($vmm.tap_write_us / 1e3), $vmm.no_tx_avail_buffer, $vmm.tx_rate_limiter_throttled, $vmm.tx_fails, $vmm.tap_write_fails
        }
        Write-Host $line
    } else {
        Write-Host "  NETTX: the guest's counters did not parse: '$out'"
    }
    return @($got, $rate, $irq)
}

# The guest's receive rate (its rx_bytes over `seconds`) while the host
# floods it with UDP to port 9 (bytes per second), and its interrupts a
# second over the same time (/proc/stat).
function Get-NetRxRate($vm, $switch, [int]$seconds = 2) {
    $mac = [byte[]]($GuestMac -split ':' | ForEach-Object { [Convert]::ToByte($_, 16) })
    $switch.StartFlood($mac)
    try {
        Start-Sleep -Milliseconds 500  # past the bucket's first, full, budget
        $out = $vm.Sh("i=$GuestInterrupts; " + 'a=$(cat /sys/class/net/eth0/statistics/rx_bytes); S=$(date +%s%N); ' +
            "sleep $seconds; j=$GuestInterrupts; " + 'b=$(cat /sys/class/net/eth0/statistics/rx_bytes); echo $((b - a)) $(( ($(date +%s%N) - S) / 1000 )) $((j - i))', 60000, $true)
    } finally {
        $sent = $switch.StopFlood()
    }
    $f = Get-Fields $out
    $got = [long]$f[0]; $us = [long]$f[1]
    Check ($sent -gt $got) "host flood sent $sent bytes, guest counted $got"
    return @(($got / ($us / 1e6)), ([long]$f[2] / ($us / 1e6)))
}

# rx and tx bandwidth limiters set on the running device (PATCH): each
# direction runs at the limit, and without one at three times it or more
# (the counterpart of the macOS stage's net_rate_limiters).
function Test-NetRateLimiters($vm, $switch, [string]$metrics = '') {
    $mib = 1MB
    $r = Get-NetTxRate $vm $switch 3MB $metrics
    $txFree = $r[1]; $txIrq = $r[2]
    $r = Get-NetRxRate $vm $switch
    $rxFree = $r[0]; $rxIrq = $r[1]
    # The guest's interrupts a second under net load, unlimited: what
    # option C (an EOI through the backend, about 9.5 us more each on the
    # PC at 81072df) would cost such a guest.
    Write-Host ('  NETIRQ unlimited: tx {0:N1} MiB/s with {1:N0} guest interrupts a second; rx {2:N1} MiB/s with {3:N0} a second' -f ($txFree / $mib), $txIrq, ($rxFree / $mib), $rxIrq)
    Invoke-Api $vm 'PATCH' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; tx_rate_limiter = $NetLimit }) | Out-Null
    $r = Get-NetTxRate $vm $switch 3MB $metrics
    $txGot = $r[0]; $tx = $r[1]
    Invoke-Api $vm 'PATCH' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; rx_rate_limiter = $NetLimit; tx_rate_limiter = $NoLimit }) | Out-Null
    $rx = (Get-NetRxRate $vm $switch)[0]
    Invoke-Api $vm 'PATCH' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; rx_rate_limiter = $NoLimit }) | Out-Null
    $txAfter = (Get-NetTxRate $vm $switch 3MB $metrics)[1]
    $summary = 'tx {0:N1} -> {1:N2} MiB/s, rx {2:N1} -> {3:N2} MiB/s at a 1 MiB/s limit; tx {4:N1} MiB/s once removed; guest interrupts a second unlimited: tx {5:N0}, rx {6:N0}' -f ($txFree / $mib), ($tx / $mib), ($rxFree / $mib), ($rx / $mib), ($txAfter / $mib), $txIrq, $rxIrq
    Check ($txGot -ge 1MB) "throttled tx: only $txGot bytes reached the host ($summary)"
    Check ($tx -ge 0.5 * $NetLimitBps -and $tx -le 1.25 * $NetLimitBps) "tx limiter: $summary"
    Check ($rx -ge 0.5 * $NetLimitBps -and $rx -le 1.25 * $NetLimitBps) "rx limiter: $summary"
    Check ($txFree -ge 3 * $NetLimitBps -and $rxFree -ge 3 * $NetLimitBps -and $txAfter -ge 3 * $NetLimitBps) "unthrottled rates not above the limit: $summary"
    return $summary
}

function Stage-Net {
    $endpoint = Get-SockPath 'n.ep'
    if (Test-Path $endpoint) { Remove-Item $endpoint -Force }
    $dir = Join-Path $Results 'net'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # For the NETTX lines' VMM counts; Firecracker opens it, it does not
    # create it.
    $metrics = Join-Path $dir 'metrics.json'
    New-Item -ItemType File -Force -Path $metrics | Out-Null
    $cfg = Base-Config 2
    $cfg['network-interfaces'] = @([ordered]@{ iface_id = 'eth0'; host_dev_name = $endpoint; guest_mac = $GuestMac })
    $cfg['metrics'] = [ordered]@{ metrics_path = $metrics }
    $vm = Start-Vm 'net' $cfg -Api
    try {
        $switch = New-Object Wick.Switch($endpoint, 10000)
    } catch {
        # Firecracker that exited never listened: report why it exited.
        if ($vm.Exited) { Wait-Shell $vm }
        throw
    }
    try {
        Wait-Shell $vm
        $mac = $vm.Sh('cat /sys/class/net/eth0/address')
        Check ($mac -eq $GuestMac) "guest MAC '$mac'"
        $vm.Sh('ip addr add 10.0.0.2/24 dev eth0 && ip link set eth0 up && ip link set lo up') | Out-Null
        $out = $vm.Sh('ping -c 3 -i 0.3 -W 3 10.0.0.1')
        Check ($out -match ' 0% packet loss') "ping: $out"
        $out = $vm.Sh('ping -c 2 -s 1400 -W 3 10.0.0.1')
        Check ($out -match ' 0% packet loss') "ping -s 1400: $out"
        # Many frames back to back: the stream framing under load.
        $out = $vm.Sh('ping -q -c 200 -i 0.01 -s 1000 -W 3 10.0.0.1', 120000, $true)
        Check ($out -match ' 0% packet loss') "ping -c 200 -i 0.01: $out"
        $out = $vm.Sh('echo udp-$((6*7)) | socat -t 3 - UDP:10.0.0.1:7')
        Check ($out -eq 'udp-42') "UDP echo '$out'"
        $rates = Test-NetRateLimiters $vm $switch $metrics
        Save-Dmesg $vm 'net'
        $switch.Closing = $true
        $vm.Reboot()
    } finally {
        $switch.Close()
    }
    Check ($switch.ReadError -eq $null) "switch: $($switch.ReadError) ($($switch.Counts))"
    Check ($switch.Bad.Count -eq 0) "bad frames from the guest: $(($switch.Bad | Select-Object -First 3) -join '; ')"
    Check ($switch.Arp -ge 1 -and $switch.Icmp -ge 205 -and $switch.Udp -ge 1) "switch saw $($switch.Counts)"
    return "Unix stream endpoint: ARP, ICMP (1400 B, 200 back to back), UDP echo, checksums valid ($($switch.Counts)); $rates"
}

# A helper binary: next to firecracker.exe or this script, else where the
# build (and CI's artifact) puts it.
function Find-Tool([string]$exe) {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $candidates = @(
        (Join-Path (Split-Path -Parent $Fc) $exe),
        (Join-Path $PSScriptRoot $exe),
        (Join-Path $root "lib\firecracker\build\cargo_target\release\$exe"),
        (Join-Path $root "lib\firecracker\build\cargo_target\release\examples\$exe"),
        (Join-Path $root "lib\firecracker\build\vhost-user-blk\release\$exe")
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    Fail "$exe not found (looked in: $($candidates -join ', '))"
}

# A guest service on vsock port 52 that echoes, and the host waiting for it.
function Start-GuestEcho($vm, [string]$uds) {
    $vm.Sh('command -v socat >/dev/null') | Out-Null
    $vm.Sh('(socat VSOCK-LISTEN:52,fork EXEC:cat >/dev/null 2>&1 &)') | Out-Null
    [Wick.Vsock]::WaitListening($uds, 52, 10000)
}

# Full snapshot of a 2 vCPU guest with a data drive and vsock, restored in a
# new Firecracker process; over virtio-pci with -Pci.
function Stage-Snapshot([switch]$Pci) {
    $tag = if ($Pci) { 'pci' } else { 'snapshot' }
    $extra = if ($Pci) { '--enable-pci' } else { '' }
    $bootArgs = if ($Pci) { $BootArgs -replace ' pci=off', '' } else { $BootArgs }
    $dir = Join-Path $Scratch $tag
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $uds = if ($Pci) { Get-SockPath 'pci.v' } else { Get-SockPath 'snapshot.v' }
    if (Test-Path $uds) { [IO.File]::Delete($uds) }
    $data = Join-Path $dir 'data.img'
    [Wick.Util]::WriteRandom($data, 4MB)
    $cfg = Base-Config 2 256 $bootArgs
    $cfg['drives'] += [ordered]@{ drive_id = 'data'; path_on_host = $data; is_root_device = $false; is_read_only = $true; io_engine = 'Async' }
    $cfg['vsock'] = [ordered]@{ guest_cid = 3; uds_path = $uds }
    $vm = Start-Vm "$tag-1" $cfg $extra -Api
    Wait-Shell $vm
    if ($Pci) {
        $n = [int]$vm.Sh('ls /sys/bus/pci/devices | wc -l')
        Check ($n -ge 3) "$n PCI devices for root, data and vsock"
        $msix = $vm.Sh("grep -c -i 'PCI-MSI' /proc/interrupts; true")
        Check ([int]$msix -ge 1) "no PCI-MSI interrupts in the guest: '$msix'"
    }
    Start-GuestEcho $vm $uds
    $vm.Sh('A=before-$((6*7))') | Out-Null
    $bashMd5 = $vm.Sh('md5sum /usr/bin/bash')
    $state = Join-Path $dir 'vm.state'
    $mem = Join-Path $dir 'vm.mem'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
    $vm.Kill()
    [IO.File]::Delete($uds)
    $size = (Get-Item $mem).Length
    Check ($size -eq 256MB) "memory file is $size bytes"

    $vm = Start-Vm "$tag-2" $null $extra -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
        resume_vm     = $true
    }) | Out-Null
    Test-Restored $vm $bashMd5 $data
    [Wick.Vsock]::Echo($uds, 52, 1MB)
    Save-Dmesg $vm "$tag-2"
    $vm.Reboot()
    if (-not $Pci) {
        $script:SnapshotFiles = @{ State = $state; Mem = $mem; Data = $data; Uds = $uds; BashMd5 = $bashMd5 }
    }
    $over = if ($Pci) { ' over virtio-pci (MSI-X)' } else { '' }
    return "Full snapshot, restore in a new process: shell state, clock on both vCPUs, root and data drives, vsock$over"
}

# One snapshot restored many times, each restore paused and snapshotted
# again, the counterpart of the macOS stage: races between vCPU threads at
# restore (a vCPU created while another makes an interrupt pending) and at
# the pause before a snapshot (a vCPU kicked between two runs).
function Stage-Restores([int]$Rounds = 20) {
    $dir = Join-Path $Scratch 'restores'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $uds = Get-SockPath 'rs.v'
    if (Test-Path $uds) { [IO.File]::Delete($uds) }
    $cfg = Base-Config 2
    $cfg['vsock'] = [ordered]@{ guest_cid = 3; uds_path = $uds }
    $vm = Start-Vm 'rs0' $cfg -Api
    Wait-Shell $vm
    Start-GuestEcho $vm $uds
    $vm.Sh('A=before-$((6*7))') | Out-Null
    $state = Join-Path $dir 'rs.state'; $mem = Join-Path $dir 'rs.mem'
    $again = Join-Path $dir 'rs2.state'; $againMem = Join-Path $dir 'rs2.mem'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
    $vm.Kill()
    for ($i = 1; $i -le $Rounds; $i++) {
        if (Test-Path $uds) { [IO.File]::Delete($uds) }
        $vm = Start-Vm "rs$i" $null '' -Api
        Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
            snapshot_path = $state
            mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
            resume_vm     = $true
        }) | Out-Null
        try { $out = $vm.Sh('echo restored $A', 20000, $true) } catch { Fail "restore $i of ${Rounds}: $($_.Exception.Message)" }
        Check ($out -eq 'restored before-42') "restore ${i}: '$out'"
        Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
        Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $again; mem_file_path = $againMem }) | Out-Null
        $vm.Kill()
    }
    Remove-Item $mem, $againMem -ErrorAction SilentlyContinue
    return "$Rounds restores of one snapshot, each paused and snapshotted again"
}

# A diff snapshot on top of a full one (dirty page tracking), merged with
# snapshot-editor and restored.
function Stage-Diff {
    $editor = Find-Tool 'snapshot-editor.exe'
    $dir = Join-Path $Scratch 'diff'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $cfg = Base-Config 2
    $cfg['machine-config']['track_dirty_pages'] = $true
    $vm = Start-Vm 'diff-1' $cfg -Api
    Wait-Shell $vm
    $vm.Sh('A=before-$((6*7))') | Out-Null
    $bashMd5 = $vm.Sh('md5sum /usr/bin/bash')
    $base = Join-Path $dir 'base.mem'
    $diff = Join-Path $dir 'diff.mem'
    $state = Join-Path $dir 'diff.state'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = (Join-Path $dir 'full.state'); mem_file_path = $base }) | Out-Null
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Resumed' } | Out-Null
    $vm.Sh('B=second-$((7*7)); cat /usr/bin/* > /dev/null 2>&1; true', 120000, $true) | Out-Null
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Diff'; snapshot_path = $state; mem_file_path = $diff }) | Out-Null
    $vm.Kill()
    $size = (Get-Item $diff).Length
    $allocated = [Wick.Util]::Allocated($diff)
    Check ($size -eq 256MB) "diff file is $size bytes"
    Check ($allocated -gt 0 -and $allocated -lt 200MB) "diff file allocates $([math]::Round($allocated / 1MB)) MiB of 256 (holes lost?)"
    $out = & $editor edit-memory rebase --memory-path $base --diff-path $diff 2>&1 | Out-String
    Check ($LASTEXITCODE -eq 0) "snapshot-editor rebase: exit $LASTEXITCODE $($out.Trim())"

    $vm = Start-Vm 'diff-2' $null -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $base }
        resume_vm     = $true
    }) | Out-Null
    Test-Restored $vm $bashMd5 $null
    $out = $vm.Sh('echo $B')
    Check ($out -eq 'second-49') "diff state after restore: '$out'"
    Save-Dmesg $vm 'diff-2'
    $vm.Reboot()
    return "Diff snapshot ($([math]::Round($allocated / 1MB)) MiB allocated of 256), snapshot-editor rebase, restore"
}

# The snapshot stage's snapshot restored with the Uffd memory backend, its
# pages served by upstream's uffd_on_demand_handler in another process.
function Stage-Uffd {
    $handlerExe = Find-Tool 'uffd_on_demand_handler.exe'
    $f = $script:SnapshotFiles
    Check ($null -ne $f) "needs the snapshot stage's files (-Stage snapshot,uffd)"
    # The snapshot's vsock socket path is reused as it was.
    if (Test-Path $f.Uds) { [IO.File]::Delete($f.Uds) }
    $sock = Get-SockPath 'uffd'
    if (Test-Path $sock) { [IO.File]::Delete($sock) }
    $log = Join-Path (Join-Path $Results 'uffd') 'handler.txt'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $log) | Out-Null
    $handler = New-Object Wick.Vm($handlerExe, "`"$sock`" `"$($f.Mem)`"", $log)
    $script:Vms += $handler
    $until = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path $sock)) {
        if ($handler.Exited -or [DateTime]::UtcNow -gt $until) { Fail "uffd handler did not start ($($handler.ExitReason()))" }
        Start-Sleep -Milliseconds 20
    }
    $vm = Start-Vm 'uffd' $null '' -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $f.State
        mem_backend   = [ordered]@{ backend_type = 'Uffd'; backend_path = $sock }
        resume_vm     = $true
    }) | Out-Null
    Test-Restored $vm $f.BashMd5 $f.Data
    [Wick.Vsock]::Echo($f.Uds, 52, 1MB)
    # Fresh pages after the restore.
    $out = $vm.Sh('head -c 64m /dev/zero | md5sum', 120000, $true)
    Check ((Get-Fields $out)[0] -eq '7f614da9329cd3aebf59b91aadc30bf0') "64 MiB of zeros: '$out'"
    Save-Dmesg $vm 'uffd'
    $vm.Reboot()
    return 'restore with the Uffd backend served by uffd_on_demand_handler: shell state, clock, drives, vsock'
}

# A vhost-user-blk drive served by tools/vhost-user-blk in another process:
# guest memory and eventfds cross the process boundary.
function Stage-VhostUser {
    $vub = Find-Tool 'vhost-user-blk.exe'
    $dir = Join-Path $Scratch 'vhost-user'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $img = Join-Path $dir 'vub.img'
    [Wick.Util]::WriteRandom($img, 8MB)
    $want = [Wick.Util]::Md5File($img, -1)
    $sock = Get-SockPath 'vub'
    if (Test-Path $sock) { [IO.File]::Delete($sock) }
    $log = Join-Path (Join-Path $Results 'vhost-user') 'backend.txt'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $log) | Out-Null
    $backend = New-Object Wick.Vm($vub, "`"$sock`" `"$img`"", $log)
    $script:Vms += $backend
    $until = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path $sock)) {
        if ($backend.Exited -or [DateTime]::UtcNow -gt $until) { Fail "vhost-user backend did not start ($($backend.ExitReason()))" }
        Start-Sleep -Milliseconds 20
    }
    $cfg = Base-Config 2
    $cfg['drives'] += [ordered]@{ drive_id = 'vub'; socket = $sock; is_root_device = $false }
    $vm = Start-Vm 'vhost-user' $cfg
    Wait-Shell $vm
    $out = $vm.Sh('md5sum /dev/vdb')
    Check ((Get-Fields $out)[0] -eq $want) "guest md5 over vhost-user '$out', host $want"
    $vm.Sh('echo vhost-user-$((6*7)) | dd of=/dev/vdb bs=512 seek=8 conv=fsync,notrunc 2>/dev/null') | Out-Null
    Save-Dmesg $vm 'vhost-user'
    $vm.Reboot()
    $backend.Kill()
    $fs = [IO.File]::Open($img, 'Open', 'Read', 'ReadWrite')
    try {
        $fs.Position = 4096
        $b = New-Object byte[] 14
        [void]$fs.Read($b, 0, 14)
    } finally { $fs.Dispose() }
    $got = [Text.Encoding]::ASCII.GetString($b)
    Check ($got -eq "vhost-user-42`n") "the guest's write is not in the backend's image: '$got'"
    return 'vhost-user-blk backend in another process: read md5, write reaches the image'
}

# Guest memory on 2 MiB large pages (machine-config huge_pages "2M"). Large
# pages need the "Lock pages in memory" right (SeLockMemoryPrivilege), as
# hugetlbfs on Linux needs huge pages reserved by an administrator.
# Row 4 of docs/PORTING.md: the API thread's own, narrower filter. On
# Windows the API server's HTTP side is a process of its own
# (vmm::ext::api_process), made by Firecracker from its own binary before
# its sandbox is set, with the whole mitigation profile from its start
# (what raises SIGSYS there: test_api_profile_* in ext::sandbox); it serves
# the API, its end ends Firecracker as the API thread's does on Linux (a
# panic, panic = "abort"), and Firecracker's end ends it.
function Stage-ApiProcess {
    $all = @{ ExtensionPoint = 1; ImageLoad = 7; Signature = 1; StrictHandle = 3; Win32k = 1; DynamicCode = 1; ChildProcess = 1 }
    $vm = Start-Vm 'api-process' (Base-Config 1) -Api
    Wait-Shell $vm
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($vm.Pid)" | Where-Object { $_.Name -eq 'firecracker.exe' })
    Check ($kids.Count -eq 1) "Firecracker's child processes from its binary: $($kids.Count)"
    $api = [int]$kids[0].ProcessId
    $apiM = [Wick.Mitigation]::Of($api)
    $meM = [Wick.Mitigation]::Of($PID)
    $missing = @($all.Keys | Where-Object { ($apiM[$_] -band $all[$_]) -ne $all[$_] })
    Check ($missing.Count -eq 0) "mitigations not in force in the API process: $($missing -join ', ')"
    $here = @($all.Keys | Where-Object { ($meM[$_] -band $all[$_]) -ne 0 })
    Check ($here.Count -eq 0) "mitigations in force in this shell (the control is lost): $($here -join ', ')"
    $info = Invoke-Api $vm 'GET' '/'
    Check ($info -match '"state":"Running"') "instance information through the API process: $info"
    $status = 0
    [void][Wick.Api]::Call($vm.ApiSock, 'PUT', '/nothing-here', '{}', 30000, [ref]$status)
    Check ($status -eq 400) "an unknown path: $status"
    Stop-Process -Id $api -Force
    $until = [DateTime]::UtcNow.AddSeconds(15)
    while (-not $vm.Exited -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
    Check $vm.Exited 'Firecracker did not end within 15 s of the API process being killed'
    Check ($vm.ExitCode -ne 0) "Firecracker exited 0 after the API process was killed"
    $vm.Drain(5000)
    # The panic hook logs through the logger, which --log-path sends to the log file.
    $said = $vm.Output + "`n" + (Get-Content -Raw $vm.LogPath -ErrorAction SilentlyContinue)
    Check ($said -match 'The API server process ended') "no panic message for the API process's end ($($vm.ExitReason()))"

    $vm = Start-Vm 'api-process-2' (Base-Config 1) -Api
    Wait-Shell $vm
    $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($vm.Pid)" | Where-Object { $_.Name -eq 'firecracker.exe' })
    Check ($kids.Count -eq 1) "Firecracker's child processes from its binary: $($kids.Count)"
    $api = [int]$kids[0].ProcessId
    $vm.Kill()
    $until = [DateTime]::UtcNow.AddSeconds(10)
    while ((Get-Process -Id $api -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
    Check ($null -eq (Get-Process -Id $api -ErrorAction SilentlyContinue)) 'the API process outlived Firecracker by 10 s'
    return 'API process under the whole mitigation profile (this shell under none), serves the API; each one''s end ends the other'
}

# Logger, metrics, MMDS, balloon, entropy and a rate limiter: what upstream
# configures beside the devices above (tools/macos/boot-test.py, stage_devices).
function Stage-Devices {
    $dir = Join-Path $Results 'devices'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $metrics = Join-Path $dir 'metrics.json'
    # Firecracker opens the metrics file, it does not create it.
    New-Item -ItemType File -Force -Path $metrics | Out-Null
    $data = Join-Path $dir 'data.img'
    [Wick.Util]::WriteRandom($data, 4MB)
    $endpoint = Get-SockPath 'd.ep'
    if (Test-Path $endpoint) { Remove-Item $endpoint -Force }
    $cfg = Base-Config 2 512
    $cfg['drives'] += [ordered]@{
        drive_id = 'data'; path_on_host = $data; is_root_device = $false; is_read_only = $true
        rate_limiter = [ordered]@{ bandwidth = [ordered]@{ size = 1MB; refill_time = 100 } }
    }
    $cfg['network-interfaces'] = @([ordered]@{ iface_id = 'eth0'; host_dev_name = $endpoint; guest_mac = $GuestMac })
    $cfg['mmds-config'] = [ordered]@{ version = 'V2'; network_interfaces = @('eth0') }
    $cfg['balloon'] = [ordered]@{ amount_mib = 0; deflate_on_oom = $true; stats_polling_interval_s = 1 }
    $cfg['entropy'] = [ordered]@{}
    $cfg['metrics'] = [ordered]@{ metrics_path = $metrics }
    # The logger is the one every stage's VM has (--log-path, Start-Vm).
    $vm = Start-Vm 'devices' $cfg -Api
    try {
        $switch = New-Object Wick.Switch($endpoint, 10000)
    } catch {
        if ($vm.Exited) { Wait-Shell $vm }
        throw
    }
    try {
        Wait-Shell $vm
        # Entropy device.
        $out = $vm.Sh('head -c 64 /dev/hwrng | od -An -tx1 | wc -w')
        Check ($out -eq '64') "64 bytes from virtio-rng: '$out'"
        # Rate limiter: 4 MiB at 1 MiB per 100 ms takes at least ~300 ms.
        $out = $vm.Sh('S=$(date +%s%N); dd if=/dev/vdb of=/dev/null bs=1M iflag=direct 2>/dev/null; echo $(( ($(date +%s%N) - S) / 1000000 ))')
        Check ([int]$out -ge 250) "4 MiB read past a 10 MiB/s limiter in $out ms"
        # MMDS (V2: a token, then the data).
        Invoke-Api $vm 'PUT' '/mmds' ([ordered]@{ wick = [ordered]@{ answer = 'v42' } }) | Out-Null
        $vm.Sh('ip addr add 10.0.0.2/24 dev eth0 && ip link set eth0 up && ip link set lo up && ip route add 169.254.169.254 dev eth0') | Out-Null
        $token = $vm.Sh('printf ''PUT /latest/api/token HTTP/1.1\r\nX-metadata-token-ttl-seconds: 60\r\n\r\n'' | socat -t 5 - TCP:169.254.169.254:80 | tail -1')
        Check ($token.Length -gt 20) "MMDS token '$token'"
        $out = $vm.Sh("printf 'GET /wick/answer HTTP/1.1\r\nX-metadata-token: $token\r\n\r\n' | socat -t 5 - TCP:169.254.169.254:80 | tail -1")
        Check ($out -eq 'v42') "MMDS answer '$out'"
        # Balloon: inflate by 64 MiB, statistics.
        Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 64 }) | Out-Null
        $until = [DateTime]::UtcNow.AddSeconds(30)
        while ($true) {
            $raw = Invoke-Api $vm 'GET' '/balloon/statistics'
            $stats = $raw | ConvertFrom-Json
            if ($stats.actual_mib -ge 64) { break }
            Check ([DateTime]::UtcNow -lt $until) "balloon statistics $raw"
            Start-Sleep -Milliseconds 500
        }
        Check ($stats.actual_mib -eq 64 -and $null -ne $stats.free_memory) "balloon statistics $raw"
        Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 0 }) | Out-Null
        # Metrics, flushed on demand.
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $fs = [IO.File]::Open($metrics, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
        $lines = @($text -split "`n" | Where-Object { $_.Trim() })
        Check ($lines.Count -ge 1) 'no metrics line after FlushMetrics'
        $last = $lines[-1] | ConvertFrom-Json
        Check ($null -ne $last.utc_timestamp_ms -and $last.block.read_bytes -ge 4MB) "metrics: $($lines.Count) lines, block.read_bytes $($last.block.read_bytes)"
        Save-Dmesg $vm 'devices'
        $switch.Closing = $true
        $vm.Reboot()
    } finally {
        $switch.Close()
    }
    # Lines of the VMM thread and of the API thread.
    $log = Get-Content -Raw $vm.LogPath
    Check ($log -match 'Successfully started microvm that was configured from one single json' -and $log -match 'The API server received a Put request on "/mmds"') 'the logger writes to its file'
    return 'virtio-rng, rate-limited block, MMDS V2 over the net endpoint, balloon inflate + statistics, logger and metrics files'
}
# A balloon cycle on a guest restored from a memory file, then on a booted
# one, the counterpart of the macOS stage: the guest and the host keep using
# the same pages (O_DIRECT reads of the drive, whose buffers come from pages
# the balloon gave back, read what the file holds), and the pages the balloon
# took leave Firecracker's commit charge, which the jail's memory.max limits
# (row 15), and come back when the guest writes them again.
function Stage-Balloon {
    $disk = [Wick.Util]::Md5File($Rootfs, 64MB)
    $dir = Join-Path $Scratch 'balloon'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $cfg = Base-Config 2 512
    $cfg['balloon'] = [ordered]@{ amount_mib = 0; deflate_on_oom = $true; stats_polling_interval_s = 1 }
    # The O_DIRECT reads of the drive's first 64 MiB that read it wrong.
    $directReads = {
        param($vm, [int]$n)
        $bad = @()
        for ($i = 0; $i -lt $n; $i++) {
            $out = $vm.Sh('dd if=/dev/vda bs=1M count=64 iflag=direct 2>/dev/null | md5sum', 120000, $true)
            if ((Get-Fields $out)[0] -ne $disk) { $bad += $i }
        }
        return , $bad
    }
    $actual = {
        param($vm, [int]$mib)
        $until = [DateTime]::UtcNow.AddSeconds(60)
        while ($true) {
            $raw = Invoke-Api $vm 'GET' '/balloon/statistics'
            if (($raw | ConvertFrom-Json).actual_mib -eq $mib) { return }
            Check ([DateTime]::UtcNow -lt $until) "balloon statistics $raw, wanted $mib MiB"
            Start-Sleep -Milliseconds 500
        }
    }
    # Private bytes: the commit charge (Process.PagefileUsage is 32-bit).
    $commit = { param($vm) return (Get-Process -Id $vm.Pid).PrivateMemorySize64 }
    # Pages the guest wrote and freed: what the balloon hands over is then
    # backed on the host, and so is what O_DIRECT reads land in.
    $dirty = 'mount -t tmpfs -o size=300m tmpfs /tmp 2>/dev/null; head -c 200m /dev/urandom > /tmp/f && rm /tmp/f'

    # A guest restored from a memory file.
    $vm = Start-Vm 'balloon-1' $cfg -Api
    Wait-Shell $vm
    $bad = & $directReads $vm 2
    Check ($bad.Count -eq 0) "O_DIRECT reads $($bad -join ', ') of /dev/vda read it wrong before any balloon"
    $vm.Sh($dirty, 120000, $true) | Out-Null
    $state = Join-Path $dir 'balloon.state'
    $mem = Join-Path $dir 'balloon.mem'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
    $vm.Kill()
    $vm = Start-Vm 'balloon-2' $null -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
        resume_vm     = $true
    }) | Out-Null
    Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 150 }) | Out-Null
    & $actual $vm 150
    Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 0 }) | Out-Null
    & $actual $vm 0
    $bad = & $directReads $vm 6
    Check ($bad.Count -eq 0) "after a restore from file and a 150 MiB balloon cycle, O_DIRECT reads $($bad -join ', ') of /dev/vda read it wrong"
    $vm.Reboot()
    Remove-Item -Force $mem, $state

    # A booted guest: the commit charge goes down by what the balloon took
    # and up again when the guest writes the pages again.
    $vm = Start-Vm 'balloon-3' $cfg -Api
    Wait-Shell $vm
    $vm.Sh($dirty, 120000, $true) | Out-Null
    $before = & $commit $vm
    Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 150 }) | Out-Null
    & $actual $vm 150
    $inflated = & $commit $vm
    Check (($before - $inflated) -ge 100MB) ("commit charge {0} MiB before a 150 MiB balloon, {1} MiB after" -f ($before -shr 20), ($inflated -shr 20))
    Invoke-Api $vm 'PATCH' '/balloon' ([ordered]@{ amount_mib = 0 }) | Out-Null
    & $actual $vm 0
    $bad = & $directReads $vm 6
    Check ($bad.Count -eq 0) "after a 150 MiB balloon cycle, O_DIRECT reads $($bad -join ', ') of /dev/vda read it wrong"
    $vm.Sh($dirty, 120000, $true) | Out-Null
    $again = & $commit $vm
    Check (($again - $inflated) -ge 100MB) ("commit charge {0} MiB while inflated, {1} MiB after the guest wrote 200 MiB again" -f ($inflated -shr 20), ($again -shr 20))
    Save-Dmesg $vm 'balloon'
    $vm.Reboot()
    $summary = "on a booted guest, commit charge {0} -> {1} -> {2} MiB and reads match 6 of 6" -f ($before -shr 20), ($inflated -shr 20), ($again -shr 20)
    return "150 MiB balloon cycles: after a restore from file, O_DIRECT reads of /dev/vda match 6 of 6; $summary"
}

function Stage-Hugepages {
    $priv = (whoami /priv | Select-String 'SeLockMemoryPrivilege') -ne $null
    Check $priv ("this account lacks 'Lock pages in memory' (SeLockMemoryPrivilege): an administrator grants it in " +
        "secpol.msc, Local Policies, User Rights Assignment, then sign out and in")
    # The guest's memory in large pages, from this process, before Firecracker
    # asks for it: a host that cannot give them fails here by name, not with
    # Firecracker's bare OutOfMemory.
    $probe = [Wick.LargePages]::Probe(256MB)
    Check ($probe -eq '') "$probe (large page minimum $([Wick.LargePages]::Minimum()) bytes); the guest's 256 MiB are not to be had right now, which is the host's state, not Firecracker's"
    $cfg = Base-Config 2
    $cfg['machine-config']['huge_pages'] = '2M'
    $vm = Start-Vm 'hugepages' $cfg
    Wait-Shell $vm
    $mem = [int]$vm.Sh("awk '/MemTotal/ {print `$2}' /proc/meminfo")
    Check ($mem -gt 200000 -and $mem -le 262144) "MemTotal $mem kB for 256 MiB"
    # Touches most of guest memory.
    $out = $vm.Sh('mount -t tmpfs -o size=200m tmpfs /tmp && head -c 160m /dev/urandom > /tmp/f && md5sum /tmp/f > /tmp/a && md5sum /tmp/f | cmp - /tmp/a && echo same', 120000, $true)
    Check ($out -eq 'same') "160 MiB in guest memory read back differently: '$out'"
    Save-Dmesg $vm 'hugepages'
    $vm.Reboot()
    return '2 vCPUs on 2 MiB large pages: boots, 160 MiB written and read back'
}

# Runs Firecracker (or `exe`) to its end; returns its exit code and its
# output (stdout and stderr).
function Invoke-Exe([string]$exe, [string[]]$argv, [int]$ms = 30000) {
    $psi = New-Object Diagnostics.ProcessStartInfo($exe)
    $psi.Arguments = ($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # What Rust writes: UTF-8 (the console's code page otherwise).
    $psi.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $psi.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($ms)) {
        try { $p.Kill() } catch { }
        Fail "$(Split-Path -Leaf $exe) $($psi.Arguments): still running after $($ms / 1000) s"
    }
    $p.WaitForExit()
    return @($p.ExitCode, ($out.Result + $err.Result))
}

# Microseconds on CLOCK_MONOTONIC as Firecracker reads it on Windows (the
# performance counter, the clock of Stopwatch).
function Get-MonotonicUs {
    return [long]([double][Diagnostics.Stopwatch]::GetTimestamp() * 1000000 / [Diagnostics.Stopwatch]::Frequency)
}

# The metrics lines (JSON) in `text`, parsed.
function Get-MetricsLines([string]$text) {
    return @($text -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json })
}

# The origins (source files) of the log lines in `text`: what
# --show-log-origin writes after the level.
function Get-LogOrigins([string]$text) {
    return @([regex]::Matches($text, '\[[^\]\r\n]*?:(?:ERROR|WARN|INFO|DEBUG|TRACE):([^:\]\r\n]+\.rs):\d+\]') | ForEach-Object { $_.Groups[1].Value })
}

# Firecracker's own command line, the counterpart of the macOS stage:
# (a) exit codes, (b) --module, (c) --start-time-us, --start-time-cpu-us,
# --parent-cpu-time-us, (d) the logger and metrics on named pipes, the
# Windows counterpart of a FIFO, (e) --boot-timer. (a) needs no guest.
function Stage-Cli {
    $done = @()
    $dir = Join-Path $Results 'cli'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # (a) Upstream maps an argument parsing error to 153 (ArgParsing) and an
    # invalid --level to 152 (BadConfiguration); a configuration file that
    # does not parse is a generic error, 1 (main.rs, FcExitCode).
    $good = Join-Path $dir 'good.json'
    (Base-Config 1) | ConvertTo-Json -Depth 8 | Set-Content -Encoding ASCII $good
    $bad = Join-Path $dir 'bad.json'
    [IO.File]::WriteAllText($bad, '{"boot-source": {"kernel_image_path": ')
    $cases = @(
        @(@('--no-such-flag'), 153, 'ParseArguments'),
        @(@('--api-sock'), 153, 'ParseArguments'),
        @(@('--no-api', '--config-file', $good, '--level', 'Bogus'), 152, 'InvalidLogLevel'),
        @(@('--no-api', '--config-file', $bad), 1, 'ParseFromJson')
    )
    foreach ($c in $cases) {
        $r = Invoke-Exe $Fc $c[0]
        $tail = $r[1].Trim(); if ($tail.Length -gt 300) { $tail = $tail.Substring($tail.Length - 300) }
        Check ($r[0] -eq $c[1] -and $r[1].Contains($c[2]) -and $r[1].Contains("exit_code=$($c[1])")) "firecracker $($c[0] -join ' '): exit $($r[0]), wanted $($c[1]); $tail"
    }
    $done += 'exit 153 for bad arguments, 152 for a bad --level, 1 for a bad configuration file'
    Write-Step $done[-1]

    # (b) --module: only lines from modules under the filter are written;
    # file!() of a line names its crate's directory. Without a guest the
    # vmm crate logs nothing, so each filter boots one.
    $crates = [ordered]@{ vmm = 'src/vmm/'; firecracker = 'src/firecracker/' }
    $seen = @()
    foreach ($module in @('vmm', 'firecracker', '')) {
        $name = if ($module) { "cli-module-$module" } else { 'cli-module-all' }
        $metrics = Join-Path $dir "$name.metrics"
        New-Item -ItemType File -Force -Path $metrics | Out-Null
        $extra = "--metrics-path `"$metrics`""
        if ($module) { $extra += " --module $module" }
        $vm = Start-Vm $name (Base-Config 1) $extra -Api
        Wait-Shell $vm
        Invoke-Api $vm 'GET' '/machine-config' | Out-Null
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $vm.Reboot()
        $origins = Get-LogOrigins (Get-Content -Raw $vm.LogPath)
        Check ($origins.Count -gt 0) "--module ${module}: no log lines with an origin in $($vm.LogPath)"
        if ($module) {
            $stray = @($origins | Where-Object { -not $_.StartsWith($crates[$module]) } | Sort-Object -Unique)
            Check ($stray.Count -eq 0) "--module ${module}: lines from $(($stray | Select-Object -First 5) -join ', ')"
        } else {
            foreach ($k in $crates.Keys) {
                Check (@($origins | Where-Object { $_.StartsWith($crates[$k]) }).Count -gt 0) "no filter: no line from $k"
            }
            # Without the start time flags both metrics stay 0.
            $api = (Get-MetricsLines (Get-Content -Raw $metrics))[-1].api_server
            Check ($api.process_startup_time_us -eq 0 -and $api.process_startup_time_cpu_us -eq 0) "start time metrics without the flags: $($api | ConvertTo-Json -Compress)"
        }
        $seen += "$(if ($module) { $module } else { 'all' })=$($origins.Count)"
    }
    $done += "--module keeps its crate's lines ($($seen -join ', '))"
    Write-Step $done[-1]

    # (c, d) --start-time-us is CLOCK_MONOTONIC in us (what the jailer
    # passes), --start-time-cpu-us the CPU time the process had at the exec,
    # --parent-cpu-time-us the jailer's: once the API server is up the
    # metrics hold the time since the start and the CPU time since then plus
    # the parent's (ProcessTimeReporter). The metrics go to a named pipe
    # given on the command line, the log to one given through the API,
    # before the microVM is configured and started there (upstream refuses
    # PUT /logger once it runs: OperationNotSupportedPostBoot), as the
    # macOS stage does with FIFOs. Unlike a FIFO, a pipe exists only while
    # its reader holds it, so the readers are made first; Firecracker
    # connects to them.
    $tag = "wick-bt-$PID"
    $mpipe = New-Object Wick.PipeReader("$tag-metrics", $true, 65536)
    $lpipe = New-Object Wick.PipeReader("$tag-log", $true, 65536)
    try {
        $parent = 1000
        $t0 = Get-MonotonicUs
        $vm = Start-Vm 'cli-time' $null "--start-time-us $t0 --start-time-cpu-us 0 --parent-cpu-time-us $parent --metrics-path $($mpipe.Path)" -Api
        Check ($mpipe.WaitConnected(10000)) "Firecracker did not open the metrics pipe $($mpipe.Path)"
        Invoke-Api $vm 'PUT' '/logger' ([ordered]@{ log_path = $lpipe.Path; level = 'Info' }) | Out-Null
        Check ($lpipe.WaitConnected(10000)) "Firecracker did not open the log pipe $($lpipe.Path)"
        Invoke-Api $vm 'GET' '/machine-config' | Out-Null
        # Metrics are flushed on demand once the microVM runs.
        $cfg = Base-Config 1
        Invoke-Api $vm 'PUT' '/boot-source' $cfg['boot-source'] | Out-Null
        Invoke-Api $vm 'PUT' '/drives/rootfs' $cfg['drives'][0] | Out-Null
        Invoke-Api $vm 'PUT' '/machine-config' $cfg['machine-config'] | Out-Null
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'InstanceStart' }) | Out-Null
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $wall = (Get-MonotonicUs) - $t0
        Check ($mpipe.WaitFor('utc_timestamp_ms', 10000)) "no metrics through the pipe: '$($mpipe.Text)'"
        Check ($lpipe.WaitFor('Get request on "/machine-config"', 10000)) "no log lines through the pipe: '$($lpipe.Text)'"
        $api = (Get-MetricsLines $mpipe.Text)[-1].api_server
        $start = [long]$api.process_startup_time_us
        $cpu = [long]$api.process_startup_time_cpu_us
        $ncpu = [Environment]::ProcessorCount
        Check ($start -gt 0 -and $start -le $wall) "process_startup_time_us $start, $wall us since --start-time-us"
        Check ($cpu -gt $parent -and $cpu -lt $parent + $wall * $ncpu) "process_startup_time_cpu_us $cpu (parent $parent, wall $wall us, $ncpu CPUs)"
        # The readers go away mid-run. On Linux Firecracker holds both FIFOs
        # open read-write and non-blocking (open_file_nonblock), so a write
        # with no reader goes into the FIFO, and fails with EAGAIN only past
        # its 64 KiB; a reader that opens the FIFO later reads what is in
        # it. A Windows pipe ends with its reader (a write then fails with
        # 232 or 233), so Firecracker keeps what it writes meanwhile, to
        # the same 64 KiB, and gives it to the reader that makes the pipe
        # again (overlay/vmm/ext/fifo.rs, wick_os::fifo). So FlushMetrics
        # answers 204 here, as on Linux (Invoke-Api fails on anything else),
        # and new readers of the two names get that metrics line and log
        # lines of these requests.
        #
        # Each request's time, with the readers and without, printed and in
        # the failure: a PC's runs took 789 s here and their FlushMetrics
        # after the requests was refused (would block). The requests took
        # under 3 ms each either way (PC, c2042da); the time was the log
        # reader's Close, which waited for Firecracker's next log line
        # (PipeReader). The steps' times say where a run spends it.
        $timed = {
            param([int]$n)
            $each = New-Object Collections.Generic.List[double]
            for ($i = 0; $i -lt $n; $i++) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                Invoke-Api $vm 'GET' '/machine-config' | Out-Null
                $each.Add($sw.Elapsed.TotalMilliseconds)
            }
            $sorted = @($each | Sort-Object)
            '{0} GET /machine-config in {1:N1} s: median {2:N1} ms, max {3:N1} ms' -f $n, (($each | Measure-Object -Sum).Sum / 1000), $sorted[[int]($n / 2)], $sorted[-1]
        }
        $with = & $timed 50
        $mpipe.Close()
        $lpipe.Close()
        Write-Step "the pipes' readers closed"
        $without = & $timed 500
        $requests = "with the readers $with; without them $without"
        Write-Step "requests' times: $requests"
        try {
            Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        } catch {
            $f = Get-Failure $_
            if (-not $f) { throw }
            Fail "$($f.Message) (after the pipes' readers went: $requests)"
        }
        $mpipe = New-Object Wick.PipeReader("$tag-metrics", $true, 65536)
        $lpipe = New-Object Wick.PipeReader("$tag-log", $true, 65536)
        Check ($mpipe.WaitFor('utc_timestamp_ms', 10000)) "the metrics pipe's new reader did not get the line flushed while there was none: '$($mpipe.Text)'"
        Check ($lpipe.WaitFor('Get request on "/machine-config"', 10000)) "the log pipe's new reader did not get the lines written while there was none: '$($lpipe.Text)'"
        Wait-Shell $vm
        $out = $vm.Sh('echo after-$((6*7))')
        Check ($out -eq 'after-42' -and -not $vm.Exited) "after the pipes' readers went away: '$out' ($($vm.ExitReason()))"
        $vm.Reboot()
        $done += "start time metrics $start us, $cpu CPU us (of $wall us); logger and metrics on named pipes; once their readers went FlushMetrics answers 204, new readers get what was written meanwhile, and the microVM goes on ($requests)"
        Write-Step $done[-1]
    } finally {
        $mpipe.Close(); $lpipe.Close()
    }

    # A log pipe nobody ever reads, given on the command line: once its
    # buffer is full each line is lost and counted in
    # logger.missed_log_count (logging.rs), as on Linux with a FIFO.
    $unread = New-Object Wick.PipeReader("$tag-unread", $false, 4096)
    try {
        $metrics = Join-Path $dir 'cli-unread.metrics'
        New-Item -ItemType File -Force -Path $metrics | Out-Null
        $vm = Start-Vm 'cli-unread' (Base-Config 1) "--metrics-path `"$metrics`"" -Api -LogPath $unread.Path
        Check ($unread.WaitConnected(10000)) "Firecracker did not open the log pipe nobody reads"
        Wait-Shell $vm
        for ($i = 0; $i -lt 2000; $i++) { Invoke-Api $vm 'GET' '/machine-config' | Out-Null }
        Invoke-Api $vm 'PUT' '/actions' ([ordered]@{ action_type = 'FlushMetrics' }) | Out-Null
        $missed = [long](Get-MetricsLines (Get-Content -Raw $metrics))[-1].logger.missed_log_count
        Check ($missed -gt 0) "logger.missed_log_count $missed after 2000 requests logged to a pipe nobody reads"
        $out = $vm.Sh('echo unread-$((6*7))')
        Check ($out -eq 'unread-42' -and -not $vm.Exited) "guest with an unread log pipe: '$out' ($($vm.ExitReason()))"
        $vm.Reboot()
        $done += "a log pipe nobody reads: $missed lines missed and counted, the microVM goes on"
        Write-Step $done[-1]
    } finally {
        $unread.Close()
    }

    # (e) --boot-timer: the guest's /usr/local/bin/init (upstream's rootfs
    # overlay) writes 123 to the boot timer device through /dev/mem, then
    # runs /sbin/init; upstream's test_boottime boots it so. Without the
    # flag there is no device.
    $timer = 'Guest-boot-time =\s+(\d+) us\s+(\d+) ms,\s+(\d+) CPU us\s+(\d+) CPU ms'
    $bootArgs = $BootArgs -replace 'init=/bin/sh', 'init=/usr/local/bin/init'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $vm = Start-Vm 'cli-boot-timer' (Base-Config 1 256 $bootArgs) '--boot-timer'
    $until = [DateTime]::UtcNow.AddSeconds(60)
    $m = $null
    while ([DateTime]::UtcNow -lt $until) {
        $m = [regex]::Match((Get-Content -Raw $vm.LogPath) + $vm.Output, $timer)
        if ($m.Success -or $vm.Exited) { break }
        Start-Sleep -Milliseconds 200
    }
    $wall = $sw.Elapsed.TotalMilliseconds * 1000
    Check ($m -and $m.Success) "no Guest-boot-time line within 60 s ($($vm.ExitReason()))"
    $us = [long]$m.Groups[1].Value; $cpuUs = [long]$m.Groups[3].Value
    $ncpu = [Environment]::ProcessorCount
    # Both are differences of two clock reads (boot_timer.rs, unsigned): a
    # read that failed would leave 0 and the difference wrap to near 2^64.
    Check ($us -gt 0 -and $us -lt $wall -and $cpuUs -gt 0 -and $cpuUs -lt $wall * $ncpu -and [long]$m.Groups[2].Value -eq [math]::Floor($us / 1000) -and [long]$m.Groups[4].Value -eq [math]::Floor($cpuUs / 1000)) "Guest-boot-time '$($m.Value)'; $([long]$wall) us since the start, $ncpu host CPUs"
    # The guest goes on to /sbin/init.
    $vm.WaitFor('systemd\[1\]|Welcome to', 60000, 0) | Out-Null
    Check (-not $vm.Exited) "Firecracker after the boot timer write: $($vm.ExitReason())"
    $vm.Kill()
    $vm = Start-Vm 'cli-no-boot-timer' (Base-Config 1 256 $bootArgs)
    $vm.WaitFor('Run /usr/local/bin/init as init process', 60000, 0) | Out-Null
    $vm.WaitFor('systemd\[1\]|Welcome to', 60000, 0) | Out-Null
    Check (-not [regex]::IsMatch((Get-Content -Raw $vm.LogPath) + $vm.Output, $timer)) 'Guest-boot-time without --boot-timer'
    $vm.Kill()
    $done += "--boot-timer: Guest-boot-time $us us ($cpuUs CPU us), none without it"
    return ($done -join '; ')
}

# Copies `base` to `out`, rebases it with `diff` through `tool`
# (rebase-snap or snapshot-editor); returns its exit code and output.
function Invoke-Rebase([string]$tool, [string]$base, [string]$diff) {
    if ($tool -eq 'rebase-snap') {
        return Invoke-Exe (Find-Tool 'rebase-snap.exe') @('--base-file', $base, '--diff-file', $diff)
    }
    return Invoke-Exe (Find-Tool 'snapshot-editor.exe') @('edit-memory', 'rebase', '--memory-path', $base, '--diff-path', $diff)
}

# rebase-snap and snapshot-editor, the counterpart of the macOS stage: on a
# diff file NTFS keeps holes in (sparse) and one it does not (refused, the
# base untouched: patches/0036), both without a guest; then on a diff
# snapshot of a 2 vCPU guest, with snapshot-editor's info-vmstate commands
# and Firecracker's refusal of a state file of another architecture or
# snapshot version.
function Stage-Tools {
    $done = @()
    $dir = Join-Path $Scratch 'tools'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $size = 16MB
    $base = Join-Path $dir 'synthetic-base.bin'
    $want = Join-Path $dir 'synthetic-want.bin'
    [Wick.Util]::WriteRandom($base, $size)
    $data = [Wick.Util]::Random(64KB)
    Copy-Item $base $want
    $fs = [IO.File]::OpenWrite($want); $fs.Position = 4MB; $fs.Write($data, 0, $data.Length); $fs.Close()
    $sparse = Join-Path $dir 'synthetic-sparse.diff'
    $dense = Join-Path $dir 'synthetic-dense.diff'
    [Wick.Sparse]::Write($sparse, $size, $data, 4MB, $true)
    [Wick.Sparse]::Write($dense, $size, $data, 4MB, $false)
    Check ([Wick.Sparse]::Is($sparse) -and -not [Wick.Sparse]::Is($dense)) 'the synthetic diff files'
    foreach ($tool in @('rebase-snap', 'snapshot-editor')) {
        $b = Join-Path $dir "synthetic-$tool.bin"
        Copy-Item $base $b -Force
        $r = Invoke-Rebase $tool $b $dense
        Check ($r[0] -ne 0 -and $r[1] -match 'not a sparse file') "${tool}: a diff file that is not sparse: exit $($r[0]) $($r[1].Trim())"
        $changed = [Wick.Sparse]::Differ($b, $base)
        Check ($changed -eq 0) "${tool}: refused, yet $changed bytes of the base changed"
        $r = Invoke-Rebase $tool $b $sparse
        Check ($r[0] -eq 0) "${tool}: a sparse diff file: exit $($r[0]) $($r[1].Trim())"
        $wrong = [Wick.Sparse]::Differ($b, $want)
        Check ($wrong -eq 0) "${tool}: $wrong bytes wrong after rebasing a sparse diff"
    }
    $done += 'a sparse diff rebased right and one that is not refused, the base untouched, by both tools'
    Write-Step $done[-1]

    $editor = Find-Tool 'snapshot-editor.exe'
    $cfg = Base-Config 2
    $cfg['machine-config']['track_dirty_pages'] = $true
    $vm = Start-Vm 'tools-1' $cfg -Api
    Wait-Shell $vm
    $vm.Sh('A=before-$((6*7))') | Out-Null
    $bashMd5 = $vm.Sh('md5sum /usr/bin/bash')
    $mem = Join-Path $dir 'base.mem'
    $diff = Join-Path $dir 'diff.mem'
    $state = Join-Path $dir 'diff.state'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    $fullState = Join-Path $dir 'full.state'
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $fullState; mem_file_path = $mem }) | Out-Null
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Resumed' } | Out-Null
    $vm.Sh('B=second-$((7*7)); cat /usr/bin/* > /dev/null 2>&1; true', 120000, $true) | Out-Null
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Diff'; snapshot_path = $state; mem_file_path = $diff }) | Out-Null
    $vm.Kill()
    # Firecracker writes a diff snapshot as a sparse file (keep_holes), with
    # holes where no page was dirtied (what rebase-snap copies around).
    $size = (Get-Item $diff).Length
    $allocated = [Wick.Util]::Allocated($diff)
    Check ([Wick.Sparse]::Is($diff) -and $size -eq 256MB -and $allocated -lt $size) "diff memory file: $size bytes, $allocated allocated, $((Get-Item $diff).Attributes)"

    # snapshot-editor info-vmstate: the version, the vCPU states and the
    # whole state (info.rs).
    $r = Invoke-Exe $editor @('info-vmstate', 'version', '--vmstate-path', $state)
    Check ($r[0] -eq 0 -and $r[1].Trim() -eq 'v12.0.0') "info-vmstate version: $($r[0]) '$($r[1].Trim())'"
    $r = Invoke-Exe $editor @('info-vmstate', 'vcpu-states', '--vmstate-path', $state)
    # Kept with the results: the state file (a few KiB) and the listing.
    $keep = Join-Path $Results 'tools'
    New-Item -ItemType Directory -Force -Path $keep | Out-Null
    Copy-Item $state (Join-Path $keep 'diff.state')
    [IO.File]::WriteAllText((Join-Path $keep 'vcpu-states.txt'), $r[1])
    Check ($r[0] -eq 0) "info-vmstate vcpu-states: $($r[0]) $($r[1])"
    $parts = [regex]::Split($r[1], '(?m)^vcpu (\d+):\r?$')
    $ids = @(); for ($i = 1; $i -lt $parts.Count; $i += 2) { $ids += $parts[$i] }
    Check (($ids -join ',') -eq '0,1') "vcpu-states lists vCPUs $($ids -join ',')"
    $seen = @()
    for ($i = 0; $i -lt 2; $i++) {
        $body = $parts[2 * $i + 2]
        # x86_64: kvm_mp_state RUNNABLE (0) or, for a vCPU idle in HLT,
        # HALTED (3), as KVM reports a paused guest's (x86.c:
        # __kvm_emulate_halt sets HALTED, kvm_arch_vcpu_ioctl_get_mpstate
        # returns it); and the instruction pointer in kernel space (a guest
        # whose only process is an idle shell).
        $mp = [regex]::Match($body, 'mp_state: (\d+),')
        $rip = [regex]::Match($body, '(?m)^\s*rip: (\d+),')
        $mpv = if ($mp.Success) { [int]$mp.Groups[1].Value } else { -1 }
        $ripv = if ($rip.Success) { [UInt64]::Parse($rip.Groups[1].Value) } else { [UInt64]0 }
        $what = "vcpu ${i}: mp_state $(if ($mp.Success) { $mpv } else { 'missing' }), rip $(if ($rip.Success) { '0x{0:x}' -f $ripv } else { 'missing' }) (listing in $keep\vcpu-states.txt)"
        Check ($mpv -eq 0 -or $mpv -eq 3) $what
        Check ($ripv -ge [UInt64]'18446603336221196288') $what
        $seen += "mp_state $mpv"
    }
    $r = Invoke-Exe $editor @('info-vmstate', 'vm-state', '--vmstate-path', $state)
    Check ($r[0] -eq 0 -and $r[1] -match 'mem_size_mib: 256' -and ([regex]::Matches($r[1], 'kvm_mp_state \{')).Count -eq 2 -and $r[1] -match 'device_states:') "info-vmstate vm-state: $($r[0]) $($r[1].Substring(0, [math]::Min(300, $r[1].Length)))"
    $r = Invoke-Exe $editor @('info-vmstate', 'version', '--vmstate-path', $Kernel)
    Check ($r[0] -ne 0) "info-vmstate version of a kernel image: $($r[0]) $($r[1])"
    $done += "info-vmstate version v12.0.0, vcpu-states (2 vCPUs: $($seen -join ', '), RIP in the kernel), vm-state; a non-snapshot refused"
    Write-Step $done[-1]

    # rebase-snap (deprecated for snapshot-editor edit-memory rebase): the
    # diff's data written over the base; both tools give the same file.
    $other = Join-Path $dir 'base2.mem'
    Copy-Item $mem $other
    $r = Invoke-Rebase 'rebase-snap' $mem $diff
    Check ($r[0] -eq 0) "rebase-snap: $($r[0]) $($r[1].Trim())"
    $r = Invoke-Rebase 'snapshot-editor' $other $diff
    Check ($r[0] -eq 0) "snapshot-editor rebase: $($r[0]) $($r[1].Trim())"
    Check ([Wick.Util]::Md5File($mem, -1) -eq [Wick.Util]::Md5File($other, -1)) 'rebase-snap and snapshot-editor rebase give different memory files'
    Remove-Item $other
    $vm = Start-Vm 'tools-2' $null -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
        resume_vm     = $true
    }) | Out-Null
    Test-Restored $vm $bashMd5 $null
    $out = $vm.Sh('echo $A $B')
    Check ($out -eq 'before-42 second-49') "after a rebase-snap restore: '$out'"
    Save-Dmesg $vm 'tools-2'
    $vm.Reboot()
    $done += 'rebase-snap equals snapshot-editor rebase and restores'
    Write-Step $done[-1]

    # A state file with another architecture's magic, then with a newer
    # version, is refused at the load with upstream's error (snapshot/mod.rs,
    # checked before the CRC), by snapshot-editor and by Firecracker, which
    # then ends as after any failed load. bitcode writes the header first: a
    # byte, the magic (8 bytes, little-endian), the version's length and text.
    $bytes = [IO.File]::ReadAllBytes($fullState)
    $x86 = [BitConverter]::GetBytes([UInt64]'0x0710198486640000')
    for ($i = 0; $i -lt 8; $i++) { Check ($bytes[1 + $i] -eq $x86[$i]) "the x86_64 magic is not at offset 1 of $fullState" }
    Check ([Text.Encoding]::ASCII.GetString($bytes, 10, 6) -eq '12.0.0') "the version is not at offset 10 of $fullState"
    $arm = [byte[]]$bytes.Clone()
    [Array]::Copy([BitConverter]::GetBytes([UInt64]'0x07101984AAAA0000'), 0, $arm, 1, 8)
    $newer = [byte[]]$bytes.Clone()
    $newer[10] = [byte][char]'9'; $newer[11] = [byte][char]'9'
    foreach ($case in @(@('aarch64 magic', $arm, 'Magic value does not match arch'), @('version 99.0.0', $newer, 'Invalid data version'))) {
        $f = Join-Path $dir 'patched.state'
        [IO.File]::WriteAllBytes($f, $case[1])
        $r = Invoke-Exe $editor @('info-vmstate', 'version', '--vmstate-path', $f)
        Check ($r[0] -ne 0 -and $r[1].Contains($case[2])) "info-vmstate of a state file with $($case[0]): $($r[0]) $($r[1].Trim())"
        $vm = Start-Vm "tools-$($case[0] -replace '\W', '')" $null -Api
        $status = 0
        $body = [ordered]@{ snapshot_path = $f; mem_backend = [ordered]@{ backend_type = 'File'; backend_path = $mem } } | ConvertTo-Json -Compress
        $out = [Wick.Api]::Call($vm.ApiSock, 'PUT', '/snapshot/load', $body, 30000, [ref]$status)
        Check ($status -eq 400 -and $out.Contains($case[2])) "a state file with $($case[0]): $status $out"
        $until = [DateTime]::UtcNow.AddSeconds(10)
        while (-not $vm.Exited -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
        Check ($vm.Exited -and $vm.ExitCode -ne 0) "Firecracker after a failed load ($($case[0])): $($vm.ExitReason())"
    }
    $done += 'a state file with the aarch64 magic or a newer version refused by snapshot-editor and the load'
    return ($done -join '; ')
}

# A snapshot state file made on another host (-ForeignState; the macOS
# boot test's snapshot stage makes an aarch64 one): refused at the load
# with upstream's error, and Firecracker ends, as after any failed load.
# The same upstream decoding as on Linux; needs no guest.
function Stage-ForeignSnapshot {
    Check ($ForeignState -and (Test-Path $ForeignState)) 'pass -ForeignState <a snapshot state file made on another host, e.g. by tools/macos/boot-test.py snapshot>'
    $vm = Start-Vm 'foreign-snapshot' $null -Api
    $status = 0
    $body = [ordered]@{ snapshot_path = (Resolve-Path $ForeignState).Path; mem_backend = [ordered]@{ backend_type = 'File'; backend_path = (Join-Path $Scratch 'none.mem') } } | ConvertTo-Json -Compress
    $out = [Wick.Api]::Call($vm.ApiSock, 'PUT', '/snapshot/load', $body, 30000, [ref]$status)
    Check ($status -eq 400 -and $out -match 'Failed to load snapshot state from file') "PUT /snapshot/load of $ForeignState`: $status $out"
    $until = [DateTime]::UtcNow.AddSeconds(10)
    while (-not $vm.Exited -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
    Check ($vm.Exited -and $vm.ExitCode -ne 0) "Firecracker after a failed load: $($vm.ExitReason())"
    $why = ([regex]::Match($out, 'Failed to load snapshot state from file: ([^"]*)')).Groups[1].Value
    $r = Invoke-Exe (Find-Tool 'snapshot-editor.exe') @('info-vmstate', 'version', '--vmstate-path', $ForeignState)
    Check ($r[0] -ne 0) "snapshot-editor info-vmstate version of it: $($r[0]) $($r[1])"
    return "refused at the load ($why), Firecracker exits; snapshot-editor refuses it too"
}

# The guest's CPU flags (/proc/cpuinfo), after checking that every CPU
# lists the same.
function Get-GuestFlags($vm, [string]$when) {
    $out = $vm.Sh('grep ^flags /proc/cpuinfo')
    $lines = @($out -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { ($_ -split ':', 2)[1].Trim() })
    Check ($lines.Count -eq 2 -and $lines[0] -eq $lines[1]) "$when`: the guest's two CPUs list different flags, or not two CPUs: '$out'"
    return @(Get-Fields $lines[0])
}

# A guest started through the API with a CPU template put before the
# start. Returns the VM and the start's status and body.
function Start-WithTemplate([string]$name, $cfg, $template) {
    $vm = Start-Vm $name $null -Api
    Invoke-Api $vm 'PUT' '/boot-source' $cfg['boot-source'] | Out-Null
    Invoke-Api $vm 'PUT' '/drives/rootfs' $cfg['drives'][0] | Out-Null
    Invoke-Api $vm 'PUT' '/machine-config' $cfg['machine-config'] | Out-Null
    Invoke-Api $vm 'PUT' '/cpu-config' $template | Out-Null
    $status = 0
    $out = [Wick.Api]::Call($vm.ApiSock, 'PUT', '/actions', '{"action_type":"InstanceStart"}', 120000, [ref]$status)
    return @($vm, $status, $out)
}

# Custom CPU templates on x86_64 (upstream's test_api_cpu_config and
# test_cpu_template are skipped on a processor that is not in their table,
# which is every host here). A template is CPUID modifiers and MSR
# modifiers (cpu_config/x86_64/custom_cpu_template.rs); upstream applies the
# first to the supported CPUID and sets the result on every vCPU, and reads
# the MSRs of the second from vCPU 0, modifies and writes them
# (arch/x86_64/mod.rs, configure_vcpus_for_boot).
#
# The bits cleared here are three that every x86-64-v3 processor has, one
# in each leaf upstream's templates change most, and that no other flag of
# Linux's depends on (arch/x86/kernel/cpu/cpuid-deps.c): MOVBE (leaf 1 ECX
# bit 22), BMI1 (leaf 7 EBX bit 3), ABM (leaf 0x80000001 ECX bit 5).
function Stage-CpuTemplates {
    $bit = { param([int]$n) '0b' + ('x' * (31 - $n)) + '0' + ('x' * $n) }
    $leaf = { param([string]$l, [int]$flags, [string]$reg, [int]$n)
        [ordered]@{ leaf = $l; subleaf = '0x0'; flags = $flags; modifiers = @([ordered]@{ register = $reg; bitmap = (& $bit $n) }) } }
    $template = [ordered]@{ cpuid_modifiers = @((& $leaf '0x1' 0 'ecx' 22), (& $leaf '0x7' 1 'ebx' 3), (& $leaf '0x80000001' 0 'ecx' 5)) }
    $lost = @('movbe', 'bmi1', 'abm')
    $cfg = Base-Config 2

    $vm = Start-Vm 'tmpl-none' $cfg
    Wait-Shell $vm
    $hostFlags = Get-GuestFlags $vm 'no template'
    $vm.Kill()
    foreach ($f in $lost) { Check ($hostFlags -contains $f) "this host's guest has no $f without a template: $($hostFlags -join ' ')" }
    $want = @($hostFlags | Where-Object { $lost -notcontains $_ })

    $r = Start-WithTemplate 'tmpl-custom' $cfg $template
    $vm = $r[0]
    Check ($r[1] -eq 204) "InstanceStart with the template: $($r[1]) $($r[2])"
    Wait-Shell $vm
    $got = Get-GuestFlags $vm 'the template'
    $diff = @(Compare-Object $want $got | ForEach-Object { "$($_.SideIndicator)$($_.InputObject)" })
    Check ($diff.Count -eq 0) "the template's guest against the host's less $($lost -join ', '): $($diff -join ' ') (<= missing, => extra)"
    $warp = Test-CounterWarp $vm 'with the template, after the boot'
    $vm.Sh('A=before-$((6*7))') | Out-Null
    $bashMd5 = $vm.Sh('md5sum /usr/bin/bash')

    # The template is in the snapshot (each vCPU's CPUID is part of its state).
    $dir = Join-Path $Scratch 'cpu-templates'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $state = Join-Path $dir 'tmpl.state'
    $mem = Join-Path $dir 'tmpl.mem'
    Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
    Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
    $vm.Kill()
    $vm = Start-Vm 'tmpl-restored' $null -Api
    Invoke-Api $vm 'PUT' '/snapshot/load' ([ordered]@{
        snapshot_path = $state
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
        resume_vm     = $true
    }) | Out-Null
    Test-Restored $vm $bashMd5 $null
    $warpRestored = Test-CounterWarp $vm 'with the template, after a snapshot restore'
    # cpu1 offline and online: it comes back with the template's CPUID.
    $spurious = Test-CpuOfflineOnline $vm 'the template restored'
    $got = Get-GuestFlags $vm 'the template restored'
    $diff = @(Compare-Object $want $got | ForEach-Object { "$($_.SideIndicator)$($_.InputObject)" })
    Check ($diff.Count -eq 0) "the restored guest against the host's less $($lost -join ', '): $($diff -join ' ')"
    Save-Dmesg $vm 'tmpl-restored'
    $vm.Reboot()
    Remove-Item -Force $mem

    # A leaf the supported CPUID lacks: upstream's own refusal
    # (CpuConfigurationError::CpuidFeatureNotSupported), at the start.
    $r = Start-WithTemplate 'tmpl-leaf' $cfg ([ordered]@{ cpuid_modifiers = @((& $leaf '0x8fffffff' 0 'eax' 0)) })
    Check ($r[1] -eq 400 -and $r[2] -match 'CPUID entry not supported by KVM: Leaf: 8fffffff') "a template of a CPUID leaf no host has: $($r[1]) $($r[2])"
    $r[0].Kill()

    # An MSR modifier of 0x10a (IA32_ARCH_CAPABILITIES), the one MSR
    # upstream's templates modify (T2S, T2CL). KVM keeps it for each vCPU;
    # this backend keeps it nowhere, so its KVM_GET_MSRS ends there and
    # upstream reports the MSR, where before the modifier was dropped and
    # the guest started without it.
    $r = Start-WithTemplate 'tmpl-msr' $cfg ([ordered]@{ msr_modifiers = @([ordered]@{ addr = '0x10a'; bitmap = '0b' + ('x' * 64) }) })
    Check ($r[1] -eq 400 -and $r[2] -match 'msr: 0x10a') "a template with a modifier of MSR 0x10a: $($r[1]) $($r[2])"
    $why = ([regex]::Match($r[2], '"fault_message":\s*"(.*)"')).Groups[1].Value
    $r[0].Kill()
    return "a template through PUT /cpu-config takes $($lost -join ', ') from the guest on both vCPUs, also after a restore and cpu1's restart (spurious LAPIC timer interrupts: $spurious); TSCs agree (after the boot: $warp; after the restore: $warpRestored); a leaf no host has is refused; a modifier of MSR 0x10a is refused ($why)"
}

# Upstream's test_diff_snapshot_works_after_error
# (test_snapshot_not_losing_dirty_pages.py): a diff snapshot that fails for
# lack of space must not lose the dirty pages, so that the next one, with
# the space there, is whole. Upstream puts the jail on a 512 MiB tmpfs and
# fills 90% of what is free with fallocate. Windows has no tmpfs; a small
# volume is a virtual disk file, made, attached, formatted and mounted on
# a directory by diskpart (create vdisk, attach vdisk, create partition
# primary, format, assign: the sequence of Microsoft's "Boot to a virtual
# hard disk", step 1; `assign mount=<path>` for the directory), which
# needs an elevated prompt. The fill is a file extended to its size: NTFS
# allocates the clusters of a file that is not sparse, as fallocate does.
# The error is Windows's for a full volume, ERROR_DISK_FULL (112), where
# upstream's test reads Linux's "No space left on device".
function Invoke-Diskpart([string]$dir, [string[]]$commands) {
    $script = Join-Path $dir 'diskpart.txt'
    Set-Content -Path $script -Value $commands -Encoding ASCII
    return Invoke-Exe (Join-Path $env:SystemRoot 'System32\diskpart.exe') @('/s', $script) 120000
}

function Stage-DiffNoSpace {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $admin 'this stage makes and attaches a virtual disk with diskpart, which needs an elevated prompt (run as administrator)'
    $dir = Join-Path $Scratch 'diff-nospace'
    $vhd = Join-Path $dir 'small.vhdx'
    $mnt = Join-Path $dir 'mnt'
    $detach = @("select vdisk file=`"$vhd`"", 'detach vdisk')
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if (Test-Path $vhd) {
        # What a killed run left: attached or not, the file must go, and
        # removing it fails if it is still attached.
        Invoke-Diskpart $dir $detach | Out-Null
        Remove-Item -Force $vhd
    }
    if (Test-Path $mnt) { [IO.Directory]::Delete($mnt) }
    New-Item -ItemType Directory -Path $mnt | Out-Null
    $r = Invoke-Diskpart $dir @("create vdisk file=`"$vhd`" maximum=512 type=expandable", 'attach vdisk', 'create partition primary',
        'format fs=ntfs quick', "assign mount=`"$mnt`"")
    Check ($r[0] -eq 0) "diskpart (a 512 MiB virtual disk mounted on $mnt): exit $($r[0]) $($r[1].Trim())"
    $vm = $null
    $vm2 = $null
    try {
        $free = [Wick.Util]::FreeSpace($mnt)
        Check ($free -gt 400MB -and $free -lt 512MB) "the new volume has $([math]::Round($free / 1MB)) MiB free of 512"
        $cfg = Base-Config 2
        $cfg['machine-config']['track_dirty_pages'] = $true
        $vm = Start-Vm 'diff-nospace-1' $cfg -Api
        Wait-Shell $vm
        $vm.Sh('A=before-$((6*7))') | Out-Null
        $bashMd5 = $vm.Sh('md5sum /usr/bin/bash')
        # 100 MiB the guest wrote: more than the failed snapshot has room
        # for, and what the second one must not have lost.
        $vm.Sh('mount -t tmpfs -o size=128m tmpfs /tmp && dd if=/dev/urandom of=/tmp/f bs=1M count=100 2>/dev/null', 120000, $true) | Out-Null
        $written = $vm.Sh('md5sum /tmp/f')

        $fill = Join-Path $mnt 'fill'
        $target = [long][math]::Round($free * 0.9)
        $f = [IO.File]::Create($fill)
        try { $f.SetLength($target) } finally { $f.Close() }
        $left = [Wick.Util]::FreeSpace($mnt)
        Check ($left -lt 100MB -and $left -le $free - $target) "after a $([math]::Round($target / 1MB)) MiB fill the volume has $([math]::Round($left / 1MB)) MiB free (it had $([math]::Round($free / 1MB)))"

        $state = Join-Path $mnt 'diff.state'
        $mem = Join-Path $mnt 'diff.mem'
        $body = [ordered]@{ snapshot_type = 'Diff'; snapshot_path = $state; mem_file_path = $mem } | ConvertTo-Json -Compress
        Invoke-Api $vm 'PATCH' '/vm' @{ state = 'Paused' } | Out-Null
        $status = 0
        $out = [Wick.Api]::Call($vm.ApiSock, 'PUT', '/snapshot/create', $body, 120000, [ref]$status)
        Check ($status -eq 400 -and $out -match 'os error 112') "a diff snapshot with $([math]::Round($left / 1MB)) MiB free: $status $out"
        $why = ([regex]::Match($out, '"fault_message":\s*"(.*)"')).Groups[1].Value
        Check (-not $vm.Exited) "Firecracker after the failed snapshot: $($vm.ExitReason())"
        Write-Step "with $([math]::Round($left / 1MB)) MiB free: $status $why"

        Remove-Item -Force $fill
        Invoke-Api $vm 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Diff'; snapshot_path = $state; mem_file_path = $mem }) | Out-Null
        $vm.Kill()
        $allocated = [Wick.Util]::Allocated($mem)
        Check ((Get-Item $mem).Length -eq 256MB -and $allocated -ge 100MB) "the second diff file: $((Get-Item $mem).Length) bytes, $([math]::Round($allocated / 1MB)) MiB allocated"

        # As upstream: the diff alone is the memory file (the first diff of
        # a guest holds every page it has touched).
        $vm2 = Start-Vm 'diff-nospace-2' $null -Api
        Invoke-Api $vm2 'PUT' '/snapshot/load' ([ordered]@{
            snapshot_path = $state
            mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = $mem }
            resume_vm     = $true
        }) | Out-Null
        Test-Restored $vm2 $bashMd5 $null
        $out = $vm2.Sh('md5sum /tmp/f')
        Check ($out -eq $written) "the 100 MiB written before the failed snapshot, after the restore: '$out', before '$written'"
        Save-Dmesg $vm2 'diff-nospace-2'
        $vm2.Reboot()
        $result = "a diff snapshot with $([math]::Round($left / 1MB)) MiB free fails ($why) and Firecracker stays; with the space back the next one ($([math]::Round($allocated / 1MB)) MiB) restores with the 100 MiB the guest wrote before"
    } finally {
        # Nothing may hold the volume when its disk is detached.
        if ($vm) { $vm.Kill() }
        if ($vm2) { $vm2.Kill() }
        $r = Invoke-Diskpart $dir $detach
        if ($r[0] -ne 0) { Write-Host "  ! diskpart detach of $vhd`: exit $($r[0]) $($r[1].Trim())" }
    }
    # Reached only when the steps above passed; a failure of theirs is the
    # stage's, with the detach's own printed above.
    Check ($r[0] -eq 0) "diskpart detach of $vhd`: exit $($r[0]) $($r[1].Trim())"
    [IO.Directory]::Delete($mnt)
    Remove-Item -Force $vhd
    return $result
}

# A whole snapshot made on Linux x86_64 (KVM) by the same Firecracker
# version (-LinuxSnapshot: tools/linux/make-vmstate.py's fourth argument,
# CI's artifact linux-snapshot), loaded and resumed here. Upstream supports
# a snapshot only on the host kind it was made on (docs/snapshotting/
# snapshot-support.md), and this is another hypervisor, so the stage is a
# record: what the load answers and, if it is taken, whether the guest
# goes on. The state names the root drive by its file name alone, and the
# drive is this test's own copy of the same file (the text file has its
# SHA-256), so Firecracker runs in the directory that holds it.
function Stage-LinuxSnapshot {
    Check ($LinuxSnapshot -and (Test-Path $LinuxSnapshot)) 'pass -LinuxSnapshot <the directory tools/linux/make-vmstate.py kept a whole snapshot in; CI: the artifact linux-snapshot>'
    $state = Join-Path $LinuxSnapshot 'linux-x86_64.vmstate'
    $mem = Join-Path $LinuxSnapshot 'linux-x86_64.mem'
    $txt = Join-Path $LinuxSnapshot 'linux-x86_64.txt'
    foreach ($f in @($state, $mem, $txt)) { Check (Test-Path $f) "$f is missing" }
    $about = @(Get-Content $txt)
    $made = ($about | Select-Object -First 2) -join ', '
    $m = [regex]::Match(($about -join "`n"), '(?m)^rootfs: (\S+), (\d+) bytes, sha256 ([0-9a-f]{64})')
    Check $m.Success "$txt does not name the root drive's file"
    Check ($m.Groups[1].Value -eq (Split-Path -Leaf $Rootfs)) "the snapshot's root drive is $($m.Groups[1].Value), this test's is $(Split-Path -Leaf $Rootfs)"
    $sha = (Get-FileHash -Algorithm SHA256 $Rootfs).Hash.ToLower()
    Check ($sha -eq $m.Groups[3].Value) "this test's $(Split-Path -Leaf $Rootfs) (sha256 $sha) is not the file the snapshot was made with ($($m.Groups[3].Value))"
    # Firecracker in the drive's directory: a new process starts in .NET's
    # current directory, not PowerShell's location.
    $before = [Environment]::CurrentDirectory
    [Environment]::CurrentDirectory = Split-Path -Parent $Rootfs
    try { $vm = Start-Vm 'linux-snapshot' $null -Api } finally { [Environment]::CurrentDirectory = $before }
    $status = 0
    $body = [ordered]@{
        snapshot_path = (Resolve-Path $state).Path
        mem_backend   = [ordered]@{ backend_type = 'File'; backend_path = (Resolve-Path $mem).Path }
        resume_vm     = $true
    } | ConvertTo-Json -Compress
    $out = [Wick.Api]::Call($vm.ApiSock, 'PUT', '/snapshot/load', $body, 120000, [ref]$status)
    if ($status -lt 200 -or $status -ge 300) {
        $until = [DateTime]::UtcNow.AddSeconds(10)
        while (-not $vm.Exited -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 }
        Check ($vm.Exited -and $vm.ExitCode -ne 0) "Firecracker after a refused load ($status $out): $($vm.ExitReason())"
        # What the backend said of it: the WHP call and register a refusal
        # of the vCPU state comes from (`whp:` lines, ffi::hr_of), which the
        # API's error, an errno, does not name.
        $vm.Drain(5000)
        $said = $vm.Output + "`n" + (Get-Content -Raw $vm.LogPath -ErrorAction SilentlyContinue)
        $whp = @($said -split "`n" | Where-Object { $_ -match 'whp:' } | ForEach-Object { $_.Trim() } | Select-Object -First 5)
        return "REFUSED at the load: $status $out; Firecracker exits, as after any failed load. Snapshot made by: $made. The backend's lines: $(if ($whp.Count) { $whp -join ' | ' } else { 'none' })"
    }
    $vm.Shell(60000)
    $out = $vm.Sh('echo alive $((6*7))')
    Check ($out -eq 'alive 42') "the resumed guest's shell: '$out'"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = $vm.Sh('cat /proc/uptime; sleep 1; cat /proc/uptime')
    $host_dt = $sw.Elapsed.TotalSeconds
    $lines = @($out -split "`n" | Where-Object { $_.Trim() })
    Check ($lines.Count -eq 2) "uptime twice after the restore: '$out'"
    $a = [double]::Parse((Get-Fields $lines[0])[0], [Globalization.CultureInfo]::InvariantCulture)
    $b = [double]::Parse((Get-Fields $lines[1])[0], [Globalization.CultureInfo]::InvariantCulture)
    Check (($b - $a) -gt 0.9 -and ($b - $a) -le $host_dt + 0.1) ("guest clock advanced {0:N2} s in {1:N2} s after the restore" -f ($b - $a), $host_dt)
    $out = $vm.Sh('md5sum /usr/bin/bash')
    Check ($out -match '^[0-9a-f]{32} ') "the root drive read after the restore: '$out'"
    Save-Dmesg $vm 'linux-snapshot'
    $vm.Reboot()
    return "RESTORED and resumed: the guest's shell answers, its clock runs, the root drive is read, a reset exits 0. Snapshot made by: $made"
}

# --no-seccomp turns the mitigation profile off, in Firecracker and in its
# API process, and without it the profile is on (vmm::ext::sandbox).
# Needs no guest: an API session reaches the sandbox's setup phase (the
# run phase begins at InstanceStart).
function Stage-NoSeccomp {
    $setup = @{ ExtensionPoint = 1; Signature = 1; StrictHandle = 3; Win32k = 1; ChildProcess = 1 }
    $all = @{ ExtensionPoint = 1; ImageLoad = 7; Signature = 1; StrictHandle = 3; Win32k = 1; DynamicCode = 1; ChildProcess = 1 }
    $seen = @()
    foreach ($off in @($false, $true)) {
        $name = if ($off) { 'no-seccomp-off' } else { 'no-seccomp-on' }
        $vm = Start-Vm $name $null $(if ($off) { '--no-seccomp' } else { '' }) -Api
        # An answer from Firecracker's API thread: its sandbox is installed by then.
        Invoke-Api $vm 'PUT' '/machine-config' ([ordered]@{ vcpu_count = 1; mem_size_mib = 128 }) | Out-Null
        $fcM = [Wick.Mitigation]::Of($vm.Pid)
        $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($vm.Pid)" | Where-Object { $_.Name -eq 'firecracker.exe' })
        Check ($kids.Count -eq 1) "${name}: Firecracker's child processes from its binary: $($kids.Count)"
        $apiM = [Wick.Mitigation]::Of([int]$kids[0].ProcessId)
        if ($off) {
            $on = @($all.Keys | Where-Object { ($fcM[$_] -band $all[$_]) -ne 0 })
            Check ($on.Count -eq 0) "--no-seccomp: in force in Firecracker: $($on -join ', ')"
            $on = @($all.Keys | Where-Object { ($apiM[$_] -band $all[$_]) -ne 0 })
            Check ($on.Count -eq 0) "--no-seccomp: in force in the API process: $($on -join ', ')"
        } else {
            $missing = @($setup.Keys | Where-Object { ($fcM[$_] -band $setup[$_]) -ne $setup[$_] })
            Check ($missing.Count -eq 0) "without --no-seccomp: not in force in Firecracker: $($missing -join ', ')"
            $missing = @($all.Keys | Where-Object { ($apiM[$_] -band $all[$_]) -ne $all[$_] })
            Check ($missing.Count -eq 0) "without --no-seccomp: not in force in the API process: $($missing -join ', ')"
        }
        $info = Invoke-Api $vm 'GET' '/'
        Check ($info -match '"state":"Not started"') "${name}: instance information: $info"
        $vm.Kill()
    }
    Write-Step 'before a boot: the setup-phase mitigations in Firecracker and the whole profile in its API process without --no-seccomp, none in either with it'
    # With a guest running, as the macOS stage: Firecracker under the whole
    # profile (the run phase's mitigations since the boot) and the API
    # process too, or neither; the guest runs either way.
    foreach ($off in @($false, $true)) {
        $name = if ($off) { 'no-seccomp-guest-off' } else { 'no-seccomp-guest-on' }
        $vm = Start-Vm $name (Base-Config 1) $(if ($off) { '--no-seccomp' } else { '' }) -Api
        Wait-Shell $vm
        $out = $vm.Sh('echo guest-$((6*7))')
        Check ($out -eq 'guest-42') "${name}: guest '$out'"
        $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($vm.Pid)" | Where-Object { $_.Name -eq 'firecracker.exe' })
        Check ($kids.Count -eq 1) "${name}: Firecracker's child processes from its binary: $($kids.Count)"
        foreach ($proc in @(@('Firecracker', $vm.Pid), @('the API process', [int]$kids[0].ProcessId))) {
            $m = [Wick.Mitigation]::Of($proc[1])
            if ($off) {
                $on = @($all.Keys | Where-Object { ($m[$_] -band $all[$_]) -ne 0 })
                Check ($on.Count -eq 0) "--no-seccomp, a guest running: in force in $($proc[0]): $($on -join ', ')"
            } else {
                $missing = @($all.Keys | Where-Object { ($m[$_] -band $all[$_]) -ne $all[$_] })
                Check ($missing.Count -eq 0) "a guest running: not in force in $($proc[0]): $($missing -join ', ')"
            }
        }
        $vm.Reboot()
    }
    return 'without --no-seccomp the setup-phase mitigations in Firecracker and the whole profile in its API process before a boot, the whole profile in both with a guest running; with it none in either; the guest runs in both'
}

# virtio-mem, as upstream's test_virtio_mem_hotplug_hotunplug does it: 512 MiB
# plugged into a guest of 512 MiB (a 1 GiB hotplug area, 128 MiB slots, 2 MiB
# blocks) and seen in its MemTotal, used, then unplugged again.
# The gdb client: -Gdb, else gdb-multiarch or gdb on PATH, else MSYS2's
# (pacman -S mingw-w64-ucrt-x86_64-gdb-multiarch). It must read x86-64 Linux
# ELF files: a gdb built for Windows targets only cannot.
function Find-Gdb {
    if ($Gdb) { return (Resolve-Path $Gdb).Path }
    foreach ($n in @('gdb-multiarch', 'gdb')) {
        $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    foreach ($c in @('C:\msys64\ucrt64\bin\gdb-multiarch.exe', 'C:\msys64\mingw64\bin\gdb-multiarch.exe', 'C:\msys64\ucrt64\bin\gdb.exe', 'C:\msys64\mingw64\bin\gdb.exe')) {
        if (Test-Path $c) { return $c }
    }
    Fail 'no gdb: install MSYS2 and `pacman -S mingw-w64-ucrt-x86_64-gdb-multiarch`, or pass -Gdb <gdb.exe>'
}

# Runs gdb in batch mode on `$symbols` with `$script`; returns its process,
# its output going to `$out`.
function Start-Gdb([string]$gdb, [string]$symbols, [string]$script, [string]$out) {
    $scriptPath = "$out.gdb"
    [IO.File]::WriteAllText($scriptPath, $script)
    $p = Start-Process -FilePath $gdb -ArgumentList @('-nx', '-batch', '-x', "`"$scriptPath`"", "`"$symbols`"") -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    # Windows PowerShell 5.1 keeps no exit code for a Start-Process process
    # unless its handle was taken while it ran.
    $null = $p.Handle
    return $p
}

function Get-GdbText([string]$out) {
    return ((Get-Content -Raw $out, "$out.err" -ErrorAction SilentlyContinue) -join "`n")
}

# The bytes gdb's `x/16xb` printed after the line `$marker`.
function Get-GdbBytes([string]$text, [string]$marker) {
    $i = $text.IndexOf("$marker`n")
    if ($i -lt 0) { $i = $text.IndexOf("$marker`r`n") }
    if ($i -lt 0) { return '' }
    $lines = @($text.Substring($i) -split "`r?`n" | Select-Object -Skip 1 -First 2)
    return (($lines | ForEach-Object { [regex]::Matches(($_ -split ':', 2)[-1], '0x[0-9a-f]{2}\b') | ForEach-Object { $_.Value } }) -join ' ')
}

# Firecracker's gdb stub (the gdb feature), as upstream's test_gdb_connects:
# gdb connects to the stub's socket and a hardware breakpoint at start_kernel
# is hit; then what the stub's address translation (WHvTranslateGva) reads
# must be the vmlinux's bytes: at start_kernel (a page offset kept, the
# kernel text's large page) and, at a software breakpoint at rest_init, at
# the kernel's start through the direct map (2 MiB or 1 GiB pages); the guest
# then boots on under gdb.
# Expected in Firecracker's log at a stop before the guest enables kvm-clock
# (start_kernel's is): "KVM_KVMCLOCK_CTRL call failed (os error 87)", EINVAL,
# as Linux's kvm_set_guest_paused returns while !pv_time.active (x86.c
# 5687-5690, v6.12); not a defect.
# Whether this gdb reaches the socket by its path (`target remote <path>`) is
# tried first and reported; otherwise it goes
# through a TCP relay (Wick.Relay).
function Stage-Gdb {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $fc = if ($GdbFirecracker) { (Resolve-Path $GdbFirecracker).Path } else { Join-Path $root 'lib\firecracker\build\cargo_target\debug\firecracker.exe' }
    Check (Test-Path $fc) "no Firecracker built with the gdb feature at $fc (cargo build -p firecracker --features gdb, or pass -GdbFirecracker)"
    $gdb = Find-Gdb
    Write-Step "gdb: $gdb ($((& $gdb --version 2>&1 | Select-Object -First 1)))"
    New-Item -ItemType Directory -Force -Path (Join-Path $WorkDir 'debug') | Out-Null
    $kernel = Get-Asset "debug/$KernelName"
    $symbols = Join-Path $WorkDir "debug\$KernelName.debug"
    if (-not (Test-Path $symbols)) {
        $gz = Get-Asset "debug/$KernelName.debug.gz"
        $in = [IO.File]::OpenRead($gz)
        try {
            $z = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
            $o = [IO.File]::Create("$symbols.part")
            try { $z.CopyTo($o) } finally { $o.Close(); $z.Close() }
        } finally { $in.Close() }
        Move-Item -Force "$symbols.part" $symbols
    }
    # What the kernel file holds, read by gdb without a target: from the
    # kernel itself (its code is PROGBITS), with the split debug file's
    # symbols, which the live session uses. The debug file alone has the
    # code sections as NOBITS, which gdb reads as zeros.
    $dir = Join-Path $Results 'gdb'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $offline = Join-Path $dir 'offline.txt'
    # gdb's argument parser takes backslashes as escapes: forward slashes.
    $symbolFile = $symbols -replace '\\', '/'
    $p = Start-Gdb $gdb $kernel "symbol-file `"$symbolFile`"`nprintf `"WICK-X1\n`"`nx/16xb start_kernel`nprintf `"WICK-X3\n`"`nx/16xb _text`n" $offline
    Check ($p.WaitForExit(120000) -and $p.ExitCode -eq 0) "gdb cannot read $kernel with the symbols of $symbols ($gdb must read x86-64 Linux kernels): exit $($p.ExitCode): $(Get-GdbText $offline)"
    $offlineText = Get-GdbText $offline
    $fileStart = Get-GdbBytes $offlineText 'WICK-X1'
    $fileText = Get-GdbBytes $offlineText 'WICK-X3'
    Check ($fileStart -match '^(0x[0-9a-f]{2} ){15}0x[0-9a-f]{2}$' -and $fileText -match '^(0x[0-9a-f]{2} ){15}') "gdb's reading of start_kernel and _text in $kernel`: $offlineText"
    # Code is not all zeros: zeros are what a section without its bytes reads as.
    Check ($fileStart -notmatch '^(0x00 ?)+$' -and $fileText -notmatch '^(0x00 ?)+$') "gdb read zeros for start_kernel or _text in $kernel (no code bytes in the file it read): $offlineText"

    $sock = Get-SockPath 'gdb.sock'
    if (Test-Path $sock) { [IO.File]::Delete($sock) }
    $config = Base-Config 1
    $config.'boot-source'.kernel_image_path = $kernel
    $config.'machine-config'.gdb_socket_path = $sock
    $saved = $script:Fc
    $script:Fc = $fc
    try { $vm = Start-Vm 'gdb' $config } finally { $script:Fc = $saved }
    # Firecracker waits for gdb before it runs the guest.
    $until = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path $sock)) {
        Check (-not $vm.Exited -and [DateTime]::UtcNow -lt $until) "no gdb socket at $sock ($($vm.ExitReason()))"
        Start-Sleep -Milliseconds 50
    }
    $session = @'
set pagination off
set confirm off
target remote TARGET
hbreak start_kernel
continue
printf "WICK-RIP %lx %lx\n", $rip, &start_kernel
printf "WICK-X1\n"
x/16xb start_kernel
break rest_init
continue
printf "WICK-REST %lx %lx\n", $rip, &rest_init
printf "WICK-X2\n"
x/16xb (char *)0xffff888001000000
continue
'@
    # By the socket's path first, then through the relay.
    $out = Join-Path $dir 'gdb-direct.txt'
    $g = Start-Gdb $gdb $symbols ($session.Replace('TARGET', $sock)) $out
    $direct = $false
    $t = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $t -and -not $g.HasExited) {
        if ((Get-GdbText $out) -match 'WICK-RIP|Remote debugging using') { $direct = $true; break }
        Start-Sleep -Milliseconds 200
    }
    $relay = $null
    if (-not $direct) {
        $directText = (Get-GdbText $out).Trim()
        try { $g.Kill() } catch { }
        Write-Step "gdb does not reach the Unix socket by its path ($(($directText -split "`n" | Select-Object -Last 2) -join ' | ')); through a TCP relay"
        Check (Test-Path $sock) 'the gdb socket went away after the direct attempt'
        $relay = New-Object Wick.Relay($sock)
        $out = Join-Path $dir 'gdb-relay.txt'
        $g = Start-Gdb $gdb $symbols ($session.Replace('TARGET', "127.0.0.1:$($relay.Port)")) $out
    } else {
        Write-Step 'gdb reaches the Unix socket by its path'
    }
    try {
        $text = ''
        $t = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
        while ([DateTime]::UtcNow -lt $t -and -not $g.HasExited) {
            $text = Get-GdbText $out
            if ($text -match 'WICK-REST [0-9a-f]+ [0-9a-f]+\s+WICK-X2\s+\S+:(\s+0x[0-9a-f]{2}){8}\s+\S+:(\s+0x[0-9a-f]{2}){8}') { break }
            Start-Sleep -Milliseconds 200
        }
        $text = Get-GdbText $out
        [IO.File]::WriteAllText((Join-Path $dir 'gdb-session.txt'), $text)
        if ($relay -and $relay.Error) { Fail "relay: $($relay.Error)" }
        # Firecracker's end first: what gdb did not reach after it is its
        # consequence, not the failure.
        Check (-not $vm.Exited) "Firecracker ended during the gdb session ($($vm.ExitReason())); gdb's session: $text"
        # gdb words the stop "Thread N hit Hardware assisted breakpoint 1, ..."
        # with threads and "Hardware assisted breakpoint 1, ..." without.
        Check ($text -match '(hit )?(Hardware assisted )?[Bb]reakpoint 1, (0x[0-9a-f]+ in )?start_kernel') "the hardware breakpoint at start_kernel was not hit: $text"
        Check ($text -match 'WICK-RIP ([0-9a-f]+) ([0-9a-f]+)' -and $Matches[1] -eq $Matches[2]) "RIP at the breakpoint is not start_kernel: $text"
        $seenStart = Get-GdbBytes $text 'WICK-X1'
        Check ($seenStart -eq $fileStart) "start_kernel through the stub: '$seenStart', in the kernel file: '$fileStart'"
        Check ($text -match 'Breakpoint 2, (0x[0-9a-f]+ in )?rest_init') "the software breakpoint at rest_init was not hit: $text"
        Check ($text -match 'WICK-REST ([0-9a-f]+) ([0-9a-f]+)' -and $Matches[1] -eq $Matches[2]) "RIP at the software breakpoint is not rest_init: $text"
        $seenDirect = Get-GdbBytes $text 'WICK-X2'
        Check ($seenDirect -eq $fileText) "the kernel's start through the direct map: '$seenDirect', _text in the kernel file: '$fileText'"
        # gdb's last `continue`: the guest boots on under it.
        Wait-Shell $vm
        $o = $vm.Sh('echo gdb-$((6*7))')
        Check ($o -eq 'gdb-42') "the guest under gdb: '$o'"
    } finally {
        try { $g.Kill() } catch { }
        if ($relay) { $relay.Stop() }
    }
    $vm.Kill()
    $how = if ($direct) { 'by the socket path' } else { 'through a TCP relay (this gdb does not reach a Unix socket by its path)' }
    return "gdb $how`: hardware breakpoint at start_kernel, its bytes and the kernel's start through the direct map as in the vmlinux, software breakpoint at rest_init, the guest boots on"
}

function Stage-MemoryHotplug {
    $cfg = Base-Config 2 512 ($BootArgs + ' memhp_default_state=online_movable')
    $cfg['memory-hotplug'] = [ordered]@{ total_size_mib = 1024; slot_size_mib = 128; block_size_mib = 2 }
    $vm = Start-Vm 'memory-hotplug' $cfg -Api
    Wait-Shell $vm
    # Firecracker's commit charge (private bytes: what a job's memory limit
    # counts, as a cgroup's memory.current counts a Linux VMM's touched
    # anonymous pages) and private working set (resident and not shared,
    # Linux's RSS of anonymous memory). On Linux the guest's memory is
    # MAP_NORESERVE, so never in Committed_AS (mm/mmap.c do_mmap), and an
    # mprotect brings in no pages (mm/mprotect.c change_protection): only
    # touched pages are resident or charged, and MADV_DONTNEED gives them
    # back.
    $commit = { (Get-Process -Id $vm.Pid).PrivateMemorySize64 }
    $privateWs = {
        $p = Get-CimInstance Win32_PerfRawData_PerfProc_Process -Filter "IDProcess = $($vm.Pid)"
        return [long]$p.WorkingSetPrivate
    }
    # The 1024 MiB of hotplug memory, all unplugged (PROT_NONE): not charged.
    $booted = & $commit
    $bootedWs = & $privateWs
    Check ($booted -lt 1024MB) ("commit charge {0} MiB at the boot of a 512 MiB guest with 1024 MiB of unplugged hotplug memory" -f ($booted -shr 20))
    $memTotal = { [math]::Floor([long]$vm.Sh("awk '/MemTotal/ {print `$2}' /proc/meminfo") / 1024) }
    $base = & $memTotal
    $plug = {
        param([int]$mib)
        Invoke-Api $vm 'PATCH' '/hotplug/memory' ([ordered]@{ requested_size_mib = $mib }) | Out-Null
        $until = [DateTime]::UtcNow.AddSeconds(60)
        while ($true) {
            $hp = (Invoke-Api $vm 'GET' '/hotplug/memory') | ConvertFrom-Json
            if ($hp.plugged_size_mib -eq $mib) { break }
            Check ([DateTime]::UtcNow -lt $until) "plugged_size_mib $($hp.plugged_size_mib) 60 s after asking for $mib MiB"
            Start-Sleep -Milliseconds 100
        }
        # The guest's driver received the request ...
        $req = $vm.Sh("dmesg | grep virtio_mem | grep 'requested size' | tail -1 | awk -F': ' '{print `$NF}'")
        Check ([Convert]::ToInt64($req.Trim(), 16) -eq ([long]$mib -shl 20)) "virtio_mem's requested size '$req' for $mib MiB"
        # ... and carried it out.
        $until = [DateTime]::UtcNow.AddSeconds(5)
        while ($true) {
            $now = & $memTotal
            if ($now -eq $base + $mib) { break }
            Check ([DateTime]::UtcNow -lt $until) "MemTotal $now MiB, $base + $mib expected"
            Start-Sleep -Milliseconds 500
        }
    }
    & $plug 512
    # Memory past what the guest booted with, written and read back. (The
    # root file system is read-only: the tmpfs goes on /tmp, as in the
    # macOS stage.)
    $out = $vm.Sh('mount -t tmpfs -o size=900m tmpfs /tmp && head -c 600m /dev/urandom > /tmp/f && md5sum /tmp/f > /tmp/a && md5sum /tmp/f | cmp - /tmp/a && echo same', 180000, $true)
    Check ($out -eq 'same') "600 MiB in a guest of $base + 512 MiB read back differently: '$out'"
    $vm.Sh('rm /tmp/f /tmp/a && umount /tmp') | Out-Null
    # The unplugged memory leaves Firecracker's commit charge and its
    # private working set (the counterpart of the macOS stage's resident
    # size, and of Linux's RSS).
    $plugged = & $commit
    $pluggedWs = & $privateWs
    & $plug 0
    $unplugged = & $commit
    $unpluggedWs = & $privateWs
    $numbers = "commit charge {0} MiB at the boot, {1} plugged, {2} unplugged; private working set {3}, {4}, {5} MiB" -f ($booted -shr 20), ($plugged -shr 20), ($unplugged -shr 20), ($bootedWs -shr 20), ($pluggedWs -shr 20), ($unpluggedWs -shr 20)
    Write-Host "  $numbers"
    Check ($unplugged -lt $plugged) "the commit charge did not fall at the unplug: $numbers"
    Check ($unpluggedWs -lt $pluggedWs) "the private working set did not fall at the unplug: $numbers"
    & $plug 512  # again, as upstream's test does
    Save-Dmesg $vm 'memory-hotplug'
    $vm.Reboot()
    return ("virtio-mem: MemTotal $base -> $($base + 512) MiB and back and again, 600 MiB written and read back while plugged, $numbers")
}

$Stages = [ordered]@{
    boot     = { Stage-Boot }
    smp      = { Stage-Smp }
    block    = { Stage-Block }
    vsock    = { Stage-Vsock }
    net      = { Stage-Net }
    snapshot = { Stage-Snapshot }
    diff     = { Stage-Diff }
    uffd     = { Stage-Uffd }
    pci      = { Stage-Snapshot -Pci }
    restores = { Stage-Restores }
    'vhost-user' = { Stage-VhostUser }
    hugepages = { Stage-Hugepages }
    'api-process' = { Stage-ApiProcess }
    devices  = { Stage-Devices }
    balloon  = { Stage-Balloon }
    cli      = { Stage-Cli }
    tools    = { Stage-Tools }
    'no-seccomp' = { Stage-NoSeccomp }
    'foreign-snapshot' = { Stage-ForeignSnapshot }
    'cpu-templates' = { Stage-CpuTemplates }
    'diff-nospace' = { Stage-DiffNoSpace }
    'linux-snapshot' = { Stage-LinuxSnapshot }
    'memory-hotplug' = { Stage-MemoryHotplug }
    gdb      = { Stage-Gdb }
}
# Stages `all` leaves out: they need what a plain kit does not have.
$NotInAll = @('gdb', 'diff-nospace', 'linux-snapshot', 'foreign-snapshot')

# --- run ------------------------------------------------------------------------

if ($SelfTest) {
    $dir = Join-Path ([IO.Path]::GetTempPath()) "wbt-self-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $tests = [ordered]@{
        switch = { [Wick.SelfTest]::SwitchTest($dir) }
        vsock  = { [Wick.SelfTest]::VsockTest($dir) }
        api    = { [Wick.SelfTest]::ApiTest($dir) }
        pipe   = { [Wick.PipeSelfTest]::Run() }
        relay  = {
            # The gdb stage's TCP relay, against a stand-in for the gdb stub.
            $path = Join-Path $dir 'gdb.sock'
            $stub = [Wick.USock]::Listen($path)
            $relay = New-Object Wick.Relay($path)
            $tcp = New-Object Net.Sockets.TcpClient('127.0.0.1', $relay.Port)
            try {
                $c = $stub.Accept(5000)
                $st = $tcp.GetStream()
                $ask = [Text.Encoding]::ASCII.GetBytes('$qSupported#37')
                $st.Write($ask, 0, $ask.Length)
                $got = New-Object byte[] $ask.Length
                $c.RecvExact($got, 0, $got.Length, 5000)
                Check ([Text.Encoding]::ASCII.GetString($got) -eq '$qSupported#37') 'the stub did not get the client''s bytes'
                $c.SendAll([Text.Encoding]::ASCII.GetBytes('+$OK#9a'))
                $back = New-Object byte[] 7
                $n = 0
                $st.ReadTimeout = 5000
                while ($n -lt 7) { $r = $st.Read($back, $n, 7 - $n); if ($r -le 0) { break }; $n += $r }
                Check ([Text.Encoding]::ASCII.GetString($back, 0, $n) -eq '+$OK#9a') 'the client did not get the stub''s bytes'
                Check (-not $relay.Error) "relay: $($relay.Error)"
                $c.Dispose()
            } finally { $tcp.Close(); $relay.Stop(); $stub.Dispose() }
            return 'Relay: TCP to a Unix socket and back'
        }
        stuck = {
            # Get-StuckState's reading of snapshot-editor's print, on a
            # stand-in of its Debug layout: an AP in TSC-deadline mode with
            # the local timer's vector pending and not in service.
            $dump = {
                param([UInt64]$clock, [UInt64]$tsc, [UInt64]$rip)
                $regs = New-Object int[] 1024
                $regs[0x320] = -20; $regs[0x322] = 4      # LVT timer 0x000400ec
                $regs[0x271] = 0x10                         # IRR bit 0xec
                $regs[0x390] = [int]($clock % 100)
                $t = @('MicrovmState {', '    vm_state: VmState {', '        clock: kvm_clock_data {', "            clock: $clock,", '            flags: 0,',
                    "            host_tsc: $tsc,", '        },', '    },', '    vcpu_states: [', '        VcpuState {', '            lapic: kvm_lapic_state {', '                regs: [')
                $t += @($regs | ForEach-Object { "                    $_," })
                $t += @('                ],', '            },', '            mp_state: kvm_mp_state {', '                mp_state: 1,', '            },',
                    '            regs: kvm_regs {', '                rax: 0,', "                rip: $rip,", '                rflags: 514,', '            },', '        },', '    ],', '}')
                return ($t -join "`n")
            }
            $a = Read-VmStateDump (& $dump 1000000 5000 4096)
            $b = Read-VmStateDump (& $dump 2000000 10000 4096)
            Check ($a.Clock -eq 1000000 -and $b.Tsc -eq 10000 -and $a.Vcpus.Count -eq 1 -and $a.Vcpus[0].Lapic.Length -eq 1024) "the stand-in read as clock $($a.Clock), TSC $($b.Tsc), $($a.Vcpus.Count) vCPUs"
            $text = Format-StuckState $a $b 1.0
            foreach ($want in @('rip 0x1000 (the same in both)', 'IF 1', 'mp_state 1', 'LVT timer 0x400ec (TSC-deadline, unmasked, vector 0xec)', 'IRR highest 0xec', 'ISR highest none')) {
                Check ($text.Contains($want)) "no '$want' in: $text"
            }
            $none = Format-StuckState (Read-VmStateDump 'nothing') (Read-VmStateDump 'nothing') 1.0
            Check ($none.Contains('not in the print')) "a print without the fields: $none"
            return 'Stuck guest: a vCPU''s RIP, IF, mp_state, LAPIC timer, IRR and ISR and the VM clock read from snapshot-editor''s print'
        }
        health = {
            # tools/guest-health.txt read as the Linux and macOS boot tests
            # read it, and each kind of line they refuse refused here too,
            # naming its line.
            $real = Read-GuestHealth (Join-Path (Split-Path -Parent $PSScriptRoot) 'guest-health.txt') 'x86_64'
            Check ($real -ccontains 'WARNING: CPU:' -and $real -ccontains 'Call Trace:' -and $real -cnotcontains 'Call trace:') "the x86_64 patterns of tools/guest-health.txt: $($real -join ' | ')"
            $f = Join-Path $dir 'health.txt'
            $write = { param($t) [IO.File]::WriteAllText($f, $t, (New-Object Text.UTF8Encoding($false))) }
            & $write "# a comment`n`nall one`nx86_64 two words`naarch64 three`n"
            $got = Read-GuestHealth $f 'x86_64'
            Check (($got -join '|') -ceq 'one|two words') "a good file read as: $($got -join '|')"
            foreach ($bad in @(@("all one`r`nall two`r`n", 1), @("all one`nall`ttab`n", 2), @("all one`nall it's`n", 2), @("all one`nALL two`n", 2),
                    @("all one`nall`n", 2), @("all one`nall  two`n", 2), @("all one`nall two `n", 2), @("all one`nriscv two`n", 2), @("aarch64 one`n", 0))) {
                & $write $bad[0]
                $why = 'read'
                try { Read-GuestHealth $f 'x86_64' | Out-Null } catch { $why = $_.Exception.Message }
                $want = if ($bad[1] -gt 0) { "${f}:$($bad[1]): not a comment" } else { 'has no pattern for x86_64' }
                Check ($why.Contains($want)) "$(($bad[0]) -replace "`r", '\r' -replace "`t", '\t' -replace "`n", '\n'): $why"
            }
            return "Guest health: tools/guest-health.txt read ($($real.Count) x86_64 patterns), and 9 malformed files refused, each naming its line"
        }
        counterwarp = {
            # tools/guest-counter-warp.py as Test-CounterWarp sends it: the
            # raw deflate inflates back to the file, and the pieces of W
            # are lines the guest's console takes.
            $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'guest-counter-warp.py'
            $b64 = Get-GuestTool $path
            $in = New-Object IO.Compression.DeflateStream((New-Object IO.MemoryStream(, [Convert]::FromBase64String($b64))), [IO.Compression.CompressionMode]::Decompress)
            $back = New-Object IO.MemoryStream
            $in.CopyTo($back)
            $want = [IO.File]::ReadAllBytes($path)
            Check ([Convert]::ToBase64String($back.ToArray()) -ceq [Convert]::ToBase64String($want)) "the tool does not inflate back to its $($want.Length) bytes"
            $text = [Text.Encoding]::UTF8.GetString($want)
            foreach ($need in @('counter-warp: pass: ', 'counter-warp: FAIL: ', "b64decode('`$W'),-15)")) {
                Check ($text.Contains($need)) "the tool's header does not say '$need'"
            }
            $longest = 2000 + "W=`$W''".Length + '; echo RC=$?:K999Z'.Length
            Check ($longest -lt 4095) "a piece of W is $longest bytes"
            return "Guest TSC check: tools/guest-counter-warp.py ($($want.Length) bytes) sent as $($b64.Length) base64 characters in $([Math]::Ceiling($b64.Length / 2000)) lines, which inflate back to it"
        }
        socknames = {
            # Every socket name of the stages within the bound the start
            # takes (a name over it once failed the cli stage on the PC),
            # and a name the bound cannot cover refused.
            $mine = Get-SockNames $PSCommandPath
            Check ($mine.Bad.Count -eq 0) "Get-SockPath given what is not a string constant: $($mine.Bad -join '; ')"
            Check ($mine.Names.Count -ge 10) "only $($mine.Names.Count) socket names found: $($mine.Names -join ', ')"
            $bound = Get-SockBound $mine.Names
            foreach ($n in $mine.Names) { Check ([Text.Encoding]::UTF8.GetByteCount($n) -le $bound) "$n is over the bound $bound" }
            $f = Join-Path $dir 'names.ps1'
            Set-Content -Encoding UTF8 $f @(
                "Get-SockPath 'a.v'",
                'Get-SockPath "$x.v"',
                "`$p = Get-SockPath 'longer-than-the-rest.sock'"
            )
            $theirs = Get-SockNames $f
            Check ($theirs.Bad.Count -eq 1 -and $theirs.Bad[0] -like 'line 2: *') "a name made at run time not refused: $($theirs.Bad -join '; ')"
            Check ((Get-SockBound $theirs.Names) -eq 25) "the bound of a.v, longer-than-the-rest.sock and $ApiSockMax.api is $(Get-SockBound $theirs.Names), not 25"
            $longest = $mine.Names | Sort-Object { [Text.Encoding]::UTF8.GetByteCount($_) } | Select-Object -Last 1
            return "Socket names: $($mine.Names.Count) in the script, the longest $longest ($bound bytes), the bound"
        }
        driveid = {
            # The block stage's expected serial: Of (BY_HANDLE_FILE_INFORMATION)
            # against FILE_ID_INFO and against `vol`'s serial number (its
            # text is localised; the number is not).
            $f = Join-Path $dir 'drive.img'
            [IO.File]::WriteAllBytes($f, (New-Object byte[] 4096))
            $ref = [Wick.DriveId]::Reference($f)
            Check ($ref[2] -eq 0) "a 128-bit file id ($('{0:x16}{1:x16}' -f $ref[2], $ref[1])): not NTFS"
            # The low 32 bits (0xffffffff alone is the Int32 -1 in PowerShell).
            $serialRef = $ref[0] -band [UInt64]4294967295
            $want = [Wick.DriveId]::Encode($serialRef, $ref[1])
            $got = [Wick.DriveId]::Of($f)
            Check ($got -eq $want) "DriveId.Of '$got', FILE_ID_INFO gives '$want'"
            $vol = (cmd /c "vol $($f.Substring(0, 2))" 2>&1) -join ' '
            $m = [regex]::Match($vol, '([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})')
            Check $m.Success "no serial number in 'vol': $vol"
            $serial = [Convert]::ToUInt64($m.Groups[1].Value + $m.Groups[2].Value, 16)
            Check ($serial -eq $serialRef) ("vol says {0:x8}, FILE_ID_INFO {1:x8}" -f $serial, $serialRef)
            return ("DriveId: '{0}' = volume {1:x8}, file index {2:x16} (FILE_ID_INFO, vol)" -f $got, $serial, $ref[1])
        }
        sparse = {
            # The synthetic diff files of the tools stage.
            $data = [Wick.Util]::Random(64KB)
            $s = Join-Path $dir 'sparse.bin'; $d = Join-Path $dir 'dense.bin'
            [Wick.Sparse]::Write($s, 16MB, $data, 4MB, $true)
            [Wick.Sparse]::Write($d, 16MB, $data, 4MB, $false)
            Check ([Wick.Sparse]::Is($s) -and -not [Wick.Sparse]::Is($d)) 'sparse attribute'
            Check ([Wick.Util]::Allocated($s) -lt 1MB -and [Wick.Util]::Allocated($d) -ge 16MB) "allocated: $([Wick.Util]::Allocated($s)), $([Wick.Util]::Allocated($d))"
            Check ([Wick.Sparse]::Differ($s, $d) -eq 0) 'the two read differently'
            return 'Sparse: a sparse and a dense file with the same content'
        }
        shell  = {
            # The serial-console protocol, against a POSIX shell on a pipe.
            $sh = @("$env:ProgramFiles\Git\bin\sh.exe", "$env:ProgramFiles\Git\usr\bin\sh.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
            if (-not $sh) { return 'SKIP: no Git for Windows sh.exe to stand in for the guest shell' }
            # A UTF-8 console code page makes .NET start a child's stdin with a
            # byte order mark, which Send must not pass on.
            try { [Console]::InputEncoding = New-Object Text.UTF8Encoding($true) } catch { }
            $vm = New-Object Wick.Vm($sh, '', (Join-Path $dir 'shell.txt'))
            try {
                $vm.Send('PS1=')
                $out = $vm.Sh('echo WICK-$((6*7))')
                Check ($out -eq 'WICK-42') "echo: '$out'"
                $o = ''
                $rc = $vm.Sh('echo partial; false', 10000, $false, [ref]$o)
                Check ($rc -eq 1 -and $o -eq 'partial') "status and output: $rc '$o'"
                $o = $vm.Sh('printf "a\nb\n"')
                Check ($o -eq "a`nb") "two lines: '$o'"
                return 'Sh: status, output, multi-line'
            } finally { $vm.Kill() }
        }
        summary = {
            # One string passes; a stray value before it, or none, fails.
            Check ((Get-StageSummary { 'one' }) -eq 'one') 'one summary'
            foreach ($case in @(@('a stray value', { 0; 'two' }), @('no value', { }))) {
                $f = $null
                try { Get-StageSummary $case[1] | Out-Null } catch { $f = Get-Failure $_ }
                Check ($f -and $f.Message.StartsWith('script error: the stage returned')) "a stage with $($case[0]) passed"
            }
            return 'a stage returns one summary; a stray value or none is a script error'
        }
    }
    $failed = 0
    foreach ($t in $tests.Keys) {
        try {
            $detail = Get-StageSummary $tests[$t]
            Write-Host "PASS  $t`: $detail" -ForegroundColor Green
        } catch {
            $failed++
            $f = Get-Failure $_
            $msg = if ($f) { $f.Message } else { "$($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
            Write-Host "FAIL  $t`: $msg" -ForegroundColor Red
        }
    }
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
    if ($failed -gt 0) { exit 1 }
    exit 0
}

# `-Stage boot,smp` reaches a -File script as one string.
$names = { param($list) @($list | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$selected = @(& $names $Stage | ForEach-Object {
    if ($_ -eq 'all') { $Stages.Keys | Where-Object { $NotInAll -notcontains $_ } } else { $_ }
} | Select-Object -Unique)
$left = @(& $names $Except)
foreach ($s in $selected + $left) {
    if (-not $Stages.Contains($s)) { throw "unknown stage '$s'; stages: all, $(@($Stages.Keys) -join ', ')" }
}
$selected = @($selected | Where-Object { $left -notcontains $_ })

# The guest's health, which every stage checks before a reset
# (Wick.Vm.Healthy): tools/guest-health.txt's x86_64 and `all` patterns.
$healthPatterns = Read-GuestHealth (Join-Path (Split-Path -Parent $PSScriptRoot) 'guest-health.txt') 'x86_64'
[Wick.Vm]::HealthGrep = ($healthPatterns | ForEach-Object { "-e '$_'" }) -join ' '
# The guest's TSC check (Test-CounterWarp), as it is sent.
$script:CounterWarp = Get-GuestTool (Join-Path (Split-Path -Parent $PSScriptRoot) 'guest-counter-warp.py')

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Results = Join-Path $WorkDir "results-$stamp"
New-Item -ItemType Directory -Force -Path $Results | Out-Null
# An AF_UNIX socket's path holds at most 107 bytes (sun_path[108] with its
# NUL: Linux unix(7); Winsock afunix.h, UNIX_PATH_MAX 108). Every socket of
# the stages is a name in $SockDir: a string constant passed to
# Get-SockPath, or Start-Vm's numbered API socket. $SockName is the longest
# of them, read from this script (Get-SockNames), and a directory that
# leaves no room for it is refused before any stage, naming the path and
# the limit.
$sockNames = Get-SockNames $PSCommandPath
if ($sockNames.Bad.Count) { throw "Get-SockPath is given a name that is not a string constant, so the socket directory's bound cannot be had: $($sockNames.Bad -join '; ')" }
$SockName = Get-SockBound $sockNames.Names
$SockDir = Join-Path $Results 's'
if ([Text.Encoding]::UTF8.GetByteCount($SockDir) + 1 + $SockName -gt 107) {
    $SockDir = Join-Path ([IO.Path]::GetTempPath()) "wbt-$stamp"
}
$longestSock = Join-Path $SockDir ('n' * $SockName)
if ([Text.Encoding]::UTF8.GetByteCount($longestSock) -gt 107) {
    throw "socket paths would be up to $([Text.Encoding]::UTF8.GetByteCount($longestSock)) bytes ($longestSock), and an AF_UNIX path holds 107; pass a short -WorkDir such as C:\wbt (or set TEMP shorter)"
}
New-Item -ItemType Directory -Force -Path $SockDir | Out-Null
# Snapshot memory files (256 MiB each) stay out of the results archive.
$Scratch = Join-Path $WorkDir "scratch-$stamp"
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$Summary = New-Object System.Collections.ArrayList
$Vms = @()

Write-Host 'wick boot test (Windows)'
$Fc = Find-Firecracker
Write-Step "firecracker: $Fc"
$version = (@(& $Fc --version 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() }) | Select-Object -First 1)
Write-Step "version: $version"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$ubr = try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).UBR } catch { '?' }
$feature = try {
    (Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction Stop).State
} catch { 'unknown (run as administrator to check)' }
$WhpUnavailable = [Wick.Whp]::Unavailable()
$whpState = if ($WhpUnavailable) { "NOT available: $WhpUnavailable" } else { 'available' }
# WHP's capabilities the guest's clock and timer rest on (WHV_CAPABILITY_CODE:
# ProcessorVendor 0x1000, ProcessorFeatures 0x1001, ProcessorXsaveFeatures
# 0x1003, ProcessorClockFrequency 0x1004, InterruptClockFrequency 0x1005).
$whpCaps = @()
foreach ($cap in @(@(0x1000, 'vendor (0 AMD, 1 Intel, 2 Hygon)', 'x'), @(0x1001, 'processor features', 'x'), @(0x1003, 'XSAVE features', 'x'),
        @(0x1004, 'processor clock', 'Hz'), @(0x1005, 'interrupt clock', 'Hz'))) {
    $why = $null
    $v = [Wick.Whp]::Capability($cap[0], [ref]$why)
    $whpCaps += if ($null -eq $v) { "$($cap[1]) $why" } elseif ($cap[2] -eq 'Hz') { "$($cap[1]) $v Hz" } else { "$($cap[1]) 0x{0:x}" -f $v }
}
$hostInfo = @(
    "firecracker: $Fc", "version: $version",
    "windows: $($os.Caption) $($os.Version) build $($os.BuildNumber).$ubr",
    "cpu: $($cpu.Name) ($($cpu.NumberOfCores) cores, $($cpu.NumberOfLogicalProcessors) threads)",
    "memory: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GiB",
    "HypervisorPlatform feature: $feature (not the test for WHP: see WHP below)",
    "hypervisor present: $($cs.HypervisorPresent)",
    "virtualization firmware enabled: $($cpu.VirtualizationFirmwareEnabled)",
    "WHP: $whpState",
    "WHP capabilities: $($whpCaps -join '; ')",
    "powershell: $($PSVersionTable.PSVersion)",
    "kernel: $Prefix/$KernelName", "rootfs: $Prefix/$RootfsName",
    "results: $Results", "sockets: $SockDir"
)
$hostInfo | Set-Content -Encoding UTF8 (Join-Path $Results 'host.txt')
Write-Step "Windows: $($os.Caption) build $($os.BuildNumber).$ubr"
Write-Step "Windows Hypervisor Platform: $whpState"
Write-Step "WHP capabilities: $($whpCaps -join '; ')"

$Kernel = Get-Asset $KernelName
$Rootfs = Get-Asset $RootfsName

foreach ($name in $selected) {
    Write-Host "== $name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $script:StageClock = $sw
    $result = 'PASS'
    try {
        $detail = Get-StageSummary $Stages[$name]
    } catch {
        $result = 'FAIL'
        $f = Get-Failure $_
        $detail = if ($f) { $f.Message } else {
            "script error: $($_.Exception.GetType().Name): $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)"
        }
    } finally {
        foreach ($vm in $Vms) { $vm.Kill() }
        $Vms = @()
    }
    $color = if ($result -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("   {0} ({1:N1} s): {2}" -f $result, $sw.Elapsed.TotalSeconds, $detail) -ForegroundColor $color
    [void]$Summary.Add([pscustomobject]@{ Result = $result; Stage = $name; Detail = $detail })
}

# --- report ---------------------------------------------------------------------

$lines = @()
foreach ($s in $Summary) {
    $short = (@($s.Detail -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' | ')
    if ($short.Length -gt 400) { $short = $short.Substring(0, 400) + ' ...' }
    $lines += "{0,-5} {1}: {2}" -f $s.Result, $s.Stage, $short
}
if ($NotImplemented.Count -gt 0) {
    $lines += ''
    $lines += 'Not implemented on Windows yet (docs/ROADMAP.md), not run:'
}
foreach ($n in $NotImplemented) { $lines += "N/A   {0}: {1}" -f $n[0], $n[1] }
$failed = @($Summary | Where-Object { $_.Result -eq 'FAIL' }).Count
$lines += ''
$lines += "$($Summary.Count - $failed) passed, $failed failed"
$full = $lines + @('', 'Details:')
foreach ($s in $Summary) { $full += "[$($s.Result)] $($s.Stage)"; $full += "    $($s.Detail)" }
$full | Set-Content -Encoding UTF8 (Join-Path $Results 'summary.txt')
Write-Host ''
$lines | ForEach-Object { Write-Host $_ }

# Socket files cannot be archived, and the disk images are generated.
foreach ($f in @(Get-ChildItem -Force -Path $SockDir -ErrorAction SilentlyContinue)) {
    try { [IO.File]::Delete($f.FullName) } catch { }
}
Remove-Item -Recurse -Force $SockDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $Scratch -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Path $Results -Filter '*.img' -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
$zip = "$Results.zip"
try {
    Compress-Archive -Path (Join-Path $Results '*') -DestinationPath $zip -Force
    Write-Host "logs: $Results"
    Write-Host "zip:  $zip   <- send this file back"
} catch {
    Write-Host "logs: $Results   <- zip this folder and send it back (Compress-Archive: $($_.Exception.Message))"
}
if ($failed -gt 0) { exit 1 }
exit 0
