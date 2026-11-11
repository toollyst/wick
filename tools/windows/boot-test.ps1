# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Scenario tests of wick on Windows (Windows Hypervisor Platform) against
# upstream Firecracker's x86_64 CI guest; the Windows counterpart of
# tools/macos/boot-test.py. Every stage boots its own VM and checks what the
# guest and the host see:
#
#   boot   1 vCPU: init, serial out and in (stdin is a pipe), CPU, memory,
#          guest clock, CPUID hypervisor bit, reset exits Firecracker with 0
#   smp    2 vCPUs: AP start-up, work on each CPU, the clock agrees between
#          them
#   block  Async read-only drive (md5), Sync and Async writable drives (the
#          host sees the guest's writes), read-only enforced
#   vsock  host -> guest CONNECT, 4 MiB echo; guest -> host <uds>_53
#   net    virtio-net over the Windows endpoint (Unix stream, 32-bit
#          big-endian length before each frame): a switch here answers ARP,
#          ICMP echo and UDP echo and checks every checksum the guest sends
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
#
# Before each reset the guest kernel log must be free of stalls, BUGs, oopses
# and warnings.
#
#   powershell -ExecutionPolicy Bypass -File boot-test.ps1 `
#       [-Firecracker <firecracker.exe>] [-WorkDir <dir>] [-Stage boot,smp,...]
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
    # Stage names, comma-separated or as a list; `all` runs every stage.
    [string[]]$Stage = @('all'),
    [int]$TimeoutSec = 120,
    # Checks the harness itself against stand-ins for Firecracker's sockets
    # (no WHP, no downloads) and exits.
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
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

        // Fails if the guest kernel logged a stall, a BUG, an oops or a warning.
        public void Healthy() {
            string out1 = Sh("dmesg | grep -E 'rcu: INFO|self-detected stall|soft lockup|hung_task|BUG:|Oops|WARNING:|Call trace' | head -5; true");
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

    public static class Util {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetCompressedFileSizeW(string path, out uint high);

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

        public void Close() {
            stop = true;
            t.Join(2000);
            conn.Dispose();
        }
    }

    // Whether this host can run a WHP partition, asked the way wick does.
    public static class Whp {
        [DllImport("WinHvPlatform.dll")]
        static extern int WHvGetCapability(int code, out long value, int size, out int written);

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

function Write-Step([string]$msg) { Write-Host "  - $msg" }

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
function Start-Vm([string]$name, $config, [string]$extra = '', [switch]$Api) {
    $dir = Join-Path $Results $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $logPath = Join-Path $dir 'firecracker.log'
    # Firecracker opens the log file, it does not create it.
    New-Item -ItemType File -Force -Path $logPath | Out-Null
    $fcArgs = "--log-path `"$logPath`" --level Debug --show-level --show-log-origin"
    if ($config) {
        $cfgPath = Join-Path $dir 'vm-config.json'
        $config | ConvertTo-Json -Depth 8 | Set-Content -Encoding ASCII $cfgPath
        $fcArgs += " --config-file `"$cfgPath`""
    }
    $sock = $null
    if ($Api) {
        $sock = Join-Path $SockDir "$name.api"
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
    return $vm
}

# One API request; fails unless the status is 2xx. Returns the body.
function Invoke-Api($vm, [string]$method, [string]$path, $body = $null) {
    $json = if ($null -ne $body) { $body | ConvertTo-Json -Depth 8 -Compress } else { $null }
    $status = 0
    $out = [Wick.Api]::Call($vm.ApiSock, $method, $path, $json, 120000, [ref]$status)
    Check ($status -ge 200 -and $status -lt 300) "$method $path -> $status $out"
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
        Fail "kernel did not reach init: $why"
    }
    $vm.Shell(60000)
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

# --- stages ---------------------------------------------------------------------

function Stage-Boot {
    $vm = Start-Vm 'boot' (Base-Config 1)
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
    Save-Dmesg $vm 'boot'
    $vm.Reboot()
    return ("init, serial in/out, x86_64, 1 CPU, $mem kB, hypervisor bit, clock {0:N2} s in {1:N2} s ($clock), reset exits 0" -f $dt, $host_dt)
}

function Stage-Smp {
    $vm = Start-Vm 'smp' (Base-Config 2)
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
    Save-Dmesg $vm 'smp'
    $vm.Reboot()
    return '2 vCPUs online, work runs on each, clock agrees across vCPUs, reset exits 0'
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
    return "Async read md5, Sync and Async writes reach the host file, read-only enforced (root bash $($rootMd5.Substring(0, 8)))"
}

function Stage-Vsock {
    $uds = Join-Path $SockDir 'v.sock'
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
    $collector = New-Object Wick.Collector("$($uds)_53", 30000)
    $vm.Sh('echo guest-to-host-$((6*7)) | socat -t 5 - VSOCK-CONNECT:2:53') | Out-Null
    $got = $collector.Finish(30000)
    Check ($got -eq "guest-to-host-42`n") "host received '$got' on $($uds)_53"
    Save-Dmesg $vm 'vsock'
    $vm.Reboot()
    return 'host->guest CONNECT, 4 MiB echo; guest->host <uds>_53'
}

$GuestMac = '06:00:0a:00:00:02'

function Stage-Net {
    $endpoint = Join-Path $SockDir 'n.ep'
    if (Test-Path $endpoint) { Remove-Item $endpoint -Force }
    $cfg = Base-Config 2
    $cfg['network-interfaces'] = @([ordered]@{ iface_id = 'eth0'; host_dev_name = $endpoint; guest_mac = $GuestMac })
    $vm = Start-Vm 'net' $cfg
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
        Save-Dmesg $vm 'net'
        $switch.Closing = $true
        $vm.Reboot()
    } finally {
        $switch.Close()
    }
    Check ($switch.ReadError -eq $null) "switch: $($switch.ReadError) ($($switch.Counts))"
    Check ($switch.Bad.Count -eq 0) "bad frames from the guest: $(($switch.Bad | Select-Object -First 3) -join '; ')"
    Check ($switch.Arp -ge 1 -and $switch.Icmp -ge 205 -and $switch.Udp -ge 1) "switch saw $($switch.Counts)"
    return "Unix stream endpoint: ARP, ICMP (1400 B, 200 back to back), UDP echo, checksums valid ($($switch.Counts))"
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
    $uds = Join-Path $SockDir "$tag.v"
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
    $uds = Join-Path $SockDir 'rs.v'
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
    $sock = Join-Path $SockDir 'uffd'
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
    $sock = Join-Path $SockDir 'vub'
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
    Check ($vm.Output -match 'The API server process ended') "no panic message for the API process's end ($($vm.ExitReason()))"

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

function Stage-Hugepages {
    $priv = (whoami /priv | Select-String 'SeLockMemoryPrivilege') -ne $null
    Check $priv ("this account lacks 'Lock pages in memory' (SeLockMemoryPrivilege): an administrator grants it in " +
        "secpol.msc, Local Policies, User Rights Assignment, then sign out and in")
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
}

# --- run ------------------------------------------------------------------------

if ($SelfTest) {
    $dir = Join-Path ([IO.Path]::GetTempPath()) "wbt-self-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $tests = [ordered]@{
        switch = { [Wick.SelfTest]::SwitchTest($dir) }
        vsock  = { [Wick.SelfTest]::VsockTest($dir) }
        api    = { [Wick.SelfTest]::ApiTest($dir) }
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
    }
    $failed = 0
    foreach ($t in $tests.Keys) {
        try {
            $detail = (& $tests[$t]) -join ' '
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
$selected = @($Stage | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($selected -contains 'all') { $selected = @($Stages.Keys) }
foreach ($s in $selected) {
    if (-not $Stages.Contains($s)) { throw "unknown stage '$s'; stages: all, $(@($Stages.Keys) -join ', ')" }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Results = Join-Path $WorkDir "results-$stamp"
New-Item -ItemType Directory -Force -Path $Results | Out-Null
# Unix socket paths hold at most 107 bytes.
$SockDir = Join-Path $Results 's'
New-Item -ItemType Directory -Force -Path $SockDir | Out-Null
if ((Join-Path $SockDir 'v.sock_53').Length -gt 100) {
    $SockDir = Join-Path ([IO.Path]::GetTempPath()) "wbt-$stamp"
    New-Item -ItemType Directory -Force -Path $SockDir | Out-Null
    if ((Join-Path $SockDir 'v.sock_53').Length -gt 100) {
        throw "socket paths under $SockDir would be too long for AF_UNIX; pass a short -WorkDir such as C:\wbt"
    }
}
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
$hostInfo = @(
    "firecracker: $Fc", "version: $version",
    "windows: $($os.Caption) $($os.Version) build $($os.BuildNumber).$ubr",
    "cpu: $($cpu.Name) ($($cpu.NumberOfCores) cores, $($cpu.NumberOfLogicalProcessors) threads)",
    "memory: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 1)) GiB",
    "HypervisorPlatform feature: $feature",
    "hypervisor present: $($cs.HypervisorPresent)",
    "virtualization firmware enabled: $($cpu.VirtualizationFirmwareEnabled)",
    "WHP: $whpState",
    "powershell: $($PSVersionTable.PSVersion)",
    "kernel: $Prefix/$KernelName", "rootfs: $Prefix/$RootfsName",
    "results: $Results", "sockets: $SockDir"
)
$hostInfo | Set-Content -Encoding UTF8 (Join-Path $Results 'host.txt')
Write-Step "Windows: $($os.Caption) build $($os.BuildNumber).$ubr"
Write-Step "Windows Hypervisor Platform: $whpState"

$Kernel = Get-Asset $KernelName
$Rootfs = Get-Asset $RootfsName

foreach ($name in $selected) {
    Write-Host "== $name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = 'PASS'
    try {
        $detail = (& $Stages[$name]) -join ' '
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
