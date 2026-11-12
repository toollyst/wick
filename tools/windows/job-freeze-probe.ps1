# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Measures whether a Job Object's processes can be frozen and thawed as a
# group, the mechanism a counterpart of cgroup.freeze would use
# (docs/COMPATIBILITY.md, "cgroup controllers"; the jailer refuses
# cgroup.freeze today). Two spinning PowerShell processes in a job: their CPU
# time per second running, frozen (NtSetInformationJobObject,
# JobObjectFreezeInformation), with a process added while frozen, thawed,
# frozen twice, and suspended one by one (NtSuspendProcess) for comparison.
# Run it elevated and unelevated:
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\job-freeze-probe.ps1
$ErrorActionPreference = 'Continue'
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
public static class Frz {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateJobObjectW(IntPtr sa, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr p, out long c, out long e, out long k, out long u);
    [DllImport("ntdll.dll")] static extern int NtSetInformationJobObject(IntPtr job, int cls, byte[] info, int len);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationJobObject(IntPtr job, int cls, byte[] info, int len, out int ret);
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr p);
    [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr p);

    static long Cpu(IntPtr p) { long c, e, k, u; GetProcessTimes(p, out c, out e, out k, out u); return k + u; }
    // CPU time (ms) each process used over `ms` of wall time.
    static string Use(IntPtr[] ps, int ms) {
        var a = new long[ps.Length];
        for (int i = 0; i < ps.Length; i++) a[i] = Cpu(ps[i]);
        Thread.Sleep(ms);
        var s = "";
        for (int i = 0; i < ps.Length; i++) s += ((Cpu(ps[i]) - a[i]) / 10000) + "ms ";
        return s.Trim();
    }
    static byte[] Freeze(bool on) {
        var b = new byte[16];
        BitConverter.GetBytes(1u).CopyTo(b, 0); // FreezeOperation
        b[4] = (byte)(on ? 1 : 0);
        return b;
    }
    public static string Run(string exe, string args, int n) {
        var log = new System.Text.StringBuilder();
        IntPtr job = CreateJobObjectW(IntPtr.Zero, "wick-freeze-probe-" + Process.GetCurrentProcess().Id);
        if (job == IntPtr.Zero) return "CreateJobObject " + Marshal.GetLastWin32Error();
        var procs = new Process[n]; var hs = new IntPtr[n];
        try {
            for (int i = 0; i < n; i++) {
                var psi = new ProcessStartInfo(exe, args); psi.UseShellExecute = false; psi.CreateNoWindow = true;
                procs[i] = Process.Start(psi);
                hs[i] = OpenProcess(0x1F0FFF, false, procs[i].Id);
                if (!AssignProcessToJobObject(job, hs[i])) log.AppendLine("assign " + i + ": " + Marshal.GetLastWin32Error());
            }
            Thread.Sleep(1500);
            log.AppendLine("running, CPU over 1 s: " + Use(hs, 1000));
            int st = NtSetInformationJobObject(job, 18, Freeze(true), 16);
            log.AppendLine("job freeze (JobObjectFreezeInformation=18, 16 bytes): NTSTATUS 0x" + st.ToString("X8"));
            if (st == 0) {
                log.AppendLine("frozen, CPU over 1 s: " + Use(hs, 1000));
                var q = new byte[16]; int r;
                int qs = NtQueryInformationJobObject(job, 18, q, 16, out r);
                log.AppendLine("query freeze: 0x" + qs.ToString("X8") + " bytes " + BitConverter.ToString(q));
                // A process put in the job while it is frozen.
                var psi = new ProcessStartInfo(exe, args); psi.UseShellExecute = false; psi.CreateNoWindow = true;
                var late = Process.Start(psi); IntPtr lh = OpenProcess(0x1F0FFF, false, late.Id);
                Thread.Sleep(300);
                bool ok = AssignProcessToJobObject(job, lh);
                log.AppendLine("late process assigned while frozen: " + ok + (ok ? "" : " err " + Marshal.GetLastWin32Error()) + "; CPU over 1 s: " + Use(new[] { lh }, 1000));
                st = NtSetInformationJobObject(job, 18, Freeze(false), 16);
                log.AppendLine("job thaw: NTSTATUS 0x" + st.ToString("X8"));
                log.AppendLine("thawed, CPU over 1 s: " + Use(hs, 1000) + "; late: " + Use(new[] { lh }, 1000));
                // Freeze twice, thaw once: nesting?
                NtSetInformationJobObject(job, 18, Freeze(true), 16);
                int st2 = NtSetInformationJobObject(job, 18, Freeze(true), 16);
                int st3 = NtSetInformationJobObject(job, 18, Freeze(false), 16);
                log.AppendLine("freeze, freeze (0x" + st2.ToString("X8") + "), thaw (0x" + st3.ToString("X8") + "): CPU over 1 s: " + Use(hs, 1000));
                NtSetInformationJobObject(job, 18, Freeze(false), 16);
                log.AppendLine("second thaw: CPU over 1 s: " + Use(hs, 1000));
                try { late.Kill(); } catch { }
            }
            // Per process suspend, for comparison.
            foreach (var h in hs) NtSuspendProcess(h);
            log.AppendLine("NtSuspendProcess each: CPU over 1 s: " + Use(hs, 1000));
            foreach (var h in hs) NtResumeProcess(h);
            log.AppendLine("NtResumeProcess each: CPU over 1 s: " + Use(hs, 1000));
        } finally {
            TerminateJobObject(job, 1);
        }
        return log.ToString();
    }
}
'@
"Windows: $([Environment]::OSVersion.Version) $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion)"
"elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
[Frz]::Run("$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", '-NoProfile -Command "while ($true) { }"', 2)
