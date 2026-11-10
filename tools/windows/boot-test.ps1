# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Boots upstream Firecracker's x86_64 CI guest with wick on Windows (Windows
# Hypervisor Platform) and checks, stage by stage, what has only been
# cross-compiled so far: boot to user space, serial output and input (stdin
# is a pipe), SMP start-up, reboot, the Async block engine and vsock.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\boot-test.ps1 `
#       [-Firecracker <firecracker.exe>] [-WorkDir <dir>] [-Stage all|boot|smp|block|vsock]
#
# Needs: Windows 10/11 x86_64 with "Windows Hypervisor Platform" turned on
# (optionalfeatures.exe, or as administrator:
#  Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform),
# and internet access for the first run (kernel and rootfs from upstream's
# public CI bucket, about 145 MB, cached in -WorkDir).
#
# Without -Firecracker it uses firecracker.exe next to this script, then
# lib\firecracker\build\cargo_target\{release,debug}\firecracker.exe.
#
# Prints PASS/FAIL per stage and writes every log (serial console,
# Firecracker log, VM config) to <WorkDir>\results-<time>, zipped as
# results-<time>.zip next to it.

[CmdletBinding()]
param(
    [string]$Firecracker,
    [string]$WorkDir = (Join-Path $env:LOCALAPPDATA 'wick-boot-test'),
    [ValidateSet('all', 'boot', 'smp', 'block', 'vsock')]
    [string]$Stage = 'all',
    [int]$TimeoutSec = 120
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

# --- helpers ---------------------------------------------------------------

Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Wick {
    // A Firecracker process: its console output collected as it comes (the
    // shell prompt has no newline, so not line by line), its stdin a pipe.
    public class Vm {
        Process p;
        StringBuilder text = new StringBuilder();
        Thread reader;

        public Vm(string exe, string args) {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            p = Process.Start(psi);
            reader = new Thread(Pump);
            reader.IsBackground = true;
            reader.Start(p.StandardOutput.BaseStream);
            var err = new Thread(Pump);
            err.IsBackground = true;
            err.Start(p.StandardError.BaseStream);
        }

        void Pump(object o) {
            var s = (Stream)o;
            var buf = new byte[4096];
            int n;
            try {
                while ((n = s.Read(buf, 0, buf.Length)) > 0) {
                    lock (text) { text.Append(Encoding.UTF8.GetString(buf, 0, n)); }
                }
            } catch (IOException) { }
        }

        public string Output { get { lock (text) { return text.ToString(); } } }
        public bool Exited { get { return p.HasExited; } }
        public int ExitCode { get { return p.ExitCode; } }

        public void Send(string line) {
            p.StandardInput.Write(line + "\n");
            p.StandardInput.Flush();
        }

        // The first match of `pattern` in the output, waiting up to `ms`.
        public string WaitFor(string pattern, int ms) {
            var re = new Regex(pattern, RegexOptions.Multiline);
            var until = DateTime.UtcNow.AddMilliseconds(ms);
            while (true) {
                var m = re.Match(Output);
                if (m.Success) return m.Value;
                if (p.HasExited || DateTime.UtcNow > until) return null;
                Thread.Sleep(50);
            }
        }

        public bool WaitExit(int ms) {
            bool done = p.WaitForExit(ms);
            if (done) { p.WaitForExit(); reader.Join(2000); }
            return done;
        }

        public void Kill() {
            try { if (!p.HasExited) p.Kill(); } catch (InvalidOperationException) { }
            p.WaitForExit(5000);
        }
    }

    // An AF_UNIX stream client (Windows 10 1803+), for the vsock socket.
    public static class Unix {
        [DllImport("ws2_32.dll")] static extern int WSAStartup(ushort v, byte[] data);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern IntPtr socket(int af, int type, int proto);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int connect(IntPtr s, byte[] addr, int len);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int send(IntPtr s, byte[] buf, int len, int flags);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int recv(IntPtr s, byte[] buf, int len, int flags);
        [DllImport("ws2_32.dll", SetLastError = true)] static extern int setsockopt(IntPtr s, int level, int name, ref int val, int len);
        [DllImport("ws2_32.dll")] static extern int closesocket(IntPtr s);
        [DllImport("ws2_32.dll")] static extern int WSAGetLastError();

        // Connects to `path`, sends `request`, and returns what came back
        // until `expect` matched, the peer closed or `ms` passed.
        public static string Exchange(string path, string request, string expect, int ms) {
            WSAStartup(0x0202, new byte[512]);
            IntPtr s = socket(1, 1, 0);
            if (s == new IntPtr(-1)) throw new Exception("socket: " + WSAGetLastError());
            try {
                var addr = new byte[110];
                addr[0] = 1;
                var p = Encoding.UTF8.GetBytes(path);
                if (p.Length >= 108) throw new Exception("socket path too long: " + path);
                Array.Copy(p, 0, addr, 2, p.Length);
                if (connect(s, addr, addr.Length) != 0) throw new Exception("connect " + path + ": " + WSAGetLastError());
                int t = 1000;
                setsockopt(s, 0xffff, 0x1006, ref t, 4); // SO_RCVTIMEO
                var req = Encoding.UTF8.GetBytes(request);
                if (send(s, req, req.Length, 0) != req.Length) throw new Exception("send: " + WSAGetLastError());
                var got = new StringBuilder();
                var buf = new byte[4096];
                var re = new Regex(expect);
                var until = DateTime.UtcNow.AddMilliseconds(ms);
                while (DateTime.UtcNow < until && !re.IsMatch(got.ToString())) {
                    int n = recv(s, buf, buf.Length, 0);
                    if (n == 0) break;
                    if (n > 0) got.Append(Encoding.UTF8.GetString(buf, 0, n));
                }
                return got.ToString();
            } finally {
                closesocket(s);
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

$BootArgs = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd ' +
    'root=/dev/vda ro rootfstype=squashfs init=/bin/sh'

# Runs one VM: writes its config, starts it, runs `$body` against it,
# collects the logs. `$body` gets the Vm and returns a list of
# @{ name; ok; detail } checks.
function Invoke-Vm([string]$name, [hashtable]$config, [scriptblock]$body) {
    $dir = Join-Path $Results $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $cfgPath = Join-Path $dir 'vm-config.json'
    $logPath = Join-Path $dir 'firecracker.log'
    $config | ConvertTo-Json -Depth 6 | Set-Content -Encoding ASCII $cfgPath
    # Firecracker opens the log file, it does not create it.
    New-Item -ItemType File -Force -Path $logPath | Out-Null
    $fcArgs = "--no-api --config-file `"$cfgPath`" --log-path `"$logPath`" --level Debug --show-level --show-log-origin"
    $vm = New-Object Wick.Vm($Fc, $fcArgs)
    $checks = @()
    try {
        $checks = @(& $body $vm)
    } catch {
        $checks += @{ name = 'script'; ok = $false; detail = "$_" }
    } finally {
        $vm.Kill()
        Set-Content -Encoding UTF8 (Join-Path $dir 'console.txt') $vm.Output
    }
    foreach ($c in $checks) {
        $mark = if ($c.ok) { 'PASS' } else { 'FAIL' }
        $script:Summary += [pscustomobject]@{ Stage = $name; Check = $c.name; Result = $mark; Detail = $c.detail }
    }
}

function Check([string]$name, $value, [scriptblock]$ok) {
    return @{ name = $name; ok = [bool](& $ok $value); detail = "$value" }
}

# Waits for the shell, mounts /proc and /sys and checks serial input.
function Start-Shell($vm) {
    $c = @()
    $up = $vm.WaitFor('Run /bin/sh as init process', $TimeoutSec * 1000)
    $c += Check 'kernel reaches init' $(if ($up) { 'yes' } else { 'no' }) { param($v) $v -eq 'yes' }
    if (-not $up) { return ,$c }
    Start-Sleep -Milliseconds 1500
    $vm.Send('mount -t proc proc /proc; mount -t sysfs sys /sys')
    # The echo of the command line holds "6*7", not "42": only the shell's
    # answer matches, which proves the input reached the guest.
    $vm.Send('echo WICK-$((6*7))')
    $answer = $vm.WaitFor('WICK-42', 15000)
    $c += Check 'serial input (stdin pipe)' $(if ($answer) { 'echoed' } else { 'no answer' }) { param($v) $v -eq 'echoed' }
    return ,$c
}

function Get-Value($vm, [string]$key, [string]$command) {
    $vm.Send("echo $key=`$($command)")
    $m = $vm.WaitFor("^$key=[^\r\n]*", 15000)
    if ($m) { return $m.Substring($key.Length + 1).Trim() }
    return $null
}

function Stop-Guest($vm) {
    # No systemd as PID 1: reboot(2) straight away, or through sysrq.
    $vm.Send('reboot -ff || echo b > /proc/sysrq-trigger')
    $exited = $vm.WaitExit(30000)
    $code = if ($exited) { $vm.ExitCode } else { 'still running' }
    return Check 'reboot exits Firecracker (code 0)' $code { param($v) "$v" -eq '0' }
}

function Base-Config([int]$vcpus) {
    return @{
        'boot-source'    = @{ kernel_image_path = $Kernel; boot_args = $BootArgs }
        'drives'         = @(@{ drive_id = 'rootfs'; path_on_host = $Rootfs; is_root_device = $true; is_read_only = $true })
        'machine-config' = @{ vcpu_count = $vcpus; mem_size_mib = 512 }
    }
}

# --- run -------------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Results = Join-Path $WorkDir "results-$stamp"
New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Summary = @()

Write-Host 'wick boot test'
$Fc = Find-Firecracker
Write-Step "firecracker: $Fc"
$version = (& $Fc --version 2>&1 | Out-String).Trim()
Write-Step "version: $version"
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$feature = try {
    (Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction Stop).State
} catch { 'unknown (run as administrator to check)' }
$hostInfo = @(
    "firecracker: $Fc", "version: $version",
    "windows: $($os.Caption) $($os.Version) build $($os.BuildNumber)",
    "cpu: $($cpu.Name) ($($cpu.NumberOfCores) cores, $($cpu.NumberOfLogicalProcessors) threads)",
    "HypervisorPlatform feature: $feature",
    "virtualization firmware enabled: $($cpu.VirtualizationFirmwareEnabled)",
    "kernel: $Prefix/$KernelName", "rootfs: $Prefix/$RootfsName"
)
$hostInfo | Set-Content -Encoding UTF8 (Join-Path $Results 'host.txt')
Write-Step "Windows Hypervisor Platform: $feature"

$Kernel = Get-Asset $KernelName
$Rootfs = Get-Asset $RootfsName

if ($Stage -in 'all', 'boot') {
    Write-Host '[boot] 1 vCPU: boot, serial out/in, clock, reboot'
    Invoke-Vm 'boot' (Base-Config 1) {
        param($vm)
        $c = Start-Shell $vm
        if (-not ($c | Where-Object { -not $_.ok })) {
            $c += Check 'guest sees 1 CPU' (Get-Value $vm 'CPUS' 'grep -c ^processor /proc/cpuinfo') { param($v) $v -eq '1' }
            $c += Check 'clocksource (informational)' (Get-Value $vm 'CLOCK' 'cat /sys/devices/system/clocksource/clocksource0/current_clocksource') { param($v) $v }
            $c += Check 'hypervisor CPUID bit' (Get-Value $vm 'HV' 'grep -c -w hypervisor /proc/cpuinfo') { param($v) $v -eq '1' }
            $vm.Send('dmesg | grep -i -E "apic|tsc|clock|hypervisor|smp" | head -40')
            Start-Sleep -Seconds 1
            $c += Stop-Guest $vm
        }
        return $c
    }
}

if ($Stage -in 'all', 'smp') {
    Write-Host '[smp] 2 vCPUs: AP start-up (INIT/SIPI), both CPUs online, reboot with 2 vCPUs'
    Invoke-Vm 'smp' (Base-Config 2) {
        param($vm)
        $c = Start-Shell $vm
        if (-not ($c | Where-Object { -not $_.ok })) {
            $c += Check 'guest sees 2 CPUs' (Get-Value $vm 'CPUS' 'grep -c ^processor /proc/cpuinfo') { param($v) $v -eq '2' }
            $c += Check 'both online' (Get-Value $vm 'ONLINE' 'cat /sys/devices/system/cpu/online') { param($v) $v -eq '0-1' }
            # Work on both CPUs (taskset is in util-linux).
            $c += Check 'runs on CPU 1' (Get-Value $vm 'ON1' 'taskset -c 1 sh -c "echo ok"') { param($v) $v -eq 'ok' }
            $c += Stop-Guest $vm
        }
        return $c
    }
}

if ($Stage -in 'all', 'block') {
    Write-Host '[block] a second drive on the Async engine: the guest reads it whole, hashes match'
    $cfg = Base-Config 1
    $cfg.drives += @{ drive_id = 'data'; path_on_host = $Rootfs; is_root_device = $false; is_read_only = $true; io_engine = 'Async' }
    $want = (Get-FileHash -Algorithm MD5 $Rootfs).Hash.ToLower()
    Invoke-Vm 'block' $cfg {
        param($vm)
        $c = Start-Shell $vm
        if (-not ($c | Where-Object { -not $_.ok })) {
            $got = Get-Value $vm 'SUM' 'md5sum /dev/vdb | cut -c1-32'
            $c += @{ name = 'Async drive md5 = host file md5'; ok = ($got -eq $want); detail = "guest $got, host $want" }
            $c += Check 'root drive (Sync) readable' (Get-Value $vm 'ROOT' 'head -c 1048576 /dev/vda | wc -c') { param($v) $v -eq '1048576' }
            $c += Stop-Guest $vm
        }
        return $c
    }
}

if ($Stage -in 'all', 'vsock') {
    Write-Host '[vsock] host -> guest CONNECT over the AF_UNIX socket, echo through socat'
    $sock = Join-Path $Results 'v.sock'
    if (Test-Path $sock) { Remove-Item $sock -Force }
    $cfg = Base-Config 1
    $cfg.vsock = @{ guest_cid = 3; uds_path = $sock }
    Invoke-Vm 'vsock' $cfg {
        param($vm)
        $c = Start-Shell $vm
        if (-not ($c | Where-Object { -not $_.ok })) {
            $vm.Send('socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/bin/cat >/dev/null 2>&1 &')
            Start-Sleep -Seconds 2
            $reply = try {
                [Wick.Unix]::Exchange($sock, "CONNECT 52`nwick-ping`n", 'wick-ping', 10000)
            } catch { "error: $_" }
            $c += Check 'CONNECT answered with OK' $reply { param($v) $v -match '^OK \d+' }
            $c += Check 'data echoed back' $reply { param($v) $v -match 'wick-ping' }
            $c += Stop-Guest $vm
        }
        return $c
    }
}

# --- report ----------------------------------------------------------------

$Summary | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Tee-Object -FilePath (Join-Path $Results 'summary.txt') | Write-Host
$zip = "$Results.zip"
Compress-Archive -Path (Join-Path $Results '*') -DestinationPath $zip -Force
$failed = @($Summary | Where-Object { $_.Result -eq 'FAIL' }).Count
Write-Host "logs: $Results"
Write-Host "zip:  $zip"
if ($failed -gt 0) {
    Write-Host "$failed check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'all checks passed' -ForegroundColor Green
