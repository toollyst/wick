# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Windows jailer on WHP hardware: what it refuses, what a jailed process
# can reach (tools/windows/jail-probe.rs, run through the jailer as the
# jailed binary), a jailed microVM booting, and the Job Object limits.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 `
#       -WorkDir C:\wjt [-Stage refuse,low,daemonize,handles,pidns,isolation,boot,limits,cpu] [-Bin <dir>]
#
# `refuse`, `low`, `daemonize`, `handles` and `pidns` need no WHP; the others
# boot a guest. `pidns` needs a console (it types into it and reads it).
#
# -Bin holds jailer.exe and firecracker.exe (default: the release build).
# Needs the boot test's guest files in -Assets (vmlinux-6.1.188 and
# ubuntu-24.04.squashfs; tools/windows/boot-test.ps1 downloads them) and
# rustc to build the probe (or -Probe with a built jail-probe.exe).

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string[]]$Stage = @('refuse', 'low', 'daemonize', 'handles', 'pidns', 'isolation', 'boot', 'limits', 'cpu'),
    [string]$Bin = '',
    [string]$Assets = 'C:\wbt',
    [string]$Probe = ''
)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Bin) { $Bin = Join-Path (Split-Path -Parent (Split-Path -Parent $Here)) 'lib\firecracker\build\cargo_target\release' }
$Jailer = Join-Path $Bin 'jailer.exe'
$Fc = Join-Path $Bin 'firecracker.exe'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Results = [ordered]@{}

class Failure : Exception { Failure([string]$m) : base($m) {} }
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw [Failure]::new($what) } }

# Firecracker first: its jailer then exits as after a guest shutdown and
# removes the jail's drive.
function Stop-Jailed {
    Get-Process firecracker, jail-probe -ErrorAction SilentlyContinue | Stop-Process -Force
    $t = [DateTime]::Now.AddSeconds(5)
    while ((Get-Process jailer -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
    Get-Process jailer -ErrorAction SilentlyContinue | Stop-Process -Force
}

# A fresh chroot base for a stage.
function New-Base([string]$name) {
    $b = Join-Path $WorkDir $name
    if (Test-Path $b) { Remove-Item -Recurse -Force $b }
    New-Item -ItemType Directory -Force -Path $b | Out-Null
    $b
}

# Runs the jailer to completion; returns @(exit code, output).
function Invoke-Jailer([string[]]$argv, [int]$ms = 20000) {
    $out = Join-Path $WorkDir 'jailer-out.txt'
    $line = ($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $p = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    # Holding the process handle keeps its exit code (else ExitCode is empty
    # once it has exited).
    $null = $p.Handle
    if (-not $p.WaitForExit($ms)) { $p.Kill(); throw [Failure]::new("jailer did not exit: $line") }
    @($p.ExitCode, ((Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue) -join ''))
}

# A jailed microVM with a serial console on stdin/stdout.
class JailedVm {
    [Diagnostics.Process]$P
    [string]$Out
    JailedVm([string]$jailer, [string]$cmdline, [string]$out) {
        $this.Out = $out
        $psi = New-Object Diagnostics.ProcessStartInfo('cmd.exe', "/c `"`"$jailer`" $cmdline > `"$out`" 2>&1`"")
        $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.CreateNoWindow = $true
        $this.P = [Diagnostics.Process]::Start($psi)
    }
    [string] Text() {
        try {
            $f = [IO.File]::Open($this.Out, 'Open', 'Read', 'ReadWrite')
            $r = (New-Object IO.StreamReader($f)).ReadToEnd(); $f.Close(); return $r
        } catch { return '' }
    }
    [void] Send([string]$s) {
        $b = [Text.Encoding]::ASCII.GetBytes($s + "`n")
        $this.P.StandardInput.BaseStream.Write($b, 0, $b.Length); $this.P.StandardInput.BaseStream.Flush()
    }
    [bool] WaitFor([string]$re, [int]$sec) {
        $t = [DateTime]::Now.AddSeconds($sec)
        while ([DateTime]::Now -lt $t) {
            if ($this.Text() -match $re) { return $true }
            if ($this.P.HasExited) { return ($this.Text() -match $re) }
            Start-Sleep -Milliseconds 100
        }
        return $false
    }
    # Runs a shell command; returns its output line (marked).
    [string] Sh([string]$cmd, [int]$sec) {
        $tag = 'Q' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
        $this.Send("echo $tag`$($cmd)$tag")
        if (-not $this.WaitFor("(?m)^$tag(.*)$tag", $sec)) { throw [Failure]::new("no answer to '$cmd'") }
        [void]($this.Text() -match "(?m)^$tag(.*)$tag")
        return $Matches[1]
    }
}

# A jail for `id` under `base` with the guest's files, and a VM in it.
function Start-JailedVm([string]$base, [string]$id, [string[]]$jailerArgs = @(), [int]$memMib = 256) {
    $root = Join-Path $base "firecracker.exe\$id\root"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Copy-Item (Join-Path $Assets 'vmlinux-6.1.188') (Join-Path $root 'vmlinux')
    Copy-Item (Join-Path $Assets 'ubuntu-24.04.squashfs') (Join-Path $root 'rootfs')
    $cfg = [ordered]@{
        'boot-source'    = [ordered]@{ kernel_image_path = '/vmlinux'; boot_args = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh' }
        'drives'         = @([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs'; is_root_device = $true; is_read_only = $true })
        'machine-config' = [ordered]@{ vcpu_count = 2; mem_size_mib = $memMib }
    }
    Set-Content -Encoding ASCII (Join-Path $root 'vm.json') ($cfg | ConvertTo-Json -Depth 5)
    $line = (@('--id', $id, '--exec-file', "`"$Fc`"", '--uid', '0', '--gid', '0', '--chroot-base-dir', "`"$base`"") + ($jailerArgs | ForEach-Object { if ($_ -match ' ') { "`"$_`"" } else { $_ } }) + @('--', '--no-api', '--config-file', '/vm.json')) -join ' '
    $vm = [JailedVm]::new($Jailer, $line, (Join-Path $base "$id-console.txt"))
    $vm
}

function Wait-Shell($vm) {
    Check ($vm.WaitFor('Run /bin/sh', 60)) "the jailed guest did not reach init: $(($vm.Text() -split "`n" | Select-Object -Last 5) -join ' | ')"
    Start-Sleep -Milliseconds 500
    $vm.Send('PS1=')
    # reboot (systemd's) needs /proc.
    $vm.Send('mount -t proc proc /proc')
}

# --- stages -------------------------------------------------------------------

function Stage-Refuse {
    $base = New-Base 'refuse'
    $common = @('--id', 'r', '--exec-file', $Fc, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base)
    $cases = [ordered]@{
        '--netns'                    = @('--netns', 'C:\x')
        'fsize'                      = @('--resource-limit', 'fsize=1024')
        'cpuset'                     = @('--cgroup', 'cpuset.cpus=0', '--cgroup-version', '2')
    }
    foreach ($k in $cases.Keys) {
        $r = Invoke-Jailer ($common + $cases[$k])
        Check ($r[0] -ne 0) "$k accepted (exit $($r[0])): $($r[1])"
        Check (-not (Get-Process firecracker -ErrorAction SilentlyContinue)) "$k started Firecracker"
    }
    "--netns, fsize= and an unsupported cgroup are refused before Firecracker starts"
}

# Row 15 of docs/PORTING.md: --daemonize, upstream's observable behaviour.
# The jailer returns 0 at once; Firecracker runs on, detached (no console),
# and the pid file holds its pid. Needs no guest.
function Stage-Daemonize {
    $base = New-Base 'daemonize'
    $root = Join-Path $base 'firecracker.exe\d\root'
    try {
        # The call operator blocks until the launcher returns; with --daemonize
        # it returns at once, leaving a detached jailer and Firecracker behind.
        $sw = [Diagnostics.Stopwatch]::StartNew()
        & $Jailer --id d --exec-file $Fc --uid 0 --gid 0 --chroot-base-dir $base --daemonize 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $sw.Stop()
        Check ($code -eq 0) "the jailer did not return 0 with --daemonize (exit $code)"
        Check ($sw.Elapsed.TotalSeconds -lt 10) "the jailer did not return promptly: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s"
        # The detached Firecracker keeps running after the launcher returned.
        $sock = Join-Path $root 'run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) 'the detached Firecracker did not open its API socket'
        $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$root*" } | Select-Object -First 1
        Check ($null -ne $fcp) 'no detached Firecracker'
        $pidFile = Join-Path $root 'firecracker.exe.pid'
        Check (Test-Path $pidFile) 'no pid file'
        $written = [int](Get-Content $pidFile)
        Check ($written -eq $fcp.Id) "the pid file holds $written, Firecracker is $($fcp.Id)"
        # It has no console window of its own.
        Check ($fcp.MainWindowHandle -eq 0) 'the detached Firecracker has a window'
        $answer = Invoke-Api $sock 'GET' '/'
        Check ($answer -match ' 200$') "the detached Firecracker's API: $answer"
        # Ending Firecracker lets its detached jailer exit cleanly and remove
        # the jail's drive, as a guest shutdown does.
        $fcp | Stop-Process -Force
        $t = [DateTime]::Now.AddSeconds(5)
        while ((Get-Process jailer -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        "the launcher returned 0 in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s; a detached Firecracker (pid $written, in the pid file) ran with no console and answered its API"
    } finally { Stop-Jailed }
}

# tools\windows\jail-probe.rs, built once (or -Probe).
function Get-Probe {
    if ($script:Probe) { return $script:Probe }
    $p = Join-Path $WorkDir 'jail-probe.exe'
    $rustc = Get-Command rustc -ErrorAction SilentlyContinue
    Check ($null -ne $rustc) 'needs rustc (or -Probe) to build tools\windows\jail-probe.rs'
    & $rustc.Source --edition 2021 -O -o $p (Join-Path $Here 'jail-probe.rs') 2>&1 | Out-Host
    Check (Test-Path $p) 'jail-probe.rs did not build'
    $script:Probe = $p
    $p
}

Add-Type -Namespace WickJailerTest -Name Handle -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetHandleInformation(System.IntPtr h, uint mask, uint flags);'

# Runs a program that inherits the test's inheritable handles (ProcessStartInfo
# with redirected output sets bInheritHandles = TRUE) and returns its stdout.
function Invoke-Inheriting([string]$exe, [string]$argline) {
    $psi = New-Object Diagnostics.ProcessStartInfo($exe, $argline)
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
    [void]$p.WaitForExit(20000)
    $out
}

# Row 15 of docs/PORTING.md: a handle the jailer inherited is not open in the
# jailed Firecracker (the counterpart of the macOS inherited-descriptor
# check). The jailer passes only the standard handles
# (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), so an inheritable handle it holds does
# not reach the jailed binary. Needs no guest.
function Stage-Handles {
    $base = New-Base 'handles'
    $probe = Get-Probe
    $secret = "LEAK-$([Guid]::NewGuid().ToString('N'))"
    $file = Join-Path $WorkDir "handle-secret-$PID.txt"
    [IO.File]::WriteAllText($file, $secret)
    $fs = [IO.File]::Open($file, 'Open', 'Read', 'ReadWrite')
    try {
        $h = $fs.SafeFileHandle.DangerousGetHandle()
        # HANDLE_FLAG_INHERIT: the handle inherits into a child when the launch
        # inherits handles.
        Check ([WickJailerTest.Handle]::SetHandleInformation($h, 1, 1)) 'could not make the handle inheritable'
        $value = $h.ToInt64()
        # The control: a child that inherits the handle reads the secret back
        # through its value, so the value is live and inheritable.
        $ctl = Invoke-Inheriting $probe "handle:$value"
        Check ($ctl -match "handle:$value allowed $secret") "the inheritable handle did not reach a plain child (so the test proves nothing): $ctl"
        # Through the jailer: the jailer inherits the handle (Invoke-Jailer's
        # launch inherits handles) but passes only the standard handles on, so
        # the jailed probe does not have it.
        $r = Invoke-Jailer @('--id', 'h', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', "handle:$value") 20000
        $line = ($r[1] -split "`r?`n" | Where-Object { $_.StartsWith("handle:$value ") } | Select-Object -First 1)
        Check ($null -ne $line) "the jailed probe did not answer: $($r[1])"
        Check (-not ($line -match "allowed $secret")) "a handle the jailer inherited reached the jailed Firecracker: $line"
        Check ($line -match 'denied') "unexpected answer: $line"
        "a handle the jailer inherited (which a plain child does read) is not open in the jailed binary: $line"
    } finally {
        $fs.Close()
        Remove-Item $file -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# A jailed Firecracker with an API socket and no guest (no WHP needed).
# Returns @{ Jailer; Fc (process); Root; Sock }.
function Start-ApiJail([string]$base, [string]$id, [string[]]$jailerArgs = @()) {
    $extra = ($jailerArgs | ForEach-Object { if ($_ -match ' ') { "`"$_`"" } else { $_ } }) -join ' '
    $j = Start-Process $Jailer -ArgumentList "--id $id --exec-file `"$Fc`" --uid 0 --gid 0 --chroot-base-dir `"$base`" $extra" -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $base "$id-out.txt") -RedirectStandardError (Join-Path $base "$id-err.txt")
    $root = Join-Path $base "firecracker.exe\$id\root"
    $sock = Join-Path $root 'run\firecracker.socket'
    $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $j.HasExited) { Start-Sleep -Milliseconds 100 }
    Check (Test-Path $sock) "the jailed API socket did not appear: $(Get-Content -Raw (Join-Path $base "$id-err.txt") -ErrorAction SilentlyContinue)"
    $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$root*" } | Select-Object -First 1
    Check ($null -ne $fcp) "the jailed Firecracker $id is not running"
    @{ Jailer = $j; Fc = $fcp; Root = $root; Sock = $sock }
}

# One API call to a socket; returns "<body> <status>".
function Invoke-Api([string]$sock, [string]$method, [string]$path) {
    & curl.exe -s -o - -w ' %{http_code}' --unix-socket $sock -X $method "http://localhost$path"
}

# Runs jail-probe with `checks` (check -> whether it must be allowed); returns
# the lines that did not answer as expected.
function Test-Probe([string[]]$prefix, $expect) {
    $lines = @(& (Get-Probe) @($prefix + @($expect.Keys)) 2>&1 | ForEach-Object { "$_" })
    $bad = @()
    foreach ($k in $expect.Keys) {
        $l = $lines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
        if (-not $l) { $bad += "${k}: no answer ($($lines -join ' | '))"; continue }
        $allowed = $l.Substring($k.Length + 1).StartsWith('allowed')
        if ($allowed -ne $expect[$k]) { $bad += $l }
    }
    $bad
}

function Stage-Isolation {
    $probe = Get-Probe
    $base = New-Base 'isolation'
    $secret = Join-Path $env:USERPROFILE "wick-jailer-test-$PID.txt"
    Set-Content $secret 'secret'
    $outside = Join-Path $WorkDir "outside-$PID.txt"
    try {
        $other = Start-JailedVm $base 'other'
        Wait-Shell $other
        $otherRoot = Join-Path $base 'firecracker.exe\other\root'
        $otherFc = (Get-Process firecracker | Where-Object { $_.Path -like "$otherRoot*" } | Select-Object -First 1).Id
        Check ($null -ne $otherFc) 'the other jailed Firecracker is not running'
        # A jailed Firecracker with an API socket, for the operator.
        $api = Start-Process $Jailer -ArgumentList "--id api --exec-file `"$Fc`" --uid 0 --gid 0 --chroot-base-dir `"$base`"" -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $base 'api-out.txt') -RedirectStandardError (Join-Path $base 'api-err.txt')
        $sock = Join-Path $base 'firecracker.exe\api\root\run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) 'the jailed API socket did not appear'
        $explorer = (Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).Id
        # check -> whether the jailed probe must be allowed.
        $expect = [ordered]@{
            "read:$secret"                                  = $false   # the user's files
            'read:C:\Windows\System32\config\SAM'           = $false
            'read:C:\Windows\win.ini'                       = $true    # what every process may read
            "write:$outside"                                = $false   # outside the jail
            'write:C:\Users\Public\wick-jailer-test.txt'    = $false
            'write:own.txt'                                 = $true    # its own jail
            "read:$otherRoot\vm.json"                       = $false   # another microVM's jail
            "write:$otherRoot\intruder.txt"                 = $false
            "connect:$sock"                                 = $false   # another microVM's API
            "open:$otherFc"                                 = $false   # another microVM
            "open:$PID"                                     = $false   # the operator
        }
        if ($explorer) { $expect["open:$explorer"] = $false }
        $r = Invoke-Jailer (@('--id', 'probe', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--') + @($expect.Keys)) 30000
        $lines = $r[1] -split "`r?`n"
        $bad = @()
        foreach ($k in $expect.Keys) {
            $l = $lines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            if (-not $l) { $bad += "${k}: no answer"; continue }
            $allowed = $l.Substring($k.Length + 1).StartsWith('allowed')
            if ($allowed -ne $expect[$k]) { $bad += $l }
        }
        Check ($bad.Count -eq 0) "jailed: $($bad -join '; ')"
        # The operator reaches the jailed API socket.
        $op = & $probe "connect:$sock"
        Check ($op -match ' allowed$') "operator: $op"
        $other.Send('reboot -ff')
        # Its Firecracker: the jailer then exits and removes the drive.
        Get-Process firecracker | Where-Object { $_.Path -like "$base*\api\root*" } | Stop-Process -Force
        [void]$api.WaitForExit(10000)
        "jailed: no user files, nothing outside its jail, no other jail, API socket or process (the operator's, another microVM's); the operator reaches the API socket ($($expect.Count) checks)"
    } finally {
        Remove-Item $secret, $outside, 'C:\Users\Public\wick-jailer-test.txt' -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# Row 16 of docs/PORTING.md: only the jail's identity reaches a jail. A plain
# low-integrity process of the same user (jail-probe `low`: the user's token
# at low integrity, as a browser's sandbox runs) holds the user's SID, which
# the jail directory grants; the jail's integrity label, above low, keeps it
# out of the jail's files, its API socket and the jailed process. Needs no
# guest.
function Stage-Low {
    $base = New-Base 'low'
    try {
        $jail = Start-ApiJail $base 'target'
        Set-Content (Join-Path $jail.Root 'secret.txt') 'secret'
        $localLow = Join-Path $env:USERPROFILE 'AppData\LocalLow'
        $medium = Join-Path $env:USERPROFILE "wick-jailer-test-low-$PID.txt"
        $lowFile = Join-Path $localLow "wick-jailer-test-low-$PID.txt"
        $expect = [ordered]@{
            "read:$($jail.Root)\secret.txt"     = $false  # the jail's files
            "write:$($jail.Root)\intruder.txt"  = $false
            "write:$($jail.Root)\run\x.txt"    = $false
            "connect:$($jail.Sock)"             = $false  # its API socket
            "open:$($jail.Fc.Id)"               = $false  # the jailed process
            # The controls: it is a low-integrity process of the user.
            'read:C:\Windows\win.ini'          = $true
            "write:$lowFile"                    = $true
            "write:$medium"                     = $false
        }
        $bad = Test-Probe @('low') $expect
        Check ($bad.Count -eq 0) "low integrity: $($bad -join '; ')"
        Check (-not (Test-Path (Join-Path $jail.Root 'intruder.txt'))) 'a file appeared in the jail'
        # The operator still reaches the jailed Firecracker, which answers.
        $op = Test-Probe @() ([ordered]@{ "connect:$($jail.Sock)" = $true; "read:$($jail.Root)\secret.txt" = $true })
        Check ($op.Count -eq 0) "operator: $($op -join '; ')"
        $answer = Invoke-Api $jail.Sock 'GET' '/'
        Check ($answer -match '"state":"Not started".* 200$') "the jailed Firecracker's API: $answer"
        Check (-not $jail.Fc.HasExited) 'the jailed Firecracker exited'
        "a low-integrity process of the user reaches neither the jail's files, its API socket nor the jailed process ($($expect.Count - 3) checks, 3 controls); the operator does, and the jailed Firecracker answers"
    } finally {
        Remove-Item (Join-Path $env:USERPROFILE "wick-jailer-test-low-$PID.txt"), (Join-Path $env:USERPROFILE "AppData\LocalLow\wick-jailer-test-low-$PID.txt") -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# The test's console, for the stages that give the jailer a terminal: its
# input and output handles (inheritable), a process started on them, keys
# typed into it and its screen read back.
Add-Type -Namespace WickJailerTest -Name Term -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct SI { public int cb; public string r; public string d; public string t; public int x, y, w, h, cx, cy, fa, fl; public short sw, cb2; public System.IntPtr r2, i, o, e; }
[StructLayout(LayoutKind.Sequential)]
public struct PI { public System.IntPtr p, t; public int pid, tid; }
[StructLayout(LayoutKind.Sequential)]
public struct SA { public int n; public System.IntPtr sd; public bool inherit; }
[StructLayout(LayoutKind.Explicit)]
public struct KEY { [FieldOffset(0)] public ushort type; [FieldOffset(4)] public int down; [FieldOffset(8)] public ushort repeat; [FieldOffset(10)] public ushort vk; [FieldOffset(12)] public ushort scan; [FieldOffset(14)] public ushort ch; [FieldOffset(16)] public uint state; }
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool CreateProcessW(string app, System.Text.StringBuilder cmd, System.IntPtr pa, System.IntPtr ta, bool inherit, uint flags, System.IntPtr env, string cwd, ref SI si, out PI pi);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern System.IntPtr CreateFileW(string name, uint access, uint share, ref SA sa, uint disp, uint flags, System.IntPtr t);
[DllImport("kernel32.dll")] static extern uint WaitForSingleObject(System.IntPtr h, uint ms);
[DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(System.IntPtr h, out uint code);
[DllImport("kernel32.dll")] static extern bool CloseHandle(System.IntPtr h);
[DllImport("kernel32.dll")] static extern bool GetConsoleMode(System.IntPtr h, out uint m);
[DllImport("kernel32.dll")] static extern bool WriteConsoleInputW(System.IntPtr h, KEY[] r, uint n, out uint w);
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool ReadConsoleOutputCharacterW(System.IntPtr h, System.Text.StringBuilder s, uint n, uint xy, out uint read);
[DllImport("kernel32.dll")] static extern bool FlushConsoleInputBuffer(System.IntPtr h);
static System.IntPtr In = System.IntPtr.Zero, Out = System.IntPtr.Zero;
static System.IntPtr File(string path, uint disp) {
  var sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.inherit = true;
  var h = CreateFileW(path, 0xC0000000, 3, ref sa, disp, 0, System.IntPtr.Zero);
  if (h.ToInt64() == -1) throw new System.Exception(path + ": error " + Marshal.GetLastWin32Error());
  return h;
}
public static void Open() { if (In == System.IntPtr.Zero) { In = File("CONIN$", 3); Out = File("CONOUT$", 3); } }
// Starts `cmd` with the console as its input and, unless `output` names a
// file (PowerShell passes $null as ""), as its output and error; `group`
// gives it a process group of its own.
public static PI Start(string cmd, string output, bool group) {
  Open();
  var si = new SI(); si.cb = Marshal.SizeOf(typeof(SI)); PI pi;
  bool toFile = !string.IsNullOrEmpty(output);
  var o = toFile ? File(output, 2) : Out;
  si.fl = 0x100; si.i = In; si.o = o; si.e = o;
  bool ok = CreateProcessW(null, new System.Text.StringBuilder(cmd), System.IntPtr.Zero, System.IntPtr.Zero, true, group ? 0x200u : 0u, System.IntPtr.Zero, null, ref si, out pi);
  int err = Marshal.GetLastWin32Error();
  if (toFile) CloseHandle(o);
  if (!ok) throw new System.Exception("CreateProcess: error " + err);
  CloseHandle(pi.t);
  return pi;
}
// The exit code, or -1 if it did not exit in `ms`.
public static long Wait(PI pi, uint ms) {
  if (WaitForSingleObject(pi.p, ms) != 0) return -1;
  uint c; GetExitCodeProcess(pi.p, out c); CloseHandle(pi.p); return c;
}
public static uint Mode() { Open(); uint m; GetConsoleMode(In, out m); return m; }
public static void Flush() { Open(); FlushConsoleInputBuffer(In); }
public static void Type(string s) {
  Open();
  var r = new KEY[s.Length];
  for (int i = 0; i < s.Length; i++) { r[i].type = 1; r[i].down = 1; r[i].repeat = 1; r[i].ch = s[i]; }
  uint w; WriteConsoleInputW(In, r, (uint)r.Length, out w);
}
public static string Screen() { Open(); var sb = new System.Text.StringBuilder(200 * 300); uint n; ReadConsoleOutputCharacterW(Out, sb, 200 * 300, 0, out n); return sb.ToString(); }
'@

# A process of the user on the test's console, in a process group of its own,
# for the jailed process to act on (jail-probe `wait`).
function Start-Victim { [WickJailerTest.Term]::Start("`"$(Get-Probe)`" wait:300", $null, $true).pid }
function Test-Alive([int]$p) { [bool](Get-Process -Id $p -ErrorAction SilentlyContinue) }

# Runs jail-probe `checks` on the test's console (input; output to a file),
# plain or through the jailer; returns its answer lines.
function Invoke-OnConsole([string]$cmd, [string]$out) {
    $pi = [WickJailerTest.Term]::Start($cmd, $out, $false)
    $code = [WickJailerTest.Term]::Wait($pi, 30000)
    Check ($code -ne -1) "did not exit: $cmd"
    @(Get-Content $out)
}

# Row 7 of docs/PORTING.md: --new-pid-ns. In its own PID namespace the
# jailed Firecracker sees and signals no other process; on Windows every
# jail holds that, flag or not: its token opens no other process or thread
# (the user's, another jail's, the jailer, SYSTEM's), a process snapshot
# shows it none, and it is not on the jailer's console, so console control
# events and typed input reach no other process (the jailer relays the
# console through pipes). The flag gives upstream's jailer behaviour: the
# jailer returns 0 once Firecracker runs, its pid in the pid file, and
# Firecracker runs on. Controls: the same checks from a plain process of the
# user, on the same console, are allowed. Needs no guest.
function Stage-Pidns {
    $base = New-Base 'pidns'
    $probe = Get-Probe
    $out = Join-Path $WorkDir 'pidns-out.txt'
    $victims = @()
    try {
        $other = Start-ApiJail $base 'other'
        $victims = @((Start-Victim), (Start-Victim))
        $services = (Get-Process services).Id
        # A pid no process has (the highest of the system's plus a margin, a
        # multiple of 4 as process ids are).
        $unused = ((Get-Process | Measure-Object Id -Maximum).Maximum + 4000) -band -bnot 3

        # The control: a plain process of the user on the console reaches
        # all of it.
        $ctl = Invoke-OnConsole "`"$probe`" procs:0 see:$($victims[0]) signal:$($victims[0]) thread:$($victims[0]) signal:$($other.Fc.Id) inject:0 ctrl:$($victims[0])" $out
        [WickJailerTest.Term]::Flush()
        $bad = @($ctl | Where-Object { $_ -notmatch ' allowed' })
        Check ($ctl.Count -eq 7 -and $bad.Count -eq 0) "the control was not allowed everything (so the test proves nothing): $($ctl -join ' | ')"
        Start-Sleep -Milliseconds 500
        Check (-not (Test-Alive $victims[0])) "the control's console control event did not end the victim"

        # Jailed, on the same console.
        $v = $victims[1]
        $checks = [ordered]@{
            'procs:0'            = 'a process snapshot shows another process'
            "see:$v"             = 'a process of the user is visible'
            "see:$($other.Fc.Id)" = "another jail's Firecracker is visible"
            'see:parent'         = 'the jailer is visible'
            "signal:$v"          = 'a process of the user can be opened'
            "signal:$PID"        = 'the operator can be opened'
            "signal:$($other.Fc.Id)" = "another jail's Firecracker can be opened"
            'signal:parent'      = 'the jailer can be opened'
            "signal:$services"   = 'a SYSTEM process can be opened'
            "thread:$v"          = "a thread of the user's process can be opened"
            'inject:0'           = 'input can be typed into the console'
            'attach:parent'      = "it can attach to the jailer's console"
        }
        $line = "`"$Jailer`" --id probe --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- $(@($checks.Keys) -join ' ') ctrl:$v signal:$unused"
        $got = Invoke-OnConsole $line $out
        $fails = @()
        foreach ($k in $checks.Keys) {
            $l = $got | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            if (-not $l) { $fails += "${k}: no answer"; continue }
            if ($l -match "^$([regex]::Escape($k)) allowed") { $fails += "$($checks[$k]): $l" }
        }
        Check ($fails.Count -eq 0) "jailed: $($fails -join '; ')"
        Start-Sleep -Milliseconds 500
        Check (Test-Alive $v) "the jailed process's console control event ended a process of the user"
        # What Windows still tells it: whether a pid is in use (OpenProcess
        # fails with access denied for one that is, invalid parameter for one
        # that is not), as kill(pid, 0) tells a Linux process outside a PID
        # namespace. Recorded, not hidden.
        $oracle = $got | Where-Object { $_.StartsWith("signal:$unused ") } | Select-Object -First 1
        Check ($oracle -match 'os error 87') "an unused pid: $oracle"

        # The relay: keys typed on the console reach the jailed process as
        # the bytes it would have read (Ctrl+C a byte), its output reaches the
        # console, and the console's mode is restored after.
        $mode = [WickJailerTest.Term]::Mode()
        $pi = [WickJailerTest.Term]::Start("`"$Jailer`" --id echo --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- echo:echo.txt", $null, $false)
        $t = [DateTime]::Now.AddSeconds(10)
        while ([WickJailerTest.Term]::Mode() -eq $mode -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 50 }
        $raw = [WickJailerTest.Term]::Mode()
        Check ($raw -ne $mode) 'the jailer did not set the console to raw mode'
        [WickJailerTest.Term]::Type("hi$([char]3)q")
        $code = [WickJailerTest.Term]::Wait($pi, 20000)
        Check ($code -eq 0) "the relayed jailer: exit $code"
        $bytes = Get-Content (Join-Path $base 'jail-probe.exe\echo\root\echo.txt') -ErrorAction SilentlyContinue
        Check ($bytes -eq '68 69 03 71') "typed 'hi', Ctrl+C, 'q'; the jailed process read: $bytes"
        Check ([WickJailerTest.Term]::Screen() -match '\[jail-probe echo 4\]') "the jailed process's output did not reach the console"
        Check ([WickJailerTest.Term]::Mode() -eq $mode) ("the console mode was 0x{0:x}, is 0x{1:x} after" -f $mode, [WickJailerTest.Term]::Mode())

        # --new-pid-ns: the jailer returns 0 once Firecracker runs; the pid
        # file holds Firecracker's pid; Firecracker runs on.
        # (Output to a file: the keeper and Firecracker keep the jailer's
        # standard handles, so a pipe would stay open while they run.)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $pi = [WickJailerTest.Term]::Start("`"$Jailer`" --id ns --exec-file `"$Fc`" --uid 0 --gid 0 --chroot-base-dir `"$base`" --new-pid-ns", (Join-Path $WorkDir 'pidns-ns.txt'), $false)
        $code = [WickJailerTest.Term]::Wait($pi, 20000)
        $sw.Stop()
        Check ($code -eq 0) "--new-pid-ns: the jailer exited $code (-1: did not return)"
        $root = Join-Path $base 'firecracker.exe\ns\root'
        $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$root*" } | Select-Object -First 1
        Check ($null -ne $fcp) '--new-pid-ns: Firecracker is not running after the jailer returned'
        $written = [int](Get-Content (Join-Path $root 'firecracker.exe.pid'))
        Check ($written -eq $fcp.Id) "--new-pid-ns: the pid file holds $written, Firecracker is $($fcp.Id)"
        $sock = Join-Path $root 'run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        $answer = Invoke-Api $sock 'GET' '/'
        Check ($answer -match ' 200$') "--new-pid-ns: Firecracker's API: $answer"
        # The same isolation with the flag.
        $r = Invoke-Jailer @('--id', 'nsprobe', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--new-pid-ns', '--', 'procs:0', 'signal:parent', "signal:$PID", 'wait:2') 20000
        Check ($r[0] -eq 0) "--new-pid-ns, the probe: the jailer exited $($r[0])"
        $t = [DateTime]::Now.AddSeconds(15)
        while ((Get-Process jail-probe -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$base*nsprobe*" }) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        $nsLines = @(Get-Content (Join-Path $WorkDir 'jailer-out.txt'))
        foreach ($k in 'procs:0', 'signal:parent', "signal:$PID") {
            $l = $nsLines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            Check ($l -and $l -notmatch ' allowed') "--new-pid-ns, jailed: $k -> $l"
        }
        # A jail that cannot be built: the jailer exits with the keeper's
        # status, not 0 (upstream's jailer fails before it clones). A binary
        # without the hand-over mark is refused once the jail is built.
        $plain = Join-Path $WorkDir 'unmarked.exe'
        Copy-Item (Join-Path $env:SystemRoot 'System32\whoami.exe') $plain -Force
        $r = Invoke-Jailer @('--id', 'nsbad', '--exec-file', $plain, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--new-pid-ns') 20000
        Check ($r[0] -ne 0) "--new-pid-ns with a jail that cannot be built: the jailer exited 0: $($r[1])"
        Remove-Item $plain -ErrorAction SilentlyContinue
        # Ending Firecracker ends its keeper, which removes the jail's drive.
        $fcp | Stop-Process -Force
        $t = [DateTime]::Now.AddSeconds(5)
        while ((Get-Process jailer -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $other.Jailer.Id }) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        "the control reaches every process ($($ctl.Count) checks); jailed, nothing ($($checks.Count) checks and a console control event: the user's process survives); typed keys reach it through the relay as bytes and the console mode is restored; --new-pid-ns: the jailer returned 0 in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s with Firecracker running (pid file), refused a jail it could not build; a pid's existence still shows ($oracle)"
    } finally {
        $victims | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        [WickJailerTest.Term]::Flush()
        Stop-Jailed
    }
}

function Stage-Boot {
    $base = New-Base 'boot'
    $vm = Start-JailedVm $base 'vm'
    try {
        Wait-Shell $vm
        $out = $vm.Sh('echo $((6*7)) $(nproc)', 10)
        Check ($out -eq '42 2') "guest: '$out'"
        $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$base*" } | Select-Object -First 1
        Check ($null -ne $fcp) 'no jailed Firecracker'
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        "a 2 vCPU microVM boots in the jail (WHP under the restricted token) and the jailer exits 0 with it"
    } finally { Stop-Jailed }
}

function Stage-Limits {
    # Job memory limit: below the guest's memory Firecracker cannot run it.
    $base = New-Base 'limits'
    $vm = Start-JailedVm $base 'small' @('--cgroup-version', '2', '--cgroup', 'memory.max=134217728') 256
    try {
        $booted = $vm.WaitFor('Run /bin/sh', 30)
        if ($booted) {
            Wait-Shell $vm
            # Touch all of guest memory: the job limit must stop it.
            $vm.Send('mount -t tmpfs -o size=240m none /mnt && head -c 230m /dev/zero > /mnt/z; echo FILLED')
            [void]$vm.WaitFor('FILLED', 60)
        }
        $exited = $vm.P.WaitForExit(30000)
        Check $exited "a 256 MiB guest ran under memory.max=128 MiB"
    } finally { Stop-Jailed }
    "memory.max below the guest's memory: Firecracker cannot map it and exits"
}

# cpu.max is the job's CPU rate hard cap, from Firecracker's start, with a
# 100 ms period. Each run boots a 2 vCPU guest under it: the boot itself is
# held to the limit (no grace), each vCPU's local timer is in TSC-deadline
# mode (lapic-deadline, as on KVM: the guest never calibrates its APIC timer,
# which a throttled vCPU got wrong in about 1 boot in 3 at a quarter of a CPU
# and then stopped taking interrupts), and a 5 s spin is held to the limit.
# 12 boots: a failure rate of 1 in 3 passes them all with probability 0.8%.
function Stage-Cpu([int]$Boots = 12) {
    $base = New-Base 'cpu'
    $used = @()
    $booting = @()
    for ($b = 1; $b -le $Boots; $b++) {
        $vm = Start-JailedVm $base "cpu$b" @('--cgroup-version', '2', '--cgroup', 'cpu.max=25000 100000')
        try {
            Check ($vm.WaitFor('Run /bin/sh', 120)) "boot ${b}: the guest did not reach init under cpu.max=25000 100000: $(($vm.Text() -split "`n" | Select-Object -Last 5) -join ' | ')"
            $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$base*" } | Select-Object -First 1
            Check ($null -ne $fcp) "boot ${b}: no jailed Firecracker"
            $bu = $fcp.TotalProcessorTime.TotalSeconds / ([DateTime]::Now - $fcp.StartTime).TotalSeconds
            Check ($bu -le 0.4) "boot ${b}: cpu.max of a quarter CPU: Firecracker used $([math]::Round($bu * 100))% of one CPU from its start to init"
            $booting += [math]::Round($bu * 100)
            Wait-Shell $vm
            $deadline = $vm.Sh('grep -c "Clock Event Device: lapic-deadline" /proc/timer_list', 10)
            Check ($deadline -eq '2') "boot ${b}: $deadline of 2 vCPUs have their local timer in TSC-deadline mode (/proc/timer_list)"
            $fcp.Refresh()
            $t0 = $fcp.TotalProcessorTime; $w0 = [DateTime]::Now
            $vm.Send('timeout 5 sh -c "while :; do :; done"; echo SPUN')
            if (-not $vm.WaitFor('(?m)^SPUN', 30)) {
                $vm.Send('')
                $echo = $vm.WaitFor('(?m)^SPUN', 10)
                throw [Failure]::new("boot ${b}: a guest spinning 5 s under cpu.max=25000 100000 did not finish in 30 s (a keystroke after: $(if ($echo) { 'finished' } else { 'no echo' }); $(if ($vm.Text() -match 'APIC frequency too slow') { 'the guest disabled its APIC timer' } else { 'APIC timer kept' }))")
            }
            $fcp.Refresh()
            $u = ($fcp.TotalProcessorTime - $t0).TotalSeconds / ([DateTime]::Now - $w0).TotalSeconds
            Check ($u -le 0.4) "boot ${b}: cpu.max of a quarter CPU: Firecracker used $([math]::Round($u * 100))% of one CPU"
            Check (-not ($vm.Text() -match 'APIC frequency too slow')) "boot ${b}: the guest disabled its APIC timer"
            $used += [math]::Round($u * 100)
            $vm.Send('reboot -ff')
            [void]$vm.P.WaitForExit(15000)
        } finally { Stop-Jailed }
    }
    "cpu.max=25000 100000 from the start: $Boots boots, held to $($booting -join '%, ')% of a CPU up to init and $($used -join '%, ')% in a spin, local timers in TSC-deadline mode"
}

# --- run ----------------------------------------------------------------------

Stop-Jailed
# -File passes "a,b" as one string.
$Stage = @($Stage | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($s in $Stage) {
    Write-Host "== $s"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $msg = & "Stage-$((Get-Culture).TextInfo.ToTitleCase($s))"
        $Results[$s] = "PASS  ${s}: $msg"
    } catch {
        $Results[$s] = "FAIL  ${s}: $($_.Exception.Message)"
        Stop-Jailed
    }
    Write-Host "   $($Results[$s]) ($([math]::Round($sw.Elapsed.TotalSeconds, 1)) s)"
}
# Every jailer removed its jail's drive (DefineDosDevice mappings outlive
# the process).
Add-Type -Namespace WickJailerTest -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern uint QueryDosDevice(string d, System.Text.StringBuilder t, int n);'
$left = foreach ($c in [char[]](68..90)) {
    $sb = New-Object Text.StringBuilder 1024
    if ([WickJailerTest.Dos]::QueryDosDevice("$($c):", $sb, 1024) -gt 0 -and $sb.ToString().StartsWith("\??\$WorkDir", 'OrdinalIgnoreCase')) { "$($c): -> $($sb.ToString().Substring(4))" }
}
$Results['drives'] = if ($left) { "FAIL  drives: left mapped: $($left -join ', ')" } else { 'PASS  drives: every jail drive was removed' }
$failed = @($Results.Values | Where-Object { $_.StartsWith('FAIL') }).Count
$summary = @($Results.Values) + @('', "$($Results.Count - $failed) passed, $failed failed")
$summary | Set-Content -Encoding UTF8 (Join-Path $WorkDir 'summary.txt')
''
$summary
exit [int]($failed -ne 0)
