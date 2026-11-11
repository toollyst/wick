# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Windows jailer on WHP hardware: what it refuses, what a jailed process
# can reach (tools/windows/jail-probe.rs, run through the jailer as the
# jailed binary), a jailed microVM booting, and the Job Object limits.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 `
#       -WorkDir C:\wjt [-Stage refuse,low,daemonize,isolation,boot,limits,cpu] [-Bin <dir>]
#
# `refuse`, `low` and `daemonize` need no WHP; the other stages boot a guest.
#
# -Bin holds jailer.exe and firecracker.exe (default: the release build).
# Needs the boot test's guest files in -Assets (vmlinux-6.1.188 and
# ubuntu-24.04.squashfs; tools/windows/boot-test.ps1 downloads them) and
# rustc to build the probe (or -Probe with a built jail-probe.exe).

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string[]]$Stage = @('refuse', 'low', 'daemonize', 'isolation', 'boot', 'limits', 'cpu'),
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
        '--new-pid-ns'               = @('--new-pid-ns')
        'fsize'                      = @('--resource-limit', 'fsize=1024')
        'cpuset'                     = @('--cgroup', 'cpuset.cpus=0', '--cgroup-version', '2')
    }
    foreach ($k in $cases.Keys) {
        $r = Invoke-Jailer ($common + $cases[$k])
        Check ($r[0] -ne 0) "$k accepted (exit $($r[0])): $($r[1])"
        Check (-not (Get-Process firecracker -ErrorAction SilentlyContinue)) "$k started Firecracker"
    }
    "--netns, --new-pid-ns, fsize= and an unsupported cgroup are refused before Firecracker starts"
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

# cpu.max is the job's CPU rate hard cap, from Firecracker's third CPU-second
# on: a guest that boots under the cap calibrates its LAPIC timer while
# throttled and can stop taking interrupts for good (about 1 boot in 3 at a
# quarter of a CPU when the cap was there from the start). Each run boots a
# guest under the limit, spins past the grace, then measures a 5 s spin.
function Stage-Cpu([int]$Boots = 3) {
    $base = New-Base 'cpu'
    $used = @()
    for ($b = 1; $b -le $Boots; $b++) {
        $vm = Start-JailedVm $base "cpu$b" @('--cgroup-version', '2', '--cgroup', 'cpu.max=25000 100000')
        try {
            Wait-Shell $vm
            $vm.Send('timeout 3 sh -c "while :; do :; done"; echo WARM')
            Check ($vm.WaitFor('(?m)^WARM', 30)) "boot ${b}: the warm-up spin did not finish"
            $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$base*" } | Select-Object -First 1
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
    "cpu.max=25000 100000: $Boots boots, each held to $($used -join '%, ')% of a CPU in a spin, APIC timer kept"
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
