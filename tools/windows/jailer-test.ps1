# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Windows jailer on WHP hardware: what it refuses, what a jailed process
# can reach (tools/windows/jail-probe.rs, run through the jailer as the
# jailed binary), a jailed microVM booting, and the Job Object limits.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 `
#       -WorkDir C:\wjt [-Stage refuse,freeze,cpuset,parent,weight,low,links,nofile,sections,daemonize,handles,pidns,handoff,netns,netguest,api,isolation,reach,boot,restart,shared,bindlink,limits,memory,cpu,hugepages,uffd,vhost-user|x2storm] [-Bin <dir>] [-X2ApicFirecracker <exe>] [-ReachSmbShare] [-ReachHostHardening]
#
# `refuse`, `freeze`, `cpuset`, `parent`, `weight`, `low`, `links`, `nofile`, `sections`, `daemonize`, `handles`, `pidns`, `handoff`, `netns`,
# `api` and `reach` need no WHP; the others boot a guest. `helpers` (not in
# the default list; CI's windows job runs it) needs no jailer or WHP, and
# the probe only with -ReachSmbShare: it runs the harness's own helpers
# (Stage-Helpers). `pidns` needs a console (it types into it
# and reads it): run with other stages, it is run alone in a console of
# its own, as CI's step runs it (<WorkDir>-pidns); `netns` needs an elevated PowerShell (the jailer adds Windows Filtering
# Platform filters). `hugepages` needs the account to hold "Lock pages in memory" (it
# fails, saying so, without it). `bindlink` needs an elevated PowerShell and Windows 11
# 24H2 or later (bindlink.dll; it fails, saying so, without it). `x2storm`
# (not in the default list, about 10 minutes) needs the x2APIC record build
# (-X2ApicFirecracker, default the build's x2apic\release\firecracker.exe,
# which CI's kit has) and an AMD host; on another it is not applicable, and
# the script's exit code is 3 if no stage failed. -ReachSmbShare lets
# `reach` make a share of its own for the run, read granted to Everyone,
# removed at the stage's end (elevated only; without it no share is made),
# and `helpers` run that share probe's parts that need no jailer.
# -ReachHostHardening lets `reach` stop fastfat, list the host's names again
# and start it again as it was (elevated only; without it nothing is
# stopped).
#
# -Bin holds jailer.exe and firecracker.exe (default: the release build),
# `examples\uffd_on_demand_handler.exe` for `uffd` and, for `vhost-user`,
# vhost-user-blk.exe next to them or in the build's vhost-user-blk\release.
# Needs the boot test's guest files in -Assets (vmlinux-6.1.188 and
# ubuntu-24.04.squashfs; tools/windows/boot-test.ps1 downloads them) and
# the probe: -Probe, else jail-probe.exe next to this script (CI's kit has
# it), else rustc to build it from jail-probe.rs. `parent` needs
# jail-parent.exe the same way (the kit's, else built from jail-parent.rs).

param(
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string[]]$Stage = @('refuse', 'freeze', 'cpuset', 'parent', 'weight', 'low', 'links', 'nofile', 'sections', 'daemonize', 'handles', 'pidns', 'handoff', 'netns', 'netguest', 'api', 'isolation', 'reach', 'boot', 'restart', 'shared', 'bindlink', 'limits', 'memory', 'cpu', 'hugepages', 'uffd', 'vhost-user'),
    [string]$Bin = '',
    [string]$Assets = 'C:\wbt',
    [string]$Probe = '',
    [string]$X2ApicFirecracker = '',
    [switch]$ReachSmbShare,
    [switch]$ReachHostHardening
)
$ErrorActionPreference = 'Stop'
# Firecracker, the jailer and the probes write UTF-8 (Rust's strings,
# Windows' error texts in them included, which are in the system's language);
# Windows PowerShell reads a file in the ANSI code page and a redirected
# stream in the console's unless told: on a Korean or Japanese Windows their
# text came out garbled.
$PSDefaultParameterValues['Get-Content:Encoding'] = 'UTF8'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Bin) { $Bin = Join-Path (Split-Path -Parent (Split-Path -Parent $Here)) 'lib\firecracker\build\cargo_target\release' }
$Jailer = Join-Path $Bin 'jailer.exe'
$Fc = Join-Path $Bin 'firecracker.exe'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$Results = [ordered]@{}

class Failure : Exception { Failure([string]$m) : base($m) {} }
# A stage that cannot run on this host, by design (x2storm on a host whose
# partitions are xAPICs): its line says so, and the script's exit code is 3
# when no stage failed.
class NotApplicable : Exception { NotApplicable([string]$m) : base($m) {} }
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw [Failure]::new($what) } }

# An AF_UNIX socket's path holds at most 107 bytes (sun_path[108] with its
# NUL: Linux unix(7), "path must be shorter than SUN_LEN"; Winsock afunix.h,
# UNIX_PATH_MAX 108). The longest path the stages connect to from outside a
# jail is a jail's API socket, <WorkDir>\<base>\firecracker.exe\<id>\root\
# run\firecracker.socket, with a base (New-Base) and an id of at most 12
# characters. A WorkDir that leaves no room is refused here, before any
# stage: on a PC one 163 bytes long made 8 stages fail at their connects.
$SockBound = 107
$NameBound = 12
$longestSock = Join-Path $WorkDir (('b' * $NameBound) + '\firecracker.exe\' + ('i' * $NameBound) + '\root\run\firecracker.socket')
$longestBytes = [Text.Encoding]::UTF8.GetByteCount($longestSock)
if ($longestBytes -gt $SockBound) {
    throw "-WorkDir $WorkDir is too long: a jail's API socket path would be $longestBytes bytes ($longestSock), and an AF_UNIX path holds $SockBound; pass a shorter one, such as C:\wjt"
}

# Fails unless `sock` fits an AF_UNIX path, naming it and the limit.
function Assert-SockPath([string]$sock) {
    $n = [Text.Encoding]::UTF8.GetByteCount($sock)
    Check ($n -le $SockBound) "the socket path $sock is $n bytes, and an AF_UNIX path holds $SockBound"
}

# The processes the harness's cleanup killed while they ran (Stop-Alive
# -Cleanup), in order: a failed stage's summary line names those of the stage,
# whose output ends where the kill came. A process a stage ends itself, done
# with it (a control, a Firecracker whose check is over), is not one of them
# (EndedByStage): macOS's harness named such a kill (jailer-test vmnet's
# control, CI run 44414358364), as this one did.
$KilledAlive = New-Object Collections.ArrayList
$EndedByStage = New-Object Collections.ArrayList

# Kills each of `procs` still running, and records it, with a line on the
# host's output, as boot-test.ps1 records a kill of a live VM (Wick.Vm.Kill):
# with -Cleanup (the cleanup after a stage, a stage's own cleanup in a
# `finally`, a wait that ran out) in KilledAlive, else as the stage's own end
# of it in EndedByStage.
function Stop-Alive($procs, [switch]$Cleanup) {
    foreach ($p in @($procs)) {
        if (-not $p -or $p.HasExited) { continue }
        $what = "$($p.ProcessName) pid $($p.Id)"
        try { $p | Stop-Process -Force -ErrorAction Stop } catch { if (-not $p.HasExited) { throw } }
        if ($Cleanup) {
            [void]$KilledAlive.Add($what)
            Write-Host "   jailer-test: killed by the harness while alive: $what ($($p.Path))"
        } else {
            [void]$EndedByStage.Add($what)
            Write-Host "   jailer-test: ended by its stage, done with it: $what ($($p.Path))"
        }
    }
}

# Firecracker first: its jailer then exits as after a guest shutdown and
# removes the jail's drive. A cleanup (Stop-Alive -Cleanup), unless -Done: a
# stage ending the jails it is done with.
function Stop-Jailed([switch]$Done) {
    Stop-Alive (Get-Process firecracker, jail-probe -ErrorAction SilentlyContinue) -Cleanup:(-not $Done)
    $t = [DateTime]::Now.AddSeconds(5)
    while ((Get-Process jailer -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
    Stop-Alive (Get-Process jailer -ErrorAction SilentlyContinue) -Cleanup:(-not $Done)
}

# A failed stage's result line, naming the processes the harness's cleanup
# killed while they ran (KilledAlive), as boot-test.ps1's Add-KilledAlive.
function Add-Killed([string]$result, $killed) {
    if (@($killed).Count -eq 0) { return $result }
    "$result; killed by the harness while alive: $(@($killed) -join ', ')"
}

# Ends the jailers a stage started and still runs: their jailed processes
# first, after which each jailer exits by itself and removes its jail's drive
# (`unmap_at_exit`); one still running after 10 s is killed, and the drive
# it leaves is reported by the end's `drives` check. Killing a jailer first
# left its drive mapped for the logon session (run 43428124115's parent
# stage: Y: and Z:). The jailed processes are looked for again until the
# jailers have exited: a jailer stopped before it started its jailed process
# starts it after a single look, which then keeps it past its 10 s, and the
# jailer killed then leaves its drive (isolation at de8805f4: its probe's
# jailer killed, X: left mapped, no probe found to kill). -Cleanup: as
# Stop-Alive's.
function Stop-Jailers([object[]]$jailers, [switch]$Cleanup) {
    $t = [DateTime]::Now.AddSeconds(10)
    do {
        Stop-Alive (Get-Process firecracker, jail-probe -ErrorAction SilentlyContinue) -Cleanup:$Cleanup
        $alive = @($jailers | Where-Object { $_ -and -not $_.HasExited })
        if ($alive.Count) { Start-Sleep -Milliseconds 200 }
    } while ($alive.Count -and [DateTime]::Now -lt $t)
    foreach ($j in $alive) { Stop-Alive $j -Cleanup:$Cleanup }
}

# A fresh chroot base for a stage.
function New-Base([string]$name) {
    Check ($name.Length -le $NameBound) "the base $name is longer than $NameBound characters, which the socket paths' bound assumes"
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
    if (-not $p.WaitForExit($ms)) { Stop-Jailers @($p) -Cleanup; throw [Failure]::new("jailer did not exit: $line") }
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
        # Process.Start makes the stdin writer with the console's input
        # encoding and flushes its preamble at once: with a UTF-8 code page
        # the guest's serial input would start with a byte order mark, which
        # a booting guest drops and a restored guest's shell reads as part of
        # its first command (measured: `uffd`, EF BB BF before "PS1=").
        $saved = $null
        try { $saved = [Console]::InputEncoding; if ($saved.GetPreamble().Length -gt 0) { [Console]::InputEncoding = [Text.UTF8Encoding]::new($false) } } catch { $saved = $null }
        try { $this.P = [Diagnostics.Process]::Start($psi) } finally { if ($saved -and $saved.GetPreamble().Length -gt 0) { try { [Console]::InputEncoding = $saved } catch {} } }
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
# -Api keeps the API socket (/run/firecracker.socket in the jail) and sets
# `Sock` and `Root` on the VM; -NoConfig starts Firecracker with nothing
# configured (the API configures it); `drives` are added to the root drive;
# `bootArgs` go at the end of the guest kernel's command line; `links` (a
# name in the root -> a file outside it) are hard-linked into the root
# before the jailer starts.
function Start-JailedVm([string]$base, [string]$id, [string[]]$jailerArgs = @(), [int]$memMib = 256, [switch]$Api, [switch]$NoConfig, [object[]]$drives = @(), [string]$hugePages = '', [int]$vcpus = 2, [string]$exec = '', [string]$bootArgs = '', [hashtable]$links = @{}) {
    if (-not $exec) { $exec = $Fc }
    $root = Join-Path $base "firecracker.exe\$id\root"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Copy-Item (Join-Path $Assets 'vmlinux-6.1.188') (Join-Path $root 'vmlinux')
    Copy-Item (Join-Path $Assets 'ubuntu-24.04.squashfs') (Join-Path $root 'rootfs')
    foreach ($name in $links.Keys) { New-Item -ItemType HardLink -Path (Join-Path $root $name) -Target $links[$name] | Out-Null }
    $cfg = [ordered]@{
        'boot-source'    = [ordered]@{ kernel_image_path = '/vmlinux'; boot_args = ('console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh ' + $bootArgs).Trim() }
        'drives'         = @([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs'; is_root_device = $true; is_read_only = $true }) + $drives
        'machine-config' = [ordered]@{ vcpu_count = $vcpus; mem_size_mib = $memMib }
    }
    if ($hugePages) { $cfg['machine-config']['huge_pages'] = $hugePages }
    Set-Content -Encoding ASCII (Join-Path $root 'vm.json') ($cfg | ConvertTo-Json -Depth 5)
    $fcArgs = @('--')
    if (-not $Api) { $fcArgs += '--no-api' }
    if (-not $NoConfig) { $fcArgs += @('--config-file', '/vm.json') }
    $line = (@('--id', $id, '--exec-file', "`"$exec`"", '--uid', '0', '--gid', '0', '--chroot-base-dir', "`"$base`"") + ($jailerArgs | ForEach-Object { if ($_ -match ' ') { "`"$_`"" } else { $_ } }) + $fcArgs) -join ' '
    $vm = [JailedVm]::new($Jailer, $line, (Join-Path $base "$id-console.txt"))
    $vm | Add-Member -NotePropertyName Root -NotePropertyValue $root
    $sock = Join-Path $root 'run\firecracker.socket'
    $vm | Add-Member -NotePropertyName Sock -NotePropertyValue $sock
    if ($Api) {
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $vm.P.HasExited) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) "the jailed API socket of $id did not appear: $(($vm.Text() -split "`n" | Select-Object -Last 3) -join ' | ')"
    }
    $vm
}

# Waits until the guest's shell answers, as boot-test.ps1's Shell does, then
# clears its prompt. Input typed before the shell runs is echoed by the tty
# at once and read later, so the shell's first prompt ("# ") then comes before
# the next answer on its line, where Sh looks for the answer at a line's
# start: run 43528910212's cpu stage, boot 4 under cpu.max=25000 100000,
# echoed PS1=, the mount and the command, then printed "can't access tty",
# then "# Q35a8af2Q35a8af" (its answer, 2, behind the prompt), half a second
# after "Run /bin/sh" not being enough for the shell to start.
function Wait-Shell($vm) {
    Check ($vm.WaitFor('Run /bin/sh', 60)) "the jailed guest did not reach init: $(($vm.Text() -split "`n" | Select-Object -Last 5) -join ' | ')"
    $until = [DateTime]::Now.AddSeconds(60)
    while ($true) {
        $vm.Send('echo READY-$((20+22))')
        if ($vm.WaitFor('(?m)^READY-42\r?$', 2)) { break }
        Check ((-not $vm.P.HasExited) -and [DateTime]::Now -lt $until) "the jailed guest's shell did not answer within 60 s of init: $(($vm.Text() -split "`n" | Select-Object -Last 5) -join ' | ')"
    }
    $vm.Send('PS1=')
    # reboot (systemd's) needs /proc.
    $vm.Send('mount -t proc proc /proc')
}

# --- stages -------------------------------------------------------------------

function Stage-Refuse {
    $base = New-Base 'refuse'
    $common = @('--id', 'r', '--exec-file', $Fc, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base)
    # --netns names a directory of endpoints that must exist, as the
    # namespace file must on Linux.
    $cases = [ordered]@{
        '--netns of a missing directory' = @('--netns', (Join-Path $WorkDir 'no-such-network'))
        'fsize'                          = @('--resource-limit', 'fsize=1024')
        'memory.high'                    = @('--cgroup', 'memory.high=1048576', '--cgroup-version', '2')
        # A page size an x86_64 Linux has no hugetlb files for: refused at
        # the value that sets no limit too, as the write fails there.
        'hugetlb.64KB.max=max'           = @('--cgroup', 'hugetlb.64KB.max=max', '--cgroup-version', '2')
    }
    # docs/PORTING.md row 8: each controller Windows has no counterpart for
    # is refused with the reason (the message says "refused on Windows: why").
    $v2 = [ordered]@{
        'pids'          = 'pids.max=100'
        'io'            = 'io.weight=default 200'
        'hugetlb'       = 'hugetlb.2MB.rsvd.max=2097152'
        'rdma'          = 'rdma.max=mlx4_0'  # upstream's parser takes one '=' only
        'misc'          = 'misc.max=sev 1'
        'cpuset excl'   = 'cpuset.cpus.exclusive=0'
    }
    $v1 = [ordered]@{
        'blkio'         = 'blkio.throttle.read_bps_device=8:0 1048576'
        'devices'       = 'devices.deny=a'
        'net_cls'       = 'net_cls.classid=1'
        'net_prio'      = 'net_prio.ifpriomap=eth0 1'
    }
    $reasoned = [ordered]@{}
    foreach ($k in $v2.Keys) { $reasoned["v2 $k"] = @('--cgroup', $v2[$k], '--cgroup-version', '2') }
    foreach ($k in $v1.Keys) { $reasoned["v1 $k"] = @('--cgroup', $v1[$k], '--cgroup-version', '1') }
    $reasoned['cpu.max with cpu.weight'] = @('--cgroup', 'cpu.max=50000 100000', '--cgroup', 'cpu.weight=50', '--cgroup-version', '2')
    $nodes = 0; [void][WickJailerTest.Numa]::GetNumaHighestNodeNumber([ref]$nodes)
    if ($nodes -gt 0) { $reasoned['cpuset.mems short of every node'] = @('--cgroup', 'cpuset.mems=0', '--cgroup-version', '2') }
    foreach ($k in @($cases.Keys) + @($reasoned.Keys)) {
        $argv = if ($cases.Contains($k)) { $cases[$k] } else { $reasoned[$k] }
        $r = Invoke-Jailer ($common + $argv)
        Check ($r[0] -ne 0) "$k accepted (exit $($r[0])): $($r[1])"
        Check (-not (Get-Process firecracker -ErrorAction SilentlyContinue)) "$k started Firecracker"
        if ($reasoned.Contains($k)) { Check ($r[1] -match 'is refused on Windows: \S') "${k}: refused without its reason: $($r[1])" }
        if ($k -eq 'hugetlb.64KB.max=max') { Check ($r[1].Contains('--cgroup hugetlb.64KB.max=max: an x86_64 Linux host has no hugetlb files for this page size')) "${k}: refused without its reason: $($r[1])" }
        if ($k -eq 'fsize') { Check ($r[1].Contains('--resource-limit fsize is not supported on Windows: Windows cannot limit the size of the files a process writes')) "${k}: refused without its reason: $($r[1])" }
    }
    "--netns of a missing directory, fsize=, an unsupported cgroup file, a hugetlb page size Linux does not have and $($reasoned.Count) cgroup controllers Windows cannot enforce are refused before Firecracker starts, each with its reason"
}

Add-Type -Namespace WickJailerTest -Name Numa -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool GetNumaHighestNodeNumber(ref uint n);'

# Runs jail-probe through the jailer with `cgroups` (each a --cgroup value)
# and returns its answer to `check`.
function Invoke-JailedProbe([string]$base, [string]$id, [string]$version, [string[]]$cgroups, [string]$check) {
    $argv = @('--id', $id, '--exec-file', (Get-Probe), '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--cgroup-version', $version)
    foreach ($c in $cgroups) { $argv += @('--cgroup', $c) }
    $r = Invoke-Jailer ($argv + @('--', $check)) 30000
    Check ($r[0] -eq 0) "--cgroup $($cgroups -join ' --cgroup '): the jailer exited $($r[0]): $($r[1])"
    $line = ($r[1] -split "`r?`n" | Where-Object { $_.StartsWith("$check ") } | Select-Object -First 1)
    Check ($null -ne $line) "the jailed probe did not answer ${check}: $($r[1])"
    $line.Substring($check.Length + 1)
}

# docs/PORTING.md row 8: cpuset.cpus is the job's processor affinity, which
# the jailed process sees as its own; cpuset.mems naming every memory node of
# the host binds nothing and is accepted. Needs no guest.
function Stage-Cpuset {
    $base = New-Base 'cpuset'
    $cpus = [Environment]::ProcessorCount
    Check ($cpus -ge 2) "needs 2 processors, the host has $cpus"
    $last = $cpus - 1
    $nodes = 0; [void][WickJailerTest.Numa]::GetNumaHighestNodeNumber([ref]$nodes)
    $results = @()
    foreach ($case in @(
            @('2', "cpuset.cpus=1", 0x2),
            @('1', "cpuset.cpus=0-1", 0x3),
            @('2', "cpuset.cpus=0,$last", (1 + [math]::Pow(2, $last))))) {
        $job = Invoke-JailedProbe $base "c$($results.Count)" $case[0] @($case[1], "cpuset.mems=0-$nodes") 'job:0'
        $want = '0x{0:x}' -f [long]$case[2]
        Check ($job -match "affinity=$want ") "v$($case[0]) $($case[1]): the job's affinity: $job"
        $own = Invoke-JailedProbe $base "a$($results.Count)" $case[0] @($case[1]) 'affinity:0'
        Check ($own -match "^allowed $want of ") "v$($case[0]) $($case[1]): the jailed process's affinity: $own"
        $results += "$($case[1]) -> $want"
    }
    "the job's and the jailed process's affinity: $($results -join ', '); cpuset.mems=0-$nodes accepted"
}

# tools\windows\jail-parent.rs, as Get-Probe finds the probe.
function Get-ParentTool {
    if ($script:ParentTool) { return $script:ParentTool }
    $kit = Join-Path $Here 'jail-parent.exe'
    if (Test-Path $kit) {
        $script:ParentTool = $kit
        return $kit
    }
    $p = Join-Path $WorkDir 'jail-parent.exe'
    $rustc = Get-Command rustc -ErrorAction SilentlyContinue
    Check ($null -ne $rustc) 'needs rustc to build tools\windows\jail-parent.rs (or the kit, which has jail-parent.exe)'
    & $rustc.Source --edition 2021 -O -o $p (Join-Path $Here 'jail-parent.rs') 2>&1 | Out-Host
    Check (Test-Path $p) 'jail-parent.rs did not build'
    $script:ParentTool = $p
    $p
}

# jail-parent run to its end, its standard input at its end from the start,
# so that it holds nothing after what it does: for a command line it must
# refuse, or for a write to a level another jail-parent holds. Its exit code
# (none if it had to be stopped) and what it wrote.
function Invoke-ParentTool([string]$Arguments) {
    $psi = New-Object Diagnostics.ProcessStartInfo((Get-ParentTool), $Arguments)
    $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(10000)) {
        $p.Kill()
        return @($null, "still running after 10 s: $($err.Result)")
    }
    @($p.ExitCode, "$($p.StandardOutput.ReadToEnd()) $($err.Result)")
}

# docs/PORTING.md row 8: --parent-cgroup. A parent made with jail-parent on
# processor 0, and jails under it, each allowed 1 GiB of its own. A parent's
# memory limit is refused for now (the tool refuses memory.max with a
# limit; the jailer refuses a jail under a parent that has one: its jails'
# sections are counted against their own memory.max only, docs/COMPATIBILITY.md):
# - the first commits 200 MiB and runs on processor 0 though it asked for 0
#   and 1 (cgroup v2: the processors it has in common with its parent);
# - the second commits 200 MiB too while the first holds its own;
# - cgroup v1 refuses a jail that asks for processor 1 (not in its parent's);
# - with the tool ended and the first jail still running, a jail that names
#   the parent with cgroup v2 and no --cgroup joins it, on its processor: a
#   jailer keeps the parent of its jail;
# - a level under the parent (`<parent>/inner`, made with the tool while the
#   parent's is running): a jail under it runs on the parent's processor;
#   the tool refuses, for cgroup v1, a level on a processor its parent has
#   not; a write of the processors of the parent that is there is taken, as
#   Linux takes a write to cpuset.cpus at any time: a jail that asks for
#   processors 0 and 1 then has both, and processor 0 again after the write
#   back (the jobs below a level written to: jail-parent's own test);
# - a jailed process tries to reach the parent cgroups' private namespace,
#   to make a parent's job itself for later jails to join: it can neither
#   open nor make it. What it may make in the session's own namespace is
#   printed, and is nothing to a jail given a parent of that name.
# Needs no guest.
function Stage-Parent {
    $base = New-Base 'parent'
    $cpus = [Environment]::ProcessorCount
    Check ($cpus -ge 2) "needs 2 processors, the host has $cpus"
    $name = "wjt-$PID"
    $probe = Get-Probe
    $r = Invoke-ParentTool "--name $name --cgroup memory.max=268435456 --cgroup cpuset.cpus=0"
    Check ($r[0] -eq 1 -and $r[1].Contains('memory.max=268435456: refused on Windows for now')) "the tool did not refuse a parent's memory limit: exit $($r[0]): $($r[1])"
    $psi = New-Object Diagnostics.ProcessStartInfo((Get-ParentTool), "--name $name --cgroup memory.max=max --cgroup cpuset.cpus=0")
    $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
    $holder = [Diagnostics.Process]::Start($psi)
    $first = $null
    $squat = $null
    $inner = $null
    try {
        $said = ''
        while ($null -ne ($line = $holder.StandardOutput.ReadLine())) { $said += "$line; "; if ($line -match 'held until') { break } }
        Check ($said -match "${name}: made" -and $said -match 'held until') "jail-parent did not make and hold the parent: $said"
        $jail = @('--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--parent-cgroup', $name)
        $own = @('--cgroup', 'memory.max=1073741824')

        # A level under the parent, before any jail runs under it.
        $r = Invoke-ParentTool "--name $name/bad --cgroup-version 1 --cgroup cpuset.cpus=1"
        Check ($r[0] -eq 1 -and $r[1].Contains("CPUs outside the parent cgroup's")) "cgroup v1: a level on processor 1 under a parent on processor 0 was not refused by the tool: exit $($r[0]): $($r[1])"
        $r = Invoke-ParentTool "--name $name --cgroup cpuset.cpus=0-1"
        Check ($r[0] -eq 0 -and $r[1] -match "${name}: opened" -and $r[1] -match "${name}: 0 jobs below it") "the tool did not write the processors of the parent that was there: exit $($r[0]): $($r[1])"
        $r = Invoke-Jailer (@('--id', 'wide') + $jail + @('--cgroup-version', '2', '--cgroup', 'cpuset.cpus=0-1', '--', 'affinity:0')) 60000
        Check ($r[1] -match 'affinity:0 allowed 0x3 of ') "a jail that asked for processors 0-1 under the parent written to 0-1: exit $($r[0]): $($r[1])"
        $r = Invoke-ParentTool "--name $name --cgroup cpuset.cpus=0"
        Check ($r[0] -eq 0 -and $r[1] -match "${name}: opened") "the tool did not write the parent's processors back: exit $($r[0]): $($r[1])"
        $psi2 = New-Object Diagnostics.ProcessStartInfo((Get-ParentTool), "--name $name/inner --cgroup memory.max=max")
        $psi2.UseShellExecute = $false; $psi2.RedirectStandardInput = $true; $psi2.RedirectStandardOutput = $true; $psi2.CreateNoWindow = $true
        $inner = [Diagnostics.Process]::Start($psi2)
        $said = ''
        while ($null -ne ($line = $inner.StandardOutput.ReadLine())) { $said += "$line; "; if ($line -match 'held until') { break } }
        Check ($said -match "${name}: opened" -and $said -match "${name}/inner: made" -and $said -match 'held until') "jail-parent did not open the parent and make the level under it: $said"
        $r = Invoke-Jailer (@('--id', 'level', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--parent-cgroup', "$name/inner", '--cgroup-version', '2') + $own + @('--', 'private:150', 'affinity:0')) 60000
        Check ($r[1] -match 'private:150 allowed 150') "a jail under a level under the parent, its own memory.max 1 GiB: exit $($r[0]): $($r[1])"
        Check ($r[1] -match 'affinity:0 allowed 0x1 of ') "a jail under a level without processors of its own, under a parent on processor 0: $($r[1])"
        $inner.StandardInput.Close()
        Check ($inner.WaitForExit(10000)) 'jail-parent did not end with its standard input (the level)'

        $out = Join-Path $base 'first.txt'
        $line = "--id first --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" --parent-cgroup $name --cgroup-version 2 --cgroup memory.max=1073741824 --cgroup cpuset.cpus=0-1 -- private:200 affinity:0 wait:60"
        $first = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        $null = $first.Handle
        $text = ''
        $t = [DateTime]::Now.AddSeconds(30)
        while ([DateTime]::Now -lt $t -and -not $first.HasExited -and $text -notmatch 'affinity:0 ') {
            Start-Sleep -Milliseconds 200
            $text = (Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue) -join ''
        }
        Check ($text -match 'private:200 allowed 200') "the first jail's 200 MiB under the parent: $text"
        Check ($text -match 'affinity:0 allowed 0x1 of ') "the first jail asked for processors 0-1 under a parent on processor 0 (cgroup v2: processor 0): $text"

        $r = Invoke-Jailer (@('--id', 'second') + $jail + @('--cgroup-version', '2') + $own + @('--', 'private:200')) 60000
        Check ($r[1] -match 'private:200 allowed 200') "the second jail's 200 MiB under the parent, 200 held by the first: exit $($r[0]): $($r[1])"

        $r = Invoke-Jailer (@('--id', 'v1') + $jail + @('--cgroup-version', '1', '--cgroup', 'cpuset.cpus=1', '--', 'affinity:0'))
        Check ($r[0] -ne 0 -and $r[1].Contains("CPUs outside the parent cgroup's")) "cgroup v1, processor 1 under a parent on processor 0, was not refused: exit $($r[0]): $($r[1])"
        Check ($r[1] -notmatch 'affinity:0 allowed') "cgroup v1, processor 1 under a parent on processor 0: the jail ran: $($r[1])"

        $holder.StandardInput.Close()
        Check ($holder.WaitForExit(10000)) 'jail-parent did not end with its standard input'
        Check (-not $first.HasExited) "the first jail ended before the tool: $text"
        $r = Invoke-Jailer (@('--id', 'joins') + $jail + @('--cgroup-version', '2', '--', 'affinity:0')) 60000
        Check ($r[1] -match 'affinity:0 allowed 0x1 of ') "with the tool ended and a jail left, a jail that joins the parent (v2, no --cgroup), on the parent's processor 0: exit $($r[0]): $($r[1])"

        # A jailed process and a parent's name: the parents' namespace is
        # neither opened nor made by it (asserted); what it may do in the
        # session's own namespace is printed, and a job it makes there under
        # a name like a parent's changes nothing for a jail given that parent.
        $taken = "wjt-taken-$PID"
        $sout = Join-Path $base 'squat.txt'
        $line = "--id squat --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- namespace:0 namedjob:Local\wick-cgroup-$taken wait:30"
        $squat = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $sout -RedirectStandardError "$sout.err"
        $null = $squat.Handle
        $stext = ''
        $t = [DateTime]::Now.AddSeconds(30)
        while ([DateTime]::Now -lt $t -and -not $squat.HasExited -and $stext -notmatch 'namedjob:\S+ (allowed|denied)') {
            Start-Sleep -Milliseconds 200
            $stext = (Get-Content $sout, "$sout.err" -Raw -ErrorAction SilentlyContinue) -join ''
        }
        Check ($stext -match 'namespace:0 (denied [^\r\n]*)') "a jailed process reached the parent cgroups' namespace, or did not say: $stext"
        $reach = $Matches[1]
        Check ($stext -match 'namedjob:\S+ (allowed \w+|denied [^\r\n]*)') "a jailed process making a job in the session's namespace said neither allowed nor denied: $stext"
        $made = $Matches[1]
        $r = Invoke-Jailer (@('--id', 'unfooled', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--parent-cgroup', $taken, '--cgroup-version', '2', '--cgroup', 'memory.max=1073741824', '--', 'affinity:0'))
        Check ($r[0] -eq 0 -and $r[1] -match 'affinity:0 allowed') "a jail given a parent whose name a jailed process used in the session's namespace did not start: exit $($r[0]): $($r[1])"
        "a parent on processor 0 (jail-parent; its memory limit refused): a jail under a level under it ran on processor 0; the tool refused a cgroup v1 level on processor 1 and a change of the parent's processors; the first jail took 200 MiB and ran on processor 0 of the 0-1 it asked for, the second took 200 MiB too; cgroup v1 refused processor 1; with the tool ended, a jail joining the parent ran on processor 0; a jailed process and the parents' namespace: $reach; a job of a parent's name in the session's namespace: $made, and a jail given that parent started"
    } finally {
        Stop-Jailers @($first, $squat) -Cleanup
        if (-not $holder.HasExited) { $holder.Kill() }
        if ($inner -and -not $inner.HasExited) { $inner.Kill() }
    }
}

# docs/PORTING.md row 8: cpu.weight is the job's CPU weight. Two jailed
# processes spin on one processor (cpuset.cpus=0), one at cpu.weight=50 and
# one at the default 100: Linux gives the first half the second's CPU time;
# Windows weight 2 (the nearest, measured at 0.49 of the default) must give
# it between 0.3 and 0.7 of it. Needs no guest.
function Stage-Weight([int]$Seconds = 6) {
    $base = New-Base 'weight'
    $probe = Get-Probe
    $runs = @()
    foreach ($w in 50, 100) {
        $out = Join-Path $base "w$w.txt"
        $line = "--id w$w --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" --cgroup-version 2 --cgroup cpuset.cpus=0 --cgroup cpu.weight=$w -- job:0 spin:$Seconds"
        $p = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        $null = $p.Handle
        $runs += @{ W = $w; P = $p; Out = $out }
    }
    try {
        $cpu = @{}
        foreach ($r in $runs) {
            Check ($r.P.WaitForExit(($Seconds + 30) * 1000)) "the jailer at cpu.weight=$($r.W) did not exit"
            $text = (Get-Content $r.Out, "$($r.Out).err" -Raw -ErrorAction SilentlyContinue) -join ''
            Check ($r.P.ExitCode -eq 0) "cpu.weight=$($r.W): the jailer exited $($r.P.ExitCode): $text"
            $want = if ($r.W -eq 50) { '0x3:2' } else { '0x3:5' }
            Check ($text -match "job:0 allowed affinity=0x1 cpu=$want") "cpu.weight=$($r.W): the job's limits: $text"
            Check ($text -match "spin:$Seconds allowed ([0-9.]+)") "cpu.weight=$($r.W): no spin result: $text"
            $cpu[$r.W] = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        }
        $ratio = $cpu[50] / [math]::Max($cpu[100], 0.001)
        Check ($ratio -ge 0.3 -and $ratio -le 0.7) ("cpu.weight 50 against 100 on one processor: {0:N2} s against {1:N2} s of CPU (ratio {2:N2}; Linux gives 0.5)" -f $cpu[50], $cpu[100], $ratio)
        "cpu.weight=50 and 100 on one processor: Windows weights 2 and 5, {0:N2} s against {1:N2} s of CPU in {2} s (ratio {3:N2}; Linux gives 0.5)" -f $cpu[50], $cpu[100], $Seconds, $ratio
    } finally {
        Stop-Jailers @($runs | ForEach-Object { $_.P }) -Cleanup
    }
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
        # Its stderr is read as text: under 'Stop' a native command's stderr
        # line is an error. The launcher prints nothing.
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ErrorActionPreference = 'Continue'
        $said = @(& $Jailer --id d --exec-file $Fc --uid 0 --gid 0 --chroot-base-dir $base --daemonize 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $sw.Stop()
        Check ($code -eq 0) "the jailer did not return 0 with --daemonize (exit $code): $($said -join ' | ')"
        Check ($said.Count -eq 0) "the launcher printed: $($said -join ' | ')"
        Check ($sw.Elapsed.TotalSeconds -lt 10) "the jailer did not return promptly: $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s"
        # The detached Firecracker keeps running after the launcher returned.
        $sock = Join-Path $root 'run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) 'the detached Firecracker did not open its API socket'
        # Two processes of the binary run the jail, Firecracker and its API
        # process (`api`); Firecracker is the one without the API process's
        # whole mitigation profile (no dynamic code policy before a guest).
        $fcp = Get-JailFirecracker $root
        $pidFile = Join-Path $root 'firecracker.exe.pid'
        Check (Test-Path $pidFile) 'no pid file'
        $written = [int](Get-Content $pidFile)
        Check ($written -eq $fcp.Id) "the pid file holds $written, Firecracker is $($fcp.Id)"
        # It has no console window, and no console at all.
        Check ($fcp.MainWindowHandle -eq 0) 'the detached Firecracker has a window'
        $looked = Assert-NoConsole $root
        $answer = Invoke-Api $sock 'GET' '/'
        Check ($answer -match ' 200$') "the detached Firecracker's API: $answer"
        # Ending Firecracker lets its detached jailer exit cleanly and remove
        # the jail's drive, as a guest shutdown does.
        Stop-Alive $fcp
        $t = [DateTime]::Now.AddSeconds(5)
        while ((Get-Process jailer -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        "the launcher returned 0 in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s; a detached Firecracker (pid $written, in the pid file) ran with no console (no console host for its $looked processes) and answered its API"
    } finally { Stop-Jailed }
}

# The jail's processes at `root` (Firecracker and its API process, `api`)
# have no console: the jailer starts them with DETACHED_PROCESS, so no
# console host (conhost.exe, which Windows starts as a child of the process
# it serves) runs for them on the jail's token. Before, each had a hidden
# console of its own (CREATE_NO_WINDOW) and a console host; under the jail's
# SID alone that host failed the process's start with 0xC0000142. Returns
# how many processes of the binary it looked at.
function Assert-NoConsole([string]$root) {
    $procs = @(Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$root*" })
    Check ($procs.Count -ge 1) "no process of the jail's binary under $root to look at for a console"
    $ids = @($procs | ForEach-Object { $_.Id })
    $hosts = @(Get-CimInstance Win32_Process -Filter "Name = 'conhost.exe'" | Where-Object { $ids -contains [int]$_.ParentProcessId })
    Check ($hosts.Count -eq 0) "a console host runs for the jail's processes: $(@($hosts | ForEach-Object { "conhost.exe $($_.ProcessId) of $($_.ParentProcessId)" }) -join ', ')"
    $procs.Count
}

# tools\windows\jail-probe.rs, built once (or -Probe).
# The process mitigations of pid $id, by name, through jail-probe.
function Get-Mitigations([int]$id) {
    $line = & (Get-Probe) "mitigations:$id"
    Check ($line -match '^mitigations:\d+ allowed') "reading pid $id's mitigations: $line"
    $m = @{}
    foreach ($kv in ($line -split ' ' | Where-Object { $_ -match '=' })) { $k, $v = $kv -split '='; $m[$k] = [Convert]::ToInt32($v, 16) }
    $m
}

# The jailed Firecracker of the jail at `root`, of the two processes of the
# binary there (Firecracker and its API process, `api`): the one without the
# API process's whole mitigation profile (no dynamic code policy before a
# guest). The API process sets that profile itself once Firecracker has
# linked to it (vmm::ext::api_process, sandbox::apply_api), after both run
# and after the API socket exists (Firecracker binds it and hands it over):
# until then neither has the policy, and taking "the first without it" took
# the API process on CI (run 43428124115, pidns: "the pid file holds 9040,
# Firecracker is 7240"). So this waits, up to 10 s, until exactly one has it.
function Get-JailFirecracker([string]$root) {
    $t = [DateTime]::Now.AddSeconds(10)
    while ($true) {
        $procs = @(Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$root*" })
        $plain = @($procs | Where-Object { (Get-Mitigations $_.Id).DynamicCode -eq 0 })
        if ($procs.Count -eq 2 -and $plain.Count -eq 1) { return $plain[0] }
        if ([DateTime]::Now -ge $t) {
            Check $false "the jail's Firecracker and its API process are not told apart after 10 s: $($procs.Count) processes of the binary in $root, $($plain.Count) without the dynamic code policy ($(@($procs | ForEach-Object { "$($_.Id) DynamicCode=$((Get-Mitigations $_.Id).DynamicCode)" }) -join ', '))"
        }
        Start-Sleep -Milliseconds 100
    }
}

function Get-Probe {
    if ($script:Probe) { return $script:Probe }
    # CI's kit has it built next to this script.
    $kit = Join-Path $Here 'jail-probe.exe'
    if (Test-Path $kit) {
        $script:Probe = $kit
        return $kit
    }
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
    # Windows PowerShell 5.1 keeps no exit code for a Start-Process process
    # unless its handle was taken while it ran (the api stage checks it).
    $null = $j.Handle
    $root = Join-Path $base "firecracker.exe\$id\root"
    $sock = Join-Path $root 'run\firecracker.socket'
    $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $j.HasExited) { Start-Sleep -Milliseconds 100 }
    Check (Test-Path $sock) "the jailed API socket did not appear: $(Get-Content -Raw (Join-Path $base "$id-err.txt") -ErrorAction SilentlyContinue)"
    # The jail runs two processes of the binary, Firecracker (the pid file)
    # and its API server's process.
    $pidFile = Join-Path $base "firecracker.exe\$id\root\firecracker.exe.pid"
    $fcPid = [int](Get-Content $pidFile -Raw).Trim()
    $fcp = Get-Process -Id $fcPid -ErrorAction SilentlyContinue
    Check ($null -ne $fcp -and $fcp.Path -like "$root*") "the jailed Firecracker $id (pid $fcPid) is not running"
    $api = Get-Process firecracker | Where-Object { $_.Path -like "$root*" -and $_.Id -ne $fcPid }
    @{ Jailer = $j; Fc = $fcp; Api = $api; Root = $root; Sock = $sock }
}

# One API call to a socket; returns "<body> <status>". A body (an object) is
# sent as JSON from a file: Windows PowerShell drops the quotes of a JSON
# argument.
function Invoke-Api([string]$sock, [string]$method, [string]$path, $body = $null) {
    Assert-SockPath $sock
    $a = @('-s', '-o', '-', '-w', ' %{http_code}', '--unix-socket', $sock, '-X', $method, "http://localhost$path")
    if ($null -ne $body) {
        $file = Join-Path $WorkDir "api-body-$PID.json"
        [IO.File]::WriteAllText($file, ($body | ConvertTo-Json -Depth 8 -Compress))
        $a += @('-H', 'Content-Type: application/json', '--data-binary', "@$file")
    }
    # One string: a body with newlines would come back as an array, on which
    # -match returns the matching lines rather than a boolean.
    (& curl.exe @a) -join "`n"
}

# The answer patches/0050 gives a request the VMM can no longer serve.
$VmmEnded = 'The VMM has ended and Firecracker is exiting'
# How long a jailed Firecracker that gave that answer has to exit.
$ExitBoundSec = 10

# A jailed Firecracker that answered that its VMM ended (on `sock`) is exiting
# by itself and writes its reason after the answer: waits for it, up to
# $ExitBoundSec, and says how it ended, so that the stage's cleanup does not
# kill it while it writes (macOS's harness did: CI run 43823078930). One that
# does not exit within the bound is killed, recorded (Stop-Alive), and is a
# failure of its own.
function Wait-Ending([string]$sock) {
    $root = Split-Path (Split-Path $sock)
    $fc = @(Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$root*" })
    foreach ($p in $fc) { $null = $p.Handle }
    foreach ($p in $fc) {
        if (-not $p.WaitForExit($ExitBoundSec * 1000)) {
            Stop-Alive $p -Cleanup
            throw [Failure]::new("Firecracker said it was exiting and did not within $ExitBoundSec s; killed by the harness while alive")
        }
    }
    $codes = @($fc | ForEach-Object { "pid $($_.Id) exit $($_.ExitCode)" })
    "then it exited: $(if ($codes) { $codes -join ', ' } else { 'already gone' })"
}

# `Invoke-Api` that fails unless the status is 2xx; returns the body. After
# patches/0050's answer, the failure comes once the jail's Firecracker has
# exited (Wait-Ending).
function Invoke-ApiOk([string]$sock, [string]$method, [string]$path, $body = $null) {
    $r = Invoke-Api $sock $method $path $body
    if ($r -match ' 500$' -and $r.Contains($VmmEnded)) { $r = "$r; $(Wait-Ending $sock)" }
    Check ($r -match ' 2\d\d$') "$method $path -> $r"
    $r -replace ' \d{3}$', ''
}

# Runs jail-probe with `checks` (check -> whether it must be allowed); returns
# the lines that did not answer as expected.
# Runs a program as a plain process of the user (jail-probe `medium`:
# medium integrity, the administrators' group for deny only, no privilege
# but SeChangeNotify, as UAC gives a user's programs); returns
# (exit code, output).
function Invoke-Medium([string[]]$argv, [int]$ms = 20000) {
    $out = Join-Path $WorkDir 'medium-out.txt'
    $line = 'medium ' + (($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $p = Start-Process (Get-Probe) -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    $null = $p.Handle
    if (-not $p.WaitForExit($ms)) { $p.Kill(); throw [Failure]::new("the medium process did not exit: $line") }
    @($p.ExitCode, ((Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue) -join ''))
}

# Fails unless jail-probe `medium` makes a plain process of the user, in
# which a program that loads user32 runs (PowerShell: it died at start with
# 0xC0000142 while the token kept an elevated default DACL).
function Assert-Medium {
    $t = Invoke-Medium @((Get-Probe), 'token:0')
    Check ($t[1] -match 'token:0 allowed integrity 8192 administrators no privileges 1') "jail-probe medium is not a plain process of the user: $($t[1])"
    $ps = Join-Path $PSHOME 'powershell.exe'
    $t = Invoke-Medium @($ps, '-NoProfile', '-NonInteractive', '-Command', 'exit 7') 60000
    Check ($t[0] -eq 7) ("PowerShell as a plain process of the user: exit 0x{0:x8} {1}" -f $t[0], $t[1])
}

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

# Gives the operator's file `f` a protected DACL that grants the jail's SID
# `sid` read (FILE_GENERIC_READ) and no group of the jail's token anything:
# the user, SYSTEM and the administrators full access besides. Fails unless
# the DACL read back by SID is exactly that. jailer-test.ps1 helpers runs it
# with a made-up jail SID, without a jailer.
function Grant-JailRead([string]$f, [string]$sid) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # The DACL as SDDL, set through .NET with the SIDs as they are:
    # icacls looks a `*SID` up and refuses one no account has, as
    # the jail's (S-1-9, the resource manager authority) is ("No
    # mapping between account names and security IDs was done",
    # ERROR_NONE_MAPPED: CI's links and isolation at de8805f4).
    # Protected, so nothing is inherited; FR is FILE_GENERIC_READ,
    # icacls's (R).
    $fs = New-Object System.Security.AccessControl.FileSecurity
    $fs.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;$user)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$sid)", [System.Security.AccessControl.AccessControlSections]::Access)
    (Get-Item -LiteralPath $f).SetAccessControl($fs)
    # Read back by SID: exactly these entries, allowed, not
    # inherited, the jail's FILE_GENERIC_READ (0x120089) and nothing
    # more.
    $back = (Get-Item -LiteralPath $f).GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $rules = @($back.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $seen = @($rules | ForEach-Object { "$($_.IdentityReference.Value)=$($_.AccessControlType)/$(if ($_.IsInherited) { 'inherited' } else { 'own' })/0x$('{0:x}' -f [int]$_.FileSystemRights)" })
    $jail = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
    $want = @($user, 'S-1-5-18', 'S-1-5-32-544', $sid | Select-Object -Unique).Count
    Check ($back.AreAccessRulesProtected -and $rules.Count -eq $want -and $jail.Count -eq 1 -and $jail[0].AccessControlType -eq 'Allow' -and -not $jail[0].IsInherited -and [int]$jail[0].FileSystemRights -eq 0x120089) "giving $f a read entry for the jail's SID ${sid}: the DACL reads $($seen -join ', ')"
    $kept = (Get-Acl $f).Sddl
    Check ($kept -notmatch ';;;(WD|BU|AU|IU|S-1-1-0|S-1-5-32-545|S-1-5-11|S-1-5-4)\)') "$f still grants a group of the jail's token: $kept"
}

# Runs the jailed probe (`--id id` under `base`) with `checks`, after the
# operator gave each file of `grant`, outside the jail, a read entry for that
# jail's SID and a protected DACL with no other entry a jail's token is
# granted by (SYSTEM, the administrators and the user besides): a file of the
# operator's that the jail may read, under the jail's token today and under
# one restricted to the jail's SID alone (option P), where a file every
# process may read (Users, Everyone) is not the jail's. The jail's SID is
# read from its root's DACL once the jailer set it; the probe's first check,
# `waitfor:/go`, holds its checks until the operator's go. Returns @(exit
# code, output, the jail's SID).
function Invoke-JailedWithGrant([string]$base, [string]$id, [string[]]$grant, [string[]]$checks, [int]$ms = 30000) {
    $probe = Get-Probe
    $root = Join-Path $base "jail-probe.exe\$id\root"
    $out = Join-Path $WorkDir "grant-$id.txt"
    $argv = @('--id', $id, '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'waitfor:/go') + $checks
    $line = ($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    $p = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    $null = $p.Handle
    try {
        $sid = $null
        $t = [DateTime]::Now.AddSeconds(15)
        while (-not $sid -and -not $p.HasExited -and [DateTime]::Now -lt $t) {
            Start-Sleep -Milliseconds 100
            $sddl = try { (Get-Acl $root -ErrorAction Stop).Sddl } catch { '' }
            if ($sddl -match ';;;(S-1-9-\d+-\d+-\d+-\d+)\)') { $sid = $Matches[1] }
        }
        Check ($null -ne $sid) "the jail's SID did not appear on ${root}: $((Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue) -join '')"
        foreach ($f in $grant) { Grant-JailRead $f $sid }
        Set-Content (Join-Path $root 'go') 'go'
        if (-not $p.WaitForExit($ms)) { throw [Failure]::new("jailer did not exit: $line") }
    } finally {
        if (-not $p.HasExited) { Stop-Jailers @($p) -Cleanup }
    }
    @($p.ExitCode, ((Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue) -join ''), $sid)
}

function Stage-Isolation {
    $probe = Get-Probe
    $base = New-Base 'isolation'
    $secret = Join-Path $env:USERPROFILE "wick-jailer-test-$PID.txt"
    Set-Content $secret 'secret'
    $outside = Join-Path $WorkDir "outside-$PID.txt"
    $granted = Join-Path $WorkDir "granted-$PID.txt"
    Set-Content $granted 'granted'
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
            "read:$granted"                                 = $true    # a file outside given to the jail's SID
            'read:C:\Windows\win.ini'                       = $false   # what every process of the session may read
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
        # The jail's SID is the probe's only restricting SID (option P): it
        # does not read what the system grants every process of the session
        # (win.ini, through Users and Everyone, which the token gave before),
        # and the probe, failing as Firecracker fails, would not have run
        # with another (preload::jail_sid_alone). The SID the token holds is
        # the one on its root's DACL.
        $restricted = 'restricted:0'
        $r = Invoke-JailedWithGrant $base 'probe' @($granted) (@($expect.Keys) + $restricted)
        $lines = $r[1] -split "`r?`n"
        $bad = @()
        foreach ($k in $expect.Keys) {
            $l = $lines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            if (-not $l) { $bad += "${k}: no answer ($($r[1].Trim()))"; continue }
            $allowed = $l.Substring($k.Length + 1).StartsWith('allowed')
            if ($allowed -ne $expect[$k]) { $bad += $l }
        }
        Check ($bad.Count -eq 0) "jailed: $($bad -join '; ')"
        $sole = $lines | Where-Object { $_.StartsWith("$restricted ") } | Select-Object -First 1
        Check ($sole -and $sole.Trim() -eq "$restricted allowed 1 $($r[2])") "jailed: the token's restricting SIDs are not the jail's ($($r[2])) alone: $sole"
        # The operator reaches the jailed API socket.
        $op = & $probe "connect:$sock"
        Check ($op -match ' allowed$') "operator: $op"
        $other.Send('reboot -ff')
        # Its Firecracker: the jailer then exits and removes the drive.
        Stop-Alive (Get-Process firecracker | Where-Object { $_.Path -like "$base*\api\root*" })
        [void]$api.WaitForExit(10000)
        "jailed: no user files, nothing outside its jail but the file given to its SID, no other jail, API socket or process (the operator's, another microVM's); the operator reaches the API socket ($($expect.Count) checks); its token's only restricting SID the jail's ($($r[2]))"
    } finally {
        Remove-Item $secret, $outside, $granted, 'C:\Users\Public\wick-jailer-test.txt' -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# The SMB client's connections now, by Get-SmbConnection, or by `net use`
# where that cmdlet fails (reach; helpers runs it too).
function Get-SmbConns([string]$when) {
    try {
        $c = @(Get-SmbConnection -ErrorAction Stop | ForEach-Object { "\\$($_.ServerName)\$($_.ShareName) as $($_.UserName), dialect $($_.Dialect), $($_.NumOpens) opens" })
        "smb-connections ${when}: $(if ($c.Count) { $c -join '; ' } else { 'none' }) (Get-SmbConnection)"
    } catch {
        $why = $_.Exception.Message
        $u = @(net use 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -match '\\\\' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
        "smb-connections ${when}: Get-SmbConnection: $why; net use: $(if ($u.Count) { $u -join '; ' } else { 'none' })"
    }
}

# The server's side after a run (its sessions and open files), and the SMB
# event-log entries of the run's window: a channel that is not there or not
# enabled is said so, and nothing is enabled. One line each, $SmbChannels.Count
# + 2 in all.
$SmbChannels = @('Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-SMBServer/Operational', 'Microsoft-Windows-SMBClient/Security', 'Microsoft-Windows-SMBClient/Connectivity')
function Get-SmbServerRecord([string]$who, [datetime]$from, [datetime]$to) {
    $out = @()
    $out += try { "smb-sessions after ${who}: $(@(Get-SmbSession -ErrorAction Stop | ForEach-Object { "$($_.SessionId) $($_.ClientComputerName) $($_.ClientUserName) dialect $($_.Dialect) $($_.NumOpens) opens" }) -join '; ')" } catch { "smb-sessions after ${who}: Get-SmbSession: $($_.Exception.Message)" }
    $out += try { "smb-open-files after ${who}: $(@(Get-SmbOpenFile -ErrorAction Stop | ForEach-Object { "$($_.ClientUserName) $($_.ShareRelativePath) on $($_.Path)" }) -join '; ')" } catch { "smb-open-files after ${who}: Get-SmbOpenFile: $($_.Exception.Message)" }
    foreach ($ch in $SmbChannels) {
        $log = Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue
        if (-not $log) { $out += "smb-events $who ${ch}: no such channel"; continue }
        if (-not $log.IsEnabled) { $out += "smb-events $who ${ch}: channel not enabled"; continue }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $ch; StartTime = $from; EndTime = $to } -ErrorAction SilentlyContinue)
        $out += "smb-events $who ${ch}: $(if ($ev.Count) { @($ev | ForEach-Object { $m = "$($_.Message)" -split "`r?`n" | Select-Object -First 1; "$($_.Id) $($_.LevelDisplayName): $m" }) -join ' | ' } else { 'none' })"
    }
    $out
}

# The share of reach's SMB probe (elevated; New-SmbShare is for
# administrators): a name of this run's, temporary (gone at a reboot), over
# `dir`, made here and holding the canary alone, read granted to Everyone by
# the share and by the canary's ACL. Returns its record lines (its access
# and the canary's ACL). The caller holds the name before the call, so that
# its cleanup (Remove-ReachShare) removes a share made before a later line
# here failed.
$SmbCanary = 'wick reach canary'
function New-ReachShareName { "wick-reach-$PID-$(Get-Random -Maximum 100000)" }
function New-ReachShare([string]$name, [string]$dir) {
    $everyone = ([Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([Security.Principal.NTAccount]).Value
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $canary = Join-Path $dir 'canary.txt'
    Set-Content -Path $canary -Value $SmbCanary
    & icacls $dir /inheritance:r /grant:r '*S-1-1-0:(OI)(CI)R' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    Check ($LASTEXITCODE -eq 0) "icacls on the share's directory: exit $LASTEXITCODE"
    & icacls $canary /inheritance:r /grant:r '*S-1-1-0:R' '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    Check ($LASTEXITCODE -eq 0) "icacls on the canary: exit $LASTEXITCODE"
    New-SmbShare -Name $name -Path $dir -ReadAccess $everyone -Temporary -ErrorAction Stop | Out-Null
    "smb-share $name over $dir, temporary"
    "smb-share-access: $(@(Get-SmbShareAccess -Name $name | ForEach-Object { "$($_.AccountName) $($_.AccessControlType) $($_.AccessRight)" }) -join '; ')"
    "smb-share-canary-acl: $((Get-Acl $canary).Sddl)"
}

# Removes New-ReachShare's share and directory, and returns the failure if
# the share is still there (a share left behind would serve its directory to
# the network), nothing otherwise. It runs in a finally block, so it does not
# throw: the caller reports it with any failure before it (Complete-Stage).
function Remove-ReachShare([string]$name, [string]$dir) {
    Remove-SmbShare -Name $name -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
    $left = Get-SmbShare -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $left) { "the share $name is still there after the stage (Remove-SmbShare did not remove it): remove it by hand" }
}

# Ends a stage whose cleanup can fail after the stage itself failed: an
# exception thrown in a finally block replaces the one in flight, so the
# stage catches its own (`err`), cleans up, and this reports both when both
# failed, the cleanup's alone, or the stage's.
function Complete-Stage($err, [string]$cleanup) {
    if ($cleanup -and $err) { throw [Failure]::new("$cleanup; and before it: $($err.Exception.Message)") }
    if ($cleanup) { throw [Failure]::new($cleanup) }
    if ($err) { throw $err }
}

# The SMB checks of a run: C$ and the rest, the share when there is one,
# and `more`.
function Get-SmbChecks([string]$share, [string[]]$more) {
    $c = @('smb:0')
    if ($share) { $c += "smb:$share" }
    foreach ($m in $more) { $c += $m }
    $c
}

# One SMB check's end line in a run's lines `ls` (each prefixed `prefix`),
# and its opens, a form and a word each (the share's forms are named
# share-...); fails if the check's record did not end.
function Get-SmbEnd([string[]]$ls, [string]$prefix, [string]$who, [string]$check) {
    $end = $ls | Where-Object { $_ -match "^$([regex]::Escape("$prefix$check")) done \d+ of \d+ opened$" } | Select-Object -First 1
    Check ($null -ne $end) "the SMB record ($who, $check) did not end: $(($ls | Select-Object -Last 3) -join ' | ')"
    $share = $check -ne 'smb:0'
    $each = @($ls | Where-Object { $_.StartsWith("${prefix}smb-open ") } | ForEach-Object { $f = $_ -split "`t"; $form = ($f[0] -split ' ')[-1]; if ($form.StartsWith('share-') -eq $share) { "$form $(@(($f[2] -replace '^allowed granted ', 'allowed ') -split ' ')[0..1] -join ' ')" } })
    "$($end -replace "^$([regex]::Escape("$prefix$check")) done ", '') ($($each -join ', '))"
}

# A run's SMB records summed: C$ and the rest, and the share when there is one.
function Get-SmbAll([string[]]$ls, [string]$prefix, [string]$who, [string]$share) {
    $parts = @("C$ and the rest $(Get-SmbEnd $ls $prefix $who 'smb:0')")
    if ($share) { $parts += "the share $(Get-SmbEnd $ls $prefix $who "smb:$share")" }
    $parts -join '; '
}

# The devices a jail reaches under the jail's SID alone, each with its
# reason; all reached beneath their names, which the I/O manager does not
# check against the device's security when the device lacks
# FILE_DEVICE_SECURE_OPEN, so the restricting SIDs are not asked. Optional
# ones are there on some hosts only. The assertion is "a subset of these",
# with the required one reached.
$ReachDevices = [ordered]@{
    '\Device\Afd'                    = @{ Required = $true; Why = "Winsock's and the polling crate's driver: Firecracker uses it" }
    '\Ntfs'                           = @{ Required = $false; Why = "NTFS's control device; nothing to change from user mode" }
    '\Refs'                           = @{ Required = $false; Why = "ReFS's control device, where ReFS is loaded (Server 2022 under fs-probe's imitation); nothing to change from user mode" }
    '\Device\RawDisk'                = @{ Required = $false; Why = "the RAW file system's control device; nothing to change from user mode" }
    '\Device\RawCdRom'               = @{ Required = $false; Why = "the RAW file system's control device; nothing to change from user mode" }
    '\Device\RawTape'                = @{ Required = $false; Why = "the RAW file system's control device; nothing to change from user mode" }
    '\Fat'                            = @{ Required = $false; Why = "fastfat's control device, while fastfat is loaded (host hardening: stop or disable fastfat where no FAT volume is used)" }
    '\FatCdrom'                       = @{ Required = $false; Why = "fastfat's control device, while fastfat is loaded (as \Fat)" }
    '\Device\LanmanDatagramReceiver' = @{ Required = $false; Why = "bowser.sys, the computer browser's datagram receiver (host hardening, untested: disable the browser)" }
    '\Device\MQAC'                   = @{ Required = $false; Why = "Message Queuing's driver, where MSMQ is installed (CI's runner) (host hardening, untested: remove MSMQ)" }
}
# The object classes of the operator's list and what a jail reaches of
# each: Device is $ReachDevices's; every other, none. A class the list has
# that is not here fails, named, so that a Windows that adds one is a
# difference on the record, not a pass by omission.
$ReachClasses = [ordered]@{}
foreach ($c in 'ALPC Port', 'Callback', 'CpuPartition', 'Directory', 'Directory-unlisted', 'Driver', 'Event', 'FilterConnectionPort', 'Job', 'Key', 'KeyedEvent', 'Mailslot', 'Mutant', 'Partition', 'Pipe', 'Section', 'Semaphore', 'Session', 'SymbolicLink', 'Type', 'WindowStation') { $ReachClasses[$c] = 0 }
$ReachClasses['Device'] = 'the allowlist'
# The checks that are not names, as the jail's SID alone gives them: true
# allowed, false denied. The pipe list and IP are recorded, not asserted
# (IP: docs/windows-jail-reach.md, "IP without --netns").
$ReachChecks = [ordered]@{
    'load-library-after-revert version.dll' = $false
    'load-library-after-revert dbghelp.dll' = $false
    'hklm-read'                             = $false
    'hklm-system-read'                      = $false
    'named-pipe-create'                     = $false
    'mailslot-create'                       = $false
    'unix-socket-bind'                      = $true
}

# What the jail reached against $ReachClasses, $ReachDevices and
# $ReachChecks: the failures, each named (empty when it holds), and the
# devices reached. `listed` is the classes of the operator's list: each must
# have its summary line, and a record with none fails.
function Test-ReachAllowlist([string[]]$lines, [string[]]$listed) {
    $bad = @()
    $summary = @($lines | Where-Object { $_.StartsWith('reach-summary ') })
    $counts = @($summary | ForEach-Object { $_.Substring('reach-summary '.Length) }) -join '; '
    if ($summary.Count -eq 0) { $bad += 'the jailed record has no reach-summary line, so no class was checked' }
    if (@($listed).Count -eq 0) { $bad += "the operator's list has no class, so no class was checked" }
    foreach ($c in @($listed | Sort-Object -Unique)) {
        if (-not ($summary | Where-Object { $_.StartsWith("reach-summary $c tried ") })) { $bad += "the operator's list has class $c, and the jailed record has no summary for it" }
    }
    foreach ($l in $summary) {
        if ($l -notmatch '^reach-summary (.+) tried (\d+) reached (\d+)$') { $bad += "a summary line not read: $l"; continue }
        $class = $Matches[1]; $n = [int]$Matches[3]
        if (-not $ReachClasses.Contains($class)) { $bad += "a class not in the allowlist's classes: $class ($l)"; continue }
        if ($class -ne 'Device' -and $n -ne $ReachClasses[$class]) { $bad += "$class reached $n, where the allowlist has $($ReachClasses[$class])" }
    }
    $devices = @($lines | Where-Object { $_.StartsWith("reach Device`t") })
    $names = @()
    foreach ($l in $devices) {
        $f = $l -split "`t"
        $name = $f[1]; $how = $f[2]
        $names += $name
        if ($ReachDevices.Contains($name)) { continue }
        $kind = if ($how -match '(type 0x[0-9a-f]+ chars 0x[0-9a-f]+ secure-open \S+)') { $Matches[1] } else { $how }
        $remedy = if ($name -match '^\\Device\\[0-9a-fA-F]{8}$') {
            "an unnamed device (a PnP stack's; its name changes between boots): to try, not measured, FILE_DEVICE_SECURE_OPEN in its class key's DeviceCharacteristics"
        } elseif ($name -match '^\\Device\\(KeyboardClass|PointerClass)\d+$') {
            "an input class device: what a jail can do there is not measured; to try, not measured, FILE_DEVICE_SECURE_OPEN in the class key's DeviceCharacteristics (docs/windows-jail-reach.md)"
        } else {
            "a driver of this host without FILE_DEVICE_SECURE_OPEN: the operator's to decide (docs/windows-jail-reach.md)"
        }
        $bad += "$name reached, not in the allowlist ($kind): $remedy"
    }
    foreach ($k in $ReachDevices.Keys) {
        if ($ReachDevices[$k].Required -and $names -notcontains $k) { $bad += "$k not reached: it is the allowlist's control (Firecracker uses it), so the probe's opening or the jail changed" }
    }
    foreach ($k in $ReachChecks.Keys) {
        $l = $lines | Where-Object { $_.StartsWith("reach-check $k ") } | Select-Object -First 1
        if (-not $l) { $bad += "reach-check $k did not answer"; continue }
        if ($l.Substring("reach-check $k ".Length).StartsWith('allowed') -ne $ReachChecks[$k]) { $bad += $l }
    }
    if ($bad.Count) { $bad += "the classes as reached: $counts" }
    @{ Bad = $bad; Devices = $names; Counts = $counts }
}

# Host hardening for two of the allowlist's devices: fastfat stopped
# (sc.exe stop, its start type left as it is), and, once it is Stopped, the
# host's names listed again (jail-probe reachlist) and whether \Fat and
# \FatCdrom went; then started again, failing if it is not as it was. A stop
# refused, or one that does not reach Stopped within 10 s, is recorded as
# such and the list is not read as the hardened one; nothing is tried twice.
# A failure to start it again is reported with any failure before it, which
# it would otherwise replace (an exception thrown in a finally block replaces
# the one in flight). Returns the record line.
function Test-FastfatHardening([string]$probe, [string]$base) {
    $was = Get-CimInstance Win32_SystemDriver -Filter "Name='fastfat'" -ErrorAction SilentlyContinue
    if (-not $was) { return 'fastfat: no such driver on this host' }
    $head = "fastfat $($was.State), start $($was.StartMode)"
    if ($was.State -ne 'Running') { return "${head}: not running, so not tried" }
    $list = Join-Path $base 'fat-objects.txt'
    $stop = (& sc.exe stop fastfat 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join ' '
    $stopCode = $LASTEXITCODE
    if ($stopCode -ne 0) { return "${head}: sc stop refused (exit $stopCode): $stop" }
    $line = $null
    $err = $null
    try {
        $t = [DateTime]::Now.AddSeconds(10)
        do { Start-Sleep -Milliseconds 200; $now = Get-CimInstance Win32_SystemDriver -Filter "Name='fastfat'" } while ($now.State -ne 'Stopped' -and [DateTime]::Now -lt $t)
        if ($now.State -ne 'Stopped') {
            $line = "${head}: sc stop accepted, but fastfat did not stop within 10 s (state $($now.State)), so the host's names were not listed as hardened"
        } else {
            $made = & $probe "reachlist:$list"
            $names = @(Get-Content $list -ErrorAction SilentlyContinue | Where-Object { $_ -match "^Device`t\\(Fat|FatCdrom)$" })
            $line = "${head}: stopped; the host's list then $(if ($names.Count) { "still has $($names -join ', ')" } else { 'has neither \Fat nor \FatCdrom' }) ($($made -replace '^reachlist:\S+ allowed ', ''))"
        }
    } catch {
        $err = $_
    }
    $start = (& sc.exe start fastfat 2>&1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join ' '
    $t = [DateTime]::Now.AddSeconds(10)
    do { Start-Sleep -Milliseconds 200; $back = Get-CimInstance Win32_SystemDriver -Filter "Name='fastfat'" -ErrorAction SilentlyContinue } while ($back.State -ne 'Running' -and [DateTime]::Now -lt $t)
    $restart = if ($back.State -ne 'Running' -or $back.StartMode -ne $was.StartMode) { "fastfat is not as it was after the stage (state $($back.State), start $($back.StartMode); sc start: $start): start it by hand" }
    Complete-Stage $err $restart
    $line
}

# What a jailed process reaches of the host's named objects, under the
# jail's token as the jailer makes it (docs/windows-jail-reach.md; option P:
# step A recorded it under the token with the session's groups, step C under
# the jail's SID alone, the record the allowlist above is written from): jail-probe `reachlist`, run by the operator, lists
# every named object of the object manager's namespace, every named pipe and
# every mailslot into the jail's root; jail-probe `reach`, the jailer's own
# spawn, after Firecracker's preload and RevertToSelf as every jailed check
# runs, opens each (a device by its name or beneath it, an ALPC port
# connected to, the rest by name) and runs the checks that are not names: a
# DLL loaded after the revert, HKLM read, TCP to loopback (a listener of
# this stage), the link-local metadata address and -External, an AF_UNIX
# bind, a pipe and a mailslot made, the pipes listed (tools/windows/
# jail-reach.rs), and the token's restricting SIDs (`restricted:0`). Its
# lines (`reach <type> <path> <how>`, `reach-check
# <name> <result>`, `reach-summary <type> tried <n> reached <m>`) are
# printed here whole: the format the allowlist will read. Then jail-probe
# `smb`: this host's files and pipes through the network redirectors
# (\Device\Mup, \Device\LanmanRedirector, a UNC name, the RDP client drives
# through \Device\RdpDrPort), which no device security guards beneath their
# names. Three runs, in this order, so that none finds an SMB connection
# another made (a restricted token shares the operator's logon session, so a
# jailed open could reuse a connection the operator's made): in
# the jail with --netns (elevated only: its filters) while this stage has
# made no connection, then in the jail, then by the operator, the control,
# last (which shares this host serves itself, so that a refusal is told from
# a share it does not have). The SMB client's connections are recorded
# before each run and after the --netns run and the control, so that a
# connection a run reused, or one a --netns run made, is on the record, not
# inferred. The server service's state and the shares are recorded too.
# With -ReachSmbShare (elevated; CI passes it, a run on a PC makes no share
# unless asked) the stage makes a share of its own for the run, read
# granted to Everyone, over a directory of its own holding only a canary
# that Everyone may read, and opens the canary by every form C$ is opened
# by: in the jail with --netns, in the jail, from jail-probe's
# low-integrity mode (the operator's token at low integrity, not
# restricted) and by the operator, in that order. Token A's restricting
# SIDs hold Everyone, so the share tells a refusal by the share's security
# (C$ grants administrators) from one by the client or by the token itself
# (docs/windows-jail-reach.md: what each outcome means). After each run
# the server's sessions and open files (Get-SmbSession, Get-SmbOpenFile)
# and the SMB server's and client's event-log entries of the run's window
# are recorded. Last, the jail again, on the sessions and tree connects the
# low-integrity run and the operator left behind (the jail's token shares
# the operator's logon session, by which the SMB client keeps them): a
# desktop with mapped drives, where the first jailed runs had nothing to
# reuse; with the share made, the stage fails if no connection to it is
# there for that run. The share and its directory are removed when the
# stage ends, and the stage fails if the share is still there.
# The records are kept as reach-record.txt and reach-objects.txt in the
# work directory, which CI's upload takes. The record must be whole (the
# list made, the jailed probe's end line, a summary, each SMB run's end
# line), and what the jail reached is asserted against $ReachClasses,
# $ReachDevices and $ReachChecks, written from the record under the jail's
# SID alone (f4fb55c4): every class but Device reached 0, and a class the
# operator's list has that is not in $ReachClasses fails, named; every
# device reached is in $ReachDevices (a name outside it fails, printed with
# its device type, characteristics and the remedy to try), and \Device\Afd,
# which Firecracker uses, is reached (the control); each check as measured;
# no SMB form opened by any jailed run. With -ReachHostHardening (elevated;
# CI passes it) it then stops fastfat, lists the host's names again, records
# whether \Fat and \FatCdrom went, and starts it again, failing if it is not
# running as before. Needs no guest.
function Stage-Reach([string]$External = '8.8.8.8:53') {
    $probe = Get-Probe
    $base = New-Base 'reach'
    $root = Join-Path $base 'jail-probe.exe\r\root'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    # The list in the jail's root, which the jail's directory grants it, as
    # a file Firecracker opens there is.
    $made = & $probe "reachlist:$(Join-Path $root 'objects.txt')"
    Check ($made -match ' allowed (\d+) names') "the operator's list: $made"
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $shareName = $null
    $shareDir = Join-Path $base 'share'
    $stageErr = $null
    $cleanup = $null
    try {
        $port = $listener.LocalEndpoint.Port
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        # The share, only when asked, and only elevated (New-ReachShare).
        $shareLines = @()
        if (-not $ReachSmbShare) {
            $shareLines += 'smb-share probe not run: not asked (-ReachSmbShare)'
        } elseif (-not $elevated) {
            $shareLines += 'smb-share probe not run: not elevated (New-SmbShare is for administrators)'
        } else {
            # The name first, so that the finally removes a share made
            # before a later line of New-ReachShare failed.
            $shareName = New-ReachShareName
            $shareLines += New-ReachShare $shareName $shareDir
        }
        # First, the jail with a network of its own: --netns's filters are
        # the jail's token's, and a redirector's connection is the system's.
        # The record is kept in the order things happened.
        $record = @("smb-order: the jailed run with --netns, the jailed run, the low-integrity run, the operator's control, the jailed run on the user's sessions") + $shareLines
        $connLines = @()
        if ($elevated) {
            $connLines += Get-SmbConns 'before the --netns run'
            $record += $connLines[-1]
            $net = Join-Path $base 'net'
            New-Item -ItemType Directory -Force -Path $net | Out-Null
            $t0 = Get-Date
            $n = Invoke-Jailer (@('--id', 'n', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--netns', $net, '--') + (Get-SmbChecks $shareName @())) 300000
            $netLines = @(@($n[1] -split "`r?`n" | Where-Object { $_ }) | ForEach-Object { "netns: $_" })
            $record += $netLines
            $record += Get-SmbServerRecord 'the --netns run' $t0 (Get-Date)
            $connLines += Get-SmbConns 'after the --netns run, before the jailed run'
        } else {
            $netLines = @('netns: not run: not elevated (--netns adds Windows Filtering Platform filters)')
            $record += $netLines
            $connLines += Get-SmbConns 'before the jailed run'
        }
        $record += $connLines[-1]
        $t0 = Get-Date
        $r = Invoke-Jailer (@('--id', 'r', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'restricted:0') + (Get-SmbChecks $shareName @("reach:/objects.txt:${port}:$External"))) 900000
        $lines = @($r[1] -split "`r?`n" | Where-Object { $_ })
        $record += $lines
        $record += Get-SmbServerRecord 'the jailed run' $t0 (Get-Date)
        # Then jail-probe's low-integrity mode: the operator's token at low
        # integrity, not restricted, outside any jail.
        $connLines += Get-SmbConns 'after the jailed run, before the low-integrity run'
        $record += $connLines[-1]
        $t0 = Get-Date
        $lowLines = @(& $probe low @(Get-SmbChecks $shareName @()) | Where-Object { $_ } | ForEach-Object { "low: $_" })
        $record += $lowLines
        $record += Get-SmbServerRecord 'the low-integrity run' $t0 (Get-Date)
        # Last, the control, outside any jail.
        $connLines += Get-SmbConns "after the low-integrity run, before the operator's control"
        $record += $connLines[-1]
        $serverState = try { "LanmanServer $((Get-Service LanmanServer -ErrorAction Stop).Status)" } catch { "LanmanServer: $($_.Exception.Message)" }
        $shares = try { "shares: $(@(Get-SmbShare -ErrorAction Stop | ForEach-Object { $_.Name }) -join ', ')" } catch { "shares: $($_.Exception.Message)" }
        $head = "operator: $serverState; $shares"
        $t0 = Get-Date
        $control = @(& $probe @(Get-SmbChecks $shareName @()) | Where-Object { $_ } | ForEach-Object { "operator: $_" })
        $record += @($head) + $control
        $record += Get-SmbServerRecord "the operator's control" $t0 (Get-Date)
        $connLines += Get-SmbConns "after the operator's control, before the jailed run on the user's sessions"
        $record += $connLines[-1]
        # Then the jail again, on the sessions and tree connects the
        # low-integrity run and the operator left (a desktop with mapped
        # drives): the jail's token shares the operator's logon session, the
        # key the SMB client keeps its sessions by. With the share made, a
        # connection to it must be there, or the run would not be the
        # measurement it is named; the same checks as the first jailed run's
        # SMB ones, and the token's restricting SIDs.
        $before = @(try { @(Get-SmbConnection -ErrorAction Stop) } catch { @() })
        $toShare = @($before | Where-Object { $shareName -and $_.ShareName -eq $shareName })
        $record += "smb-reuse: the jailed run on the user's sessions finds $($before.Count) connections, $(if ($toShare.Count) { "the share's among them" } else { 'none to the share' })"
        $t0 = Get-Date
        $u = Invoke-Jailer (@('--id', 'u', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'restricted:0') + (Get-SmbChecks $shareName @())) 300000
        $reuseLines = @(@($u[1] -split "`r?`n" | Where-Object { $_ }) | ForEach-Object { "reuse: $_" })
        $record += $reuseLines
        $record += Get-SmbServerRecord 'the jailed run on the user''s sessions' $t0 (Get-Date)
        $connLines += Get-SmbConns "after the jailed run on the user's sessions"
        $record += $connLines[-1]
        foreach ($l in $record) { Write-Host "     $l" }
        # Kept for CI's upload (the stage's own directory goes when it passes).
        Set-Content -Path (Join-Path $WorkDir 'reach-record.txt') -Value $record
        Copy-Item (Join-Path $root 'objects.txt') (Join-Path $WorkDir 'reach-objects.txt') -ErrorAction SilentlyContinue
        if ($shareName) { Check ($toShare.Count -gt 0) "no connection to \\127.0.0.1\$shareName after the operator's control, so the jailed run on the user's sessions had none to run on: $($connLines[-2])" }
        $smbControl = Get-SmbAll $control 'operator: ' 'the operator' $shareName
        $smbJailed = Get-SmbAll $lines '' 'jailed' $shareName
        $smbLow = Get-SmbAll $lowLines 'low: ' 'the low-integrity run' $shareName
        $smbNet = if ($elevated) { Get-SmbAll $netLines 'netns: ' 'jailed with --netns' $shareName } else { 'not run, not elevated' }
        $smbReuse = Get-SmbAll $reuseLines 'reuse: ' "jailed on the user's sessions" $shareName
        $done = $lines | Where-Object { $_ -match '^reach:\S+ done \d+ of \d+ names reached$' } | Select-Object -First 1
        Check ($r[0] -eq 0 -and $done) "the jailed record did not end: exit $($r[0]): $(($lines | Select-Object -Last 3) -join ' | ')"
        $summary = @($lines | Where-Object { $_.StartsWith('reach-summary ') } | ForEach-Object { $_.Substring('reach-summary '.Length) })
        Check ($summary.Count -gt 0) 'the jailed record has no reach-summary line'
        $checks = @($lines | Where-Object { $_.StartsWith('reach-check ') })
        $sids = $lines | Where-Object { $_.StartsWith('restricted:0 ') } | Select-Object -First 1
        # The allowlist, and no SMB form opened by a jailed run (with
        # --netns, without, and on the user's sessions).
        $listed = @(Get-Content (Join-Path $root 'objects.txt') -ErrorAction SilentlyContinue | ForEach-Object { ($_ -split "`t")[0] } | Where-Object { $_ } | Sort-Object -Unique)
        $allow = Test-ReachAllowlist $lines $listed
        # Each jailed run the stage made must have at least one SMB end line
        # with forms tried, every one with none opened: a run whose record
        # has none (it died, the format changed) fails, named.
        $opened = @()
        $sets = @(@{ N = 'the jailed run'; P = ''; L = $lines }, @{ N = "the jailed run on the user's sessions"; P = 'reuse: '; L = $reuseLines })
        if ($elevated) { $sets += @{ N = 'the jailed run with --netns'; P = 'netns: '; L = $netLines } }
        foreach ($set in $sets) {
            $ends = @($set.L | Where-Object { $_ -match "^$([regex]::Escape($set.P))smb:\S+ done \d+ of \d+ opened$" })
            if ($ends.Count -eq 0) { $opened += "$($set.N): no SMB end line"; continue }
            foreach ($l in $ends) {
                $null = $l -match ' done (\d+) of (\d+) opened$'
                if ([int]$Matches[2] -eq 0) { $opened += "$($set.N): tried no form: $l" }
                elseif ([int]$Matches[1] -ne 0) { $opened += "$($set.N): $l" }
            }
        }
        Check ($allow.Bad.Count -eq 0 -and $opened.Count -eq 0) "what the jail reached is not the allowlist's: $(@($allow.Bad + $opened) -join ' | ')"
        # Host hardening, when asked: fastfat stopped, the host's names
        # listed again, fastfat started again as it was.
        $fat = 'fastfat not tried: not asked (-ReachHostHardening)'
        if ($ReachHostHardening) {
            Check $elevated 'reach -ReachHostHardening needs an elevated PowerShell (it stops and starts a driver)'
            $fat = Test-FastfatHardening $probe $base
        }
        "the allowlist held under a token whose restricting SIDs are $($sids -replace '^restricted:0 allowed ', ''): devices $($allow.Devices -join ', '), every other class 0, the checks as measured, no SMB form opened by a jailed run; $fat; the operator's list $($made -replace '^reachlist:\S+ allowed ', ''); jailed, $($done -replace '^reach:\S+ done ', ''): $($summary -join '; '); $($checks.Count) other checks; SMB ($serverState; $shares; $($shareLines -join '; ')), in this order: jailed with --netns $smbNet; jailed $smbJailed; low integrity $smbLow; the operator $smbControl; jailed on the user's sessions ($($toShare.Count) to the share of $($before.Count) connections) $smbReuse; $($connLines -join '; ')"
    } catch {
        $stageErr = $_
    } finally {
        $listener.Stop()
        Stop-Jailed
        # The share goes with the stage, whatever happened.
        if ($shareName) { $cleanup = Remove-ReachShare $shareName $shareDir }
    }
    Complete-Stage $stageErr $cleanup
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
// Raw as vmm_sys_util::terminal sets it: no line input, echo or Ctrl+C
// processing (ENABLE_LINE_INPUT 2, ENABLE_ECHO_INPUT 4, ENABLE_PROCESSED_INPUT
// 1), virtual terminal input (0x200); canonical: all of those but the last.
public static bool IsRaw(uint m) { return (m & 7) == 0 && (m & 0x200) != 0; }
public static bool IsCanonical(uint m) { return (m & 7) == 7 && (m & 0x200) == 0; }
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
# What a jail could plant for the jailer that next starts a jail of its id
# to act on. That jailer grants the jail full access to each file in its root
# with other names (the operator's files linked into several jails), and
# writes Firecracker's copy and the pid file there, refusing a link in their
# place (unit test test_copy_exec_refuses_a_planted_link). From the jail
# (jail-probe as the jailed binary): no hard link to a file outside it, the
# operator's that it can read, a system file, another jail's (a hard link
# needs write access to the file's attributes), while it can link its own
# files (the control); no entry in the directories above its root, so no
# junction in place of the root or above. Needs no guest.
function Stage-Links {
    $base = New-Base 'links'
    $readable = Join-Path $WorkDir "links-readable-$PID.txt"
    try {
        $other = Start-ApiJail $base 'other'
        $otherFile = Join-Path $other.Root 'kernel.bin'
        Set-Content $otherFile "another jail's file"
        # The operator's file the jail reads (given a read entry for the
        # jail's SID, Invoke-JailedWithGrant: readable under the jail's token
        # today and under one restricted to the jail's SID alone) and may
        # not link, as Linux's protected_hardlinks refuses a link to a file
        # its caller may read but not write (fs/namei.c, may_linkat).
        Set-Content $readable "the operator's file"
        $root = Join-Path $base 'jail-probe.exe\probe\root'
        $parent = Split-Path -Parent $root
        $expect = [ordered]@{
            "read:$readable"                                 = $true    # the controls: it reads that file,
            'write:own.txt'                                  = $true    # writes in its jail
            "link:$root\link-own.txt|$root\own.txt"          = $true    # and links its own file
            "link:$root\link-operator.txt|$readable"         = $false
            "link:$root\link-system.txt|C:\Windows\win.ini"  = $false
            "link:$root\link-other.txt|$otherFile"           = $false
            "write:$parent\entry.txt"                        = $false   # the directory of its root
            "write:$(Split-Path -Parent $parent)\entry.txt"  = $false
            "write:$base\entry.txt"                          = $false   # the chroot base
        }
        $r = Invoke-JailedWithGrant $base 'probe' @($readable) @($expect.Keys)
        $lines = $r[1] -split "`r?`n"
        $bad = @()
        $denied = @()
        foreach ($k in $expect.Keys) {
            $l = $lines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            if (-not $l) { $bad += "${k}: no answer ($($r[1].Trim()))"; continue }
            $allowed = $l.Substring($k.Length + 1).StartsWith('allowed')
            if ($allowed -ne $expect[$k]) { $bad += $l }
            if ($k.StartsWith('link:') -and -not $allowed) { $denied += ($l.Substring($k.Length + 1) -replace '^denied ', '') }
        }
        Check ($bad.Count -eq 0) "jailed: $($bad -join '; ')"
        Check ((Get-Content -Raw $readable).Trim() -eq "the operator's file" -and (Get-Content -Raw $otherFile).Trim() -eq "another jail's file") 'a linked file changed'
        "jailed: no hard link to the operator's file it reads, a system file or another jail's ($($denied -join '; ')), while it links its own; no entry above its root"
    } finally {
        Remove-Item $readable -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# --resource-limit no-file= (upstream's 2048 when not given) is each jailed
# process's limit on its handles, where Linux counts descriptors
# (docs/COMPATIBILITY.md): a call of wick's POSIX layer (the compat libc,
# wick-os, the std::fs shadow, vmm-sys-util, memfd) that would make a
# descriptor past it fails with EMFILE (WSAEMFILE, os error 10024, through
# the errno table) and the process goes on; the calls' own tests are
# `wick_nofile::tests` (libc), `windows::tests` (wick-os) and wick-std's.
# Here, through the jailer:
# - no-file=3, below the handles any process starts with, stops the jailed
#   Firecracker at once with EMFILE, as upstream's test_negative_no_file_limit
#   asserts (Windows' number and text);
# - the default, 2048 given and 512 are accepted without a warning, the API
#   answers, and each process of the jail holds fewer handles than the limit;
# - handles made outside that layer are not refused: the jailed probe opens
#   5000 files with Windows' own calls under no-file=512, and 100000 under
#   memory.max of 32 MiB too. This records what is left to the jailer's
#   supervision (not written yet) and fails once it bounds them.
# Needs no guest.
function Stage-Nofile {
    $probe = Get-Probe
    $base = New-Base 'nofile'
    try {
        $r = Invoke-Jailer @('--id', 'three', '--exec-file', $Fc, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--resource-limit', 'no-file=3') 30000
        Check ($r[0] -ne 0) "no-file=3: the jailed Firecracker ran and exited 0: $($r[1])"
        Check ($r[1] -match 'os error 10024') "no-file=3: the jailed Firecracker did not stop with EMFILE: exit $($r[0]): $($r[1])"
        $left = @(Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$base*" })
        Check ($left.Count -eq 0) "no-file=3: $($left.Count) processes of the jail are left"
        $counts = @()
        foreach ($case in @(@('default', @(), 2048), @('given', @('--resource-limit', 'no-file=2048'), 2048), @('set', @('--resource-limit', 'no-file=512'), 512))) {
            $id = $case[0]
            $jail = Start-ApiJail $base $id $case[1]
            $null = Invoke-ApiOk $jail.Sock 'GET' '/'
            $said = (Get-Content -Raw (Join-Path $base "$id-err.txt") -ErrorAction SilentlyContinue)
            Check (-not ($said -match 'jailer: warning')) "${id}: the jailer warned: $said"
            foreach ($p in @($jail.Fc) + @($jail.Api)) {
                $p.Refresh()
                Check ($p.HandleCount -le $case[2]) "${id}: process $($p.Id) of the jail holds $($p.HandleCount) handles, past no-file=$($case[2])"
                $counts += "$id $($p.Id): $($p.HandleCount)"
            }
            Stop-Process -Id $jail.Fc.Id -Force
            [void]$jail.Jailer.WaitForExit(10000)
        }
        $common = @('--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--resource-limit', 'no-file=512')
        $r = Invoke-Jailer (@('--id', 'raw') + $common + @('--', 'files:5000')) 60000
        Check ($r[0] -eq 0 -and $r[1] -match 'files:5000 allowed 5000') "no-file=512, the probe's own opens: exit $($r[0]): $($r[1])"
        $r = Invoke-Jailer (@('--id', 'memory', '--cgroup-version', '2', '--cgroup', 'memory.max=33554432') + $common + @('--', 'files:100000')) 120000
        Check ($r[0] -eq 0 -and $r[1] -match 'files:100000 allowed 100000') "no-file=512 and memory.max=32 MiB, the probe's own opens: exit $($r[0]): $($r[1])"
        "no-file=3 stops the jailed Firecracker with EMFILE (os error 10024); the default, 2048 and 512 are accepted without a warning and the API answers (handles: $($counts -join ', ')); opens outside wick's POSIX layer are not refused: the jailed probe opens 5000 files under no-file=512, and 100000 under memory.max=32 MiB too"
    } finally { Stop-Jailed }
}

# memory.max bounds the jailed process's memory, as a cgroup does, sections
# included: under 32 MiB, private memory (the control) is refused by the job
# (or the process is ended with 137 by the jailer's count, whichever comes
# first), and pagefile-backed sections, which no job charges, end the jail
# with 137 at the jailer's next count, one poll after the last one under the
# limit (overlay/jailer/platform/windows/commit.rs); the jailer's line, with
# its polls' timing, goes into the summary and each run's output into
# sections-<id>.txt. Sections of temporary
# files are page cache, which Linux too reclaims at memory.max rather than
# ending the process for (the memory.max row): all 256 MiB are allowed.
function Stage-Sections {
    $probe = Get-Probe
    $base = New-Base 'sections'
    $common = @('--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--cgroup-version', '2', '--cgroup', 'memory.max=33554432')
    $killed = 'jailer: memory\.max: the jail''s memory, (\d+) bytes .* is past the memory limit \(memory\.max 33554432\): the jail is ended with 137; this poll woke (\d+) us after its tick; the poll before, (\d+) us earlier, counted (\d+), took (\d+) us and woke (\d+) us after its tick; .*; a poll every (\d+) us, the cover read every (\d+) us'
    # Each run's output kept in the work directory (CI uploads it), not only
    # the shared jailer-out.txt, which the next run overwrites.
    $keep = { param($id, $r) Set-Content -Encoding UTF8 (Join-Path $WorkDir "sections-$id.txt") "exit $($r[0])`r`n$($r[1])" }
    $r = Invoke-Jailer (@('--id', 'private') + $common + @('--', 'private:256')) 120000
    & $keep 'private' $r
    $denied = $r[1] -match 'private:256 denied after (\d+)' -and [int]$Matches[1] -le 32
    $control = if ($denied) { "denied after $($Matches[1]) MiB" } else { '' }
    if (-not $denied -and $r[0] -eq 137 -and $r[1] -match $killed) { $control = "ended with 137 at $([math]::Round([long]$Matches[1] / 1MB, 1)) MiB counted" }
    Check ($control -ne '') "the control, private memory under memory.max=32 MiB: exit $($r[0]): $($r[1])"
    $r = Invoke-Jailer (@('--id', 'sections') + $common + @('--', 'sections:256')) 120000
    & $keep 'sections' $r
    Check ($r[0] -eq 137 -and $r[1] -match $killed) "pagefile-backed sections under memory.max=32 MiB: not ended with 137 by the jailer's count: exit $($r[0]): $($r[1])"
    $line = $Matches[0]
    $counted = [long]$Matches[1]; $late = [long]$Matches[2]; $gap = [long]$Matches[3]; $before = [long]$Matches[4]
    $took = [long]$Matches[5]; $lateBefore = [long]$Matches[6]; $walk = [long]$Matches[8]
    # The kill is at the first poll past the limit: the poll before it, the
    # one just before on the jailer's own schedule, counted under it.
    Check ($before -le 33554432) "the poll before the kill counted $before bytes, past the limit, and did not end the jail: $line"
    # How far apart the two polls were is the jailer's scheduling, not a
    # property of the count (SECURITY.md, the window: a poll every 1 ms, 6090
    # us apart once on a loaded runner, CI run 44108132406). What fails here
    # is a poll thread starved past the cover's read period (WALK in
    # overlay/jailer/platform/windows/commit.rs, which the jailer's line
    # gives as "the cover read every N us").
    Check ($gap -lt $walk) "the poll before the kill was $gap us earlier, past the cover's read period of $walk us (WALK): the count's thread was starved: $line"
    Check (-not ($r[1] -match 'sections:256 allowed')) "the probe took all 256 MiB of sections: $($r[1])"
    $r = Invoke-Jailer (@('--id', 'filesections') + $common + @('--', 'filesections:256')) 120000
    & $keep 'filesections' $r
    Check ($r[0] -eq 0 -and $r[1] -match 'filesections:256 allowed 256') "temporary-file sections under memory.max=32 MiB (page cache, not counted): exit $($r[0]): $($r[1])"
    "under memory.max=32 MiB private memory is $control; pagefile-backed sections end the jail with 137 at $([math]::Round($counted / 1MB, 1)) MiB counted, $gap us after the last count under the limit ($([math]::Round($before / 1MB, 1)) MiB; that poll took $took us, its tick woke it $lateBefore us late, the kill's $late us); temporary-file sections, page cache, take all 256 MiB; the jailer's line: $line"
}

function Stage-Pidns {
    $base = New-Base 'pidns'
    $probe = Get-Probe
    $out = Join-Path $WorkDir 'pidns-out.txt'
    $victims = @()
    # The console's input mode at each step, timed, for the messages.
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $timeline = New-Object System.Collections.Generic.List[string]
    $note = {
        param([string]$what)
        $m = [WickJailerTest.Term]::Mode()
        $timeline.Add(('{0} ms {1}: 0x{2:x}' -f $clock.ElapsedMilliseconds, $what, $m))
        $m
    }
    try {
        $start = & $note 'the stage starts'
        Check ([WickJailerTest.Term]::IsCanonical($start)) ("the console is not in canonical mode at the start (0x{0:x}), so its mode proves nothing" -f $start)
        $other = Start-ApiJail $base 'other'
        # Started from this shell: on the operator's console when the shell's
        # input is one (an interactive console; not under ssh).
        $m = & $note 'an API-only jail started from the shell'
        Check ($m -eq $start) "an API-only jail changed the console's mode (upstream Firecracker sets raw mode only when it starts the microVM's vCPUs): $($timeline -join '; ')"
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

        # The console's mode, as a Linux terminal's under a jailed
        # Firecracker: as the operator left it while Firecracker runs no
        # microVM (upstream sets raw mode in Vm::start_vcpus and canonical
        # mode in Vmm::stop), and nothing reads it then. An API-only jailed
        # Firecracker with the console as its input (given here, so that
        # this holds under ssh too) leaves the mode, and takes none of the
        # keys typed below for another jail.
        $idle = [WickJailerTest.Term]::Start("`"$Jailer`" --id idle --exec-file `"$Fc`" --uid 0 --gid 0 --chroot-base-dir `"$base`"", (Join-Path $WorkDir 'pidns-idle.txt'), $false)
        $idleSock = Join-Path $base 'firecracker.exe\idle\root\run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $idleSock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $idleSock) "the API-only jail on the console: no API socket: $(Get-Content -Raw (Join-Path $WorkDir 'pidns-idle.txt') -ErrorAction SilentlyContinue)"
        $m = & $note 'an API-only jail with the console as its input'
        Check ($m -eq $start) "an API-only jail on the console changed its mode: $($timeline -join '; ')"

        # The relay: the jailed process asks for raw mode as Firecracker does
        # at a microVM's start (jail-probe echo: the jailer's mode pipe),
        # keys typed on the console then reach it as the bytes it would have
        # read (Ctrl+C a byte), its output reaches the console, and after it
        # asked for canonical mode and ended the console has its mode back.
        $pi = [WickJailerTest.Term]::Start("`"$Jailer`" --id echo --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- echo:echo.txt", $null, $false)
        $t = [DateTime]::Now.AddSeconds(10)
        while (-not [WickJailerTest.Term]::IsRaw([WickJailerTest.Term]::Mode()) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 20 }
        $m = & $note 'the jailed process asked for raw mode'
        if (-not [WickJailerTest.Term]::IsRaw($m)) {
            $code = [WickJailerTest.Term]::Wait($pi, 0)
            $state = if ($code -eq -1) { 'still runs' } else { "exited with $code" }
            $screen = ([WickJailerTest.Term]::Screen() -replace '\s+', ' ').Trim()
            if ($screen.Length -gt 400) { $screen = $screen.Substring($screen.Length - 400) }
            Check $false ("the jailer did not set the console to raw mode in 10 s: {0}; the jailer {1}; the screen ends: {2}" -f ($timeline -join '; '), $state, $screen)
        }
        [WickJailerTest.Term]::Type("hi$([char]3)q")
        $code = [WickJailerTest.Term]::Wait($pi, 20000)
        $m = & $note 'the relayed jailer ended'
        Check ($code -eq 0) "the relayed jailer: exit $code"
        $bytes = Get-Content (Join-Path $base 'jail-probe.exe\echo\root\echo.txt') -ErrorAction SilentlyContinue
        Check ($bytes -eq '68 69 03 71') "typed 'hi', Ctrl+C, 'q'; the jailed process read: $bytes (the API-only jail on the console must take none)"
        Check ([WickJailerTest.Term]::Screen() -match '\[jail-probe echo 4\]') "the jailed process's output did not reach the console"
        Check ($m -eq $start) "the console's mode after the relayed jailer: $($timeline -join '; ')"

        # The API-only jail ends: its Firecracker never asked, and the mode
        # stays.
        Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like (Join-Path $base 'firecracker.exe\idle\*') } | Stop-Process -Force
        $code = [WickJailerTest.Term]::Wait($idle, 10000)
        $m = & $note 'the API-only jail on the console ended'
        Check ($code -ne -1) 'the API-only jail on the console did not end with its Firecracker'
        Check ($m -eq $start) "the console's mode after the API-only jail ended: $($timeline -join '; ')"

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
        # Firecracker, not its API process (which has the whole profile, ACG among it).
        $fcp = Get-JailFirecracker $root
        $written = [int](Get-Content (Join-Path $root 'firecracker.exe.pid'))
        Check ($written -eq $fcp.Id) "--new-pid-ns: the pid file holds $written, Firecracker is $($fcp.Id)"
        $sock = Join-Path $root 'run\firecracker.socket'
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        $answer = Invoke-Api $sock 'GET' '/'
        Check ($answer -match ' 200$') "--new-pid-ns: Firecracker's API: $answer"
        # The keeper's Firecracker, on the operator's console, has none.
        $looked = Assert-NoConsole $root
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
        Stop-Alive $fcp
        $t = [DateTime]::Now.AddSeconds(5)
        while ((Get-Process jailer -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $other.Jailer.Id }) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        "the control reaches every process ($($ctl.Count) checks); jailed, nothing ($($checks.Count) checks and a console control event: the user's process survives); the console's mode stays with API-only jails and is raw only once the jailed process asks, typed keys reach it through the relay as bytes, none reach an API-only jail, and the mode is back after ($($timeline -join '; ')); --new-pid-ns: the jailer returned 0 in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s with Firecracker running (pid file) and no console host for its $looked processes, refused a jail it could not build; a pid's existence still shows ($oracle)"
    } finally {
        $victims | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        [WickJailerTest.Term]::Flush()
        Stop-Jailed
    }
}

# Row 14 of docs/PORTING.md: a jailed VMM passes descriptors to a userfaultfd
# handler or a vhost-user backend of the operator. The jail's token opens no
# process outside the jail, so a jailed sender cannot duplicate handles into
# the receiver, and neither can Winsock, which duplicates a socket into the
# target process itself: the receiver pulls them out of the sender instead
# (vmm-sys-util's sock_ctrl_msg, its FLAG_PULL frames). This stage checks that
# with the jail's real tokens: a file handle and a socket a jailed process
# holds are pulled out of it by a process of the operator (the test's, and a
# plain medium-integrity one when the test is elevated), and the jailed
# process cannot open the operator's. The protocol end to end, under a
# guest, is `uffd` and `vhost-user`. Needs no guest.
function Stage-Handoff {
    $base = New-Base 'handoff'
    $probe = Get-Probe
    $root = Join-Path $base 'jail-probe.exe\h\root'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $secret = "HANDOFF-$([Guid]::NewGuid().ToString('N'))"
    # The file the jailed process holds is the jail's own, in its root, as
    # a file Firecracker opens is (a drive, a snapshot): the jail's SID,
    # which the jail's directory grants, opens it with any token the jailer
    # gives. A file of the operator's outside the jail is not the jail's
    # to open (the jail's SID alone is denied it, measured; Linux's chroot
    # cannot name it).
    $file = Join-Path $root 'handoff-secret.txt'
    [IO.File]::WriteAllText($file, $secret)
    # The socket's receiver listens in the jail: a socket outside it is out
    # of the jail's reach, as a handler's socket is placed in the jail.
    $sock = Join-Path $root 'handoff.sock'
    $out = Join-Path $WorkDir 'handoff-out.txt'
    $listenOut = Join-Path $WorkDir 'handoff-listen.txt'
    $listener = $null
    try {
        $listener = Start-Process $probe -ArgumentList "listenpull:$sock" -PassThru -NoNewWindow -RedirectStandardOutput $listenOut
        $t = [DateTime]::Now.AddSeconds(5); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) 'the receiver did not listen'
        $j = Start-Process $Jailer -ArgumentList "--id h --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- sockpull:$sock signal:$PID hold:/handoff-secret.txt:20" -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        $t = [DateTime]::Now.AddSeconds(15); $held = $null
        while ([DateTime]::Now -lt $t -and -not $held -and -not $j.HasExited) {
            Start-Sleep -Milliseconds 200
            $held = Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_ -match '^hold:.* allowed (\d+)$' } | Select-Object -First 1
        }
        Check ($null -ne $held) "the jailed process did not hold the file: $(Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue)"
        $value = [int64]($held -replace '.* allowed (\d+)$', '$1')
        $jailed = Get-Process jail-probe | Where-Object { $_.Path -like "$root*" } | Select-Object -First 1
        Check ($null -ne $jailed) 'the jailed process is not running'
        # The socket the jailed process handed over works in the receiver.
        [void]$listener.WaitForExit(10000)
        $sent = Get-Content $out | Where-Object { $_.StartsWith('sockpull:') } | Select-Object -First 1
        Check ($sent -match ' allowed') "the jailed sender: $sent"
        $got = Get-Content $listenOut -Raw -ErrorAction SilentlyContinue
        Check ($got -match 'listenpull:.* allowed') "the receiver: $got"
        # The file handle is pulled out of the jailed process and read.
        $pulled = & $probe "pull:$($jailed.Id):$value"
        Check ($pulled -match "allowed $secret$") "the operator pulling the handle: $pulled"
        $medium = ''
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($elevated) {
            # Also from a plain process of the user (medium integrity, no
            # administrator's group or privileges), as a handler of the user
            # runs: jail-probe `medium`, checked to be one first.
            Assert-Medium
            $m = Invoke-Medium @($probe, "pull:$($jailed.Id):$value")
            Check ($m[1] -match "allowed $secret") "a medium-integrity process pulling the handle: $($m[1])"
            $medium = ' and by a medium-integrity process of the user'
        }
        # The signal check ran before the hold (its line came first); the
        # hold's 20 s are a bound for the pulls above, not something to
        # wait out: the jailed process is ended once they are done, and its
        # jailer then exits and removes the jail's drive (Stop-Jailers).
        $sig = Get-Content $out | Where-Object { $_.StartsWith("signal:$PID ") } | Select-Object -First 1
        Check ($sig -and $sig -notmatch ' allowed') "the jailed process can open the operator: $sig"
        Stop-Jailers @($j)
        "a socket and a handle to a file of the jail held by the jailed process were pulled out by the operator$medium; the jailed process cannot open the operator ($sig)"
    } finally {
        if ($listener -and -not $listener.HasExited) { $listener.Kill() }
        Remove-Item $file -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# A tool next to the binaries, or where the build puts it.
function Find-Tool([string]$name) {
    $dirs = @($Bin, (Join-Path $Bin 'examples'), (Join-Path $Bin '..\..\vhost-user-blk\release'))
    foreach ($d in $dirs) { $p = Join-Path $d $name; if (Test-Path $p) { return (Resolve-Path $p).Path } }
    throw [Failure]::new("$name not found in $($dirs -join ', ')")
}

# Row 14, end to end: a jailed guest snapshotted, then restored in another
# jail with its memory served by upstream's uffd_on_demand_handler, a process
# of the operator: the jailed Firecracker hands it the userfaultfd (a
# socket) and the memory file, which the handler pulls out of the jail.
# Needs a guest (WHP). The userfaultfd's waiter mirror is pulled too: the
# jailed VMM may not open the handler to push it (its OP_MIRROR answers
# -EPERM), so the handler opens the VMM and copies the read-only handle out.
function Stage-Uffd {
    $handler = Find-Tool 'uffd_on_demand_handler.exe'
    $base = New-Base 'uffd'
    $h = $null
    try {
        $vm = Start-JailedVm $base 'snap' @() 256 -Api
        Wait-Shell $vm
        # Done before the pause: serial input still in flight at the snapshot
        # is not part of it (upstream saves no serial input buffer).
        # The root is read-only: a tmpfs for the mark.
        Check ($vm.Sh('mount -t tmpfs tmpfs /tmp; echo snapshot-$((6*7)) > /tmp/mark; cat /tmp/mark', 30) -eq 'snapshot-42') 'the mark was not written'
        Invoke-ApiOk $vm.Sock 'PATCH' '/vm' ([ordered]@{ state = 'Paused' }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/snapshot/create' ([ordered]@{ snapshot_type = 'Full'; snapshot_path = '/snap.state'; mem_file_path = '/snap.mem' }) | Out-Null
        Stop-Jailed -Done
        # The restoring jail: the snapshot, the drives the snapshot names,
        # and the handler's socket, in the jail.
        $root = Join-Path $base 'firecracker.exe\restore\root'
        New-Item -ItemType Directory -Force -Path $root | Out-Null
        foreach ($f in 'snap.state', 'snap.mem') { Copy-Item (Join-Path $vm.Root $f) (Join-Path $root $f) }
        $sock = Join-Path $root 'uffd.sock'
        $h = Start-Process $handler -ArgumentList "`"$sock`" `"$(Join-Path $root 'snap.mem')`"" -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $base 'handler-out.txt') -RedirectStandardError (Join-Path $base 'handler-err.txt')
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $h.HasExited) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) "the uffd handler did not listen: $(Get-Content (Join-Path $base 'handler-err.txt') -Raw -ErrorAction SilentlyContinue)"
        $vm2 = Start-JailedVm $base 'restore' @() 256 -Api -NoConfig
        Invoke-ApiOk $vm2.Sock 'PUT' '/snapshot/load' ([ordered]@{ snapshot_path = '/snap.state'; mem_backend = [ordered]@{ backend_type = 'Uffd'; backend_path = '/uffd.sock' }; resume_vm = $true }) | Out-Null
        $vm2.Send('PS1=')
        $mark = $vm2.Sh('cat /tmp/mark', 30)
        Check ($mark -eq 'snapshot-42') "the restored guest's state: '$mark'"
        $md5 = $vm2.Sh('head -c 64m /dev/zero | md5sum', 120)
        Check ($md5 -match '^7f614da9329cd3aebf59b91aadc30bf0') "64 MiB of fresh pages through the handler: '$md5'"
        Check (-not $h.HasExited) "the handler exited: $(Get-Content (Join-Path $base 'handler-err.txt') -Raw -ErrorAction SilentlyContinue)"
        $vm2.Send('reboot -ff')
        Check ($vm2.P.WaitForExit(15000)) 'the jailer did not exit after the restored guest rebooted'
        Check ($vm2.P.ExitCode -eq 0) "jailer exit $($vm2.P.ExitCode)"
        'a jailed guest restored in another jail from a snapshot served by uffd_on_demand_handler outside it: state kept, fresh pages served'
    } finally {
        if ($h -and -not $h.HasExited) { $h.Kill() }
        Stop-Jailed
    }
}

# Row 14, end to end: a jailed guest with a vhost-user-blk drive served by
# tools/vhost-user-blk, a process of the operator: the jailed Firecracker
# hands it guest memory and eventfds, which the backend pulls out of the jail.
function Stage-Vhost-User {
    $vub = Find-Tool 'vhost-user-blk.exe'
    $base = New-Base 'vhost-user'
    $root = Join-Path $base 'firecracker.exe\vub\root'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $img = Join-Path $WorkDir 'vub.img'
    $bytes = New-Object byte[] (8MB); (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes($img, $bytes)
    $want = ([BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($bytes)) -replace '-', '').ToLower()
    $sock = Join-Path $root 'vub.sock'
    $b = $null
    try {
        $b = Start-Process $vub -ArgumentList "`"$sock`" `"$img`"" -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $base 'backend-out.txt') -RedirectStandardError (Join-Path $base 'backend-err.txt')
        $t = [DateTime]::Now.AddSeconds(10); while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $b.HasExited) { Start-Sleep -Milliseconds 100 }
        Check (Test-Path $sock) "the vhost-user backend did not listen: $(Get-Content (Join-Path $base 'backend-err.txt') -Raw -ErrorAction SilentlyContinue)"
        $vm = Start-JailedVm $base 'vub' @() 256 -drives @([ordered]@{ drive_id = 'vub'; socket = '/vub.sock'; is_root_device = $false })
        Wait-Shell $vm
        $got = $vm.Sh('md5sum /dev/vdb', 120)
        Check ($got -match "^$want") "the guest's md5 over vhost-user '$got', the image's $want"
        $vm.Sh('echo vhost-user-$((6*7)) | dd of=/dev/vdb bs=512 seek=8 conv=fsync,notrunc 2>/dev/null; echo WROTE', 30) | Out-Null
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        $b.Kill(); [void]$b.WaitForExit(5000)
        $fs = [IO.File]::Open($img, 'Open', 'Read', 'ReadWrite')
        try { $fs.Position = 4096; $w = New-Object byte[] 14; [void]$fs.Read($w, 0, 14) } finally { $fs.Dispose() }
        $text = [Text.Encoding]::ASCII.GetString($w)
        Check ($text -eq "vhost-user-42`n") "the guest's write is not in the backend's image: '$text'"
        'a jailed guest reads and writes a vhost-user-blk drive served by a backend outside the jail'
    } finally {
        if ($b -and -not $b.HasExited) { $b.Kill() }
        Remove-Item $img -ErrorAction SilentlyContinue
        Stop-Jailed
    }
}

# Row 6 of docs/PORTING.md: --netns. On Linux the jailed Firecracker joins a
# network namespace and the guest reaches only the network given there; a TAP
# in it is its owner's (drivers/net/tun.c: tun_not_capable, and tun_attach
# refuses a second attach with EBUSY). On Windows the network is a directory
# of endpoints, which grants no jail anything: each jail makes its endpoints
# in a directory of its own in it, <network>\<id>, which only that jail and
# the operator reach; and the jail's copy of Firecracker gets no IP
# networking at all (Windows Filtering Platform, in a session that ends with
# the jailer). Two jails, each with a network of its own, and a third jail
# and a jailed probe given the first's: every endpoint is in its jail's own
# directory; the probe, a jail of that network too, cannot connect to,
# delete or take the name of another jail's endpoint, or make a name in the
# network directory itself, and makes one in its own (the control); a second
# jail of a running jail's id is refused and the first keeps its endpoint;
# the operator reaches every endpoint (the control); IP is denied to a jail
# with a network and allowed to one without (the control), and a jailer that
# is not elevated refuses the flag. The jail's token alone does not stop IP:
# since option P's step C, Winsock's first AF_INET socket in a jailed process
# fails (os error 5: the TCP/IP transport's first use reads what the jail's
# SID may not), but that is Winsock's own step in the process, which a process
# that has taken it before its revert does not take again, and the TCP/IP
# stack itself is not refused (fs-probe on Windows Server 2022: a socket made
# before the revert, a new one after it connects). So every IP check here is
# made by a probe that took that step before its revert (jail-probe
# inetwarm:0, the probe's alone; Firecracker's preload does not take it):
# the control must then connect, or the stage fails; the jails with a
# network must not. The refusal without it, and Winsock's keys as the jail
# opens them (wsreg:0), are recorded. Needs no guest; needs an elevated
# PowerShell.
function Stage-Netns {
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $elevated 'needs an elevated PowerShell: the jailer adds Windows Filtering Platform filters for --netns'
    $base = New-Base 'netns'
    $probe = Get-Probe
    $nets = @{}
    foreach ($n in 'a', 'b') { $nets[$n] = Join-Path $base "net-$n"; New-Item -ItemType Directory -Force -Path $nets[$n] | Out-Null }
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    try {
        # Two jailed Firecrackers (no guest), each given a network of its
        # own and a network interface through the API.
        $jails = @{}
        $macs = @{ a = '06:00:AC:10:00:0A'; b = '06:00:AC:10:00:0B' }
        foreach ($n in 'a', 'b') {
            $jails[$n] = Start-ApiJail $base $n @('--netns', $nets[$n])
            Invoke-ApiOk $jails[$n].Sock 'PUT' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; host_dev_name = "tap$n"; guest_mac = $macs[$n] }) | Out-Null
        }
        $ep = @{ a = (Join-Path $nets['a'] 'a\tapa'); b = (Join-Path $nets['b'] 'b\tapb') }
        foreach ($n in 'a', 'b') {
            $other = if ($n -eq 'a') { 'b' } else { 'a' }
            Check (Test-Path $ep[$n]) "jail $n's endpoint is not in its own directory of its network ($($ep[$n]))"
            Check (-not (Test-Path (Join-Path $nets[$n] "tap$n"))) "jail $n's endpoint is in the network directory itself, which every jail given it reached"
            Check (-not (Test-Path (Join-Path $nets[$n] "$other\tap$other"))) "jail $other's endpoint is in jail $n's network"
            Check (-not (Test-Path (Join-Path $jails[$n].Root "tmp\firecracker-net\tap$n"))) "jail $n's endpoint is in the jail's temporary directory, not its network's"
        }
        # A jailed process given network a, as jail a is: it reaches no other
        # jail's endpoint there (it would be that jail's switch: every frame of
        # its guest, and frames into it), cannot delete one, and cannot make a
        # name in the network directory itself, where it could take a later
        # jail's name or directory first; it makes one in its own directory
        # (the control). No IP at all (the operator's TCP port, a UDP
        # datagram) for a probe that took Winsock's first AF_INET step before
        # its revert; a jailed process without a network that took it reaches
        # IP (the control).
        $expect = [ordered]@{
            'inetwarm:0'                                       = $true
            "connect:$($ep['a'])"                              = $false
            "delete:$($ep['a'])"                               = $false
            "bind:$(Join-Path $nets['a'] 'tapc')"              = $false
            "write:$(Join-Path $nets['a'] 'c')"                = $false
            "bind:$(Join-Path $nets['a'] 'probe\own')"         = $true
            "connect:$($ep['b'])"                              = $false
            "tcp:127.0.0.1:$port"                             = $false
            'udp:127.0.0.1:9'                                  = $false
        }
        $r = Invoke-Jailer (@('--id', 'probe', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--netns', $nets['a'], '--') + @($expect.Keys)) 30000
        $lines = $r[1] -split "`r?`n"
        $bad = @()
        foreach ($k in $expect.Keys) {
            $l = $lines | Where-Object { $_.StartsWith("$k ") } | Select-Object -First 1
            if (-not $l) { $bad += "${k}: no answer"; continue }
            if ($l.Substring($k.Length + 1).StartsWith('allowed') -ne $expect[$k]) { $bad += $l }
        }
        Check ($bad.Count -eq 0) "jailed in network a: $($bad -join '; ')"
        $ctl = Invoke-Jailer @('--id', 'control', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'inetwarm:0', "tcp:127.0.0.1:$port", 'udp:127.0.0.1:9') 30000
        $ctlLines = @(($ctl[1] -split "`r?`n") | Where-Object { $_ -match '^(inetwarm|tcp|udp):' })
        $ctlBad = @($ctlLines | Where-Object { $_ -notmatch '^\S+ allowed' })
        Check ($ctlLines.Count -eq 3 -and $ctlBad.Count -eq 0) "the control (a jail without a network, Winsock's AF_INET step taken before its revert) was denied IP or did not answer, so the test proves nothing: $(if ($ctlBad.Count) { $ctlBad -join '; ' } else { $ctl[1].Trim() })"
        # Recorded, not asserted: a jail without a network that did not take
        # that step (Firecracker's case), and Winsock's keys as it opens them.
        $cold = Invoke-Jailer @('--id', 'cold', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'wsreg:0', "tcp:127.0.0.1:$port", 'udp:127.0.0.1:9') 30000
        $coldLines = @(($cold[1] -split "`r?`n") | Where-Object { $_ -match '^(wsreg|tcp|udp):' })
        foreach ($l in $coldLines) { Write-Host "     cold: $l" }
        $opKeys = (& $probe 'wsreg:0') -join ' '
        Write-Host "     operator: $opKeys"
        Check (Test-Path $ep['a']) "jail a's endpoint went while a jailed process of its network tried it"
        # Jail c, given network a after the probe tried c's names there: its
        # endpoint is made, in its own directory.
        $jails['c'] = Start-ApiJail $base 'c' @('--netns', $nets['a'])
        Invoke-ApiOk $jails['c'].Sock 'PUT' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; host_dev_name = 'tapc'; guest_mac = '06:00:AC:10:00:0C' }) | Out-Null
        $ep['c'] = Join-Path $nets['a'] 'c\tapc'
        Check (Test-Path $ep['c']) "jail c's endpoint is not in its own directory of the network ($($ep['c']))"
        # A second jail of id a while a runs is refused (Linux: a second
        # attach of a TAP, EBUSY), and a keeps its endpoint.
        $second = Invoke-Jailer @('--id', 'a', '--exec-file', $Fc, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--netns', $nets['a']) 30000
        Check ($second[0] -ne 0) "a second jail of id a started while a ran: $($second[1])"
        Check ($null -ne (Get-Process -Id $jails['a'].Fc.Id -ErrorAction SilentlyContinue)) "jail a ended when a second jail of its id was started: $($second[1])"
        Check (Test-Path $ep['a']) "jail a's endpoint went when a second jail of its id was started: $($second[1])"
        # The operator reaches every jail's endpoint (the control for the
        # denials above).
        $op = Test-Probe @() ([ordered]@{ "connect:$($ep['a'])" = $true; "connect:$($ep['b'])" = $true; "connect:$($ep['c'])" = $true })
        Check ($op.Count -eq 0) "operator: $($op -join '; ')"
        # Without elevation (a plain process of the user: jail-probe
        # `medium`) the jailer refuses --netns, before Firecracker starts.
        Assert-Medium
        $m = Invoke-Medium @($Jailer, '--id', 'medium', '--exec-file', $Fc, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--netns', $nets['a'])
        Check ($m[0] -ne 0 -and $m[1] -match 'elevated') "a jailer that is not elevated (exit $($m[0])): $($m[1])"
        Check (-not (Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$base*medium*" })) 'a jailer that is not elevated started Firecracker'
        # Ending the jailers ends their filter sessions: IP is back for the jail's binary.
        Stop-Jailed -Done
        $after = Invoke-Jailer @('--id', 'after', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', 'inetwarm:0', "tcp:127.0.0.1:$port") 30000
        Check ($after[1] -match 'inetwarm:0 allowed' -and $after[1] -match 'tcp:\S+ allowed') "after the jailers ended, the jail's binary is still denied IP: $($after[1])"
        $coldTcp = $coldLines | Where-Object { $_.StartsWith('tcp:') } | Select-Object -First 1
        "two jails, each with a network of its own, and a jail and a probe given the first's: each endpoint in its jail's own directory of the network; the probe could not connect to, delete or take the name of another jail's endpoint, nor make a name in the network directory, and made one in its own (control); a second jail of a running id refused, the first keeping its endpoint; the operator reaches every endpoint (control); no IP (TCP, UDP) with a network and IP without (control), each probe having taken Winsock's AF_INET step before its revert; the filters end with the jailer; an unelevated jailer refuses --netns; recorded: without that step, $coldTcp; Winsock's keys, jailed: $(($coldLines | Where-Object { $_.StartsWith('wsreg:') }) -replace '^wsreg:0 record ', ''); the operator's: $($opKeys -replace '^wsreg:0 record ', '')"
    } finally {
        $listener.Stop()
        Stop-Jailed
    }
}

# Row 4 of docs/PORTING.md: the API thread's own, narrower filter. The API
# server's HTTP side is a process of its own (vmm::ext::api_process), which
# the jailer makes alongside Firecracker from the same binary on the same
# token, in the same job: it has the whole mitigation profile from the start
# (Firecracker, still building, has the setup phase's only), answers the
# API, and each one's end ends the other. Needs no guest.
function Stage-Api {
    $base = New-Base 'api'
    $probe = Get-Probe
    $all = [ordered]@{ ExtensionPoint = 1; ImageLoad = 7; Signature = 1; StrictHandle = 3; Win32k = 1; DynamicCode = 1; ChildProcess = 1 }
    $run = @('ImageLoad', 'DynamicCode')
    try {
        $jail = Start-ApiJail $base 'api'
        Check ($jail.Api.Count -eq 1) "processes of the jail's binary besides Firecracker: $($jail.Api.Count) (expected the API server's process)"
        $apiPid = $jail.Api.Id
        # The API answers, through the API process.
        $info = Invoke-ApiOk $jail.Sock 'GET' '/'
        Check ($info -match '"state":"Not started"') "instance information: $info"
        $bad = Invoke-Api $jail.Sock 'PUT' '/nothing-here' ([ordered]@{ a = 1 })
        Check ($bad -match ' 400$') "an unknown path: $bad"
        # The profile: all of it in the API process; the setup phase's only in
        # Firecracker, which has not built the microVM; none in this shell.
        $apiM = Get-Mitigations $apiPid
        $fcM = Get-Mitigations $jail.Fc.Id
        $meM = Get-Mitigations $PID
        $missing = @($all.Keys | Where-Object { ($apiM[$_] -band $all[$_]) -ne $all[$_] })
        Check ($missing.Count -eq 0) "mitigations not in force in the API process: $($missing -join ', ') ($apiM)"
        $fcSetup = @($all.Keys | Where-Object { $run -notcontains $_ -and ($fcM[$_] -band $all[$_]) -ne $all[$_] })
        Check ($fcSetup.Count -eq 0) "setup-phase mitigations not in force in Firecracker: $($fcSetup -join ', ')"
        $fcRun = @($run | Where-Object { ($fcM[$_] -band $all[$_]) -ne 0 })
        Check ($fcRun.Count -eq 0) "run-phase mitigations already in force in Firecracker, before its microVM is built (the control is lost): $($fcRun -join ', ')"
        $here = @($all.Keys | Where-Object { ($meM[$_] -band $all[$_]) -ne 0 })
        Check ($here.Count -eq 0) "mitigations in force in this shell (the control is lost): $($here -join ', ')"
        # The API process's end ends Firecracker (a panic, as the API thread's
        # end does on Linux), and the jailer returns its status.
        Stop-Process -Id $apiPid -Force
        [void]$jail.Jailer.WaitForExit(15000)
        Check ($jail.Jailer.HasExited) 'the jailer (and Firecracker) did not end within 15 s of the API process being killed'
        Check ($null -ne $jail.Jailer.ExitCode -and $jail.Jailer.ExitCode -ne 0) "the jailer returned $($jail.Jailer.ExitCode) after the API process was killed"
        # The panic hook logs (the log is stdout here) besides stderr.
        $err = (Get-Content -Raw (Join-Path $base 'api-out.txt'), (Join-Path $base 'api-err.txt') -ErrorAction SilentlyContinue) -join "`n"
        Check ($err -match 'The API server process ended') "no panic message for the API process's end: $err"
        Check ($null -eq (Get-Process -Id $jail.Fc.Id -ErrorAction SilentlyContinue)) 'Firecracker outlived the API process'
        # Firecracker's end ends the API process.
        $jail2 = Start-ApiJail $base 'api2'
        Check ($jail2.Api.Count -eq 1) "processes of the second jail's binary besides Firecracker: $($jail2.Api.Count)"
        $apiPid2 = $jail2.Api.Id
        Stop-Process -Id $jail2.Fc.Id -Force
        $t = [DateTime]::Now.AddSeconds(10)
        while ((Get-Process -Id $apiPid2 -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
        Check ($null -eq (Get-Process -Id $apiPid2 -ErrorAction SilentlyContinue)) 'the API process outlived Firecracker by 10 s'
        "the jail runs Firecracker and its API process (the whole mitigation profile; Firecracker the setup phase's only; this shell none); the API answers through it; each one's end ends the other"
    } finally { Stop-Jailed }
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
        # A guest's serial console runs through the jailer's relay pipes;
        # Firecracker itself has no console.
        $looked = Assert-NoConsole $base
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        "a 2 vCPU microVM boots in the jail (WHP under the restricted token), its $looked processes with no console host, and the jailer exits 0 with it"
    } finally { Stop-Jailed }
}

# A start that failed, tried again in the same jailed Firecracker, as
# upstream allows (PrebootApiController::start_microvm keeps the controller
# after a failed InstanceStart). The jailed Firecracker parked its partition
# before the jail's token (vmm::ext::jail::enter; kvm-ioctls whp/park.rs),
# under which none can be made once the jail's own SID is the only
# restricting SID (docs/windows-jail-reach.md, option P). A file that is not
# a kernel fails at load_kernel, after the VM, its vCPUs and its memory are
# made (vmm/src/builder.rs, build_microvm_for_boot), so the VM is dropped
# and the partition given back and checked against itself as parked; the
# second InstanceStart, with the kernel, boots on it. A partition that could
# not be given back is said on a line (`wick: whp: ...`) and makes the
# second start an error: either fails the stage. The second guest's serial
# input is not read, by upstream's code on every host (boot-test.ps1's
# `restart` says where): the warning that says so is asserted, as the cause,
# and the guest is checked without input: both vCPUs up, its init and shell
# started, its clock against the host's across 3 s idle, and SendCtrlAltDel
# ending the jailer with 0. Recorded (PARKIDLE): the
# idle Firecracker with its partition parked, and its API process, a
# process of the same binary that parks none: private bytes, working set,
# handles and threads. The run without a jail is boot-test.ps1's `restart`.
function Stage-Restart {
    $base = New-Base 'restart'
    $bad = Join-Path $base 'not-a-kernel'
    [IO.File]::WriteAllBytes($bad, [byte[]]::new(65536))
    $vm = Start-JailedVm $base 'r' @() 256 -Api -NoConfig -links @{ 'not-a-kernel' = $bad }
    try {
        $fcPid = [int](Get-Content (Join-Path $vm.Root 'firecracker.exe.pid') -Raw).Trim()
        $procs = @(Get-Process firecracker | Where-Object { $_.Path -like "$($vm.Root)*" })
        $idle = @($procs | Sort-Object { $_.Id -ne $fcPid } | ForEach-Object {
                $what = if ($_.Id -eq $fcPid) { 'Firecracker (parked)' } else { 'API process' }
                '{0}: private {1} KiB, working set {2} KiB, handles {3}, threads {4}' -f $what, ($_.PrivateMemorySize64 / 1KB), ($_.WorkingSet64 / 1KB), $_.HandleCount, $_.Threads.Count
            })
        Write-Host "PARKIDLE $($idle -join '; ')"
        $args0 = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh'
        Invoke-ApiOk $vm.Sock 'PUT' '/boot-source' ([ordered]@{ kernel_image_path = '/not-a-kernel'; boot_args = $args0 }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/drives/rootfs' ([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs'; is_root_device = $true; is_read_only = $true }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/machine-config' ([ordered]@{ vcpu_count = 2; mem_size_mib = 256 }) | Out-Null
        $out = Invoke-Api $vm.Sock 'PUT' '/actions' ([ordered]@{ action_type = 'InstanceStart' })
        Check ($out -match ' 400$' -and $out -match 'kernel') "the start with a file that is not a kernel: $out"
        $lines = @($vm.Text() -split "`n" | Where-Object { $_ -match 'wick: whp: (the partition made at|this process)' })
        Check ($lines.Count -eq 0) "the partition after the failed start: $($lines -join ' | ')"
        Invoke-ApiOk $vm.Sock 'PUT' '/boot-source' ([ordered]@{ kernel_image_path = '/vmlinux'; boot_args = $args0 }) | Out-Null
        $from = $vm.Text().Length
        Invoke-ApiOk $vm.Sock 'PUT' '/actions' ([ordered]@{ action_type = 'InstanceStart' }) | Out-Null
        $tail = { (($vm.Text() -split "`n" | Select-Object -Last 5) -join ' | ') }
        $at = { param($re) $t = $vm.Text(); $t = $t.Substring([Math]::Min($from, $t.Length)); if ($t -match $re) { $Matches[1] } else { $null } }
        $initRe = '\[\s*(\d+\.\d+)\] Run /bin/sh as init process'
        Check ($vm.WaitFor($initRe, 60)) "the second guest did not reach init: $(& $tail)"
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $init = & $at $initRe
        Check ($vm.WaitFor("can't access tty; job control turned off", 10)) "the second guest's shell did not start: $(& $tail)"
        $cpus = & $at 'smp: Brought up 1 node, (\d+) CPUs?'
        Check ($cpus -eq '2') "the guest of the second start brought up '$cpus' CPUs, not 2"
        $warned = 'Failed to register serial input fd: event_manager: file descriptor has already been registered'
        Check ($vm.Text().Contains($warned)) "the second start's serial input: no `"$warned`" in Firecracker's output, the cause of its unread input in run 44274141226; the partition is suspect again"
        Start-Sleep -Seconds 3
        $sent = $clock.Elapsed.TotalSeconds
        Invoke-ApiOk $vm.Sock 'PUT' '/actions' ([ordered]@{ action_type = 'SendCtrlAltDel' }) | Out-Null
        $restartRe = '\[\s*(\d+\.\d+)\] reboot: Restarting system'
        Check ($vm.WaitFor($restartRe, 30)) "the second guest did not restart within 30 s of SendCtrlAltDel: $(& $tail)"
        $seen = $clock.Elapsed.TotalSeconds
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $guest = [double]::Parse((& $at $restartRe), $inv) - [double]::Parse($init, $inv)
        $numbers = 'guest {0:F3} s from init to the restart, host {1:F3} s from init seen to SendCtrlAltDel, {2:F3} s to the restart seen' -f $guest, $sent, $seen
        Check ($guest -ge 0.9 * $sent -and $guest -le $seen + 2) "the second guest's clock against the host's: $numbers"
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after SendCtrlAltDel'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        "a start with a file that is not a kernel failed (400) after its VM was made; the second, with the kernel, on the partition given back in the same jailed Firecracker: 2 CPUs up, init and its shell, $numbers, SendCtrlAltDel ended the jailer with 0; its serial input not read, as upstream's code leaves it (PARKIDLE $($idle -join '; '))"
    } finally { Stop-Jailed }
}

# A file hard-linked into three jails at once, read-write: a jailed
# microVM's data drive (V) and two jailed probes (A and B, jail-probe as the
# jailed binary, which a Firecracker jail cannot run), each jail started
# while the ones before it run. Each jail's SID gets one entry of its own on
# the file, FILE_GENERIC_READ | FILE_GENERIC_WRITE (0x12019f), and the full
# access its directory passes down to the file goes before any process of
# the jail exists (`share_with_jail`): while all three run, the file holds
# exactly one such entry per jail and no inherited entry of any jail's SID;
# the guest writes through its drive before A and B start and writes and
# reads it again after; from inside A and B, writing the file is allowed and
# opening it for WRITE_DAC (changing its DACL), WRITE_OWNER (taking
# ownership) and DELETE through the operator's name of it are refused. DELETE
# through the jail's own name, in its root, is printed and not checked:
# Windows grants it through the root's FILE_DELETE_CHILD, which the jail's
# directory gives the jail, and it removes the jail's name only, as unlink in
# a chroot the jail owns. After all three end, no entry of any jail's SID is
# left and the file's own entries are as before; its inherited entries and
# its label are the last jail directory's, on every name of it (recorded in
# the stage's line, docs/windows-jail-reach.md). The label is read as SDDL,
# and the one read while the jails run is printed beside A's and B's token
# integrity levels: whether the jails' writes passed MIC at the label's level
# or the file had none.
# A file's mandatory label as SDDL (`S:...`), read with GetNamedSecurityInfoW
# (LABEL_SECURITY_INFORMATION, which needs READ_CONTROL alone), or the error.
# icacls names a label by its level's account name, and the jail's level,
# S-1-16-6144, is not a well-known one (Microsoft Learn, Well-known SIDs).
Add-Type -Namespace WickJailerTest -Name Label -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern uint GetNamedSecurityInfoW(string name, int type, uint info, System.IntPtr owner, System.IntPtr group, System.IntPtr dacl, System.IntPtr sacl, out System.IntPtr sd);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(System.IntPtr sd, uint revision, uint info, out System.IntPtr text, out uint len);
[DllImport("kernel32.dll")] public static extern System.IntPtr LocalFree(System.IntPtr p);
public static string Of(string path) {
    System.IntPtr sd;
    uint rc = GetNamedSecurityInfoW(path, 1, 0x10, System.IntPtr.Zero, System.IntPtr.Zero, System.IntPtr.Zero, System.IntPtr.Zero, out sd);
    if (rc != 0) { return "GetNamedSecurityInfoW error " + rc; }
    try {
        System.IntPtr text;
        uint len;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x10, out text, out len)) { return "ConvertSecurityDescriptorToStringSecurityDescriptorW error " + Marshal.GetLastWin32Error(); }
        try { string s = Marshal.PtrToStringUni(text); return s.Length == 0 ? "none" : s; } finally { LocalFree(text); }
    } finally { LocalFree(sd); }
}
'@
function Stage-Shared {
    $base = New-Base 'shared'
    $probe = Get-Probe
    $files = Join-Path $base 'files'
    New-Item -ItemType Directory -Force -Path $files | Out-Null
    $data = Join-Path $files 'data.img'
    $f = [IO.File]::Create($data); $f.SetLength(16MB); $f.Close()
    $own = { param($sddl) [regex]::Matches(($sddl -replace '^.*?D:[A-Z]*', ''), '\(([^)]*)\)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { ($_ -split ';')[1] -notmatch 'ID' } }
    $owner = { param($sddl) ($sddl -replace 'D:.*$', '') }
    $jailSid = 'S-1-9-\d+-\d+-\d+-\d+'
    $before = (Get-Acl $data).Sddl
    $labelBefore = [WickJailerTest.Label]::Of($data)
    # Reads `n` bytes of the file at `at` as text, beside the jails that hold it.
    $peek = { param($at, $n)
        $s = [IO.File]::Open($data, 'Open', 'Read', 'ReadWrite'); $b = New-Object byte[] $n
        [void]$s.Seek($at, 'Begin'); [void]$s.Read($b, 0, $n); $s.Close(); [Text.Encoding]::ASCII.GetString($b) }
    $jailers = @()
    $vm = $null
    try {
        $drive = [ordered]@{ drive_id = 'data'; path_on_host = '/data.img'; is_root_device = $false; is_read_only = $false }
        $vm = Start-JailedVm $base 'v' -drives @($drive) -links @{ 'data.img' = $data }
        Wait-Shell $vm
        $tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $w = $vm.Sh("echo V1-$tag | dd of=/dev/vdb conv=notrunc,fsync 2>/dev/null; echo `$?", 20)
        Check ($w -eq '0') "the guest's first write to its hard-linked drive: '$w'"
        Check ((& $peek 0 11) -eq "V1-$tag") "the guest's first write did not reach the file: '$(& $peek 0 11)'"
        # A and B: jailed probes on the same file, started one after the other.
        $results = [ordered]@{}
        $tokens = [ordered]@{}
        foreach ($id in 'a', 'b') {
            $root = Join-Path $base "jail-probe.exe\$id\root"
            New-Item -ItemType Directory -Force -Path $root | Out-Null
            New-Item -ItemType HardLink -Path (Join-Path $root 'data.img') -Target $data | Out-Null
            $out = Join-Path $WorkDir "shared-$id.txt"
            $checks = "token write:/data.img dacl:/data.img owner:/data.img `"deleteopen:$data`" deleteopen:/data.img wait:120"
            $j = Start-Process $Jailer -ArgumentList "--id $id --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- $checks" -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
            $null = $j.Handle
            $jailers += $j
            $t = [DateTime]::Now.AddSeconds(20); $lines = @()
            while ([DateTime]::Now -lt $t -and -not $j.HasExited) {
                Start-Sleep -Milliseconds 200
                $lines = @(Get-Content $out -ErrorAction SilentlyContinue)
                if ($lines | Where-Object { $_.StartsWith('deleteopen:/data.img ') }) { break }
            }
            $got = { param($c) $lines | Where-Object { $_.StartsWith("$c ") } | ForEach-Object { $_.Substring($c.Length + 1) } | Select-Object -First 1 }
            Check ($null -ne (& $got 'deleteopen:/data.img')) "jail $id's probe did not answer: $(Get-Content $out, "$out.err" -Raw -ErrorAction SilentlyContinue)"
            Check ((& $got 'write:/data.img') -eq 'allowed') "jail ${id}: writing the shared file: $(& $got 'write:/data.img')"
            foreach ($c in 'dacl:/data.img', 'owner:/data.img', "deleteopen:$data") {
                $r = & $got $c
                Check ($r -match '^denied ') "jail ${id}: $c is $r (refused expected)"
            }
            $tokens[$id] = & $got 'token'
            $results[$id] = "WRITE_DAC $(& $got 'dacl:/data.img'); WRITE_OWNER $(& $got 'owner:/data.img'); DELETE by the operator's name $(& $got "deleteopen:$data"); DELETE by the jail's own name (not checked) $(& $got 'deleteopen:/data.img')"
        }
        # All three run: one entry of its own per jail, 0x12019f, and no
        # inherited entry of any jail's SID.
        $during = (Get-Acl $data).Sddl
        $labelDuring = [WickJailerTest.Label]::Of($data)
        $mine = @(& $own $during | Where-Object { $_ -match ";;;$jailSid$" })
        $sids = @($mine | ForEach-Object { ($_ -split ';')[5] } | Sort-Object -Unique)
        Check ($mine.Count -eq 3 -and $sids.Count -eq 3) "while V, A and B run, the file holds $($mine.Count) entries of their own for $($sids.Count) jail SIDs, not one each for three: $during"
        $bad = @($mine | Where-Object { ($_ -split ';')[2] -notmatch '^(0x12019f|FRFW|FWFR)$' })
        Check ($bad.Count -eq 0) "a jail's entry is not FILE_GENERIC_READ | FILE_GENERIC_WRITE: $($bad -join ', ') in $during"
        $inherited = [regex]::Matches($during, "\(A;[A-Z]*ID[A-Z]*;[^;]*;;;$jailSid\)").Count
        Check ($inherited -eq 0) "the file holds $inherited inherited entries of a jail's SID while the jails run: $during"
        # The guest still writes and reads its drive after A's and B's starts.
        $w = $vm.Sh("echo V2-$tag | dd of=/dev/vdb bs=512 seek=8 conv=notrunc,fsync 2>/dev/null; echo `$?", 20)
        Check ($w -eq '0') "the guest's write after the other jails started: '$w'"
        Check ((& $peek 4096 11) -eq "V2-$tag") "the guest's second write did not reach the file: '$(& $peek 4096 11)'"
        $r = $vm.Sh("dd if=/dev/vdb bs=512 skip=8 count=1 iflag=direct 2>/dev/null | tr -d '\000'", 20)
        Check ($r -eq "V2-$tag") "the guest reading its drive after the other jails started: '$r'"
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        Stop-Jailers $jailers
        $jailers = @()
        $after = (Get-Acl $data).Sddl
        Check ($after -notmatch $jailSid) "an entry of a jail's SID is left on the file after the jails: $after"
        Check (((& $own $after) -join '') -eq ((& $own $before) -join '') -and (& $owner $after) -eq (& $owner $before)) "the file's own entries or owner changed: before [$before] after [$after]"
        $labelAfter = [WickJailerTest.Label]::Of($data)
        "a file hard-linked into three jails at once (a guest's read-write drive, two probes): one entry of its own per jail SID, 0x12019f, no inherited jail entry while all run; the guest wrote it before and wrote and read it after the others started; A: $($results['a']); B: $($results['b']); after: no jail SID left, own entries as before; inherited entries and label now the last jail directory's on every name: $after label $labelAfter (before: $before label $labelBefore); while all ran, the file's label $labelDuring beside the jails' tokens (A: $($tokens['a']); B: $($tokens['b']))"
    } finally {
        Stop-Jailers $jailers -Cleanup
        Stop-Jailed
    }
}

# Written, never run: no host with bindlink.dll is available (Windows 11
# build 26300 and Windows Server 2025 build 26100 have none), so neither the
# boot through the links nor the security checks below have run anywhere.
#
# Upstream's test_jailer_bind_mount_propagation on Windows: files bound into
# the jail's root before the jailer starts are what the jailed Firecracker
# opens at /vmlinux.bin and /rootfs.img, and the guest boots from them.
# Linux's `mount --bind` is a bind link here (CreateBindLink, bindlink.dll,
# from Windows 11 24H2; the API from build 25314): made by an administrator, as the mount needs
# root, and seen by every process at that path, as a mount in the host's
# namespace is (Windows has no mount namespace of the jail's own). The
# backing files are copies under the stage's directory, so what the jailer
# does to them through the links touches no guest asset. A bind link takes
# the backing file's security for the virtual path (Microsoft, Bindlink API
# overview), which the jail's directory does not give the jail's SID. The
# jailer gives each backing file one entry of the jail's SID's own,
# FILE_GENERIC_READ | FILE_GENERIC_WRITE (0x12019f), while the jail runs and
# takes it off when Firecracker ends, and nothing else: the
# stage fails if a backing file's security descriptor, the jail's entry
# aside, differs while the jail runs, if that entry is not there then, or if
# the descriptor differs at all after it (the jail directory's DACL, which
# Windows passes on to what the directory holds, must not reach the backing
# files through the links). Linux's jailer leaves a bind-mounted file's owner
# and mode alone; there the operator's mode decides, here the jail's SID is
# the jailer's own random one, which the operator cannot name beforehand.
# The drives here are read-only. A read-write drive through a bind link
# probably cannot work: the backing file keeps its own label (none: medium
# integrity), and the jail's token, below medium, cannot write up to it
# (Microsoft Learn, Mandatory Integrity Control); not measured, as nothing
# here has run.
Add-Type -Namespace WickJailerTest -Name Bind -MemberDefinition @'
[DllImport("bindlink.dll", CharSet = CharSet.Unicode)] public static extern int CreateBindLink(string virtualPath, string backingPath, uint flags, uint exceptionCount, System.IntPtr exceptionPaths);
[DllImport("bindlink.dll", CharSet = CharSet.Unicode)] public static extern int RemoveBindLink(string virtualPath);
'@
function Stage-Bindlink {
    $dll = Join-Path $env:SystemRoot 'System32\bindlink.dll'
    Check (Test-Path $dll) "this Windows (build $([Environment]::OSVersion.Version.Build)) has no bind links: no $dll (Microsoft: the Bindlink API is available from Windows 11 build 25314, and bind links from 24H2)"
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $elevated 'needs an elevated PowerShell: CreateBindLink is for administrators, as mount --bind is for root'
    $base = New-Base 'bindlink'
    $id = 'bind'
    $backing = Join-Path $base 'backing'
    New-Item -ItemType Directory -Force -Path $backing | Out-Null
    $kernel = Join-Path $backing 'vmlinux'
    $rootfs = Join-Path $backing 'rootfs'
    Copy-Item (Join-Path $Assets 'vmlinux-6.1.188') $kernel
    Copy-Item (Join-Path $Assets 'ubuntu-24.04.squashfs') $rootfs
    $root = Join-Path $base "firecracker.exe\$id\root"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    # As upstream's test: the mount points exist (touched) before the binds.
    $links = [ordered]@{ (Join-Path $root 'vmlinux.bin') = $kernel; (Join-Path $root 'rootfs.img') = $rootfs }
    $sddl = { ($links.Values | ForEach-Object { "$(Split-Path -Leaf $_): $((Get-Acl $_).Sddl)" }) -join '; ' }
    $before = & $sddl
    $made = @()
    try {
        foreach ($v in $links.Keys) {
            New-Item -ItemType File -Force -Path $v | Out-Null
            $hr = [WickJailerTest.Bind]::CreateBindLink($v, $links[$v], 0, 0, [IntPtr]::Zero)
            Check ($hr -eq 0) ("CreateBindLink({0} -> {1}): HRESULT 0x{2:x8}" -f $v, $links[$v], $hr)
            $made += $v
        }
        foreach ($v in $links.Keys) {
            Check ((Get-Item $v).Length -eq (Get-Item $links[$v]).Length) "$v does not show its backing file before the jailer starts"
        }
        $cfg = [ordered]@{
            'boot-source'    = [ordered]@{ kernel_image_path = '/vmlinux.bin'; boot_args = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh' }
            'drives'         = @([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs.img'; is_root_device = $true; is_read_only = $true })
            'machine-config' = [ordered]@{ vcpu_count = 2; mem_size_mib = 256 }
        }
        Set-Content -Encoding ASCII (Join-Path $root 'vm.json') ($cfg | ConvertTo-Json -Depth 5)
        $line = (@('--id', $id, '--exec-file', "`"$Fc`"", '--uid', '0', '--gid', '0', '--chroot-base-dir', "`"$base`"", '--', '--no-api', '--config-file', '/vm.json')) -join ' '
        $vm = [JailedVm]::new($Jailer, $line, (Join-Path $base "$id-console.txt"))
        try {
            Wait-Shell $vm
            $out = $vm.Sh('echo $((6*7)) $(nproc)', 10)
            Check ($out -eq '42 2') "guest: '$out'"
            $during = & $sddl
            $vm.Send('reboot -ff')
            Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
            Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        } finally { Stop-Jailed }
        $after = & $sddl
        # While the jail runs, each backing file holds one entry of the
        # jail's SID (S-1-9-..., the jailer's own), 0x12019f, and is
        # otherwise unchanged; after it, it is as it was (the jail's DACL,
        # passed on through the links, would grant the jail access to files
        # outside it, and for good).
        $jailAce = '\(A;;(0x12019f|FRFW|FWFR);;;S-1-9-\d+-\d+-\d+-\d+\)'
        $entries = [regex]::Matches($during, $jailAce).Count
        Check ($entries -eq $links.Count) "the guest booted, but the backing files held $entries entries of the jail's SID while it ran, not one each: $during"
        Check (($during -replace $jailAce, '') -eq $before) "the guest booted, but the jail changed the backing files' security beyond its own entry: before [$before] during [$during]"
        Check ($after -eq $before) "the jail left the backing files' security changed: before [$before] after [$after]"
        "the jailed guest booted from the kernel and root drive bound into its root before the jailer started (bind links); each backing file held one entry of the jail's SID while it ran, and its security is as before after it: $before"
    } finally {
        foreach ($v in $made) { [void][WickJailerTest.Bind]::RemoveBindLink($v) }
    }
}

# docs/PORTING.md row 10: a jailed guest's memory on large pages. A token
# below medium integrity cannot have a privilege enabled ("Lock pages in
# memory" among them), so the jail's token keeps no privilege but
# traversal, a jailed process cannot open its token to adjust it, and it
# cannot map large pages itself. The jailer, which holds the privilege,
# makes the sections (its large-page broker): a jailed guest on 2 MiB pages
# boots and uses them, and the jail's hugetlb.2MB.max bounds what the jailer
# gives, as the hugetlb controller bounds huge pages on Linux. Without the
# privilege, a jailed guest on 2 MiB pages is refused with the cause named.
function Stage-Hugepages {
    $base = New-Base 'hugepages'
    $held = $null -ne (whoami /priv | Select-String 'SeLockMemoryPrivilege')
    $privs = Invoke-JailedProbe $base 'p' '2' @() 'privileges:0'
    $got = (($privs -replace '^allowed ', '') -split ',' | Sort-Object) -join ','
    Check ($got -eq 'SeChangeNotifyPrivilege+') "the jail's token holds '$privs', not 'SeChangeNotifyPrivilege+'"
    $own = Invoke-JailedProbe $base 't' '2' @() 'tokenopen:0'
    Check ($own -match '^denied ') "a jailed process opened its own token to adjust it: $own"
    $large = Invoke-JailedProbe $base 'l' '2' @() 'largepage:64'
    Check ($large -match '^denied ') "64 MiB of large pages by a jailed process itself: $large"
    if (-not $held) {
        $vm = Start-JailedVm $base 'vm' @() 256 -hugePages '2M'
        try {
            Check ($vm.P.WaitForExit(30000)) 'the jailer did not exit after Firecracker refused large pages'
            Check ($vm.P.ExitCode -ne 0) "jailer exit $($vm.P.ExitCode) for a jailed guest on large pages"
            $text = $vm.Text()
            Check ($text -match 'below medium') "the refusal does not name the integrity level: $(($text -split "`n" | Select-Object -Last 5) -join ' | ')"
        } finally { Stop-Jailed }
        return "the jail keeps only traversal, cannot open its token or map large pages; this account lacks 'Lock pages in memory', so the jailer has none to give and a jailed guest on 2 MiB pages is refused naming the cause"
    }
    # No hugetlb.2MB.max, no broker (the limit stands for Linux's pool): a
    # jailed guest on large pages is refused, naming the limit.
    $vm = Start-JailedVm $base 'nolimit' @() 256 -hugePages '2M'
    try {
        Check ($vm.P.WaitForExit(30000)) 'the jailer did not exit for a jail on large pages without hugetlb.2MB.max'
        Check ($vm.P.ExitCode -ne 0) "jailer exit $($vm.P.ExitCode) for a jail on large pages without hugetlb.2MB.max"
        $text = $vm.Text()
        Check ($text -match 'hugetlb\.2MB\.max') "the refusal without a limit does not name hugetlb.2MB.max: $(($text -split "`n" | Select-Object -Last 4) -join ' | ')"
    } finally { Stop-Jailed }
    # The jailer's sections: the guest boots on them and uses them.
    $vm = Start-JailedVm $base 'vm' @('--cgroup-version', '2', '--cgroup', 'hugetlb.2MB.max=268435456') 256 -hugePages '2M'
    try {
        Check ($vm.WaitFor('Run /bin/sh', 30)) "a jailed guest on 2 MiB pages did not boot: $(($vm.Text() -split "`n" | Select-Object -Last 4) -join ' | ')"
        Wait-Shell $vm
        $mem = [int]$vm.Sh("awk '/MemTotal/ {print `$2}' /proc/meminfo", 10)
        Check ($mem -gt 200000 -and $mem -le 262144) "MemTotal $mem kB for 256 MiB"
        $out = $vm.Sh('mount -t tmpfs -o size=200m tmpfs /run && head -c 160m /dev/urandom > /run/f && md5sum /run/f > /run/a && md5sum /run/f | cmp - /run/a && echo same', 120)
        Check ($out -eq 'same') "160 MiB in guest memory read back differently: '$out'"
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
    } finally { Stop-Jailed }
    # hugetlb.2MB.max below the guest's memory: the jailer gives no more, and
    # Firecracker fails to start naming the limit.
    $vm = Start-JailedVm $base 'cap' @('--cgroup-version', '2', '--cgroup', 'hugetlb.2MB.max=134217728') 256 -hugePages '2M'
    try {
        Check ($vm.P.WaitForExit(30000)) 'the jailer did not exit when hugetlb.2MB.max was below the guest memory'
        Check ($vm.P.ExitCode -ne 0) "jailer exit $($vm.P.ExitCode) for a guest past hugetlb.2MB.max"
        $text = $vm.Text()
        Check ($text -match 'hugetlb\.2MB\.max') "the refusal does not name hugetlb.2MB.max: $(($text -split "`n" | Select-Object -Last 4) -join ' | ')"
    } finally { Stop-Jailed }
    "the jail keeps only traversal and cannot map large pages itself; the jailer's sections give a jailed 256 MiB guest its 2 MiB pages (160 MiB written and read back), hugetlb.2MB.max of 128 MiB refuses it naming the limit, and without hugetlb.2MB.max the jailer gives none"
}

# A guest booted under the jailer with --netns: its network endpoint is made
# in the network directory, and frames pass through it (boot-test.ps1's
# switch, its C# taken from that script: ARP, ICMP echoes, a UDP echo).
function Stage-Netguest {
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $elevated 'needs an elevated PowerShell: the jailer adds Windows Filtering Platform filters for --netns'
    if (-not ('Wick.Switch' -as [type])) {
        $source = [regex]::Match((Get-Content -Raw (Join-Path $Here 'boot-test.ps1')), "Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@", 'Singleline')
        Check $source.Success "boot-test.ps1's switch was not found next to this script"
        Add-Type -TypeDefinition $source.Groups[1].Value
    }
    $base = New-Base 'netguest'
    $net = Join-Path $base 'net'
    New-Item -ItemType Directory -Force -Path $net | Out-Null
    $vm = Start-JailedVm $base 'g' @('--netns', $net) 256 -Api -NoConfig
    try {
        Invoke-ApiOk $vm.Sock 'PUT' '/boot-source' ([ordered]@{ kernel_image_path = '/vmlinux'; boot_args = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh' }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/drives/rootfs' ([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs'; is_root_device = $true; is_read_only = $true }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/machine-config' ([ordered]@{ vcpu_count = 2; mem_size_mib = 256 }) | Out-Null
        Invoke-ApiOk $vm.Sock 'PUT' '/network-interfaces/eth0' ([ordered]@{ iface_id = 'eth0'; host_dev_name = 'tapg'; guest_mac = '06:00:0a:00:00:02' }) | Out-Null
        # The jail's endpoints are in its own directory of the network, <network>\<id>.
        $endpoint = Join-Path $net 'g\tapg'
        Check (Test-Path $endpoint) "the guest's endpoint is not in the jail's own directory of its network ($endpoint)"
        Check (-not (Test-Path (Join-Path $vm.Root 'tmp\firecracker-net\tapg'))) "the guest's endpoint is in the jail's temporary directory, not its network's"
        $switch = New-Object Wick.Switch($endpoint, 10000)
        try {
            Invoke-ApiOk $vm.Sock 'PUT' '/actions' ([ordered]@{ action_type = 'InstanceStart' }) | Out-Null
            Wait-Shell $vm
            [void]$vm.Sh('ip addr add 10.0.0.2/24 dev eth0 && ip link set eth0 up && ip link set lo up', 20)
            $out = $vm.Sh('ping -q -c 3 -i 0.3 -W 3 10.0.0.1 | grep transmitted', 30)
            Check ($out -match ' 0% packet loss') "ping: $out"
            $out = $vm.Sh('ping -q -c 50 -i 0.02 -s 1000 -W 3 10.0.0.1 | grep transmitted', 60)
            Check ($out -match ' 0% packet loss') "ping -c 50 -s 1000: $out"
            $out = $vm.Sh('echo udp-$((6*7)) | socat -t 3 - UDP:10.0.0.1:7', 30)
            Check ($out -eq 'udp-42') "UDP echo '$out'"
            $switch.Closing = $true
        } finally { $switch.Close() }
        Check ($null -eq $switch.ReadError) "switch: $($switch.ReadError) ($($switch.Counts))"
        Check ($switch.Bad.Count -eq 0) "bad frames from the guest: $(($switch.Bad | Select-Object -First 3) -join '; ')"
        Check ($switch.Arp -ge 1 -and $switch.Icmp -ge 53 -and $switch.Udp -ge 1) "switch saw $($switch.Counts)"
    } finally { Stop-Jailed }
    "a jailed guest with --netns: its endpoint in the network directory; ARP, ICMP (50 back to back), UDP echo through it, checksums valid ($($switch.Counts))"
}
# The guest using memory past the limit ends the VMM, as the cgroup OOM
# killer does (tools/macos/jailer-test.py, stage_memory): a 1024 MiB guest
# that writes 700 MiB, under a limit below that and under one above it. Guest
# memory is committed as it is touched (libc windows_mm, lazy memory), so the
# job is charged when Linux charges the cgroup.
function Stage-Memory {
    $base = New-Base 'memory'
    $results = @()
    foreach ($case in @(@{ Mib = 300; Ends = $true }, @{ Mib = 3000; Ends = $false })) {
        $id = "mem$($case.Mib)"
        $vm = Start-JailedVm $base $id @('--cgroup-version', '2', '--cgroup', "memory.max=$($case.Mib * 1MB)") 1024
        try {
            $how = ''
            if ($vm.WaitFor('Run /bin/sh', 30)) {
                Wait-Shell $vm
                $vm.Send('mount -t tmpfs -o size=900m tmpfs /run && dd if=/dev/zero of=/run/x bs=1M count=700 2>/dev/null; echo WROTE-$?')
                $wrote = $vm.WaitFor('WROTE-0', 120)
                $how = if ($wrote) { 'the guest wrote 700 MiB' } else { 'the guest did not finish writing 700 MiB' }
            } else {
                $how = 'the guest did not boot'
            }
            $ended = $vm.P.WaitForExit($(if ($case.Ends) { 30000 } else { 2000 }))
            $code = if ($ended) { $vm.P.ExitCode } else { 'running' }
            Check ($ended -eq $case.Ends) "memory.max=$($case.Mib) MiB, a 1024 MiB guest writing 700 MiB: $how; the jailer: $code; $(($vm.Text() -split "`n" | Select-Object -Last 3) -join ' | ')"
            if ($case.Ends) {
                # As on Linux: the guest boots (its memory is charged as it is touched), and
                # the VMM ends as the OOM killer ends it, with the cause named.
                Check ($how -ne 'the guest did not boot') "memory.max=$($case.Mib) MiB: the guest did not boot (its memory charged before it ran)"
                Check ($vm.P.ExitCode -eq 137) "the jailer returned $($vm.P.ExitCode) for a VMM ended by its memory limit, not 137 (128 + SIGKILL)"
                Check ($vm.Text() -match 'the memory limit') "the VMM's end does not name the memory limit"
            }
            $results += "$($case.Mib) MiB: $(if ($ended) { "ended ($how, exit $code)" } else { 'survived' })"
        } finally { Stop-Jailed }
    }
    "a 1024 MiB guest writes 700 MiB; memory.max " + ($results -join ', ')
}
function Stage-Limits {
    # Job memory limit below the guest's memory: as on Linux, the guest boots
    # (its memory is charged as it is touched) and the VMM ends, with the OOM
    # killer's exit code, once it touches more than the limit.
    $base = New-Base 'limits'
    $vm = Start-JailedVm $base 'small' @('--cgroup-version', '2', '--cgroup', 'memory.max=134217728') 256
    try {
        Check ($vm.WaitFor('Run /bin/sh', 30)) "a 256 MiB guest did not boot under memory.max=128 MiB: $(($vm.Text() -split "`n" | Select-Object -Last 3) -join ' | ')"
        Wait-Shell $vm
        # Touch most of guest memory: the job limit must stop it.
        $vm.Send('mount -t tmpfs -o size=240m tmpfs /run && head -c 230m /dev/zero > /run/z; echo FILLED-$?')
        $filled = $vm.WaitFor('FILLED-0', 60)
        $exited = $vm.P.WaitForExit(30000)
        Check $exited "a 256 MiB guest wrote 230 MiB under memory.max=128 MiB and ran on (filled: $filled)"
        Check ($vm.P.ExitCode -eq 137) "the jailer returned $($vm.P.ExitCode), not 137, for a VMM past its memory limit"
    } finally { Stop-Jailed }
    "memory.max below the guest's memory: the guest boots, and the VMM ends with 137 once it touches more than the limit"
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

# Option E-ii's isolation, a record (X2STORM lines): a guest that loops on
# the held LVT timer write, each write holding every vCPU of its VM while
# the backend sets the APIC page (SECURITY.md, option E-ii), against a
# control that loops on an exit with no hold. The x2APIC record build
# (-X2ApicFirecracker) on an AMD host, as boot-test.ps1 x2apic. Each run
# boots, jailed, A (4 vCPUs) and B (2 vCPUs, the release build) side by
# side, first with no cpu.max and then with cpu.max=100000 100000 (one CPU)
# on A, and for each of the two loops, 10 s on A's vCPU 1:
# - storm: the guest's own LVT timer value written back to MSR 0x832
#   through /dev/cpu/1/msr, one WRMSR a pwrite (Linux v6.1
#   arch/x86/kernel/msr.c msr_write: wrmsr_safe_on_cpu after filter_write).
#   Mainline allows such writes by default with a rate-limited warning
#   (`allow_writes = MSR_WRITES_DEFAULT`), but CI's guest kernel, upstream
#   Firecracker's vmlinux-6.1.188 built from Amazon Linux's tree
#   (amazonlinux/linux, microvm-kernel-6.1.188-56.393.amzn2023, as
#   lib/firecracker/resources/rebuild.sh picks it), sets
#   `allow_writes = MSR_WRITES_OFF` (its msr.c :51), so filter_write
#   refuses every write with EPERM (:95) unless the command line has
#   msr.allow_writes=on (:296 to :329): CI run 43927377548's storm died so
#   at its first write. A boots with msr.allow_writes=on on its command
#   line (this stage's guests only; B and every other stage boot without
#   it). Before the runs the stage says what A's kernel
#   has (X2STORMMSR: uname -r, the msr module's allow_writes, the lockdown
#   LSM's state or its absence, the config's lockdown and X86_MSR lines)
#   and makes one write of the value read; a write refused fails the stage
#   there, with the errno and those values;
# - control: a byte written to port 0x80 through /dev/port (an exit to the
#   VMM, no hold);
# and records: the loop's writes and the time a write; A's held writes over
# the window (X2HOLDCOUNT, whose lines past 64 come every 1000th: a count to
# the thousand); A's API, GET /machine-config every 50 ms (curl's own
# time_total, its process start not in it): median, p99, max; A's CPU (its
# Firecracker's processor time over the wall time, in CPUs); B's 1 kHz loop
# (sleep 1 ms) in iterations a second. Asserted: every request answered
# 200, both loops ran, the storm's writes were held (the count rose by the
# writes, to the thousand), and A under cpu.max used no more than its CPU
# (1.15 with the sampling's slack). Whether the storm is no worse than the
# control is read from the lines (X2STORMSUM: the median over the runs).
# On a host whose partitions the build makes xAPICs (not AMD) it is not
# applicable, exit code 3.
$StormGuest = @'
import os, sys, time
mode, cpu, secs, tag = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
os.sched_setaffinity(0, {cpu})
n = 0
t0 = time.monotonic()
end = t0 + secs
if mode == 'tick':
    while time.monotonic() < end:
        time.sleep(0.001)
        n += 1
    v = b''
else:
    if mode == 'storm':
        f = os.open('/dev/cpu/%d/msr' % cpu, os.O_RDWR)
        at = 0x832
        v = os.pread(f, 8, at)
    else:
        f = os.open('/dev/port', os.O_WRONLY)
        at = 0x80
        v = b'\0'
    while time.monotonic() < end:
        os.pwrite(f, v, at)
        n += 1
print('DONE', tag, mode, n, '%.3f' % (time.monotonic() - t0), v.hex() or '-', flush=True)
'@

# The guest command of a loop: python3 runs $StormGuest, then the shell
# says how it ended (`EXIT <tag> <status>`), so that a loop that dies (a
# traceback) ends the wait for it at once ([Wait-StormLoop]).
function Get-StormCommand([string]$mode, [int]$cpu, [int]$secs, [string]$tag) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(($StormGuest -replace "`r", '')))
    "python3 -c `"import base64,sys;exec(base64.b64decode('$b64'))`" $mode $cpu $secs $tag; echo EXIT $tag `$?"
}

# The guest's own lines of `vm`'s console from `from` (a length of its
# text) on, the last `n`, joined: the VMM's log lines (a timestamp, then
# "[<id>:fc_") left out, which in CI run 43927377548 were all a failure
# message quoted (A's API log) and hid the guest's traceback.
function Get-GuestLines($vm, [int]$from, [int]$n = 6) {
    $t = $vm.Text()
    if ($from -gt $t.Length) { $from = 0 }
    @($t.Substring($from) -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\d{4}-\d\d-\d\dT[\d:.]+ \[[^\]]*:fc_' } | Select-Object -Last $n) -join ' | '
}

# Waits up to `sec` s for loop `tag` on `vm` to end (its EXIT line, which
# comes at once when python3 dies): $null when it printed DONE and ended with
# 0, else why not, with the guest's own lines since `from`.
function Wait-StormLoop($vm, [string]$tag, [int]$from, [int]$sec) {
    if (-not $vm.WaitFor("(?m)^EXIT $tag \d+", $sec)) { return "did not end in $sec s: $(Get-GuestLines $vm $from)" }
    $t = $vm.Text()
    $code = [regex]::Match($t, "(?m)^EXIT $tag (\d+)").Groups[1].Value
    $done = $t -match "(?m)^DONE $tag "
    if ($code -ne '0' -or -not $done) { return "ended with status $code$(if (-not $done) { ', no DONE line' }): $(Get-GuestLines $vm $from)" }
    $null
}

# X2STORMMSR: what A's kernel has for an MSR write through /dev/cpu/1/msr,
# and one write of MSR 0x832's own value: the line, and whether the write
# was taken. sysfs and securityfs are mounted for it (init=/bin/sh mounts
# neither); every value is said, its absence too.
function Get-MsrWrites($vm) {
    [void]$vm.Sh('mount -t sysfs sysfs /sys 2>/dev/null; mount -t securityfs securityfs /sys/kernel/security 2>/dev/null; echo mounted', 10)
    $uname = $vm.Sh('uname -r', 10)
    $allow = $vm.Sh('cat /sys/module/msr/parameters/allow_writes 2>&1 | tr "\n" " "', 10)
    $lockdown = $vm.Sh('if test -e /sys/kernel/security/lockdown; then cat /sys/kernel/security/lockdown; else echo absent; fi 2>&1 | tr "\n" " "', 10)
    $config = $vm.Sh('zcat /proc/config.gz 2>&1 | grep -i -E "lockdown|X86_MSR" | tr "\n" " "', 20)
    $write = $vm.Sh('python3 -c "import os;f=os.open(\"/dev/cpu/1/msr\",os.O_RDWR);v=os.pread(f,8,0x832);os.pwrite(f,v,0x832);print(\"taken\",v.hex())" 2>&1 | tail -1', 20)
    $dmesg = $vm.Sh('dmesg 2>&1 | grep -i -E "msr|lockdown" | tail -3 | tr "\n" " "', 10)
    $line = "X2STORMMSR A's kernel $uname; msr allow_writes '$($allow.Trim())'; lockdown '$($lockdown.Trim())'; config '$($config.Trim())'; a write of MSR 0x832's value through /dev/cpu/1/msr: '$($write.Trim())'; dmesg '$($dmesg.Trim())'"
    [pscustomobject]@{ Line = $line; Taken = $write -match '^taken ' }
}

# The record build's count of held LVT timer writes so far in a VM's output
# (its X2HOLDCOUNT lines), 0 with none.
function Get-HeldWrites([string]$text) {
    $counts = @([regex]::Matches($text, 'whp: X2HOLDCOUNT (\d+) ') | ForEach-Object { [long]$_.Groups[1].Value })
    if ($counts.Count -eq 0) { return 0 }
    return ($counts | Measure-Object -Maximum).Maximum
}

# GET /machine-config on `sock` every 50 ms for `secs`: the latencies of the
# answered requests (curl's time_total, in ms) and the others' answers.
function Measure-ApiGets([string]$sock, [double]$secs) {
    Assert-SockPath $sock
    $lat = New-Object Collections.Generic.List[double]
    $bad = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $next = 0.0
    while ($sw.Elapsed.TotalSeconds -lt $secs) {
        $r = (& curl.exe -s -o NUL -w '%{http_code} %{time_total}' --max-time 10 --unix-socket $sock 'http://localhost/machine-config') -join ''
        $f = @($r -split ' ')
        if ($f.Count -eq 2 -and $f[0] -eq '200') { $lat.Add([double]::Parse($f[1], [Globalization.CultureInfo]::InvariantCulture) * 1000) } else { $bad += $r }
        $next += 0.05
        $wait = $next - $sw.Elapsed.TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int][math]::Ceiling($wait * 1000)) } else { $next = $sw.Elapsed.TotalSeconds }
    }
    $s = @($lat | Sort-Object)
    $q = { param($p) if ($s.Count) { $s[[math]::Max(0, [int][math]::Ceiling($p * $s.Count) - 1)] } else { [double]::NaN } }
    [pscustomobject]@{ N = $s.Count; Bad = $bad; Median = (& $q 0.5); P99 = (& $q 0.99); Max = (& $q 1.0) }
}

function Get-JailedFirecracker([string]$base, [string]$id) {
    $p = Get-Process firecracker -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$base\firecracker.exe\$id\*" } | Select-Object -First 1
    Check ($null -ne $p) "no jailed Firecracker for $id under $base"
    $null = $p.Handle
    $p
}

function Get-Median([double[]]$v) {
    $s = @($v | Sort-Object)
    if (-not $s.Count) { return [double]::NaN }
    $s[[int][math]::Floor(($s.Count - 1) / 2)]
}

function Stage-X2storm([int]$Runs = 5, [int]$Secs = 10) {
    $x2 = if ($X2ApicFirecracker) { $X2ApicFirecracker } else { Join-Path (Split-Path -Parent (Split-Path -Parent $Here)) 'lib\firecracker\build\x2apic\release\firecracker.exe' }
    Check (Test-Path $x2) "no x2APIC record build at $x2 (cargo build --release -p firecracker -p <kvm-ioctls' package id> --features kvm-ioctls/whp-x2apic-record, or pass -X2ApicFirecracker)"
    $x2 = (Resolve-Path $x2).Path
    $base = New-Base 'x2storm'
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $rows = @()
    $msrLine = ''
    for ($run = 1; $run -le $Runs; $run++) {
        foreach ($cap in @('', '100000 100000')) {
            $capName = if ($cap) { 'cpu.max one CPU' } else { 'no cpu.max' }
            $ida = "a$run$(if ($cap) { 'c' } else { 'u' })"
            $idb = "b$run$(if ($cap) { 'c' } else { 'u' })"
            $capArgs = if ($cap) { @('--cgroup-version', '2', '--cgroup', "cpu.max=$cap") } else { @() }
            try {
                $a = Start-JailedVm $base $ida $capArgs 256 -Api -vcpus 4 -exec $x2 -bootArgs 'msr.allow_writes=on'
                $b = Start-JailedVm $base $idb @() 256 -vcpus 2
                Wait-Shell $a
                Wait-Shell $b
                $build = [regex]::Match($a.Text(), 'whp: a whp-x2apic-record build[^\r\n]*').Value
                $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
                if ($build -match 'emulate an xAPIC' -and $cpu.Manufacturer -ne 'AuthenticAMD') {
                    throw [NotApplicable]::new("not applicable on this host ($($cpu.Manufacturer), $($cpu.Name.Trim())): option E makes x2APIC partitions on AMD hosts only; the build's line: '$build'")
                }
                Check ($build -match 'emulate an x2APIC') "A is not an x2APIC partition (this host is $($cpu.Manufacturer), or $x2 is not the record build): '$build'"
                $deadline = $a.Sh('grep -c "Clock Event Device: lapic-deadline" /proc/timer_list', 10)
                Check ($deadline -eq '4') "A's local timers in TSC-deadline mode (/proc/timer_list): '$deadline' of 4 vCPUs"
                $dev = $a.Sh('test -c /dev/cpu/1/msr && test -c /dev/port && echo both', 10)
                Check ($dev -eq 'both') "A has no /dev/cpu/1/msr or /dev/port: '$dev'"
                $msr = Get-MsrWrites $a
                Write-Host "     $($msr.Line)"
                if ($run -eq 1 -and -not $cap) { $msrLine = $msr.Line }
                Check $msr.Taken "${capName}: A's kernel refused a write of MSR 0x832, so the storm cannot run: $($msr.Line)"
                $fcA = Get-JailedFirecracker $base $ida
                foreach ($mode in @('control', 'storm')) {
                    $tag = "$ida$mode"
                    $held0 = Get-HeldWrites $a.Text()
                    $fromA = $a.Text().Length; $fromB = $b.Text().Length
                    $b.Send((Get-StormCommand 'tick' 0 $Secs "B$tag"))
                    $a.Send((Get-StormCommand $mode 1 $Secs "A$tag"))
                    # Inside both loops: they start once python3 has.
                    Start-Sleep -Milliseconds 1500
                    # A loop that died at its start fails the stage now.
                    foreach ($l in @(@($a, "A$tag", $fromA, 'A'), @($b, "B$tag", $fromB, 'B'))) {
                        if ($l[0].Text() -match "(?m)^EXIT $($l[1]) \d+") { Check $false "${capName}, ${mode}: $($l[3])'s loop ended at its start, $(Wait-StormLoop $l[0] $l[1] $l[2] 1)" }
                    }
                    $fcA.Refresh(); $c0 = $fcA.TotalProcessorTime; $w0 = [Diagnostics.Stopwatch]::StartNew()
                    $api = Measure-ApiGets $a.Sock ($Secs - 3)
                    $fcA.Refresh(); $used = ($fcA.TotalProcessorTime - $c0).TotalSeconds / $w0.Elapsed.TotalSeconds
                    $why = Wait-StormLoop $a "A$tag" $fromA ($Secs + 60)
                    Check ($null -eq $why) "${capName}, ${mode}: A's loop $why"
                    $why = Wait-StormLoop $b "B$tag" $fromB ($Secs + 60)
                    Check ($null -eq $why) "${capName}, ${mode}: B's loop $why"
                    $held = (Get-HeldWrites $a.Text()) - $held0
                    $da = [regex]::Match($a.Text(), "(?m)^DONE A$tag \S+ (\d+) ([\d.]+) (\S+)")
                    $db = [regex]::Match($b.Text(), "(?m)^DONE B$tag \S+ (\d+) ([\d.]+)")
                    $writes = [long]$da.Groups[1].Value
                    $took = [double]::Parse($da.Groups[2].Value, $inv)
                    $tick = [long]$db.Groups[1].Value / [double]::Parse($db.Groups[2].Value, $inv)
                    $us = if ($writes) { $took * 1e6 / $writes } else { [double]::NaN }
                    $line = "X2STORM run $run, $capName, ${mode}: $writes writes in $($da.Groups[2].Value) s ($('{0:N1}' -f $us) us a write, value $($da.Groups[3].Value)), held +$held; A's API GET median $('{0:N2}' -f $api.Median) ms, p99 $('{0:N2}' -f $api.P99), max $('{0:N2}' -f $api.Max) ($($api.N) answered, $($api.Bad.Count) not); A's CPU $('{0:N2}' -f $used); B's 1 kHz loop $('{0:N0}' -f $tick)/s"
                    Write-Host "     $line"
                    Check ($api.Bad.Count -eq 0 -and $api.N -gt 0) "${capName}, ${mode}: A's API: $($api.Bad.Count) requests not answered 200: $($api.Bad -join ' | ')"
                    Check ($writes -gt 0) "${capName}, ${mode}: A's loop wrote nothing"
                    if ($mode -eq 'storm') { Check ($held + 2000 -ge $writes -and $held -le $writes + 2000) "${capName}: $writes writes, $held held: the storm's writes were not the held write" }
                    if ($cap) { Check ($used -le 1.15) "${capName}, ${mode}: A used $('{0:N2}' -f $used) CPUs" }
                    $rows += [pscustomobject]@{ Cap = $capName; Mode = $mode; Us = $us; Median = $api.Median; P99 = $api.P99; Max = $api.Max; Cpu = $used; Tick = $tick }
                }
                $a.Send('reboot -ff'); $b.Send('reboot -ff')
                [void]$a.P.WaitForExit(15000); [void]$b.P.WaitForExit(15000)
            } finally { Stop-Jailed }
        }
    }
    $sum = foreach ($capName in @('no cpu.max', 'cpu.max one CPU')) {
        $by = { param($m, $f) Get-Median @($rows | Where-Object { $_.Cap -eq $capName -and $_.Mode -eq $m } | ForEach-Object { $_.$f }) }
        $c = [ordered]@{}; $s = [ordered]@{}
        foreach ($f in 'Us', 'Median', 'P99', 'Max', 'Cpu', 'Tick') { $c[$f] = & $by 'control' $f; $s[$f] = & $by 'storm' $f }
        $l = "X2STORMSUM $capName, medians of $Runs runs, storm against control: a write $('{0:N1}' -f $s.Us) us against $('{0:N1}' -f $c.Us); API GET median $('{0:N2}' -f $s.Median) ms against $('{0:N2}' -f $c.Median), p99 $('{0:N2}' -f $s.P99) against $('{0:N2}' -f $c.P99), max $('{0:N2}' -f $s.Max) against $('{0:N2}' -f $c.Max); A's CPU $('{0:N2}' -f $s.Cpu) against $('{0:N2}' -f $c.Cpu); B's 1 kHz loop $('{0:N0}' -f $s.Tick)/s against $('{0:N0}' -f $c.Tick)/s"
        Write-Host "     $l"
        $l
    }
    (@($msrLine) + $sum) -join '; '
}

# Row 8 of docs/PORTING.md, the freezer (overlay/jailer/platform/windows/freezer.rs):
# upstream's cgroup freezer files in <chroot-base>\<exec>\<id>\, kept by the
# jailer, which freezes and thaws the jail's Job Object. The jailed binary is
# jail-probe spinning in Firecracker's place (in the API process's place it
# has nothing to serve and ends). Every case runs and is reported, failed or
# not:
# - v1 at run time (upstream's default --cgroup-version 1): freezer.state
#   reads THAWED; FROZEN stops both processes (no CPU time), written again it
#   changes nothing, an invalid value is ignored and the file restored, a
#   value in another form (CRLF) is read back canonical, THAWED resumes it;
# - v2 at run time: cgroup.freeze and cgroup.events (populated, frozen) as on
#   Linux; Firecracker killed while frozen ends the jail, populated 0;
# - the jail cannot write its own control file;
# - the jailer killed while the jail is frozen: the jail ends with it;
# - --cgroup freezer.state=FROZEN at the start, plain, with --daemonize, with
#   --new-pid-ns and with both: the jail does not start and the operator's
#   command does not return until THAWED is written; then the jail runs (the
#   command returns as without the option) and the relaunched jailer still
#   keeps the files (frozen and thawed again);
# - at the start: THAWED runs; FREEZING, freezer.self_freezing and v2's
#   cgroup.freeze are refused as on Linux.
# Prints the Windows build: the freezer's job information class is not
# documented by Microsoft, so where it was measured matters. Needs no guest.
function Stage-Freeze {
    $base = New-Base 'freeze'
    $probe = Get-Probe
    $exe = Split-Path -Leaf $probe
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = "$($reg.CurrentMajorVersionNumber).$($reg.CurrentMinorVersionNumber).$($reg.CurrentBuildNumber).$($reg.UBR)"
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $report = @(); $fails = @()
    $dirOf = { param($id) Join-Path $base "$exe\$id" }
    # The jail's processes (jail-probe in its root).
    $procs = { param($id) @(Get-Process jail-probe -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$(& $dirOf $id)\root\*" }) }
    # Firecracker's place: the process the pid file names, once it runs.
    $fc = {
        param($id)
        $f = Join-Path (& $dirOf $id) "root\$exe.pid"
        if (-not (Test-Path $f)) { return $null }
        $n = [int](Get-Content $f -ErrorAction SilentlyContinue)
        Get-Process -Id $n -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$(& $dirOf $id)\root\*" }
    }
    $started = { param($id, [int]$ms = 10000) & $until { $null -ne (& $fc $id) } $ms }
    # CPU milliseconds Firecracker's place used over $ms.
    $cpu = {
        param($id, $ms = 1000)
        $p = & $fc $id
        if ($null -eq $p) { return -1 }
        $a = $p.TotalProcessorTime.TotalMilliseconds
        Start-Sleep -Milliseconds $ms
        $p.Refresh()
        [math]::Round($p.TotalProcessorTime.TotalMilliseconds - $a)
    }
    # Read as type and Get-Content open a file, sharing reading and writing: such a reader is never
    # refused. File.ReadAllText shares reading alone, which Windows refuses for the microseconds any
    # handle can write the file, the jailer's write-back's or the operator's own (freezer.rs; refused
    # so once on Windows 11 26300).
    $read = {
        param($id, $f)
        $p = Join-Path (& $dirOf $id) $f
        if (-not (Test-Path $p)) { return '<none>' }
        $s = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
        try { (New-Object IO.StreamReader($s)).ReadToEnd() } finally { $s.Dispose() }
    }
    $write = { param($id, $f, $v) [IO.File]::WriteAllText((Join-Path (& $dirOf $id) $f), $v) }
    $until = {
        param([scriptblock]$cond, [int]$ms = 5000)
        $t = [DateTime]::Now.AddMilliseconds($ms)
        while (-not (& $cond)) { if ([DateTime]::Now -gt $t) { return $false }; Start-Sleep -Milliseconds 50 }
        $true
    }
    $start = {
        param($id, [string[]]$extra, [string]$check = 'spin:120')
        $out = Join-Path $base "$id.txt"
        $line = "--id $id --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" $($extra -join ' ') -- $check"
        $p = Start-Process $Jailer -ArgumentList $line -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        $null = $p.Handle
        $p
    }
    $said = { param($id) (Get-Content (Join-Path $base "$id.txt"), (Join-Path $base "$id.txt.err") -Raw -ErrorAction SilentlyContinue) -join '' }
    $stop = { param($id) & $procs $id | Stop-Process -Force -ErrorAction SilentlyContinue }
    $case = {
        param([string]$name, [scriptblock]$body)
        try { $script:report += "${name}: $(& $body)" } catch { $script:fails += "${name}: $($_.Exception.Message)" }
    }
    # What a start case saw, for its failure: CI run 44287648054's said "the jail did not start
    # after THAWED:" and no more (--daemonize --new-pid-ns), the operator's jailer having written
    # nothing and the jailers it started writing to NUL (--daemonize). Their starts and ends, with
    # parent and exit status, come from a kernel trace through WMI (elevated only), which sees a
    # process that lived a millisecond; then what is alive, the pid file, the root's files and the
    # control file, each timed from THAWED. The trace also names the process each console host
    # the tree started belongs to: a console program started by one without a console (the
    # --daemonize jailer starting the --new-pid-ns keeper) gets a console of its own (Learn,
    # "Creation of a Console"). The trace's events are in the order WMI gave them; their
    # TIME_CREATED is not when the process started (run 44307674793: the operator's jailer,
    # started 1.5 s before THAWED, and the jail had the same time, after THAWED), so none is shown.
    $jname = Split-Path -Leaf $Jailer
    $traced = "wjt-freeze-$PID"
    $trace = if ($elevated) {
        try {
            foreach ($k in 'Start', 'Stop') {
                $null = Register-CimIndicationEvent -Query "SELECT * FROM Win32_Process${k}Trace WHERE ProcessName='$jname' OR ProcessName='$exe' OR ProcessName='conhost.exe'" -SourceIdentifier "${traced}-$k" -ErrorAction Stop
            }
            $null
        } catch { "not traced: $($_.Exception.Message)" }
    } else { 'not traced: not elevated' }
    $defender = try { "Defender real-time protection $(if ((Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled) { 'on' } else { 'off' })" } catch { "Defender: $($_.Exception.Message)" }
    $at = { param([DateTime]$t, [DateTime]$t0) '{0:+0.000;-0.000} s' -f ($t - $t0).TotalSeconds }
    # The traced processes of the tree from $root (the operator's jailer), in WMI's order, each
    # with its role: the operator's jailer, jailer 1 and 2 (relaunched by the one before), the
    # jail's process, or a console host of one of those.
    $tree = {
        param([int]$root)
        $role = @{ $root = "the operator's jailer" }
        $gen = @{ $root = 0 }
        $events = @(Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like "${traced}-*" } | Sort-Object EventIdentifier | ForEach-Object {
                $e = $_.SourceEventArgs.NewEvent
                [pscustomobject]@{ Start = $_.SourceIdentifier -like '*-Start'; Id = [int]$e.ProcessID; Parent = [int]$e.ParentProcessID; Name = $e.ProcessName; Status = $e.ExitStatus }
            })
        foreach ($e in $events) {
            if ($e.Start -and $role.ContainsKey($e.Parent) -and -not $role.ContainsKey($e.Id)) {
                $role[$e.Id] = if ($e.Name -eq $jname) {
                    $gen[$e.Id] = [int]$gen[$e.Parent] + 1
                    "jailer $($gen[$e.Id])"
                } elseif ($e.Name -eq $exe) { "the jail's $exe" } else { "a console host of $($role[$e.Parent])" }
            }
            if ($role.ContainsKey($e.Id)) { $e | Add-Member -NotePropertyName Role -NotePropertyValue $role[$e.Id] -PassThru }
        }
    }
    $saw = {
        param($id, $p, [DateTime]$t0)
        $now = [DateTime]::Now
        $traceSaid = if ($trace) { $trace } else {
            # WMI hands the events over late.
            Start-Sleep -Milliseconds 1500
            $seen = @(& $tree $p.Id | ForEach-Object { if ($_.Start) { "$($_.Role) $($_.Id) started" } else { "$($_.Role) $($_.Id) ended $($_.Status)" } })
            if ($seen) { "in WMI's order: $($seen -join ', ')" } else { 'none traced' }
        }
        $op = if ($p.HasExited) { "exited $($p.ExitCode) at $(& $at $p.ExitTime $t0)" } else { 'running' }
        $live = @(Get-CimInstance Win32_Process -Filter "Name='$jname' OR Name='$exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match "--id $id " -or "$($_.ExecutablePath)" -like "$(& $dirOf $id)\*" } | ForEach-Object { "$($_.Name) $($_.ProcessId) (parent $($_.ParentProcessId), started $(& $at $_.CreationDate $t0)): $($_.CommandLine)" })
        $root = Join-Path (& $dirOf $id) 'root'
        $pidFile = Join-Path $root "$exe.pid"
        $pf = if (Test-Path $pidFile) { "holds '$(Get-Content -Raw $pidFile -ErrorAction SilentlyContinue)'" } else { 'none' }
        $files = try { @(Get-ChildItem -Force $root -ErrorAction Stop | ForEach-Object { "$($_.Name)$(if (-not $_.PSIsContainer) { " $($_.Length) B" }) written $(& $at $_.LastWriteTime $t0)" }) -join ', ' } catch { $_.Exception.Message }
        "looked $(& $at $now $t0) after THAWED; the operator's jailer $($p.Id) $op, its output '$((& $said $id).Trim())'; jailers and jail-probes: $traceSaid; alive: $(if ($live) { $live -join '; ' } else { 'none' }); pid file $pf; root: $files; freezer.state '$((& $read $id 'freezer.state') -replace "`n", '\n')'; $defender"
    }
    $script:report = @(); $script:fails = @()
    try {
        & $case 'v1 at run time' {
            $p = & $start 'v1' @()
            Check (& $started 'v1') "the jail did not start: $(& $said 'v1')"
            Check ((& $read 'v1' 'freezer.state') -eq "THAWED`n") "freezer.state reads $(& $read 'v1' 'freezer.state')"
            Check (-not (Test-Path (Join-Path (& $dirOf 'v1') 'cgroup.events'))) 'a v1 jail has cgroup.events'
            $run = & $cpu 'v1'
            Check ($run -gt 200) "running: CPU $($run -join ', ') ms per s"
            # CRLF, as PowerShell's Set-Content writes, written with the stage's own writer: Set-Content opens
            # read|write, and when that open fails (another handle on the file for an instant, which one not
            # traced yet) it opens write-only and still builds a reader on it, and fails with "Stream was not
            # readable" (PowerShell's FileSystemContentStream.cs, CreateStreams; once in 30 runs on Windows 11
            # 26300, kit dd657f4).
            & $write 'v1' 'freezer.state' "FROZEN`r`n"
            Check (& $until { (& $read 'v1' 'freezer.state') -eq "FROZEN`n" }) "FROZEN`r`n not read back canonical: $(& $read 'v1' 'freezer.state')"
            Start-Sleep -Milliseconds 300
            $frozen = & $cpu 'v1'
            Check ($frozen -eq 0) "frozen: CPU $($frozen -join ', ') ms per s"
            & $write 'v1' 'freezer.state' "FROZEN`n"
            Start-Sleep -Milliseconds 300
            $again = & $cpu 'v1'
            Check ($again -eq 0) "FROZEN written again: CPU $($again -join ', ') ms per s"
            & $write 'v1' 'freezer.state' 'BOGUS'
            Check (& $until { (& $read 'v1' 'freezer.state') -eq "FROZEN`n" } 3000) "an invalid value was not restored: $(& $read 'v1' 'freezer.state')"
            $bogus = & $cpu 'v1' 500
            Check ($bogus -eq 0) "after an invalid value: CPU $($bogus -join ', ') ms per 0.5 s"
            Check (-not $p.HasExited) 'the jailer ended'
            & $write 'v1' 'freezer.state' 'THAWED'
            Start-Sleep -Milliseconds 300
            $thawed = & $cpu 'v1'
            Check ($thawed -gt 200) "thawed: CPU $($thawed -join ', ') ms per s"
            Check ((& $said 'v1') -match 'freezer.state: not a valid value') "no line about the invalid value: $(& $said 'v1')"
            & $stop 'v1'
            "running $($run -join '/') ms/s, FROZEN $($frozen -join '/'), again $($again -join '/'), invalid restored $($bogus -join '/'), THAWED $($thawed -join '/')"
        }
        & $case 'v2 at run time' {
            $p = & $start 'v2' @('--cgroup-version', '2')
            Check (& $started 'v2') "the jail did not start: $(& $said 'v2')"
            Check ((& $read 'v2' 'cgroup.freeze') -eq "0`n") "cgroup.freeze reads $(& $read 'v2' 'cgroup.freeze')"
            Check ((& $read 'v2' 'cgroup.events') -eq "populated 1`nfrozen 0`n") "cgroup.events reads $(& $read 'v2' 'cgroup.events')"
            & $write 'v2' 'cgroup.freeze' '1'
            Check (& $until { (& $read 'v2' 'cgroup.events') -eq "populated 1`nfrozen 1`n" }) "cgroup.events after 1: $(& $read 'v2' 'cgroup.events')"
            $frozen = & $cpu 'v2'
            Check ($frozen -eq 0) "frozen: CPU $($frozen -join ', ') ms per s"
            & $write 'v2' 'cgroup.freeze' '0'
            Check (& $until { (& $read 'v2' 'cgroup.events') -eq "populated 1`nfrozen 0`n" }) "cgroup.events after 0: $(& $read 'v2' 'cgroup.events')"
            $thawed = & $cpu 'v2'
            Check ($thawed -gt 200) "thawed: CPU $($thawed -join ', ') ms per s"
            & $write 'v2' 'cgroup.freeze' '1'
            Check (& $until { (& $read 'v2' 'cgroup.events') -eq "populated 1`nfrozen 1`n" }) 'not frozen again'
            (& $fc 'v2') | Stop-Process -Force
            Check ($p.WaitForExit(10000)) 'the jailer did not end after Firecracker was killed while frozen'
            Check ((& $procs 'v2').Count -eq 0) 'the API process outlived Firecracker'
            Check ((& $read 'v2' 'cgroup.events') -match "^populated 0`n") "cgroup.events after the end: $(& $read 'v2' 'cgroup.events')"
            "0/1 with cgroup.events following, frozen $($frozen -join '/') ms/s, thawed $($thawed -join '/'); Firecracker killed while frozen: the jailer exited $($p.ExitCode), $((& $read 'v2' 'cgroup.events').Trim() -replace "`n", ', ')"
        }
        & $case 'the jail writes its own control file' {
            $file = Join-Path (& $dirOf 'own') 'freezer.state'
            $p = & $start 'own' @() "write:$file"
            Check ($p.WaitForExit(20000)) 'the jailer did not end'
            $out = & $said 'own'
            Check ($out -match "write:\S+ denied") "the jail's write: $out"
            Check ((& $read 'own' 'freezer.state') -eq "THAWED`n") "the file reads $(& $read 'own' 'freezer.state')"
            ($out -split "`r?`n" | Where-Object { $_ -like 'write:*' } | Select-Object -First 1) -replace '^write:\S+ ', ''
        }
        & $case 'the jailer killed while frozen' {
            $p = & $start 'kj' @()
            Check (& $started 'kj') "the jail did not start: $(& $said 'kj')"
            & $write 'kj' 'freezer.state' 'FROZEN'
            Check (& $until { (& $read 'kj' 'freezer.state') -eq "FROZEN`n" }) 'not frozen'
            Start-Sleep -Milliseconds 300
            $p.Kill()
            Check (& $until { (& $procs 'kj').Count -eq 0 }) "the frozen jail outlived its jailer: $((& $procs 'kj').Count) processes"
            'the frozen jail ended with it'
        }
        # The start cases below find Firecracker by reading the pid file every 50 ms. The jailer once
        # wrote it twice, its own pid (upstream's write, before an exec) and then, over 100 ms later,
        # Firecracker's through a handle that shared nothing: a reader that had the file open then
        # failed the jail's start ("the pid file: ... being used by another process (os error 32)",
        # CI run 44435909393, 1 start in 9), and one that read before read the jailer's pid. Here a
        # reader opens the file the moment it exists (sharing reading, writing and deleting, as `type`
        # and Get-Content do) and holds it until Firecracker runs: every value it reads must be
        # Firecracker's pid, or empty for the moment the file is being written (as on Linux).
        & $case 'a reader holds the pid file from its first moment' {
            $f = Join-Path (& $dirOf 'rd') "root\$exe.pid"
            $t0 = [DateTime]::Now
            $p = & $start 'rd' @()
            $s = $null
            $end = $t0.AddSeconds(20)
            while ($null -eq $s -and [DateTime]::Now -lt $end -and -not $p.HasExited) {
                # Unbuffered (a buffer of 1): a FileStream's buffer would give an earlier read back.
                try { $s = [IO.FileStream]::new($f, 'Open', 'Read', 'ReadWrite, Delete', 1) } catch { }
            }
            if ($null -eq $s) { Check $false "the reader never opened the pid file: $(& $saw 'rd' $p $t0)" }
            $opened = & $at ([DateTime]::Now) $t0
            $seen = [Collections.Generic.List[string]]::new()
            try {
                $buf = New-Object byte[] 64
                $look = {
                    $s.Position = 0
                    $v = [Text.Encoding]::ASCII.GetString($buf, 0, $s.Read($buf, 0, $buf.Length))
                    if ($seen.Count -eq 0 -or $seen[$seen.Count - 1] -ne $v) { $seen.Add($v) }
                }
                & $look
                $ran = & $until { & $look; $null -ne (& $fc 'rd') } 10000
                if (-not $ran) { Check $false "the jail did not start while a reader held the pid file (it read $(@($seen | ForEach-Object { "'$_'" }) -join ', ')): $(& $saw 'rd' $p $t0)" }
                & $look
            } finally { $s.Dispose() }
            $fcPid = (& $fc 'rd').Id
            $other = @($seen | Where-Object { $_ -ne '' -and $_ -ne "$fcPid" })
            Check ($other.Count -eq 0) "the pid file named another process than Firecracker ($fcPid) while the reader held it: $(@($seen | ForEach-Object { "'$_'" }) -join ', ')"
            Check (-not $p.HasExited) "the jailer ended (exit $($p.ExitCode)): $(& $said 'rd')"
            & $stop 'rd'
            Check ($p.WaitForExit(10000)) 'the jailer did not end with its jail'
            "the reader opened it at $opened from the jailer's start and held it; the jail started, the file read $(@($seen | ForEach-Object { "'$_'" }) -join ' then ') (Firecracker $fcPid)"
        }
        $n = 0
        foreach ($flags in @(@(), @('--daemonize'), @('--new-pid-ns'), @('--daemonize', '--new-pid-ns'))) {
            $name = "FROZEN at the start$(if ($flags) { ' with ' + ($flags -join ' ') } else { '' })"
            $id = "s$n"; $n++
            & $case $name {
                $p = & $start $id (@('--cgroup', 'freezer.state=FROZEN') + $flags)
                Check (& $until { (& $read $id 'freezer.state') -eq "FROZEN`n" }) "no freezer.state: $(& $said $id)"
                Start-Sleep -Milliseconds 1500
                Check ((& $procs $id).Count -eq 0) "the jail started while frozen ($((& $procs $id).Count) processes)"
                Check (-not $p.HasExited) "the operator's jailer returned while frozen (exit $($p.ExitCode)): $(& $said $id)"
                Check (-not (Test-Path (Join-Path (& $dirOf $id) "root\$exe.pid"))) 'a pid file while frozen'
                $t0 = [DateTime]::Now
                & $write $id 'freezer.state' 'THAWED'
                # The failure's detail is looked for only on a failure: it waits for the trace.
                if (-not (& $started $id)) { Check $false "the jail did not start after THAWED: $(& $saw $id $p $t0)" }
                $run = & $cpu $id
                Check ($run -gt 200) "after THAWED: CPU $($run -join ', ') ms per s"
                $returned = if ($flags) {
                    if (-not $p.WaitForExit(10000)) { Check $false "the operator's jailer did not return with $($flags -join ' '): $(& $saw $id $p $t0)" }
                    if ($p.ExitCode -ne 0) { Check $false "the operator's jailer exited $($p.ExitCode): $(& $saw $id $p $t0)" }
                    'returned 0'
                } else {
                    Check (-not $p.HasExited) 'the jailer ended while its jail runs'
                    'waits for the jail'
                }
                # The jailer that runs the jail (relaunched, with the flags) keeps the files.
                & $write $id 'freezer.state' 'FROZEN'
                Check (& $until { (& $read $id 'freezer.state') -eq "FROZEN`n" }) 'not frozen at run time'
                Start-Sleep -Milliseconds 300
                $frozen = & $cpu $id
                Check ($frozen -eq 0) "frozen at run time: CPU $($frozen -join ', ') ms per s"
                & $write $id 'freezer.state' 'THAWED'
                Start-Sleep -Milliseconds 300
                $again = & $cpu $id
                Check ($again -gt 200) "thawed at run time: CPU $($again -join ', ') ms per s"
                & $stop $id
                # The jailers relaunched and whose each console host is (the trace).
                $when = if ($trace) { $trace } else {
                    $t = @(& $tree $p.Id | Where-Object { $_.Start })
                    $j = @($t | Where-Object { $_.Name -eq $jname }).Count - 1
                    $h = @($t | Where-Object { $_.Name -eq 'conhost.exe' } | ForEach-Object { $_.Role -replace '^a console host of ', '' })
                    "$j jailers relaunched; console hosts of: $(if ($h) { $h -join ', ' } else { 'none' })"
                }
                "held (no process, no pid file, the command not returned) until THAWED; then ran $($run -join '/') ms/s ($when), the command $returned; frozen again $($frozen -join '/'), thawed $($again -join '/')"
            }
        }
        & $case 'start values' {
            $common = @('--id', 'sv', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base)
            $r = Invoke-Jailer ($common + @('--cgroup', 'freezer.state=THAWED', '--', 'job:0')) 30000
            Check ($r[0] -eq 0 -and $r[1] -match 'job:0 allowed') "freezer.state=THAWED: exit $($r[0]): $($r[1])"
            $out = @()
            foreach ($c in @(
                    @('1', 'freezer.state=FREEZING', 'only FROZEN or THAWED'),
                    @('1', 'freezer.self_freezing=1', 'read-only'),
                    @('2', 'cgroup.freeze=1', 'Controller cgroup is unavailable'),
                    @('2', 'cgroup.freeze=0', 'Controller cgroup is unavailable'),
                    @('2', 'freezer.state=FROZEN', 'Controller freezer is unavailable'))) {
                $r = Invoke-Jailer (@('--id', "sv$($out.Count)", '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--cgroup-version', $c[0], '--cgroup', $c[1], '--', 'job:0'))
                Check ($r[0] -ne 0 -and $r[1].Contains($c[2])) "v$($c[0]) $($c[1]): exit $($r[0]): $($r[1])"
                Check ($r[1] -notmatch 'job:0') "v$($c[0]) $($c[1]): the jail ran"
                $out += "v$($c[0]) $($c[1])"
            }
            "THAWED runs; refused: $($out -join ', ')"
        }
    } finally {
        Get-Process jail-probe -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$base\*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        foreach ($k in 'Start', 'Stop') { Unregister-Event -SourceIdentifier "${traced}-$k" -ErrorAction SilentlyContinue }
        Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like "${traced}-*" } | Remove-Event -ErrorAction SilentlyContinue
    }
    foreach ($l in $script:report) { Write-Host "     $l" }
    foreach ($l in $script:fails) { Write-Host "     FAIL $l" }
    $on = "Windows $build$(if ($elevated) { ', elevated' } else { ', unelevated' }), $defender"
    Check ($script:fails.Count -eq 0) "${on}: $($script:fails.Count) of $($script:report.Count + $script:fails.Count) cases failed: $($script:fails -join ' | ')"
    "${on}: $($script:report.Count) cases: $($script:report -join ' | ')"
}

# A stage that needs a console of its own (pidns types into its console and
# reads it), in a run of several stages: run alone, by this script, in a new
# console, as CI's step runs it, with "<WorkDir>-<stage>" as its work
# directory; its line is this run's. In the console the other stages wrote
# to it is not a test of anything (the PC's run of the default list, 861d365,
# gave it the list without pidns).
function Invoke-InOwnConsole([string]$s) {
    $dir = "$WorkDir-$s"
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-WorkDir', $dir, '-Bin', $Bin, '-Assets', $Assets, '-Stage', $s)
    if ($Probe) { $argv += @('-Probe', $Probe) }
    # Start-Process joins the arguments with spaces as they are.
    $argv = @($argv | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } })
    $p = Start-Process powershell -PassThru -Wait -ArgumentList $argv
    $lines = @(Get-Content (Join-Path $dir 'summary.txt') -ErrorAction SilentlyContinue)
    $mine = @($lines | Where-Object { $_.StartsWith("PASS  ${s}: ") -or $_.StartsWith("FAIL  ${s}: ") })
    Check ($mine.Count -eq 1) "the $s run in a console of its own ($dir, exit $($p.ExitCode)) wrote no line of its own: $($lines -join ' | ')"
    $drives = @($lines | Where-Object { $_.StartsWith('FAIL  drives: ') })
    Check ($drives.Count -eq 0) "the $s run in a console of its own ($dir): $($drives -join ' ')"
    if ($mine[0].StartsWith('FAIL')) { throw [Failure]::new("$($mine[0].Substring("FAIL  ${s}: ".Length)) (in a console of its own, $dir)") }
    return "$($mine[0].Substring("PASS  ${s}: ".Length)) (in a console of its own, $dir)"
}
$OwnConsole = @('pidns')

# The harness's own helpers, on their first run without a jailer, a probe
# or a guest, so that a helper changed without a run is not first run by
# the hour-long windows-guest job (CI's windows job runs this stage):
# - Grant-JailRead with a made-up jail SID (S-1-9 and four random
#   sub-authorities, as the jailer's vm_sid makes them, which no account
#   has): the DACL it sets is read back by Grant-JailRead itself and here,
#   apart, from the file's SDDL.
# - Stop-Jailers against the race that left isolation's drive mapped: a
#   stand-in jailer (a PowerShell) that starts its jailed process (a copy of
#   ping.exe named jail-probe.exe) 1.5 s after it starts, after
#   Stop-Jailers' first look, and exits when that process ends. Stop-Jailers
#   must find the late process and the stand-in exit by itself, not be
#   killed at the 10 s.
# - With -ReachSmbShare (elevated; CI's windows job passes it), reach's
#   share probe in the runs of it that need no jailer: the share made by
#   New-ReachShare, its access and the canary's ACL checked to grant
#   Everyone, the SMB client's connections, jail-probe low, jail-probe
#   medium (the UAC-filtered token at medium integrity, asserted to be
#   that by its token:0 line) and the operator's jail-probe opening it and
#   C$ by every form (each record must end; what opens is printed, not
#   asserted), the operator's own read of
#   the canary through \\127.0.0.1 (asserted: the share is served), the
#   server's record of the window, and Remove-ReachShare. jail-probe is the
#   kit's or built with rustc (Get-Probe).
function Stage-Helpers {
    $base = New-Base 'helpers'
    $rnd = [Security.Cryptography.RandomNumberGenerator]::Create()
    $word = { $b = New-Object byte[] 4; $rnd.GetBytes($b); [BitConverter]::ToUInt32($b, 0) }
    $sid = "S-1-9-$(& $word)-$(& $word)-$(& $word)-$(& $word)"
    $f = Join-Path $base 'granted.txt'
    Set-Content $f 'granted'
    Grant-JailRead $f $sid
    $sddl = (Get-Acl $f).Sddl
    Check ($sddl.Contains('D:P') -and $sddl.Contains("(A;;FR;;;$sid)") -and $sddl -notmatch ';ID;') "Grant-JailRead's DACL read apart: $sddl"

    $stand = Join-Path $base 'jail-probe.exe'
    Copy-Item (Join-Path $env:SystemRoot 'System32\PING.EXE') $stand
    $script = "Start-Sleep -Milliseconds 1500; `$c = Start-Process -FilePath '$stand' -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden; `$c.WaitForExit(); exit 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $j = Start-Process powershell -ArgumentList '-NoProfile', '-EncodedCommand', $encoded -PassThru -WindowStyle Hidden
    $null = $j.Handle
    $standIn = "$($j.ProcessName) pid $($j.Id)"
    $before = $KilledAlive.Count
    $endedBefore = $EndedByStage.Count
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Stop-Jailers @($j) -Cleanup
    $took = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $killed = @($KilledAlive | Select-Object -Skip $before)
    Check ($j.HasExited -and $killed -notcontains $standIn) "Stop-Jailers: the stand-in jailer was killed or still runs after $took s (killed: $($killed -join ', '))"
    Check (@($killed | Where-Object { $_ -like 'jail-probe pid *' }).Count -eq 1) "Stop-Jailers: the late jailed process was not found and killed once (killed: $($killed -join ', '))"
    Check ($EndedByStage.Count -eq $endedBefore) "Stop-Jailers -Cleanup: a kill counted as the stage's own: $(@($EndedByStage | Select-Object -Skip $endedBefore) -join ', ')"
    # A process a stage ends itself, alive (a control it is done with), is
    # not one the cleanup killed: a failed stage's line does not name it
    # (macOS's jailer-test vmnet named its control so: CI run 44414358364);
    # one the cleanup kills is named.
    $mine = Start-Process (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden
    $left = Start-Process (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden
    $null = $mine.Handle; $null = $left.Handle
    $mineIs = "$($mine.ProcessName) pid $($mine.Id)"; $leftIs = "$($left.ProcessName) pid $($left.Id)"
    $before = $KilledAlive.Count; $endedBefore = $EndedByStage.Count
    Stop-Alive $mine
    Stop-Alive $left -Cleanup
    $killed = @($KilledAlive | Select-Object -Skip $before)
    $ended = @($EndedByStage | Select-Object -Skip $endedBefore)
    Check ($mine.WaitForExit(5000) -and $left.WaitForExit(5000)) 'Stop-Alive: a process still runs 5 s after its kill'
    Check (($ended -join ',') -eq $mineIs -and ($killed -join ',') -eq $leftIs) "Stop-Alive: the stage's own end ($mineIs) and the cleanup's kill ($leftIs) read as ended '$($ended -join ',')', killed '$($killed -join ',')'"
    Check ((Add-Killed 'FAIL  x: why' $killed) -eq "FAIL  x: why; killed by the harness while alive: $leftIs" -and (Add-Killed 'FAIL  x: why' @()) -eq 'FAIL  x: why') "Add-Killed: '$(Add-Killed 'FAIL  x: why' $killed)'"
    $msg = "Grant-JailRead gave $sid read alone ($sddl); Stop-Jailers found the jailed process started after its first look and the stand-in jailer exited by itself, in $took s; a process the stage ends itself is not named as killed by the harness, one the cleanup kills is"

    # reach's SMB share probe, the runs of it that need no jailer.
    if (-not $ReachSmbShare) { return "$msg; reach's share probe not run: not asked (-ReachSmbShare)" }
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Check $elevated 'helpers -ReachSmbShare needs an elevated PowerShell (New-SmbShare is for administrators)'
    $probe = Get-Probe
    $dir = Join-Path $base 'share'
    $name = New-ReachShareName
    $stageErr = $null
    $cleanup = $null
    try {
        $record = @(New-ReachShare $name $dir)
        # The share grants read (to Everyone, named in the system's
        # language), and the canary's DACL allows Everyone (WD) something.
        Check ($record[1] -match ' Allow Read(;|$)' -and $record[2] -match '\(A;;[^;]+;;;WD\)') "the share's access or the canary's ACL: $($record[1..2] -join ' | ')"
        $record += Get-SmbConns 'before the low-integrity run'
        $t0 = Get-Date
        $low = @(& $probe low @(Get-SmbChecks $name @()) | Where-Object { $_ } | ForEach-Object { "low: $_" })
        $record += $low
        $record += Get-SmbConns 'after the low-integrity run, before the medium-integrity run'
        # jail-probe medium: this elevated token filtered as UAC filters an
        # administrator's (CreateRestrictedToken with LUA_TOKEN and
        # DISABLE_MAX_PRIVILEGE: the administrators for deny only, no
        # privilege but SeChangeNotify) at medium integrity, not restricted;
        # its token:0 line must say so. Made from this token, it keeps this
        # logon session, where UAC's filtered token has a logon session of
        # its own, so its opens go on the sessions the low-integrity run
        # left and are granted as those sessions' user is: it tells whether
        # the low run's 0xc0000201 is a rule of integrity below medium or
        # not, not what a separate medium user is granted.
        $m = Invoke-Medium (@($probe, 'token:0') + @(Get-SmbChecks $name @())) 120000
        $medium = @(@($m[1] -split "`r?`n" | Where-Object { $_ }) | ForEach-Object { "medium: $_" })
        $record += $medium
        $record += Get-SmbConns "after the medium-integrity run, before the operator's"
        $op = @(& $probe @(Get-SmbChecks $name @()) | Where-Object { $_ } | ForEach-Object { "operator: $_" })
        $read = try { "$(Get-Content -LiteralPath "\\127.0.0.1\$name\canary.txt" -ErrorAction Stop)" } catch { "refused: $($_.Exception.Message)" }
        $server = @(Get-SmbServerRecord 'the low- and medium-integrity runs and the operator' $t0 (Get-Date))
        $record += $op + $server
        $record += Get-SmbConns 'after the operator'
        foreach ($l in $record) { Write-Host "     $l" }
        Check ($read -eq $SmbCanary) "the operator's read of \\127.0.0.1\$name\canary.txt: $read"
        Check ($server.Count -eq $SmbChannels.Count + 2) "Get-SmbServerRecord gave $($server.Count) lines, not $($SmbChannels.Count + 2): $($server -join ' | ')"
        $sumLow = Get-SmbAll $low 'low: ' 'the low-integrity run' $name
        $token = $medium | Where-Object { $_.StartsWith('medium: token:0 ') } | Select-Object -First 1
        Check ($token -match 'token:0 allowed integrity 8192 administrators no privileges 1') "jail-probe medium is not the UAC-filtered token at medium integrity: $token (exit $($m[0]))"
        $sumMedium = Get-SmbAll $medium 'medium: ' 'the medium-integrity run' $name
        $sumOp = Get-SmbAll $op 'operator: ' 'the operator' $name
    } catch {
        $stageErr = $_
    } finally {
        $cleanup = Remove-ReachShare $name $dir
    }
    Complete-Stage $stageErr $cleanup
    "$msg; reach's share probe without a jailer, nothing asserted of what opens: $name made and removed, its access and the canary's ACL as reach makes them, the operator read the canary through \\127.0.0.1; jail-probe low $sumLow; jail-probe medium (the UAC-filtered token, on the low run's sessions) $sumMedium; the operator $sumOp"
}

# --- run ----------------------------------------------------------------------

Stop-Jailed
# -File passes "a,b" as one string.
$Stage = @($Stage | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($s in $Stage) {
    Write-Host "== $s"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $killedBefore = $KilledAlive.Count
    $passed = $false
    try {
        $msg = if ($Stage.Count -gt 1 -and $OwnConsole -contains $s) { Invoke-InOwnConsole $s } else { & "Stage-$((Get-Culture).TextInfo.ToTitleCase($s))" }
        $Results[$s] = "PASS  ${s}: $msg"
        $passed = $true
    } catch {
        $Results[$s] = if ($_.Exception -is [NotApplicable]) { "N/A   ${s}: $($_.Exception.Message)" } else { "FAIL  ${s}: $($_.Exception.Message)" }
    } finally {
        # What the stage left running ends with it, whether it passed or not
        # (before, only after a failure, so what a passing stage left ran on
        # into the next), as boot-test.ps1's stages and macOS's jailer-test.
        Stop-Jailed
    }
    if ($passed) {
        # A passing stage's jails (guest image copies) go; a failing one's stay to look at.
        $dir = Join-Path $WorkDir $s
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    } else {
        # The processes the harness's cleanup killed while they ran in this
        # stage (not those the stage ended itself): their output ends where
        # the kill came.
        $Results[$s] = Add-Killed $Results[$s] @($KilledAlive | Select-Object -Skip $killedBefore)
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
$na = @($Results.Values | Where-Object { $_.StartsWith('N/A') }).Count
$summary = @($Results.Values) + @('', "$($Results.Count - $failed - $na) passed, $failed failed$(if ($na) { ", $na not applicable" })")
$summary | Set-Content -Encoding UTF8 (Join-Path $WorkDir 'summary.txt')
''
$summary
if ($failed) { exit 1 }
if ($na) { exit 3 }
exit 0
