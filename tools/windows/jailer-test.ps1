# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Windows jailer on WHP hardware: what it refuses, what a jailed process
# can reach (tools/windows/jail-probe.rs, run through the jailer as the
# jailed binary), a jailed microVM booting, and the Job Object limits.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 `
#       -WorkDir C:\wjt [-Stage refuse,freeze,cpuset,parent,weight,low,links,nofile,sections,daemonize,handles,pidns,handoff,netns,netguest,api,isolation,boot,bindlink,limits,memory,cpu,hugepages,uffd,vhost-user] [-Bin <dir>]
#
# `refuse`, `freeze`, `cpuset`, `parent`, `weight`, `low`, `links`, `nofile`, `sections`, `daemonize`, `handles`, `pidns`, `handoff`, `netns`
# and `api` need no WHP; the others boot a guest. `pidns` needs a console (it types into it
# and reads it); `netns` needs an elevated PowerShell (the jailer adds Windows Filtering
# Platform filters). `hugepages` needs the account to hold "Lock pages in memory" (it
# fails, saying so, without it). `bindlink` needs an elevated PowerShell and Windows 11
# 24H2 or later (bindlink.dll; it fails, saying so, without it).
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
    [string[]]$Stage = @('refuse', 'freeze', 'cpuset', 'parent', 'weight', 'low', 'links', 'nofile', 'sections', 'daemonize', 'handles', 'pidns', 'handoff', 'netns', 'netguest', 'api', 'isolation', 'boot', 'bindlink', 'limits', 'memory', 'cpu', 'hugepages', 'uffd', 'vhost-user'),
    [string]$Bin = '',
    [string]$Assets = 'C:\wbt',
    [string]$Probe = ''
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

# Firecracker first: its jailer then exits as after a guest shutdown and
# removes the jail's drive.
function Stop-Jailed {
    Get-Process firecracker, jail-probe -ErrorAction SilentlyContinue | Stop-Process -Force
    $t = [DateTime]::Now.AddSeconds(5)
    while ((Get-Process jailer -ErrorAction SilentlyContinue) -and [DateTime]::Now -lt $t) { Start-Sleep -Milliseconds 100 }
    Get-Process jailer -ErrorAction SilentlyContinue | Stop-Process -Force
}

# Ends the jailers a stage started and still runs: their jailed processes
# first, after which each jailer exits by itself and removes its jail's drive
# (`unmap_at_exit`); one still running after 10 s is killed, and the drive
# it leaves is reported by the end's `drives` check. Killing a jailer first
# left its drive mapped for the logon session (run 43428124115's parent
# stage: Y: and Z:).
function Stop-Jailers([object[]]$jailers) {
    Get-Process firecracker, jail-probe -ErrorAction SilentlyContinue | Stop-Process -Force
    foreach ($j in $jailers) {
        if ($j -and -not $j.WaitForExit(10000)) { $j.Kill() }
    }
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
    if (-not $p.WaitForExit($ms)) { Stop-Jailers @($p); throw [Failure]::new("jailer did not exit: $line") }
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
# configured (the API configures it); `drives` are added to the root drive.
function Start-JailedVm([string]$base, [string]$id, [string[]]$jailerArgs = @(), [int]$memMib = 256, [switch]$Api, [switch]$NoConfig, [object[]]$drives = @(), [string]$hugePages = '') {
    $root = Join-Path $base "firecracker.exe\$id\root"
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Copy-Item (Join-Path $Assets 'vmlinux-6.1.188') (Join-Path $root 'vmlinux')
    Copy-Item (Join-Path $Assets 'ubuntu-24.04.squashfs') (Join-Path $root 'rootfs')
    $cfg = [ordered]@{
        'boot-source'    = [ordered]@{ kernel_image_path = '/vmlinux'; boot_args = 'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh' }
        'drives'         = @([ordered]@{ drive_id = 'rootfs'; path_on_host = '/rootfs'; is_root_device = $true; is_read_only = $true }) + $drives
        'machine-config' = [ordered]@{ vcpu_count = 2; mem_size_mib = $memMib }
    }
    if ($hugePages) { $cfg['machine-config']['huge_pages'] = $hugePages }
    Set-Content -Encoding ASCII (Join-Path $root 'vm.json') ($cfg | ConvertTo-Json -Depth 5)
    $fcArgs = @('--')
    if (-not $Api) { $fcArgs += '--no-api' }
    if (-not $NoConfig) { $fcArgs += @('--config-file', '/vm.json') }
    $line = (@('--id', $id, '--exec-file', "`"$Fc`"", '--uid', '0', '--gid', '0', '--chroot-base-dir', "`"$base`"") + ($jailerArgs | ForEach-Object { if ($_ -match ' ') { "`"$_`"" } else { $_ } }) + $fcArgs) -join ' '
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

# docs/PORTING.md row 8: --parent-cgroup. A parent made with jail-parent,
# 256 MiB and processor 0, and jails under it, each allowed 1 GiB of its own:
# - the first commits 200 MiB and runs on processor 0 though it asked for 0
#   and 1 (cgroup v2: the processors it has in common with its parent);
# - the second, while the first holds its memory, is stopped short of 200
#   MiB: the parent's limit bounds the two together;
# - cgroup v1 refuses a jail that asks for processor 1 (not in its parent's);
# - with the tool ended and the first jail still running, a jail that names
#   the parent with cgroup v2 and no --cgroup joins it and is bounded by it:
#   a jailer keeps the parent of its jail;
# - a level under the parent (`<parent>/inner`, 100 MiB, made with the tool
#   while the parent's is running): a jail under it is stopped short of 150
#   MiB, the least limit along the path, and runs on the parent's processor;
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
    $psi = New-Object Diagnostics.ProcessStartInfo((Get-ParentTool), "--name $name --cgroup memory.max=268435456 --cgroup cpuset.cpus=0")
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

        # A level under the parent, before any jail takes the parent's memory.
        $r = Invoke-ParentTool "--name $name/bad --cgroup-version 1 --cgroup cpuset.cpus=1"
        Check ($r[0] -eq 1 -and $r[1].Contains("CPUs outside the parent cgroup's")) "cgroup v1: a level on processor 1 under a parent on processor 0 was not refused by the tool: exit $($r[0]): $($r[1])"
        $r = Invoke-ParentTool "--name $name --cgroup cpuset.cpus=0-1"
        Check ($r[0] -eq 0 -and $r[1] -match "${name}: opened" -and $r[1] -match "${name}: 0 jobs below it") "the tool did not write the processors of the parent that was there: exit $($r[0]): $($r[1])"
        $r = Invoke-Jailer (@('--id', 'wide') + $jail + @('--cgroup-version', '2', '--cgroup', 'cpuset.cpus=0-1', '--', 'affinity:0')) 60000
        Check ($r[1] -match 'affinity:0 allowed 0x3 of ') "a jail that asked for processors 0-1 under the parent written to 0-1: exit $($r[0]): $($r[1])"
        $r = Invoke-ParentTool "--name $name --cgroup cpuset.cpus=0"
        Check ($r[0] -eq 0 -and $r[1] -match "${name}: opened") "the tool did not write the parent's processors back: exit $($r[0]): $($r[1])"
        $psi2 = New-Object Diagnostics.ProcessStartInfo((Get-ParentTool), "--name $name/inner --cgroup memory.max=104857600")
        $psi2.UseShellExecute = $false; $psi2.RedirectStandardInput = $true; $psi2.RedirectStandardOutput = $true; $psi2.CreateNoWindow = $true
        $inner = [Diagnostics.Process]::Start($psi2)
        $said = ''
        while ($null -ne ($line = $inner.StandardOutput.ReadLine())) { $said += "$line; "; if ($line -match 'held until') { break } }
        Check ($said -match "${name}: opened" -and $said -match "${name}/inner: made" -and $said -match 'held until') "jail-parent did not open the parent and make the level under it: $said"
        $r = Invoke-Jailer (@('--id', 'level', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--parent-cgroup', "$name/inner", '--cgroup-version', '2') + $own + @('--', 'private:150', 'affinity:0')) 60000
        Check ($r[1] -match 'private:150 denied after (\d+)' -and [int]$Matches[1] -le 100) "a jail under a level of 100 MiB under the parent of 256: exit $($r[0]): $($r[1])"
        $level = [int]$Matches[1]
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
        Check ($text -match 'private:200 allowed 200') "the first jail's 200 MiB under a parent of 256: $text"
        Check ($text -match 'affinity:0 allowed 0x1 of ') "the first jail asked for processors 0-1 under a parent on processor 0 (cgroup v2: processor 0): $text"

        $r = Invoke-Jailer (@('--id', 'second') + $jail + @('--cgroup-version', '2') + $own + @('--', 'private:200')) 60000
        Check ($r[1] -match 'private:200 denied after (\d+)' -and [int]$Matches[1] -le 60) "the second jail under the parent of 256 MiB, 200 held by the first: exit $($r[0]): $($r[1])"
        $second = [int]$Matches[1]

        $r = Invoke-Jailer (@('--id', 'v1') + $jail + @('--cgroup-version', '1', '--cgroup', 'cpuset.cpus=1', '--', 'affinity:0'))
        Check ($r[0] -ne 0 -and $r[1].Contains("CPUs outside the parent cgroup's")) "cgroup v1, processor 1 under a parent on processor 0, was not refused: exit $($r[0]): $($r[1])"
        Check ($r[1] -notmatch 'affinity:0 allowed') "cgroup v1, processor 1 under a parent on processor 0: the jail ran: $($r[1])"

        $holder.StandardInput.Close()
        Check ($holder.WaitForExit(10000)) 'jail-parent did not end with its standard input'
        Check (-not $first.HasExited) "the first jail ended before the tool: $text"
        $r = Invoke-Jailer (@('--id', 'joins') + $jail + @('--cgroup-version', '2', '--', 'private:200')) 60000
        Check ($r[1] -match 'private:200 denied after (\d+)' -and [int]$Matches[1] -le 60) "with the tool ended and a jail left, a jail that joins the parent (v2, no --cgroup): exit $($r[0]): $($r[1])"
        $joined = [int]$Matches[1]

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
        "a parent of 256 MiB on processor 0 (jail-parent): a jail under a level of 100 MiB under it stopped after $level MiB, on processor 0; the tool refused a cgroup v1 level on processor 1 and a change of the parent's processors; the first jail took 200 MiB and ran on processor 0 of the 0-1 it asked for; the second stopped after $second MiB; cgroup v1 refused processor 1; with the tool ended, a jail joining the parent stopped after $joined MiB; a jailed process and the parents' namespace: $reach; a job of a parent's name in the session's namespace: $made, and a jail given that parent started"
    } finally {
        Stop-Jailers @($first, $squat)
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
        Stop-Jailers @($runs | ForEach-Object { $_.P })
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
        $procs = @(Get-Process firecracker | Where-Object { $_.Path -like "$root*" })
        Check ($procs.Count -eq 2) "processes of the jail's binary: $($procs.Count) (expected Firecracker and its API process)"
        $fcp = $procs | Where-Object { (Get-Mitigations $_.Id).DynamicCode -eq 0 } | Select-Object -First 1
        Check ($null -ne $fcp) 'no detached Firecracker (both processes of the binary carry the API profile)'
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
# The process mitigations of pid $id, by name, through jail-probe.
function Get-Mitigations([int]$id) {
    $line = & (Get-Probe) "mitigations:$id"
    Check ($line -match '^mitigations:\d+ allowed') "reading pid $id's mitigations: $line"
    $m = @{}
    foreach ($kv in ($line -split ' ' | Where-Object { $_ -match '=' })) { $k, $v = $kv -split '='; $m[$k] = [Convert]::ToInt32($v, 16) }
    $m
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

# `Invoke-Api` that fails unless the status is 2xx; returns the body.
function Invoke-ApiOk([string]$sock, [string]$method, [string]$path, $body = $null) {
    $r = Invoke-Api $sock $method $path $body
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
    $probe = Get-Probe
    $base = New-Base 'links'
    $readable = Join-Path $WorkDir "links-readable-$PID.txt"
    try {
        $other = Start-ApiJail $base 'other'
        $otherFile = Join-Path $other.Root 'kernel.bin'
        Set-Content $otherFile "another jail's file"
        Set-Content $readable "the operator's file"
        # Readable as C:\Windows\win.ini is: Users, Everyone, application packages.
        icacls $readable /grant '*S-1-5-32-545:R' '*S-1-1-0:R' '*S-1-15-2-1:R' | Out-Null
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
        $r = Invoke-Jailer (@('--id', 'probe', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--') + @($expect.Keys)) 30000
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

# memory.max bounds all of the jailed process's memory, as a cgroup does: under
# 32 MiB, private memory (the control), pagefile-backed sections and sections of
# temporary files (wick's memfd) are each refused well before 256 MiB.
# FAILS today: a Job Object charges private commit only (docs/COMPATIBILITY.md,
# memory.max), and this stage says how much the sections took.
function Stage-Sections {
    $probe = Get-Probe
    $base = New-Base 'sections'
    $common = @('--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--cgroup-version', '2', '--cgroup', 'memory.max=33554432')
    $r = Invoke-Jailer (@('--id', 'private') + $common + @('--', 'private:256')) 120000
    Check ($r[1] -match 'private:256 denied after (\d+)' -and [int]$Matches[1] -le 32) "the control, private memory under memory.max=32 MiB: exit $($r[0]): $($r[1])"
    $control = [int]$Matches[1]
    $escaped = @()
    foreach ($kind in 'sections', 'filesections') {
        $r = Invoke-Jailer (@('--id', $kind) + $common + @('--', "${kind}:256")) 120000
        if ($r[1] -match "${kind}:256 denied after (\d+)" -and [int]$Matches[1] -le 32) { continue }
        $escaped += "${kind}: $(($r[1] -split "`n" | Where-Object { $_ -match "^${kind}:" }) -join ' ') (exit $($r[0]))"
    }
    Check ($escaped.Count -eq 0) "memory.max=32 MiB holds private memory (denied after $control MiB) but not: $($escaped -join '; ')"
    "under memory.max=32 MiB private memory stops after $control MiB, and so do pagefile-backed and temporary-file sections"
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
        $fcp = Get-Process firecracker | Where-Object { $_.Path -like "$root*" -and (Get-Mitigations $_.Id).DynamicCode -eq 0 } | Select-Object -First 1
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
        "the control reaches every process ($($ctl.Count) checks); jailed, nothing ($($checks.Count) checks and a console control event: the user's process survives); the console's mode stays with API-only jails and is raw only once the jailed process asks, typed keys reach it through the relay as bytes, none reach an API-only jail, and the mode is back after ($($timeline -join '; ')); --new-pid-ns: the jailer returned 0 in $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s with Firecracker running (pid file), refused a jail it could not build; a pid's existence still shows ($oracle)"
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
    $file = Join-Path $WorkDir "handoff-secret-$PID.txt"
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
        $j = Start-Process $Jailer -ArgumentList "--id h --exec-file `"$probe`" --uid 0 --gid 0 --chroot-base-dir `"$base`" -- sockpull:$sock hold:${file}:20 signal:$PID" -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError "$out.err"
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
        [void]$j.WaitForExit(30000)
        $sig = Get-Content $out | Where-Object { $_.StartsWith("signal:$PID ") } | Select-Object -First 1
        Check ($sig -and $sig -notmatch ' allowed') "the jailed process can open the operator: $sig"
        "a socket and a file handle held by the jailed process were pulled out by the operator$medium; the jailed process cannot open the operator ($sig)"
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
        Stop-Jailed
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
# is not elevated refuses the flag. Needs no guest; needs an elevated
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
        # datagram); a jailed process without a network reaches IP (the
        # control).
        $expect = [ordered]@{
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
        $ctl = Invoke-Jailer @('--id', 'control', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', "tcp:127.0.0.1:$port", 'udp:127.0.0.1:9') 30000
        $ctlBad = @(($ctl[1] -split "`r?`n") | Where-Object { $_ -match '^(tcp|udp):' -and $_ -notmatch ' allowed' })
        Check ($ctlBad.Count -eq 0) "the control (a jail without a network) was denied IP, so the test proves nothing: $($ctlBad -join '; ')"
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
        Stop-Jailed
        $after = Invoke-Jailer @('--id', 'after', '--exec-file', $probe, '--uid', '0', '--gid', '0', '--chroot-base-dir', $base, '--', "tcp:127.0.0.1:$port") 30000
        Check ($after[1] -match 'tcp:.* allowed') "after the jailers ended, the jail's binary is still denied IP: $($after[1])"
        "two jails, each with a network of its own, and a jail and a probe given the first's: each endpoint in its jail's own directory of the network; the probe could not connect to, delete or take the name of another jail's endpoint, nor make a name in the network directory, and made one in its own (control); a second jail of a running id refused, the first keeping its endpoint; the operator reaches every endpoint (control); no IP (TCP, UDP) with a network and IP without (control); the filters end with the jailer; an unelevated jailer refuses --netns"
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
        $vm.Send('reboot -ff')
        Check ($vm.P.WaitForExit(15000)) 'the jailer did not exit after the guest rebooted'
        Check ($vm.P.ExitCode -eq 0) "jailer exit $($vm.P.ExitCode)"
        "a 2 vCPU microVM boots in the jail (WHP under the restricted token) and the jailer exits 0 with it"
    } finally { Stop-Jailed }
}

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
# overview), and the jailer sets the jail directory's DACL, which Windows
# passes on to what the directory holds: the stage fails if a backing file's
# security descriptor differs while the jail runs or after it, as Linux's
# jailer leaves a bind-mounted file's owner and mode alone.
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
        # As on Linux, where the jailer leaves a bind-mounted file's owner and
        # mode alone, the jail's setup must not change what the backing files
        # allow (the jail's DACL, passed on through the links, would grant the
        # jail access to files outside it).
        Check ($during -eq $before -and $after -eq $before) "the guest booted, but the jail changed the backing files' security: before [$before] during [$during] after [$after]"
        "the jailed guest booted from the kernel and root drive bound into its root before the jailer started (bind links); the backing files' security unchanged: $before"
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
                & $write $id 'freezer.state' 'THAWED'
                Check (& $started $id) "the jail did not start after THAWED: $(& $said $id)"
                $run = & $cpu $id
                Check ($run -gt 200) "after THAWED: CPU $($run -join ', ') ms per s"
                $returned = if ($flags) {
                    Check ($p.WaitForExit(10000)) "the operator's jailer did not return with $($flags -join ' ')"
                    Check ($p.ExitCode -eq 0) "the operator's jailer exited $($p.ExitCode): $(& $said $id)"
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
                "held (no process, no pid file, the command not returned) until THAWED; then ran $($run -join '/') ms/s, the command $returned; frozen again $($frozen -join '/'), thawed $($again -join '/')"
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
    }
    foreach ($l in $script:report) { Write-Host "     $l" }
    foreach ($l in $script:fails) { Write-Host "     FAIL $l" }
    Check ($script:fails.Count -eq 0) "Windows $build$(if ($elevated) { ', elevated' } else { ', unelevated' }): $($script:fails.Count) of $($script:report.Count + $script:fails.Count) cases failed: $($script:fails -join ' | ')"
    "Windows $build$(if ($elevated) { ', elevated' } else { ', unelevated' }): $($script:report.Count) cases: $($script:report -join ' | ')"
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
        # A passing stage's jails (guest image copies) go; a failing one's stay to look at.
        $dir = Join-Path $WorkDir $s
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
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
