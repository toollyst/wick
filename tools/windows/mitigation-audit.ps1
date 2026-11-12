# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The measure-then-enforce loop of the Windows sandbox (docs/PORTING.md, "The
# system call filter"), the counterpart of tools/macos/sandbox-discovery.sh.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\mitigation-audit.ps1 `
#       [-Release] [-Stage boot,net,...] [-WorkDir <dir>]
#
# Builds Firecracker with --cfg wick_sandbox_discovery in a target directory
# of its own (lib\firecracker\build\sandbox-discovery; never installed or
# released). That build sets the audit variant of each mitigation Windows
# reports audits for at run time (dynamic code, child processes, win32k), so
# an operation the mitigation would deny is allowed and reported in the
# Security-Mitigations event log; the others are enforced as in the product,
# and their denials are reported too. A clean run reports nothing.
#
# Without -Stage it runs an API session that needs no WHP: configure a
# microVM, ask to start it (which fails without WHP), query it, and checks
# that Firecracker answered and kept running. With -Stage it runs those
# stages of tools\windows\boot-test.ps1 with the discovery build (needs WHP).
# A control (a PowerShell child with the dynamic code audit on that allocates
# executable memory) must be reported, or a clean run would show nothing.
# Writes summary.txt in -WorkDir; kills every process it started on any exit.

param(
    [string]$WorkDir = (Join-Path $env:LOCALAPPDATA 'wick-mitigation-audit'),
    [string[]]$Stage = @(),
    [switch]$Release
)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent (Split-Path -Parent $Here)
$Stage = @($Stage | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Logs = @('Microsoft-Windows-Security-Mitigations/KernelMode', 'Microsoft-Windows-Security-Mitigations/UserMode')

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Results = [ordered]@{}
$Started = @()
function Stop-Started {
    foreach ($p in $script:Started) { if (-not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(5000) } }
}

$since = Get-Date
$control = $null
try {
    # The discovery build.
    $target = Join-Path $Root 'lib\firecracker\build\sandbox-discovery'
    $profile = if ($Release) { 'release' } else { 'debug' }
    $env:CARGO_TARGET_DIR = $target
    $env:RUSTFLAGS = '--cfg wick_sandbox_discovery'
    Push-Location (Join-Path $Root 'lib\firecracker')
    $cargo = @('build', '--locked', '-p', 'firecracker') + $(if ($Release) { @('--release') } else { @() })
    cmd /c "cargo $($cargo -join ' ') > `"$(Join-Path $WorkDir 'build.txt')`" 2>&1"
    $built = $LASTEXITCODE -eq 0
    Pop-Location
    Remove-Item Env:\RUSTFLAGS, Env:\CARGO_TARGET_DIR
    if (-not $built) { throw "the discovery build failed (build.txt)" }
    $Fc = Join-Path $target "$profile\firecracker.exe"

    # The control.
    $script = @'
$ErrorActionPreference = 'Stop'
# x86_64: SIZE_T is 64 bits.
Add-Type -Name M -Namespace W -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern bool SetProcessMitigationPolicy(int p, ref uint f, ulong n);
[DllImport("kernel32.dll")] public static extern System.IntPtr VirtualAlloc(System.IntPtr a, ulong n, uint t, uint p);
"@
$f = [uint32]8
if (-not [W.M]::SetProcessMitigationPolicy(2, [ref]$f, 4)) { exit 2 }
# MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE: allowed and reported.
if ([W.M]::VirtualAlloc([IntPtr]::Zero, 4096, 0x3000, 0x40) -eq [IntPtr]::Zero) { exit 3 }
'@
    $controlFile = Join-Path $WorkDir 'control.ps1'
    Set-Content -Encoding ASCII $controlFile $script
    $control = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$controlFile`"" -PassThru -WindowStyle Hidden
    # Windows PowerShell 5.1 keeps no exit code for a Start-Process process
    # unless its handle was taken while it ran.
    $null = $control.Handle
    $script:Started += $control
    [void]$control.WaitForExit(60000)
    if (-not $control.HasExited -or $control.ExitCode -ne 0) { throw "the control did not run (exit $($control.ExitCode))" }

    if ($Stage.Count -gt 0) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Here 'boot-test.ps1') `
            -Firecracker $Fc -WorkDir (Join-Path $WorkDir 'boot-test') -Stage ($Stage -join ',')
        $Results['boot-test'] = if ($LASTEXITCODE -eq 0) { "PASS  boot-test: $($Stage -join ',') with the discovery build" } else { "FAIL  boot-test: exit $LASTEXITCODE (boot-test\summary.txt)" }
    } else {
        $sock = Join-Path $WorkDir 'api.sock'
        $kernel = Join-Path $WorkDir 'vmlinux'
        Set-Content -Encoding ASCII $kernel 'not a kernel'
        $p = Start-Process $Fc -ArgumentList "--api-sock `"$sock`"" -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $WorkDir 'stdout.txt') -RedirectStandardError (Join-Path $WorkDir 'stderr.txt')
        $null = $p.Handle
        $script:Started += $p
        $t = [DateTime]::Now.AddSeconds(10)
        while (-not (Test-Path $sock) -and [DateTime]::Now -lt $t -and -not $p.HasExited) { Start-Sleep -Milliseconds 50 }
        $calls = @(
            @('GET', '/', ''),
            @('PUT', '/machine-config', '{"vcpu_count":1,"mem_size_mib":128}'),
            @('PUT', '/boot-source', ('{"kernel_image_path":"' + ($kernel -replace '\\', '\\') + '"}')),
            @('PUT', '/actions', '{"action_type":"InstanceStart"}'),
            @('GET', '/machine-config', '')
        )
        $bad = @()
        $n = 0
        $answers = foreach ($c in $calls) {
            $a = @('-s', '-o', '-', '-w', ' %{http_code}', '--unix-socket', $sock, '-X', $c[0], "http://localhost$($c[1])")
            if ($c[2]) {
                # Windows PowerShell drops the quotes of a JSON argument: the body goes in a file.
                $body = Join-Path $WorkDir "body-$n.json"; $n++
                [IO.File]::WriteAllText($body, $c[2])
                $a += @('-H', 'Content-Type: application/json', '--data-binary', "@$body")
            }
            $r = "$($c[0]) $($c[1]) -> $(& curl.exe @a)"
            # Without WHP the start fails (400); everything else succeeds.
            if ($c[1] -ne '/actions' -and $r -notmatch ' 20\d$') { $bad += $r }
            $r
        }
        $answers | Out-File (Join-Path $WorkDir 'api.txt')
        $alive = -not $p.HasExited
        Stop-Started
        $Results['api'] = if (-not $alive) { "FAIL  api: Firecracker exited ($($p.ExitCode)): $(Get-Content -Raw (Join-Path $WorkDir 'stderr.txt'))" }
            elseif ($bad) { "FAIL  api: $($bad -join '; ')" }
            else { "PASS  api: Firecracker answered $($calls.Count) API calls and kept running" }
    }
} finally {
    Stop-Started
}
# The event log writes with a delay.
Start-Sleep -Seconds 3
$all = @(Get-WinEvent -FilterHashtable @{ LogName = $Logs; StartTime = $since } -ErrorAction SilentlyContinue)
$all | ForEach-Object { "$($_.TimeCreated.ToString('o')) $($_.LogName) $($_.Id): $($_.Message)" } |
    Out-File (Join-Path $WorkDir 'events.txt')
$controlEvents = @($all | Where-Object { $control -and $_.Message -match "\(PID $($control.Id)\)" })
$Results['control'] = if ($controlEvents.Count -gt 0) { "PASS  control: the audit reported the control ($($controlEvents.Count) events)" } else { 'FAIL  control: the audit reported nothing for the control, so it cannot show a clean run' }
$events = @($all | Where-Object { $_.Message -match 'sandbox-discovery' })
$Results['audit'] = if ($events.Count -eq 0) { 'PASS  audit: no operation of Firecracker a mitigation would deny' } else {
    "FAIL  audit: $($events.Count) operations a mitigation would deny (events.txt): $(($events | Select-Object -First 3 | ForEach-Object { ($_.Message -split "`n")[0] }) -join ' | ')" }

$failed = @($Results.Values | Where-Object { $_.StartsWith('FAIL') }).Count
$summary = @($Results.Values) + @('', "$($Results.Count - $failed) passed, $failed failed")
$summary | Set-Content -Encoding UTF8 (Join-Path $WorkDir 'summary.txt')
$summary
exit [int]($failed -ne 0)
