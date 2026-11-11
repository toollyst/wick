# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs upstream's integration tests (pytest, tests/integration_tests) against
# the Windows build, as tools/macos/integration-tests.sh runs them against the
# macOS one (docs/PORTING.md row 12). Upstream's framework is unchanged; the
# host side it needs on Windows is tools/windows/integration/wick_windows.py,
# a pytest plugin loaded before upstream's conftest.py.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\integration-tests.ps1 [-Out DIR] [-Pytest "PYTEST ARGS"]
#
# Without test arguments, upstream's functional and security suites. Needs the
# release build (lib\firecracker\build\cargo_target\release), the Python
# environment (tools\windows\integration\venv.ps1), the guest artifacts
# (tools\windows\integration\setup-artifacts.ps1) and Git for Windows's bash.
# Runs as the user; --netns tests need an elevated shell (the jailer's
# Windows Filtering Platform filters).
#
# OUT (default build\integration-tests\<time>) gets the pytest JSON report
# (test-report.json), pytest's output (pytest.log) and upstream's
# test_results directory; summary.txt ends "N passed, M failed".
# (The pytest arguments are one string: PowerShell would take "-x" or "-k" for its own.)
param([string]$Out = '', [string]$Pytest = '')
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Fc = Join-Path $Root 'lib\firecracker'
$PytestArgs = @($Pytest -split '\s+' | Where-Object { $_ })
if ($PytestArgs.Count -eq 0) { $PytestArgs = @('integration_tests/functional', 'integration_tests/security') }
if (-not $Out) { $Out = Join-Path $Root ("build\integration-tests\" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$py = Join-Path $Root 'build\integration\venv-windows\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "no Python environment: tools\windows\integration\venv.ps1" }
if (-not (Test-Path (Join-Path $Fc 'build\current_artifacts'))) { throw "no guest artifacts: tools\windows\integration\setup-artifacts.ps1" }

# The binaries, as upstream's tests name them.
$release = Join-Path $Fc 'build\cargo_target\release'
$bin = Join-Path $Out 'bin'
New-Item -ItemType Directory -Force -Path (Join-Path $bin 'examples') | Out-Null
foreach ($b in 'firecracker', 'jailer', 'snapshot-editor', 'rebase-snap', 'cpu-template-helper', 'seccompiler-bin') {
    $exe = Join-Path $release "$b.exe"
    # Both names: the framework checks for the Linux name and runs it (CreateProcess takes a binary without the extension).
    if (Test-Path $exe) { Copy-Item $exe (Join-Path $bin "$b.exe"); Copy-Item $exe (Join-Path $bin $b) }
}
Get-ChildItem (Join-Path $release 'examples') -Filter '*.exe' -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -notmatch '-' } | ForEach-Object { Copy-Item $_.FullName (Join-Path $bin "examples\$($_.Name)") }
if (-not (Test-Path (Join-Path $bin 'firecracker.exe'))) { throw "no release build in $release" }
# The vhost-user-blk backend upstream's tests start is crosvm's, which has no
# Windows build: tools/vhost-user-blk takes crosvm's command lines when named
# crosvm.
$vub = Join-Path $Fc 'build\vhost-user-blk\release\vhost-user-blk.exe'
if (Test-Path $vub) { Copy-Item $vub (Join-Path $bin 'crosvm.exe') }
else { Write-Warning "no $vub (tools/vhost-user-blk): the vhost-user tests fail" }
$env:PATH = "$bin;$env:PATH"

# The session root (upstream: /srv): short, as AF_UNIX paths are limited to
# 108 bytes and the jail's sockets sit several levels below it.
$session = Join-Path $env:SystemDrive ("wit-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Force -Path (Join-Path $session 'tmp') | Out-Null
$env:PYTHONPATH = Join-Path $Root 'tools\windows\integration'
$env:WICK_IT_ROOT = $session
# Text files and pipes in UTF-8, as on Linux (Windows's default is the code page).
$env:PYTHONUTF8 = '1'
$env:TMP = Join-Path $session 'tmp'
$env:TEMP = $env:TMP
Remove-Item -Recurse -Force (Join-Path $Fc 'test_results') -ErrorAction SilentlyContinue
Push-Location (Join-Path $Fc 'tests')
try {
    & $py -m pytest -p wick_windows --binary-dir $bin @PytestArgs 2>&1 | Tee-Object -FilePath (Join-Path $Out 'pytest.log')
    $status = $LASTEXITCODE
} finally {
    Pop-Location
    # Everything the session started runs from its bin directory or its root.
    Get-Process | Where-Object { $_.Path -and ($_.Path.StartsWith($bin) -or $_.Path.StartsWith($session)) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $session -ErrorAction SilentlyContinue
}
"$status" | Set-Content (Join-Path $Out 'status')
$results = Join-Path $Fc 'test_results'
if (Test-Path $results) { Copy-Item -Recurse -Force $results (Join-Path $Out 'test_results') }
$report = Join-Path $results 'test-report.json'
if (Test-Path $report) {
    Copy-Item $report (Join-Path $Out 'test-report.json')
    $s = (Get-Content -Raw $report | ConvertFrom-Json).summary
    "$([int]$s.passed) passed, $([int]$s.failed + [int]$s.error) failed, $([int]$s.skipped) skipped" | Set-Content (Join-Path $Out 'summary.txt')
    Get-Content (Join-Path $Out 'summary.txt')
}
Write-Host "pytest exited with $status; results in $Out"
exit $status
