# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs upstream's integration tests (pytest, tests/integration_tests) against
# the Windows build, as tools/macos/integration-tests.sh runs them against the
# macOS one (docs/PORTING.md row 12). Upstream's framework is unchanged
# (patches/0027's conftest.py change acts on macOS only; test_api_version
# accepts the +wick.N version, patches/0015); the
# host side it needs on Windows is tools/windows/integration/wick_windows.py,
# a pytest plugin loaded before upstream's conftest.py.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\integration-tests.ps1 [-Out DIR] [-Pytest "PYTEST ARGS"]
#
# Without test arguments, upstream's functional and security suites. Needs the
# release build (lib\firecracker\build\cargo_target\release), the Python
# environment (tools\windows\integration\venv.ps1), the guest artifacts
# (tools\windows\integration\setup-artifacts.ps1), Git for Windows's bash,
# rustup's Rust and Visual Studio's C++ build tools (for the tests that build
# Firecracker themselves; checked at the start). Run it elevated: upstream's
# suite runs as root on Linux, and every jailed microVM's --netns needs an
# elevated jailer (its Windows Filtering Platform filters).
#
# OUT (default build\integration-tests\<time>) gets the pytest JSON report
# (test-report.json), pytest's output (pytest.log), upstream's test_results
# directory and the comparison with Linux's results (comparison.md); the
# script fails on a difference not in tools\windows\integration-test-differences.txt.
# (The pytest arguments are one string: PowerShell would take "-x" or "-k" for its own.)
# -Keep leaves the session root (jails, screen logs: the jailer's output) in
# place for a look after the run.
param([string]$Out = '', [string]$Pytest = '', [switch]$Keep)
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

# What the tests that build Firecracker themselves (test_fuzzing_warning,
# test_gdb_connects, test_instrumented_firecracker) need, checked here rather
# than deep in a test. Their cargo runs through Git's bash (wick_windows.py),
# whose PATH puts its own /usr/bin first. A WHP PC run (2026-11-13) needed:
# - rustup's cargo before any other: a Chocolatey cargo 1.92 failed with
#   "can't find crate for core";
# - MSVC's link.exe named for cargo: in Git's bash `link` is coreutils';
# - vswhere's directory on PATH, for vcvars64 (aws-lc-sys's build).
$bash = if ($env:WICK_IT_BASH) { $env:WICK_IT_BASH } else { 'C:\Program Files\Git\bin\bash.exe' }
if (-not (Test-Path $bash)) { throw "no Git for Windows bash at $bash (or set WICK_IT_BASH)" }
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$rustupCargo = Join-Path $cargoHome 'bin\cargo.exe'
if (-not (Test-Path $rustupCargo)) { throw "no rustup cargo at ${rustupCargo}: install Rust with rustup (https://rustup.rs)" }
$psCargo = (Get-Command cargo -ErrorAction SilentlyContinue).Source
if ($psCargo -ine $rustupCargo) { throw "the first cargo on PATH is '$psCargo', not rustup's ${rustupCargo}: put $(Split-Path $rustupCargo) first in PATH" }
# (No double quote in the command: Windows PowerShell 5.1 passes them to a
# native program unescaped.)
$bashCargo = (& $bash -c 'command -v cargo | cygpath -w -f -' 2>$null | Select-Object -First 1)
if ($bashCargo -ine $rustupCargo) { throw "in Git's bash the first cargo is '$bashCargo', not rustup's ${rustupCargo}: put $(Split-Path $rustupCargo) first in PATH" }
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
$vswhere = Join-Path $vsInstaller 'vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "no ${vswhere}: install Visual Studio Build Tools with the C++ workload" }
$env:PATH = "$vsInstaller;$env:PATH"
if (-not $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER) {
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw "vswhere finds no Visual Studio with the C++ x64 tools (Microsoft.VisualStudio.Component.VC.Tools.x86.x64)" }
    $msvc = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = Join-Path $msvc.FullName 'bin\Hostx64\x64\link.exe'
}
$link = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
if (-not (Test-Path $link) -or (Split-Path -Leaf $link) -ine 'link.exe' -or $link -match '\\Git\\usr\\bin\\') {
    throw "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER is '$link', not MSVC's link.exe"
}
# Upstream's suite runs as root (tools/devtool test: a --privileged container),
# which the jailer's chroot, cgroups and network namespaces need. Here the
# same: a jailed microVM's --netns adds Windows Filtering Platform filters,
# which need an elevated jailer.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Warning "not elevated: every jailed microVM's --netns is refused (upstream's suite runs as root on Linux)" }

# The binaries, as upstream's tests name them.
$release = Join-Path $Fc 'build\cargo_target\release'
$bin = Join-Path $Out 'bin'
New-Item -ItemType Directory -Force -Path (Join-Path $bin 'examples') | Out-Null
foreach ($b in 'firecracker', 'jailer', 'snapshot-editor', 'rebase-snap', 'cpu-template-helper', 'seccompiler-bin', 'clippy-tracing') {
    $exe = Join-Path $release "$b.exe"
    # Both names: the framework checks for the Linux name and runs it (CreateProcess takes a binary without the extension).
    if (Test-Path $exe) { Copy-Item $exe (Join-Path $bin "$b.exe"); Copy-Item $exe (Join-Path $bin $b) }
}
Get-ChildItem (Join-Path $release 'examples') -Filter '*.exe' -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -notmatch '-' } | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $bin "examples\$($_.Name)")
        Copy-Item $_.FullName (Join-Path $bin "examples\$($_.BaseName)")
    }
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
$env:WICK_IT_BIN = $bin
# Text files and pipes in UTF-8, as on Linux (Windows's default is the code page).
$env:PYTHONUTF8 = '1'
$env:TMP = Join-Path $session 'tmp'
$env:TEMP = $env:TMP
# Upstream's tests write to lib\firecracker (test_results, a build of the
# instrumented binary that rewrites the sources with clippy-tracing): one run
# at a time, and what a test leaves in the sources is put back after it.
$lock = Join-Path $Fc 'build\integration-tests.lock'
New-Item -ItemType Directory -Force -Path (Split-Path $lock) | Out-Null
try { $lockFile = [IO.File]::Open($lock, 'OpenOrCreate', 'ReadWrite', 'None') }
catch { throw "another integration test run is going on ($lock)" }
$sourcesBefore = @(git -C $Fc diff --name-only)
Remove-Item -Recurse -Force (Join-Path $Fc 'test_results') -ErrorAction SilentlyContinue
Push-Location (Join-Path $Fc 'tests')
try {
    # A module that imports what Windows lacks (seccomp) is one error, not the
    # end of the session. The log in UTF-8 (Tee-Object writes UTF-16).
    $log = New-Object IO.StreamWriter((Join-Path $Out 'pytest.log'), $false, (New-Object Text.UTF8Encoding $false))
    try {
        # pytest's standard error is output, not an error to stop on (Windows
        # PowerShell makes each line of a native command's stderr one).
        $ErrorActionPreference = 'Continue'
        & $py -m pytest -p wick_windows --continue-on-collection-errors --binary-dir $bin @PytestArgs 2>&1 |
            ForEach-Object { $line = "$_"; $log.WriteLine($line); $log.Flush(); $line }
        $status = $LASTEXITCODE
    } finally { $log.Close(); $ErrorActionPreference = 'Stop' }
} finally {
    Pop-Location
    # Everything the session started runs from its bin directory or its root.
    Get-Process | Where-Object { $_.Path -and ($_.Path.StartsWith($bin) -or $_.Path.StartsWith($session)) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    if ($Keep) { Write-Host "session root kept: $session" }
    else { Remove-Item -Recurse -Force $session -ErrorAction SilentlyContinue }
    $touched = @(git -C $Fc diff --name-only | Where-Object { $sourcesBefore -notcontains $_ })
    if ($touched.Count) {
        Write-Warning "the tests changed $($touched.Count) upstream source files; put back: $($touched -join ', ')"
        git -C $Fc checkout -- @touched
    }
    $lockFile.Close()
}
"$status" | Set-Content (Join-Path $Out 'status')
$results = Join-Path $Fc 'test_results'
if (Test-Path $results) { Copy-Item -Recurse -Force $results (Join-Path $Out 'test_results') }
$report = Join-Path $results 'test-report.json'
if (Test-Path $report) { Copy-Item $report (Join-Path $Out 'test-report.json') }
# Against Linux's results (tools/windows/compare-integration-tests.py):
# comparison.md, and summary.txt's "N passed, M failed" counts the tests that
# agree with Linux and the differences not listed with a reason.
$full = if ($Pytest) { @() } else { @('--full') }
& $py -I (Join-Path $Root 'tools\windows\compare-integration-tests.py') $Out @full `
    --summary (Join-Path $Out 'comparison.md') --summary-txt (Join-Path $Out 'summary.txt') | Out-Null
$compared = $LASTEXITCODE
if (Test-Path (Join-Path $Out 'summary.txt')) { Get-Content (Join-Path $Out 'summary.txt') }
Write-Host "pytest exited with $status; comparison with Linux: $(if ($compared -eq 0) { 'no unlisted difference' } else { 'differences, see comparison.md' }); results in $Out"
exit $compared
