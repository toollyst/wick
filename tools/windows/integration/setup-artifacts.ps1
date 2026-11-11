# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Upstream's x86_64 CI guest artifacts for its integration tests on Windows,
# prepared as upstream's tools/setup-ci-artifacts.sh prepares them: an SSH
# key, each squashfs root file system again with the key in it, and an ext4
# image made from it. The images are made by that script itself, run as root
# in WSL on a Linux file system there (a Linux root file system has names
# that differ only in case, and modes and owners NTFS does not keep); the
# results are copied back. Records the directory in
# lib\firecracker\build\current_artifacts, where the framework looks.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\integration\setup-artifacts.ps1 [-Distro Ubuntu-24.04]
#
# Needs WSL with squashfs-tools and e2fsprogs.
param([string]$Distro = 'Ubuntu-24.04')
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
# The artifact set of upstream's CI that tools/macos/integration-tests.sh uses (its aarch64 twin).
$S3 = 'https://s3.amazonaws.com/spec.ccfc.min'
$Prefix = 'firecracker-ci/20261105-6ea6634994fa-0'
$Artifacts = @(
    'vmlinux-6.1.188', 'vmlinux-6.1.188.config',
    'amazonlinux-2023.squashfs', 'amazonlinux-2023.manifest',
    'ubuntu-24.04.squashfs', 'ubuntu-24.04.manifest',
    'debug/vmlinux-6.1.188', 'debug/vmlinux-6.1.188.config', 'debug/vmlinux-6.1.188.debug.gz'
)
$art = Join-Path $env:LOCALAPPDATA "wick\integration\$($Prefix -replace '/', '\')\x86_64"
New-Item -ItemType Directory -Force -Path (Join-Path $art 'debug') | Out-Null
foreach ($name in $Artifacts) {
    $dest = Join-Path $art ($name -replace '/', '\')
    $done = (Test-Path $dest) -or (Test-Path "$dest.orig") -or (Test-Path ($dest -replace '\.gz$', ''))
    if ($done -and (Get-Item ($(if (Test-Path $dest) { $dest } elseif (Test-Path "$dest.orig") { "$dest.orig" } else { $dest -replace '\.gz$', '' }))).Length -gt 0) { continue }
    Write-Host "downloading $name"
    curl.exe -fsSL --retry 3 -o "$dest.part" "$S3/$Prefix/x86_64/$name"
    if ($LASTEXITCODE -ne 0) { throw "downloading $name failed" }
    Move-Item -Force "$dest.part" $dest
}
# The images: upstream's script, as root, on WSL's own file system.
$squashfs = @(Get-ChildItem $art -Filter '*.squashfs' | Where-Object { -not (Test-Path "$($_.FullName).orig") -or -not (Test-Path ($_.FullName -replace '\.squashfs$', '.ext4')) })
$needDebug = Test-Path (Join-Path $art 'debug\vmlinux-6.1.188.debug.gz')
if ($squashfs.Count -gt 0 -or $needDebug) {
    $winArt = (wsl.exe -d $Distro -- wslpath -a ($art -replace '\\', '/')).Trim()
    $script = (wsl.exe -d $Distro -- wslpath -a ((Join-Path $Root 'lib\firecracker\tools\setup-ci-artifacts.sh') -replace '\\', '/')).Trim()
    $cmd = @"
set -euo pipefail
work=/root/wick-artifacts
rm -rf "`$work" && mkdir -p "`$work/debug"
cp -a '$winArt'/. "`$work"/
# Upstream's script wants its helper next to it.
tr -d '\r' < '$script' > "`$work/setup-ci-artifacts.sh"
printf 'say() { echo "== `$*"; }\n' > "`$work/functions"
cd "`$work"
bash ./setup-ci-artifacts.sh "`$work"
rm -f "`$work/wick-setup.sh"; cp -a "`$work"/. '$winArt'/
rm -f '$winArt'/setup-ci-artifacts.sh '$winArt'/functions; find '$winArt' -name '*.debug.gz' -delete
rm -rf "`$work"
"@
    # As a file without a byte order mark or CRs (a pipe from Windows
    # PowerShell would start with one).
    $sh = Join-Path $art 'wick-setup.sh'
    [IO.File]::WriteAllText($sh, ($cmd -replace "`r", ''), (New-Object Text.UTF8Encoding($false)))
    wsl.exe -d $Distro -u root -- bash "$winArt/wick-setup.sh"
    $code = $LASTEXITCODE
    Remove-Item -Force $sh -ErrorAction SilentlyContinue
    $LASTEXITCODE = $code
    if ($LASTEXITCODE -ne 0) { throw 'preparing the images in WSL failed' }
}
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'lib\firecracker\build') | Out-Null
[IO.File]::WriteAllText((Join-Path $Root 'lib\firecracker\build\current_artifacts'), $art)
Get-ChildItem $art -Recurse -File | Select-Object @{n = 'file'; e = { $_.FullName.Substring($art.Length + 1) } }, Length | Format-Table -AutoSize | Out-String -Width 160
