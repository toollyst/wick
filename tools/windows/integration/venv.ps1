# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Python environment upstream's tests run in on Windows
# (build\integration\venv-windows): the packages the framework and the
# functional and security tests import, at the versions of upstream's
# development container (lib\firecracker\tools\devctr\poetry.lock), as
# tools/macos/integration/venv.sh makes them on macOS. Prints the
# environment's directory.
#
#   powershell -ExecutionPolicy Bypass -File tools\windows\integration\venv.ps1
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$Packages = @('pytest', 'pytest-json-report', 'pytest-timeout', 'pytest-xdist', 'pytest-rerunfailures',
    'pytest-repeat', 'tenacity', 'psutil', 'requests', 'requests-unixsocket2', 'filelock', 'semver', 'setproctitle',
    'pyyaml', 'openapi-spec-validator', 'aws-embedded-metrics', 'numpy', 'scipy', 'pandas', 'ipython', 'packaging')
$lock = Join-Path $Root 'lib\firecracker\tools\devctr\poetry.lock'
$pins = python -I (Join-Path $PSScriptRoot 'pins.py') $lock @Packages
if ($LASTEXITCODE -ne 0) { throw "reading $lock failed" }
$venv = Join-Path $Root 'build\integration\venv-windows'
if (-not (Test-Path (Join-Path $venv 'Scripts\python.exe'))) {
    python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "python -m venv $venv failed" }
}
& (Join-Path $venv 'Scripts\python.exe') -m pip install -q --disable-pip-version-check @($pins -split "`r?`n" | Where-Object { $_ })
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
$venv
