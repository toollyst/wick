#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Cargo runner for macOS: signs the binary with the Hypervisor.framework
# entitlement, then runs it. Used by tools/macos/test.sh through
# CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER.
set -euo pipefail
bin="$1"; shift
codesign --force --sign - --entitlements "$(dirname "$0")/hypervisor.entitlements" "$bin" 2>/dev/null
exec "$bin" "$@"
