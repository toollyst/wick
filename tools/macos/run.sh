#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Build Firecracker for macOS, sign it with the Hypervisor.framework
# entitlement and run it with the given arguments.
#
#   tools/macos/run.sh [--release] -- <firecracker arguments>
#   tools/macos/run.sh --build-only [--release]
#
# Run tools/setup.sh first.
#
# Requirements: Apple silicon, macOS 15 or later (hv_gic_*).
# The signature is ad hoc, which is enough to run locally.
# Unix socket paths (--api-sock, vsock uds_path) must be shorter than 104 bytes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE=debug
BUILD_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) PROFILE=release; shift ;;
        --build-only) BUILD_ONLY=1; shift ;;
        --) shift; break ;;
        *) break ;;
    esac
done

[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "error: needs macOS on Apple silicon" >&2; exit 1; }

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"
cargo_args=(build --locked -p firecracker --bin firecracker)
[[ $PROFILE == release ]] && cargo_args+=(--release)
(cd "$ROOT/lib/firecracker" && CARGO_TARGET_DIR="$TARGET_DIR" cargo "${cargo_args[@]}")

BIN="$TARGET_DIR/$PROFILE/firecracker"
codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" "$BIN"
echo "signed: $BIN" >&2
[[ $BUILD_ONLY == 1 ]] && exit 0
exec "$BIN" "$@"
