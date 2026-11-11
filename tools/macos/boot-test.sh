#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Scenario tests of the macOS build against upstream's aarch64 CI kernel and
# rootfs: boot, SMP, block (Sync/Async, read and write), vsock in both
# directions, networking over a Unix datagram endpoint and vmnet, full and diff
# snapshots restored in a new process, snapshot-editor rebase, the Uffd memory
# backend, PCI with snapshot restore, a vhost-user-blk backend, the
# logger, metrics, MMDS, balloon, entropy device and a rate limiter, and
# balloon cycles after a restore from file and on a booted guest (the guest
# keeps the host's pages; the footprint follows the balloon).
#
#   tools/macos/boot-test.sh [--release] [stage...]
#
# Stages (default: all, in this order): boot smp block vsock net vmnet
# snapshot diff uffd hugepages pci vhost-user devices balloon restores
# api-process. vmnet uses vmnet-shared (NAT); older macOS releases need root
# for vmnet.framework.
# The guest images are cached in ~/Library/Caches/wick/boot-test; results and
# logs go to build/boot-test/<time>. Run tools/setup.sh first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
PROFILE=debug
cargo_profile=()
if [[ "${1:-}" == "--release" ]]; then
    PROFILE=release
    cargo_profile=(--release)
    shift
fi
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "error: needs macOS on Apple silicon" >&2; exit 1; }

prepare_test_run "$ROOT/build/boot-test" 5
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"
"$ROOT/tools/macos/run.sh" --build-only ${cargo_profile[@]+"${cargo_profile[@]}"}
(cd "$ROOT/lib/firecracker" &&
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p snapshot-editor &&
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p firecracker \
        --example uffd_on_demand_handler)
(cd "$ROOT/tools/vhost-user-blk" && CARGO_TARGET_DIR="$ROOT/lib/firecracker/build/vhost-user-blk" \
    cargo build --release --locked)

OUT="$ROOT/build/boot-test/$(date +%Y%m%d-%H%M%S)"
exec python3 -I "$ROOT/tools/macos/boot-test.py" \
    --firecracker "$TARGET_DIR/$PROFILE/firecracker" \
    --snapshot-editor "$TARGET_DIR/$PROFILE/snapshot-editor" \
    --uffd-handler "$TARGET_DIR/$PROFILE/examples/uffd_on_demand_handler" \
    --vhost-user-blk "$ROOT/lib/firecracker/build/vhost-user-blk/release/vhost-user-blk" \
    --cache "$HOME/Library/Caches/wick/boot-test" \
    --out "$OUT" "$@"
