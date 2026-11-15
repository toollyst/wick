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
# keeps the host's pages; the footprint follows the balloon); Firecracker's
# command line (exit codes, --module, the start time flags, the logger and
# metrics on FIFOs, --boot-timer) and the tools (rebase-snap, snapshot-editor
# info-vmstate), and the sandbox on by default and off with --no-seccomp.
#
#   tools/macos/boot-test.sh [--release] [stage...]
#
# Stages (default: all, in this order): boot smp block vsock net vmnet
# snapshot snapshot-permissions diff uffd hugepages pci vhost-user
# vhost-user-hotplug devices balloon restores api-process cli machine-config fingerprint sigxfsz tools
# no-seccomp memory-hotplug cpu-templates pvtime (PV steal time: on macOS 27 its figures,
# elsewhere that it is not offered). vmnet uses vmnet-shared (NAT), which needs
# root for vmnet.framework before macOS 26: there the vmnet stage alone runs as
# root (it asks for sudo), its results then given back to you.
# The guest images are cached in ~/Library/Caches/wick/boot-test; results and
# logs go to build/boot-test/<time>. Run tools/setup.sh first. Run it as
# yourself, not under sudo: as root it refuses to start (not_as_root,
# tools/common.sh), since its builds would leave root-owned files in the
# build directories your own builds share.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
not_as_root "$0" "$@"
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
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p snapshot-editor -p rebase-snap \
        -p cpu-template-helper &&
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p firecracker \
        --example uffd_on_demand_handler)
(cd "$ROOT/tools/vhost-user-blk" && CARGO_TARGET_DIR="$ROOT/lib/firecracker/build/vhost-user-blk" \
    cargo build --release --locked)
# cpu-template-helper boots a microVM for its fingerprint (the fingerprint
# stage): Hypervisor.framework serves only a signed entitlement.
codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" \
    "$TARGET_DIR/$PROFILE/cpu-template-helper"

OUT="$ROOT/build/boot-test/$(date +%Y%m%d-%H%M%S)"
CACHE="$HOME/Library/Caches/wick/boot-test"
args=(--firecracker "$TARGET_DIR/$PROFILE/firecracker"
    --snapshot-editor "$TARGET_DIR/$PROFILE/snapshot-editor"
    --rebase-snap "$TARGET_DIR/$PROFILE/rebase-snap"
    --uffd-handler "$TARGET_DIR/$PROFILE/examples/uffd_on_demand_handler"
    --vhost-user-blk "$ROOT/lib/firecracker/build/vhost-user-blk/release/vhost-user-blk"
    --cpu-template-helper "$TARGET_DIR/$PROFILE/cpu-template-helper"
    --cache "$CACHE")

# Before macOS 26 vmnet.framework needs root: the vmnet stage then runs alone
# as root, the others as you. -B: root writes no bytecode into the source
# tree; the images are fetched as you first, so the cache stays yours; and
# what root wrote (that stage's results) is given back to you.
major="$(sw_vers -productVersion | cut -d. -f1)"
stages=("$@")
if ((${#stages[@]} == 0)); then
    # bash 3.2 (macOS's): no mapfile.
    stages=()
    while IFS= read -r stage; do stages+=("$stage"); done < <(ROOT="$ROOT" python3 -I -B - <<'PY'
import importlib.util, os
spec = importlib.util.spec_from_file_location("bt", os.path.join(os.environ["ROOT"], "tools/macos/boot-test.py"))
bt = importlib.util.module_from_spec(spec); spec.loader.exec_module(bt)
print("\n".join(bt.STAGES))
PY
    )
fi
vmnet_as_root=0
others=()
for stage in "${stages[@]}"; do
    if [[ "$stage" == vmnet ]] && ((major < 26)); then
        vmnet_as_root=1
    else
        others+=("$stage")
    fi
done
if ((!vmnet_as_root)); then
    exec python3 -I "$ROOT/tools/macos/boot-test.py" "${args[@]}" --out "$OUT" "$@"
fi
status=0
if ((${#others[@]})); then
    python3 -I "$ROOT/tools/macos/boot-test.py" "${args[@]}" --out "$OUT" "${others[@]}" || status=$?
fi
ROOT="$ROOT" python3 -I -B - "$CACHE" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("bt", os.path.join(os.environ["ROOT"], "tools/macos/boot-test.py"))
bt = importlib.util.module_from_spec(spec); spec.loader.exec_module(bt)
bt.fetch(sys.argv[1], bt.KERNEL); bt.fetch(sys.argv[1], bt.ROOTFS)
PY
echo "boot-test: the vmnet stage runs as root on macOS $major (vmnet.framework needs it before 26): sudo asks" >&2
sudo python3 -I -B "$ROOT/tools/macos/boot-test.py" "${args[@]}" --out "$OUT/vmnet" vmnet || status=$?
sudo chown -R "$(id -u):$(id -g)" "$OUT/vmnet"
exit "$status"
