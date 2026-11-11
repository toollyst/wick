#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Scenario tests of the macOS jailer (tools/macos/jailer-test.py): builds the
# jailer and a signed Firecracker as the invoking user, then runs the tests as
# root with sudo, since the jailer chroots and changes user.
#
#   tools/macos/jailer-test.sh [--release] [--no-vm] [stage...]
#
# Stages (default: all): refuse jail daemonize pidns limits no-api boot netns memory cpu.
# no-api, boot, netns, memory and cpu start a VM and need Hypervisor.framework; --no-vm skips them (GitHub's
# macOS runners have no Hypervisor.framework). Results and logs go to
# build/jailer-test/<time>. Run tools/setup.sh first.
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

prepare_test_run "$ROOT/build/jailer-test" 5
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"
"$ROOT/tools/macos/run.sh" --build-only ${cargo_profile[@]+"${cargo_profile[@]}"}
(cd "$ROOT/lib/firecracker" &&
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked ${cargo_profile[@]+"${cargo_profile[@]}"} -p jailer)

OUT="$ROOT/build/jailer-test/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
CACHE="$HOME/Library/Caches/wick/boot-test"
# Fetch the guest images as the user, so the cache stays the user's.
ROOT="$ROOT" python3 -I - "$CACHE" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("bt", os.path.join(os.environ["ROOT"], "tools/macos/boot-test.py"))
bt = importlib.util.module_from_spec(spec); spec.loader.exec_module(bt)
bt.fetch(sys.argv[1], bt.KERNEL); bt.fetch(sys.argv[1], bt.ROOTFS)
PY
exec sudo python3 -I "$ROOT/tools/macos/jailer-test.py" \
    --jailer "$TARGET_DIR/$PROFILE/jailer" \
    --firecracker "$TARGET_DIR/$PROFILE/firecracker" \
    --cache "$CACHE" \
    --out "$OUT" "$@"
