#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs upstream's integration tests (pytest, tests/integration_tests) against
# the macOS build, then compares them test by test with upstream's tests on
# Linux (tools/macos/compare-integration-tests.py).
#
#   tools/macos/integration-tests.sh [--jailer] [-o OUT] [PYTEST ARGS...]
#
# --jailer runs the session as root (it asks for sudo) with wick's jailer,
# as upstream's CI runs it on Linux. Without it the session runs as the user,
# with tools/macos/integration/jailer in the jailer's place (what that leaves
# out is listed in its header). Upstream's framework is unchanged but for one
# patch to tests/conftest.py; the host side it needs on macOS is
# tools/macos/integration/wick_macos.py.
#
# The binaries are the release build, signed as tools/macos/run.sh signs
# them. The guest artifacts are upstream's aarch64 CI set (the 6.1 kernel,
# its debug build, Ubuntu 24.04 and Amazon Linux 2023), prepared by
# tools/macos/integration/setup-artifacts.sh in
# ~/Library/Caches/wick/integration. Needs squashfs, e2fsprogs, screen 5 and
# zig (the guest's helper programs, wick_macos.gcc_compile) from Homebrew
# (brew install squashfs e2fsprogs screen zig).
#
# OUT (default build/integration-tests/<time>) gets the pytest JSON report
# (test-report.json), pytest's output (pytest.log), upstream's test_results
# directory and the comparison (comparison.md); summary.txt ends
# "N passed, M failed", and session-peak-kib the most the session's
# directory held (sampled every 10 s), what the free-space check is sized by.
#
# A run needs WICK_IT_FREE_GIB (default 20) GiB free; a selection of tests
# that session-peak-kib shows to need less may ask for less.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
mode=user
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jailer) mode=jailer; shift ;;
        -o) out="$2"; shift 2 ;;
        *) break ;;
    esac
done
# Without test arguments, upstream's functional and security suites, as the
# Linux comparison runs them; every test of theirs is then compared.
compare=()
if [[ $# -eq 0 ]]; then
    set -- -n 2 --dist worksteal integration_tests/functional integration_tests/security
    compare=(--full)
fi
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die "needs macOS on Apple silicon"

S3="https://s3.amazonaws.com/spec.ccfc.min"
PREFIX="firecracker-ci/20261105-6ea6634994fa-0"
ARTIFACTS=(
    vmlinux-6.1.188 vmlinux-6.1.188.config
    amazonlinux-2023.squashfs amazonlinux-2023.manifest
    ubuntu-24.04.squashfs ubuntu-24.04.manifest
    debug/vmlinux-6.1.188 debug/vmlinux-6.1.188.config debug/vmlinux-6.1.188.debug.gz
)
SCREEN_DIR="$(env PATH="/opt/homebrew/bin:$PATH" brew --prefix screen 2>/dev/null)/bin"
[[ -x "$SCREEN_DIR/screen" ]] || die "screen 5 missing: brew install screen (macOS's screen 4.0 has no -Logfile)"
PATH="/opt/homebrew/bin:$PATH" command -v zig >/dev/null ||
    die "zig missing: brew install zig (it builds the programs the tests run in the guest)"

free_gib="${WICK_IT_FREE_GIB:-20}"
[[ "$free_gib" =~ ^[0-9]+$ ]] || die "WICK_IT_FREE_GIB must be a number of GiB"
prepare_test_run "$ROOT/build/integration-tests" "$free_gib"
out="${out:-$ROOT/build/integration-tests/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
echo aarch64 >"$out/arch"

# The release build, as upstream's tests use it.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"
(cd "$ROOT/lib/firecracker" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked --release \
    -p firecracker -p jailer -p snapshot-editor -p rebase-snap -p cpu-template-helper \
    -p seccompiler --bins --examples)
bin="$out/bin"
mkdir -p "$bin/examples"
for b in firecracker jailer snapshot-editor rebase-snap cpu-template-helper seccompiler-bin; do
    cp "$TARGET_DIR/release/$b" "$bin/$b"
done
find "$TARGET_DIR/release/examples" -maxdepth 1 -type f -perm -u+x ! -name '*-*' -exec cp {} "$bin/examples/" \;
codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" "$bin/firecracker"
# Upstream's memory monitor counts the pages each mapping has resident. On
# Linux that is the pages a process mapped; a macOS observer that is not the
# process's debugger sees the pages of the mapped object, which for a file
# is the whole file once it is in the buffer cache (as cp and codesign leave
# it): Firecracker's text would count 3.9 MiB instead of the 1.6 MiB it
# touches. Rewritten without caching, the file's resident pages are the ones
# its processes touched.
python3 -I "$ROOT/tools/macos/integration/nocache-copy.py" "$bin/firecracker"

# The networks' host side (tools/macos/integration/wick_macos_net.py).
slirp_cflags="$(env PATH="/opt/homebrew/bin:$PATH" pkg-config --cflags --libs slirp)" ||
    die "libslirp missing: brew install libslirp pkg-config"
# shellcheck disable=SC2086
cc -O2 -Wall -Wextra -Werror -o "$bin/netns-slirp" "$ROOT/tools/macos/integration/netns-slirp.c" $slirp_cflags
# crosvm's vhost-user block device (tools/macos/integration/bin/crosvm).
(cd "$ROOT/tools/vhost-user-blk" && CARGO_TARGET_DIR="$ROOT/lib/firecracker/build/vhost-user-blk" \
    cargo build --release --locked)
cp "$ROOT/lib/firecracker/build/vhost-user-blk/release/vhost-user-blk" "$bin/vhost-user-blk"
if [[ $mode == user ]]; then
    cp "$ROOT/tools/macos/integration/jailer" "$bin/jailer"
fi

# Upstream's guest artifacts.
art="$HOME/Library/Caches/wick/integration/$PREFIX/aarch64"
mkdir -p "$art"
for name in "${ARTIFACTS[@]}"; do
    [[ -s "$art/$name" || -s "$art/$name.orig" || -s "$art/${name%.gz}" ]] && continue
    echo "downloading $name"
    mkdir -p "$(dirname "$art/$name")"
    curl -fsSL --retry 3 -o "$art/$name.part" "$S3/$PREFIX/aarch64/$name"
    mv "$art/$name.part" "$art/$name"
done
"$ROOT/tools/macos/integration/setup-artifacts.sh" "$art"
mkdir -p "$ROOT/lib/firecracker/build"
echo "$art" >"$ROOT/lib/firecracker/build/current_artifacts"

# The session root (upstream: /srv): short, as Unix socket paths are limited
# to 104 bytes, and ssh's control socket in a jail
# (<root>/jailer/firecracker/<uuid>/root/ssh-0.sock plus ssh's 17-byte
# suffix) is the longest: 102 bytes with this root.
session="$(mktemp -d /tmp/wit-XXXX)"
cleanup() {
    # Everything the session started carries its root in its command line.
    pkill -KILL -f -- "$session" 2>/dev/null || true
    [[ -n "${sampler:-}" ]] && kill "$sampler" 2>/dev/null
    rm -rf "$session"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

env_args=(
    "PATH=$ROOT/tools/macos/integration/bin:$SCREEN_DIR:/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
    "PYTHONPATH=$ROOT/tools/macos/integration"
    "WICK_IT_MODE=$mode" "WICK_IT_ROOT=$session" "TMPDIR=$session/tmp"
    "WICK_IT_NETNS_HELPER=$bin/netns-slirp" "WICK_IT_VHOST_USER_BLK=$bin/vhost-user-blk"
    "PYTEST_ADDOPTS=${PYTEST_ADDOPTS:-}"
)
mkdir -p "$session/tmp"
# The session directory's peak size, sampled: the blocks of its files that
# have one link (the guest artifacts are hard links to the cache).
(
    peak=0
    while [[ -d "$session" ]]; do
        kib="$(find "$session" -type f -links 1 -exec stat -f %b {} + 2>/dev/null |
            awk '{ s += $1 } END { print int(s / 2) }')"
        if ((kib > peak)); then
            peak=$kib
            echo "$peak" >"$out/session-peak-kib"
        fi
        sleep 10
    done
) &
sampler=$!
rm -rf "$ROOT/lib/firecracker/test_results"
pytest=("$ROOT/build/integration/venv/bin/python" -m pytest -p wick_macos --binary-dir "$bin" "$@")
[[ -x "$ROOT/build/integration/venv/bin/python" ]] || die "no Python environment: tools/macos/integration/venv.sh"
set +e
if [[ $mode == jailer ]]; then
    (cd "$ROOT/lib/firecracker/tests" && sudo env "${env_args[@]}" "${pytest[@]}") 2>&1 | tee "$out/pytest.log"
else
    (cd "$ROOT/lib/firecracker/tests" && env "${env_args[@]}" "${pytest[@]}") 2>&1 | tee "$out/pytest.log"
fi
status=${PIPESTATUS[0]}
set -e
echo "$status" >"$out/status"
echo "$mode" >"$out/mode"
[[ -d "$ROOT/lib/firecracker/test_results" ]] && cp -r "$ROOT/lib/firecracker/test_results" "$out/test_results"
cp "$ROOT/lib/firecracker/test_results/test-report.json" "$out/test-report.json" 2>/dev/null || true
echo "pytest exited with $status"
python3 -I "$ROOT/tools/macos/compare-integration-tests.py" "$out" ${compare[@]+"${compare[@]}"} --summary "$out/comparison.md" \
    --summary-txt "$out/summary.txt"
