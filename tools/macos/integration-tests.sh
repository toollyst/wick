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
# patch to tests/conftest.py (and test_api_version accepts the +wick.N
# version: patches/0015); the host side it needs on macOS is
# tools/macos/integration/wick_macos.py.
#
# The binaries are the release build, signed as tools/macos/run.sh signs
# them. The guest artifacts are upstream's aarch64 CI set (the 6.1 kernel,
# its debug build, Ubuntu 24.04 and Amazon Linux 2023), prepared by
# tools/macos/integration/setup-artifacts.sh in
# ~/Library/Caches/wick/integration. Needs squashfs, e2fsprogs, screen 5 and
# zig (the guest's helper programs, wick_macos.gcc_compile), coreutils (GNU
# truncate and du, tools/macos/integration/bin), libslirp and pkg-config (the
# networks' host side), socat (the vsock tests' host side) and iperf3 (the
# network tests' host side), as upstream's container has them, from Homebrew
# (brew install squashfs e2fsprogs screen zig coreutils libslirp pkg-config
# socat iperf3). A missing one stops the run before any test.
#
# OUT (default build/integration-tests/<time>) gets the pytest JSON report
# (test-report.json; upstream's per-test test_results directory beside it, in
# OUT/test_results), pytest's output (pytest.log), the comparison
# (comparison.md), provenance.txt (wick's and lib/firecracker's commits and
# the Rust paths that differ from them: a run built from a dirty tree says
# WARNING, at the start, at the head of pytest.log and summary.txt, and at
# the end), summary.txt, which ends "N passed, M failed", and
# session-peak-kib the most the session's directory held (sampled every
# 10 s), what the free-space check is sized by. A test file that does not
# import does not end the run; the comparison counts it.
#
# Runs may overlap, with each other and with the other test scripts: each
# has its own session (/tmp/wit-*, whose .owner-pid keeps tools/clean.sh
# off it while the run lives; tools/macos/integration/clean-selftest.sh) and
# its own OUT. They share the build (cargo's lock orders two builds) and the
# Mac's memory: one microVM per run (-n 1) when the Mac is short of it. The
# disk images a session attaches (bin/losetup, the tmpfs of
# test_snapshot_not_losing_dirty_pages.py) are detached when it ends, also
# when a worker was killed (tools/macos/integration/disks-selftest.sh).
#
# --jailer asks for sudo once, at the start of pytest; run the script as the
# user, not under sudo (as root it refuses to start: not_as_root,
# tools/common.sh). Root's tests (the security suite, the [root] entries
# of tools/macos/integration-test-differences.txt) in one run:
#   tools/macos/integration-tests.sh --jailer -n 1 integration_tests/security \
#     integration_tests/functional/test_snapshot_basic.py::test_negative_snapshot_permissions \
#     integration_tests/functional/test_api_server.py::test_api_socket_in_use
#
# A run needs WICK_IT_FREE_GIB (default 20) GiB free; a selection of tests
# that session-peak-kib shows to need less may ask for less.
#
# A diagnostic run: one with WICK_IT_DIAG_MEMORY=1 (each memory reading of
# get_stable_rss_mem logged with its parts, the host's paging and the guest's
# /proc/meminfo, in OUT/memory-diag.jsonl), WICK_IT_DIAG_RSS_LESS=vmm (that
# reading without the VMM's own part too; it always leaves out the VMM's
# shared cache part), WICK_IT_DEFER_MEMORY_ERROR=1
# (the memory monitor's error at a kill inside a test held to the test's
# end, so that the steps after the kill run; the test still fails) or
# WICK_IT_DIAG_MEMORY_KINDS=1 (each microVM's peak of the VMM's own part by
# kind of mapping, in OUT/memory-peaks.jsonl, the kinds Linux's CI step
# reports: tools/linux/integration/wick_memdiag.py summary reads both), as
# tools/macos/integration/wick_macos.py (DIAGNOSTIC_SWITCHES) describes.
# provenance.txt says DIAGNOSTIC RUN, and the comparison counts that as a
# problem: what such a run shows is to read, not a result.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
not_as_root "$0" "$@"
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
for tool in socat iperf3; do
    PATH="/opt/homebrew/bin:$PATH" command -v "$tool" >/dev/null ||
        die "$tool missing: brew install $tool (the host side of upstream's vsock and network tests)"
done

free_gib="${WICK_IT_FREE_GIB:-20}"
[[ "$free_gib" =~ ^[0-9]+$ ]] || die "WICK_IT_FREE_GIB must be a number of GiB"
# No run with less than tools/macos/boot-test.sh's 5 GiB.
((free_gib >= 5)) || die "WICK_IT_FREE_GIB must be at least 5"
prepare_test_run "$ROOT/build/integration-tests" "$free_gib"
# The session's jails are under /tmp, which may be on another volume than
# the build output prepare_test_run checked: the same free space there.
tmp_avail_gib="$(df -Pk /tmp | awk 'NR == 2 { print int($4 / 1048576) }')"
tmp_mount="$(df -Pk /tmp | awk 'NR == 2 { print $6 }')"
((tmp_avail_gib >= free_gib)) ||
    die "only $tmp_avail_gib GiB free on $tmp_mount, which holds the session's jails (/tmp); a run needs $free_gib GiB there (tools/clean.sh)"
out="${out:-$ROOT/build/integration-tests/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
echo aarch64 >"$out/arch"

# The diagnostic switches that are on (wick_macos.DIAGNOSTIC_SWITCHES).
diagnostic=()
for switch in WICK_IT_DIAG_MEMORY WICK_IT_DIAG_RSS_LESS WICK_IT_DEFER_MEMORY_ERROR WICK_IT_DIAG_MEMORY_KINDS; do
    value="${!switch:-}"
    if [[ -n "$value" && "$value" != 0 ]]; then
        diagnostic+=("$switch=$value")
    fi
done

# What the run builds from: wick's and lib/firecracker's commits, and the
# Rust sources that differ from them (another session's work in progress
# in a shared checkout ends up in the binaries). Written to provenance.txt,
# at the head of pytest.log and of summary.txt; a dirty tree is
# a loud warning, and a run's results speak for the commits only when it
# is clean.
{
    echo "wick HEAD: $(git -C "$ROOT" rev-parse HEAD)"
    echo "lib/firecracker HEAD: $(git -C "$ROOT/lib/firecracker" rev-parse HEAD)"
    dirty="$(git -C "$ROOT" status --short -- crates overlay lib/firecracker tools/vhost-user-blk;
        git -C "$ROOT/lib/firecracker" status --short -- src resources Cargo.toml Cargo.lock .cargo |
            sed 's|^\(...\)|\1lib/firecracker/|')"
    if [[ -n "$dirty" ]]; then
        echo "WARNING: built from a dirty Rust tree; these paths differ from the commits above:"
        echo "$dirty" | sed 's/^/    /'
    else
        echo "Rust tree: clean (crates, overlay, lib/firecracker, tools/vhost-user-blk)"
    fi
    if ((${#diagnostic[@]})); then
        echo "DIAGNOSTIC RUN (${diagnostic[*]}): what it shows is to read, not a result"
    fi
} >"$out/provenance.txt"
cat "$out/provenance.txt"

# The release build, as upstream's tests use it.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"
(cd "$ROOT/lib/firecracker" && CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked --release \
    -p firecracker -p jailer -p snapshot-editor -p rebase-snap -p cpu-template-helper \
    -p seccompiler -p log-instrument -p clippy-tracing --bins --examples)
bin="$out/bin"
mkdir -p "$bin/examples"
for b in firecracker jailer snapshot-editor rebase-snap cpu-template-helper seccompiler-bin clippy-tracing; do
    cp "$TARGET_DIR/release/$b" "$bin/$b"
done
find "$TARGET_DIR/release/examples" -maxdepth 1 -type f -perm -u+x ! -name '*-*' -exec cp {} "$bin/examples/" \;
# Both make a microVM (cpu-template-helper boots one to read its CPU's
# configuration): Hypervisor.framework serves only a signed entitlement.
for b in firecracker cpu-template-helper; do
    codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" "$bin/$b"
done
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
# A host program in a test's network (tools/macos/integration/bin/ip).
cc -O2 -Wall -Wextra -Werror -dynamiclib -o "$bin/netns-preload.dylib" "$ROOT/tools/macos/integration/netns-preload.c"
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
#
# The session's jails hold each microVM's memory, snapshots and disk
# copies (hundreds of MiB each). Each test's jails are removed when the test
# ends, also when it fails (wick_macos.remove_jails), and the session
# directory at exit, on failure or interruption too.
session="$(mktemp -d /tmp/wit-XXXX)"
# The session's owner: while this script runs, tools/clean.sh (which every
# test script's start runs) leaves the session and the processes naming it
# (its screen sessions have parent pid 1) alone. Its pid and start time:
# a pid used again later is not this run.
# shellcheck disable=SC2046,SC2005
echo "$$ $(echo $(ps -o lstart= -p $$))" >"$session/.owner-pid"
cleanup() {
    # Everything the session started carries its root in its command line.
    pkill -KILL -f -- "$session" 2>/dev/null || true
    # Disk images the session attached and a failed test left attached
    # (bin/losetup's, wick_macos.small_tmpfs's RAM disks); as --jailer, root
    # attached them.
    if [[ $mode == jailer ]]; then
        sudo -n "$ROOT/tools/macos/integration/detach-session-disks.sh" "$session" || true
    else
        "$ROOT/tools/macos/integration/detach-session-disks.sh" "$session" || true
    fi
    [[ -n "${sampler:-}" ]] && kill "$sampler" 2>/dev/null
    # A test may leave a jail without its owner's permissions
    # (test_negative_snapshot_permissions makes it read-only): they are given
    # back first. As --jailer, the jailer made the jails as root, and only
    # root removes them: sudo, without asking again (the run asked already).
    if [[ $mode == jailer ]]; then
        sudo -n chmod -R u+rwx "$session" 2>/dev/null || true
        sudo -n rm -rf "$session" 2>/dev/null || true
    else
        chmod -R u+rwx "$session" 2>/dev/null || true
        rm -rf "$session" || true
    fi
    [[ ! -e "$session" ]] || echo "cannot remove $session$([[ $mode == jailer ]] && echo ': root-owned, run sudo tools/clean.sh')" >&2
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

env_args=(
    "PATH=$ROOT/tools/macos/integration/bin:$SCREEN_DIR:/opt/homebrew/opt/e2fsprogs/sbin:$PATH:/opt/homebrew/bin"
    "PYTHONPATH=$ROOT/tools/macos/integration"
    "WICK_IT_MODE=$mode" "WICK_IT_ROOT=$session" "TMPDIR=$session/tmp"
    "WICK_IT_NETNS_HELPER=$bin/netns-slirp" "WICK_IT_NETNS_PRELOAD=$bin/netns-preload.dylib"
    "WICK_IT_VHOST_USER_BLK=$bin/vhost-user-blk"
    "WICK_IT_BINARY_DIR=$bin"
    "MKE2FS_CONFIG=$ROOT/tools/macos/integration/mke2fs.conf"
    "PYTEST_ADDOPTS=${PYTEST_ADDOPTS:-}"
    ${diagnostic[@]+"${diagnostic[@]}"}
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
# The JSON report, and upstream's per-test results directories next to it
# (conftest.py's results_dir), in this run's own directory: upstream's
# pytest.ini puts them in lib/firecracker/test_results, which another run
# would share.
rm -rf "$out/test_results"
mkdir -p "$out/test_results"
cp "$out/provenance.txt" "$out/pytest.log"
# A file that does not import (test_seccomp_validate.py needs Linux's
# libseccomp) would end the whole session: the run goes on without it, and
# the comparison counts it as a difference unless it is listed.
pytest=("$ROOT/build/integration/venv/bin/python" -m pytest -p wick_macos --binary-dir "$bin"
    "--json-report-file=$out/test_results/test-report.json" --continue-on-collection-errors "$@")
[[ -x "$ROOT/build/integration/venv/bin/python" ]] || die "no Python environment: tools/macos/integration/venv.sh"
set +e
if [[ $mode == jailer ]]; then
    (cd "$ROOT/lib/firecracker/tests" && sudo env "${env_args[@]}" "${pytest[@]}") 2>&1 | tee -a "$out/pytest.log"
else
    (cd "$ROOT/lib/firecracker/tests" && env "${env_args[@]}" "${pytest[@]}") 2>&1 | tee -a "$out/pytest.log"
fi
status=${PIPESTATUS[0]}
set -e
# As --jailer, pytest wrote the results as root.
[[ $mode == jailer ]] && sudo -n chown -R "$(id -u):$(id -g)" "$out/test_results" 2>/dev/null || true
echo "$status" >"$out/status"
echo "$mode" >"$out/mode"
cp "$out/test_results/test-report.json" "$out/test-report.json" 2>/dev/null || true
echo "pytest exited with $status"
set +e
python3 -I "$ROOT/tools/macos/compare-integration-tests.py" "$out" ${compare[@]+"${compare[@]}"} --summary "$out/comparison.md" \
    --summary-txt "$out/summary.txt"
compared=$?
set -e
# summary.txt keeps its last line "N passed, M failed" (what tools/clean.sh
# and the docs read): the provenance goes first.
{ cat "$out/provenance.txt"; cat "$out/summary.txt" 2>/dev/null; } >"$out/summary.txt.new"
mv "$out/summary.txt.new" "$out/summary.txt"
if grep -q '^WARNING' "$out/provenance.txt"; then
    echo "WARNING: built from a dirty Rust tree (provenance.txt): the results are not the commits'" >&2
fi
exit "$compared"
