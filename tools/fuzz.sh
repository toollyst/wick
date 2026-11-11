#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs wick's fuzz targets (fuzz/, CONTRIBUTING.md "Fuzzing") with cargo-fuzz.
#
#   tools/fuzz.sh [-t SECONDS] [-j JOBS] [TARGET...]
#
#   -t SECONDS  how long each target runs (default 60)
#   -j JOBS     libFuzzer worker processes per target (default 1)
#   TARGET      the targets to run (default: every target this host runs;
#               uffd_protocol is macOS only)
#   --list      print the targets this host runs
#   --toolchain print the nightly toolchain the targets build with
#
# Needs the pinned nightly toolchain (--toolchain; rustup installs it on first
# use) and cargo-fuzz (`cargo install cargo-fuzz --locked`). The corpus grows in
# fuzz/corpus/<target>, starting from fuzz/seeds/<target> where there is one;
# a crash is saved in fuzz/artifacts/<target> and fails the run, which then
# prints the command that reproduces it.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Pinned so that runs are comparable; CI uses the same date.
TOOLCHAIN="${WICK_FUZZ_TOOLCHAIN:-nightly-2026-11-01}"
FUZZ_DIR="$WICK_ROOT/fuzz"

host_targets() {
    echo vnet_segment
    echo vnet_offload
    echo whp_irqchip
    if [[ "$(uname -s)" == Darwin ]]; then
        echo uffd_protocol
    fi
}

# libFuzzer options per target.
target_args() {
    case "$1" in
    # A virtio-net header and a frame of up to the device's 65550 bytes.
    vnet_segment) echo "-max_len=65560 -dict=$FUZZ_DIR/vnet_segment.dict" ;;
    vnet_offload) echo "-max_len=4096" ;;
    # Each run creates and releases a userfaultfd (a thread and a socket pair).
    uffd_protocol) echo "-max_len=4096" ;;
    # Up to 256 guest accesses, line changes, routes and snapshots.
    whp_irqchip) echo "-max_len=8192" ;;
    *) die "unknown target '$1' (tools/fuzz.sh --list)" ;;
    esac
}

seconds=60
jobs=1
targets=()
while (($#)); do
    case "$1" in
    -t) seconds="${2:?-t needs a number of seconds}"; shift 2 ;;
    -j) jobs="${2:?-j needs a number of jobs}"; shift 2 ;;
    --list) host_targets; exit 0 ;;
    --toolchain) echo "$TOOLCHAIN"; exit 0 ;;
    -h | --help) awk 'NR < 5 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    -*) die "unknown option '$1'" ;;
    *) targets+=("$1"); shift ;;
    esac
done
[[ "$seconds" =~ ^[1-9][0-9]*$ ]] || die "-t takes a number of seconds, not '$seconds'"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "-j takes a number of jobs, not '$jobs'"
if ((${#targets[@]} == 0)); then
    # No mapfile: macOS ships bash 3.2.
    while read -r t; do targets+=("$t"); done < <(host_targets)
fi
for t in "${targets[@]}"; do target_args "$t" >/dev/null; done

cargo "+$TOOLCHAIN" fuzz --version >/dev/null 2>&1 \
    || die "cargo-fuzz with toolchain $TOOLCHAIN not found: rustup toolchain install $TOOLCHAIN && cargo install cargo-fuzz --locked"

# macOS: the compatibility crates expect the deployment target of the build.
if [[ "$(uname -s)" == Darwin ]]; then
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
fi

cd "$WICK_ROOT"
cargo "+$TOOLCHAIN" fuzz build --fuzz-dir fuzz

for t in "${targets[@]}"; do
    args="$(target_args "$t")"
    corpus=("fuzz/corpus/$t")
    mkdir -p "fuzz/corpus/$t"
    [[ -d "fuzz/seeds/$t" ]] && corpus+=("fuzz/seeds/$t")
    parallel=()
    ((jobs > 1)) && parallel=("-fork=$jobs")
    echo "== $t: ${seconds}s, $jobs job(s)"
    # shellcheck disable=SC2086 # $args is a list of options.
    cargo "+$TOOLCHAIN" fuzz run --fuzz-dir fuzz "$t" "${corpus[@]}" -- \
        -max_total_time="$seconds" -timeout=30 -rss_limit_mb=4096 -print_final_stats=1 \
        ${parallel[@]+"${parallel[@]}"} $args
done
