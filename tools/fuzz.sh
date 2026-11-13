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
#               uffd_protocol is macOS only, and hvf_exit is not run on
#               Windows)
#   --list      print the targets this host runs
#   --toolchain print the nightly toolchain the targets build with
#
# Needs the pinned nightly toolchain (--toolchain; rustup installs it on first
# use) and cargo-fuzz (`cargo install cargo-fuzz --locked`). On Windows (from
# Git Bash) it also needs Visual Studio's "C++ AddressSanitizer" component,
# whose runtime DLL the targets load. The corpus grows in
# fuzz/corpus/<target>, starting from fuzz/seeds/<target> where there is one;
# a crash is saved in fuzz/artifacts/<target> and fails the run, which then
# prints the command that reproduces it.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# Pinned so that runs are comparable; CI uses the same date.
TOOLCHAIN="${WICK_FUZZ_TOOLCHAIN:-nightly-2026-11-01}"
FUZZ_DIR="$WICK_ROOT/fuzz"

# Windows, from Git Bash or MSYS2.
on_windows() {
    case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) return 0 ;;
    *) return 1 ;;
    esac
}

# The targets this host runs; with `all`, those of every host.
# hvf_exit is not built on Windows: the source it compiles beside the exit
# decoding (crates/compat/kvm-ioctls/src/hvf/trng.rs) calls getentropy, which
# wick's POSIX layer for Windows does not have, as nothing in a Windows build
# calls it. The decoding is the same code on every host, and runs on Linux
# and macOS.
host_targets() {
    echo vnet_segment
    echo vnet_offload
    if [[ "${1:-}" == all ]] || ! on_windows; then
        echo hvf_exit
    fi
    echo whp_irqchip
    echo whp_exit
    if [[ "${1:-}" == all || "$(uname -s)" == Darwin ]]; then
        echo uffd_protocol
    fi
}

# Windows: the targets are built with AddressSanitizer, whose runtime is a
# DLL of Visual Studio's (clang_rt.asan_dynamic-x86_64.dll) that is on no
# PATH outside a developer prompt. Found through vswhere and put on PATH; a
# host without it is refused here, where the target would otherwise fail to
# start with the loader's dialog.
asan_runtime_on_path() {
    local dll=clang_rt.asan_dynamic-x86_64.dll vswhere vs dir
    local IFS=:
    for dir in $PATH; do
        [[ -f "$dir/$dll" ]] && return 0
    done
    unset IFS
    # vswhere's own, fixed place (Microsoft: "vswhere is included with the
    # installer as of Visual Studio 2017 version 15.2 and later, and can be
    # found at %ProgramFiles(x86)%\Microsoft Visual Studio\Installer").
    vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
    [[ -x "$vswhere" ]] || die "$dll is not on PATH and vswhere.exe is not at $vswhere: install Visual Studio's C++ AddressSanitizer component"
    vs="$("$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.ASAN -property installationPath | tr -d '\r')"
    [[ -n "$vs" ]] || die "no Visual Studio with the C++ AddressSanitizer component (Microsoft.VisualStudio.Component.VC.ASAN): the fuzz targets need its $dll"
    dir="$(find "$(cygpath -u "$vs")/VC/Tools/MSVC" -path '*/bin/Hostx64/x64/'"$dll" -print 2>/dev/null | sort | tail -1)"
    [[ -n "$dir" ]] || die "$dll not found under $vs/VC/Tools/MSVC"
    PATH="$(dirname "$dir"):$PATH"
    export PATH
    echo "AddressSanitizer runtime: $dir"
}

# Targets of fuzz/Cargo.toml no host runs, one per line: the name, then why.
# None today.
not_run() {
    :
}

# Every target in fuzz/Cargo.toml runs on some host or says why not: a target
# left out of host_targets() would otherwise build on CI and never run.
check_targets() {
    local bin
    while read -r bin; do
        host_targets all | grep -qx "$bin" && continue
        not_run | awk '{ print $1 }' | grep -qx "$bin" && continue
        die "fuzz/Cargo.toml's target $bin is in neither host_targets() nor not_run() (tools/fuzz.sh)"
    done < <(awk '/^\[\[bin\]\]/ { bin = 1; next } bin && /^name *=/ { gsub(/[" ]/, ""); sub(/^name=/, ""); print; bin = 0 }' "$FUZZ_DIR/Cargo.toml")
}

# libFuzzer options per target.
target_args() {
    case "$1" in
    # A virtio-net header and a frame of up to the device's 65550 bytes.
    # The dictionary's path is relative, as the corpus's: the script runs
    # the targets from the repository's root, and a Windows program is not
    # given a path of Git Bash's.
    vnet_segment) echo "-max_len=65560 -dict=fuzz/vnet_segment.dict" ;;
    vnet_offload) echo "-max_len=4096" ;;
    # A sequence of vCPU exits, about 40 bytes each.
    hvf_exit) echo "-max_len=4096" ;;
    # Each run creates and releases a userfaultfd (a thread and a socket pair).
    uffd_protocol) echo "-max_len=4096" ;;
    # Up to 256 guest accesses, line changes, routes and snapshots.
    whp_irqchip) echo "-max_len=8192" ;;
    # A sequence of WHP exits' fields, about 20 bytes each.
    whp_exit) echo "-max_len=4096" ;;
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
check_targets
for t in "${targets[@]}"; do target_args "$t" >/dev/null; done

cargo "+$TOOLCHAIN" fuzz --version >/dev/null 2>&1 \
    || die "cargo-fuzz with toolchain $TOOLCHAIN not found: rustup toolchain install $TOOLCHAIN && cargo install cargo-fuzz --locked"

# macOS: the compatibility crates expect the deployment target of the build.
if [[ "$(uname -s)" == Darwin ]]; then
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
fi

cd "$WICK_ROOT"
if on_windows; then
    asan_runtime_on_path
    # One by one: hvf_exit and uffd_protocol are not built here.
    while read -r t; do cargo "+$TOOLCHAIN" fuzz build --fuzz-dir fuzz "$t"; done < <(host_targets)
else
    cargo "+$TOOLCHAIN" fuzz build --fuzz-dir fuzz
fi

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
