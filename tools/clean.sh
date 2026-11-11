#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Removes what wick's builds and tests leave behind.
#
#   tools/clean.sh [--dry-run] [--keep N] [--all] [--quiet]
#
# By default:
# - test runs: keeps the newest N (10) of build/boot-test/<time>,
#   build/jailer-test/<time> and tools/linux/boot-test.sh's results-<time>
#   (in its --workdir, ~/.cache/wick-boot-test by default), and drops the
#   snapshot, memory and disk image files of the runs it keeps that passed;
# - test processes left running by a killed test run (Firecracker, the jailer,
#   the vhost-user and uffd test backends whose test runner is gone);
# - temporary directories of test runs no process uses any more
#   (/tmp/wick-bt-*, /private/tmp/wick-jt-*, the integration tests' /tmp/wit-*,
#   the jails inside; root-owned ones
#   need root, and are reported otherwise).
# --all also removes the build output: cargo's target directories, the
#   development container's cache, dist/, and every test run.
# --dry-run lists what would go, and how much space it holds.
#
# Nothing outside those paths is touched, and symbolic links are not
# followed. Anything that cannot be removed is reported, and the exit status
# is then 1.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

dry=0 keep=10 all=0 quiet=0
while (($#)); do
    case "$1" in
        --dry-run) dry=1; shift ;;
        --keep) [[ "${2:-}" =~ ^[0-9]+$ ]] || die "--keep needs a number"; keep="$2"; shift 2 ;;
        --all) all=1; shift ;;
        --quiet) quiet=1; shift ;;
        -h|--help) sed -n '4,25p' "$0"; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

linux_workdir="${WICK_LINUX_BOOT_TEST_WORKDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/wick-boot-test}"
failed=0
freed_kb=0

say() { ((quiet)) || echo "$@"; }

# The only places this script removes anything from.
allowed() {
    local p="$1"
    case "$p" in
        "$WICK_ROOT"/build/*|"$WICK_ROOT"/dist|"$WICK_ROOT"/fuzz/target) return 0 ;;
        "$UPSTREAM_DIR"/build/cargo_target|"$UPSTREAM_DIR"/build/vhost-user-blk) return 0 ;;
        "$UPSTREAM_DIR"/build/devctr-cache) return 0 ;;
        /tmp/wick-bt-*|/private/tmp/wick-bt-*|/tmp/wick-jt-*|/private/tmp/wick-jt-*) return 0 ;;
        /tmp/wit-*|/private/tmp/wit-*) return 0 ;;
        "$linux_workdir"/results-*) return 0 ;;
    esac
    return 1
}

size_kb() { du -sk "$1" 2>/dev/null | awk '{ print $1 }'; }

remove() {
    local p="$1" why="$2" kb
    [[ -e "$p" || -L "$p" ]] || return 0
    allowed "$p" || die "refusing to remove $p: not a path wick's builds or tests create"
    [[ -L "$p" ]] && die "refusing to remove $p: a symbolic link"
    kb="$(size_kb "$p")"
    if ((dry)); then
        say "would remove $p ($((kb / 1024)) MiB): $why"
        freed_kb=$((freed_kb + kb))
        return 0
    fi
    if rm -rf -- "$p" 2>/dev/null && [[ ! -e "$p" ]]; then
        say "removed $p ($((kb / 1024)) MiB): $why"
        freed_kb=$((freed_kb + kb))
    else
        echo "cannot remove $p ($why)$( ((EUID)) && echo ': run as root (sudo tools/clean.sh)')" >&2
        failed=1
    fi
}

# Test runs of one kind, newest first: directories named by their start time.
runs() {
    local dir="$1" pattern="$2"
    [[ -d "$dir" ]] || return 0
    find "$dir" -mindepth 1 -maxdepth 1 -type d | while IFS= read -r d; do
        [[ "$(basename "$d")" =~ $pattern ]] && echo "$d"
    done | sort -r
}

# A run that passed: the test script's summary.txt ends "N passed, 0 failed".
passed() {
    grep -qsE '^[0-9]+ passed, 0 failed' "$1/summary.txt"
}

clean_runs() {
    local dir="$1" pattern="$2" n=0 d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        n=$((n + 1))
        if ((all || n > keep)); then
            remove "$d" "test run beyond the newest $keep"
        elif passed "$d"; then
            while IFS= read -r f; do
                remove "$f" "snapshot or image of a passed run"
            done < <(find "$d" -type f \( -name '*.mem' -o -name '*.state' -o -name '*.img' \))
        fi
    done < <(runs "$dir" "$pattern")
}

# Processes a test run started whose test runner is gone (parent pid 1).
stray_processes() {
    ps -eo pid=,ppid=,args= | awk -v root="$WICK_ROOT" '
        $2 == 1 && ($0 ~ /\/tmp\/wick-(bt|jt)-/ || $0 ~ /\/tmp\/wit-/ || index($0, root "/build/boot-test/") || index($0, root "/build/jailer-test/")) {
            print $1 " " substr($0, index($0, $3))
        }'
}

clean_processes() {
    local pid cmd
    while read -r pid cmd; do
        [[ -n "$pid" ]] || continue
        if ((dry)); then
            say "would kill $pid ($cmd): left running by a killed test run"
        elif kill -KILL "$pid" 2>/dev/null; then
            say "killed $pid ($cmd): left running by a killed test run"
        else
            echo "cannot kill $pid ($cmd)$( ((EUID)) && echo ': run as root (sudo tools/clean.sh)')" >&2
            failed=1
        fi
    done < <(stray_processes)
}

# Temporary directories of test runs no running process names.
clean_temp() {
    local d
    for d in /tmp/wick-bt-* /private/tmp/wick-bt-* /tmp/wick-jt-* /private/tmp/wick-jt-* /tmp/wit-* /private/tmp/wit-*; do
        [[ -d "$d" && ! -L "$d" ]] || continue
        # /tmp is /private/tmp on macOS: each directory once.
        [[ "$d" == /tmp/* && -d "/private$d" && "$(uname)" == Darwin ]] && continue
        if ps -eo args= | grep -F -- "$(basename "$d")" | grep -vq -e grep -e clean.sh; then
            say "keeping $d: a running test uses it"
            continue
        fi
        remove "$d" "temporary directory of a finished test run"
    done
}

clean_processes
clean_temp
clean_runs "$WICK_ROOT/build/boot-test" '^[0-9]{8}-[0-9]{6}$'
clean_runs "$WICK_ROOT/build/jailer-test" '^[0-9]{8}-[0-9]{6}$'
clean_runs "$linux_workdir" '^results-[0-9]{8}-[0-9]{6}$'
if ((all)); then
    for p in "$WICK_ROOT/build" "$WICK_ROOT/dist" "$WICK_ROOT/fuzz/target" \
        "$UPSTREAM_DIR/build/cargo_target" "$UPSTREAM_DIR/build/vhost-user-blk" \
        "$UPSTREAM_DIR/build/devctr-cache"; do
        if [[ "$p" == "$WICK_ROOT/build" ]]; then
            [[ -d "$p" ]] || continue
            while IFS= read -r e; do
                remove "$e" "build output (--all)"
            done < <(find "$p" -mindepth 1 -maxdepth 1)
            continue
        fi
        remove "$p" "build output (--all)"
    done
fi

say "$( ((dry)) && echo would free || echo freed ) $((freed_kb / 1024)) MiB"
exit "$failed"
