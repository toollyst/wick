#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The macOS runs that need root, in one go, with one password prompt.
#
#   tools/macos/root-batch.sh                 every step, in order
#   tools/macos/root-batch.sh --only STEP...  those steps (repeat --only)
#   tools/macos/root-batch.sh --list          the steps and what each proves
#   tools/macos/root-batch.sh --selftest      the batch's own logic, with stub
#                                             steps and no root (CI runs it)
#
# Run it as yourself, never under sudo: it builds as you and asks for sudo
# once (not_as_root, tools/common.sh). The scripts it runs ask for sudo
# themselves; the batch keeps sudo's timestamp fresh while it runs, so none
# of them asks again. A failed step does not stop the others.
#
# Results: build/root-batch/<time>/<step>.log for each step, and summary.txt
# (step, exit code, seconds), all yours. The batch then looks for anything
# root-owned left in the repository (its source and its build directories)
# and fails, listing them, if it finds any. It exits non-zero if any step or
# that check failed.
#
# The first step gives back what earlier root runs left root-owned (a
# `sudo` put in front of a tool once left 283 files in lib/firecracker/build
# and build/). machdep.user_idle_level, which the guest-timer steps set, is
# put back when they end, fail or the batch is interrupted.
#
# Not here: boot-test's vmnet stage from macOS 26 on, where vmnet.framework
# needs no root (boot-test.sh asks for none there; on 15 the batch runs it).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/tools/common.sh"
not_as_root "$0" "$@"

# The steps, in order: name, then what it proves (--list).
STEPS=(
    chown "Gives back to you what earlier root runs left root-owned in the repository, before anything builds"
    jailer-unit "The jailer's unit tests as root, as CI's jailer step runs them on macOS 26, here on this Mac: \
test_the_jailer_refuses_a_network_others_may_write's refusals for a jail uid that is not 0 (the network rows), \
test_set_resource_limits (root only), and the rest"
    jailer-netns "jailer-test netns: the interface lock with a real euid 0 (COMPATIBILITY, Net hotplug): another \
jail's tap0 is EBUSY, lock files of another uid and group, the uid-0 jail's lock file, a jail cannot make or replace \
an interface; the only run of the creator's paths as root"
    jailer-freeze "jailer-test --no-vm freeze: the freezer through upstream's files, kept by the root supervisor \
(COMPATIBILITY, the freezer row), on this Mac's load"
    jailer-fsize "jailer-test fsize: --resource-limit fsize on a jailed guest (COMPATIBILITY, the jailer's \
resource limits)"
    jailer-vmnet-guest "jailer-test vmnet-guest: a jailed guest on vmnet (COMPATIBILITY, Net)"
    jailer-jail "jailer-test --no-vm jail: the jail's uid/gid, chroot, root-owned copy, no inherited descriptors, \
outside files unreachable (COMPATIBILITY, the jailer rows)"
    serial-dos "integration-tests.sh --jailer test_serial_dos: upstream's serial flood test under the jailer \
(its [root] entry in integration-test-differences.txt)"
    ulimit "sudo keeps the 4096 descriptors integration-tests.sh gives its session, soft and hard \
(integration-tests.sh's header: upstream's run condition holds for its --jailer runs too)"
    guest-timer-0 "guest-timer.py at machdep.user_idle_level 0 (COMPATIBILITY, Guest timers: the level's part in a \
guest timer's lateness); the level is put back"
    guest-timer-128 "guest-timer.py at machdep.user_idle_level 128, the level put back (as guest-timer-0)"
    vmnet "boot-test vmnet before macOS 26, where vmnet.framework needs root (COMPATIBILITY, Net: vmnet); \
from macOS 26 it needs none and the step is not run"
)

usage() {
    sed -n '5,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

list() {
    local i
    for ((i = 0; i < ${#STEPS[@]}; i += 2)); do
        printf '%s\n    %s\n' "${STEPS[i]}" "${STEPS[i + 1]}"
    done
}

is_step() {
    local i
    for ((i = 0; i < ${#STEPS[@]}; i += 2)); do
        [[ "${STEPS[i]}" == "$1" ]] && return 0
    done
    return 1
}

# Overridden by --selftest: root, sudo and the idle level.
SUDO=(sudo)
OWNER_UID=0
CHECK_DIR="$ROOT"
idle_get() { /usr/sbin/sysctl -n machdep.user_idle_level; }
idle_set() { "${SUDO[@]}" /usr/sbin/sysctl -w "machdep.user_idle_level=$1"; }

IDLE_ORIG=""
restore_idle() {
    [[ -n "$IDLE_ORIG" ]] || return 0
    if idle_set "$IDLE_ORIG" >/dev/null; then
        echo "machdep.user_idle_level put back to $IDLE_ORIG"
        IDLE_ORIG=""
    else
        echo "error: machdep.user_idle_level could not be put back to $IDLE_ORIG: run" \
            "sudo sysctl -w machdep.user_idle_level=$IDLE_ORIG" >&2
        return 1
    fi
}

firecracker_bin() { echo "$ROOT/lib/firecracker/build/cargo_target/debug/firecracker"; }

step_chown() {
    local me
    me="$(id -u):$(id -g)"
    "${SUDO[@]}" find "$ROOT" -xdev -user 0 -print -exec chown -h "$me" {} +
}

step_jailer-unit() {
    local bin
    bin="$(cd "$ROOT/lib/firecracker" && cargo test --locked -p jailer --no-run --message-format=json |
        python3 -I -c 'import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("profile", {}).get("test") and m.get("target", {}).get("name") == "jailer" and m.get("executable"):
        print(m["executable"])')" || return 1
    [[ -n "$bin" ]] || { echo "error: no jailer test binary"; return 1; }
    "${SUDO[@]}" env RUST_TEST_THREADS=1 "$bin" --skip platform::macos::freezer::tests::test_self_check_under_load ||
        return 1
    "${SUDO[@]}" env RUST_TEST_THREADS=1 "$bin" platform::macos::freezer::tests::test_self_check_under_load --exact \
        --nocapture
}

step_jailer-netns() { "$ROOT/tools/macos/jailer-test.sh" netns; }
step_jailer-freeze() { "$ROOT/tools/macos/jailer-test.sh" --no-vm freeze; }
step_jailer-fsize() { "$ROOT/tools/macos/jailer-test.sh" fsize; }
step_jailer-vmnet-guest() { "$ROOT/tools/macos/jailer-test.sh" vmnet-guest; }
step_jailer-jail() { "$ROOT/tools/macos/jailer-test.sh" --no-vm jail; }

step_serial-dos() {
    "$ROOT/tools/macos/integration-tests.sh" --jailer -n 1 \
        integration_tests/functional/test_serial_io.py::test_serial_dos
}

step_ulimit() {
    local got
    got="$(ulimit -n 4096 && "${SUDO[@]}" sh -c 'echo "$(ulimit -n) $(ulimit -Hn)"')" || return 1
    echo "under sudo: soft and hard $got"
    [[ "$got" == "4096 4096" ]] || { echo "error: sudo did not keep 4096 descriptors, soft and hard"; return 1; }
}

guest_timer() {
    local level="$1" rc
    "$ROOT/tools/macos/run.sh" --build-only || return 1
    IDLE_ORIG="$(idle_get)" || { IDLE_ORIG=""; return 1; }
    echo "machdep.user_idle_level was $IDLE_ORIG"
    idle_set "$level" || { restore_idle; return 1; }
    python3 -I -B "$ROOT/tools/macos/guest-timer.py" "$(firecracker_bin)"
    rc=$?
    restore_idle || rc=1
    return $rc
}
step_guest-timer-0() { guest_timer 0; }
step_guest-timer-128() { guest_timer 128; }

step_vmnet() {
    local major
    major="$(sw_vers -productVersion | cut -d. -f1)"
    if ((major >= 26)); then
        echo "not run: macOS $major, where vmnet.framework needs no root (tools/macos/boot-test.sh vmnet runs as you)"
        return 0
    fi
    "$ROOT/tools/macos/boot-test.sh" vmnet
}

# Runs one step into OUT/<step>.log and appends its line to the summary.
run_step() {
    local name="$1" start rc
    start=$SECONDS
    echo "== $name"
    "step_$name" > "$OUT/$name.log" 2>&1
    rc=$?
    printf '%-18s exit %-3s %5ss\n' "$name" "$rc" "$((SECONDS - start))" | tee -a "$OUT/summary.txt"
    ((rc == 0)) || FAILED+=("$name")
}

# Lists what OWNER_UID owns under CHECK_DIR; fails if anything, or if a
# directory could not be read.
check_owned() {
    local found errors
    found="$(find "$CHECK_DIR" -xdev -user "$OWNER_UID" -print 2>"$OUT/check-errors.txt")"
    errors="$(cat "$OUT/check-errors.txt")"
    if [[ -n "$found" || -n "$errors" ]]; then
        { echo "root-owned files left in $CHECK_DIR:"; echo "$found"; echo "$errors"; } |
            tee -a "$OUT/summary.txt" >&2
        return 1
    fi
    echo "root-owned files left in $CHECK_DIR: none" | tee -a "$OUT/summary.txt"
}

KEEP=""
on_exit() {
    restore_idle
    [[ -z "$KEEP" ]] || kill "$KEEP" 2>/dev/null
}
on_signal() {
    echo "interrupted" | tee -a "$OUT/summary.txt"
    exit 130
}

batch() {
    local only=("$@") step i
    OUT="${ROOT_BATCH_OUT:-$ROOT/build/root-batch/$(date +%Y%m%d-%H%M%S)}"
    mkdir -p "$OUT"
    FAILED=()
    trap on_exit EXIT
    trap on_signal INT TERM HUP
    {
        echo "commit $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "macOS $(sw_vers -productVersion 2>/dev/null || echo unknown), $(date '+%F %T')"
    } > "$OUT/summary.txt"
    if [[ "${SUDO[0]}" == sudo ]]; then
        sudo -v || die "sudo is needed"
        # sudo's timestamp lasts 5 minutes; the steps take longer.
        (while kill -0 $$ 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 60; done) &
        KEEP=$!
    fi
    for ((i = 0; i < ${#STEPS[@]}; i += 2)); do
        step="${STEPS[i]}"
        if ((${#only[@]})) && [[ " ${only[*]} " != *" $step "* ]]; then
            continue
        fi
        run_step "$step"
    done
    check_owned || FAILED+=("root-owned files")
    if ((${#FAILED[@]})); then
        echo "FAILED: ${FAILED[*]} (logs in $OUT)" | tee -a "$OUT/summary.txt"
        return 1
    fi
    echo "all passed (logs in $OUT)" | tee -a "$OUT/summary.txt"
}

# The batch's own logic without root: stub steps, sudo as a no-op, the idle
# level in a file, the root-owned check pointed at the caller's own files.
selftest() {
    local dir fails=0 out rc
    dir="$(mktemp -d "${TMPDIR:-/tmp}/root-batch-selftest.XXXXXX")"
    check() { if ! eval "$1"; then echo "selftest FAIL: $2"; fails=$((fails + 1)); fi; }

    # 1. A passing, a failing and an idle-level step; the level comes back
    # after the failing step that set it; nothing of OWNER_UID is left.
    out="$dir/run1"
    ROOT_BATCH_SELFTEST=1 ROOT_BATCH_OUT="$out" ROOT_BATCH_LEVEL="$dir/level" ROOT_BATCH_CHECK="$dir/clean" \
        "$BASH" "$0" --only good --only bad --only idle > "$dir/run1.txt" 2>&1
    rc=$?
    check '[[ $rc != 0 ]]' "a failed step must make the batch fail (exit $rc)"
    check 'grep -q "^good  *exit 0 " "$out/summary.txt"' "the passing step's line"
    check 'grep -q "^bad  *exit 3 " "$out/summary.txt"' "the failing step's line with its code"
    check 'grep -q "^idle  *exit 1 " "$out/summary.txt"' "the idle step's line"
    check 'grep -q "FAILED: bad idle" "$out/summary.txt"' "the summary names the failed steps"
    check '[[ "$(cat "$dir/level")" == 7 ]]' "the idle level is put back after a failed step ($(cat "$dir/level"))"
    check 'grep -q "^bad step output$" "$out/bad.log"' "the step's output in its log"
    check 'grep -q "none" "$out/summary.txt"' "the clean check passes on a directory with nothing of the uid"

    # 2. The root-owned check finds a file of the uid it looks for (the
    # caller's own, standing for root's), lists it and fails the batch.
    out="$dir/run2"
    mkdir -p "$dir/dirty" && touch "$dir/dirty/left"
    ROOT_BATCH_SELFTEST=1 ROOT_BATCH_OUT="$out" ROOT_BATCH_LEVEL="$dir/level" ROOT_BATCH_CHECK="$dir/dirty" \
        ROOT_BATCH_UID="$(id -u)" "$BASH" "$0" --only good > "$dir/run2.txt" 2>&1
    rc=$?
    check '[[ $rc != 0 ]]' "a root-owned file left must fail the batch (exit $rc)"
    check 'grep -q "$dir/dirty/left" "$out/summary.txt"' "the file left is listed"
    check 'grep -q "FAILED: root-owned files" "$out/summary.txt"' "the summary says why"

    # 3. Interrupted inside the idle step: the level is put back.
    out="$dir/run3"
    echo 7 > "$dir/level"
    ROOT_BATCH_SELFTEST=1 ROOT_BATCH_OUT="$out" ROOT_BATCH_LEVEL="$dir/level" ROOT_BATCH_CHECK="$dir/clean" \
        "$BASH" "$0" --only interrupt --only good > "$dir/run3.txt" 2>&1
    rc=$?
    check '[[ $rc == 130 ]]' "an interrupted batch exits 130 (exit $rc)"
    check '[[ "$(cat "$dir/level")" == 7 ]]' "the idle level is put back on an interrupt ($(cat "$dir/level"))"
    check 'grep -q "^interrupted$" "$out/summary.txt"' "the summary says it was interrupted"
    check '! grep -q "^good " "$out/summary.txt"' "no step runs after the interrupt"

    # 4. The real list: every step has a function.
    local i
    for ((i = 0; i < ${#STEPS[@]}; i += 2)); do
        check 'declare -F "step_${STEPS[i]}" >/dev/null' "step ${STEPS[i]} has no function"
    done
    if ((fails)); then
        echo "selftest: $fails failed (runs in $dir)"
        cat "$dir"/run*.txt
        return 1
    fi
    rm -r "$dir"
    echo "selftest: ok (step lines and codes, failed steps named, the idle level put back after a failure and an" \
        "interrupt, the root-owned check listing what it finds; every step has a function)"
}

if [[ -n "${ROOT_BATCH_SELFTEST:-}" ]]; then
    # Stub steps for selftest(); the real ones are not reachable from here.
    SUDO=(env)
    OWNER_UID="${ROOT_BATCH_UID:-0}"
    CHECK_DIR="$ROOT_BATCH_CHECK"
    mkdir -p "$CHECK_DIR"
    [[ -f "$ROOT_BATCH_LEVEL" ]] || echo 7 > "$ROOT_BATCH_LEVEL"
    idle_get() { cat "$ROOT_BATCH_LEVEL"; }
    idle_set() { echo "$1" > "$ROOT_BATCH_LEVEL"; }
    STEPS=(interrupt "interrupted" good "passes" bad "fails with 3" idle "sets the idle level and fails")
    step_good() { echo "good step output"; }
    step_bad() { echo "bad step output"; return 3; }
    step_idle() {
        IDLE_ORIG="$(idle_get)"
        idle_set 0
        return 1
    }
    step_interrupt() {
        IDLE_ORIG="$(idle_get)"
        idle_set 128
        kill -INT $$
    }
fi

only=()
while (($#)); do
    case "$1" in
    --list) list; exit 0 ;;
    --selftest) selftest; exit ;;
    --only)
        [[ $# -ge 2 ]] || usage
        is_step "$2" || die "no step $2 (--list names them)"
        only+=("$2")
        shift 2
        ;;
    *) usage ;;
    esac
done
batch ${only[@]+"${only[@]}"}
