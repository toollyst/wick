#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# tools/clean.sh against a running integration test session, without a VM.
#
#   tools/macos/integration/clean-selftest.sh [--remove] [CLEAN_SH]
#
# Every test script's start runs tools/clean.sh, which kills a test run's
# processes left with parent pid 1 and removes /tmp/wit-* directories no
# process names. A running session of tools/macos/integration-tests.sh has
# both: upstream's framework starts each Firecracker under `screen -dm`, whose
# daemon has parent pid 1 and the session's path in its arguments, and
# between two microVMs nothing names the session. Here a fake session gets
# what integration-tests.sh gives a real one (.owner-pid with its owner's pid
# and start time) and a screen session that names it, and clean.sh
# (--dry-run, so that nothing of anyone else's is touched) must
# - leave both while the owner lives, also with the screen session gone;
# - take both with no owner file, a garbled one, a pid whose start time is
#   another process's, or a dead owner.
# A vmm unit test process's endpoint directory ($DARWIN_USER_TEMP_DIR/
# fcnet-test-<pid>) must be left while its pid lives and taken once it is gone.
# --remove then runs clean.sh for real and checks that what it must take is
# gone and the live process's directory is not, if its dry run lists nothing
# but this test's (another run's leftovers would go too). CLEAN_SH (default
# tools/clean.sh) is the script under test.
set -Eeuo pipefail
# A command that ends the script (set -e), in a function or a trap too (-E),
# says so: a failure after "all passed" was once silent (CI run 43790310601).
trap 'echo "clean-selftest: line $LINENO: \"$BASH_COMMAND\" exited $?" >&2' ERR
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
remove=0
[[ "${1:-}" == --remove ]] && { remove=1; shift; }
clean="${1:-$ROOT/tools/clean.sh}"
SCREEN="$(env PATH="/opt/homebrew/bin:$PATH" brew --prefix screen 2>/dev/null)/bin/screen"
[[ -x "$SCREEN" ]] || { echo "screen 5 missing: brew install screen" >&2; exit 1; }

fails=0
# One owner state: clean.sh's verdict on the screen session while it runs,
# then on the directory once nothing names it (a dry run does not kill, and
# a directory a running process names is kept anyway).
verdict() { # verdict DESCRIPTION want(kept|taken)
    local what="$1" want="$2" out got_p=kept got_d=kept
    out="$("$clean" --dry-run 2>&1)"
    grep -qF "would kill $screen_pid " <<<"$out" && got_p=taken
    stop_screen
    out="$out
$("$clean" --dry-run 2>&1)"
    grep -qF "would remove /private$session " <<<"$out" && got_d=taken
    start_screen
    if [[ "$got_p" == "$want" && "$got_d" == "$want" ]]; then
        echo "ok: $what: session and its screen $want"
    else
        echo "FAIL: $what: want $want, screen $got_p, directory $got_d"
        echo "$out" | sed 's/^/    /'
        fails=$((fails + 1))
    fi
}
owner_line() { echo "$1 $(echo $(ps -o lstart= -p "$1"))"; }

session="$(mktemp -d /tmp/wit-XXXX)"
name="wit-selftest-$$"
owner_pid=""
screen_pid=""
window_pid=""
loop_pid=""
endpoint_pid=""
user_temp="$(getconf DARWIN_USER_TEMP_DIR)"
live_endpoint=""
dead_endpoint=""
# Kills what is still alive of `pid`s: one already gone (clean.sh --remove
# killed it) is not a failure.
kill_if_alive() {
    local pid
    for pid in "$@"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}
finish() {
    local rc=$?
    kill_if_alive "$loop_pid" "$screen_pid" "$window_pid" "$owner_pid" "$endpoint_pid"
    # Reaped here, or bash reports the sleep's SIGTERM as it exits.
    [[ -z "$endpoint_pid" ]] || wait "$endpoint_pid" 2>/dev/null || true
    "$SCREEN" -wipe >/dev/null 2>&1 || true
    rm -rf "$session"
    [[ -z "$live_endpoint" ]] || rm -rf "$live_endpoint"
    [[ -z "$dead_endpoint" ]] || rm -rf "$dead_endpoint"
    ((rc == 0)) || echo "clean-selftest: exit $rc" >&2
    exit "$rc"
}
trap finish EXIT

# As upstream's framework starts Firecracker (utils.start_screen_process),
# with the session's path in the command line. The window's process (sh
# execs sleep, so the path is gone from its command line) outlives a killed
# screen daemon, its parent then pid 1: it is killed with it, here and after
# clean.sh's run, or each run would leave its windows behind for 600 s.
stop_window() {
    kill_if_alive "$window_pid"
    window_pid=""
}
stop_screen() {
    kill "$screen_pid" 2>/dev/null || true
    for _ in $(seq 50); do kill -0 "$screen_pid" 2>/dev/null || break; sleep 0.1; done
    stop_window
    "$SCREEN" -wipe >/dev/null 2>&1 || true
}
start_screen() {
    screen_pid=""
    window_pid=""
    "$SCREEN" -dmS "$name" /bin/sh -c 'sleep 600' "$session/jailer"
    for _ in $(seq 50); do
        screen_pid="$(ps -eo pid=,ppid=,args= | awk -v s="$session" -v n="$name" '$2 == 1 && index($0, s) && index($0, n) { print $1 }')"
        [[ -n "$screen_pid" ]] && window_pid="$(pgrep -P "$screen_pid" | head -1)"
        [[ -n "$window_pid" ]] && return
        sleep 0.1
    done
}

sleep 600 &
owner_pid=$!
owner_line "$owner_pid" >"$session/.owner-pid"
start_screen
[[ -n "$screen_pid" && -n "$window_pid" ]] || { echo "FAIL: no screen daemon with parent pid 1 naming $session and a window"; exit 1; }
echo "screen daemon $screen_pid: parent pid $(ps -o ppid= -p "$screen_pid" | tr -d ' '), args name $session"

verdict "live owner" kept
real="$(cat "$session/.owner-pid")"
rm "$session/.owner-pid"
verdict "no owner file" taken
echo "garbage" >"$session/.owner-pid"
verdict "garbled owner file" taken
echo "$owner_pid Thu Jan 1 00:00:00 1970" >"$session/.owner-pid"
verdict "owner's pid with another start time" taken
echo "$real" >"$session/.owner-pid"
verdict "live owner again" kept
kill "$owner_pid"
wait "$owner_pid" 2>/dev/null || true
owner_pid=""
verdict "dead owner" taken

# A loop a killed tool left: a background subshell (its command line names
# integration-tests.sh, as the session sampler's does) whose script and
# process group leader are gone, parent pid 1. It ends by itself after 120 s
# whatever clean.sh does.
loop_pidfile="$(mktemp "${TMPDIR:-/tmp}/clean-selftest-loop.XXXXXX")"
python3 -I -c 'import os, sys
if os.fork():
    sys.exit(0)
os.setsid()
if os.fork():
    os._exit(0)
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
os.execv("/bin/bash", ["bash", "-c", "for i in $(seq 120); do sleep 1; done", sys.argv[2]])' \
    "$loop_pidfile" "$ROOT/tools/macos/integration-tests.sh"
for _ in $(seq 50); do [[ -s "$loop_pidfile" ]] && break; sleep 0.1; done
loop_pid="$(cat "$loop_pidfile")"
rm -f "$loop_pidfile"
for _ in $(seq 50); do [[ "$(ps -o ppid= -p "$loop_pid" | tr -d ' ')" == 1 ]] && break; sleep 0.1; done
dry="$("$clean" --dry-run 2>&1)"
if grep -q "^would kill $loop_pid .*: a loop left by a killed tool" <<<"$dry" &&
    grep -q "^found 1 loop(s) left by killed tools" <<<"$dry"; then
    echo "ok: an orphaned tool loop is found and counted"
else
    echo "FAIL: clean.sh did not find the orphaned loop $loop_pid (parent $(ps -o ppid= -p "$loop_pid"))"
    fails=$((fails + 1))
fi

# A unit test process's endpoint directory: one whose pid is running (a test
# binary in its tests) is kept; one whose pid is gone (a test binary killed
# before its exit removed it) is taken.
sleep 600 &
endpoint_pid=$!
live_endpoint="${user_temp}fcnet-test-$endpoint_pid"
mkdir "$live_endpoint"
true &
dead=$!
wait "$dead"
dead_endpoint="${user_temp}fcnet-test-$dead"
if kill -0 "$dead" 2>/dev/null; then
    echo "FAIL: pid $dead, just reaped, is running again"
    fails=$((fails + 1))
else
    mkdir "$dead_endpoint"
    dry="$("$clean" --dry-run 2>&1)"
    if grep -qF "would remove $dead_endpoint " <<<"$dry" && ! grep -qF "would remove $live_endpoint " <<<"$dry" &&
        grep -qF "keeping $live_endpoint: its test process $endpoint_pid is running" <<<"$dry"; then
        echo "ok: a gone test process's endpoint directory is taken, a running one's kept"
    else
        echo "FAIL: endpoint directories: want $dead_endpoint taken and $live_endpoint kept"
        echo "$dry" | sed 's/^/    /'
        fails=$((fails + 1))
    fi
fi

if ((remove)); then
    # What every test script's start removes anyway (passed runs' images)
    # aside, only this test's may be listed.
    dry="$("$clean" --dry-run 2>&1)"
    others="$(grep -E '^would (kill|remove)' <<<"$dry" | grep -vF -e "would kill $screen_pid " \
        -e "would remove /private$session " -e ": snapshot or image of a passed run" \
        -e "would kill $loop_pid " -e "would remove $dead_endpoint " || true)"
    if [[ -n "$others" ]]; then
        echo "not run for real: clean.sh would also take what is not this test's:"
        echo "$others" | sed 's/^/    /'
    else
        "$clean" >/dev/null 2>&1 || true
        sleep 0.5
        stop_window
        if kill -0 "$loop_pid" 2>/dev/null; then
            echo "FAIL: clean.sh left the orphaned loop $loop_pid"
            fails=$((fails + 1))
        fi
        if kill -0 "$screen_pid" 2>/dev/null || [[ -e "$session" ]]; then
            echo "FAIL: clean.sh left $([[ -e "$session" ]] && echo "$session") $(kill -0 "$screen_pid" 2>/dev/null && echo "screen $screen_pid")"
            fails=$((fails + 1))
        else
            echo "ok: clean.sh removed the session of a dead owner and killed its screen"
        fi
        if [[ -e "$dead_endpoint" || ! -d "$live_endpoint" ]]; then
            echo "FAIL: clean.sh left $dead_endpoint or took $live_endpoint"
            fails=$((fails + 1))
        else
            echo "ok: clean.sh removed the gone test process's endpoint directory and kept the running one's"
        fi
    fi
fi
((fails == 0)) && echo "all passed" || { echo "$fails failed"; exit 1; }
