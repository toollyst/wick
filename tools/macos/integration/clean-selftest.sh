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
# --remove then runs clean.sh for real and checks that both are gone, if its
# dry run lists nothing but this test's (another run's leftovers would go
# too). CLEAN_SH (default tools/clean.sh) is the script under test.
set -euo pipefail
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
finish() {
    [[ -n "$screen_pid" ]] && kill "$screen_pid" 2>/dev/null
    [[ -n "$owner_pid" ]] && kill "$owner_pid" 2>/dev/null
    "$SCREEN" -wipe >/dev/null 2>&1 || true
    rm -rf "$session"
}
trap finish EXIT

# As upstream's framework starts Firecracker (utils.start_screen_process),
# with the session's path in the command line.
stop_screen() {
    kill "$screen_pid" 2>/dev/null || true
    for _ in $(seq 50); do kill -0 "$screen_pid" 2>/dev/null || break; sleep 0.1; done
    "$SCREEN" -wipe >/dev/null 2>&1 || true
}
start_screen() {
    screen_pid=""
    "$SCREEN" -dmS "$name" /bin/sh -c 'sleep 600' "$session/jailer"
    for _ in $(seq 50); do
        screen_pid="$(ps -eo pid=,ppid=,args= | awk -v s="$session" -v n="$name" '$2 == 1 && index($0, s) && index($0, n) { print $1 }')"
        [[ -n "$screen_pid" ]] && return
        sleep 0.1
    done
}

sleep 600 &
owner_pid=$!
owner_line "$owner_pid" >"$session/.owner-pid"
start_screen
[[ -n "$screen_pid" ]] || { echo "FAIL: no screen daemon with parent pid 1 naming $session"; exit 1; }
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

if ((remove)); then
    # What every test script's start removes anyway (passed runs' images)
    # aside, only this test's may be listed.
    dry="$("$clean" --dry-run 2>&1)"
    others="$(grep -E '^would (kill|remove)' <<<"$dry" | grep -vF -e "would kill $screen_pid " \
        -e "would remove /private$session " -e ": snapshot or image of a passed run" || true)"
    if [[ -n "$others" ]]; then
        echo "not run for real: clean.sh would also take what is not this test's:"
        echo "$others" | sed 's/^/    /'
    else
        "$clean" >/dev/null 2>&1 || true
        sleep 0.5
        if kill -0 "$screen_pid" 2>/dev/null || [[ -e "$session" ]]; then
            echo "FAIL: clean.sh left $([[ -e "$session" ]] && echo "$session") $(kill -0 "$screen_pid" 2>/dev/null && echo "screen $screen_pid")"
            fails=$((fails + 1))
        else
            echo "ok: clean.sh removed the session of a dead owner and killed its screen"
        fi
    fi
fi
((fails == 0)) && echo "all passed" || { echo "$fails failed"; exit 1; }
