#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Boots upstream Firecracker's x86_64 CI guest with wick on Linux (KVM) and
# checks, stage by stage, the same as tools/windows/boot-test.ps1: boot to
# user space, serial output and input (stdin is a pipe), SMP start-up,
# reboot, the Async block engine (io_uring) and vsock.
#
#   tools/linux/boot-test.sh [--firecracker PATH] [--workdir DIR]
#                            [--stage all|boot|smp|block|vsock] [--timeout SEC]
#                            [--seccomp yes|no|auto]
#
# Needs: Linux x86_64 with read/write access to /dev/kvm, curl, python3 (the
# host end of vsock), md5sum, and internet access for the first run (kernel
# and rootfs from upstream's public CI bucket, about 145 MB, cached in
# --workdir).
#
# Without --firecracker it uses the release build upstream's release.sh
# makes (build/cargo_target/x86_64-unknown-linux-musl/release/firecracker),
# then cargo's default release and debug builds. The musl release binary is
# what upstream ships: it installs the seccomp filters, so the boot test
# also checks that wick's code stays within them, and that every thread has
# its filter (--seccomp yes; auto, the default, means yes for a musl release
# build and informational for other builds, which have no filters).
#
# Prints PASS/FAIL per check and writes every log (serial console,
# Firecracker log, VM config) to <workdir>/results-<time>.
set -euo pipefail

S3="https://s3.amazonaws.com/spec.ccfc.min"
# Upstream's CI artifacts (resources/rebuild.sh builds them); the prefix is
# the one this test was written against, the same as the Windows one.
PREFIX="firecracker-ci/20261105-6ea6634994fa-0/x86_64"
KERNEL_NAME="vmlinux-6.1.188"
ROOTFS_NAME="ubuntu-24.04.squashfs"
BOOT_ARGS="console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda ro rootfstype=squashfs init=/bin/sh"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fc=""
workdir="${XDG_CACHE_HOME:-$HOME/.cache}/wick-boot-test"
stage="all"
timeout=120
seccomp=auto
while [[ $# -gt 0 ]]; do
    case "$1" in
        --firecracker) fc="$2"; shift 2 ;;
        --workdir) workdir="$2"; shift 2 ;;
        --stage) stage="$2"; shift 2 ;;
        --timeout) timeout="$2"; shift 2 ;;
        --seccomp) seccomp="$2"; shift 2 ;;
        -h|--help) sed -n '4,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$stage" in all|boot|smp|block|vsock) ;; *) echo "unknown stage: $stage" >&2; exit 2 ;; esac
case "$seccomp" in yes|no|auto) ;; *) echo "--seccomp is yes, no or auto" >&2; exit 2 ;; esac

step() { echo "  - $*"; }
die() { echo "error: $*" >&2; exit 1; }

if [[ -z "$fc" ]]; then
    for c in \
        "$root/lib/firecracker/build/cargo_target/x86_64-unknown-linux-musl/release/firecracker" \
        "$root/lib/firecracker/build/cargo_target/release/firecracker" \
        "$root/lib/firecracker/build/cargo_target/debug/firecracker"; do
        [[ -x "$c" ]] && { fc="$c"; break; }
    done
    [[ -n "$fc" ]] || die "firecracker not found; pass --firecracker PATH"
fi
fc="$(cd "$(dirname "$fc")" && pwd)/$(basename "$fc")"
if [[ "$seccomp" == auto ]]; then
    case "$fc" in
        */*-unknown-linux-musl/release/*) seccomp=yes ;;
        *) seccomp=no ;;
    esac
fi
for tool in curl python3 md5sum; do
    command -v "$tool" >/dev/null || die "$tool is needed"
done
[[ -r /dev/kvm && -w /dev/kvm ]] || die "no read/write access to /dev/kvm (ls -l /dev/kvm: $(ls -l /dev/kvm 2>&1))"

mkdir -p "$workdir"
workdir="$(cd "$workdir" && pwd)"
results="$workdir/results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$results"
summary="$results/summary.txt"
: >"$summary"

get_asset() {
    local path="$workdir/$1"
    if [[ ! -s "$path" ]]; then
        step "downloading $1" >&2
        curl -fsSL --retry 3 -o "$path.part" "$S3/$PREFIX/$1"
        mv "$path.part" "$path"
    fi
    echo "$path"
}

echo "wick boot test"
step "firecracker: $fc"
version="$("$fc" --version 2>&1 | head -1)"
step "version: $version"
{
    echo "firecracker: $fc"
    echo "version: $version"
    echo "kernel: $(uname -sr)"
    echo "cpu: $(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //') ($(nproc) threads)"
    echo "kvm: $(ls -l /dev/kvm)"
    echo "file: $(file -b "$fc" 2>/dev/null || true)"
    echo "guest kernel: $PREFIX/$KERNEL_NAME"
    echo "guest rootfs: $PREFIX/$ROOTFS_NAME"
} >"$results/host.txt"
KERNEL="$(get_asset "$KERNEL_NAME")"
ROOTFS="$(get_asset "$ROOTFS_NAME")"

# --- one VM ------------------------------------------------------------------
# vm_start NAME CONFIG_JSON: starts Firecracker with its stdin a FIFO held
# open read-write in fd $VM_IN, its console in $VM_DIR/console.txt.
vm_start() {
    VM_NAME="$1"
    VM_DIR="$results/$1"
    mkdir -p "$VM_DIR"
    printf '%s\n' "$2" >"$VM_DIR/vm-config.json"
    # Firecracker opens the log file, it does not create it.
    : >"$VM_DIR/firecracker.log"
    : >"$VM_DIR/console.txt"
    rm -f "$VM_DIR/stdin"
    mkfifo "$VM_DIR/stdin"
    exec {VM_IN}<>"$VM_DIR/stdin"
    "$fc" --no-api --config-file "$VM_DIR/vm-config.json" \
        --log-path "$VM_DIR/firecracker.log" --level Debug --show-level --show-log-origin \
        <"$VM_DIR/stdin" >"$VM_DIR/console.txt" 2>&1 &
    VM_PID=$!
    VM_EXIT=""
}

vm_alive() { [[ -z "$VM_EXIT" ]] && kill -0 "$VM_PID" 2>/dev/null; }

# vm_reap: the exit code once Firecracker has exited.
vm_reap() {
    if [[ -z "$VM_EXIT" ]] && ! kill -0 "$VM_PID" 2>/dev/null; then
        VM_EXIT=0
        wait "$VM_PID" || VM_EXIT=$?
    fi
}

vm_stop() {
    if vm_alive; then
        kill -KILL "$VM_PID" 2>/dev/null || true
    fi
    vm_reap
    exec {VM_IN}>&-
    rm -f "$VM_DIR/stdin"
}

vm_send() { printf '%s\n' "$1" >&"$VM_IN"; }

# The console size now: wait_for looks only at what comes after a mark.
vm_mark() { stat -c %s "$VM_DIR/console.txt"; }

# wait_for MARK REGEX MS: prints the first console line after MARK that
# matches REGEX (extended, CRs dropped) within MS milliseconds.
wait_for() {
    local mark="$1" re="$2" until=$((SECONDS * 1000 + $3)) now m
    while :; do
        m="$(tail -c +"$((mark + 1))" "$VM_DIR/console.txt" | tr -d '\r' | grep -m1 -E -- "$re" || true)"
        [[ -n "$m" ]] && { printf '%s\n' "$m"; return 0; }
        vm_reap
        [[ -n "$VM_EXIT" ]] && return 1
        now=$((SECONDS * 1000))
        ((now < until)) || return 1
        sleep 0.1
    done
}

FAILED=0
check() { # check NAME OK(0/1) DETAIL
    local mark=PASS
    if [[ "$2" != 1 ]]; then
        mark=FAIL
        FAILED=$((FAILED + 1))
    fi
    printf '%-8s %-34s %-4s %s\n' "$VM_NAME" "$1" "$mark" "$3" | tee -a "$summary"
}

last_lines() { tr -d '\r' <"$VM_DIR/console.txt" | grep -v '^[[:space:]]*$' | tail -3 | paste -sd'|' -; }

# Waits for the shell, mounts /proc and /sys and checks serial input.
start_shell() {
    if ! wait_for 0 'Run /bin/sh as init process' "$((timeout * 1000))" >/dev/null; then
        vm_reap
        if [[ -n "$VM_EXIT" ]]; then
            check "kernel reaches init" 0 "firecracker exited ($VM_EXIT): $(last_lines)"
        else
            check "kernel reaches init" 0 "no init after ${timeout}s: $(last_lines)"
        fi
        return 1
    fi
    check "kernel reaches init" 1 "yes"
    sleep 1.5
    vm_send 'mount -t proc proc /proc; mount -t sysfs sys /sys'
    # The echo of the command line holds "6*7", not "42": only the shell's
    # answer matches, which proves the input reached the guest.
    local mark
    mark="$(vm_mark)"
    vm_send 'echo WICK-$((6*7))'
    if wait_for "$mark" 'WICK-42' 15000 >/dev/null; then
        check "serial input (stdin pipe)" 1 "echoed"
    else
        check "serial input (stdin pipe)" 0 "no answer"
        return 1
    fi
}

# get_value KEY COMMAND: the guest's answer to `echo KEY=$(COMMAND)`.
get_value() {
    local mark line
    mark="$(vm_mark)"
    vm_send "echo $1=\$($2)"
    line="$(wait_for "$mark" "^$1=" 15000 || true)"
    printf '%s' "${line#"$1="}" | sed 's/[[:space:]]*$//'
}

# check_value NAME VALUE EXPECTED (EXPECTED empty: informational, any value)
check_value() {
    if [[ -z "$3" ]]; then
        check "$1" "$([[ -n "$2" ]] && echo 1 || echo 0)" "$2"
    else
        check "$1" "$([[ "$2" == "$3" ]] && echo 1 || echo 0)" "$2"
    fi
}

# Every Firecracker thread runs under its seccomp filter (Seccomp: 2 in
# /proc/<pid>/task/<tid>/status). Upstream's release builds (musl, static)
# have filters; its debug and glibc builds compile an empty policy
# (resources/seccomp/unimplemented.json) and install none, so for them this
# is informational (--seccomp).
check_seccomp() {
    local total=0 filtered=0 st names=""
    for st in /proc/"$VM_PID"/task/*/status; do
        total=$((total + 1))
        if grep -q '^Seccomp:[[:space:]]*2$' "$st" 2>/dev/null; then
            filtered=$((filtered + 1))
        fi
        names+="$(sed -n 's/^Name:[[:space:]]*//p' "$st" 2>/dev/null),"
    done
    local detail="$filtered of $total threads (${names%,})"
    if [[ "$seccomp" == yes ]]; then
        check "seccomp filter on every thread" "$([[ $total -gt 0 && $filtered == "$total" ]] && echo 1 || echo 0)" "$detail"
    else
        check "seccomp (informational)" 1 "$detail"
    fi
}

stop_guest() {
    # No systemd as PID 1: reboot(2) straight away, or through sysrq.
    vm_send 'reboot -ff || echo b > /proc/sysrq-trigger'
    local until=$((SECONDS + 30))
    while ((SECONDS < until)); do
        vm_reap
        [[ -n "$VM_EXIT" ]] && break
        sleep 0.1
    done
    vm_reap
    local code="${VM_EXIT:-still running}"
    check "reboot exits Firecracker (code 0)" "$([[ "$code" == 0 ]] && echo 1 || echo 0)" "$code"
}

base_config() { # base_config VCPUS [EXTRA_DRIVES_JSON] [EXTRA_TOP_LEVEL_JSON]
    local drives="${2:-}" extra="${3:-}"
    [[ -n "$drives" ]] || drives="[]"
    [[ -n "$extra" ]] || extra="{}"
    python3 - "$KERNEL" "$ROOTFS" "$BOOT_ARGS" "$1" "$drives" "$extra" <<'EOF'
import json, sys
kernel, rootfs, args, vcpus, drives, extra = sys.argv[1:]
cfg = {
    "boot-source": {"kernel_image_path": kernel, "boot_args": args},
    "drives": [{"drive_id": "rootfs", "path_on_host": rootfs,
                "is_root_device": True, "is_read_only": True}] + json.loads(drives),
    "machine-config": {"vcpu_count": int(vcpus), "mem_size_mib": 512},
}
cfg.update(json.loads(extra))
print(json.dumps(cfg, indent=2))
EOF
}

finish_vm() {
    vm_stop
    if [[ -n "${VM_DIR:-}" ]] && grep -q -E 'ERROR|seccomp|Bad syscall' "$VM_DIR/firecracker.log" 2>/dev/null; then
        echo "    firecracker.log ($VM_NAME) has errors:"
        grep -E 'ERROR|seccomp|Bad syscall' "$VM_DIR/firecracker.log" | head -5 | sed 's/^/      /'
    fi
}
trap '[[ -n "${VM_PID:-}" && -z "${VM_EXIT:-}" ]] && kill -KILL "$VM_PID" 2>/dev/null; true' EXIT

# --- stages ------------------------------------------------------------------

if [[ "$stage" == all || "$stage" == boot ]]; then
    echo "[boot] 1 vCPU: boot, serial out/in, clock, reboot"
    vm_start boot "$(base_config 1)"
    if start_shell; then
        check_value "guest sees 1 CPU" "$(get_value CPUS 'grep -c ^processor /proc/cpuinfo')" 1
        check_value "clocksource (informational)" \
            "$(get_value CLOCK 'cat /sys/devices/system/clocksource/clocksource0/current_clocksource')" ""
        check_value "hypervisor CPUID bit" "$(get_value HV 'grep -c -w hypervisor /proc/cpuinfo')" 1
        check_seccomp
        vm_send 'dmesg | grep -i -E "apic|tsc|clock|hypervisor|smp" | head -40'
        sleep 1
        stop_guest
    fi
    finish_vm
fi

if [[ "$stage" == all || "$stage" == smp ]]; then
    echo "[smp] 2 vCPUs: AP start-up (INIT/SIPI), both CPUs online, reboot with 2 vCPUs"
    vm_start smp "$(base_config 2)"
    if start_shell; then
        check_value "guest sees 2 CPUs" "$(get_value CPUS 'grep -c ^processor /proc/cpuinfo')" 2
        check_value "both online" "$(get_value ONLINE 'cat /sys/devices/system/cpu/online')" 0-1
        # Work on both CPUs (taskset is in util-linux).
        check_value "runs on CPU 1" "$(get_value ON1 'taskset -c 1 sh -c "echo ok"')" ok
        stop_guest
    fi
    finish_vm
fi

if [[ "$stage" == all || "$stage" == block ]]; then
    echo "[block] a second drive on the Async engine: the guest reads it whole, hashes match"
    want="$(md5sum "$ROOTFS" | cut -c1-32)"
    data="$(python3 -c 'import json,sys; print(json.dumps([{"drive_id": "data", "path_on_host": sys.argv[1], "is_root_device": False, "is_read_only": True, "io_engine": "Async"}]))' "$ROOTFS")"
    vm_start block "$(base_config 1 "$data")"
    if start_shell; then
        # Firecracker logs this when it builds the Async (io_uring) engine.
        if grep -q 'Async file IO is in development preview' "$VM_DIR/firecracker.log"; then
            check "drive on the Async engine" 1 "per firecracker.log"
        else
            check "drive on the Async engine" 0 "no Async engine in firecracker.log"
        fi
        got="$(get_value SUM 'md5sum /dev/vdb | cut -c1-32')"
        check "Async drive md5 = host file md5" "$([[ "$got" == "$want" ]] && echo 1 || echo 0)" "guest $got, host $want"
        check_value "root drive (Sync) readable" "$(get_value ROOT 'head -c 1048576 /dev/vda | wc -c')" 1048576
        stop_guest
    fi
    finish_vm
fi

if [[ "$stage" == all || "$stage" == vsock ]]; then
    echo "[vsock] host -> guest CONNECT over the AF_UNIX socket, echo through socat"
    sock="$results/v.sock"
    rm -f "$sock"
    vm_start vsock "$(base_config 1 '[]' "{\"vsock\": {\"guest_cid\": 3, \"uds_path\": \"$sock\"}}")"
    if start_shell; then
        vm_send 'socat VSOCK-LISTEN:52,reuseaddr,fork EXEC:/bin/cat >/dev/null 2>&1 &'
        sleep 2
        reply="$(python3 - "$sock" <<'EOF' 2>&1 || true
import re, socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(sys.argv[1])
s.sendall(b"CONNECT 52\nwick-ping\n")
got = b""
until = time.monotonic() + 10
while time.monotonic() < until and b"wick-ping" not in got:
    try:
        chunk = s.recv(4096)
    except socket.timeout:
        continue
    if not chunk:
        break
    got += chunk
s.close()
sys.stdout.write(got.decode(errors="replace"))
EOF
)"
        reply_flat="$(printf '%s' "$reply" | tr '\n' ' ')"
        check "CONNECT answered with OK" "$([[ "$reply" =~ ^OK\ [0-9]+ ]] && echo 1 || echo 0)" "$reply_flat"
        check "data echoed back" "$([[ "$reply" == *wick-ping* ]] && echo 1 || echo 0)" "$reply_flat"
        stop_guest
    fi
    finish_vm
fi

# --- report ------------------------------------------------------------------
echo "logs: $results"
if ((FAILED > 0)); then
    echo "$FAILED check(s) failed"
    exit 1
fi
echo "all checks passed"
