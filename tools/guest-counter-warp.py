#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Run in a Linux guest: do two CPUs' counters agree? The TSC on x86_64
# (RDTSCP), the virtual counter on aarch64 (ISB; MRS CNTVCT_EL0, which Linux
# lets EL0 read: v6.1 drivers/clocksource/arm_arch_timer.c:932-955,
# arch_counter_set_user_access sets ARCH_TIMER_USR_VCT_ACCESS_EN). The
# algorithm is the kernel's TSC warp check (v6.1 arch/x86/kernel/tsc_sync.c:
# 267-321, check_tsc_warp): each CPU in turn takes a spinlock, reads the
# counter, takes the value the last reader left and leaves its own; a value
# below the one left by the other CPU is a warp. One difference: after its
# turn a CPU waits (at most 1000 pauses) for the other to take one, so that
# the turns alternate; without it one CPU retakes the lock hundreds of times
# for each hand-over (313 hand-overs in 500000 turns, measured), and only a
# hand-over compares two CPUs. The guest kernel runs that
# test only when a CPU comes online, and not at all once its CPUID has
# TSC_ADJUST; this runs it when the boot tests ask, on every host.
# Like the kernel's, the run is bounded by time: check_tsc_warp(timeout)
# reads the TSC at its start, sets end = start + tsc_khz * timeout (v6.1
# tsc_sync.c:276) and stops once the TSC passes it, or after 10000000 turns
# (:297); loop_timeout gives 2 ms, or 20 ms for a CPU alone in its package
# (:341-343). Here the bound is BOUND_S, 2 s, with ITERATIONS kept as the
# most turns. Not the kernel's 2 or 20 ms: the kernel's loop runs with both
# CPUs' interrupts off, while this one runs in user space, where either CPU
# can be taken away for milliseconds; 2 s leaves room for that. Measured, the
# turns run out first: 500000 turns took 0.10 s on GitHub's nested KVM
# runner (CI run 43486495448, both smp checks) and 0.06 to 0.10 s on a
# Windows PC (3393774). (CI run 43480682094's "no answer within 120 s" was
# not a slow run: the guest's pass line was there, after the shell's
# prompts on the same console line, where the Linux boot test's
# line-anchored match missed it. Hence the newline below.) The counter's rate, for the bound, is measured
# against CLOCK_MONOTONIC over 50 ms before the run (the loop called with no
# turns reads the counter); on aarch64 that is CNTFRQ_EL0's rate, read the
# same way rather than from the register, so both machines share one path.
#
# The record: before its verdict line, a line of its own,
#   counter-record: least step at a hand-over to CPU A S ticks, to CPU B T
#     ticks: CPU B's counter about D ticks ahead of CPU A's, the hand-over
#     about L ticks
# (signed: a warp's step is negative; "none" for a direction with no
# hand-over). With the hand-over's least latency L alike both ways and
# CPU B's counter D ahead of CPU A's, the least step to B is about L + D
# and to A about L - D, so D = (T - S) / 2 and L = (T + S) / 2: an offset
# between the two counters is measured on every run, warp or not. A
# record only; it decides nothing.
#
# Interface (the boot tests of all three hosts call it unchanged):
#   python3 guest-counter-warp.py [CPU_A CPU_B [ITERATIONS]]
#     CPU_A, CPU_B  the two CPUs (default 0 1); ITERATIONS per CPU at most
#     (default 500000); the run also ends after BOUND_S seconds.
#   Output: once the loop ran, an empty line and the record line
#   (counter-record:, above); then an empty line and one verdict line (so
#   each starts the console's line, whatever prompts stand before it),
#   then the exit status:
#     counter-warp: pass: <counter> CPUs A and B, I iterations each,
#       H hand-overs, largest forward step at a hand-over G ticks,
#       in R s                                                          exit 0
#     counter-warp: FAIL: <counter> went back W ticks from CPU X to CPU Y
#       (N warps in H hand-overs, I iterations each, in R s)            exit 1
#     counter-warp: FAIL: ... (no measurement: the reason)              exit 2
#   I is the turns the CPU that ran fewer took; R the seconds the run took.
#   A run whose CPUs handed the lock over fewer than 1000 times measured
#   nothing and exits 2, as does an unknown machine, a CPU that cannot be
#   bound, or code that cannot be mapped.
# Delivery: the guest may have no writable file system and a console line
# holds at most 4095 bytes (N_TTY_BUF_SIZE), so the boot tests send this
# file's bytes compressed as raw deflate (zlib, wbits -15), in base64, into
# the shell variable W in pieces of at most 2000 characters (W=piece, then
# W=$W'piece' ...), and run
#   python3 -c "import base64,zlib;exec(zlib.decompress(base64.b64decode('$W'),-15))" A B
#
# The loop (s[0] lock, s[1] last value, s[2] last reader, CPU + 1; out: max
# warp, warps, max forward step, hand-overs, iterations, the counter at the
# start, the last counter read), in short:
#   void warp_loop(volatile u64 *s, u64 me, u64 n, u64 ticks, u64 *out) {
#     u64 max_warp = 0, warps = 0, max_gap = 0, handovers = 0, i;
#     u64 start = counter(), last = start;
#     for (i = 0; i < n; i++) {
#       if (ticks && last - start > ticks) break;
#       while (__atomic_exchange_n(&s[0], 1, __ATOMIC_ACQUIRE)) pause/yield;
#       u64 prev = s[1], now = counter(), who = s[2]; last = now;
#       s[1] = now; s[2] = me;
#       __atomic_store_n(&s[0], 0, __ATOMIC_RELEASE);
#       for (k = 0; k < 1000 && s[2] == me; k++) pause/yield;
#       if (who != me && who != 0) {
#         handovers++;
#         if (prev > now) { warps++; max_warp = max(max_warp, prev - now); }
#         else max_gap = max(max_gap, now - prev);
#       }
#     }
#     out[0..7] = max_warp, warps, max_gap, handovers, i, start, last;
#   }
# counter() is RDTSCP on x86_64, ISB; MRS CNTVCT_EL0 on aarch64.
#
# Where CODE comes from: the full source is tools/guest-counter-warp-loop.c.
# Each machine's bytes are the .text section of the ELF object that
#   Apple clang version 21.0.0 (clang-2100.4.1.1)
# makes with
#   clang -target x86_64-linux-gnu -O2 -fno-stack-protector -ffreestanding \
#         -fPIC -fno-asynchronous-unwind-tables -c guest-counter-warp-loop.c
#   clang -target aarch64-linux-gnu -mno-outline-atomics -O2 \
#         -fno-stack-protector -ffreestanding -fPIC \
#         -fno-asynchronous-unwind-tables -c guest-counter-warp-loop.c
# (-mno-outline-atomics: upstream clang's default for aarch64-linux-gnu
# makes the atomic exchange a call to libgcc's __aarch64_swp8_acq, which
# this blob, mapped alone, cannot have; Apple clang's default does not, and
# its object is the same with the flag or without it)
# cut by reading the object's section headers (e_shoff; .text by name in
# the section-name table) and taking that section's bytes; the object has no
# relocation section, so the bytes run wherever they are mapped, and no
# other code or data section. tools/check-guest-counter-warp.py does exactly
# this and compares: that clang on this repo's Mac rebuilds both byte for
# byte. Another clang may choose other instructions for the same source
# (Ubuntu 24.04's clang 18.1.3 does, on both machines: 297 and 268
# bytes for the loop before its least step, 307 and 276 here then), so
# the check says SKIP (exit 3) when its clang is another and differs, and
# when no clang is on PATH; it never passes silently.
import ctypes
import mmap
import os
import sys
import threading
import time

CODE = {
    "x86_64": ("TSC", "554157415641554154534c894424f84989ca4989d149bbffffffffffffff7f0f01f948c1e2204189c04909d04d85c90f84df0000004531e448c74424f0000000004531ed4531ff4531f64c89c0eb14904c39e94c0f47e949ffc64d39ce0f84c40000004d85d2741a4889c14c29c14c39d1760fe9b20000000f1f840000000000f390b8010000004887074885c075f1488b6f080f01f948c1e22089c04809d0488b4f10488947084889771048c70700000000bae8030000660f1f840000000000488b5f104839f37507f39048ffca75f04839f10f95c24885c90f95c184ca0f8473ffffff49ffc74889c14829e94c39d94c0f4cd94889c14829e90f8350ffffff48ff4424f04829c54c39e54c0f47e5e943ffffff4531f64c89c04531ff4531ed31d24531e4eb084d89ce488b5424f0488b4c24f84c8921488951084c8969104c8979184c8971204c894128488941304c8959385b415c415d415e415f5dc3"),
    "aarch64": ("CNTVCT_EL0", "df3f03d548e03bd5020700b4ed031faaeb031faaea031faae9031faaec031faa0e00f09230008052ef0308aa060000145f020aeb4a828a9a8c0500919f0102eb40060054830000b4f10108cb3f0203ebe80500540ffc5fc8107c11c8d1ffff35cf0000b43f2003d50ffc5fc8107c11c8d1ffff358fffffb5110440f9df3f03d54fe03bd5057d8052120840f90f0400f9010800f91ffc9fc8060840f9df0001eb81000054a50400f13f2003d561ffff545f0201eb20fcff5412fcffb4f20111eb290500915f020eeb4eb28e9af20111eb02fbff5431020fcb6b0500913f020deb2d828d9ad5ffff17ec031faae9031faaea031faaeb031faaed031faa0e00f092ef0308aa02000014ec0302aa8d2c00a98a2401a98c2002a98f3803a9c0035fd6"),
}
U64 = ctypes.c_uint64
# The run's time bound, in seconds (the header says why 2).
BOUND_S = 2.0


def stop(code, line):
    # A newline first: the shell's prompts for the commands before this one
    # can still stand on the console's line ("# # "), and the boot tests
    # look for the line at its start.
    print("\ncounter-warp: " + line, flush=True)
    sys.exit(code)


def record(cpus, outs):
    # The least signed step at a hand-over to each CPU (out[7]), and what
    # they give (the header's record).
    least = {}
    for c in cpus:
        v = outs[c][7]
        v = v - (1 << 64) if v >= 1 << 63 else v
        least[c] = None if v == (1 << 63) - 1 else v
    a, b = cpus
    said = ", ".join(f"to CPU {c} {least[c]} ticks" if least[c] is not None else f"to CPU {c} none" for c in cpus)
    if least[a] is not None and least[b] is not None:
        said += f": CPU {b}'s counter about {(least[b] - least[a]) / 2:g} ticks ahead of CPU {a}'s, the hand-over about {(least[b] + least[a]) / 2:g} ticks"
    print("\ncounter-record: least step at a hand-over " + said, flush=True)


def main(argv):
    if len(argv) not in (0, 2, 3) or not all(a.isdigit() for a in argv):
        stop(64, "usage: guest-counter-warp.py [CPU_A CPU_B [ITERATIONS]]")
    cpus = [int(a) for a in argv[:2]] or [0, 1]
    n = int(argv[2]) if len(argv) == 3 else 500000
    machine = os.uname().machine
    if machine not in CODE:
        stop(2, f"FAIL: no counter for {machine} (no measurement)")
    counter, code = CODE[machine][0], bytes.fromhex(CODE[machine][1])
    # Written, then made executable: on arm64 the kernel makes the
    # instruction cache agree when it maps the page executable.
    page = mmap.mmap(-1, mmap.PAGESIZE)
    page.write(code)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(page))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
    if libc.mprotect(addr, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        stop(2, f"FAIL: the code cannot be made executable, errno {ctypes.get_errno()} (no measurement)")
    # CFUNCTYPE: the call lets go of Python's lock, so both run at once.
    loop = ctypes.CFUNCTYPE(None, ctypes.c_void_p, U64, U64, U64, ctypes.c_void_p)(addr)
    shared = (U64 * 8)()

    def read_counter():
        out = (U64 * 8)()
        loop(ctypes.addressof(shared), 0, 0, 0, ctypes.addressof(out))
        return out[5], time.monotonic()

    # The counter's rate against CLOCK_MONOTONIC, for the time bound.
    c0, t0 = read_counter()
    time.sleep(0.05)
    c1, t1 = read_counter()
    if c1 <= c0 or t1 <= t0:
        stop(2, f"FAIL: {counter} did not move over {t1 - t0:.3f} s (no measurement)")
    ticks = int((c1 - c0) / (t1 - t0) * BOUND_S)
    outs = {c: (U64 * 8)() for c in cpus}
    errors = []
    ready = threading.Barrier(2)

    def run(cpu):
        try:
            os.sched_setaffinity(0, {cpu})
        except OSError as e:
            errors.append(f"CPU {cpu} cannot be bound: {e}")
            ready.abort()
            return
        try:
            ready.wait()
        except threading.BrokenBarrierError:
            return
        loop(ctypes.addressof(shared), cpu + 1, n, ticks, ctypes.addressof(outs[cpu]))

    threads = [threading.Thread(target=run, args=(c,)) for c in cpus]
    began = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    took = time.monotonic() - began
    turns = min(outs[c][4] for c in cpus)
    if errors:
        stop(2, "FAIL: " + "; ".join(errors) + " (no measurement)")
    handovers = sum(outs[c][3] for c in cpus)
    warps = sum(outs[c][1] for c in cpus)
    record(cpus, outs)
    if warps:
        behind = max(cpus, key=lambda c: outs[c][0])
        ahead = cpus[1] if behind == cpus[0] else cpus[0]
        stop(1, f"FAIL: {counter} went back {outs[behind][0]} ticks from CPU {ahead} to CPU {behind} ({warps} warps in {handovers} hand-overs, {turns} iterations each, in {took:.2f} s)")
    if handovers < 1000:
        stop(2, f"FAIL: CPUs {cpus[0]} and {cpus[1]} handed over {handovers} times in {turns} iterations each, in {took:.2f} s (no measurement)")
    gap = max(outs[c][2] for c in cpus)
    stop(0, f"pass: {counter} CPUs {cpus[0]} and {cpus[1]}, {turns} iterations each, {handovers} hand-overs, largest forward step at a hand-over {gap} ticks, in {took:.2f} s")


if __name__ == "__main__":
    main(sys.argv[1:])
