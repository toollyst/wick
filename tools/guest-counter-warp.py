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
#
# Interface (the boot tests of all three hosts call it unchanged):
#   python3 guest-counter-warp.py [CPU_A CPU_B [ITERATIONS]]
#     CPU_A, CPU_B  the two CPUs (default 0 1); ITERATIONS per CPU (default
#     500000).
#   Output: one line, then the exit status:
#     counter-warp: pass: <counter> CPUs A and B, I iterations each,
#       H hand-overs, largest forward step at a hand-over G ticks      exit 0
#     counter-warp: FAIL: <counter> went back W ticks from CPU X to CPU Y
#       (N warps in H hand-overs, I iterations each)                    exit 1
#     counter-warp: FAIL: ... (no measurement: the reason)              exit 2
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
# warp, warps, max forward step, hand-overs, iterations), in short:
#   void warp_loop(volatile u64 *s, u64 me, u64 n, u64 *out) {
#     u64 max_warp = 0, warps = 0, max_gap = 0, handovers = 0, i;
#     for (i = 0; i < n; i++) {
#       while (__atomic_exchange_n(&s[0], 1, __ATOMIC_ACQUIRE)) pause/yield;
#       u64 prev = s[1], now = counter(), who = s[2];
#       s[1] = now; s[2] = me;
#       __atomic_store_n(&s[0], 0, __ATOMIC_RELEASE);
#       for (k = 0; k < 1000 && s[2] == me; k++) pause/yield;
#       if (who != me && who != 0) {
#         handovers++;
#         if (prev > now) { warps++; max_warp = max(max_warp, prev - now); }
#         else max_gap = max(max_gap, now - prev);
#       }
#     }
#     out[0..5] = max_warp, warps, max_gap, handovers, i;
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
# (Ubuntu 24.04's clang 18.1.3 does, on both machines: 225 and 220
# bytes), so the check says SKIP (exit 3) when its clang is
# another and differs, and when no clang is on PATH; it never passes
# silently.
import ctypes
import mmap
import os
import sys
import threading

CODE = {
    "x86_64": ("TSC", "4157415641554154534989c84989d14885d20f84a70000004531db4531f631db4531d24531ffeb0a0f1f840000000000f390b8010000004887074885c075f14c8b67080f01f948c1e22089c04809d0488b4f10488947084889771048c70700000000bae8030000660f1f8400000000004c8b6f104939f57507f39048ffca75f04839f10f95c24885c90f95c184ca742149ffc24c89e14829c1760c49ffc64c39d94c0f47d9eb0a4c29e04839d8480f47d849ffc74d39cf0f8575ffffffeb0b4531d231db4531f64531db4d89184d897008498958104d8950184d8948205b415c415d415e415fc3"),
    "aarch64": ("CNTVCT_EL0", "220600b4eb031faaea031faae9031faae8031faaec031faa2d008052040000148c0500919f0102eb600500540efc5fc80d7c0fc8cfffff35ce0000b43f2003d50efc5fc80d7c0fc8cfffff358effffb50e0440f9df3f03d54fe03bd5117d8052100840f90f0400f9010800f91ffc9fc8120840f95f0201eb81000054310600f13f2003d561ffff541f0201eba0fcff5490fcffb4f0010ecbd1010fcb080500911f0209eb1082899a3f020beb31828b9adf010feb0992899a4a958a9a6b91919ad8ffff17e8031faae9031faaea031faaeb031faa6b2800a9692001a9621000f9c0035fd6"),
}
U64 = ctypes.c_uint64


def stop(code, line):
    print("counter-warp: " + line, flush=True)
    sys.exit(code)


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
    loop = ctypes.CFUNCTYPE(None, ctypes.c_void_p, U64, U64, ctypes.c_void_p)(addr)
    shared = (U64 * 8)()
    outs = {c: (U64 * 5)() for c in cpus}
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
        loop(ctypes.addressof(shared), cpu + 1, n, ctypes.addressof(outs[cpu]))

    threads = [threading.Thread(target=run, args=(c,)) for c in cpus]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        stop(2, "FAIL: " + "; ".join(errors) + " (no measurement)")
    handovers = sum(outs[c][3] for c in cpus)
    warps = sum(outs[c][1] for c in cpus)
    if warps:
        behind = max(cpus, key=lambda c: outs[c][0])
        ahead = cpus[1] if behind == cpus[0] else cpus[0]
        stop(1, f"FAIL: {counter} went back {outs[behind][0]} ticks from CPU {ahead} to CPU {behind} ({warps} warps in {handovers} hand-overs, {n} iterations each)")
    if handovers < 1000:
        stop(2, f"FAIL: CPUs {cpus[0]} and {cpus[1]} handed over {handovers} times in {n} iterations each (no measurement)")
    gap = max(outs[c][2] for c in cpus)
    stop(0, f"pass: {counter} CPUs {cpus[0]} and {cpus[1]}, {n} iterations each, {handovers} hand-overs, largest forward step at a hand-over {gap} ticks")


if __name__ == "__main__":
    main(sys.argv[1:])
