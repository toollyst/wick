// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// The loop of tools/guest-counter-warp.py, which carries it as machine code
// (its CODE table). Built for each machine with
//   clang -target <x86_64|aarch64>-linux-gnu -O2 -fno-stack-protector
//         -ffreestanding -fPIC -fno-asynchronous-unwind-tables -c
// and cut as the object's .text section; tools/check-guest-counter-warp.py
// does both and compares.
//
typedef unsigned long u64;
/* s: [0] lock, [1] last counter, [2] last reader (CPU + 1); out: [0] max
   warp, [1] warps, [2] max forward step at a hand-over, [3] hand-overs,
   [4] iterations. After its turn a CPU waits (at most 1000 pauses) for the
   other's, so that the turns alternate. */
static inline u64 counter(void) {
#if defined(__x86_64__)
    unsigned lo, hi, aux;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    return ((u64)hi << 32) | lo;
#else
    u64 v;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
#endif
}
void warp_loop(volatile u64 *s, u64 me, u64 iterations, u64 *out) {
    u64 max_warp = 0, warps = 0, max_gap = 0, handovers = 0, i;
    for (i = 0; i < iterations; i++) {
        while (__atomic_exchange_n(&s[0], 1, __ATOMIC_ACQUIRE)) {
#if defined(__x86_64__)
            __asm__ volatile("pause");
#else
            __asm__ volatile("yield");
#endif
        }
        u64 prev = s[1];
        u64 now = counter();
        u64 who = s[2];
        s[1] = now;
        s[2] = me;
        __atomic_store_n(&s[0], 0, __ATOMIC_RELEASE);
        for (u64 k = 0; k < 1000 && s[2] == me; k++) {
#if defined(__x86_64__)
            __asm__ volatile("pause");
#else
            __asm__ volatile("yield");
#endif
        }
        if (who != me && who != 0) {
            handovers++;
            if (prev > now) {
                warps++;
                if (prev - now > max_warp) max_warp = prev - now;
            } else if (now - prev > max_gap) {
                max_gap = now - prev;
            }
        }
    }
    out[0] = max_warp; out[1] = warps; out[2] = max_gap; out[3] = handovers; out[4] = i;
}
