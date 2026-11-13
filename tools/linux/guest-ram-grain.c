// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// Linux's side of the lazy-RAM grain record (LINUXGRAIN lines): what KVM
// guest RAM mapped as upstream Firecracker maps it is charged and resident
// after the guest touches it. kvm-ioctls' test_lazy_guest_ram_by_grain_on_record
// (LAZYGRAIN lines) is the Windows side: the same guest addresses, the same
// two steps, the same warm-up.
//
// Guest memory is MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, as upstream's
// vstate/memory.rs maps it, with madvise(MADV_HUGEPAGE) for huge_pages
// "Transparent" only (vmm_config/machine_config.rs, HugePageConfig). One slot
// of each, 2 MiB aligned on the host as a transparent huge page needs, and in
// each the guest's two steps:
//   sparse: one byte written in each 2 MiB of 64 MiB (32 writes);
//   dense:  a byte written in each 4 KiB page of the next 4 MiB (1024).
// After each: the slot's pages present (/proc/self/pagemap, bit 63: Linux's
// Rss of the range) with the 64 KiB blocks and 2 MiB ranges they fall in,
// the AnonHugePages of the mapping that holds the slot (/proc/self/smaps),
// and the cgroup's memory.current and memory.stat anon (what memory.max
// counts), against before the step; and the step's time (KVM_RUN). The host's
// transparent_hugepage settings are printed first: which of Linux's two
// behaviours (a 4 KiB or a 2 MiB charge at a fault) the lines are.
//
// The guest runs in 32-bit protected mode without paging, so its addresses
// are guest physical ones; the program's bytes are those of the Windows
// record's long mode program.
//
//   cc -O2 -Wall -Werror -o guest-ram-grain tools/linux/guest-ram-grain.c
//   ./guest-ram-grain
//
// A record: it fails only when KVM refuses a step or a step does not end at
// its `out`.
#if !defined(__x86_64__)
#error "guest-ram-grain.c is the x86_64 record (its guest is x86 code)"
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define MIB2 (2ul << 20)
#define PAGE 4096ul
#define PORT 0x80
#define PROGRAM 0x1000ul
#define WARM 0x800000ul
#define SLOT_LEN (68ul << 20)
#define DENSE_AT (64ul << 20)

static const struct {
    const char *name;
    unsigned long gpa;
    int hugepage;
} SLOTS[] = {
    {"huge_pages None (no advice)", 0x2000000ul, 0},
    {"huge_pages Transparent (MADV_HUGEPAGE)", 0x7000000ul, 1},
};
#define NSLOTS (sizeof(SLOTS) / sizeof(SLOTS[0]))

static void die(const char *what) {
    fprintf(stderr, "LINUXGRAIN %s: %s\n", what, strerror(errno));
    exit(1);
}

static void file_line(const char *path, char *out, size_t len) {
    FILE *f = fopen(path, "r");
    out[0] = 0;
    if (!f || !fgets(out, (int)len, f)) {
        snprintf(out, len, "(not read)");
    }
    if (f) {
        fclose(f);
    }
    out[strcspn(out, "\n")] = 0;
}

// The cgroup's memory.current and memory.stat anon, in bytes; -1 if not read.
static void cgroup_memory(long *current, long *anon) {
    char line[4096], path[4200];
    *current = *anon = -1;
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) {
        return;
    }
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "0::", 3) == 0) {
            line[strcspn(line, "\n")] = 0;
            snprintf(path, sizeof path, "/sys/fs/cgroup%s/memory.current", line + 3);
            FILE *c = fopen(path, "r");
            if (c) {
                if (fscanf(c, "%ld", current) != 1) {
                    *current = -1;
                }
                fclose(c);
            }
            snprintf(path, sizeof path, "/sys/fs/cgroup%s/memory.stat", line + 3);
            FILE *s = fopen(path, "r");
            if (s) {
                char key[64];
                long v;
                while (fscanf(s, "%63s %ld", key, &v) == 2) {
                    if (strcmp(key, "anon") == 0) {
                        *anon = v;
                    }
                }
                fclose(s);
            }
        }
    }
    fclose(f);
}

// The pages of [addr, addr + len) present (pagemap bit 63), and the 64 KiB
// blocks and 2 MiB ranges (aligned on the host) that hold any.
static void present(int pagemap, unsigned long addr, unsigned long len, long *pages, long *blocks, long *ranges) {
    unsigned long last_block = ~0ul, last_range = ~0ul;
    *pages = *blocks = *ranges = 0;
    for (unsigned long at = addr; at < addr + len; at += PAGE) {
        uint64_t e;
        if (pread(pagemap, &e, sizeof e, (off_t)(at / PAGE * 8)) != sizeof e) {
            die("pread /proc/self/pagemap");
        }
        if (!(e >> 63)) {
            continue;
        }
        ++*pages;
        if (at / (64ul << 10) != last_block) {
            last_block = at / (64ul << 10);
            ++*blocks;
        }
        if (at / MIB2 != last_range) {
            last_range = at / MIB2;
            ++*ranges;
        }
    }
}

// The AnonHugePages of the mapping that holds addr, in KiB, and its range.
static long anon_huge(unsigned long addr, unsigned long *start, unsigned long *end) {
    char line[512];
    long kib = -1;
    int in = 0;
    FILE *f = fopen("/proc/self/smaps", "r");
    if (!f) {
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        unsigned long s, e;
        // A mapping's first line ("start-end perms ..."); no field line
        // parses as two hex numbers around a '-'.
        if (sscanf(line, "%lx-%lx ", &s, &e) == 2) {
            in = s <= addr && addr < e;
            if (in) {
                *start = s;
                *end = e;
            }
        } else if (in && sscanf(line, "AnonHugePages: %ld kB", &kib) == 1) {
            break;
        }
    }
    fclose(f);
    return kib;
}

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

// mov edi, base; mov ecx, count; then a byte written at edi and edi moved by
// stride, count times; out 0x80, al.
static size_t touch(uint8_t *at, uint32_t base, uint32_t count, uint32_t stride) {
    uint8_t b[] = {0xBF, 0, 0, 0, 0, 0xB9, 0, 0, 0, 0, 0xC6, 0x07, 0x01, 0x81, 0xC7, 0, 0, 0, 0,
                   0xFF, 0xC9, 0x75, 0xF3, 0xE6, PORT};
    memcpy(b + 1, &base, 4);
    memcpy(b + 6, &count, 4);
    memcpy(b + 15, &stride, 4);
    memcpy(at, b, sizeof b);
    return sizeof b;
}

static void *map_lazy(unsigned long len) {
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        die("mmap");
    }
    return p;
}

static void add_slot(int vm, uint32_t slot, unsigned long gpa, void *host, unsigned long len) {
    struct kvm_userspace_memory_region r = {
        .slot = slot, .guest_phys_addr = gpa, .memory_size = len, .userspace_addr = (uint64_t)(uintptr_t)host};
    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &r) < 0) {
        die("KVM_SET_USER_MEMORY_REGION");
    }
}

// Runs the vCPU to its next `out` to PORT: the time it took, or exits.
static double step(int vcpu, struct kvm_run *run, const char *name) {
    double t = now_us();
    for (;;) {
        if (ioctl(vcpu, KVM_RUN, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("KVM_RUN");
        }
        if (run->exit_reason == KVM_EXIT_IO && run->io.port == PORT) {
            return now_us() - t;
        }
        fprintf(stderr, "LINUXGRAIN %s: the step ended with exit reason %u, not its out\n", name, run->exit_reason);
        exit(1);
    }
}

int main(void) {
    char enabled[256], defrag[256], overcommit[64];
    struct utsname u;
    uname(&u);
    file_line("/sys/kernel/mm/transparent_hugepage/enabled", enabled, sizeof enabled);
    file_line("/sys/kernel/mm/transparent_hugepage/defrag", defrag, sizeof defrag);
    file_line("/proc/sys/vm/overcommit_memory", overcommit, sizeof overcommit);
    printf("LINUXGRAIN host: Linux %s; transparent_hugepage enabled: %s; defrag: %s; overcommit_memory %s\n",
           u.release, enabled, defrag, overcommit);

    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) {
        die("open /dev/kvm");
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) {
        die("KVM_CREATE_VM");
    }
    if (ioctl(vm, KVM_SET_TSS_ADDR, 0xfffbd000ul) < 0) {
        die("KVM_SET_TSS_ADDR");
    }
    // The program's memory (committed at once on Windows: not lazy).
    uint8_t *low = mmap(NULL, 4ul << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (low == MAP_FAILED) {
        die("mmap");
    }
    size_t at = PROGRAM;
    at += touch(low + at, WARM, 1, PAGE);
    for (size_t i = 0; i < NSLOTS; i++) {
        at += touch(low + at, (uint32_t)SLOTS[i].gpa, 32, MIB2);
        at += touch(low + at, (uint32_t)(SLOTS[i].gpa + DENSE_AT), 1024, PAGE);
    }
    memcpy(low + at, "\xF4\xEB\xFD", 3);
    add_slot(vm, 0, 0, low, 4ul << 20);
    void *warm = map_lazy(MIB2);
    add_slot(vm, 1, WARM, warm, MIB2);
    unsigned long slots[NSLOTS];
    for (size_t i = 0; i < NSLOTS; i++) {
        uint8_t *p = map_lazy(SLOT_LEN + MIB2);
        slots[i] = ((unsigned long)p + MIB2 - 1) & ~(MIB2 - 1);
        if (SLOTS[i].hugepage && madvise(p, SLOT_LEN + MIB2, MADV_HUGEPAGE) < 0) {
            die("madvise(MADV_HUGEPAGE)");
        }
        add_slot(vm, 2 + (uint32_t)i, SLOTS[i].gpa, (void *)slots[i], SLOT_LEN);
    }

    int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) {
        die("KVM_CREATE_VCPU");
    }
    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    struct kvm_run *run = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
    if (run == MAP_FAILED) {
        die("mmap kvm_run");
    }
    struct kvm_sregs s;
    if (ioctl(vcpu, KVM_GET_SREGS, &s) < 0) {
        die("KVM_GET_SREGS");
    }
    struct kvm_segment code = {.base = 0, .limit = 0xffffffff, .selector = 8, .type = 11, .present = 1,
                               .db = 1, .s = 1, .g = 1};
    struct kvm_segment data = code;
    data.selector = 16;
    data.type = 3;
    s.cs = code;
    s.ds = s.es = s.fs = s.gs = s.ss = data;
    s.cr0 |= 1;
    if (ioctl(vcpu, KVM_SET_SREGS, &s) < 0) {
        die("KVM_SET_SREGS");
    }
    struct kvm_regs r = {.rip = PROGRAM, .rsp = 0x9000, .rflags = 2};
    if (ioctl(vcpu, KVM_SET_REGS, &r) < 0) {
        die("KVM_SET_REGS");
    }
    int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (pagemap < 0) {
        die("open /proc/self/pagemap");
    }

    printf("LINUXGRAIN warm-up, the guest's first write to lazy guest RAM: the step %.1f us\n",
           step(vcpu, run, "warm-up"));
    static const struct {
        const char *name;
        double writes;
    } STEPS[] = {
        {"sparse, a byte in each 2 MiB of 64 MiB (32 writes)", 32},
        {"dense, a byte in each 4 KiB page of 4 MiB (1024 writes)", 1024},
    };
    for (size_t i = 0; i < NSLOTS; i++) {
        double per_page = 0;
        for (size_t k = 0; k < 2; k++) {
            long current0, anon0, current1, anon1, pages, blocks, ranges;
            unsigned long vs = 0, ve = 0;
            cgroup_memory(&current0, &anon0);
            double took = step(vcpu, run, STEPS[k].name);
            cgroup_memory(&current1, &anon1);
            present(pagemap, slots[i], SLOT_LEN, &pages, &blocks, &ranges);
            long huge = anon_huge(slots[i], &vs, &ve);
            char cg[128];
            if (current0 >= 0 && current1 >= 0) {
                snprintf(cg, sizeof cg, "the cgroup's memory.current %+ld KiB, anon %+ld KiB", (current1 - current0) / 1024,
                         anon0 >= 0 && anon1 >= 0 ? (anon1 - anon0) / 1024 : 0);
            } else {
                snprintf(cg, sizeof cg, "the cgroup's memory not read");
            }
            printf("LINUXGRAIN %s, %s: the step %.1f us, %.2f us a write; the slot after it: resident %ld KiB "
                   "(pages %ld, 64 KiB blocks %ld, 2 MiB ranges %ld); AnonHugePages %ld KiB of its mapping "
                   "%#lx-%#lx; %s\n",
                   SLOTS[i].name, STEPS[k].name, took, took / STEPS[k].writes, pages * 4, pages, blocks, ranges, huge,
                   vs, ve, cg);
            per_page = took / STEPS[k].writes;
        }
        printf("LINUXGRAIN %s: 256 MiB touched page by page, at the dense step's time a page: %.0f ms\n", SLOTS[i].name,
               per_page * 65536 / 1000);
    }
    fflush(stdout);
    return 0;
}
