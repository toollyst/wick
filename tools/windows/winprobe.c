// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// Windows capability probe for the jailer / sandbox backends (diagnostic, not
// product code). Each test runs in its own process because mitigation
// policies cannot be undone. `winprobe all` runs every test.

#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 0x00020009
#endif
#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x2
#endif
#define WIN32K_DISABLE_ALWAYS_ON (0x1ULL << 28)
#define MY_AF_UNIX 1
#define MY_SIO_AF_UNIX_GETPEERPID 0x58000100UL

typedef struct {
    ADDRESS_FAMILY sun_family;
    char sun_path[108];
} my_sockaddr_un;

typedef struct {
    PSID AppContainerSid;
    PSID_AND_ATTRIBUTES Capabilities;
    DWORD CapabilityCount;
    DWORD Reserved;
} my_security_capabilities;

// PROCESS_MITIGATION_POLICY values (winnt.h).
enum {
    P_DYNAMIC_CODE = 2,
    P_STRICT_HANDLE = 3,
    P_SYSCALL_DISABLE = 4,
    P_EXTENSION_POINT = 6,
    P_IMAGE_LOAD = 10,
    P_CHILD_PROCESS = 13,
};

static char g_self[MAX_PATH];
static int g_lpac; // spawn AppContainer children as LPAC
static int g_v2;   // use JOBOBJECT_EXTENDED_LIMIT_INFORMATION_V2
static int g_ws;   // job working-set limit instead of commit limit
static const char *g_ac_exe = "C:\\wickjail\\winprobe.exe";
static const wchar_t *g_caps[4];
static SID_AND_ATTRIBUTES g_cap_sids[4];

typedef struct {
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    IO_COUNTERS IoInfo;
    SIZE_T ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed, JobTotalMemoryLimit;
} ext_v2;

#define LOG(...) do { printf(__VA_ARGS__); fflush(stdout); } while (0)

static void chk(const char *what, BOOL ok) {
    DWORD e = GetLastError();
    LOG("    %-58s %s", what, ok ? "OK" : "FAIL");
    if (!ok) LOG(" (err %lu)", e);
    LOG("\n");
}

static BOOL set_policy(int policy, DWORD flags, const char *name) {
    typedef BOOL(WINAPI * F)(int, PVOID, SIZE_T);
    F f = (F)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetProcessMitigationPolicy");
    DWORD v = flags;
    BOOL ok = f && f(policy, &v, sizeof v);
    LOG("  set %-24s flags=0x%lx -> %s", name, flags, ok ? "applied" : "REFUSED");
    if (!ok) LOG(" (err %lu)", GetLastError());
    LOG("\n");
    return ok;
}

static DWORD get_policy(int policy) {
    typedef BOOL(WINAPI * F)(HANDLE, int, PVOID, SIZE_T);
    F f = (F)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessMitigationPolicy");
    DWORD v = 0xffffffff;
    if (!f || !f(GetCurrentProcess(), policy, &v, sizeof v)) return 0xffffffff;
    return v;
}

// What the Firecracker port needs at run time: memory, events, high
// resolution timers, IOCP (epoll), threads, files and AF_UNIX sockets.
static DWORD WINAPI thread_fn(LPVOID p) { (void)p; return 7; }

static void fc_needs(const char *dir) {
    LOG("  firecracker run-time needs:\n");
    void *p = VirtualAlloc(NULL, 1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    chk("VirtualAlloc RW 1 MiB", p != NULL);
    if (p) { ((volatile char *)p)[0] = 1; VirtualFree(p, 0, MEM_RELEASE); }
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    chk("CreateEvent", e != NULL);
    HANDLE t = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    chk("CreateWaitableTimerEx (high resolution)", t != NULL);
    HANDLE io = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    chk("CreateIoCompletionPort", io != NULL);
    HANDLE th = CreateThread(NULL, 0, thread_fn, NULL, 0, NULL);
    DWORD code = 0;
    BOOL tok = th && WaitForSingleObject(th, 5000) == WAIT_OBJECT_0 && GetExitCodeThread(th, &code) && code == 7;
    chk("CreateThread + join", tok);

    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\fcneeds.bin", dir);
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_FLAG_DELETE_ON_CLOSE, NULL);
    DWORD n = 0;
    BOOL fok = f != INVALID_HANDLE_VALUE && WriteFile(f, "abcd", 4, &n, NULL) && n == 4;
    chk("file create + write in jail dir", fok);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);

    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET s = socket(MY_AF_UNIX, SOCK_STREAM, 0);
    chk("socket(AF_UNIX)", s != INVALID_SOCKET);
    if (s != INVALID_SOCKET) {
        my_sockaddr_un a = {0};
        a.sun_family = MY_AF_UNIX;
        snprintf(a.sun_path, sizeof a.sun_path, "%s\\needs.sock", dir);
        DeleteFileA(a.sun_path);
        BOOL bok = bind(s, (struct sockaddr *)&a, sizeof a) == 0 && listen(s, 1) == 0;
        if (!bok) SetLastError(WSAGetLastError());
        chk("AF_UNIX bind + listen in jail dir", bok);
        closesocket(s);
        DeleteFileA(a.sun_path);
    }
}

static void whp_probe(void) {
    HMODULE h = LoadLibraryA("WinHvPlatform.dll");
    if (!h) {
        LOG("  WinHvPlatform.dll: not loadable (err %lu) -> Windows Hypervisor Platform feature off\n",
            GetLastError());
        return;
    }
    typedef HRESULT(WINAPI * Cap)(int, void *, UINT32, UINT32 *);
    Cap cap = (Cap)GetProcAddress(h, "WHvGetCapability");
    UINT64 present = 0;
    UINT32 written = 0;
    HRESULT hr = cap ? cap(0 /* HypervisorPresent */, &present, sizeof present, &written) : E_FAIL;
    LOG("  WHvGetCapability(HypervisorPresent): hr=0x%08lx present=%llu\n", (unsigned long)hr,
        (unsigned long long)present);
    const char *fns[] = {"WHvCreatePartition", "WHvSetupPartition", "WHvMapGpaRange", "WHvMapGpaRange2",
                         "WHvRunVirtualProcessor", "WHvRequestInterrupt", "WHvQueryGpaRangeDirtyBitmap",
                         "WHvGetVirtualProcessorInterruptControllerState2"};
    for (size_t i = 0; i < sizeof fns / sizeof *fns; i++)
        LOG("    export %-48s %s\n", fns[i], GetProcAddress(h, fns[i]) ? "yes" : "no");
    if (present) {
        typedef HRESULT(WINAPI * Create)(void **);
        Create cr = (Create)GetProcAddress(h, "WHvCreatePartition");
        void *part = NULL;
        hr = cr ? cr(&part) : E_FAIL;
        LOG("  WHvCreatePartition: hr=0x%08lx\n", (unsigned long)hr);
        typedef HRESULT(WINAPI * Del)(void *);
        Del del = (Del)GetProcAddress(h, "WHvDeletePartition");
        if (SUCCEEDED(hr) && del) del(part);
    }
}

// --- win32k lockdown ---------------------------------------------------------

static void win32k_after(void) {
    LOG("  ProcessSystemCallDisablePolicy now: 0x%lx\n", get_policy(P_SYSCALL_DISABLE));
    char tmp[MAX_PATH];
    GetTempPathA(sizeof tmp, tmp);
    tmp[strlen(tmp) - 1] = 0;
    fc_needs(tmp);
    HMODULE u = LoadLibraryA("user32.dll");
    LOG("  LoadLibrary(user32) after lockdown: %s (err %lu)\n", u ? "loaded" : "failed", GetLastError());
    if (u) {
        typedef HWND(WINAPI * G)(void);
        G g = (G)GetProcAddress(u, "GetDesktopWindow");
        HWND hw = g ? g() : NULL;
        LOG("  GetDesktopWindow (a win32k call): %p\n", (void *)hw);
    }
}

static int t_w32k(void) {
    LOG("  user32 already loaded at start: %s\n", GetModuleHandleA("user32.dll") ? "yes" : "no");
    set_policy(P_SYSCALL_DISABLE, 1, "win32k disable");
    win32k_after();
    return 0;
}

static int spawn(const char *args, DWORD64 mitigation, my_security_capabilities *sc, HANDLE job,
                 DWORD timeout_ms, DWORD *exit_code, PROCESS_INFORMATION *out_pi);

static int t_w32k_create(void) {
    DWORD code;
    spawn("w32k-child", WIN32K_DISABLE_ALWAYS_ON, NULL, NULL, 30000, &code, NULL);
    LOG("  child exit code: %lu (0x%lx)\n", code, code);
    return 0;
}

static int t_w32k_child(void) {
    LOG("  (child created with PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON)\n");
    win32k_after();
    return 0;
}

// --- FSCTL disable ------------------------------------------------------------

static void fsctl_ops(const char *label, const char *path, BOOL set_sparse) {
    HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { LOG("  open %s failed %lu\n", path, GetLastError()); return; }
    LOG("  %s:\n", label);
    DWORD n;
    if (set_sparse) chk("FSCTL_SET_SPARSE", DeviceIoControl(f, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &n, NULL));
    FILE_ZERO_DATA_INFORMATION z;
    z.FileOffset.QuadPart = 0;
    z.BeyondFinalZero.QuadPart = 65536;
    chk("FSCTL_SET_ZERO_DATA (punch hole)", DeviceIoControl(f, FSCTL_SET_ZERO_DATA, &z, sizeof z, NULL, 0, &n, NULL));
    FILE_ALLOCATED_RANGE_BUFFER q, r[8];
    memset(&q, 0, sizeof q);
    q.Length.QuadPart = 1 << 20;
    chk("FSCTL_QUERY_ALLOCATED_RANGES (SEEK_DATA/HOLE)",
        DeviceIoControl(f, FSCTL_QUERY_ALLOCATED_RANGES, &q, sizeof q, r, sizeof r, &n, NULL));
    FILE_END_OF_FILE_INFO eof;
    eof.EndOfFile.QuadPart = 2 << 20;
    chk("SetFileInformationByHandle(EndOfFile) (ftruncate)",
        SetFileInformationByHandle(f, FileEndOfFileInfo, &eof, sizeof eof));
    char buf[4096] = {1};
    LARGE_INTEGER off;
    off.QuadPart = 0;
    SetFilePointerEx(f, off, NULL, FILE_BEGIN);
    chk("WriteFile", WriteFile(f, buf, sizeof buf, &n, NULL));
    chk("FlushFileBuffers (fsync)", FlushFileBuffers(f));
    CloseHandle(f);
}

static int t_fsctl(void) {
    char tmp[MAX_PATH], a[MAX_PATH + 16], b[MAX_PATH + 16];
    GetTempPathA(sizeof tmp, tmp);
    snprintf(a, sizeof a, "%sfsctl_a.bin", tmp);
    snprintf(b, sizeof b, "%sfsctl_b.bin", tmp);
    DeleteFileA(a);
    DeleteFileA(b);
    fsctl_ops("baseline, before the policy (file A)", a, TRUE);
    set_policy(P_SYSCALL_DISABLE, 1u << 2, "FSCTL disable");
    LOG("  ProcessSystemCallDisablePolicy now: 0x%lx\n", get_policy(P_SYSCALL_DISABLE));
    fsctl_ops("after the policy, file A (made sparse before)", a, FALSE);
    fsctl_ops("after the policy, new file B", b, TRUE);
    tmp[strlen(tmp) - 1] = 0;
    fc_needs(tmp);
    DeleteFileA(a);
    DeleteFileA(b);
    return 0;
}

// --- ACG and the combined production profile ----------------------------------

static int t_acg(void) {
    set_policy(P_DYNAMIC_CODE, 1, "ACG (prohibit dyn code)");
    void *x = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LOG("  VirtualAlloc RWX: %s (err %lu)  [expected: blocked]\n", x ? "ALLOWED" : "blocked", GetLastError());
    void *p = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD old;
    BOOL vp = p && VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old);
    LOG("  VirtualProtect RW->RX: %s (err %lu)  [expected: blocked]\n", vp ? "ALLOWED" : "blocked", GetLastError());
    char tmp[MAX_PATH];
    GetTempPathA(sizeof tmp, tmp);
    tmp[strlen(tmp) - 1] = 0;
    fc_needs(tmp);
    whp_probe();
    return 0;
}

static int t_profile_child(void) {
    LOG("  (child created with win32k lockdown)\n");
    set_policy(P_DYNAMIC_CODE, 1, "ACG");
    set_policy(P_STRICT_HANDLE, 3, "strict handle checks");
    set_policy(P_EXTENSION_POINT, 1, "extension point disable");
    set_policy(P_IMAGE_LOAD, 1 | 2 | 4, "image load (no remote/low)");
    set_policy(P_CHILD_PROCESS, 1, "no child processes");
    char tmp[MAX_PATH];
    GetTempPathA(sizeof tmp, tmp);
    tmp[strlen(tmp) - 1] = 0;
    fc_needs(tmp);
    whp_probe();
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c exit 0";
    BOOL c = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    LOG("  CreateProcess(cmd.exe): %s (err %lu)  [expected: blocked]\n", c ? "ALLOWED" : "blocked", GetLastError());
    // Strict handle checks raise on an invalid handle: the compat libc's fd
    // table must never touch a closed handle value.
    LOG("  closing an already-closed handle under strict checks (expect exception exit 0xC0000008)...\n");
    HANDLE e = CreateEventW(NULL, FALSE, FALSE, NULL);
    CloseHandle(e);
    CloseHandle(e);
    LOG("  survived double close (strict checks not raising)\n");
    return 0;
}

static int t_profile(void) {
    DWORD code;
    spawn("profile-child", WIN32K_DISABLE_ALWAYS_ON, NULL, NULL, 30000, &code, NULL);
    LOG("  child exit code: %lu (0x%lx)\n", code, code);
    return 0;
}

// --- Job Object: memory and CPU ------------------------------------------------

static const char *job_msg(DWORD m) {
    switch (m) {
    case 1: return "END_OF_JOB_TIME";
    case 2: return "END_OF_PROCESS_TIME";
    case 3: return "ACTIVE_PROCESS_LIMIT";
    case 4: return "ACTIVE_PROCESS_ZERO";
    case 6: return "NEW_PROCESS";
    case 7: return "EXIT_PROCESS";
    case 8: return "ABNORMAL_EXIT_PROCESS";
    case 9: return "PROCESS_MEMORY_LIMIT";
    case 10: return "JOB_MEMORY_LIMIT";
    default: return "?";
    }
}

static int job_mem(const char *mode) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
    memset(&li, 0, sizeof li);
    li.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    li.BasicLimitInformation.ActiveProcessLimit = 1;
    li.JobMemoryLimit = 256u << 20;
    if (g_ws) {
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_WORKINGSET | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        li.BasicLimitInformation.MinimumWorkingSetSize = 16u << 20;
        li.BasicLimitInformation.MaximumWorkingSetSize = 256u << 20;
        chk("SetInformationJobObject(working set max 256 MiB)",
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li));
    } else if (g_v2) {
        ext_v2 v;
        memset(&v, 0, sizeof v);
        v.BasicLimitInformation = li.BasicLimitInformation;
        v.JobMemoryLimit = 256u << 20;
        v.JobTotalMemoryLimit = 256u << 20;
        chk("SetInformationJobObject(V2: job + total memory 256 MiB)",
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &v, sizeof v));
    } else
    chk("SetInformationJobObject(job memory 256 MiB, 1 process)",
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li));
    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp = {job, port};
    SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof acp);
    char args[64];
    snprintf(args, sizeof args, "mem-child %s", mode);
    PROCESS_INFORMATION pi;
    DWORD code = 0;
    spawn(args, 0, NULL, job, 0, &code, &pi);
    for (;;) {
        DWORD msg;
        ULONG_PTR key;
        LPOVERLAPPED ov;
        if (!GetQueuedCompletionStatus(port, &msg, &key, &ov, 20000)) { LOG("  job: no message in 20 s\n"); break; }
        LOG("  job message: %s\n", job_msg(msg));
        if (msg == 10 || msg == 9) {
            LOG("  -> memory limit reached: terminating the job (cgroup OOM-kill semantics)\n");
            TerminateJobObject(job, 137);
        }
        if (msg == 4) break;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    GetExitCodeProcess(pi.hProcess, &code);
    LOG("  child exit code: %lu\n", code);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION after;
    QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &after, sizeof after, NULL);
    LOG("  job peak memory used: %llu MiB\n", (unsigned long long)(after.PeakJobMemoryUsed >> 20));
    return 0;
}

static void touch(char *p, SIZE_T n) {
    for (SIZE_T i = 0; i < n; i += 4096) p[i] = 1;
}

static int t_mem_child(const char *mode) {
    const SIZE_T chunk = 16u << 20;
    if (strcmp(mode, "private") == 0) {
        // Firecracker guest memory: anonymous private mapping.
        for (int i = 1; i <= 40; i++) {
            char *p = VirtualAlloc(NULL, chunk, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!p) { LOG("  [child] private commit failed at %d MiB (err %lu)\n", (i - 1) * 16, GetLastError()); break; }
            touch(p, chunk);
            if (i % 8 == 0) LOG("  [child] private committed+touched %d MiB\n", i * 16);
        }
    } else if (strcmp(mode, "section") == 0) {
        // memfd-like shared memory on the paging file (MAP_SHARED anonymous).
        HANDLE s = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT, 0, 640u << 20, NULL);
        if (!s) { LOG("  [child] pagefile section 640 MiB refused (err %lu)\n", GetLastError()); }
        else {
            char *p = MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, 0);
            LOG("  [child] pagefile section 640 MiB created, view %p\n", (void *)p);
            if (p) { touch(p, 640u << 20); LOG("  [child] touched 640 MiB of the section\n"); }
        }
    } else if (strcmp(mode, "file") == 0) {
        // memfd as implemented today: a delete-on-close temp file.
        char tmp[MAX_PATH], path[MAX_PATH + 16];
        GetTempPathA(sizeof tmp, tmp);
        snprintf(path, sizeof path, "%smemfd_probe.bin", tmp);
        HANDLE f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        HANDLE s = CreateFileMappingW(f, NULL, PAGE_READWRITE, 0, 640u << 20, NULL);
        char *p = s ? MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, 0) : NULL;
        LOG("  [child] file-backed 640 MiB mapping: %p (err %lu)\n", (void *)p, GetLastError());
        if (p) { touch(p, 640u << 20); LOG("  [child] touched 640 MiB of the file mapping\n"); }
    }
    {
        typedef struct { DWORD cb, PageFaultCount; SIZE_T PeakWorkingSetSize, WorkingSetSize, a, b, c, d, PagefileUsage, PeakPagefileUsage; } pmc_t;
        typedef BOOL(WINAPI * G)(HANDLE, pmc_t *, DWORD);
        G g = (G)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetProcessMemoryInfo");
        pmc_t m = {sizeof m};
        if (g && g(GetCurrentProcess(), &m, sizeof m))
            LOG("  [child] working set now %llu MiB, peak %llu MiB\n", (unsigned long long)(m.WorkingSetSize >> 20),
                (unsigned long long)(m.PeakWorkingSetSize >> 20));
    }
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c exit 0";
    BOOL c = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    LOG("  [child] CreateProcess inside the 1-process job: %s (err %lu)\n", c ? "ALLOWED" : "blocked", GetLastError());
    LOG("  [child] sleeping (the parent should kill on the limit)\n");
    Sleep(4000);
    LOG("  [child] still alive at exit\n");
    return 0;
}

static int t_job_cpu(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cr;
    memset(&cr, 0, sizeof cr);
    cr.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cr.CpuRate = 500; // 5% of the whole machine
    chk("CPU rate hard cap 5%", SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cr, sizeof cr));
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LOG("  processors: %lu -> a 5%% cap = %.2f of one core\n", si.dwNumberOfProcessors,
        0.05 * si.dwNumberOfProcessors);
    DWORD code;
    spawn("spin", 0, NULL, job, 30000, &code, NULL);
    return 0;
}

static int t_spin(void) {
    ULONGLONG start = GetTickCount64();
    volatile unsigned long long x = 0;
    while (GetTickCount64() - start < 3000) x++;
    (void)x;
    FILETIME c, e, k, u;
    GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
    ULARGE_INTEGER uu;
    uu.LowPart = u.dwLowDateTime;
    uu.HighPart = u.dwHighDateTime;
    LOG("  [child] busy 3.0 s wall -> %.2f s user CPU (uncapped would be ~3.0)\n", uu.QuadPart / 1e7);
    return 0;
}

// --- AppContainer (chroot + uid + netns) -----------------------------------------

typedef HRESULT(WINAPI *CreateAC)(PCWSTR, PCWSTR, PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID *);
typedef HRESULT(WINAPI *DeriveAC)(PCWSTR, PSID *);
typedef HRESULT(WINAPI *DeleteAC)(PCWSTR);

static BOOL grant_dir(const wchar_t *dir, PSID sid, DWORD rights) {
    PACL old = NULL, acl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    if (GetNamedSecurityInfoW(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &old, NULL, &sd))
        return FALSE;
    EXPLICIT_ACCESS_W ea;
    memset(&ea, 0, sizeof ea);
    ea.grfAccessPermissions = rights;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)sid;
    if (SetEntriesInAclW(1, &ea, old, &acl)) return FALSE;
    return SetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL) == 0;
}

static int t_appcontainer(void) {
    HMODULE ue = LoadLibraryA("userenv.dll");
    CreateAC create = (CreateAC)GetProcAddress(ue, "CreateAppContainerProfile");
    DeriveAC derive = (DeriveAC)GetProcAddress(ue, "DeriveAppContainerSidFromAppContainerName");
    DeleteAC del = (DeleteAC)GetProcAddress(ue, "DeleteAppContainerProfile");
    const wchar_t *name = L"wickprobe.jail";
    PSID sid = NULL;
    del(name);
    HRESULT hr = create(name, L"wickprobe", L"wickprobe jail", NULL, 0, &sid);
    if (FAILED(hr)) hr = derive(name, &sid);
    LOG("  AppContainer profile: hr=0x%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) return 1;

    const wchar_t *jail = L"C:\\wickjail";
    CreateDirectoryW(jail, NULL);
    chk("grant the AppContainer SID full access to C:\\wickjail", grant_dir(jail, sid, GENERIC_ALL));
    chk("copy winprobe.exe into the jail (like jailer --exec-file)",
        CopyFileA(g_self, "C:\\wickjail\\winprobe.exe", FALSE));

    char secret[MAX_PATH];
    ExpandEnvironmentStringsA("%USERPROFILE%\\wickprobe-secret.txt", secret, sizeof secret);
    HANDLE sf = CreateFileA(secret, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n;
    WriteFile(sf, "secret", 6, &n, NULL);
    CloseHandle(sf);

    // Parent listens on loopback TCP so the child can try to reach the host.
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET tl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la = {0};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(tl, (struct sockaddr *)&la, sizeof la);
    listen(tl, 1);
    int ll = sizeof la;
    getsockname(tl, (struct sockaddr *)&la, &ll);

    my_security_capabilities sc = {sid, NULL, 0, 0};
    typedef BOOL(WINAPI * DeriveCap)(LPCWSTR, PSID **, DWORD *, PSID **, DWORD *);
    DeriveCap dc = (DeriveCap)GetProcAddress(LoadLibraryA("kernelbase.dll"), "DeriveCapabilitySidsFromName");
    DWORD ncap = 0;
    for (int i = 0; i < 4 && g_caps[i]; i++) {
        PSID *gs, *cs;
        DWORD gn, cn;
        if (dc && dc(g_caps[i], &gs, &gn, &cs, &cn) && cn) {
            g_cap_sids[ncap].Sid = cs[0];
            g_cap_sids[ncap].Attributes = SE_GROUP_ENABLED;
            ncap++;
            LOG("  capability %ls added\n", g_caps[i]);
        }
    }
    if (ncap) { sc.Capabilities = g_cap_sids; sc.CapabilityCount = ncap; }
    char args[600];
    snprintf(args, sizeof args, "ac-child \"%s\" %lu %u", secret, GetCurrentProcessId(), ntohs(la.sin_port));
    PROCESS_INFORMATION pi;
    DWORD code = 0;
    if (spawn(args, 0, &sc, NULL, 0, &code, &pi)) return 1;

    // Act as the API client: connect to the child's AF_UNIX socket.
    SOCKET c = INVALID_SOCKET;
    my_sockaddr_un a = {0};
    a.sun_family = MY_AF_UNIX;
    strcpy(a.sun_path, "C:\\wickjail\\api.sock");
    for (int i = 0; i < 150 && c == INVALID_SOCKET; i++) {
        SOCKET s = socket(MY_AF_UNIX, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) c = s;
        else { closesocket(s); Sleep(100); }
    }
    LOG("  [parent] connect to the jailed AF_UNIX API socket: %s\n", c != INVALID_SOCKET ? "OK" : "FAIL");
    if (c != INVALID_SOCKET) {
        ULONG peer = 0;
        DWORD br = 0;
        WSAIoctl(c, MY_SIO_AF_UNIX_GETPEERPID, NULL, 0, &peer, sizeof peer, &br, NULL, NULL);
        LOG("  [parent] SIO_AF_UNIX_GETPEERPID = %lu (child pid %lu) %s\n", peer, pi.dwProcessId,
            peer == pi.dwProcessId ? "OK" : "MISMATCH");
        // fd passing, privileged side pushes: duplicate an event into the child.
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL), remote = NULL;
        BOOL d = DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &remote, 0, FALSE, DUPLICATE_SAME_ACCESS);
        LOG("  [parent] DuplicateHandle(event -> jailed child): %s\n", d ? "OK" : "FAIL");
        char msg[32];
        snprintf(msg, sizeof msg, "%llu", (unsigned long long)(ULONG_PTR)remote);
        send(c, msg, (int)strlen(msg) + 1, 0);
        DWORD wr = WaitForSingleObject(ev, 10000);
        LOG("  [parent] child signalled the pushed event: %s\n", wr == WAIT_OBJECT_0 ? "OK" : "NO");
        closesocket(c);
    }
    WaitForSingleObject(pi.hProcess, 20000);
    GetExitCodeProcess(pi.hProcess, &code);
    LOG("  [parent] child exit code %lu\n", code);
    DeleteFileA(secret);
    del(name);
    return 0;
}

static int t_ac_child(const char *secret, DWORD ppid, int port) {
    HANDLE tok;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
    DWORD isac = 0, len;
    GetTokenInformation(tok, TokenIsAppContainer, &isac, sizeof isac, &len);
    LOG("  [jailed] token is AppContainer: %s\n", isac ? "yes" : "NO");

    HANDLE f = CreateFileA(secret, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    LOG("  [jailed] read %%USERPROFILE%% secret: %s (err %lu)  [expected: denied]\n",
        f != INVALID_HANDLE_VALUE ? "READABLE" : "denied", GetLastError());
    f = CreateFileA("C:\\Users\\Public\\Documents\\wickprobe.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    LOG("  [jailed] write C:\\Users\\Public\\Documents: %s (err %lu)  [expected: denied]\n",
        f != INVALID_HANDLE_VALUE ? "WRITABLE" : "denied", GetLastError());
    if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); DeleteFileA("C:\\Users\\Public\\Documents\\wickprobe.txt"); }
    f = CreateFileA("C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    LOG("  [jailed] read C:\\Windows\\System32\\drivers\\etc\\hosts: %s (err %lu)  [chroot would hide it]\n",
        f != INVALID_HANDLE_VALUE ? "readable" : "denied", GetLastError());
    f = CreateFileA("C:\\wickjail\\inside.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    LOG("  [jailed] write inside the jail: %s (err %lu)  [expected: OK]\n",
        f != INVALID_HANDLE_VALUE ? "OK" : "FAIL", GetLastError());
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);

    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    // Network: internet and host loopback.
    struct { const char *what; const char *ip; int port; } targets[] = {
        {"internet 1.1.1.1:80", "1.1.1.1", 80}, {"host loopback (parent listener)", "127.0.0.1", port}};
    for (int i = 0; i < 2; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) { LOG("  [jailed] TCP socket(): denied (err %d)\n", WSAGetLastError()); continue; }
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons((u_short)targets[i].port);
        inet_pton(AF_INET, targets[i].ip, &sa.sin_addr);
        connect(s, (struct sockaddr *)&sa, sizeof sa);
        fd_set wf, ef;
        FD_ZERO(&wf);
        FD_ZERO(&ef);
        FD_SET(s, &wf);
        FD_SET(s, &ef);
        struct timeval tv = {3, 0};
        int r = select(0, NULL, &wf, &ef, &tv);
        int soerr = 0, sl = sizeof soerr;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
        BOOL connected = r > 0 && FD_ISSET(s, &wf) && soerr == 0;
        LOG("  [jailed] TCP connect %s: %s (so_error %d)  [expected: blocked]\n", targets[i].what,
            connected ? "CONNECTED" : "blocked", soerr);
        closesocket(s);
    }

    HANDLE pp = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ppid);
    LOG("  [jailed] OpenProcess(parent, PROCESS_DUP_HANDLE): %s (err %lu)  [jailed side cannot push fds]\n",
        pp ? "ALLOWED" : "denied", GetLastError());
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    char cmd[] = "cmd.exe /c exit 0";
    BOOL c = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    DWORD cerr = GetLastError();
    LOG("  [jailed] CreateProcess(cmd.exe): %s (err %lu)\n", c ? "ALLOWED (needs the child policy)" : "blocked",
        c ? 0 : cerr);
    whp_probe();
    fc_needs("C:\\wickjail");

    // API socket server.
    SOCKET s = socket(MY_AF_UNIX, SOCK_STREAM, 0);
    my_sockaddr_un a = {0};
    a.sun_family = MY_AF_UNIX;
    strcpy(a.sun_path, "C:\\wickjail\\api.sock");
    DeleteFileA(a.sun_path);
    int b = bind(s, (struct sockaddr *)&a, sizeof a);
    int l = listen(s, 1);
    LOG("  [jailed] AF_UNIX API socket bind/listen: %s (err %d)\n", b == 0 && l == 0 ? "OK" : "FAIL",
        WSAGetLastError());
    SOCKET cl = accept(s, NULL, NULL);
    if (cl != INVALID_SOCKET) {
        ULONG peer = 0;
        DWORD br = 0;
        WSAIoctl(cl, MY_SIO_AF_UNIX_GETPEERPID, NULL, 0, &peer, sizeof peer, &br, NULL, NULL);
        LOG("  [jailed] accepted; GETPEERPID = %lu (parent %lu) %s\n", peer, ppid, peer == ppid ? "OK" : "MISMATCH");
        char msg[32] = {0};
        recv(cl, msg, sizeof msg - 1, 0);
        HANDLE ev = (HANDLE)(ULONG_PTR)_strtoui64(msg, NULL, 10);
        LOG("  [jailed] SetEvent on the pushed handle: %s\n", SetEvent(ev) ? "OK" : "FAIL");
        closesocket(cl);
    }
    closesocket(s);
    DeleteFileA(a.sun_path);
    return 0;
}

// --- large pages ----------------------------------------------------------------

static BOOL enable_priv(const wchar_t *name) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return FALSE;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) return FALSE;
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    return GetLastError() == ERROR_SUCCESS;
}

typedef struct { PVOID va; ULONG_PTR attr; } wsex;

static void report_large(FILE *o, const char *what, void *p) {
    typedef BOOL(WINAPI * Q)(HANDLE, PVOID, DWORD);
    Q q = (Q)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32QueryWorkingSetEx");
    wsex w = {p, 0};
    BOOL ok = q && q(GetCurrentProcess(), &w, sizeof w);
    fprintf(o, "    %s: valid=%d large_page=%d (query %s)\n", what, (int)(w.attr & 1), (int)((w.attr >> 23) & 1),
            ok ? "ok" : "failed");
}

static int t_lp_child(void) {
    FILE *o = fopen("C:\\fclp\\out.txt", "w");
    if (!o) return 1;
    SIZE_T lpm = GetLargePageMinimum();
    fprintf(o, "    GetLargePageMinimum = %llu KiB\n", (unsigned long long)(lpm >> 10));
    BOOL pr = enable_priv(L"SeLockMemoryPrivilege");
    fprintf(o, "    enable SeLockMemoryPrivilege: %s (err %lu)\n", pr ? "OK" : "FAIL", GetLastError());
    char *p = VirtualAlloc(NULL, 2 * lpm, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    fprintf(o, "    VirtualAlloc(MEM_LARGE_PAGES, 2 pages): %s (err %lu)\n", p ? "OK" : "FAIL", GetLastError());
    if (p) { p[0] = 1; report_large(o, "private large allocation", p); }
    HANDLE s = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES, 0,
                                  (DWORD)(2 * lpm), NULL);
    fprintf(o, "    CreateFileMapping(SEC_LARGE_PAGES): %s (err %lu)\n", s ? "OK" : "FAIL", GetLastError());
    if (s) {
        char *v = MapViewOfFile(s, FILE_MAP_ALL_ACCESS | FILE_MAP_LARGE_PAGES, 0, 0, 0);
        fprintf(o, "    MapViewOfFile(FILE_MAP_LARGE_PAGES): %s (err %lu)\n", v ? "OK" : "FAIL", GetLastError());
        if (v) { v[0] = 1; report_large(o, "shared large section", v); }
    }
    fclose(o);
    HMODULE ue = LoadLibraryA("userenv.dll");
    CreateAC create = (CreateAC)GetProcAddress(ue, "CreateAppContainerProfile");
    DeriveAC derive = (DeriveAC)GetProcAddress(ue, "DeriveAppContainerSidFromAppContainerName");
    PSID sid = NULL;
    if (FAILED(create(L"wickprobe.lp", L"wickprobe", L"wickprobe", NULL, 0, &sid))) derive(L"wickprobe.lp", &sid);
    my_security_capabilities sc = {sid, NULL, 0, 0};
    g_ac_exe = "C:\\fclp\\winprobe.exe";
    DWORD code;
    spawn("lp-ac", 0, &sc, NULL, 20000, &code, NULL);
    return 0;
}

static int t_lp_ac(void) {
    FILE *o = fopen("C:\\fclp\\out2.txt", "w");
    if (!o) return 1;
    SIZE_T lpm = GetLargePageMinimum();
    BOOL pr = enable_priv(L"SeLockMemoryPrivilege");
    fprintf(o, "    [AppContainer] enable SeLockMemoryPrivilege: %s (err %lu)\n", pr ? "OK" : "FAIL", GetLastError());
    char *p = VirtualAlloc(NULL, 2 * lpm, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    fprintf(o, "    [AppContainer] VirtualAlloc(MEM_LARGE_PAGES): %s (err %lu)\n", p ? "OK" : "FAIL", GetLastError());
    if (p) { p[0] = 1; report_large(o, "[AppContainer] private large allocation", p); }
    fclose(o);
    return 0;
}

static int t_largepages(void) {
    LOG("  GetLargePageMinimum = %llu KiB\n", (unsigned long long)(GetLargePageMinimum() >> 10));
    BOOL own = enable_priv(L"SeLockMemoryPrivilege");
    LOG("  current (admin) token has SeLockMemoryPrivilege: %s\n", own ? "yes" : "no");
    const wchar_t *user = L"wickprobe", *pw = L"Fc-probe-9x!Q7";
    system("net user wickprobe /delete >NUL 2>&1");
    int r = system("net user wickprobe Fc-probe-9x!Q7 /add >NUL");
    LOG("  create local user wickprobe: %s\n", r == 0 ? "OK" : "FAIL");
    BYTE sidbuf[SECURITY_MAX_SID_SIZE];
    DWORD sl = sizeof sidbuf, dl = 64;
    wchar_t dom[64];
    SID_NAME_USE use;
    LookupAccountNameW(NULL, user, sidbuf, &sl, dom, &dl, &use);
    LSA_OBJECT_ATTRIBUTES oa;
    memset(&oa, 0, sizeof oa);
    LSA_HANDLE lsa;
    NTSTATUS st = LsaOpenPolicy(NULL, &oa, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &lsa);
    LSA_UNICODE_STRING right;
    wchar_t rn[] = L"SeLockMemoryPrivilege";
    right.Buffer = rn;
    right.Length = (USHORT)(wcslen(rn) * sizeof(wchar_t));
    right.MaximumLength = right.Length + sizeof(wchar_t);
    if (st == 0) st = LsaAddAccountRights(lsa, sidbuf, &right, 1);
    LOG("  grant SeLockMemoryPrivilege to wickprobe (LsaAddAccountRights): status 0x%08lx\n", (unsigned long)st);

    CreateDirectoryW(L"C:\\fclp", NULL);
    PSID everyone = NULL;
    ConvertStringSidToSidW(L"S-1-1-0", &everyone);
    grant_dir(L"C:\\fclp", everyone, GENERIC_ALL);
    PSID allpkg = NULL;
    ConvertStringSidToSidW(L"S-1-15-2-1", &allpkg);
    grant_dir(L"C:\\fclp", allpkg, GENERIC_ALL);
    CopyFileA(g_self, "C:\\fclp\\winprobe.exe", FALSE);
    DeleteFileA("C:\\fclp\\out2.txt");
    DeleteFileA("C:\\fclp\\out.txt");
    STARTUPINFOW si;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"C:\\fclp\\winprobe.exe lp-child";
    BOOL ok = CreateProcessWithLogonW(user, L".", pw, LOGON_WITH_PROFILE, NULL, cmd, CREATE_NO_WINDOW, NULL,
                                      L"C:\\fclp", &si, &pi);
    LOG("  run the probe as wickprobe (new logon token): %s (err %lu)\n", ok ? "OK" : "FAIL", GetLastError());
    if (ok) {
        WaitForSingleObject(pi.hProcess, 30000);
        FILE *o = fopen("C:\\fclp\\out.txt", "r");
        char line[256];
        while (o && fgets(line, sizeof line, o)) LOG("%s", line);
        if (o) fclose(o);
        o = fopen("C:\\fclp\\out2.txt", "r");
        LOG("  large pages inside an AppContainer (child of the privileged user):\n");
        while (o && fgets(line, sizeof line, o)) LOG("%s", line);
        if (!o) LOG("    (no output from the AppContainer child)\n");
        if (o) fclose(o);
    }
    system("net user wickprobe /delete >NUL 2>&1");
    return 0;
}

// --- process plumbing ------------------------------------------------------------

static int spawn(const char *args, DWORD64 mitigation, my_security_capabilities *sc, HANDLE job,
                 DWORD timeout_ms, DWORD *exit_code, PROCESS_INFORMATION *out_pi) {
    char cmd[1024];
    const char *exe = sc ? g_ac_exe : g_self;
    snprintf(cmd, sizeof cmd, "\"%s\" %s", exe, args);
    SIZE_T sz = 0;
    int nattr = (mitigation ? 1 : 0) + (sc ? 1 : 0) + (sc && g_lpac ? 1 : 0);
    DWORD lpac = 1; // PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
    LPPROC_THREAD_ATTRIBUTE_LIST al = NULL;
    if (nattr) {
        InitializeProcThreadAttributeList(NULL, nattr, 0, &sz);
        al = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
        InitializeProcThreadAttributeList(al, nattr, 0, &sz);
        if (mitigation)
            UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation, sizeof mitigation,
                                      NULL, NULL);
        if (sc)
            UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, sc, sizeof *sc, NULL, NULL);
        if (sc && g_lpac)
            chk("LPAC attribute (ALL_APPLICATION_PACKAGES opt-out)",
                UpdateProcThreadAttribute(al, 0, 0x0002000F, &lpac, sizeof lpac, NULL, NULL));
    }
    STARTUPINFOEXA si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    si.lpAttributeList = al;
    PROCESS_INFORMATION pi;
    DWORD flags = (al ? EXTENDED_STARTUPINFO_PRESENT : 0) | (job ? CREATE_SUSPENDED : 0);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si.StartupInfo, &pi)) {
        LOG("  spawn '%s' failed (err %lu)\n", args, GetLastError());
        *exit_code = 0xffffffff;
        return 1;
    }
    if (job) {
        chk("AssignProcessToJobObject", AssignProcessToJobObject(job, pi.hProcess));
        ResumeThread(pi.hThread);
    }
    if (out_pi) { *out_pi = pi; return 0; }
    if (WaitForSingleObject(pi.hProcess, timeout_ms ? timeout_ms : INFINITE) != WAIT_OBJECT_0) {
        LOG("  child timed out\n");
        TerminateProcess(pi.hProcess, 1);
    }
    GetExitCodeProcess(pi.hProcess, exit_code);
    return 0;
}

static const char *ALL[] = {"whp",     "w32k",        "w32k-create",  "fsctl",      "acg",     "profile",
                            "job-mem-private", "job-mem-section", "job-mem-file", "job-cpu", "appcontainer",
                            "largepages"};

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    GetModuleFileNameA(NULL, g_self, sizeof g_self);
    const char *t = argc > 1 ? argv[1] : "all";
    if (!strcmp(t, "all")) {
        for (size_t i = 0; i < sizeof ALL / sizeof *ALL; i++) {
            LOG("\n=== %s ===\n", ALL[i]);
            DWORD code;
            spawn(ALL[i], 0, NULL, NULL, 120000, &code, NULL);
            LOG("=== %s: exit 0x%lx ===\n", ALL[i], code);
        }
        return 0;
    }
    if (!strcmp(t, "whp")) { whp_probe(); return 0; }
    if (!strcmp(t, "w32k")) return t_w32k();
    if (!strcmp(t, "w32k-create")) return t_w32k_create();
    if (!strcmp(t, "w32k-child")) return t_w32k_child();
    if (!strcmp(t, "fsctl")) return t_fsctl();
    if (!strcmp(t, "acg")) return t_acg();
    if (!strcmp(t, "profile")) return t_profile();
    if (!strcmp(t, "profile-child")) return t_profile_child();
    if (!strcmp(t, "job-mem-private")) return job_mem("private");
    if (!strcmp(t, "job-mem-section")) return job_mem("section");
    if (!strcmp(t, "job-mem-file")) return job_mem("file");
    if (!strcmp(t, "mem-child") && argc > 2) return t_mem_child(argv[2]);
    if (!strcmp(t, "job-cpu")) return t_job_cpu();
    if (!strcmp(t, "spin")) return t_spin();
    if (!strcmp(t, "appcontainer")) return t_appcontainer();
    if (!strcmp(t, "appcontainer-lpac")) { g_lpac = 1; return t_appcontainer(); }
    if (!strcmp(t, "job-v2-private")) { g_v2 = 1; return job_mem("private"); }
    if (!strcmp(t, "job-v2-section")) { g_v2 = 1; return job_mem("section"); }
    if (!strcmp(t, "job-v2-file")) { g_v2 = 1; return job_mem("file"); }
    if (!strcmp(t, "lp-ac")) return t_lp_ac();
    if (!strcmp(t, "ac-lpac-caps")) { g_lpac = 1; g_caps[0] = L"registryRead"; g_caps[1] = L"lpacCom"; return t_appcontainer(); }
    if (!strcmp(t, "job-ws-private")) { g_ws = 1; return job_mem("private"); }
    if (!strcmp(t, "job-ws-section")) { g_ws = 1; return job_mem("section"); }
    if (!strcmp(t, "round3")) {
        const char *r3[] = {"ac-lpac-caps", "job-ws-private", "job-ws-section", "largepages"};
        for (size_t i = 0; i < 4; i++) {
            LOG("\n=== %s ===\n", r3[i]);
            DWORD code;
            spawn(r3[i], 0, NULL, NULL, 120000, &code, NULL);
            LOG("=== %s: exit 0x%lx ===\n", r3[i], code);
        }
        return 0;
    }
    if (!strcmp(t, "round2")) {
        const char *r2[] = {"appcontainer-lpac", "job-v2-private", "job-v2-section", "job-v2-file", "largepages"};
        for (size_t i = 0; i < 5; i++) {
            LOG("\n=== %s ===\n", r2[i]);
            DWORD code;
            spawn(r2[i], 0, NULL, NULL, 120000, &code, NULL);
            LOG("=== %s: exit 0x%lx ===\n", r2[i], code);
        }
        return 0;
    }
    if (!strcmp(t, "ac-child") && argc > 4) return t_ac_child(argv[2], strtoul(argv[3], NULL, 10), atoi(argv[4]));
    if (!strcmp(t, "largepages")) return t_largepages();
    if (!strcmp(t, "lp-child")) return t_lp_child();
    LOG("unknown test %s\n", t);
    return 2;
}
