# Host folder sharing (fs): design

**Status: design and plan, being built. Only the frame format exists** (`crates/fs/frame`: the frames of §4.1, the
hello that checks the share id and protocol version, and the VMM's tracker of requests in flight; its unit tests and
the `fs_frame` fuzz target), **wick-fsd's FUSE decoder and guest names** (`crates/fs/fsd/src/fuse`: the bounded
decoder of §6, the reply encoder and layer 1 of row 1 with the escape mapping of §6.3; their unit tests and the
`fs_decode` fuzz target), **wick-fsd's server core over an in-memory directory** (`crates/fs/fsd/src/session.rs`
and its tables, limits, record and cache modes, the `ConfinedDir` interface of the host backends and `MemDir`, a test
backend; its unit tests and the `fs_session` fuzz target), **its Linux and macOS host directory** (`crates/fs/fsd/src/host`
and `crates/fs/sys`, the backend of §4.3 with nodes that cost memory only and a cache of held descriptors, and stage
0's share checks, `stage0.rs`; their unit tests and the host-directory tests in `crates/fs/fsd/tests`), **the
`wick-fsd` binary on Linux and macOS**: stage 0's one connection and peer check, the serving loop, Linux's
confinement of §6.1 and macOS's of §6.2 (`crates/fs/fsd/src/{main,serve}.rs`, `confine/linux.rs`,
`confine/macos.rs`, `crates/fs/sys/src/unix/confine.rs`, `crates/fs/sys/src/unix/seatbelt.rs`; tests `server.rs`
(Linux), `confine_probe.rs`, and the corpus, link and request sequences against a confined server; on Windows,
whose confinement is not built, wick-fsd refuses to start, `test_refuses_without_confinement`), and the guest
kernels of row 21: CI's `guest-kernels` job builds upstream's CI kernel
(6.1, 6.18) with `CONFIG_VIRTIO_FS=y` (`tools/linux/guest-kernel.sh`), though nothing boots them yet, and **the
VMM's virtio-fs device on Linux and macOS** (`crates/ext/src/fs`, §4.1, only in a build with Firecracker's `fs`
feature: `PUT /extensions/fs` configures shares, each a device that connects to its server's socket at boot; its unit
tests against a fake server, the `fs_proxy` fuzz target, `test_fs_snapshot_refused`). No guest has mounted a share
yet: the boot stages are planned (plan commit 12), and the jailer does not yet place the socket (plan commit 11). A
default build has none of it: there `PUT /extensions/fs` is refused as an unknown extension (`crates/ext/src/lib.rs`,
`test_unknown_extension_is_rejected`; `tools/check-fs-off.sh`).
The work is the virtio-fs item of [M7](ROADMAP.md#m7-desktop-devices). Every "is", "does" and "returns" below about
fs, `wick-fsd` or the fs device describes the design, not shipped behaviour.

Written 2026-11-13 against wick `main` (de43e5e), upstream Firecracker
v1.18.0 (`lib/firecracker`), virtiofsd 1.14.0 (a8b65ed, 2026-11-12), crosvm (dc5c7b7, 2026-11-12), libkrun
(abe0a0f, 2026-11-12), hcsshim `main`, XNU xnu-12377.121.6 and Linux `master` (fs/fuse, include/uapi/linux/fuse.h
7.47).

Each claim carries a tag:

- **[src]** read in source code (file + function named),
- **[doc]** documented by the vendor/project (URL), not measured by wick,
- **[meas]** measured by wick: the test, or the probe with its host, build and date, is named; a probe that is not in
  the repository says so,
- **[inf]** inferred, not yet checked; each one is either a test in the test plan or an open question.

**Windows:** wick has measured none of the file-system behaviour below on Windows. Every Windows statement tagged
[doc] or [inf] is from Microsoft's documentation or inferred from it, and is to be measured on a Windows PC with WHP
before any doc claims it. The few Windows [meas] items are sandbox facts, each with its test or probe named.

---

## 0. Known risks → how the design solves them → how it is to be proved

Design: split virtio-fs. The VMM copies bounded, unparsed frames between the virtqueues and one socket; `wick-fsd`
(one process per share, confined, no guest memory) parses FUSE and touches files. Every row is a plan: no fix and no
test in it exists yet unless the row names an existing one. Status: **now** = the fix needs only mechanisms that are
documented or measured; **measure** = the fix is designed, a measurement on the named host must confirm it first;
**limit** = the host cannot, so the design refuses or limits as stated.

| # | Known risk (source) | Fix (Linux / macOS / Windows) | Proof (test, §11) | Status |
| --- | --- | --- | --- | --- |
| 1 | Guest name escapes the share: `..`, `/`, absolute name in SYMLINK/RENAME/LINK (Kata CVE-2026-47243; virtiofsd name checks only 2026-11-06) | Layer 1, same code on all hosts: every guest name must be one component, not `.`/`..`, no `/` or NUL, at most 255 bytes of UTF-8, and none of the code points the Windows escape writes (U+F001–U+F01F, U+F022, U+F02A, U+F02F, U+F03A, U+F03C, U+F03E, U+F03F, U+F05C, U+F07C; `crates/fs/fsd/src/fuse/name.rs`, `test_every_name_taking_opcode_refuses_what_is_not_a_name`, `test_name_refuses_every_escape_image`), and every operation is relative to a held directory handle. Layer 2: L `openat2 RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV` / M `O_RESOLVE_BENEATH` + `O_NOFOLLOW_ANY` (on macOS 27.2, 2026-11-13, a test program's `openat(dirfd, name, O_RESOLVE_BENEATH)` returned ENOTCAPABLE for `..`, `/etc/hosts` and `../etc/hosts` and opened `.`; the program is not in the repository) / W `NtCreateFile(RootDirectory, one component, OBJ_DONT_REPARSE)`, rename via `FILE_RENAME_INFORMATION.RootDirectory`. Layer 3: the OS sandbox (row 4) | Traversal corpus over every name-taking opcode, on every CI host, no VM; canaries outside the share untouched; **any refusal from layer 2 or 3 fails the test** (layer 1 must stop it); raw-virtqueue guest replay as in the Kata PoC. Host side: `test_traversal_corpus` (38 names × every name-taking opcode, Linux and macOS) | now (L, M); measure `OBJ_DONT_REPARSE` on W |
| 2 | Symlink/junction swapped in mid-operation (TOCTOU; CVE-2016-9602) | Never follow links: L `RESOLVE_NO_SYMLINKS` / M `O_NOFOLLOW_ANY` / W `OBJ_DONT_REPARSE` + `FileAttributeTagInformation` after open, so any reparse point is shown as a link object and never traversed. Guest-made symlinks are emulated (regular file + record), so the host never has a real link the guest made | Race suite: host threads swap dirs ↔ symlinks/junctions/mount points for 10⁶ iterations while the harness operates; same assertions as 1. Host side: `test_swap_race` (a directory ↔ a symlink to outside, swapped atomically without pause, 10⁵ rounds of about ten requests) | now (L, M); measure on W |
| 3 | Aliases: case folding, Unicode normalisation, 8.3 names (`PROGRA~1`), `/.vol`, ADS `file:stream` | Identity by (dev, ino) / FileId, never by name. M: compare the stored name (`fgetattrlist ATTR_CMN_NAME`) with the request, mismatch = ENOENT/EEXIST; never build `/.vol` paths. W: reject `:`; compare `FileNormalizedNameInformation` with the request (catches 8.3) | Corpus entries for each alias form; case/NFD variants (`test_alias_names_refused`, `test_case_collision_is_eexist`) | now (M); measure 8.3 check on W |
| 4 | The file server itself is taken over (parser bug) | Confine it so a takeover reaches only the share: L user/mount/pid/net namespaces + `pivot_root` into the share + seccomp (crosvm's fs list minus mknod/setresuid/capset) + `no_new_privs` + Landlock when present / M Seatbelt `(deny default (with send-signal SIGKILL))`, each file operation the server makes allowed only `(subpath share)`, the system calls, Mach traps and MIG routines it makes listed and every other killed, no network/exec/fork/IOKit, as root the drop to `--uid`/`--gid` (§6.2) / W LPAC token (per-share AppContainer SID) + ACE on the share only + Job (memory, CPU, 1 process, kill on close) + wick's mitigation profile. **If any control cannot be set, wick-fsd does not start** | Per-host sandbox checks (`Seccomp: 2`, `CapEff: 0`; profile test; `TokenIsLessPrivilegedAppContainer`); an outside open from inside the server fails; one test per control proving refusal to start. L: `test_confined_status` (`Seccomp: 2`, `NoNewPrivs: 1`, every capability set empty, other namespaces, `/` = the share), `test_outside_open_fails`, `confine_probe` (inside the confined process: `openat`, `socket`, `execve`, `ptrace` and an executable `mmap` killed by SIGSYS; the host's paths not there), and `test_refused_without_unshare`, `_fork`, `_mount`, `_pivot_root`, `_id_drop`, `_capability_drop`, `_no_new_privs`, `_seccomp`, `test_refused_when_landlock_fails`, each under a filter that makes that step's call fail. M: `confine_probe` (inside the confined process: the outside canary by its path, metadata, `/.vol` and firmlink alias, `/etc/passwd`, exec, fork, a TCP connection, ptrace, `MAP_JIT`, executable mappings, a sysctl and the host's privileged port killed; the share's refused operations of §6.2 refused), `test_every_request_confined_answered_as_unconfined`, and one refusal test per step (`test_refused_when_the_profile_is_not_applied`, `test_refused_when_the_id_drop_fails`, `test_refused_when_a_descriptor_survives_its_close`, `test_refused_when_a_saved_id_is_left`, `test_refused_under_another_profile`, §6.2) | now (L, M); measure LPAC + AF_UNIX + inherited handles on W |
| 5 | Taken-over server attacks the VMM | It never gets guest memory (unlike vhost-user) and no handle to the VMM; the VMM validates every reply length/unique and caps frames | `fs_proxy` fuzz target: hostile descriptor chains **and** hostile replies | now |
| 6 | FUSE parser bugs from guest-controlled lengths | Bounded decoder in its own crate; fuzzed like wick's existing targets | `fs_decode`, `fs_session` fuzz targets on CI (1 min) + nightly | now |
| 7 | Host device nodes, FIFOs, sockets, setuid files (CVE-2020-35517, CVE-2023-2861, CVE-2022-0358) | Only regular files and directories are ever opened for I/O (`fstat` on the handle first); `mknod` never called; ownership, modes, setuid, devices, FIFOs live in a wick-private metadata record; server has no capabilities | Corpus: host FIFO/device/socket in the share; setuid bit never reaches the host (`test_special_files_never_opened`, `test_host_device_node_never_opened`, `test_setuid_never_reaches_host`) | now |
| 8 | Open by handle/id escapes (`open_by_handle_at` "shocker", `/.vol`, `FILE_OPEN_BY_FILE_ID`) | Never used; no `CAP_DAC_READ_SEARCH`; OS sandbox still applies | Open-by-id of an outside file from inside the server → denied. L: `confine_probe`'s `open_by_handle_at` case, killed by the seccomp filter (no capabilities either, `test_confined_status`). M: `confine_probe`'s `/.vol/<dev>/<ino>` read of the outside canary, killed by the profile's file rule (the path read before the profile) | now (L, M); measure W open-by-id under LPAC |
| 9 | Guest exhausts handles, inodes, CPU, disk | Server caps inode table, open handles, queue depth and READDIR page size (same numbers on all hosts; Windows has no per-process handle limit, so the cap is the server's own); VMM rate limiter = upstream's block-device `RateLimiter` (built, `test_rate_limiter_holds_chains`); VMM: the reply bytes it waits for capped at 16 MiB, chains left on the queue at the cap (built, `test_inflight_cap_backpressure`); CPU/memory via cgroup / jetsam + jailer CPU limit / Job; disk: a server byte budget (same on all hosts) | Limit tests: ENFILE/EMFILE/backpressure at the same numbers on every host; queue flood keeps VMM in-flight bytes under the cap | now |
| 10 | DAX: host truncates a file mapped into the guest → fault in the VMM | Not offered in v1 (ENOSYS) on any host | Guest mount with `dax` fails cleanly | now |
| 11 | Socket between VMM and server hijacked | Accept once, check the peer (`SO_PEERCRED` / `LOCAL_PEERCRED` / `SIO_AF_UNIX_GETPEERPID` → SID), then unlink | Second connection refused; wrong peer refused | now |
| 12 | Host apps act on guest-written files (Spotlight, Defender, IDEs following links) | Guest symlinks are plain files on the host, so no host tool follows them; refuse `/`, `~`, `/System`, `C:\`, `C:\Windows` as share roots by default; docs: use a dedicated directory, mark it `.metadata_never_index` | Guest `ln -s /etc/passwd x` → host sees a regular file (`test_guest_symlink_is_a_regular_file_on_host`) | now (residual risk stated in SECURITY.md) |
| 13 | Windows: no "subpath" confinement for a process | Grant an inheritable ACE for the share's own AppContainer SID (Microsoft's `HcsGrantVmAccess` pattern), via an explicit `wick-fsd grant <dir>` / `revoke <dir>`; children with protected DACLs stay unreachable (fails closed). Chosen over a broker, which would parse guest names with full user rights | Outside open from the LPAC server → `ACCESS_DENIED`; revoke removes every ACE it added | measure on W |
| 14 | A directory the host moves out of the share stays reachable through held handles | Host action, trusted in Firecracker's model; L Landlock and M Seatbelt check at access time; W ACL travels with the directory | Documented in SECURITY.md | limit (W), documented |
| 15 | Case-insensitive APFS/NTFS gives names Linux treats as different | Default: refuse a case-insensitive root with an error naming the fix (case-sensitive APFS volume/sparse image; W per-directory case sensitivity, needs admin). With the operator's flag: exact-name lookups, EEXIST on case collisions | Case collision returns EEXIST on every host (`test_case_collision_is_eexist`) | now (limit: W needs admin for existing dirs) |
| 16 | Host changes not notified to the guest (no inotify) | Impossible on every host: Linux's virtio-fs driver has no notification queue. Offer `cache=never` for shares edited on both sides | Documented; `cache=never` test | limit (all hosts, same) |
| 17 | Snapshot with a live FUSE session | v1: snapshot refused with an API error naming virtio-fs: by the extension's `snapshot_blocker` and by the VMM's `check_unsnapshottable_devices` on MMIO and PCI, before any state is saved; the device managers' saves past it leave the device out with an error line, never a panic (built, `test_fs_snapshot_refused`, patch 0056). Later: server state saved as paths and re-resolved beneath the root on restore | Snapshot create with fs → API error | now |
| 18 | Feature off still adds attack surface | Cargo feature `fs`, default off; `wick-fsd` separate binary; no device/process/socket without config | Default build has no fs symbols (built: `tools/check-fs-off.sh` in CI's linux and macos jobs, on the default `firecracker` binary, with wick-ext's fs test binary as the control that the names searched for exist); a planned boot-test stage `fs-off` shows no virtio device 26 | now |
| 19 | Older macOS releases lack `O_RESOLVE_BENEATH` | Require the first macOS release that has the flag and refuse loudly on older ones (the same layers on every host, no reduced mode). **Which release that is is unconfirmed:** the flag is in the macOS 27.2 SDK's `sys/fcntl.h` (read 2026-11-13); this research read it in XNU's `bsd/sys/fcntl.h` from xnu-11417 on, which it took to be macOS 15.4; a third-party rsync patch says macOS 15 ([patch](https://sources.suse.com/SUSE:SLFO:1.1:Build/rsync/c0c245c4f613433f762b3dee895547b4/rsync-hardening-0021-syscall-also-use-O_RESOLVE_BENEATH-on-FreeBSD-and-Ma.patch)). 15.4 is used below as that working assumption, not as a settled floor. XNU's own tags agree: xnu-11215.81.4's `bsd/sys/fcntl.h` has no `O_RESOLVE_BENEATH` and xnu-11417.101.15's has it (which macOS release each tag is, is Apple's tag numbering, not read in the source [inf]). **What the flag answers differs:** xnu-11417 refuses `..` at the starting directory, an absolute path and a link that restarts at `/` with EACCES, and xnu-12377 (macOS 26) made each ENOTCAPABLE (`bsd/vfs/vfs_lookup.c`, `lookup` and `namei`, both tags) [src]; CI's macOS 15 runner refused the probe's `..` with EACCES (run 44296604010, `test_open_never_follows_a_link_or_leaves_the_directory`), so the flag acts there. EACCES is also a plain permission refusal's errno: `probe_beneath` confirms it with an absolute path, which `namei` refuses before any lookup or permission check, and on macOS 15 a refusal by the flag is the guest's EACCES, not counted as layer 2 (layer 1 never lets a guest name reach it) | macOS 15 CI job: fs starts where the flag works and refuses below; `test_open_never_follows_a_link_or_leaves_the_directory` checks each kernel's errno by its Darwin release | first run: CI |
| 20 | Linux host with unprivileged user namespaces disabled (Ubuntu AppArmor) | Start wick-fsd from root, which confines and drops to an unprivileged uid with no capabilities, as the jailer does, or as a user under an AppArmor profile that grants the wick-fsd binary `userns` alone (§6.1); otherwise refuse loudly, naming the sysctl and AppArmor profile the host reads | Run with userns disabled: refuses without root, confined with root. `test_userns_restricted_refused` (as a user where the host restricts user namespaces, as CI's Ubuntu does, run 44207018536); the root path is every confined test run as root (CI's fs job's sudo step); user-namespace path: the fs job's AppArmor-profile step, the confined tests as the runner's user under a profile granting wick-fsd `userns` (first full pass CI run 44238015541, both Ubuntu runners; §6.1 has the profile), and Docker on the Mac; the refusal names the sysctl and the AppArmor profile it reads (`test_the_refusal_names_the_restriction_it_reads`) | now |
| 21 | Guest kernel lacks the driver | Upstream CI configs have `CONFIG_FUSE_FS=y`, `# CONFIG_VIRTIO_FS is not set`; wick's guest kernels add `CONFIG_VIRTIO_FS=y` (built: `tools/linux/guest-kernel.sh` with the fragment `tools/linux/guest-kernel-virtio-fs.config`, CI's `guest-kernels` job) | Guest boot with fs mounts the share | now |

| 22 | Performance cost of the separate server | Measured 2026-11-13 on a MacBookPro18,3, macOS 27.2, **load average 53–79** (so upper bounds; re-measure idle with a concurrent control): AF_UNIX round trip 128 B ≈ 7.6–7.9 µs median; 1 MiB through the socket 267–409 µs (≈ 2.6–3.9 GB/s); host `fstatat` 0.8 µs, `openat`+`close` 7.2 µs, create+4 KiB write+close 64 µs; memcpy 41.7 GB/s (benchmark: a C program, not in the repository; AF_UNIX stream socketpair between two processes, medians of 20,000 round trips for 128 B and 4 KiB and of 2,000 for 128 KiB and 1 MiB, two runs; the busy machine also gave p99s from 0.4 to 5.4 ms). Small ops: the hop is about one host open; vhost-user on macOS/Windows also wakes the VMM (no in-kernel ioeventfd: wick's eventfds are pipes, docs/PORTING.md) [inf], so its round-trip cost is similar and the split's real extra is the data copy. Large I/O: replace the socket payload with a fixed-size shared ring between VMM and server (never guest memory; bounded and counted, since shared sections escape the Windows Job limit): one memcpy at ~40 GB/s ≈ 25 µs/MiB, socket only for notifications. Guest page cache and attr/entry timeouts keep repeated lookups in the guest | Benchmarks per host: fio seq 1 MiB read/write, untar of a kernel tree, `git status` on a large repo, `npm install`; split vs virtiofsd (Linux) and vs an in-VMM prototype; acceptance target set from the Linux virtiofsd number | measure |

### Decisions, with their reasons and the alternatives rejected

1. **The file server is a separate process, not code in Firecracker.** In the VMM, one parser bug would hand the
   attacker everything the VMM holds (the hypervisor handles, every drive, the network endpoints, the API socket),
   and the VMM's sandbox would have to allow file creation, removal and renames for every device, not only fs.
   Splitting by threads does not isolate: on Linux threads share memory, and Seatbelt and the Windows mitigation
   policies apply to a whole process. Rejected: option A (§2.1), which is also what upstream refused (§2.2).
2. **Split device rather than vhost-user-fs.** Reasons in §1 and §2.3: no guest memory outside the VMM, no handle
   passing between jailed processes, upstream's rate limiter and metrics in the VMM, snapshots refusable in one
   place. Rejected for now: option B, kept as a possible Linux-only extra.
3. **The jailer starts `wick-fsd` next to Firecracker** when the configuration has `extensions.fs`, so an operator
   writes one configuration entry. Rejected: Firecracker starting it, because the VMM's sandbox allows no process
   creation and adding it would weaken the VMM for everyone. Until the jailer does it, the operator starts it.
4. **Windows confinement: an ACE for the share's own AppContainer SID** (row 13). Rejected: a broker that opens files
   for the LPAC server, because the broker would parse guest names with the user's full rights, outside any
   sandbox.
5. **macOS: only releases with `O_RESOLVE_BENEATH`** (row 19; the release is unconfirmed). Rejected: running on older
   releases with one layer fewer, which would make macOS weaker than the other hosts.
6. **Linux without unprivileged user namespaces: a root launcher that confines and drops** (row 20), as the jailer
   does. Rejected: Landlock alone, which cannot restrict `chmod`, `chown`, `setxattr` or `utime` and needs Linux 5.13
   (§6.1).
7. **Disk: a byte budget in the server, the same on every host** (row 9). Rejected: host quotas only, which differ by
   host and file system.
8. **Home and system directories are refused as share roots by default** (row 12), because host tools read what a
   guest writes there.

Still open: the performance of the split design against vhost-user (to be measured first, row 22). The extension
point carries the `VirtioDeviceType::Fs` variant and metrics generically (patch 0056: `Extension::write_metrics`, a
`wick` object in the metrics line, none without an extension's metrics).

---

## 1. Summary and recommendation

**Recommendation: a "split" virtio-fs device.** The guest gets a standard virtio-fs device (`mount -t virtiofs tag
/mnt`). Inside Firecracker, that device is a *thin copier* that reads of FUSE only the two header fields that pair a reply
with its request (`unique`, and the reply's `len`, §4.1). It takes each descriptor
chain's readable bytes (bounded), sends them as one framed message over a connected Unix stream socket, and writes
the reply into the chain's writable buffers. All FUSE parsing and every file operation happen in **`wick-fsd`**: a
separate per-VM, per-share server process that sandboxes itself and never sees guest memory. It is the same Rust code
on all three hosts, over a small per-host "confined directory" layer:

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Confinement of the server process | user+mount+pid+net+ipc namespaces, `pivot_root` into the share (virtiofsd's `namespace` mode); seccomp; Landlock as an extra layer where the kernel has it | Seatbelt profile: deny by default, files only `(subpath <share>)`, no network/exec/fork | LPAC token (AppContainer without ALL APPLICATION PACKAGES), DACL grant on the share to its SID only; Job Object; wick's mitigation profile |
| Open beneath a directory | `openat2(dirfd, name, RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS\|RESOLVE_NO_XDEV)` (5.6+) | `openat(dirfd, name, O_NOFOLLOW\|O_NOFOLLOW_ANY [\|O_RESOLVE_BENEATH])`; `O_RESOLVE_BENEATH` on 15.4+ (unconfirmed, §0 row 19), `AT_RESOLVE_BENEATH` for `*at` on 26+ | `NtCreateFile(RootDirectory=dir handle, ObjectName=one component, OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT)` + reparse-tag check |
| Names | one validated component per request, never a path | same | same; characters NTFS refuses escaped as WSL's DrvFs does (U+F000 + c), so their images are refused as guest names on every host |

**Why this and not vhost-user (§2.3).** It keeps everything a guest can throw at FUSE out of the VMM, which was
Firecracker's 2020 objection. It also avoids what vhost-user costs wick:

- the backend maps all of guest memory, and guest memory must become a shared memfd/section. On Windows a shared
  section is not charged to the Job memory limit [meas: `jailer-test.ps1 sections`; a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository], and is counted against `memory.max` only by the jailer's poll since c351646 (SECURITY.md);
- handles must be passed between two mutually-distrusting sandboxed processes. On Windows a jailed process cannot
  push handles to its peer, and pulling needs `PROCESS_DUP_HANDLE`, which amounts to full control of the peer
  [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository; docs/PORTING.md row 14][doc];
- upstream's vhost-user frontend has no snapshot support [src].

With the split design, rate limiting and metrics can be upstream's own code in the VMM (`RateLimiter`, as the block
device uses). The server can also be tested and fuzzed on every CI host without a VM, because its whole input is a
byte stream.

**Rules the design keeps:**

- Off by default, and unreachable when off. A cargo feature `fs` (default off) compiles the device and the extension
  out. Without the feature, `PUT /extensions/fs` stays "unknown extension `fs`" as it is today
  (`crates/ext/src/lib.rs`, `test_unknown_extension_is_rejected`). With the feature but no `extensions.fs` config:
  no device, no socket, no server process.
- Never "trust the guest". The guest kernel is assumed hostile (SECURITY.md threat model), so guest uids, names,
  lengths and flags are input to validate, never authority.
- Parity. Ownership, modes, symlinks and special files are emulated in a wick-private metadata record on **all three
  hosts**. The host only ever sees regular files and directories the server's user owns. The same limits apply
  everywhere (inode count, open handles, request size, name length). Where a host truly cannot do something
  (case-insensitive volumes, illegal NTFS names), the server refuses loudly with a named error, and the behaviour
  is documented.
- No DAX window in v1 (`FUSE_SETUPMAPPING` returns ENOSYS, as Rust virtiofsd does [src]). Snapshots with an fs
  device are refused through the existing `Extension::snapshot_blocker` hook until a state-transfer design exists.

**Biggest risks (see §5, §9, §10):**

1. **Path escape through a name.** It has happened repeatedly, most recently Kata's CVE-2026-47243: an absolute
   name in a raw `FUSE_SYMLINK` let guest root become host root [doc]. Rust virtiofsd added component validation for
   directory operations only on 2026-11-06 [src]. In libkrun's macOS and Windows servers, guest names are
   concatenated into host paths without validation [src→inf]. Defense: validate every name at the protocol
   boundary, open only one component at a time relative to a held directory handle, use beneath-flags, and keep
   the OS sandbox as a second wall. Any OS-sandbox denial during tests counts as a failure.
2. **Windows confinement has no "subpath" primitive.** It depends on an ACL grant on the user's folder, plus
   per-open reparse and alias checks (8.3 names, ADS, junctions) that are partly [inf] until measured on a WHP
   machine.
3. **Host-side consumers of guest-written files.** Indexers, antivirus engines, IDEs and backup tools on the host
   parse or follow what the guest writes. wick cannot sandbox them. The mitigation is documentation, plus
   emulated (non-native) symlinks.
4. **Semantic gaps that users will hit:**
   - APFS and NTFS are case-insensitive by default.
   - There is no inotify for host-side changes: Linux's virtio-fs driver has no notification queue [src].
   - Snapshots are refused.
   - Performance: two extra copies per request. The socket's cost was measured on one Mac (§0 row 22); the device
     itself does not exist yet, so it is not measured.

---

## 2. Protocol comparison

### 2.1 Options

| Option | What runs where | Guest needs | Host attack surface added | Fit |
| --- | --- | --- | --- | --- |
| **A. virtio-fs, server in the VMM** (libkrun's model) | FUSE decoding and file operations in Firecracker | `CONFIG_VIRTIO_FS` | the whole FUSE server inside the VMM process; the VMM's sandbox must allow file operations on the share | Rejected: it is exactly what upstream refused (§2.2), and it widens the VMM sandbox |
| **B. vhost-user-fs** (QEMU, Cloud Hypervisor, crosvm, Kata) | VMM = upstream vhost-user frontend; backend (virtiofsd or wick-fsd) maps all of guest memory and runs the virtqueues | `CONFIG_VIRTIO_FS` | backend: virtqueue + FUSE + file operations; VMM: small | Viable; costs listed in §2.3 |
| **C. split virtio-fs** (recommended) | VMM = virtio-fs device that copies opaque, bounded request/reply bytes to and from a socket; wick-fsd does FUSE + file operations | `CONFIG_VIRTIO_FS` | VMM: a copier over upstream's `Queue`/`DescriptorChain`, the pattern upstream's vsock device already uses (virtqueue ↔ Unix socket); server: FUSE + file operations, with no guest memory | Recommended |
| **D. FUSE or 9p over upstream vsock** | guest agent: `/dev/fuse` daemon or `mount -t 9p -o trans=fd` on a vsock fd; wick-fsd on the host end of the vsock UDS | guest agent; `CONFIG_FUSE_FS` (in upstream's CI configs [src]) or `CONFIG_NET_9P` (not set there [src]) | **no new VMM code**; server as in C | Fallback for guests without virtio-fs; wick-fsd can serve C and D with one protocol |
| **E. virtio-9p** | 9P2000.L server | `CONFIG_NET_9P_VIRTIO` | a 9p server; history of escapes (§3.3) | Rejected: weaker semantics, slower, worse CVE record; upstream users also argued against it ([#1180](https://github.com/firecracker-microvm/firecracker/issues/1180)) |
| **F. NFS/SMB over vsock or the network** | a full NFS/SMB server on the host | NFS/CIFS client | NFS (ganesha/unfs) or SMB (Samba; on Windows the *kernel* `srv2.sys`) parsers exposed to the guest | Rejected: on Windows it would expose a kernel-mode server to a hostile guest. Large protocol surface everywhere |
| **G. Block image** (upstream's answer) | the guest mounts an ext4 image through upstream's block or pmem device; the host copies data in and out | nothing new | none, as long as the host never mounts a guest-written image in its kernel (crafted-image bugs) | Always available, not a live share. Upstream's [drive-mounts proposal](https://github.com/firecracker-microvm/firecracker-containerd/blob/master/docs/drive-mounts-proposal.md) does this [doc] |

### 2.2 Why upstream Firecracker has not taken virtio-fs

- [#1180 "Host Filesystem Sharing"](https://github.com/firecracker-microvm/firecracker/issues/1180) (2019) was
  closed in 2020 with "it doesn't look like a path we need to take Firecracker on". The reasoning is in
  [PR #1351 "[WIP] Implement VirtioFS device backend"](https://github.com/firecracker-microvm/firecracker/pull/1351)
  (closed 2020-08-11, comment of 2020-07-31) [doc]:
  - *"We still think the attack surface implications are large. Even in read-only mode, it's still a lot of code and
    a lot of new bits the guest can throw at the Firecracker emulation layer."*
  - *"For most use cases we've seen so far, there's been a not-too-bad workaround via other channels (e.g., for
    configuration, using MMDS ...)."*
  - *"Exposing a file system will likely make (incremental) snapshot restore more complex, including in use cases
    where the same snapshot is resumed in multiple microVMs."*
  - The paths they suggested were rust-vmm crates, or *"a way to build different Firecracker 'specialized variants'
    or alternatively a plugin system"*. wick's `vmm::ext` is that kind of plugin point.
  - Earlier on the same PR: *"a large piece of functionality, and a large new attack surface"*. The PR's author
    proposed `Host --> FUSE --> VSOCK --> GUEST` (option D) as the safer route.
- A 2022 comment on #1351 proposed delegating to a separate daemon (vhost-user-fs). It got no maintainer answer.
  Later, a maintainer on #1180: "virtio-fs support is not currently on our roadmap" [doc].
- Since then upstream has added vhost-user-blk. Its doc states the rules wick must keep for any out-of-process
  backend (`lib/firecracker/docs/api_requests/block-vhost-user.md`) [doc][src]:
  - *"By design, a vhost-user frontend must share file descriptors of all guest memory regions to the backend."*
  - *"Users should consider running their backend in a jailer"*, and the jailer can only run Firecracker.
  - *"rate limiting becomes backend's responsibility"*.
  - Snapshots are not supported (`unimplemented!` in `block/vhost_user/persist.rs`).
  - docs/memory-hotplug.md adds: *"Firecracker cannot guarantee protection of unplugged memory from a vhost-user
    backend."*

The split design (C) answers each objection: no FUSE decoding in the VMM (it checks a reply's `len` and `unique`
only, §4.1), no guest memory outside the VMM, rate limiting
and metrics in the VMM, and snapshots refused loudly until designed.

### 2.3 B (vhost-user) vs C (split), in detail

| | B: vhost-user-fs | C: split |
| --- | --- | --- |
| VMM code added | device wrapper over upstream's `VhostUserHandleImpl` (`devices/virtio/vhost_user.rs`) | copier device over upstream's `Queue` (a few hundred lines); upstream's `RateLimiter` |
| Guest memory | must be memfd-backed: `resources.rs` `allocate_memory_regions` checks only *block* devices, so a patch is needed. Upstream measured "up to 24%" slower page faults for shared mappings [doc]; THP for shmem is controlled separately | stays private anonymous; nothing changes |
| Who sees guest memory | backend: all of it, including hot-unplugged memory [doc] | VMM only |
| Windows memory limit | shared sections escape `memory.max` [meas: `jailer-test.ps1 sections`] | unchanged |
| Handle passing | memory fds + kick/call eventfds via `SCM_RIGHTS`. On Windows, between a jailed VMM and a jailed backend, neither can open the other [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository], so a broker is needed; granting `PROCESS_DUP_HANDLE` hands over the process (Microsoft, [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights): with DUP_HANDLE, A "can duplicate the pseudo handle for process B ... a handle that has maximum access to process B") [doc] | none: one connected stream |
| Server sandbox needs | shared-memory mapping of received fds, eventfds | read/write on one socket + the share |
| Snapshot | upstream frontend: unsupported; would need `VHOST_USER_PROTOCOL_F_DEVICE_STATE` ([vhost-user spec](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)) | queues are VMM state (upstream persist patterns); server state is a message on the same socket |
| Rate limiting / metrics | backend's job (upstream design.md) | upstream code in the VMM, same config schema as block |
| Interop | operators could plug in virtiofsd on Linux | wick-fsd only (D reuses it) |
| Performance | zero-copy into guest memory | two extra copies of up to 1 MiB per request [inf: unmeasured] |
| Testability | needs a vhost-user frontend to drive | byte-stream harness; no VM, runs on every CI host |

B stays possible as a later Linux-only extra (a vhost-user-fs frontend for operators who want virtiofsd). It would
behave differently from C, so it would be documented as a separate device type, not as "the fs extension".

---

## 3. Prior art

### 3.1 How others confine the server

| Project | Server location | Confinement | Path handling | Notes / sources |
| --- | --- | --- | --- | --- |
| **virtiofsd** (Rust, Linux only) | separate process (vhost-user) | `--sandbox namespace` (default): new mount, pid and net namespaces + `pivot_root(2)` to the share; `chroot`; `none` "not recommended". seccomp default `kill`. Keeps CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETGID, SETUID, MKNOD, SETFCAP (+DAC_READ_SEARCH with file handles). Must run as root or fake root in a userns | `openat2(RESOLVE_IN_ROOT\|RESOLVE_NO_MAGICLINKS)` when available (`oslib.rs` `do_open_relative_to`; commit ada5b24) [src]. `FileName` (rejects `.`, `..`, `/`, empty) only since 2026-11-06 (commits 6ead577, 35f851d) [src] | [README](https://gitlab.com/virtio-fs/virtiofsd/-/blob/main/README.md) [doc]. Per-request credential switching (`setresuid`) → CVE-2022-0358 class. No fuzz targets in tree [src]. DAX: `setupmapping` → ENOSYS (`server.rs`) [src] |
| **crosvm** | separate process (in-tree or vhost-user) | minijail: user, pid, mount, net namespaces, `pivot_root` to the share dir, no_new_privs, seccomp policy `fs_device.policy` (`devices/device_virtio_fs/src/lib.rs` `create_jail`; `vhost_user/sys/linux.rs`) [src] | `validate_path_component` rejects `..` and `/`; `safe_openat2` with `RESOLVE_IN_ROOT\|RESOLVE_NO_MAGICLINKS\|RESOLVE_NO_SYMLINKS` (`passthrough.rs`) [src] | Windows: `run_fs_device` is `unimplemented!` [src]; vhost-user fs snapshot: `bail!("snapshot not implemented")` [src] |
| **Cloud Hypervisor** | virtiofsd (vhost-user) | virtiofsd's | virtiofsd's | DAX removed: "not stable yet from a daemon standpoint" ([docs/fs.md](https://git.phyllo.me/External/cloud-hypervisor/src/tag/v23.0/docs/fs.md)) [doc] |
| **Kata Containers** | virtiofsd | virtiofsd's, as Kata configures it | — | CVE-2026-47243 ([GHSA-2gv2-cffp-j227](https://github.com/kata-containers/kata-containers/security/advisories/GHSA-2gv2-cffp-j227)): runtime-rs started virtiofsd as root with `--sandbox none --seccomp none`; guest root sent a raw `FUSE_SYMLINK` whose *name* was `/etc/cron.d/...` and became host root [doc]. CVE-2026-44210: pod annotations injected virtiofsd arguments (`--sandbox=none`, another shared dir) [doc] |
| **libkrun** (also macOS, Windows) | **in the VMM process** | none by itself. [docs/security-model.md](https://github.com/containers/libkrun/blob/main/docs/security-model.md): *"Do not treat the virtio-fs export path as a sandbox for the VMM process"*; namespaces are recommended [doc] | macOS: `name_to_path` formats `"/.vol/{dev}/{ino}/{name}"`, and the server does not validate names (`server.rs` `lookup` → `bytes_to_cstr` only) [src]. Windows: `parent_path.join(cstr_to_path(name))`; `:` rejected in some operations only [src]. Traversal by a hostile guest kernel is likely: [inf], not reproduced | Precedent for macOS/Windows semantics: Windows uses an ADS `:user.containers.override_stat` for Linux metadata and LX_SYMLINK reparse points [src]. Its isolation model is not Firecracker's |
| **Apple Virtualization.framework** | per-VM XPC service `com.apple.Virtualization.VirtualMachine` | the share reaches the service as a sandbox extension of class `com.apple.virtualization.extension.fuse` (observed by a third party as a Seatbelt denial, [write-up](https://brentfitzgerald.com/posts/lima-vms-from-a-sandboxed-agent/)) [inf]; API: [VZVirtioFileSystemDevice](https://developer.apple.com/documentation/virtualization/vzvirtiofilesystemdevice), `VZSharedDirectory(url:readOnly:)` [doc] | not public | Shows the model wick's macOS side copies: the server is sandboxed and receives access to the share only |
| **Hyper-V / hcsshim (LCOW, WCOW)** | in the VM worker (Plan 9, VSMB) | the per-VM SID is granted access by ACL: `wclayer.GrantVmAccess` → `HcsGrantVmAccess` (`internal/uvm/create_wcow.go`, `internal/computecore`) [src]. Plan 9 flags: ReadOnly, LinuxMetadata, CaseSensitive, RestrictFileAccess + AllowedFiles (`internal/uvm/plan9.go`) [src] | — | Microsoft's own precedent for "grant the VM's SID an ACE on the share" |
| **WSL2** | `wslservice.exe` starts a Plan 9 server for `/mnt/c` ([wsl.dev DrvFs](https://wsl.dev/technical-documentation/drvfs/)) [doc] | runs for the user, elevated or not; WSL trusts the distro, which is not wick's model | DrvFs metadata in NTFS EAs `$LXUID`, `$LXGID`, `$LXMOD`, `$LXDEV` ([WSL file permissions](https://learn.microsoft.com/windows/wsl/file-permissions); `FILE_STAT_LX_INFORMATION`) [doc] | wick should **not** reuse the `$LX*` names: guest-set setuid/uid-0 metadata would then mean something to WSL distros sharing the folder [inf] |

### 3.2 What to take from them

- Every hardened Linux server (virtiofsd, crosvm) uses **both** a kernel confinement of the process (pivot_root into
  the share) **and** careful resolution (openat2 + component validation). The Kata escape shows what happens when the
  confinement is off and the resolution is not complete.
- Rust virtiofsd took until 2026-11 to validate names for every directory operation. The protocol-boundary checks
  are where bugs live, and they need a corpus test (§11).
- Nobody has a sandboxed virtio-fs server on macOS or Windows in open source. libkrun is in-process and unconfined,
  and crosvm's Windows server is unimplemented. wick-fsd's macOS and Windows backends are new ground and need the
  most testing.

### 3.3 Host-side CVE history (server side only)

| CVE | Component | Cause | Lesson for wick-fsd |
| --- | --- | --- | --- |
| CVE-2016-9602 | QEMU 9pfs local backend | symlink following in every path operation (Jann Horn); fixed by a series moving to `*at` + `O_NOFOLLOW` ([qemu-devel 2017](https://lore.kernel.org/all/20170224113402.07a0fb44@bahia.lan/T/)) [doc] | resolve one component at a time; never follow |
| CVE-2016-7116 | QEMU 9pfs (`hw/9pfs/9p.c`) | directory traversal by "local guest OS administrators" with a `..` sequence ([MITRE](https://cveawg.mitre.org/api/cve/CVE-2016-7116)) [doc] | reject `..` at the boundary |
| CVE-2021-20181 | QEMU 9pfs | race leading to use-after-free → privilege escalation ([MITRE](https://cveawg.mitre.org/api/cve/CVE-2021-20181)) [doc] | concurrency in fid/inode tables; fuzz with concurrency |
| CVE-2023-2861 | QEMU 9pfs | server opened host special files (device nodes) → escape; fixed by refusing to open them ([commit](https://git.cs.tu-dortmund.de/SYS-OSS/FRET-qemu/commit/f6b0de53fb87ddefed348a39284c8e2f28dc4eda)) [doc] | never open non-regular, non-directory host objects |
| CVE-2020-35517 | QEMU virtiofsd | same class (special files); "requires a modified guest driver", i.e. a hostile guest kernel ([commit](https://git.cs.tu-dortmund.de/SYS-OSS/FRET-qemu/commit/a3fdbbc7f271bff7d53d0501b29d910ece0b3789)); Rust port Oct 2021 [doc] | the guest kernel is the attacker |
| CVE-2022-0358 | QEMU virtiofsd | kept supplementary groups after switching uid/gid → files created with unintended groups in setgid dirs ([Red Hat](https://access.redhat.com/security/cve/CVE-2022-0358)) [doc] | no per-request credential switching at all (emulated ownership) |
| CVE-2026-47243 | Kata + virtiofsd | sandbox and seccomp off; absolute name in `FUSE_SYMLINK` [doc] | validate names *and* confine; refuse to start without confinement |
| CVE-2026-44210 | Kata | untrusted annotations reached the server's command line [doc] | the server's configuration comes from the operator only, never from guest-reachable channels |
| CVE-2020-13759, CVE-2023-41051 | rust-vmm vm-memory | racy access in `read_obj`/`write_obj`; out-of-bounds with custom `VolatileMemory` ([GHSA-49hh-fprx-m68g](https://osv.dev/vulnerability/GHSA-mm4m-qg48-f7wc)) [doc] | in design C the server never touches guest memory |

---

## 4. Architecture (common to all hosts)

```
guest kernel (virtio-fs driver, hostile)
   │ virtqueues: hiprio + 1 request queue (crosvm also uses 1)
   ▼
Firecracker VMM  ── ext device "fs" (feature `fs`) ── copies bounded opaque frames ──┐
   (sandbox unchanged)                                                            │ one AF_UNIX stream,
                                                                                  │ connected before narrowing
wick-fsd (one per VM per share; started by the operator/adapter, outside the jail) ◀─┘
   stage 0 (operator rights, no guest input): open share root, check volume, accept one connection, check its
            peer, unlink the listener, build confinement
   stage 1 (confined): FUSE decode → confined-directory layer → host file system
```

### 4.1 VMM side (in `wick-ext`, behind `vmm::ext`)

Built (`crates/ext/src/fs`, only with Firecracker's `fs` feature: a default build holds none of it,
`tools/check-fs-off.sh` in CI's linux and macos jobs; Linux and macOS, while a Windows build with the feature refuses
`PUT /extensions/fs` by name). Unit tests: `crates/ext/src/fs/{config,copy,metrics}.rs` and
`crates/ext/src/fs/device/tests.rs` (a fake server on a socket pair, the queues in guest memory as upstream's tests
lay them out); fuzz target `fs_proxy`. No guest has used it yet (commit 12's boot stages).

- Config `extensions.fs`: `{"shares": [{"id", "tag", "socket", "queue_size", "rate_limiter"}]}`, 1 to 8 shares,
  ids and tags unique (`test_bad_configs_are_refused`). `socket` is required: the VMM never connects to a path it was
  not given (a default in the jail comes with the jailer's `--fs-share`, plan commit 11). `queue_size` a power of two
  from 2 to 256 (default 256); `rate_limiter` upstream's block schema. The VMM knows only the tag and the socket
  path: the shared directory and `read_only` are the server's configuration (refused here as unknown fields), so the
  VMM never holds a handle to the share.
- At `attach_boot_devices`, before the sandbox narrows, each device connects to its `socket` and exchanges hellos (10
  s each way): another share's id, another protocol version, a peer that sends something else, closes or says
  nothing each stop the build with the share and the path named (`test_hello_refusals`). Then the socket is
  non-blocking. The socket is in the jail root under the jailer, as vhost-user-blk's socket is (PORTING row 14).
  `update` is refused after boot (`extension \`fs\` cannot be changed after boot`), and a snapshot is refused while a
  share is attached, by the extension (`snapshot not supported: virtio-fs (shares ...)`) and by the VMM's own check
  on both transports (`test_fs_snapshot_refused`, with the persist arms that are reached only past it).
- Frame (built: `crates/fs/frame`, whose doc comment has the byte layout): a 24-byte little-endian header
  `{u32 len, u16 kind, u16 queue, u64 cookie, u32 writable_cap, u32 reserved}`, then the payload. Kinds: hello (each
  side's first frame: protocol version and share id, checked by the other side; an id is 1 to 64 characters of
  `[a-z0-9_-]`, no capitals, since it names the jail's `fs-<id>.sock` and `Data` and `data` would be one file on a
  file system that ignores case, NTFS or APFS as macOS formats it), request (VMM → server: a chain's
  readable bytes) and reply (server → VMM: the bytes for that chain).
- A chain is its readable buffers, then its writable ones: one readable after a writable, an indirect descriptor
  (not offered) or a buffer outside guest memory completes it with used length 0, nothing sent. More readable bytes
  than a frame carries (`len ≤ 1 MiB + 4 KiB`) is answered with `-EIO`; a writable part shorter than
  `fuse_out_header` (16 bytes) is completed with used length 0; a chain without a writable part (FORGET) is sent and
  completed at once with used length 0 (`test_hostile_chains`).
- **Bounded, never blocking.** The reply bytes the VMM waits for are capped at 16 MiB (`MAX_IN_FLIGHT_REPLY_BYTES`, the
  sum of the waiting requests' `writable_cap`) and their count at both queues' size; at a cap, and while a frame's
  worth of request bytes is unsent, the device takes no chain and the rest stay on the queue
  (`test_inflight_cap_backpressure`). Replies are read 4 MiB at most per event. A server that stops reading or
  answering never blocks the event loop (`test_server_hang_never_blocks_the_loop`: other devices are served, at most
  two frames are buffered); with requests outstanding and nothing read or sent for 10 s the share's `stalled` metric
  is 1 and one warning names the requests waiting, until a reply comes (no per-request deadline in v1: a slow host
  file system is not a hang).
- **What the VMM reads of FUSE**: bytes 8..16 of each request (`fuse_in_header.unique`) and bytes 0..16 of each
  reply (`fuse_out_header`: `len`, `error` and `unique`), nothing else: no opcode, no argument. Each reply is checked
  before it is written into its chain, as Linux's driver checks it in its newest form (`virtio_fs_verify_response`,
  fs/fuse/virtio_fs.c) [src]:
  - at least 16 bytes, `len` equal to the reply's byte count and at most the chain's writable bytes, `unique` the
    request's: the checks of commit <https://git.kernel.org/torvalds/c/68b69fa0edb2> ("virtiofs: add FUSE protocol
    validation"), first released in v7.1; not in v6.1, v6.12, v6.18, v6.19 or v7.0 (read in each)
    (`test_each_reply_header_mismatch_loses_the_server`, `test_hostile_replies`);
  - `error` from -511 to 0, and an error reply the header alone (16 bytes): the checks commit
    <https://git.kernel.org/torvalds/c/5364d081125a> ("virtiofs: validate fixed-output response length") added,
    `if (oh->error <= -ERESTARTSYS || oh->error > 0)` and `if (oh->error) { if (len != sizeof(*oh))`
    (`ERESTARTSYS` is 512). That commit is in 7.4-rc3 and in no release, as read on 2026-11-18: v7.1, v7.2 and v7.3
    check no `error` (`test_the_error_range_and_an_error_reply_s_length`, each boundary; `test_hostile_replies`).
    wick-fsd answers every error with the header alone and an errno from its own list, 1 to 122
    (`fuse::encode::error`, the only builder of a reply with an error;
    `test_every_error_reply_is_a_16_byte_header_in_the_device_s_range`), and every reply its tests get, in process
    or from a confined server, is checked as the device checks it (`check_reply` in its tests' harness).

  Before v7.1 the used length is ignored and `copy_args_from_argbuf` takes `fuse_out_header.len` as given (v6.1
  :520-545) [src], so a server taken over could hand an old guest kernel a "success" with lengths the driver trusts;
  and an `error` outside that range reaches the caller as is (`fuse_simple_request`, dev.c v6.1 :512) [src], where
  /dev/fuse refuses it (`fuse_dev_do_write`, dev.c v7.1 :2226).
- **What remains the guest's exposure to a hostile server**, on every kernel without Linux's `error` checks above (all released ones
  as of 2026-11-18), from the source (v6.1 fs/fuse/virtio_fs.c) [src]: (a) a successful reply shorter than a
  request's fixed-size out arguments but with a correct `len`: the driver copies each fixed argument whole from
  `argbuf`, which `virtio_fs_enqueue_req` allocated with `kmalloc` and filled only with the in arguments (:505), so
  the guest kernel reads its own uninitialized heap as, for one, STATFS's answer. The commit with the `error` checks closes it in the
  kernel (the response's length against `fuse_len_args` of the out arguments); the VMM does not check it, since that
  needs each opcode's argument sizes. (b) what any FUSE server is trusted with (attributes, names, data). The host is
  not exposed by either; the guest is, to its own kernel's handling.
- **The server is lost** when its connection ends (EOF, EPIPE, ECONNRESET), a write or read fails, or it sends a
  frame that breaks a rule (a header the format refuses, a kind other than reply, a cookie no chain waits for or
  waits no more, a reply longer than its chain, a header mismatch above). Then every waiting chain with 16 writable
  bytes or more is answered with a `fuse_out_header` `{len 16, error -EIO, unique}` (the request's bytes 8..16, 0 if
  shorter), used length 16; one with fewer, used length 0; and every chain taken after the loss gets the same at once,
  never a hang (`test_server_death_fails_inflight_with_eio`). Nothing reconnects (`test_no_reconnect_after_loss`):
  one error line names the share and the cause, and `server_lost` is 1. Virtio-fs carries no notification on these
  queues: the device does not offer `VIRTIO_FS_F_NOTIFICATION`, so a reply whose `unique` is not its request's,
  0 included (FUSE_NOTIFY_*), is a bad frame. **Not as planned:** the device does not set `DEVICE_NEEDS_RESET`.
  Upstream's transports set that status only when an activation fails (transport/mmio.rs, transport/pci/device.rs),
  and a device has no call to set it; Linux's driver has no config-change handler that would act on it. Setting it
  would take a transport patch; the `-EIO` answers are what the guest sees instead.
- **Limit (v1): a guest's reset of the device loses the server for the rest of the VMM's life.** A guest that
  unbinds and binds the driver again, or kexecs into another kernel, has no share after it: every request fails
  with `-EIO` until the microVM is started again. The FUSE session the server holds belongs to the connection, and
  the chains waiting are no longer the guest's to write; nothing is written, and the connection closes at the
  device's next event (`test_reset_loses_the_server`). A device never activated keeps its connection. Lifting it
  would take a new server connection per activation (ROADMAP M7).
- Patches: `VirtioDeviceType::Fs` (26), the `fs` feature and the metrics hook (patch 0056); `Cargo.lock` for
  wick-ext's dependencies (patch 0057). Metrics: `fs_<id>` in the metrics line's `wick` object, atomics only, read
  without the device's lock (`test_write_metrics_takes_no_device_lock`): requests, request_bytes, replies,
  reply_bytes, refused_chains, eio_answers, inflight_full, rate_limited, event_fails, and the states server_lost,
  stalled, waiting.
- Config space: `struct virtio_fs_config { u8 tag[36]; le32 num_request_queues; }`
  (`include/uapi/linux/virtio_fs.h`) [src], one request queue (`test_config_space_is_the_tag_and_one_request_queue`).
  The tag is UTF-8, 1 to 36 bytes, without NUL. Features: `VIRTIO_F_VERSION_1` only.
- Rate limiting charges one op per chain plus its readable bytes and its writable bytes clamped to a frame, with
  upstream's `RateLimiter`, as block does; a chain without tokens stays on its queue until the limiter's timer
  (`test_rate_limiter_holds_chains`).
- Transport: upstream's device manager attaches over MMIO or PCI as for its own devices; virtio-fs needs nothing
  transport-specific. DAX would need shared-memory-region support (virtio PCI `VIRTIO_PCI_CAP_SHARED_MEMORY_CFG`,
  MMIO SHM registers; Linux `virtio_get_shm_region` in `virtio_fs_setup_dax`, `virtio_mmio.c` `vm_get_shm_region`).
  Neither upstream transport has it (grep of `transport/mmio.rs`, `transport/pci/`) [src].
- **No rule or system call added to the VMM's sandbox.** The socket is connected in the setup phase; at run time the
  device reads and writes it, registers it with the event manager and arms a timer, as vsock and the rate limiter
  do. macOS: `test_fs_socket_survives_each_profile` connects in the jail under the setup profile, narrows, then sends
  frames of up to 1 MiB and 4 KiB both ways through a non-blocking socket watched by epoll, jailed and not. Linux:
  each call is in upstream's `vmm` filter (`socket`, `connect`, `read`, `write`, `recvfrom`, `sendto`, `epoll_ctl`,
  `timerfd_settime`, `close`) [src]; the boot stage under the filter is commit 12's.

### 4.2 Server side (`wick-fsd`, its own crate and binary, not linked into `firecracker`)

- **Stage 0** (operator's rights, reads no guest bytes):
  - parse arguments (`--shared-dir`, `--socket`, `--read-only`, limits);
  - its first step, before anything is opened (`main.rs`, `start`): every descriptor it was started with but the
    standard streams and `--ready-fd` closed, whatever its number (Linux `close_range` around `--ready-fd`, by the
    kernel's `/proc/self/fd` list where the kernel has no `close_range`; macOS each descriptor of the file table
    `proc_pidinfo(PROC_PIDLISTFDS)` lists, which has no bound to miss), then that list read back: a descriptor left
    open (a close that failed, or said done and was not) is a refusal naming each, by what it is, before the socket
    is bound; standard input made `/dev/null`, read-only
    (wick-fsd reads none); `--ready-fd` required to be 3 or more (the parse refuses 0 to 2, the standard streams,
    and anything below 0: closed after the ready byte, a standard stream's number would be taken by the next open, the
    connection, and the log would go into it; `test_ready_fd_is_never_a_standard_stream`), a pipe's write end or a
    socket, and closed once its one byte is written. Nothing else closes or re-takes 0 to 2 after the first step: only
    `stdin_from_null`'s `dup2` onto 0 touches them, and a stream the launcher closed (`>&-`) is `/dev/null` before
    `main` (`test_a_closed_standard_stream_is_dev_null_at_the_first_step` on Linux and macOS,
    `test_closed_standard_streams_are_dev_null_to_the_server` on Linux). A launcher's descriptors survive `pivot_root` and a Seatbelt profile, and a read or write on one already
    open is checked by nothing of the confinement: in CI run 44233741878's fs jobs (the unit-test step's record) a
    step's shell held descriptors 142 and 145, two pipes' ends, on both Ubuntu runners, and 131 and 140, two
    `com.apple.netsrc` control sockets, and 143 and 146, pipes, on macos-latest, which every process it starts
    inherits (SECURITY.md, Fixed defects; `test_descriptors_it_was_started_with_are_closed`,
    `test_refused_when_a_descriptor_it_was_started_with_survives`, `start.rs`). Standard output and error are kept as
    given (Rust's start opens `/dev/null` for any of 0 to 2 that is closed): the operator's channel for `ready` and
    the log, which the server only writes. A terminal there is not a way out: the server's filter allows `ioctl`
    with `FS_IOC_GETFLAGS` only, so `TIOCSTI` kills it; a host file open for writing as stderr is the operator's log,
    written by the server and nothing more;
  - open the share root;
  - check the volume: local, not the volume root or a system location, case sensitivity (§7), xattr/EA support;
  - bind and listen on the socket;
  - accept **exactly one** connection, then close and unlink the listener;
  - check the peer: Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`/`getpeereid`, Windows `SIO_AF_UNIX_GETPEERPID` (works
    across the AppContainer boundary [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository]) → the expected uid or jail SID. The check is made here, by
    the process with the operator's rights: a confined server could not open the peer to read its identity (on
    Windows an LPAC process cannot open the VMM);
  - only then set up the confinement (§6), with the connected socket and the share root its only handles.
- Built for Linux (`crates/fs/fsd/src/main.rs`): `wick-fsd --share-dir DIR --socket PATH --id ID [--read-only]
  [--cache auto|never|always] [--cache-timeout-ms N] [--peer-uid UID] [--uid UID --gid GID] [--ready-fd FD (3 or more)]
  [--case-insensitive-ok] [--max-nodes N] [--max-held N] [--max-handles N] [--max-bytes N]`. It refuses a socket path that exists
  (it never removes what it did not make), says it is ready (a byte on `--ready-fd`, else a `ready` line), accepts
  one connection, closes and unlinks the listener at once, and serves only a peer of `--peer-uid` (default: its own
  uid). At the end it writes its counters to stderr (layer-2 refusals among them). `wick-fsd --version` prints its
  version, and a discovery build (§6.2, how the lists were checked) adds that it is one, never a product, there and
  as its first line on stderr.
- **Stage 1** (confined): serve the one connection until EOF, then exit. It never accepts. Refusing to start is the
  only answer to a missing control: the server has no "unconfined" flag at all (Kata's failure mode).
- **Only bytes cross between the VMM and the server.** Neither opens the other. A shared object needed later (a
  bounded bounce ring, DAX, vhost-user) is made by the jailer or stage 0 and handed to both.
- **FUSE decoder**:
  - safe Rust, no `unsafe`; each frame is parsed from a private copy (no double fetch possible).
  - Every length is checked against the frame: `fuse_in_header.len`, the name NUL inside bounds, `total_extlen`
    extensions, `BATCH_FORGET` count × 16, `max_write` 1 MiB as virtiofsd (`server.rs` `MAX_BUFFER_SIZE`) [src].
  - Opcodes not implemented return ENOSYS: IOCTL, SETUPMAPPING/REMOVEMAPPING, POLL, NOTIFY_REPLY, CUSE.
  - INIT negotiates no `POSIX_LOCKS`/`FLOCK_LOCKS`, so locks stay guest-local (§7).
- **Inode table**:
  - server-chosen node ids, never host inode numbers; a request's `nodeid` is looked up, never interpreted.
  - Identity = (volume id, file id) from the open handle: Linux `(st_dev, st_ino)`, macOS `(st_dev, st_ino)`,
    Windows `(VolumeSerialNumber, FileId 128-bit)`.
  - Entries hold, on Linux and macOS, a directory node (where it is, and its descriptor while the cache holds it)
    or a leaf (the names it is known by), each re-verified against the identity at use (§4.3); on Windows a handle
    opened by id.
- **Limits, identical on every host:**
  - inode entries: 2^18 (262144) by default (`DEFAULT_MAX_NODES`; `--max-nodes` sets it per share). On Linux and
    macOS a node costs memory, not a descriptor (§10, question 11): at most 4096 bytes (`NODE_BYTES_MAX`: its
    node-table entry, and a leaf with 8 names of 255 bytes, the most it keeps, or a directory node with its name,
    allocator rounding and the tables' spare capacity included). Measured as the growth of the process's resident
    memory, every node that worst case: 2768 to 3300 bytes; typical, one short name: 965 to 1116 bytes, the
    tables' growth included [meas: `test_a_node_costs_at_most_node_bytes_max`, 4096 and 16384 leaves, six runs,
    macOS 27.2, 2026-11-18]; 3230 and 807 bytes on Linux [meas: the same test, Docker's linuxkit 7.0.14 aarch64 on
    this Mac, 2026-11-18]. So a share's nodes take at most 1 GiB (2^18 × 4096) whatever the guest does,
    about 280 MiB when every node is typical, and a VM with N shares N times that; an operator who wants less
    lowers `--max-nodes`. The bound holds by construction (a leaf keeps at most `NAMES_MAX` names, a
    name is at most 255 bytes, a directory one name in its parent), which `HostDir::footprint` counts in the same
    test after more links and long names than a leaf keeps. (The `fs_session` fuzz target drives `MemDir`, whose
    objects are the share itself, so the bound is checked there over the host directory instead.);
  - open host handles: 1024 by default (`DEFAULT_MAX_HANDLES`; self-limited: Windows has no per-process handle limit
    [meas: `jailer-test.ps1 nofile`]);
  - descriptors the nodes hold at once: 1024 by default, the root's included (`DEFAULT_MAX_HELD`; `--max-held`), a
    cache whose least recently used is let go first (§4.3); independent of the number of nodes;
  - the descriptors these let the server hold at once, `limits::descriptors`: the nodes' cache, one per handle, and 64
    spare (`SPARE_FDS`: the standard streams, the connection, and what one request opens or keeps before its reply),
    2112 by default, whatever the number of nodes. Stage 0 refuses a share whose host limit is below it, so the server
    itself never meets EMFILE mid-run, and never lowers a limit the operator set. The defaults fit the lowest stock
    limit with 8128 to spare
    (`test_default_limits_fit_stock_hosts`): macOS enforces the lower of `RLIMIT_NOFILE` and `kern.maxfilesperproc` (xnu
    `proc_limitgetcur_nofile`) [src], which is `OPEN_MAX`, 10240, on a Mac with 8 GB or less (`bsd_scale_setup` scales
    it only for a scale above 2; `scale_setup` gives 2 below 8 GB and memory / 4 GB above) [src]; 122880 on a 32 GB M1
    Pro, where a soft limit of 200000 still stopped at 122880 descriptors [meas: `os.open` until EMFILE after
    `setrlimit`, macOS 27.2, 2026-11-18]; GitHub's ubuntu-latest (Ubuntu 26.04) and ubuntu-24.04-arm runners have a hard
    limit of 65536 (CI run 44188936001, which refused the earlier defaults, 65536 nodes and 4096 handles, 69696
    descriptors); a systemd service, and a login shell started by one, 524288 (`DefaultLimitNOFILE=1024:524288`,
    systemd-system.conf(5)) [doc]. Windows has no such limit. A guest that keeps more objects looked up than the node
    limit gets ENFILE;
  - worker threads; queued requests;
  - name ≤ 255 bytes;
  - xattr value ≤ 64 KiB, list ≤ 64 KiB; a guest xattr name ≤ 120 bytes, ERANGE beyond (macOS keeps names of at
    most 127 bytes, `XATTR_MAXNAMELEN`, less the 7 of the `wick.x.` prefix; `GUEST_XATTR_NAME_MAX`);
  - READDIR reply ≤ the request size;
  - bytes the guest's writes may add in one run of the server (decision 7): 64 GiB by default, **provisional** until
    the jailer's `--fs-share` sets it per share (virtio-fs staging 11);
  - guest xattrs per node: 3 KiB by default, each attribute charged 32 bytes (`XATTR_ENTRY_COST`) plus its name
    and value. Default ext4 is the tightest Linux file system: beside the record it held one value of 4028 bytes, or
    146 empty attributes, which the charge counts as 4066 and 5002 bytes, both over the budget; xfs, btrfs and tmpfs
    held 16 KiB or more in one value and over 100000 empty attributes [meas: `tools/linux/xattr-budget.sh`, Docker on
    an M1 Pro, Linux 7.0.14-linuxkit aarch64, 2026-11-18; 1 GiB images as `mkfs` makes them]. An ext4 entry costs 16
    bytes, the name past `user.` and the value each padded to 4, so at most 29 bytes beyond what the guest named: a
    charge of 4 per attribute (the earlier count) would let a guest of many short names past ext4's room, 32 does
    not. The rest of the 4 KiB block is left for the host's own attributes (an SELinux label, ACLs). macOS (APFS) and
    Windows (NTFS EAs, 64 KiB) hold more, so the budget is the same on every host;

  The defaults are `crates/fs/fsd/src/limits.rs`'s `DEFAULT_*` constants.

  Exhaustion returns ENFILE/EMFILE/ENOSPC to the guest and is counted in metrics.
- **Metadata emulation** (all hosts): mode bits, uid/gid, rdev, and the file type for symlinks, FIFOs, sockets and
  device nodes live in a private record.
  - Storage: Linux xattr `user.wick.stat`, macOS xattr `wick.stat`, Windows EA `WICK.STAT`.
  - On the host, every object is a regular file or a directory, owned by the server's user, with modes masked
    (no `S_ISUID`/`S_ISGID`/sticky on host objects).
  - Files that pre-exist without a record get their mode from host bits, and the configured uid/gid.
  - Symlinks the guest makes are regular files with a record and the target as content. Host-made symlinks and
    junctions are shown as symlinks (readlink only) and never traversed by the server.
- **Guest xattrs** are stored under a private prefix (`user.wick.x.*` / `wick.x.*` / an EA blob). The guest can never
  name the record, `security.*`, `trusted.*`, `system.*` or `com.apple.*`.

### 4.3 The host backend interface (`ConfinedDir`)

The server is common code on every host: the FUSE decoder, the node and handle tables, the limits, the record
(§4.5) and the cache modes (§4.4). Below it, one trait, `ConfinedDir` (`crates/fs/fsd/src/dir.rs`), is all a host
backend implements: Linux, macOS, Windows, and `MemDir`, an in-memory directory for tests and fuzzing. Its contract:

- **One checked component beneath a held directory, never following a link.** Every name a backend is given has
  passed layer 1 of row 1 (`Name::new`); a backend never takes a path. Linux opens with `openat2` beneath, macOS with
  `O_RESOLVE_BENEATH` and `O_NOFOLLOW_ANY`, Windows with `NtCreateFile` relative to a handle with `OBJ_DONT_REPARSE`
  (§6).
- **Every name a backend returns is checked again** by the server, which skips (and counts) one that is not a guest
  name.
- **Nodes and identity.** A node is what the node table holds: on Linux and macOS a directory's descriptor, or a
  leaf for anything else (below); on Windows a handle opened by id. Identity is
  (volume, 128-bit file id). Every operation that acts on an object the guest found earlier (open, unlink, rmdir,
  link) is given the identity it expects and fails with ENOENT when the name now holds another object.
- **Exact names.** A lookup whose stored name is not exactly the name asked for (an alias by case or normalization)
  is ENOENT.
- **Errors are Linux's errno on every host.** A refusal by layer 2 (the beneath flags) or 3 (the OS sandbox) is a
  separate error carrying the layer and the host's code: the guest gets EACCES, the server counts it, and any one is a
  bug in layer 1 (the corpus test of row 1 fails on it).
- **Listing:** entries after a cookie, cookies 1 to `i64::MAX`; the server adds `.` and `..` itself.
- **The record and guest xattrs** are stored and read as opaque bytes (§4.2): the backend never interprets the record,
  and the server refuses a record of another length.
- **Permission bits:** a backend keeps the server's own access to the object and never sets setuid, setgid or sticky
  on the host.
- **Rename** acts on two (directory, name) pairs, with Linux's errors (`fs/namei.c` `filename_renameat2`,
  `__start_renaming`, `vfs_rename`) [src]: a directory into itself or beneath it is EINVAL; onto an ancestor of its
  old parent ENOTEMPTY (EINVAL under exchange); two names of one object succeed with nothing changed. Of
  `renameat2`'s flags:
  - `RENAME_NOREPLACE` goes to the backend on every host: Linux `renameat2(RENAME_NOREPLACE)`, macOS
    `renameatx_np(RENAME_EXCL)`, Windows `FileRenameInformationEx` without `FILE_RENAME_REPLACE_IF_EXISTS`.
  - `RENAME_EXCHANGE` goes to the backend, which swaps the two names atomically (ENOENT if either is missing, and a
    directory may be exchanged with a non-directory, as Linux allows): Linux `renameat2(RENAME_EXCHANGE)`, macOS
    `renameatx_np(RENAME_SWAP)`. **The Windows backend refuses it with EINVAL**: NTFS has no atomic exchange. The
    `FileRenameInformationEx` flags are `REPLACE_IF_EXISTS`, `POSIX_SEMANTICS`, `IGNORE_READONLY_ATTRIBUTE` and
    storage-reserve and pin-state flags, none an exchange ([Microsoft Learn, `FILE_RENAME_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information))
    [doc], and two renames through a third name are not atomic: another process could see the third name, or a crash
    leave it. A guest that needs it gets EINVAL, as from a Linux file system without exchange (§9).
  - `RENAME_WHITEOUT` is refused with EINVAL by the server on every host: it leaves a character-device node (0, 0)
    in place of the source for overlayfs, and the server never makes device nodes on a host (they are emulated in
    the record, §4.2).
  - Both of `NOREPLACE` and `EXCHANGE`, or an unknown bit, is EINVAL, as Linux.
  - A file system without the flag gives EINVAL on every host, Linux's answer, with both files byte for byte as they
    were (`test_stage0_and_renames_on_other_volumes`, which reads them: 0 must be a real exchange, EINVAL must leave
    both). Linux: a file system without it refuses it (`renameat2`, EINVAL); vfat has it (exchanged on Linux 7.0.14, and
    on GitHub's ubuntu-latest in run 44199005130's record step). macOS: xnu hands `RENAME_SWAP` to the file system
    (`vn_rename` calls `VNOP_RENAMEX` with the flags, bsd/vfs/kpi_vfs.c, xnu-12377.121.6, :4654 to :4655) [src], and one
    without it may not refuse it. macOS 26.7.2 (25G332, GitHub's macos-latest, run 44199005130's record step): the msdos
    volume reports no `VOL_CAP_INT_RENAME_SWAP`, yet `renameatx_np(RENAME_SWAP)` of C and D returned 0 and did a plain
    rename: C was gone and D held C's bytes, D's own destroyed. macOS 27.2's msdos and exfat (FSKit modules; Apple's
    msdos module's `renameItem` takes no swap option [src]) and HFS+ give ENOTSUP [meas:
    `getattrlist(ATTR_VOL_CAPABILITIES)` and `renameatx_np` on `hdiutil` images, macOS 27.2, 2026-11-18]. So the backend
    asks the volume once, at start (`sys::rename_swap`: `VOL_CAP_INT_RENAME_SWAP`, reported by APFS, not by HFS+, msdos
    or exfat, same probe), and never the file system: an exchange on a volume that does not report it is EINVAL before
    any call (SECURITY.md, Fixed defects). The other flags wick-fsd passes on macOS are enforced by xnu above the file
    system: `RENAME_EXCL` (`renameat_internal` refuses an existing target, bsd/vfs/vfs_syscalls.c :9646) [src], EEXIST
    on msdos and exfat too (same probe); `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`, `AT_SYMLINK_NOFOLLOW`, `FSOPT_NOFOLLOW`
    and `XATTR_NOFOLLOW` are path-lookup flags of namei, and stage 0 checks beneath-resolution on the share itself
    (`probe_beneath`).

**The Linux and macOS backend** (`crates/fs/fsd/src/host/unix.rs`; every system call in `crates/fs/sys`, the
server's only unsafe code, `wick-fsd` itself forbids it):

- **Nodes, the same on both hosts.** A node costs memory; the descriptors nodes hold are a cache of at most
  `--max-held` (1024 by default, the root's included, which is never let go), the least recently used let go
  first, so the descriptors are bounded whatever the number of nodes (§4.2, Limits).
  - A directory is one *directory node* per identity, `(st_dev, st_ino)`: where it is (its parent's node and its name
    there, as the guest last looked it up or renamed it) and, while the cache holds it, its descriptor
    (`O_RDONLY|O_DIRECTORY`). One the cache let go is opened again by its one name beneath its parent (whose descriptor
    is found the same way, up to one held or the root), with the same beneath flags as any open, and checked to be the
    same identity. Where the guest moved it, it is found there; where the host moved, removed or replaced it (a link put
    in its place included, never followed: Linux's `O_DIRECTORY` answers ENOTDIR before `O_NOFOLLOW`'s ELOOP, macOS
    ELOOP, both ESTALE), or its parent's node is gone (a guest kernel never forgets a parent while it holds a child: a
    dentry holds its parent), it is ESTALE until a LOOKUP finds it again, the error Linux's FUSE gives for a node it
    cannot find again (`fuse_get_dentry`, fs/fuse/inode.c, v6.12, :1018 to :1043: a LOOKUP of `.` that finds nothing, or
    another generation, is ESTALE) [src] and virtiofsd for an inode whose file handle no longer opens
    (`--inode-file-handles`, which keeps a file handle in place of an `O_PATH` descriptor per inode [doc];
    `open_by_handle_at` is ESTALE from `exportfs_decode_fh`, fs/exportfs/expfs.c, v6.12, :166 and :190 [src])
    (`crates/fs/fsd/tests/stale.rs`). However deep the walk, it holds at most one descriptor beyond the cache at a
    time: the directory it opens the next one beneath, which the cache may already have let go, kept until the next
    is open and then closed; so a request holds the cache, one more, and what it opens itself (a handle's
    descriptor), all inside `SPARE_FDS` and so inside `limits::descriptors`
    (`test_a_chain_deeper_than_the_cache_is_walked_within_one_spare_descriptor`: a cache of 2, a chain of 8 all let
    go, walked under a soft `RLIMIT_NOFILE` of the descriptors open and one more, then one more for CREATE's
    handle, in a process of its own that starts with its standard streams alone, whatever its launcher left open: a
    CI runner leaves descriptors far above them, 131 to 146 on macos-latest in run 44225041771). An identity is `(st_dev, st_ino)`, as a leaf's (below, Inode numbers reused). A
    directory the cache still holds is served wherever the host moved it, as before
    (`test_a_held_directory_the_host_moved_is_served`).
  - Any other object is one *leaf* per identity, which keeps the names it is known by, as (directory node, name),
    the most recently used first, at most 8 (`NAMES_MAX`); every LOOKUP, CREATE and LINK that reaches it adds its
    name; the guest's UNLINK removes one; RENAME moves one (and takes it from an object renamed over; EXCHANGE
    swaps them). Once the guest has opened it, the leaf keeps the descriptor of its widest open (read-write over
    write over read), as virtiofsd's `O_PATH` descriptor keeps the inode, until the node is forgotten
    (`test_forget_frees_an_unlinked_file`) or the cache lets it go. It is the open's own descriptor, shared with
    the handle: while a handle shares it, it is the handle's to count and the cache does not take it, so a file
    the guest unlinked while it holds it open stays served (`test_an_unlinked_file_open_while_the_cache_lets_go_is_served`);
    once the last such handle closes it is the cache's again. A leaf only looked up holds none.
  - A leaf's names refer to their directory nodes without keeping a descriptor, and a name whose directory the
    guest forgot is dropped (an honest guest loses no name it uses), so a guest that links a file into
    directories and forgets them holds no more descriptors (`test_one_descriptor_per_node_and_handle`); a guest
    that walks many times more directories and files than the cache holds, one chain 24 deep and 48 side by
    side, and uses each again after it was let go, never holds more than the cache and its handles
    (`test_a_walk_beyond_the_cache_holds_at_most_the_cache`, which counts the process's descriptors after every
    step; the swap race runs again with a cache of two, `test_swap_race`).
  - **Inode numbers reused.** An object is known by `(st_dev, st_ino)` only, and a file system may give a freed inode
    number to the next object it makes (ext4 does: `test_a_directory_the_host_removed_or_replaced_is_estale` met it in
    Docker on this Mac, overlayfs over ext4; APFS does not). A number is freed only once its object has no name and
    nothing holds it open, so it is never reused while a guest handle, a leaf's held descriptor or a directory's
    descriptor in the cache holds the object: the guest's I/O goes through its handle's own descriptor, and an open file
    the host unlinks and replaces is still the guest's file. Reuse is possible for an object the server holds nothing
    of: a leaf only looked up, or one whose descriptor the cache let go, and a directory the cache let go. If the host
    removes one, makes another under one of its known names, and the file system gives it the same number, the node is
    rebound to the new object without an error: the guest then sees the new object's contents, size, times and record
    under the old node, as if a host process had rewritten the file, or replaced the directory's contents, in place;
    nothing outside the share is reachable, as the name and the parent are the ones the guest knew. Before the cache, a
    directory and an opened leaf held their descriptor and were not rebound; a leaf only looked up was, as it is now.
    Telling the two apart would cost: the birth time, with the identity (Linux `statx` with `STATX_BTIME` where the file
    system reports it in `stx_mask`, as ext4, btrfs and XFS do, and the identity alone where it does not; macOS
    `st_birthtimespec` from the `fstatat` the server makes already, APFS and HFS+): 16 bytes a node and no extra system
    call on either host, since `statx` replaces the `fstatat` on Linux (allowed with `AT_SYMLINK_NOFOLLOW`); two objects
    born in the same nanosecond with the same number would still be one. The inode generation would need an open and
    `FS_IOC_GETVERSION` per check on Linux (not in the filter) and is root-only on macOS (xnu's `vn_stat_noauth`,
    bsd/vfs/vfs_vnops.c, xnu-12377.121.6, :1693, gives `st_gen` 0 to a process that is not root), so it is not a cheap
    check on either. Not built (open question 12, §10).

  Each use finds the object by the first known name that still is it (`fstatat`, then the identity checked with
  `fstat` on anything opened): a host's swap is ENOENT, never another object. When no known name is it:
  - an object with no name at all (`nlink` 0: unlinked while the guest holds it) is served through the held
    descriptor: GETATTR and SETATTR with or without the handle flag, a new OPEN the descriptor's access covers,
    and truncation if it may write; LINK is ENOENT, as Linux's `link(2)` of an unlinked file;
  - any other is looked for in the directories the guest knows, those the cache holds first, at most 65536 entries
    per search (`SEARCH_MAX`; a directory opened again counts as one), each a guest name checked by `fstatat`
    (overlayfs's `d_ino` is not always `st_ino`). An object the guest reaches has its parent's node, so a name the
    leaf pushed out is found; one the host moved out of every directory the guest knows is ENOENT.

  So the guest's own links, renames and unlinks never make a live object ENOENT
  (`crates/fs/fsd/tests/links.rs`: each sequence over `MemDir` and over the host directory: a link's other name
  after an unlink, a node first reached by another name, one of two links renamed or exchanged, 20 links of one
  file removed newest first, an open file renamed and its directory renamed while it is open, an unlinked file
  open with I/O, FSYNC, FALLOCATE, GETATTR and SETATTR; the `fs_session` fuzz target checks after every request
  that each node it holds answers GETATTR while its object has a name or a handle). Neither host uses `O_PATH`
  (macOS has none) or reopens through `/proc` (§6.1). The server needs read access to every directory it holds;
  a share's directories it cannot read are EACCES to the guest.
- **Opens.** Linux: `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`.
  macOS: `openat` with `O_NOFOLLOW_ANY|O_RESOLVE_BENEATH` (`O_NOFOLLOW` with `O_NOFOLLOW_ANY` is EINVAL on macOS 27.2,
  and `O_NOFOLLOW_ANY` covers the last component; `test_open_never_follows_a_link_or_leaves_the_directory`). Always
  `O_CLOEXEC|O_NOCTTY|O_NONBLOCK`, and only the access mode the guest asked for: the guest's `O_APPEND`, `O_TRUNC`,
  `O_DIRECT`, `O_SYNC` and `O_NOATIME` never reach the host (`test_open_flags_never_reach_the_host`,
  `test_opens_carry_no_guest_flag`). Its kernel positions appends and sends `SETATTR` for a truncation; a synchronous
  write is the guest's `FSYNC`.
- **No fallback.** A host without beneath-resolution is refused at start: Linux without `openat2` (before 5.6, or a
  seccomp filter that denies it) and macOS without `O_RESOLVE_BENEATH` (decision 5). The probe opens `..` beneath
  the share root and must be refused (`probe_beneath`).
- **Refusals by layer 2.** The object's kind is read with `fstatat(..., AT_SYMLINK_NOFOLLOW)` before any open, so a
  link or an escape only reaches an open if the host swapped it in since. The open then fails (`ELOOP`, Linux's
  `EXDEV`, macOS's `ENOTCAPABLE`; macOS 15's EACCES, which a permission refusal shares, is not counted, §0 row 19):
  a layer-2 refusal, EACCES to the guest and counted (`test_swap_race` sees them;
  `test_traversal_corpus` fails on any).
- **Host symlinks, FIFOs, sockets and devices** are shown (symlinks as symlinks, the others as regular files with
  no permission) and never opened: their kind is read without opening, they carry no record or guest attribute,
  and READLINK reads a symlink with `readlinkat`, checked against the node's identity before and after
  (`test_special_files_never_opened`: a writer waiting on a host FIFO is never let through;
  `test_host_device_node_never_opened` as root). A name beneath a host symlink is ENOTDIR.
- **What the guest makes** of those kinds is a regular host file with a record and **no permission bits beyond the
  server's own** (`0o600`), so host tools neither run it nor take it for what it stands for (row 12;
  `test_guest_symlink_is_a_regular_file_on_host`). A regular file or directory gets the guest's permission bits plus
  the server's own access; setuid, setgid and sticky never reach the host (`test_setuid_never_reaches_host`).
- **Mount points beneath the share are not entered**, on both hosts: a name whose object is on another device is
  EXDEV, though a listing shows it (`test_mount_point_beneath_the_share_is_exdev`). Linux's `RESOLVE_NO_XDEV` refuses
  the crossing as well.
- **Exact names.** A lookup checks that the name is stored as exactly those bytes where the host folds names: macOS
  always (APFS and HFS+ fold Unicode normalization on every volume, and case on most), by `getattrlistat(...,
  ATTR_CMN_NAME, FSOPT_NOFOLLOW)`; Linux in a casefold directory and on vfat and exfat, by listing the directory.
  Another stored form is ENOENT to a lookup or unlink, EEXIST to a create, mkdir or rename onto it
  (`test_alias_names_refused`, `test_case_collision_is_eexist`). An object renamed to its own other case is stored under
  the new one, as the guest asked, with or without `RENAME_NOREPLACE` (the new case is no name the guest has), keeping
  its node and its other links; `RENAME_EXCHANGE` with it is ENOENT; a name that folds onto another link of the object,
  in the same directory or another, is EEXIST, as onto another object; two links stored as given are two names of one
  object, and the rename does nothing (Linux's 0; EEXIST with `RENAME_NOREPLACE`). macOS: one `renameatx_np`, which
  stores the new case, when `getattrlistat` says the name folds onto the source's own entry (xnu hands a rename between
  two names of one vnode to a case-insensitive file system, `renameat_internal`) [src]. Linux will not: a casefold
  directory's dentries hash and compare folded (fs/libfs.c, v6.12, `generic_ci_d_hash` :1846, `generic_ci_d_compare`
  :1794, set for the superblock by ext4 at fs/ext4/super.c :5472), so the lookup of the new case finds the source's
  dentry and `vfs_rename` returns 0 with nothing done when both are one inode (fs/namei.c :4908; with
  `RENAME_NOREPLACE`, EEXIST first, `do_renameat2` :5125 to :5126; unchanged in Linux's master) [src]. virtiofsd passes
  the guest's `renameat2` through unchanged (`passthrough/mod.rs` `rename`) [src], so its guest gets that 0. Here the
  source goes to a name the server makes (`.wick-recase-` and 16 hex digits) and then to the new case, each
  `RENAME_NOREPLACE` in the one held directory (`HostDir::recase`); if the new case still names something once the
  source is gone, it was another link, and the source goes back (EEXIST). Requests are served one at a time, so no guest
  request sees the middle name; a host process may, between the two renames, see neither name and the middle one, and a
  crash there leaves the object under it. A step that fails puts the source back; if a host process took the source's
  name meanwhile, EIO, with the object at the middle name, where its node still finds it.
- **Host names that are not guest names** (not UTF-8, an escape image of §6.3) are skipped by a listing and counted
  (`names_skipped`); no guest name reaches them (`test_host_names_that_are_not_guest_names_are_skipped`).
- **Extended attributes.** The record is `user.wick.stat` (Linux) or `wick.stat` (macOS); a guest attribute `n` is
  `user.wick.x.n` or `wick.x.n`. The host's other attributes are neither listed nor touched, and the guest cannot
  name the record (`test_host_xattrs_outside_the_prefix_are_not_shown`). Guest attribute names are at most 120 bytes
  on every host (§4.2).
- **Host hard links** to a file outside the share are that file. The server cannot tell where a file's other names
  are, so a guest write reaches them; the guest sees the link count, and its unlink removes the share's name only
  (`test_host_hard_link_to_a_file_outside_is_the_same_file`). It is the operator's to keep such links out of a share,
  as with any program given the directory; a guest cannot make one (LINK takes a node the share holds).
- **`fsync` and `fdatasync`**: Linux's own; on macOS both are `F_FULLFSYNC`, which asks the drive to write its cache
  to stable storage as Linux's `fsync` does (macOS's `fsync` only hands the data to the drive, fsync(2)). A file
  system without `F_FULLFSYNC` gets `fsync`. Slower on macOS, by the drive's flush.
- **Errors are Linux's numbers.** Linux passes its errno through. macOS maps each error the backend can see:

  | macOS | → Linux | macOS | → Linux |
  | --- | --- | --- | --- |
  | EAGAIN 35 | EAGAIN 11 | ENOATTR 93 | ENODATA 61 |
  | ENAMETOOLONG 63 | 36 | EOVERFLOW 84 | 75 |
  | ENOSYS 78 | 38 | EILSEQ 92 | 84 |
  | ENOTEMPTY 66 | 39 | ENOTSUP 45, EOPNOTSUPP 102 | EOPNOTSUPP 95 |
  | ELOOP 62 | 40 | ETIMEDOUT 60 | 110 |
  | EDQUOT 69 | 122 | ESTALE 70 | 116 |
  | EFTYPE 79 | EINVAL 22 | ENOTCAPABLE 107 | a layer-2 refusal (EACCES) |

  Errors 1 to 34 but 11 have the same numbers on both (macOS's 11 is EDEADLK, unmapped). Any other is EIO. `crates/fs/sys` `MAC_TO_LINUX`
  (`test_errno_table`, `test_errors_are_linux_numbers`).

**Stage 0's share checks** (`crates/fs/fsd/src/stage0.rs`, with the operator's rights, before any guest byte), each
a refusal that names the problem, none with a switch (`test_stage0_refusals`,
`test_stage0_and_renames_on_other_volumes`):

1. the canonical path (a link to a directory serves the directory; on macOS EPERM is reported as TCC's);
2. not a refused root: the system's trees (Linux `/bin`, `/boot`, `/dev`, `/etc`, `/lib*`, `/proc`, `/root`, `/run`,
   `/sbin`, `/sys`, `/usr`, `/var/lib`, `/var/log`, `/var/run`; macOS `/Applications`, `/Library`, `/System`, `/bin`,
   `/cores`, `/dev`, `/etc`, `/private/etc`, `/private/var/db`, `/private/var/root`, `/sbin`, `/usr/bin`, `/usr/lib`,
   `/usr/libexec`, `/usr/sbin`, `/usr/share`) and anything beneath them; directories that hold others' files
   (`/`, `/home`, `/Users`, `/tmp`, `/private/tmp`, `/var`, `/Volumes`, `/mnt`, `/opt`, ...) themselves; the home
   directory itself, and beneath it a directory whose first component starts with `.` (`~/.ssh`, `~/.config`) or,
   on macOS, `~/Library` (`refused_root`, `test_refused_share_roots`);
3. a directory, the same object the path names;
4. not a volume's root, and on a local file system (NFS, SMB, AFP, WebDAV and FUSE file systems are refused);
5. read-write only where the file system keeps extended attributes itself: Linux, an attribute read is not
   ENOTSUP; macOS, the volume's `VOL_CAP_INT_EXTENDED_ATTR`, as on msdos and exfat macOS keeps attributes in `._`
   AppleDouble files beside each file, which host tools and listings would see (measured: macOS 27.2 msdos image,
   `fsetxattr` succeeded and made `._f`). Without, a share is served read-only, with no records;
6. `RLIMIT_NOFILE` raised to the descriptors the limits let the server hold (`limits::descriptors`, §4.2) and read
   back, or refused if the hard limit is lower (macOS: or `kern.maxfilesperproc`, which xnu enforces when lower);
   the server binary then sets the soft limit to exactly that, lowering it where it was higher (§6.1, step 10);
7. beneath-resolution present, and names not folded by case unless the operator allowed it.

### 4.4 Cache modes

How long the guest may keep what the server tells it, per share. The names are virtiofsd's `cache=` (`passthrough/mod.rs`,
`CachePolicy`) [src]. The guest has no mount option for it: it caches what each reply allows
(`crates/fs/fsd/src/cache.rs`).

| Mode | Entry, attribute and negative-entry timeout | Opens | INIT |
| --- | --- | --- | --- |
| `never` | 0, no negative entries | `FOPEN_DIRECT_IO`: every read reaches the host | |
| `auto` (default) | 1 s, **provisional** (§10, question 10) | no `FOPEN_KEEP_CACHE`: a file's pages are dropped at each open (close-to-open, as NFS) | `FUSE_AUTO_INVAL_DATA`: a getattr that sees a new mtime or size drops them too |
| `always` | the share's timeout, a day by default | `FOPEN_KEEP_CACHE`, `FOPEN_CACHE_DIR` | |

A timeout is at most a day. Under `never`, a shared `mmap` of a file fails in the guest unless the server negotiates
`FUSE_DIRECT_IO_ALLOW_MMAP` (FUSE 7.39), which it does not yet. `always` is for shares nothing else changes.

### 4.5 The metadata record (`wick.stat`)

What the guest set that a host object cannot hold as the guest means it (§4.2, Metadata emulation;
`crates/fs/fsd/src/record.rs`). 40 bytes, little-endian, the same bytes on every host, so a share moved between hosts
keeps it.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `wkst` |
| 4 | 2 | version, 1 |
| 6 | 2 | flags: bit 0 mode, 1 uid, 2 gid, 3 rdev present |
| 8 | 4 | mode: Linux `st_mode`, type bits and `0o7777` |
| 12 | 4 | uid |
| 16 | 4 | gid |
| 20 | 4 | rdev major |
| 24 | 4 | rdev minor |
| 28 | 12 | reserved, 0 |

- A record that breaks any rule is refused (the operation fails with EIO and is counted), never reinterpreted or
  repaired: another length, magic or version; an unknown flag bit; a reserved byte, or an absent field's bytes, not
  0; a mode with bits beyond the type and `0o7777` or no known type; a type the host object cannot carry (a host
  directory only a directory's type, a host regular file any type but a directory's, a host symlink or other host
  object none).
- Without a record, or for a field it lacks, the guest sees the host's type and permission bits and the share's
  configured owner. A host symlink shows `0o777`; another host object (FIFO, device) shows as a regular file with no
  permission, and is never opened.
- Times, size and link count are always the host's.

---

## 5. Threat table

Attacker: a hostile guest kernel sending arbitrary FUSE frames (the Kata PoC builds its own virtqueue from guest
userspace, so even "guest root" suffices). Goal: anything outside "read/write regular files and directories under the
share root with the server user's rights".

| # | Threat | Linux | macOS | Windows | Sources |
| --- | --- | --- | --- | --- | --- |
| 1 | **Traversal by name** (`..`, `/`, absolute name, `a/../..`) | boundary check: one component, not `.`/`..`, no `/` or NUL; operations are `*at(dirfd, name)` only; `openat2 RESOLVE_BENEATH`; pivot_root confinement | same check; `openat` + `O_RESOLVE_BENEATH` (xnu-11417; 15.4+ unconfirmed, §0 row 19) and `AT_RESOLVE_BENEATH` (26+, xnu-12377); XNU returns `ENOTCAPABLE` for `..` at the start dir and for absolute paths from xnu-12377, EACCES in xnu-11417 (`vfs_lookup.c` `lookup`, `namei`; §0 row 19) [src]; Seatbelt `subpath` | same check, plus `\` and `:`; `NtCreateFile` with `RootDirectory` and a single component; rename/link use `FILE_RENAME_INFORMATION.RootDirectory` + simple name, **never** `RootDirectory=NULL` with a full path (allowed by the API [doc]); DACL confinement | Kata GHSA-2gv2-cffp-j227; virtiofsd 6ead577/35f851d; crosvm `validate_path_component`; libkrun (§3.1); [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html) [doc]; [FILE_RENAME_INFORMATION](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information) [doc] |
| 2 | **Symlink/junction swap races (TOCTOU)**, host- or guest-side | `RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS`, `O_NOFOLLOW`, `AT_SYMLINK_NOFOLLOW`; operations on fds opened and checked against the node's identity (`fchmod`, `fstat`, `f*xattr`; no `/proc/self/fd` reopen, §4.3) | `O_NOFOLLOW_ANY` (11+) [src: fcntl.h history], `AT_SYMLINK_NOFOLLOW_ANY`, `O_SYMLINK` for link objects, `XATTR_NOFOLLOW` | `OBJ_DONT_REPARSE` ("no reparse points will be followed ... fail with STATUS_REPARSE_POINT_ENCOUNTERED") [doc]; `FILE_OPEN_REPARSE_POINT` on the final component; then `FileAttributeTagInformation`: any reparse tag → not traversed (shown as a symlink or refused) [inf: measure on 20348/26300] | CVE-2016-9602; [OBJECT_ATTRIBUTES](https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_object_attributes) [doc] |
| 3 | **Crossing into another file system** (bind mounts, volume mount points, network mounts, devfs) | `RESOLVE_NO_XDEV`; v1 shows no submounts | compare `st_dev` after open; XNU's `RESOLVE_NOCROSSMOUNT`/`RESOLVE_NODEVFS`/`RESOLVE_LOCAL` are `__APPLE_API_PRIVATE` (`sys/paths.h`) [src], so they are not relied on | volume mount points are reparse points (`IO_REPARSE_TAG_MOUNT_POINT`) → refused by #2 | |
| 4 | **Aliases** that bypass name-based logic: case folding, Unicode normalization, 8.3 names, `/.vol/<dev>/<ino>`, `..namedfork` | identity by `(dev, ino)`; casefold dirs (`FS_CASEFOLD_FL`) checked per directory | APFS is normalization-insensitive, and case-insensitive by default; after each lookup or create, compare the stored name (`fgetattrlist ATTR_CMN_NAME`) with the requested one, and treat a mismatch as ENOENT/EEXIST; never build `/.vol` paths (libkrun does); `/..namedfork/` cannot be reached since `/` is rejected (XNU `RESOLVE_NOXATTRS` is private) [src] | after open, compare `FileNormalizedNameInformation` (long-name form) with the request → catches `PROGRA~1`-style 8.3 aliases [inf: measure]; per-directory case sensitivity via `FileCaseSensitiveInformation` [doc] | [Case sensitivity (WSL docs)](https://learn.microsoft.com/windows/wsl/case-sensitivity) [doc] |
| 5 | **Alternate data streams / EAs as a side channel** (`file:stream`, `dir::$INDEX_ALLOCATION`) | — | — | reject `:` in names (ADS syntax); the metadata EA is never guest-nameable | NTFS stream rules in FILE_RENAME_INFORMATION remarks [doc] |
| 6 | **Special files**: opening host device nodes, FIFOs (blocking), sockets | never open a non-regular, non-directory object (its kind read with `fstatat(AT_SYMLINK_NOFOLLOW)` first, the opened object checked with `fstat`, §4.3); never call `mknod` | same (`O_NOFOLLOW` + `fstat` before reading); FIFOs opened `O_NONBLOCK` only to stat, never for I/O | no device files on NTFS; `\\.\` names cannot be reached through relative names [inf]; reparse refused | CVE-2020-35517, CVE-2023-2861 |
| 7 | **setuid/setgid/file capabilities** on host objects | server unprivileged, no caps; host modes masked; emulated KILLPRIV semantics in the record (virtiofsd's fallocate/copy_file_range lesson, fc18227) [src] | same | same (no such bits on NTFS) | CVE-2022-0358 |
| 8 | **xattrs/ACLs** | guest xattrs prefixed into `user.`; `security.capability` emulated in the record; POSIX ACLs EOPNOTSUPP | prefixed; `com.apple.*` (quarantine, provenance, ResourceFork, FinderInfo) not guest-settable | EAs are case-insensitive ASCII names, so guest xattrs go into one EA blob; host DACLs are never changed by guest chmod | virtiofsd `--xattrmap` doc [doc] |
| 9 | **Ownership mapping** abused for privilege | emulated only; the server never calls `setresuid`/`fchown` with guest ids | same | same; not WSL's `$LX*` EAs (§3.1) | |
| 10 | **Open by handle/id escapes** (`open_by_handle_at`, `/.vol`, `FILE_OPEN_BY_FILE_ID`) | never use; no `CAP_DAC_READ_SEARCH` (the "shocker" container escape) | never use `/.vol`; the profile kills a `/.vol/<dev>/<ino>` read of an outside file (`confine_probe`) | not used with guest-influenced ids; ACL confinement still applies [inf: test] | virtiofsd README on DAC_READ_SEARCH [doc] |
| 11 | **Inode/handle exhaustion**; never-forgotten lookups | inode-table and handle caps (virtiofsd's `GuestFdSemaphore` idea, `guest_fd_limit.rs`) [src]; `RLIMIT_NOFILE` too | caps; `RLIMIT_NOFILE` | caps (no OS handle limit [meas: `jailer-test.ps1 nofile`]) | |
| 12 | **DoS**: huge directories, slow host fs, disk fill, CPU | bounded READDIR pages, bounded worker pool, queue cap; VMM rate limiter; CPU/memory via cgroup | same; jetsam + CPU limit (wick's jailer mechanisms) | same; Job memory/CPU/1-process | disk fill: host quotas only (§10) |
| 13 | **DAX window**: host truncation → fault in the VMM; host page cache mapped into the guest | not offered (ENOSYS) | not offered | not offered (NTFS also refuses to truncate a file with a mapped section, so semantics would differ) [inf] | virtiofsd `setupmapping` [src]; Cloud Hypervisor removed DAX [doc] |
| 14 | **Server access to guest memory** | none in design C | none | none | B would give all of it [doc] |
| 15 | **Guest-controlled lengths/fields** in FUSE frames | decoder bounds, fuzzing (§11); the VMM caps frames | same | same | |
| 16 | **Hostile server → VMM** (a compromised wick-fsd) | VMM validates replies (§4.1); the server cannot reach guest memory or the VMM process | same | same; no `PROCESS_DUP_HANDLE` either way | |
| 17 | **Socket hijack / impersonation** | accept once, `SO_PEERCRED`, unlink (connection.rs: `test_second_connection_refused`, `test_wrong_peer_refused`) | accept once, `LOCAL_PEERCRED`, unlink (the same tests) | accept once, `SIO_AF_UNIX_GETPEERPID` → token SID [meas: works across the AppContainer boundary, a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository] | |
| 18 | **Directory moved out of the share by the host** while the guest holds it | pivot_root does not stop it for held fds, but Landlock checks the hierarchy at access time [inf]; document | Seatbelt `subpath` is evaluated on the current path at access time [inf]; document | the DACL travels with the moved directory, so it **stays reachable**; document | trusted-host action in Firecracker's model |
| 19 | **Host consumers of guest-written content** (Spotlight/QuickLook, Defender, indexers, IDEs following symlinks) | doc: dedicated dir, exclude it from indexers | doc: `.metadata_never_index`, a dedicated volume | doc; antivirus exclusions weaken the host and are not recommended | residual risk on every host |
| 20 | **Untrusted server configuration** | operator-only command line; the VMM never forwards guest data into it | same | same | CVE-2026-44210 |
| 21 | **Two VMs sharing one directory** | allowed but documented: they can race and signal each other through it | same | same | |

**Test principle:** layers 2 and 3 (beneath-flags and the OS sandbox) must never be what stops an attack. Any
`ENOTCAPABLE`/`EXDEV`/Seatbelt denial/`ACCESS_DENIED` raised by a traversal corpus counts as a failed test, because
it means layer 1 let the request through.

---

## 6. Per-host design

### 6.1 Linux

- **Confinement:**
  - Unprivileged: `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC)` with a 1:1 map of
    the caller's uid, bind-mount the share (read-only bind for `--read-only`), `pivot_root`, `umount` the old root,
    then `no_new_privs`, seccomp, and Landlock where available.
  - As root: the same without the userns, then drop to an unprivileged uid with no capabilities.
  - If none of these is possible (unprivileged user namespaces disabled, as with Ubuntu's AppArmor userns
    restriction), **fail loudly**. Landlock alone is not enough: it "currently [cannot] restrict ... chmod(2),
    chown(2), setxattr(2), utime(2) ..." ([Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)) [doc].
  - **Stock hosts restrict unprivileged user namespaces**, so the root start is the common one:
    - Ubuntu: 23.10 added `kernel.apparmor_restrict_unprivileged_userns`, under which an unconfined process's new
      user namespace gets AppArmor's `unprivileged_userns` profile and no capabilities in it
      ([Canonical, 2023-10-09](https://canonical.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces);
      [spec](https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626))
      [doc], and 24.04 turns it on by default ([LP #2046477](https://bugs.launchpad.net/bugs/2046477)) [doc].
      GitHub's ubuntu-latest (Ubuntu 26.04 now) and ubuntu-24.04-arm have it on: as the runner's user, the `unshare`
      succeeds and the write of `/proc/self/setgroups` in the new namespace is refused (EACCES), so wick-fsd refuses
      naming that file, and `confine_probe` says "ran nothing confined:
      kernel.apparmor_restrict_unprivileged_userns = 1" (CI run 44225041771's fs jobs). There, as a user without the
      profile below, every confined test checks that refusal instead (a user namespace's step named, nothing served,
      no confined child: `is_userns_refusal` in `tests/common/remote.rs`); the confined child's own steps are reached
      as root (the sudo step) and under the profile (the AppArmor step). `WICK_FS_TEST_SIMULATE_USERNS_RESTRICTED=1`
      runs that branch on a host without the restriction: each server the tests start does so under a filter that
      refuses its setgroups write with EACCES, as the restriction does.
    - Debian: its own kernel patch's `kernel.unprivileged_userns_clone`, 0 (off) before bullseye (11) and 1 since
      ([bubblewrap's README.Debian](https://sources.debian.org/src/bubblewrap/0.11.0-2/debian/README.Debian)) [doc].
    - RHEL and others: upstream's `user.max_user_namespaces`, 0 disables them
      ([kernel docs](https://docs.kernel.org/admin-guide/sysctl/user.html)) [doc]; RHEL 7 needed
      `namespace.unpriv_enable=1` as well ([Red Hat bug 1499046](https://bugzilla.redhat.com/show_bug.cgi?id=1499046))
      [doc], and the RHEL 9 STIG sets it to 0 where no containers run
      ([V-257816](https://stigviewer.com/stig/red_hat_enterprise_linux_9/2023-12-01/finding/V-257816)) [doc].

    What an operator does: start wick-fsd as root with `--uid`/`--gid`, as the jailer will (decision 6): the
    supported path, which every confined test runs as root on CI. The tested alternative on Ubuntu is an AppArmor
    profile that grants `userns` to the wick-fsd binary alone, by its absolute path, and nothing else
    (`flags=(unconfined)`, Ubuntu's way for a program that needs user namespaces); wick-fsd then starts as the
    operator's user and confines itself in a user namespace of its own:

    ```text
    abi <abi/4.0>,
    include <tunables/global>

    profile wick-fsd /absolute/path/to/wick-fsd flags=(unconfined) {
      userns,
    }
    ```

    loaded with `sudo apparmor_parser -r FILE` (or as `/etc/apparmor.d/wick-fsd`, which loads at boot) and removed
    with `sudo apparmor_parser -R FILE`. The CI fs job loads this profile for the built wick-fsd and `confine_probe`,
    runs the confined tests as the runner's user with `WICK_FS_TEST_USERNS_GRANTED=1`, and removes it whatever
    happened; `tools/linux/fs-userns-check.py` gives the step's verdict from each binary's whole output: every binary
    passed, none ran nothing confined, and each other "ran nothing" line is one it knows, printed with why it is not a
    confined test left unconfined (a root-only read, the root-only id drop, the restricted host's refusal test). CI
    run 44238015541 is its first full pass, on ubuntu-latest (Ubuntu 26.04) and ubuntu-24.04-arm: the server's 23
    tests, `confine_probe`'s 18 cases, the corpus's 2 and the link sequences' 18, as the runner's user under the
    profile (in 44233741878 the server's tests had passed and the step failed on its own output filter, since
    replaced). Without such a grant, wick-fsd started as a user on a restricted host refuses at its user namespace's
    first step that fails, and names what the host says restricts it, read, never guessed from the errno: each
    sysctl that does (`kernel.apparmor_restrict_unprivileged_userns = 1`, `user.max_user_namespaces = 0`,
    `kernel.unprivileged_userns_clone = 0`) and the AppArmor profile Ubuntu put the process in
    (`/proc/self/attr/apparmor/current`, `unprivileged_userns (enforce)` on both runners after `unshare`, run
    44233741878), then "start wick-fsd as root with --uid and --gid, or grant this binary user namespaces with an
    AppArmor profile" (`userns_restriction`, `test_the_restriction_is_named_as_read`; one sysctl at a time, the
    server started as 65534 with a stand-in for it bound over `/proc/sys` under the simulated restriction:
    `test_the_refusal_names_the_restriction_it_reads`, which execs a link or copy of wick-fsd in the temporary
    directory: execve needs every directory of the path searchable, and a runner's home, where the build is, may
    not be by others (run 44244968658: EACCES at the spawn; the sudo step records the path with `namei -l`); the host's own in `test_userns_restricted_refused`, whose
    refusal the unit step prints on record). A helper step of the tests' that fails before the exec names itself on
    the child's stderr (`pre_exec: <step> failed (errno N)`), so a failed spawn is the exec's own. wick
    never asks an operator to turn a host-wide restriction off: it guards every program on the host.
  - Landlock first appeared in Linux 5.13 [doc], and upstream supports 5.10 hosts (docs/kernel-policy.md) [src], so it
    is an added layer, never the only one.
  - **As built** (`crates/fs/fsd/src/confine/linux.rs`, the calls in `crates/fs/sys/src/unix/confine.rs`), after
    stage 0 has accepted the one connection and checked its peer:
    1. `unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWIPC)`, with `CLONE_NEWUSER` when not root (its own uid
       and gid mapped 1:1, `setgroups` denied);
    2. `fork`: the child is pid 1 of the new pid namespace. The parent drops the connection and everything else it
       holds but its end of the pipe the child watches and the standard streams, then confines itself: the child's
       `--uid`/`--gid` when root-started, every capability dropped, not dumpable, `no_new_privs`, and a seccomp filter
       of its own, `PARENT_SYSCALLS` (`wait4`, `write`/`writev` for its one line, `rt_sigreturn`, `restart_syscall`,
       `exit_group`, `exit`; anything else kills it). It takes no input and needs to signal nothing (the child dies
       with it), but it lives as long as the share, so it keeps nothing it does not need
       (`test_confined_status` reads its `/proc/<pid>/status` as the child's). A step that fails ends it, and the
       child with it. It waits and exits as the child did, by `_exit` (a child killed by the filter shows as signal
       31, SIGSYS, logged);
    3. the child: `PR_SET_PDEATHSIG` SIGKILL (killing wick-fsd kills it), not dumpable (no ptrace or `/proc/<pid>`
       access for the host's processes of its uid), every mount private, the share bind-mounted onto itself without
       what is mounted beneath it, remounted `nosuid,nodev,noexec` (read-only for `--read-only`, and keeping the flags
       the mount is locked with); then its descriptors, the kernel's whole list from `/proc/self/fd` (the last point
       it is in the root), required to be exactly the standard streams, the connection, its end of the parent's pipe
       and stage 0's root (`held_exactly`): everything opened since the first step is one of these or closed again
       (the listener and `--ready-fd` after the ready byte, the setgroups and map writes, `/proc/self/task`), so this
       is an equality, not a subset, and anything else is named and refused; then `pivot_root` into it and the old
       root detached;
    4. `/` opened and checked to be the object stage 0 checked (else refused), and the backend made on it;
    5. the bounding set emptied while `CAP_SETPCAP` is held (each drop asks for it, security/commoncap.c, v6.12,
       `cap_prctl_drop` :1235 to :1248, and a drop from root takes it with the permitted set, `cap_emulate_setxuid`
       :1085 to :1098) [src], a capability that cannot be dropped a refusal; then, as root, `--uid`/`--gid`
       (required, never 0) with no supplementary groups, every id checked; not root, no `--uid`;
    6. every other capability dropped (ambient, effective, permitted, inheritable), the bounding set checked empty
       (SECURITY.md, Fixed defects: it used to be dropped after the ids, and the refusal taken as nothing left);
       then the parent-death
       signal and not-dumpable of step 3 set again, the parent checked alive through the pipe: a change of the
       effective or file-system ids clears the signal and sets dumpable to `fs.suid_dumpable` (`commit_creds`,
       kernel/cred.c, v6.12, :406 to :413) [src] (`test_the_confined_server_dies_with_its_parent`; SECURITY.md,
       Fixed defects);
    7. `no_new_privs`;
    8. Landlock where the kernel has it: file rights beneath the new root only, never execute or making devices,
       sockets, FIFOs or symlinks (the server makes regular files only); TCP bind and connect handled with no rule
       (ABI 4); abstract Unix sockets and signals scoped (ABI 6). Without Landlock the server says so on stderr and
       goes on (decision Q11, `test_landlock_absent_is_logged`);
    9. the seccomp filter: `SERVER_SYSCALLS`, each system call with why and its argument rule (`ioctl` only
       `FS_IOC_GETFLAGS`, `fcntl` only `F_GETFL`/`F_GETFD`, `mmap`/`mprotect` never `PROT_EXEC`, `sendto`/`recvfrom`
       without an address, `tgkill` only SIGABRT); this architecture only and no x32; anything else
       `SECCOMP_RET_KILL_PROCESS`. No `openat` (opens are `openat2` beneath a held directory), no `socket`, `clone` or
       `execve`, no `mknodat`, `setresuid`, `setresgid` or `capset`. The path-taking calls the server makes have
       the rules their arguments allow, so that no form that follows a link or makes what the server never makes is
       there even inside the pivoted root: `utimensat` only with no path (`futimens`), `linkat` with no flags (never
       `AT_SYMLINK_FOLLOW` or `AT_EMPTY_PATH`), `newfstatat` and `statx` only with `AT_SYMLINK_NOFOLLOW` or
       `AT_EMPTY_PATH`, `unlinkat` with no flag or `AT_REMOVEDIR`, `mkdirat` with mode 0o700 only, `renameat2`
       with no flag, `RENAME_NOREPLACE` or `RENAME_EXCHANGE` (never `RENAME_WHITEOUT`), `fchmod` never setuid,
       setgid or sticky. The last two are what the server sends for any guest request: `HostDir::mkdir` makes every
       directory 0o700 and `HostDir::set_perm` passes the guest's permission bits with its own access
       (`(mode & 0o777) | 0o700` or `0o600`), the guest's mode, special bits included, kept in the record
       (`test_a_guest_s_special_mode_bits_pass_the_filter`). `confine_probe` makes each refused form and must be
       killed. No rule is possible for
       `readlinkat` (no flags; it never follows its last component, and the server gives it one) or for `openat2`'s
       `RESOLVE_*` (in a structure behind a pointer, which a seccomp filter cannot read: classic BPF sees only the
       system call's number and argument values, Documentation/userspace-api/seccomp_filter.rst) [doc]: those rest on
       the server's single-component names, `pivot_root` and Landlock. One more entry is never made for what it
       does: `getppid`, which cannot fail, fails with `ENOTRECOVERABLE` under this filter and no other, for step 10;
    10. read back, in one place (`confine::linux::check`), from the calls that read each (`/proc` is not in the new
       root): the four uids and gids (`--uid`/`--gid`, or the real ones, none apart), no supplementary groups as
       root, every capability set empty, `SECBIT_KEEP_CAPS` clear, `no_new_privs`, the parent-death signal SIGKILL,
       not dumpable, all read just before the filter, and the filter by its own effect just after. One refusal names
       everything that did not hold (`test_each_thing_that_did_not_hold_is_named_in_one_refusal`). Before them, its
       descriptors by number (`fcntl(F_GETFD)` over every one below the soft `RLIMIT_NOFILE`, where the kernel gives
       each new one the lowest free number, so every descriptor it opened itself is seen; above it nothing was open
       at step 3's list), required to be exactly the standard streams, the connection and the backend's root
       (`test_descriptors_held_exactly`). The soft limit is set after stage 0 to exactly what the share's limits may
       hold open (`limits::descriptors`, 2112 by default): the server needs no more, and the walk costs 0.4 ms there
       against 193 ms at Docker's default soft limit of 1048576 (measured in Docker's linuxkit 7.0.14, aarch64). A server that is
       not root keeps its user's supplementary groups: its user namespace denies `setgroups` (user_namespaces(7))
       [doc], and they grant nothing its user does not have.

    Only then are the hellos exchanged and a frame read. Each step is required and a failure is a refusal naming it;
    there is no flag that skips one.

    **What a later step could reset**, from the kernel's source (v6.12) [src], for each state set before a change
    of credentials or namespaces:

    | State | Set at | What could reset it later | Read back (step 10) |
    |---|---|---|---|
    | parent-death signal | step 3, again in step 6 | `fork` gives a child none (kernel/fork.c :2453): set in the child. `commit_creds` clears it when the euid, egid, fsuid or fsgid changes or the new permitted set is not a subset of the old (kernel/cred.c :406 to :413, `cred_cap_issubset` :353 to :376): the drop to `--uid`/`--gid` does, so step 6 sets it again after. `unshare(CLONE_NEWUSER)` commits new credentials (kernel/fork.c :3360) but counts as a subset (the new namespace's owner is the euid, cred.c :369 to :373), and it comes before step 3; the capability drops only shrink the permitted set; Landlock's `commit_creds` (security/landlock/syscalls.c :524) changes no id. The signal is the dying parent's kill, checked as one (kernel/exit.c :712 to :714, `check_kill_permission` in kernel/signal.c :839 to :860, `kill_ok_by_cred` :814 to :823: a uid of the sender must match the target's, or the sender has `CAP_KILL`): after both drops the two have the same ids (as root `--uid`/`--gid`; as a user that uid, in the one user namespace), so it is sent, and SIGKILL reaches the child although it is its pid namespace's init, the sender being outside it (signal.c :1222). As root, between the parent's drop and the child's step 6, the parent is `--uid` and the child still root: a death then is refused, silently, and the child ends at step 6, which checks the parent's pipe after arming the signal (`die_with_parent`); the refusal tests whose parent fails after its drop end so, each checking that no process of the server is left (server.rs, `no_confined_child_left`) | `PR_GET_PDEATHSIG` |
    | not dumpable | step 3, again in step 6 | the same `commit_creds` rule sets `fs.suid_dumpable` | `PR_GET_DUMPABLE` |
    | `uid_map`, `gid_map`, `setgroups` deny | step 1 (not root) | the writes set the namespace's maps and flag, not the process's credentials (kernel/user_namespace.c `map_write` :922, `proc_setgroups_write` :1215: no `commit_creds`), and nothing writes them again | the ids |
    | securebits | (none set) | `unshare(CLONE_NEWUSER)` sets them to the default and every capability set to full in the new namespace (kernel/user_namespace.c `set_cred_user_ns` :43 to :53); `execve` clears `SECBIT_KEEP_CAPS` (security/commoncap.c :961), with which a drop from root would keep the permitted set (:1085 to :1098); step 6 empties every set whatever they are | `PR_GET_SECUREBITS` (`SECBIT_KEEP_CAPS` clear), `capget`, `PR_CAPBSET_READ`, `PR_CAP_AMBIENT_IS_SET` |
    | `no_new_privs` | step 7 | nothing: `PR_SET_NO_NEW_PRIVS` only sets it (kernel/sys.c :2619 to :2624) | `PR_GET_NO_NEW_PRIVS` |
    | Landlock domain | step 8 | nothing: a domain is only ever stacked onto (syscalls.c :513, `landlock_merge_ruleset`) | not possible: the kernel has no call that reads a domain (syscalls.c: `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self` only); `landlock_restrict_self` returns 0 only from the `commit_creds` of the new domain (:524) |
    | seccomp filter | step 9 | nothing: filters are only ever added (kernel/seccomp.c `seccomp_set_mode_filter` :1990 to :1996), and its install changes no credentials | the `getppid` probe |

    **Refusal tests.** `test_refused_without_*` make a system call fail for the first process that makes it; for the
    steps both processes take (`setresuid`, `capset`, not dumpable, `no_new_privs`, the filter) that is the waiting
    parent, and they now check its refusal ("the waiting parent: ..."). The child's own steps are reached by a test
    filter that tells a supervisor in the test of each such call (`SECCOMP_RET_USER_NOTIF`): it lets the parent's call
    through as made and answers the child's (by its pid namespace) with a failure, or with a 0 for a call it did not
    make, which only the read-back finds (`in_the_child`; `test_the_child_s_parent_death_signal_steps`,
    `test_the_child_s_dumpable_steps`, `test_the_child_s_id_drop`, `test_the_child_s_capability_drop`,
    `test_the_child_s_no_new_privs`, `test_the_child_s_seccomp_filter`). Where the host makes a step's state hold
    without it, the test checks that it holds: as root, the drop to 65534 empties the capabilities and sets dumpable to
    `fs.suid_dumpable`; a test filter installed without `CAP_SYS_ADMIN` needs `no_new_privs` itself, and without
    `no_new_privs` the kernel refuses the server's Landlock domain and filter (security/landlock/syscalls.c :488,
    kernel/seccomp.c :683 to :684). The steps only the child takes (`PR_SET_PDEATHSIG`, the mounts, `pivot_root`,
    Landlock) are failed by the first-caller tests too. No test makes these fail in the child: the check that the new
    root is the object stage 0 checked (it needs the share replaced between the two, a race no test wins on purpose);
    the parent-alive check of steps 3 and 6 (`EIDRM` when its pipe is closed); and a Landlock domain that was said to be
    made and was not, which nothing can read back.

- **Resolution:** `openat2(2)` (Linux 5.6+) with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`
  and a single component; no fallback (§4.3). Nodes as on macOS (§4.3): directories held open, anything else a
  leaf found by its known names and checked at each use. Not `O_PATH` fds reopened through `/proc/self/fd` as
  virtiofsd does (`passthrough/util.rs`): that needs `/proc` inside the namespace and a magic-link reopen, and would
  make Linux behave unlike macOS when the host renames a file the guest holds.
- **seccomp:** list like crosvm's `fs_device.policy` [src], minus `mknodat`, `setresuid`/`setresgid` and
  `capset` (ownership is emulated).
- **No** file handles (`name_to_handle_at`), no `CAP_DAC_READ_SEARCH`, no DAX.

### 6.2 macOS (Apple silicon; wick supports macOS 15, 26, 27)

- **Confinement:** stage 0 resolves the share with `realpath` and checks it; Seatbelt matches the canonical path at
  each access. The share reached by its firmlink form (`/System/Volumes/Data/...` vs `/Users/...`) is an open
  question; an outside file by its firmlink alias or by `/.vol/<dev>/<ino>` is killed (`confine_probe`). As root,
  `confine_probe` drops to 65534, so its share and canaries are under `/tmp` and the share's file is 65534's: under
  root's own temporary directory (`/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T`, mode 0700, std's choice when
  `sudo` clears `TMPDIR`) every case by path was refused at that directory before the profile was asked (CI run
  44317533490); the probe now fails naming any directory above the canary the dropped id cannot search. The server
  itself reaches the share through descriptors only, so where the share's parents are does not change it.
  - **As built** (`crates/fs/fsd/src/confine/macos.rs`, the calls in `crates/fs/sys/src/unix/seatbelt.rs`), after
    stage 0 has accepted the one connection, checked its peer, and the backend holds the share's root. There is no
    fork: the process that accepted the connection serves it. wick-fsd on macOS forks nothing and spawns nothing at
    any point (its sources have no `fork`, `posix_spawn` or `Command` outside tests), and once confined the profile
    kills a fork (confine_probe's "fork" case). That matters beyond the confinement: a fork made while another thread
    is inside a first-time `os_once` gives the child that gate held by a thread it does not have, and libSystem's fork
    child handlers abort it before it can exec (`_notify_fork_child`: "os_once_t is corrupt", "crashed on child
    side of fork pre-exec"; CI run 44375259298 on macOS 15.8.2, a test whose other thread's libsandbox made the
    process's first libnotify registration through `os_log`; 1117 of 1500 children in a C program on macOS 27.2,
    a thread's first `notify_register_check` against the main thread's `fork`). The tests start programs with
    descriptors set up through `sys::launch`, which on macOS is `posix_spawn` with file actions, no fork in the test
    process (`test_a_launch_while_another_thread_first_registers_with_libnotify`: 100 rounds, each a fresh process
    whose other thread makes its first registration, none lost; std's fork with `pre_exec` on record beside it);
    the forking helpers (`command_with_*`) are Linux-only; the probe's own fork (`probe::fork`) is refused unless
    the process has one thread, as Linux's `confine::fork` is. Every other product fork on macOS refuses unless the
    process has one thread: the jailer's (`--daemonize`'s two, the new pid namespace's, the freezer's self-check and
    supervisor) through overlay/jailer/platform/macos/mod.rs `fork_alone` (`test_daemonize_refuses_a_second_thread`;
    the jailer starts no thread), Firecracker's (the jail's API process, the profile's compiler) through
    overlay/vmm/ext/api_process.rs `fork_alone`.
    0. libc's first uses that read what the profile denies, made once before it on the share's root and kept by
       libc for the process's life (`first_uses`; `confine` takes its proof, so no profile is applied before it):
       one `fdopendir` of the root, closed again (below, after the allocator table). Its failure, the root not
       opened again as a directory, is a refusal naming it
       (`test_first_uses_refused_by_name_where_the_root_is_no_directory`);
    1. the profile below built for the canonical path and compiled (`sandbox_compile_string`), with the operator's
       rights;
    2. as root, `--uid`/`--gid` (required, never 0), its one group the gid's; not root, no `--uid`;
    3. the ids read back; its descriptors, the file table's whole list (`proc_pidinfo`), required to be exactly the
       standard streams, the connection and the backend's root (`held_exactly`, as on Linux); the soft
       `RLIMIT_NOFILE`; and that no profile is in force yet (`sandbox_check` with no operation). Each of these is a
       call the profile kills, so it is read before it. Then the compiled profile applied (`sandbox_apply`);
    4. under the profile, its descriptors by number (`fcntl(F_GETFD)` below the soft limit) exactly those again,
       then one read-back (`confine::macos::check`): the real and effective uids and gids, the one group as root,
       no saved id of 0 to go back to (`seteuid(0)` and `setegid(0)` refused), and no profile before this one. A
       second profile cannot replace it: a second apply is a Sandbox mac-syscall, which the profile kills
       (Seatbelt itself refuses a second profile over one with any denial, EPERM; over `(allow default)` alone it
       takes it, so such a profile counts as none: measured on macOS 27.2, and `confine_probe` keeps the first
       on record).

    Only then are the hellos exchanged and a frame read. Each step is required and a failure is a refusal naming
    it; there is no flag that skips one (`test_what_held_is_served_and_what_did_not_is_named`).

    **Refusal tests** (`crates/fs/fsd/tests/refusals.rs`, as the user and, on CI, as root). The server runs with a
    library the test builds and inserts (`DYLD_INSERT_LIBRARIES`), macOS's stand-in for Linux's test filter, and must
    refuse naming the step: the profile not compiled (`test_refused_when_the_profile_does_not_compile`), not applied
    (`test_refused_when_the_profile_is_not_applied`), the id drop refused at `setgroups`
    (`test_refused_when_the_id_drop_fails`; a server that is not root is taken for root so that it drops), the
    listener's close said done and not done, so a descriptor it did not keep is open before the profile
    (`test_refused_when_a_descriptor_survives_its_close`), `seteuid(0)` said done at the read-back
    (`test_refused_when_a_saved_id_is_left`), and another profile with a denial applied before `main`
    (`test_refused_under_another_profile`). With the library inserted and doing nothing the server serves
    (`test_the_inserted_library_alone_changes_nothing`). The apply leaving a descriptor open is found by the walk
    under the profile and refused, the descriptor named by its kind alone, as asking for its path (`F_GETPATH`)
    is a command the profile kills (`test_refused_when_the_apply_leaves_a_descriptor`). Not made to fail: the walk
    itself (`fcntl(F_GETFD)` below the soft limit), which cannot lie for one call without lying for every `fcntl`
    the server makes; the equality it checks is tested before the profile.
  - **The profile** (`BASE` and `profile`): `(deny default (with send-signal SIGKILL))`, so whatever no rule
    allows ends the process inside the call; a denial means the server's own checks let a request through, and it
    dies loudly (the VMM sees the connection close). System calls, Mach traps, MIG routines and Sandbox
    mac-syscalls are killed unless listed, and so are generated code (`dynamic-code-generation`) and the issue of
    sandbox extensions. The lists are by number or name, each entry with why (table below): `SYSCALLS`,
    `MACH_TRAPS` (libmalloc's `_kernelrpc_mach_vm_map_trap`, `mach_msg2_trap` and, for macOS 15's magazine,
    `_kernelrpc_mach_vm_deallocate_trap`, for a frame of up to 2 MiB and the node tables), and `mach_vm_reallocate` where the kernel defines it (`(when (defined? ...))`: the routine is in
    xnu from xnu-12377.101.15, so macOS 15 and the macOS 26 releases before it do not compile the name;
    `test_every_name_of_the_profile_is_defined_on_this_macos` checks each such name bound exactly from its first
    xnu). Those traps were measured on macOS 27.2, whose allocator for wick-fsd is xzone (crash reports of a killed
    server show `_xzm_*` frames; the probe's `malloc_engaged_secure_allocator()` is 1). A zone found by a block's
    address does not say which: `malloc_zone_from_ptr` gives the default zone's wrapper, `virtual_default_zone`
    (version 10, libmalloc malloc.c), on every major, so the probe's first record line, "DefaultMallocZone, version
    10" on both 27.2 and 15, named the wrapper; it now prints the engaged allocator instead. macOS 15's
    libmalloc-715.140.5 picks the magazine allocator for a binary that is not the platform's unless its
    `SecureAllocator` feature flags say otherwise (malloc.c :700 to :727), and CI's crash reports on macOS 15.8.2
    show it (`szone_malloc_should_clear`). There a block past 32 KiB is medium up to 8 MiB where the medium
    allocator is engaged, which on arm64 is always (malloc.c :357; on x86_64 only at 32 GiB of memory or more,
    thresholds.h), so every block of the server's (a frame is at most 1 MiB + 4 KiB) is medium on the Apple silicon
    Macs wick runs on, and large (past 32 KiB, magazine_large.c) only on an x86_64 Mac, which wick does not run on.
    A medium block comes from a region of 128 MiB (magazine_medium.c :2448, `mvm_allocate_pages` aligned to
    2^27), mapped with `_kernelrpc_mach_vm_map_trap` (15); when the mapping lands above the entropic limit, libmalloc
    gives it back with `mach_vm_deallocate` (`_kernelrpc_mach_vm_deallocate_trap`, 12) and maps again 256 MiB lower
    (vm.c :245, `mvm_allocate_plat`): so trap 12 comes with a new region, whenever one is made, not with a free.
    The large paths make further calls (magazine_large.c): a large block grows in place with `vm_allocate` at the
    address after it (`_kernelrpc_mach_vm_allocate_trap`, 10; `large_try_realloc_in_place`, libsyscall mach_vm.c);
    a freed one is marked with `madvise(MADV_CAN_REUSE)` (system call 75) and kept in a cache of 16 entries (64 at
    32 GiB or more), whose oldest is given back with `mach_vm_deallocate` (12) when it is full (`free_large`); the
    table of large blocks grows by a new mapping and gives the old one back with `mach_vm_deallocate`
    (`large_entries_grow_no_lock`); and a realloc that moves a block copies with `vm_copy` past 2 MiB of data
    (magazine_malloc.c :592). CI run 44347657778's macos-15 job killed a confined realloc of 3 MiB to 8 MiB at trap
    12 (`deny(1) syscall-mach 12`; no crash report of that process was kept, so not which path). confine_probe now checks the server's own shapes, each done confined:
    a zeroed block of the largest frame (1 MiB + 4 KiB) allocated and freed, a buffer grown by appends to it (the last
    growth to 2 MiB), a realloc of 256 KiB to it, the node tables grown entry by entry to their cap (2^18 nodes,
    each growth a new table and the old one freed: the largest, the node map, is 2^19 buckets of its entry), and
    96 large blocks of the server's sizes held and freed (past the cache); each runs again under the profile with
    every unlisted call allowed and reported, and the probe prints Seatbelt's reports by the case's pid, with the
    allocator on record (the engaged allocator, `MallocReportConfig`'s lines, the memory size and architecture).
    The realloc of 3 MiB to 8 MiB is on record only. On macOS 27.2 (xzone) a zeroed block of the largest frame was
    killed at `madvise` (`deny(1) syscall-unix 75`) in 7 of 8 runs, and its reporting run reported `allow
    syscall-unix 75`; the control (`task_info`, an unlisted MIG routine) reports `allow syscall-mig 195`. What
    decides it: xzone hands out a large block it had freed (not pristine) after clearing it when the caller asked
    for zeroes (`calloc`, Rust's `vec![0; n]`), with `madvise(MADV_ZERO)` (libmalloc-812.100.31 xzone_segment.c,
    `_xzm_segment_group_clear_chunk`), and a fresh one without; a case's child inherits its parent's heap, so whether
    its first block was fresh was chance. It also gives a freed large chunk's pages back with `madvise` where the
    kernel's deferred reclamation is not in use (`_xzm_segment_group_uses_deferred_reclamation`). The server makes
    that shape on every READ: its reply buffer is `vec![0u8; want]` (session.rs, `read`), and the crash report of a
    confined server killed there shows `madvise` ← `_xzm_segment_group_clear_chunk` ← `xzm_segment_group_alloc_chunk`
    ← `_xzm_malloc_large_huge` ← `Session::read`. So `madvise` (75) is in `SYSCALLS`: it acts on the caller's own
    map only (xnu bsd/kern/kern_mman.c, `user_map = current_map()`), and Seatbelt has no filter on its advice
    (libsandbox's filters on a call's argument are `fcntl-command`, `ioctl-command`, `fsctl-command` and the like;
    none for `madvise`), as Firecracker's own profile allows it. Each shape now repeats its allocation 16 times in
    one child, so a block freed earlier in it is handed out again whatever the child inherited, and each runs four
    times under the reporting profile, the union of what they report printed.
    `test_a_confined_server_answers_large_reads_again_and_again` (requests.rs) reads 1 MiB 64 times from a confined
    server, which must stay up and answer each with the file's bytes; without the entry it was killed at its second
    READ. macOS 15's report came from CI run 44362564244 (95ea43f9, macOS 15.8.2, an arm64 runner of 7.5 GiB): every
    allocator shape reported trap 12 and nothing else unlisted, in 1 to 4 of its 4 runs (the node tables in all 4),
    and four of the five were killed at it confined; the realloc past 2 MiB reported it too; a confined server of
    requests.rs was killed at it in `Session::read`'s `vec![0u8; want]` (crash report: `mach_vm_deallocate` ←
    `mvm_allocate_pages_plat` ← `medium_malloc_should_clear`). So `_kernelrpc_mach_vm_deallocate_trap` (12) is in
    `MACH_TRAPS`, by its `MSC_` name, on every major: the name is defined on macOS 15, 26 and 27 (Firecracker's
    profile lists it unconditionally and compiles in the macos-seatbelt jobs on macos-15 and macos-26, and here on
    27.2), and the trap acts on the caller's own task only (xnu-11417 osfmk/ipc/mach_kernelrpc.c :77,
    `port_name_to_current_task_noref`, as every `_kernelrpc_mach_vm_*_trap`). `vm_allocate` (10) is not: no run has
    reported it (the server's blocks are not large on Apple silicon). What each major's allocator was measured to
    call, beyond `_kernelrpc_mach_vm_map_trap` and `mach_msg2_trap`:

    | macOS | Allocator, and the class of the server's blocks | Calls the server's shapes make | Measured by |
    | --- | --- | --- | --- |
    | 15.8.2 (24H232), arm64, 7.5 GiB (CI's macos-15) | magazine (crash reports' `szone_*` frames); medium, as on every Apple silicon Mac whatever its memory | trap 12 (a new medium region); `madvise` not on record (allowed before the run) | CI run 44362564244: confine_probe's reports, crash reports of the probe and of confined servers |
    | 26.7.2 (CI's macos-latest) | not on record yet | not on record yet (its fs job passed at de8805f4, before the allocator shapes) | the next CI run's confine_probe |
    | 27.2, arm64 (here) | xzone (crash reports' `_xzm_*` frames) | `madvise` (75, `MADV_ZERO` on a reused zeroed block); `mach_vm_reallocate` where defined; deferred reclamation's accounting trap (63) at the first free 10 s after the last sample (below) | the C allocation program (c15/sbx/alloc.c), confine_probe, requests.rs |

    The size class depends on the machine (architecture and memory, above), so a user's Mac and a runner can
    differ; the probe prints both with its reports. The same run's crash reports show a second kill on macOS 15,
    not an allocator's, which the probe's shapes do not make: `deny(1) syscall-unix 202` (`sysctl`) in
    `fdopendir` (`__sysctl` ← `sysctlbyname` ← `__opendir_common`), in links.rs and requests.rs. Libc's
    `__opendir_common` reads `kern.secure_kernel` once per process (`__kernel_supports_unionfs`, a static filled on
    first use; gen/FreeBSD/opendir.c in Libc-1669 to 1725, macOS 15 and macOS 26.0 to 26.3; gone from Libc-1752,
    macOS 26.4 on, and from 27.2 here). There a confined server was killed at its first READDIR, or its first
    search of a directory for a name a node no longer keeps (`HostDir::search`). Step 0 (`first_uses`) makes one
    `fdopendir` of the share's root before the profile, which fills that static, so the confined server never
    makes the call; no rule is added, and `sysctl` stays killed. The confined tests (requests.rs's every-request
    set and links.rs, a READDIR and a search each under the profile) check it on each major CI runs, and
    confine_probe records, on each, whether a fresh process confined without step 0 is killed at its first
    `fdopendir` ("record: the first fdopendir confined without step 0"): signal 9 where Libc makes the call, exit 1
    where it does not; when every major says exit 1, step 0's `fdopendir` can go. Seatbelt does not check the number of some calls at all (Firecracker's
    `UNFILTERED_SYSCALLS` in `overlay/vmm/ext/sandbox.rs`: `openat`, `close`, `write`, `pwrite`, `fchmod`,
    `fsetxattr`, `fremovexattr`, `linkat`, `unlinkat` among those wick-fsd makes); for those the file rules decide.
    `fcntl`'s command is checked too (`system-fcntl`, below).

    What the listed calls still allow. Seatbelt checks most of them by number alone; `fcntl`'s command it checks
    too (libsandbox's own filter names, read from the loaded library, and compile checks on macOS 27.2):
    - `fcntl` (92) and `fcntl_nocancel` (406) with the commands of `FCNTL_COMMANDS` only:
      `(deny system-fcntl (with send-signal SIGKILL))` and `(allow system-fcntl (fcntl-command ...))`, as
      Firecracker's profile does for its own (`fcntl_rule`; the filter compiled and held on macOS 15 and 26 in CI
      run 44287648054, the macos-seatbelt jobs). The default rule does not cover `system-fcntl`: before this rule
      the server's commands ran under it. The commands: `F_GETFD` (step 4's walk), `F_SETFD` (libc's `fdopendir`
      marks the stream's descriptor close-on-exec: READDIR), `F_FULLFSYNC` (FSYNC), `F_PREALLOCATE` and
      `F_PUNCHHOLE` (FALLOCATE); no `F_GETFL` (Linux's filter allows `F_GETFL` and `F_GETFD`). Measured: the
      confined tests pass with exactly these, and each is needed, a run of requests, corpus and links without it
      killed with Seatbelt's report naming the command's number (`deny(1) system-fcntl 1`, `2`, `51`, `42`, `99`
      respectively; macOS 27.2). Any other command is the kill, before a rule on what it asks:
      `F_GETPATH` (the host path of a held descriptor), `F_DUPFD`, `F_SETFL` and a lock by `F_SETLK` are
      `confine_probe` cases, each killed (reported `system-fcntl 50`, `0`, `4`, `8`), with `F_GETFD` done.
    - `sendto` (133) and `recvfrom` (29) on the one connection only: `socket`, `connect`, `socketpair` and
      `accept` are not listed, so no other socket can be made, and `sendmsg`/`recvmsg` are not either, so no
      descriptor passes over the connection. Seatbelt has no filter on a send's or a receive's flags or length;
      `network-outbound` and `network-inbound` with their address filters decide a send that names an address
      only.
    - `fsetattrlist` (229) and `getattrlistat` (476): no filter on the attributes asked (`file-attribute` matches
      properties of the file, such as `datavault` or `sip-protected`, not attribute-list bits); each is decided by
      the file operation it makes (`file-write-times`, `file-write-finderinfo`, `file-read-metadata`, in the
      share).
    - `lseek` (199): no operation and no filter; its number alone.
    - `mach_msg2_trap` (47), which libmalloc needs, sends any Mach message to a port the process holds (its task
      port, the bootstrap port). Behind it, a kernel MIG routine not listed is killed by the `syscall-mig` rule
      (`mach_vm_reallocate` alone is listed): `task_info` of its own task, `deny(1) syscall-mig 195` in the crash
      report of a C program under the same profile (macOS 27.2). A bootstrap lookup through libxpc is killed before
      any message, at `mach_port_mod_refs` (`deny(1) syscall-mach 19`, the same program). Both are `confine_probe`
      cases, killed confined and working unconfined. A lookup built by hand and sent with `mach_msg` alone (the
      request libxpc sends, captured unconfined: an XPC pipe message, id 0x400000cf, carrying the bootstrap port; a
      reply port allocated before the profile) reaches launchd, which asks Seatbelt `mach-lookup` for its sender:
      the default's kill ends the process inside `mach_msg2_trap` (sandboxd: `deny(1) mach-lookup
      com.apple.system.notification_center`; crash report code 1, no details) and no port comes back. Unconfined the
      same message is answered with the service's port (macOS 27.2; the program is not in the repository). No
      `confine_probe` case: the request's format is libxpc's own and may change with it, and a reply port is
      allocated by a Mach trap the profile kills, so the case would need one made before the profile.

    The share's file operations, each named, inside `(subpath "<share>")` only:
    - allowed: `file-read-data`, `file-read-metadata`, `file-read-xattr`, `file-test-existence`, and, read-write,
      `file-write-create`, `-data`, `-mode`, `-times`, `-unlink`, `-xattr` and `file-link`, each with the requests
      that make it (`FILE_READ_OPS`, `FILE_WRITE_OPS`), with the composite `file-read*` and `file-write*` (a call
      can be checked as one: `futimens`'s `fsetattrlist` asks `file-write*`). A rule on one operation decides over
      a rule on a composite whatever their order (measured), so no composite rule widens a leaf one. Read-only
      shares: every write operation and `file-write*` killed in the share;
    - killed: `file-mount`, `file-mount-update`, `file-unmount` (`KILLED_IN_SHARE`);
    - refused with an error (EPERM), not killed: `ERROR_IN_SHARE`, the next paragraph; `file-graft` and
      `file-ungraft` (`ERROR_IN_SHARE_IF_DEFINED`) each in a rule of its own emitted only where the macOS defines
      the operation, `(when (defined? 'file-graft) (deny file-graft (subpath ...)))`: macOS 26 made them
      (xnu-12377's `mpo_graft_check_graft` and `_ungraft`), and macOS 15 has neither the MAC check nor the operation,
      so a profile naming them did not compile there and every share was refused (CI run 44317533490). Every
      other name the profile uses is required: a missing one fails the compile and the share is refused, naming it.
      `test_every_name_of_the_profile_is_defined_on_this_macos` checks each symbol of the profile on its own on each
      macOS CI runs, and that the two are unbound exactly on macOS 15. The rule is the same where they exist: the
      profile with these lines compiled to the same bytes as the one naming them in the error line (macOS 27.2).

    Outside the share every file operation is the default's kill, `file-map-executable` and the rest included.

    Two rules of `BASE` are not kills:
    - `(deny mach-priv-host-port)`: libsandbox asks for the host's privileged port inside `sandbox_apply`, once the
      profile is in force; with the kill the process ends in the apply (bisect on macOS 27.2: `BASE` alone 137,
      each kill class over `(allow default)` 0, `(deny default (with send-signal SIGKILL))` with `mach-priv*`
      allowed 0, with this plain deny 0). Firecracker's own profile has the same rule for the same reason. A
      process asking for the port afterwards is killed before the rule is consulted: the ask
      (`host_get_special_port`) is Mach trap 47 (`deny(1) syscall-mach 47`) and, with traps unfiltered, MIG
      routine 33, neither allowed (`confine_probe`'s "the host's privileged port");
    - `(allow system-info (info-type "vfs.disk-space"))`, which `fstatfs` asks: denied, the free blocks are rounded
      (measured: 5945470 shown as 5940000), where Linux's STATFS answers exactly. The guest learns the share
      volume's free space, as on Linux, or what the byte budget leaves where that is less; `requests.rs` requires
      STATFS confined to equal STATFS in process, from a session that served the same requests, on both hosts.

  - **Why the share's other operations are refused with an error and not killed.** Seatbelt evaluates, for both
    names of a hard link (`linkat`), the share's whole set of file operations, the composites `file*`,
    `file-read*`, `file-write*`, `fs-snapshot*` and `network*`, and `process-exec` and `system-automount`; a kill
    action on any of them ends the process after the link is made (measured on macOS 27.2 with a C program,
    `c15/sbx/link.c`, one operation at a time: each one killed in the share alone ends `linkat`, and the
    composites need a rule of their own). The crash report of such a kill carries termination code 1 and no
    "details", where a system call filter's kill carries code 221 and names the call. A denial stays a denial:
    moving these from kill to error changes what happens to a server that makes them, not what it reaches. Each
    one, with what shows it still refused under the profile (`confine_probe`; unconfined, the same calls are on
    record in its output):

    | In the share | Refused by | `confine_probe` case (confined; unconfined) |
    |---|---|---|
    | `file-write-flags` | the rule: EPERM | `fchflags(UF_NODUMP)`: EPERM; done |
    | `file-write-owner` | the rule: EPERM | `fchown(-1, -1)`: EPERM; done |
    | `file-write-setugid` | the rule: the call returns 0 and the bit is not kept, silently | `fchmod(fd, 04644)` on a regular file of the share the probe made and opened: 0, and `fstat` after shows no set-user-id bit; unconfined the bit is kept. No guest request asks it: the backend makes files 0o600 and directories 0o700, and `set_perm` passes the permission bits alone with its own access, so a guest's special bits are kept in the record only (`requests.rs`: MKDIR 07777, CREATE 06755, SETATTR 06777, 04700 and 01755, each answered in full, confined as in process, and the host's objects with none of them) |
    | `file-clone` | the rule: EPERM | `clonefileat`: EPERM; done |
    | `file-ioctl` | the rule: EPERM | `ioctl(DKIOCGETBLOCKSIZE)`: EPERM; ENOTTY (`FIONREAD` is answered by the descriptor layer and never asks `file-ioctl`: done both ways) |
    | `file-write-finderinfo` | the rule: EPERM | `fsetattrlist(ATTR_CMN_FNDRINFO)` (a listed call): EPERM; done |
    | `fs-snapshot*` | the call, unlisted: killed | `fs_snapshot_create`: killed; EPERM |
    | `file-chroot` | the call, unlisted: killed | `chroot`: killed; EPERM |
    | `file-revoke` | the call, unlisted: killed | `revoke`: killed; ENOTSUP |
    | `file-lock` | the call, unlisted: killed; `fcntl(F_SETLK)`, a command `system-fcntl` does not list: killed | `flock`: killed; done. `fcntl(F_SETLK)` of a read lock: killed; done |
    | `file-mknod` | the call, unlisted: killed | `mkfifoat`: killed; done |
    | `file-map-executable` | the call, unlisted (`mmap`, 197): killed | a share file mapped executable: killed |
    | `process-exec` | the call, unlisted: killed | exec of a file of the share: killed |
    | `network*` | the call, unlisted: killed | a TCP connection: killed |
    | `file-graft`, `file-ungraft` | the call, unlisted (`graftdmg` 549, `ungraftdmg` 555): killed at its number on every major, before the kernel's entitlement check (`com.apple.private.vfs.graftdmg`, EPERM without it; bsd/vfs/vfs_syscalls.c) and before macOS 26's rule; macOS 15 has no such operation | `graftdmg` and `ungraftdmg` on the share: killed (measured on macOS 27.2; macOS 15 and 26 not run yet, CI); EPERM both |
    | `file-search` | the call, unlisted (`searchfs`): as the row above | none |
    | `file-write-acl` | the call, unlisted (`chmod_extended`, `fchmod_extended`): as the row above | none |
    | `file-issue-extension` | `sandbox_issue_extension` is a Sandbox mac-syscall: killed | none |
    | `system-automount` | no call of the server's asks it; nothing is mounted in the share | none |
    | `file*` | the composite: every file operation of the share has its own rule above, so none falls to it | none |

  - **Each request's host calls**, from the code (`crates/fs/fsd/src/host/unix.rs`, `crates/fs/sys`), every one in
    `SYSCALLS`, the unfiltered set or the traps; `requests.rs` makes every request kind against a confined server
    and requires each reply to equal the in-process backend's. Each call was reported unlisted by a discovery run
    but `fsync` and `readlinkat`, as their rows say:

    | Request | Host calls |
    |---|---|
    | every frame | `recvfrom` (29), `sendto` (133); a large frame and the node tables: traps 15 and 47, `mach_vm_reallocate`; a large block handed out again zeroed or given back: `madvise` (75) |
    | at exit | `sigaltstack` (53), `munmap` (73): std's stack-overflow handler; the counters' line: `write` (unchecked) |
    | INIT, DESTROY, FLUSH, FSYNCDIR, the ENOSYS group | none |
    | ACCESS | a node lookup (LOOKUP's) |
    | LOOKUP | `fstatat64` (470), `getattrlistat` (476, the stored name), `openat` (unchecked), `fstat64` (339) |
    | GETATTR | `fstat64` or `fstatat64` |
    | SETATTR | size: `openat`, `ftruncate` (201); mode: `fchmod` (unchecked); times: `fsetattrlist` (229, libc's `futimens`), and a time set to now reads the wall clock, which libc makes as `gettimeofday` (116) about once in a million reads (below); ids: the record by `fsetxattr` (unchecked) |
    | READLINK | a symlink the host made: `readlinkat` (473; never reported by a discovery run, measured by a run of `requests.rs` without it: killed, `deny(1) syscall-unix 473`), `fstatat64`; the guest's own (kept as files): `pread` (153) |
    | CREATE, MKNOD, SYMLINK | `openat`, `fsetxattr`, `fstat64`, `fstatat64` |
    | MKDIR | `mkdirat` (475) |
    | UNLINK, RMDIR | `unlinkat` (unchecked) |
    | RENAME | `renameatx_np` (488) |
    | LINK | `linkat` (unchecked), `unlinkat` to undo a link it cannot keep |
    | OPEN | `openat`, `fstat64` |
    | READ, WRITE | `pread` (153), `pwrite` (unchecked) |
    | STATFS | `fstatfs64` (346), with `vfs.disk-space` |
    | RELEASE, RELEASEDIR | `close` (unchecked) |
    | FSYNC | `fcntl(F_FULLFSYNC)`, `fsync` (95) where the file system has no `F_FULLFSYNC` (from the code, never run: the volumes the tests make, APFS, have it) |
    | GETXATTR, LISTXATTR, SETXATTR, REMOVEXATTR | `fgetxattr` (235), `flistxattr` (241), `fsetxattr`, `fremovexattr` (unchecked) |
    | OPENDIR, READDIR, READDIRPLUS | `fcntl_nocancel` (406, libc's `fdopendir`: `F_SETFD`), `getdirentries64` (344), `lseek` (199), `fstatat64`, `close` |
    | FALLOCATE | `fstat64`, `lseek`, `pwrite`, `fcntl(F_PREALLOCATE, F_PUNCHHOLE)`, `ftruncate`, `fstatfs64` |
    | step 4's read-back | `fcntl(F_GETFD)` |

    `gettimeofday` (116): the server reads the wall clock under the profile in one place, SETATTR of a time to now
    (`Session`'s `now()`, `SystemTime::now`, libc's `clock_gettime(CLOCK_REALTIME)`). libc reads the commpage's time
    and makes the system call when it cannot: libsyscall's `__commpage_gettimeofday_internal` (xnu-11417) returns 1
    while the kernel is updating that time (`TimeStamp_tick` 0; the kernel updates it at every
    `clock_gettimeofday_and_absolute_time` and `clock_update_calendar`, osfmk/kern/clock.c) or when it is more than a
    second old, and `gettimeofday` then calls `__gettimeofday`. Measured on macOS 27.2: 20,000,000 back-to-back
    `clock_gettime(CLOCK_REALTIME)` under a profile reporting 116 gave 13 reports (12 of them as "12 duplicate
    reports"), 3000 reads 1 ms apart none. A discovery build of the server reported it once in a run of the confined tests (that build then read the wall
    clock for its own per-request lines too, so which read it was is not known). So until 116 was
    listed a confined server was killed at about one SETATTR-to-now in a million, on every major. It is listed; it
    only reads the time, and Firecracker's profile lists it too. confine_probe makes the call by its number under the
    profile (expected done), so the race does not decide the case;
    `test_a_confined_server_sets_times_to_now_again_and_again` (requests.rs) makes 20000 such SETATTRs confined.

    Deferred reclamation (`MACH_TRAPS_IF_DEFINED`, `MIG_ROUTINES_WITH_RECLAMATION`): from macOS 26, libmalloc's xzone
    allocator does not give a freed span back at once but puts it into a ring the kernel reclaims from when memory is
    short (libmalloc-792.80.2 and 812.100.31: `CONFIG_XZM_DEFERRED_RECLAIM` 1 on macOS, `XZM_DEFERRED_RECLAIM_ENABLED_DEFAULT`
    true; the ring, 1016 entries measured, is allocated at malloc's start, before the profile). Entering a span
    (`mach_vm_reclaim_try_enter`) asks for an accounting update once the ring's sampling period has passed since its
    last sample, and `mach_vm_reclaim_update_kernel_accounting` makes it as Mach trap 63 (xnu-12377.1.9
    libsyscall/mach/vm_reclaim.c :265, :417). The period is 10 s on every macOS (osfmk/vm/vm_reclaim.c :79,
    `vm_reclaim_sampling_period_ns` under `CONFIG_WORKING_SET_ESTIMATION`, off only on iOS), counted from the ring's
    allocation: a timer, not a chance. So every confined server that lived 10 s and then freed a span was killed:
    measured on macOS 27.2, the first READ of 1 MiB after an idle of 11 s (crash report: the trap ←
    `mach_vm_reclaim_update_kernel_accounting` ← `_xzm_reclaim_mark_free` ← `xzm_segment_group_free_chunk` ← the
    reply frame's buffer dropped in `Session::handle`). No test saw it, as every test's server ended within 10 s, and
    neither did the discovery runs, for the same reason. The trap is listed where libsandbox knows its name, on that
    measurement. That is macOS 15.8.2 too (CI run 44384853363 bound the name there): its kernel answers trap 63
    `kern_invalid` and its libmalloc-715 has no deferred reclamation on macOS, so on 15 the rule allows a trap that does
    nothing and that nothing makes. The same ring's MIG routines are listed where the trap's name and theirs are known
    (15.8.2 binds both; there the kernel refuses them for a process without a ring, xnu-11417.140.69 vm_reclaim.c
    :1237, :1297), by source and not measured: libmalloc resizes a full
    ring when it frees a span (`mach_vm_deferred_reclamation_buffer_resize`, xzone_segment.c :345, :300) and flushes it
    when that fails or when taking back a span loses a race with the kernel's reclamation
    (`mach_vm_deferred_reclamation_buffer_flush`, xzone_segment.c :305, :260; xzone_malloc.c :447, :612, :689, :6904);
    frees of up to 12,000 blocks of 64 KiB to 1 MiB in one process did not reach either, each run under a rule that
    killed it by name. The three act on the caller's own task only (osfmk/ipc/mach_kernelrpc.c :784,
    `port_name_to_current_task_noref`; osfmk/vm/vm_user.c: `task != current_task()` is `KERN_INVALID_TASK`).
    confine_probe makes each by the call itself on the process's own ring (found with
    `mach_vm_reclaim_get_rings_for_task`) under the profile, expected done where the trap is defined, and says on
    record which is missing elsewhere; `test_a_confined_server_answers_again_after_the_reclamation_period`
    (requests.rs, macOS) reads 1 MiB, waits 11 s and reads again; without the entries the probe's three cases were
    killed and the server was killed at the second round. Not done: `MallocLargeCache=0` in the server's environment,
    which turns the reclamation off (xzone reads it in release builds, `_xzm_production_getenv`; measured: no ring,
    and the 11 s case passes under a rule killing the trap), because it needs a re-exec or the launcher to set it
    and puts the allocator in a mode measured nowhere else. Firecracker differs: it runs libmalloc with
    `MallocSpaceEfficient=1` (`vmm::ext::malloc_config`), in which xzone makes no ring (xzone_malloc.c :8576,
    :9124), so its profiles list none of the three and it refuses to apply one to a process the kernel records a ring
    for (SECURITY.md, Heap); wick-fsd runs libmalloc's default mode and keeps its entries.

    Paths into the kernel that libSystem or libmalloc takes only in a state the tests do not make, by source, each
    with where it stands in the profile (a call no list names is killed):

    | Call | Path (source) | Reached when | In the profile | Why, and what holds it |
    | --- | --- | --- | --- | --- |
    | `_kernelrpc_mach_vm_allocate_trap` (10) | libmalloc-715.140.5 magazine_large.c `large_try_realloc_in_place`: `vm_allocate` at a fixed address | a large block, past the medium allocator's 8 MiB, grown in place; the medium allocator is engaged on arm64 and under Rosetta and is off only on native Intel under 32 GiB (malloc.c :357) | no | native Intel under 32 GiB only, not a host; and no buffer the server grows passes 2 MiB (next rows) |
    | `vm_copy` (MIG) | libmalloc-715.140.5 magazine_malloc.c :592 | a realloc that moves more than 2 MiB (`VM_COPY_THRESHOLD`) | no | every buffer the server grows stays at or under 2 MiB: the frame's payload, a READDIR reply, a dirent, a LISTXATTR answer (`test_the_buffers_the_server_grows_stay_under_a_vm_copy`, whose message names these two routines for a larger one); the node and handle tables are hash tables, which grow by a new allocation |
    | `mach_vm_copy` (MIG) | libmalloc-812.100.31 xzone_malloc.c :5754 | the same past `XZM_LARGE_BLOCK_SIZE_MAX` (2 MiB) | no | the same test |
    | `_kernelrpc_mach_port_construct_trap` (24) | xnu-12377.1.9 libsyscall/mach/mig_reply_port.c :64 `mig_get_reply_port` | a MIG call on a thread with no reply port: a new thread's first, or the main thread's after the next row (measured on 27.2: a new thread's slot is empty at its start, the main thread's is set before `main`) | no (Firecracker's lists have it) | the server has one thread, its main one (nothing in crates/fs/fsd/src makes a thread), so only after the next row |
    | `_kernelrpc_mach_port_mod_refs_trap` (19), `_kernelrpc_mach_port_deallocate_trap` (18) | mig_reply_port.c :85 `mig_dealloc_reply_port`, which a MIG stub calls when `mach_msg` fails other than with `MACH_SEND_INVALID_DATA`, `_DEST` or `_HEADER` (mig's `__MachMsgErrorWithoutTimeout`, in every stub it generates) | an exchange with the kernel (`mach_vm_reallocate`, the ring's routines) failing at the transport: the kernel out of message buffers, the reply port gone | no (Firecracker's lists have them) | in no run; measured on 27.2: on the main thread the call clears the slot, so the next MIG call makes trap 24; a kill if it happens, its crash report naming the trap |
    | `mach_vm_reclaim_update_kernel_accounting_trap` (63), `mach_vm_deferred_reclamation_buffer_resize`, `_flush` | the ring's timer and its full or raced ring (above) | from macOS 26, the first free 10 s after the last sample; a full ring; a lost race | yes, where libsandbox knows the names | above |
    | `getentropy` (500) | Libc's `arc4random`: a reseed at the first draw 5 s or more after the last (measured on 27.2: every 5.05 s, by time) | an `arc4random` draw after confinement | no (Firecracker's lists have it) | not reached, measured: the server draws nothing random once confined (fs-server-report at 34626765, the idle test included); a thread made later that makes a `HashMap` draws its keys (std's `RandomState`), a rule question then |

    Each entry of the profile's lists against Firecracker's (overlay/vmm/ext/sandbox.rs, after the microVM is built:
    "run"; before: "setup"; the API process: "API"), then the calls Firecracker's lists have for libSystem's own
    paths that wick-fsd's do not:

    | wick-fsd's entry | Firecracker | Note |
    | --- | --- | --- |
    | `recvfrom` (29), `sendto` (133) | run, API | frames |
    | `sigaltstack` (53), `munmap` (73) | run, API | std's stack-overflow handler at exit |
    | `madvise` (75) | run, API (API: `MADV_DONTNEED` only, the compatibility libc's check) | libmalloc |
    | `fcntl` (92), `fcntl_nocancel` (406) | run, API | commands below |
    | `fsync` (95), `pread` (153), `lseek` (199), `ftruncate` (201), `fstatfs64` (346), `fstatat64` (470) | run | the host's file calls |
    | `gettimeofday` (116), `fstat64` (339) | run, API | |
    | `getdirentries64` (344) | setup | Firecracker reads a directory only while it builds the microVM |
    | `fsetattrlist` (229), `fgetxattr` (235), `flistxattr` (241), `readlinkat` (473), `mkdirat` (475), `getattrlistat` (476), `renameatx_np` (488) | none | a file server's own: times, attributes, links, directories, the stored name, RENAME2 |
    | fcntl `F_GETFD`, `F_SETFD` | run, API | |
    | fcntl `F_FULLFSYNC`, `F_PUNCHHOLE` | run | |
    | fcntl `F_PREALLOCATE` | none | FALLOCATE that allocates (Firecracker's fallocate only punches) |
    | `_kernelrpc_mach_vm_deallocate_trap` (12), `_kernelrpc_mach_vm_map_trap` (15) | run, API | libmalloc |
    | `mach_msg2_trap` (47) | run | the MIG calls below; the API process sends no message |
    | `mach_vm_reclaim_update_kernel_accounting_trap` (63) | none (from e3613478) | Firecracker runs libmalloc in its space-efficient mode, which makes no ring, and refuses a profile to a process that has one |
    | `mach_vm_reallocate` (MIG) | setup, where defined | Firecracker grows guest memory only while it builds the microVM |
    | `mach_vm_deferred_reclamation_buffer_resize`, `_flush` (MIG) | none | as trap 63 |
    | Firecracker's only: `_kernelrpc_mach_vm_allocate_trap` (10) | run, API | the first table's first row |
    | Firecracker's only: `_kernelrpc_mach_port_construct_trap` (24), `_mod_refs_trap` (19), `_deallocate_trap` (18), `_destruct_trap` | run, API | MIG reply ports: the first table; Firecracker makes threads, wick-fsd does not |
    | Firecracker's only: `semaphore_*` traps, `psynch_*`, `ulock_*`, `swtch_pri`, `syscall_thread_switch` | run, API | a contended lock waits or yields; wick-fsd's one thread contends with nothing |
    | Firecracker's only: `__semwait_signal` | run | `nanosleep`: wick-fsd never sleeps |
    | Firecracker's only: `getentropy` (500) | run, API | the first table's last row |
    | Firecracker's only: `__pthread_canceled` | run, API | a cancellation point's `EINTR` from a handled signal: wick-fsd's only handlers are std's for a stack overflow (SIGSEGV, SIGBUS), raised by a fault, not inside a blocking call |

  - **How the lists were made, and the limit of that.** A discovery build (`--cfg wick_fsd_discovery`, never
    released) ends the profile with `(allow default (with report))` and allows unlisted calls with a report;
    the confined tests are run under it and each `Sandbox:` report line read (`/usr/bin/log show`). What that
    rule covers: a call no list names and an operation no rule names. It does not report a listed call (the
    list's rule, which has a filter, decides over the discovery rule whatever their order) or an operation the
    share's rules or the plain denials name, and Seatbelt never sees the number of an unfiltered call. And the
    reports are lossy: a process making N distinct reported accesses gave 100 report lines for N = 100, 922 for
    1000 and 3210 for 5000 (macOS 27.2, `c15/sbx/many.c`, `stat` of N files under one report rule; no fixed cap,
    lines dropped as the rate grows). So discovery shows what a run reached and cannot prove a list complete.
    The lists are completed from the code, each request kind's calls named in the table above, and checked by
    `requests.rs`, which makes every request kind confined (a missing entry is a kill, which the test sees as the
    connection closing); a kill's crash report names a system call filter's denial (`deny(1) syscall-unix N`),
    and a file rule's kill leaves a report with no details. Crash reports are lossy too: of `confine_probe`'s 23
    kills in one run macOS wrote reports for the first five only (19:00:18 on 2026-11-18), and in some runs none,
    so a missing report shows nothing.

    **The server itself under the reporting profile** (`tools/macos/fs-server-report.py`, CI's fs job on macos-15 and
    macos-latest). The two defects found on macOS 15, `mach_vm_deallocate` and the `sysctl` of `fdopendir`, were calls
    the server's own request paths make and the allocator probe's shapes did not; this measures the server. The
    script builds crates/fs with `--cfg wick_fsd_discovery` into `build/fs-discovery` (check-tree holds that no other
    tracked file sets the cfg). There `profile()` is the product's function with the same lists, ending with the
    discovery rules above, so nothing is copied that could drift; the server says each request it serves on stderr
    with the time (5 ms apart, a spin that makes no call; its clock is the wall clock read once before the profile
    and the monotonic clock after, so its lines make no call either), and once
    confined makes one control call no list names (`task_info`), whose report also gives the difference between the
    log's clock and the server's (measured: some milliseconds). It runs requests.rs (every
    request kind, the error paths, 64 READs of 1 MiB, a directory of 3000 entries), links.rs, corpus.rs and
    connection.rs three times, reads Seatbelt's reports of each confined server, and prints the macOS build (sw_vers,
    the libraries' versions from the dyld cache) with each unlisted call or operation: how many runs reported it, the
    tests, and the request in flight: the requests the server said in the 4 ms up to the report on the log's clock
    (a report's time moves by a few milliseconds against the call: measured with `readlinkat` taken out of the list,
    the report fell on READLINK in one run and on the LOOKUP before it in the other, 3 ms apart), so one or two
    candidates. It runs requests.rs without the 20000 SETATTRs' test (every-request makes that request). It fails on
    any such line, on a test none of whose servers had its control reported, and on a failed test. Reports are lost:
    on macOS 27.2 here, the servers of the first run's first seconds (about 9 s: connection.rs, corpus.rs, links.rs)
    had no report in the log in 6 of 6 runs of the script, with or without a pause or the test binaries started
    before, where the rest of that run's and every later run's had theirs (cause not found). So the tests run one at
    a time, each server's control says whether it was measured, and each test needs one run in which it was. Such a
    build never passes for the product: it says it is one as its first line on stderr and in
    `--version` (`test_a_build_says_whether_it_is_a_discovery_build`, run in both builds). The reports' limits above
    hold: an empty union is what the runs reached, and the library path that makes a call is not in a report (a
    killed run's crash report names it).
  - The memory limit is jetsam; the CPU limit uses the jailer's mechanism.
- **Resolution:**
  - `openat(dirfd, name, O_NOFOLLOW_ANY|O_RESOLVE_BENEATH|O_CLOEXEC)` (§4.3; `O_NOFOLLOW` as well is EINVAL), with
    `O_RESOLVE_BENEATH` on 15.4+ (unconfirmed, §0 row 19);
  - `*at` calls with `AT_SYMLINK_NOFOLLOW` (+`AT_SYMLINK_NOFOLLOW_ANY`, and `AT_RESOLVE_BENEATH` on 26+);
  - `renameatx_np(RENAME_EXCL|RENAME_SWAP)` for RENAME2;
  - xattrs only through fds (`f*xattr`, `XATTR_NOFOLLOW`), since macOS has no `*at` xattr calls.

  Flag history from XNU's `bsd/sys/fcntl.h`: `O_NOFOLLOW_ANY` in xnu-7195 (macOS 11); `O_RESOLVE_BENEATH` in
  xnu-11417 (taken to be macOS 15.4; unconfirmed, §0 row 19); `AT_RESOLVE_BENEATH` and `O_UNIQUE` in xnu-12377 (macOS 26) [src].

  On releases without `O_RESOLVE_BENEATH` the server refuses to start (decision 5 in §0).
- **No `O_PATH`.** Directories are held as `O_RDONLY|O_DIRECTORY` fds, as on Linux (§4.3). Non-directories are
  leaves: found by their known names and checked per use, or, unlinked, through the descriptor of the guest's
  widest open (§4.3).
- **Case and normalization:** APFS is case-insensitive by default and always normalization-insensitive, and names
  must be valid UTF-8. See §7 for the behaviour.
- **TCC:** a share under `~/Documents`, `~/Desktop`, `~/Downloads`, iCloud or removable volumes needs the responsible
  app's permission. The server reports `EPERM` at stage 0 with a message naming TCC, rather than at the first
  guest access.

### 6.3 Windows (x86_64, WHP)

- **Confinement:** there is no "subpath" for a process, so access must come from the DACL.
  - Stage 0 derives an AppContainer SID per share (`DeriveAppContainerSidFromAppContainerName("wick.fsd.<hash>")`).
  - It makes sure the share root has an inheritable (OI|CI) ACE for that SID: read for read-only shares, modify
    otherwise. This is Microsoft's own pattern (`HcsGrantVmAccess` in hcsshim) [src].
  - It starts stage 1 as **LPAC** (`PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`) with capabilities
    `registryRead` and `lpacCom`: without them LPAC loses Winsock, including AF_UNIX; with them AF_UNIX works and TCP
    is denied [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository].
  - The process runs in a Job (memory, CPU, active-process limit 1, kill-on-close) with wick's mitigation profile
    (no child processes, no win32k, ACG, strict handles, no extension points).
    `DisallowFsctlSystemCalls` cannot be set, because the server needs FSCTLs (sparse files, zero data, reparse
    queries), and it fails on build 20348 anyway [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository].
  - The connected socket (stage 0 accepted it and checked the peer, §4.2) and the share-root handle are inherited
    by the LPAC child. A handle does not bypass access
    checks on relative opens, hence the ACE [inf: confirm].
  - Granting the ACE to existing children rewrites their security descriptors (O(n) files, persistent). Children
    with protected DACLs stay unreachable, which fails closed.
  - Options: an explicit `wick-fsd grant <dir>` / `revoke <dir>` step, or a broker that opens on the server's behalf
    (open question).
- **Resolution:**
  - `NtCreateFile` with `RootDirectory` = the parent handle, `ObjectName` = one escaped component,
    `OBJ_DONT_REPARSE`, and `FILE_OPEN_REPARSE_POINT` when opening a link object itself;
  - `FILE_SHARE_READ|WRITE|DELETE` on every server handle, so parent directory renames are not blocked
    [inf: measure];
  - after open, `FileAttributeTagInformation` (reparse → not traversed) and `FileNormalizedNameInformation`
    (alias check);
  - rename with `FileRenameInformationEx` + `FILE_RENAME_POSIX_SEMANTICS` (replace a file with open handles) +
    `RootDirectory`;
  - delete with `FileDispositionInformationEx` POSIX semantics [inf: version minimum to confirm, believed 1709+].
- **Names:** reject `:` and `\`. Escape characters NTFS forbids (`* ? " < > |`, 0x01–0x1F) into the private-use
  range, as WSL DrvFs does [inf: confirm WSL's mapping], and round-trip them: each character c becomes U+F000 + c
  (U+F001–U+F01F, U+F022, U+F02A, U+F03A, U+F03C, U+F03E, U+F03F, U+F05C, U+F07C). A guest name holding any image, or
  U+F02F (the image of `/`), is refused with EINVAL on every host, so a share behaves the same wherever it is served
  (`crates/fs/fsd/src/fuse/name.rs`, `test_name_refuses_every_escape_image`). Trailing dots and spaces are kept by the
  common mapping and handled by the Windows backend [inf: measure against WSL]. NT relative opens
  do not apply DOS device names (`CON`, `NUL`) [inf]. Refuse a share at a volume root (NTFS `$` metafiles).
- **Case:** `FileCaseSensitiveInformation` per directory. Setting it needs elevation and an empty directory, and new
  subdirectories inherit it (Windows 10 build 17107+) [doc].

---

## 7. Semantics gaps (Linux guest expectations vs host)

| Area | Behaviour on all hosts (parity) | Linux host | macOS host | Windows host |
| --- | --- | --- | --- | --- |
| uid/gid/mode, setuid, devices, FIFOs, sockets | emulated in the record; guest-side checks are the guest's own business | same | same | same |
| Symlinks | guest-made = emulated (regular file + record); host-made = shown as symlinks, never traversed by the server | real symlinks possible but not used (parity; keeps host tools from following guest links) | same | native NTFS symlinks need a privilege or Developer Mode, so emulation is needed anyway |
| Hard links | supported within the share; `st_nlink` from the host | yes | yes (APFS) | yes (NTFS) |
| Inode numbers | server-chosen, stable for the session; `st_ino` = a hash of the host identity, not guaranteed stable across server restarts | | | 128-bit FileId hashed |
| Rename over an open file / unlink while open | POSIX semantics | native | native | POSIX rename/disposition flags [inf: minimum build] |
| Case | require a case-sensitive root by default; with an explicit operator flag, run on a case-insensitive root with exact-name lookups and EEXIST on case collisions (loud, documented) | ext4/f2fs casefold dirs handled the same way; a rename to an object's own other case, which Linux returns 0 for and does not do, goes through a middle name (§4.3) | APFS default is insensitive; use a case-sensitive APFS volume or sparse image (`hdiutil` needs no admin [inf]) | per directory; needs admin |
| Names | UTF-8 only, ≤255 bytes; `EILSEQ`/`ENAMETOOLONG` otherwise | non-UTF-8 host names: open question | APFS requires UTF-8 | escaped (§6.3); total NT path length ~32K characters |
| Locks (`fcntl`, `flock`) | not negotiated, so guest-local only; not visible to host processes | | | |
| mmap coherence | guest page cache (no DAX): coherent inside the guest; host writers show up after cache timeouts; `cache=never` option for shares edited on both sides | | | |
| inotify/fsnotify for host changes | **not delivered**: Linux's virtio-fs driver has only hiprio and request queues, no notification queue (`fs/fuse/virtio_fs.c`, `VQ_HIPRIO`/`VQ_REQUEST`) [src]; guest-side changes do fire in the guest | | | |
| `O_TMPFILE` (FUSE_TMPFILE), POSIX ACLs, ioctls | ENOSYS/EOPNOTSUPP, so applications fall back | | | |
| Sparse files, fallocate, punch hole | supported; wick's `platform::fs` already has hole semantics per host | native | `F_PUNCHHOLE` | `FSCTL_SET_ZERO_DATA` |
| Quotas / free space | `statfs` from the host volume, its free and available blocks capped by what the server's byte budget leaves this run (decision 7; `Session::statfs`, `test_byte_budget_is_enospc_counted_and_shown_in_statfs`), so the guest sees the budget where the volume has more free | | | |
| `fsync`, `fdatasync` | the data on stable storage when the call returns, as Linux's `fsync` (§4.3) | `fsync` / `fdatasync` | both `F_FULLFSYNC` (macOS's `fsync` stops at the drive's cache); slower by the drive's flush | — |
| Open flags | only the access mode reaches the host; `O_APPEND`, `O_TRUNC`, `O_DIRECT`, `O_SYNC` are the guest kernel's (§4.3) | same | same | — |

---

## 8. Firecracker-specific items

- **Off and compiled out:**
  - cargo feature `fs` on `wick-ext` (and on the overlay device module if it lives in `vmm`), default off;
  - `wick-fsd` is a separate crate and binary, shipped separately;
  - with the feature off, the binary has no fs code and `test_unknown_extension_is_rejected` still holds.

  Tests: `nm`/size check that no fs symbols are in a default build; `/sys/bus/virtio/devices` in the guest shows no
  device type 26 without config.
- **MMIO and PCI:** both work; no transport changes for v1 (§4.1).
- **Snapshots:**
  - v1: `snapshot_blocker()` returns `"virtio-fs"`. Snapshot creation fails with an API error (hook exists:
    `overlay/vmm/ext/mod.rs` `check_snapshot`, `test_snapshot_blocker`).
  - Later:
    1. drain in-flight frames at pause;
    2. the server serializes its table as paths (virtiofsd's `find-paths` mode; [doc/migration.md](https://gitlab.com/virtio-fs/virtiofsd/-/blob/main/doc/migration.md));
    3. the blob is stored in the VM state.

    On restore, every path is re-resolved **beneath the root with the same resolver**: snapshots are trusted input,
    but this costs nothing. Failures become ESTALE (virtiofsd's `guest-error` analogue).
  - Share contents are the operator's job. virtiofsd says: "virtiofsd's state includes absolutely no data". One
    snapshot restored into many VMs needs one share copy per clone. This is upstream's 2020 concern, so document it.
- **Jailer:**
  - the server runs outside the jail, as upstream advises for vhost-user backends;
  - its socket is inside the jail root, as vhost-user-blk's is (PORTING row 14);
  - the share is never visible inside the jail;
  - the server confines itself (§6); a jailer flag could start it as a sibling later.
- **Rate limiting:** in the VMM, with upstream's `RateLimiter` (ops + bandwidth), the block device's schema. The same
  code on all hosts gives parity.
- **Metrics:**
  - VMM: `fs_<id>` (requests, bytes, throttled, in-flight, device resets, server EOF);
  - server: its own metrics file in upstream's JSON format (errors by errno, limit hits, refusals by reason).
- **Guest kernel:** upstream's CI configs have `CONFIG_FUSE_FS=y` but `# CONFIG_VIRTIO_FS is not set` and
  `# CONFIG_NET_9P is not set` (all seven `microvm-kernel-ci-*.config`) [src]. wick's CI builds upstream's 6.1 and
  6.18 CI kernels with `CONFIG_VIRTIO_FS=y` added (`tools/linux/guest-kernel.sh`); wick's images (M6) would add it
  too. Option D works with upstream kernels as they are.

---

## 9. What is impossible on which host (and fails loudly)

| Item | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Kernel-enforced path confinement of the server | namespaces + pivot_root (needs userns or root); Landlock 5.13+ | Seatbelt subpath | none as such: DACL grant to an LPAC SID (modifies the share's ACL) |
| Beneath-flag resolution | 5.6+ | `O_RESOLVE_BENEATH` 15.4+ (unconfirmed), `AT_RESOLVE_BENEATH` 26+ | `OBJ_DONT_REPARSE` (version minimum undocumented [inf]) |
| Containment of dirs the host moves out | Landlock (dynamic) [inf] | Seatbelt (dynamic) [inf] | **no** (static ACLs): documented |
| Case-sensitive share without admin | yes | case-sensitive APFS volume/image | **no** for existing dirs (admin + empty dir) |
| Native symlinks without privilege | yes | yes | **no** (privilege or Developer Mode): emulated everywhere |
| Atomic `RENAME_EXCHANGE` | `renameat2` (EINVAL where the file system has none) | `renameatx_np(RENAME_SWAP)` on a volume that reports `VOL_CAP_INT_RENAME_SWAP` (APFS); EINVAL on others (HFS+, msdos, exfat; §4.3) | **no**: NTFS has no exchange (`FILE_RENAME_INFORMATION`'s flags, §4.3); EINVAL |
| `RENAME_WHITEOUT` | **no** on every host: the server makes no device nodes; EINVAL | | |
| Serving without beneath-resolution | **no**: `openat2` required (5.6+, not denied by seccomp) | **no**: `O_RESOLVE_BENEATH` required | — |
| A read-write share on a file system without extended attributes | **no** (vfat, exfat): read-only only | **no** (msdos, exfat: AppleDouble `._` files): read-only only | — |
| Per-process handle limit | `RLIMIT_NOFILE` | `RLIMIT_NOFILE`, enforced as at most `kern.maxfilesperproc` (10240 on a Mac with 8 GB or less) | **none** [meas: `jailer-test.ps1 nofile`]: self-limit everywhere |
| A file the guest holds, renamed or replaced by the host (a known difference) | served again only if its new name is in a directory the server holds (§4.3), else ENOENT, never another object. virtiofsd keeps serving it through its `O_PATH` descriptor wherever it went. wick reaches an object with a name only through a held directory, so an object the host moved out of the share is out of the guest's reach, and opened and never-opened nodes behave alike | the same as Linux: no `O_PATH` | the planned backend reopens by file id and so would keep serving it, as virtiofsd; to be decided with the port |
| A new OPEN of an unlinked file the guest holds (the guest's `/proc/<pid>/fd/<n>`) | only for an access the descriptor of the guest's widest open covers, else ENOENT (virtiofsd reopens through `/proc`) | the same as Linux | — |
| Host change notifications to the guest | **no** on any host (Linux driver) | no | no |
| DAX | not in v1 on any host | | |
| Snapshot with fs | refused on every host in v1 | | |

---

## 10. Open questions

1. **Windows confinement:** decided for the ACE grant (§0, decision 4). Open: how revocation and cleanup are made
   crash-safe, and the cost of the first grant on a large tree (O(n), persistent).
2. **Windows measurements on 20348 and 26300:**
   - `OBJ_DONT_REPARSE` on file-system reparse points in `RootDirectory` opens;
   - NTFS treatment of `.`/`..` in relative names;
   - whether `FILE_SHARE_DELETE` handles keep parent renames working;
   - `FileNormalizedNameInformation` for 8.3 aliases;
   - the minimum builds for the POSIX rename/disposition flags;
   - LPAC + AF_UNIX + inherited handles;
   - `FILE_OPEN_BY_FILE_ID` under LPAC for an outside file.
3. **macOS:**
   - Seatbelt `subpath` vs the share reached by its firmlink alias, and very deep paths (an outside file by `/.vol`
     or its firmlink alias is killed: `confine_probe`);
   - whether a sandboxed (non-App-Sandbox) process's files get `com.apple.quarantine`/`com.apple.provenance`;
   - which macOS release first has `O_RESOLVE_BENEATH` (decision 5 in §0 needs it);
4. **Linux:** where unprivileged userns is disabled, a root launcher that drops (§0, decision 6). Open: how
   non-UTF-8 host names are presented under the parity rule.
5. **Quota:** decided for a byte budget in the server (§0, decision 7).
6. **Performance of C** vs vhost-user (measure before deciding whether a VMM↔server bounce ring, never guest
   memory, is needed).
7. **Patch footprint:** a `VirtioDeviceType::Fs` variant, metrics, and later persist. Answered for the variant and
   metrics: patch 0056 (the variant; `Extension::write_metrics`, generic for later devices); persist is not needed
   while a snapshot with fs is refused.
8. **Read-only shares on macOS/Windows:** do atime updates on reads (virtiofsd notes this on Linux) matter to
   operators?
9. Share roots: home and system locations are refused by default (§0, decision 8). The list per host is §4.3's,
   stage 0 step 2 (`refused_root`).
10. **Cache `auto` timeout:** 1 s, provisional (§4.4). Open: how soon a host-side edit must show in the guest,
    measured against the metadata requests a shorter timeout costs.
11. **Nodes against descriptors:** each node holds a descriptor (a directory's own; a leaf's once opened), so the node
    limit is bound by the smallest stock descriptor limit, 8192 nodes (§4.2, Limits). A Linux guest keeps a node while
    its dentry is cached and forgets only under memory pressure, and Linux's virtio-fs driver has no notification queue
    to ask it to drop entries (`fs/fuse/virtio_fs.c`: hiprio and request queues only) [src], so a guest that walks more
    than 8192 objects (a large checkout, `npm install`) gets ENFILE where virtiofsd, which holds an `O_PATH` descriptor
    per inode under a limit raised to `fs.nr_open`, would not. Recommendation: decouple the two, nodes bounded by memory
    (a node is a few hundred bytes) and descriptors by a cache of held directories closed least recently used first and
    reopened by name beneath a held parent as leaves are now, so the descriptor bound stays fixed and the node limit can
    be 2^20; its own commit, with the leaf tests and the race over it. **Resolved:** decoupled (§4.3, Nodes), the
    node limit 2^18 by default (a worst-case node is 4 KiB, so 2^20 would let a guest hold 4 GiB of the host's
    memory; §4.2, Limits), and a directory that cannot be found again is ESTALE.
12. **Inode numbers reused** (§4.3): a node the server holds nothing of is rebound, with no error, to an object
    the host made under its name with a reused inode number. Recommendation: the birth time with the identity
    (16 bytes a node, no extra call on either host), where the file system reports one; decide before fs v1.

---

## 11. Test plan (none of these tests exists yet, except where marked; each gets its name in the docs once it exists, per `tools/check-claims.py`)

1. **Off by default:**
   - `test_unknown_extension_is_rejected` (exists);
   - a default build has no fs symbols (exists: `tools/check-fs-off.sh`, CI's linux and macos jobs);
   - with the feature but no config: no virtio device 26 in the guest, no socket, no process (a planned boot-test
     stage `fs-off` on each host).
2. **Traversal corpus (host-side harness, no VM, every CI host).** Exists for Linux and macOS as
   `test_traversal_corpus` (`crates/fs/fsd/tests/corpus.rs`), over the session and the host backend without the
   frame layer, and on Linux and macOS as `test_traversal_corpus_confined`, against a confined wick-fsd over its
   socket, which must end normally with no layer-2 or layer-3 refusal. A Rust harness speaks wick-fsd's frame protocol
   and sends every name-taking opcode (LOOKUP, MKNOD, MKDIR, SYMLINK (name *and* target), UNLINK, RMDIR, RENAME,
   RENAME2, LINK, CREATE, TMPFILE, SETXATTR/GETXATTR names). Names:
   - `..`, `.`, `a/b`, `/etc/x`, `../../x`;
   - `C:\x`, `\\?\C:\x`, `\??\x`, `CON`, `NUL.txt`;
   - `f:s`, `f::$DATA`, `d::$INDEX_ALLOCATION`, `PROGRA~1`, trailing dot/space;
   - NFC/NFD and case variants;
   - 255/256-byte names, invalid UTF-8, embedded NUL, no NUL.

   Assertions:
   - canary files outside the share are unchanged and unread (Linux fanotify; macOS: the canary path is denied by
     the profile **and** the denial counter must be zero; Windows: canary with a SACL audit);
   - every refusal comes from the protocol layer (§5 test principle).
3. **Race suite** (exists for Linux and macOS as `test_swap_race`, directory ↔ symlink; junctions are Windows',
   mount points need privileges a test lacks):
   - host threads swap directories ↔ symlinks / junctions / mount points and hard links while the harness issues
     operations, 10⁶ iterations, each loop under an alarm so that a hang fails the test;
   - the same assertions as 2.
4. **Fuzzing** (cargo-fuzz in `fuzz/`, CI one minute each like the existing targets, longer nightly):
   - `fs_decode`: frame → request; no panic, bounded allocation;
   - `fs_session`: request sequences against an in-memory backend and a temp-dir backend with canaries;
   - `fs_proxy` (exists): the device's request/reply core (`crates/ext/src/fs/copy.rs`) with hostile descriptor
     chains **and** hostile server replies (headers of the wrong length, of another request, short, unknown or
     repeated cookies, a lost server), checked against a model of the requests waiting.
5. **Guest-level, on each host:**
   - pjdfstest in the guest on the share;
   - an xfstests `generic` subset with `FSTYP=virtiofs`;
   - results compared across hosts with a differences file like `tools/macos/integration-test-differences.txt`
     (each difference with its reason: impossible / emulated / bug).
6. **Raw guest attack:** a guest-root tool that builds its own virtqueue (as in the Kata PoC) and replays corpus 2
   from inside the guest, on all three hosts (Windows on the WHP PC).
7. **Sandbox checks of wick-fsd:**
   - Linux: `/proc/<pid>/status` (`Seccomp: 2`, `NoNewPrivs: 1`, `CapEff: 0`), `/` = the share, an open of an outside
     path fails (exist: `test_confined_status`, `test_outside_open_fails`, `confine_probe`);
   - macOS: `confine_probe` (the outside canary by its path, its metadata, `/.vol` and its firmlink alias, exec, fork,
     a TCP connection, the host's privileged port and the share's refused operations of §6.2, each killed or
     refused) and `test_every_request_confined_answered_as_unconfined` (every request kind confined, each reply
     equal to the in-process backend's, no kill); one test per step failing (`refusals.rs`, §6.2);
   - Windows: `TokenIsLessPrivilegedAppContainer`, Job limits, `GetProcessMitigationPolicy`, outside open and
     open-by-id → `ACCESS_DENIED`;
   - all hosts: the server refuses to start when any control cannot be installed (one test per control; Linux's exist,
     `test_refused_without_*` in `crates/fs/fsd/tests/server.rs`).
8. **VMM sandbox unchanged:** `tools/macos/sandbox-discovery.sh` with an fs device shows no new entries; the Windows
   profile is identical; Linux seccomp is unchanged.
9. **Limits:** inode/handle/queue caps produce ENFILE/EMFILE/backpressure with the same numbers on every host;
   VMM in-flight bytes stay under the cap with a guest flooding the queue (the VMM's exists:
   `test_inflight_cap_backpressure`, `test_the_in_flight_limit_holds_chains_back`).
10. **Snapshot refusal:** snapshot create with fs attached → API error naming virtio-fs (the VMM's refusal on both
    transports exists: `test_fs_snapshot_refused`; through the API, a planned boot stage).
11. **The VMM device against its server** (exist, `crates/ext/src/fs/device/tests.rs`, a fake server over a socket
    pair): `test_a_request_and_its_reply`, `test_server_death_fails_inflight_with_eio`,
    `test_no_reconnect_after_loss`, `test_server_hang_never_blocks_the_loop`, `test_hostile_chains`,
    `test_hostile_replies`, `test_reset_loses_the_server`, `test_hello_refusals`,
    `test_write_metrics_takes_no_device_lock`, `test_a_writable_buffer_outside_guest_memory`; the header checks one
    by one in `copy.rs` (`test_each_reply_header_mismatch_loses_the_server`,
    `test_the_error_range_and_an_error_reply_s_length`). In a guest, on 6.1 and 6.18: the server killed mid-request
    → the guest's system call returns `EIO`, no hang (planned, plan commit 12's boot stage).

---

## 12. Sources

**wick repo (read in source):**
- README.md, SECURITY.md (threat model; Windows jailer gaps), docs/ARCHITECTURE.md (item 5), docs/ROADMAP.md (M7),
  docs/PORTING.md (rows 14, vhost-user and memfd);
- crates/ext/src/lib.rs; overlay/vmm/ext/mod.rs (`Extension`, `BootContext::attach_virtio_device`,
  `snapshot_blocker`); overlay/vmm/ext/sandbox.rs (Seatbelt `subpath` rules, memfd names);
- tools/vhost-user-blk (vhost-user-backend 0.23 on all hosts);
- a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository [meas].

**Upstream Firecracker v1.18.0 (`lib/firecracker`):**
- `src/vmm/src/devices/virtio/vhost_user.rs` (`update_mem_table`, `setup_backend`);
- `devices/virtio/device.rs` (`VirtioDeviceType`);
- `resources.rs` (`allocate_memory_regions`);
- `devices/virtio/block/vhost_user/persist.rs`; `transport/mmio.rs`, `transport/pci/`;
- `resources/guest_configs/*.config`;
- docs/api_requests/block-vhost-user.md, docs/design.md, docs/memory-hotplug.md, docs/hugepages.md,
  docs/kernel-policy.md, docs/pmem.md.

**Upstream discussions:**
- https://github.com/firecracker-microvm/firecracker/issues/1180
- https://github.com/firecracker-microvm/firecracker/pull/1351
- https://github.com/firecracker-microvm/firecracker-containerd/blob/master/docs/drive-mounts-proposal.md

**virtiofsd:** https://gitlab.com/virtio-fs/virtiofsd (README.md, doc/migration.md; src/filename.rs, oslib.rs,
server.rs, passthrough/{mod,util,guest_fd_limit}.rs; commits 6ead577, 35f851d, fc18227, ada5b24).

**crosvm:** https://github.com/google/crosvm (devices/device_virtio_fs/src/{lib,passthrough}.rs,
vhost_user/sys/{linux,windows}.rs, jail/seccomp/x86_64/fs_device.policy).

**libkrun:** https://github.com/containers/libkrun (docs/security-model.md;
src/devices/src/virtio/fs/{server.rs, macos/passthrough.rs, windows/passthrough.rs}).

**hcsshim:** https://github.com/microsoft/hcsshim (internal/uvm/plan9.go, vsmb.go, create_wcow.go;
internal/wclayer/grantvmaccess.go).

**Linux (torvalds/linux master):** fs/fuse/virtio_fs.c, fs/fuse/Kconfig, fs/fuse/dax.c, drivers/virtio/virtio_mmio.c,
include/uapi/linux/fuse.h, include/uapi/linux/virtio_fs.h;
https://man7.org/linux/man-pages/man2/openat2.2.html; https://docs.kernel.org/userspace-api/landlock.html.

**vhost-user spec:** https://qemu-project.gitlab.io/qemu/interop/vhost-user.html (master has no shmem-map message;
device-state transfer exists).

**XNU (apple-oss-distributions/xnu):** bsd/sys/fcntl.h at xnu-7195.50.7.100.1, 8019.41.5, 10002.1.13, 11215.1.10,
11417.101.15, 12377.1.9; bsd/vfs/vfs_lookup.c, bsd/sys/namei.h at xnu-12377.121.6; SDK sys/paths.h, open(2) man page
(macOS 27.2).

**Apple:**
- https://developer.apple.com/documentation/virtualization/vzvirtiofilesystemdevice
- https://developer.apple.com/documentation/virtualization/vzvirtiofilesystemdeviceconfiguration
- third-party Seatbelt observation: https://brentfitzgerald.com/posts/lima-vms-from-a-sandboxed-agent/

**Microsoft:**
- https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_object_attributes
- https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
- https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_case_sensitive_information
- https://learn.microsoft.com/windows/wsl/case-sensitivity
- https://learn.microsoft.com/windows/wsl/file-permissions
- https://learn.microsoft.com/windows/win32/procthread/process-security-and-access-rights
- https://wsl.dev/technical-documentation/drvfs/

**CVE records:**
- Kata GHSA-2gv2-cffp-j227 / CVE-2026-47243 (https://seclists.org/oss-sec/2026/q2/650); CVE-2026-44210;
- CVE-2020-35517, CVE-2022-0358 (https://access.redhat.com/security/cve/CVE-2022-0358), CVE-2023-2861,
  CVE-2016-9602, CVE-2021-20181 (https://cveawg.mitre.org/api/cve/CVE-2021-20181);
- CVE-2020-13759, CVE-2023-41051 (vm-memory).
