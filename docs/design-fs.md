# Host folder sharing (fs): design

**Status: design and plan only. There is no code yet.** Nothing here describes what wick does today: today
`PUT /extensions/fs` is refused as an unknown extension (`crates/ext/src/lib.rs`, `test_unknown_extension_is_rejected`).
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
| 1 | Guest name escapes the share: `..`, `/`, absolute name in SYMLINK/RENAME/LINK (Kata CVE-2026-47243; virtiofsd name checks only 2026-11-06) | Layer 1, same code on all hosts: every guest name must be one component, not `.`/`..`, no `/` or NUL (Windows also `\` and `:`), and every operation is relative to a held directory handle. Layer 2: L `openat2 RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV` / M `O_RESOLVE_BENEATH` + `O_NOFOLLOW_ANY` (on macOS 27.2, 2026-11-13, a test program's `openat(dirfd, name, O_RESOLVE_BENEATH)` returned ENOTCAPABLE for `..`, `/etc/hosts` and `../etc/hosts` and opened `.`; the program is not in the repository) / W `NtCreateFile(RootDirectory, one component, OBJ_DONT_REPARSE)`, rename via `FILE_RENAME_INFORMATION.RootDirectory`. Layer 3: the OS sandbox (row 4) | Traversal corpus over every name-taking opcode, on every CI host, no VM; canaries outside the share untouched; **any refusal from layer 2 or 3 fails the test** (layer 1 must stop it); raw-virtqueue guest replay as in the Kata PoC | now (L, M); measure `OBJ_DONT_REPARSE` on W |
| 2 | Symlink/junction swapped in mid-operation (TOCTOU; CVE-2016-9602) | Never follow links: L `RESOLVE_NO_SYMLINKS` / M `O_NOFOLLOW_ANY` / W `OBJ_DONT_REPARSE` + `FileAttributeTagInformation` after open, so any reparse point is shown as a link object and never traversed. Guest-made symlinks are emulated (regular file + record), so the host never has a real link the guest made | Race suite: host threads swap dirs ↔ symlinks/junctions/mount points for 10⁶ iterations while the harness operates; same assertions as 1 | now (L, M); measure on W |
| 3 | Aliases: case folding, Unicode normalisation, 8.3 names (`PROGRA~1`), `/.vol`, ADS `file:stream` | Identity by (dev, ino) / FileId, never by name. M: compare the stored name (`fgetattrlist ATTR_CMN_NAME`) with the request, mismatch = ENOENT/EEXIST; never build `/.vol` paths. W: reject `:`; compare `FileNormalizedNameInformation` with the request (catches 8.3) | Corpus entries for each alias form; case/NFD variants | now (M); measure 8.3 check on W |
| 4 | The file server itself is taken over (parser bug) | Confine it so a takeover reaches only the share: L user/mount/pid/net namespaces + `pivot_root` into the share + seccomp (crosvm's fs list minus mknod/setresuid/capset) + `no_new_privs` + Landlock when present / M Seatbelt `(deny default)` with `file-read*`/`file-write*` only `(subpath share)`, no network/exec/fork/IOKit / W LPAC token (per-share AppContainer SID) + ACE on the share only + Job (memory, CPU, 1 process, kill on close) + wick's mitigation profile. **If any control cannot be set, wick-fsd does not start** | Per-host sandbox checks (`Seccomp: 2`, `CapEff: 0`; profile test; `TokenIsLessPrivilegedAppContainer`); an outside open from inside the server fails; one test per control proving refusal to start | now (L, M); measure LPAC + AF_UNIX + inherited handles on W |
| 5 | Taken-over server attacks the VMM | It never gets guest memory (unlike vhost-user) and no handle to the VMM; the VMM validates every reply length/unique and caps frames | `fs_proxy` fuzz target: hostile descriptor chains **and** hostile replies | now |
| 6 | FUSE parser bugs from guest-controlled lengths | Bounded decoder in its own crate; fuzzed like wick's existing targets | `fs_decode`, `fs_session` fuzz targets on CI (1 min) + nightly | now |
| 7 | Host device nodes, FIFOs, sockets, setuid files (CVE-2020-35517, CVE-2023-2861, CVE-2022-0358) | Only regular files and directories are ever opened for I/O (`fstat` on the handle first); `mknod` never called; ownership, modes, setuid, devices, FIFOs live in a wick-private metadata record; server has no capabilities | Corpus: host FIFO/device/socket in the share; setuid bit never reaches the host | now |
| 8 | Open by handle/id escapes (`open_by_handle_at` "shocker", `/.vol`, `FILE_OPEN_BY_FILE_ID`) | Never used; no `CAP_DAC_READ_SEARCH`; OS sandbox still applies | Open-by-id of an outside file from inside the server → denied | now (L); measure M `/.vol`, W open-by-id under LPAC |
| 9 | Guest exhausts handles, inodes, CPU, disk | Server caps inode table, open handles, queue depth and READDIR page size (same numbers on all hosts; Windows has no per-process handle limit, so the cap is the server's own); VMM rate limiter = upstream's block-device `RateLimiter`; CPU/memory via cgroup / jetsam + jailer CPU limit / Job; disk: a server byte budget (same on all hosts) | Limit tests: ENFILE/EMFILE/backpressure at the same numbers on every host; queue flood keeps VMM in-flight bytes under the cap | now |
| 10 | DAX: host truncates a file mapped into the guest → fault in the VMM | Not offered in v1 (ENOSYS) on any host | Guest mount with `dax` fails cleanly | now |
| 11 | Socket between VMM and server hijacked | Accept once, check the peer (`SO_PEERCRED` / `LOCAL_PEERCRED` / `SIO_AF_UNIX_GETPEERPID` → SID), then unlink | Second connection refused; wrong peer refused | now |
| 12 | Host apps act on guest-written files (Spotlight, Defender, IDEs following links) | Guest symlinks are plain files on the host, so no host tool follows them; refuse `/`, `~`, `/System`, `C:\`, `C:\Windows` as share roots by default; docs: use a dedicated directory, mark it `.metadata_never_index` | Guest `ln -s /etc/passwd x` → host sees a regular file | now (residual risk stated in SECURITY.md) |
| 13 | Windows: no "subpath" confinement for a process | Grant an inheritable ACE for the share's own AppContainer SID (Microsoft's `HcsGrantVmAccess` pattern), via an explicit `wick-fsd grant <dir>` / `revoke <dir>`; children with protected DACLs stay unreachable (fails closed). Chosen over a broker, which would parse guest names with full user rights | Outside open from the LPAC server → `ACCESS_DENIED`; revoke removes every ACE it added | measure on W |
| 14 | A directory the host moves out of the share stays reachable through held handles | Host action, trusted in Firecracker's model; L Landlock and M Seatbelt check at access time; W ACL travels with the directory | Documented in SECURITY.md | limit (W), documented |
| 15 | Case-insensitive APFS/NTFS gives names Linux treats as different | Default: refuse a case-insensitive root with an error naming the fix (case-sensitive APFS volume/sparse image; W per-directory case sensitivity, needs admin). With the operator's flag: exact-name lookups, EEXIST on case collisions | Case collision returns EEXIST on every host | now (limit: W needs admin for existing dirs) |
| 16 | Host changes not notified to the guest (no inotify) | Impossible on every host: Linux's virtio-fs driver has no notification queue. Offer `cache=never` for shares edited on both sides | Documented; `cache=never` test | limit (all hosts, same) |
| 17 | Snapshot with a live FUSE session | v1: snapshot refused with an API error naming virtio-fs (`snapshot_blocker` hook exists). Later: server state saved as paths and re-resolved beneath the root on restore | Snapshot create with fs → API error | now |
| 18 | Feature off still adds attack surface | Cargo feature `fs`, default off; `wick-fsd` separate binary; no device/process/socket without config | Default build has no fs symbols; a planned boot-test stage `fs-off` shows no virtio device 26 | now |
| 19 | Older macOS releases lack `O_RESOLVE_BENEATH` | Require the first macOS release that has the flag and refuse loudly on older ones (the same layers on every host, no reduced mode). **Which release that is is unconfirmed:** the flag is in the macOS 27.2 SDK's `sys/fcntl.h` (read 2026-11-13); this research read it in XNU's `bsd/sys/fcntl.h` from xnu-11417 on, which it took to be macOS 15.4; a third-party rsync patch says macOS 15 ([patch](https://sources.suse.com/SUSE:SLFO:1.1:Build/rsync/c0c245c4f613433f762b3dee895547b4/rsync-hardening-0021-syscall-also-use-O_RESOLVE_BENEATH-on-FreeBSD-and-Ma.patch)). 15.4 is used below as that working assumption, not as a settled floor | macOS 15 CI job: fs starts where the flag works and refuses below | measure on macOS 15 |
| 20 | Linux host with unprivileged user namespaces disabled (Ubuntu AppArmor) | Start wick-fsd from root, which confines and drops to an unprivileged uid with no capabilities, as the jailer does; otherwise refuse loudly | Run with userns disabled: refuses without root, confined with root | now |
| 21 | Guest kernel lacks the driver | Upstream CI configs have `CONFIG_FUSE_FS=y`, `# CONFIG_VIRTIO_FS is not set`; wick images add `CONFIG_VIRTIO_FS=y` | Guest boot with fs mounts the share | now |

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

Still open: the performance of the split design against vhost-user (to be measured first, row 22), and whether the
extension point can carry a `VirtioDeviceType::Fs` variant and metrics generically.

---

## 1. Summary and recommendation

**Recommendation: a "split" virtio-fs device.** The guest gets a standard virtio-fs device (`mount -t virtiofs tag
/mnt`). Inside Firecracker, that device is a *thin copier* that knows nothing about FUSE. It takes each descriptor
chain's readable bytes (bounded), sends them as one framed message over a connected Unix stream socket, and writes
the reply into the chain's writable buffers. All FUSE parsing and every file operation happen in **`wick-fsd`**: a
separate per-VM, per-share server process that sandboxes itself and never sees guest memory. It is the same Rust code
on all three hosts, over a small per-host "confined directory" layer:

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Confinement of the server process | user+mount+pid+net+ipc namespaces, `pivot_root` into the share (virtiofsd's `namespace` mode); seccomp; Landlock as an extra layer where the kernel has it | Seatbelt profile: deny by default, files only `(subpath <share>)`, no network/exec/fork | LPAC token (AppContainer without ALL APPLICATION PACKAGES), DACL grant on the share to its SID only; Job Object; wick's mitigation profile |
| Open beneath a directory | `openat2(dirfd, name, RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS\|RESOLVE_NO_XDEV)` (5.6+) | `openat(dirfd, name, O_NOFOLLOW\|O_NOFOLLOW_ANY [\|O_RESOLVE_BENEATH])`; `O_RESOLVE_BENEATH` on 15.4+ (unconfirmed, §0 row 19), `AT_RESOLVE_BENEATH` for `*at` on 26+ | `NtCreateFile(RootDirectory=dir handle, ObjectName=one component, OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT)` + reparse-tag check |
| Names | one validated component per request, never a path | same | same, plus `:` and `\` rejected and illegal characters escaped |

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

The split design (C) answers each objection: no FUSE code in the VMM, no guest memory outside the VMM, rate limiting
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
   stage 0 (operator rights, no guest input): open share root, check volume, build confinement
   stage 1 (confined): FUSE decode → confined-directory layer → host file system
```

### 4.1 VMM side (in `wick-ext`, behind `vmm::ext`)

- Config `extensions.fs`: `{"shares": [{"id", "tag", "socket", "read_only", "queue_size", "rate_limiter"}]}`.
  `rate_limiter` uses upstream's block schema. The VMM knows only the tag and the socket path. The shared directory
  is the server's configuration, so the VMM never holds a handle to it.
- At `attach_boot_devices`, before the sandbox narrows, the device connects to `socket`. The socket is in the jail
  root under the jailer, as vhost-user-blk's socket is (PORTING row 14). Failure means boot fails, with the error.
  Hot-plug is refused (`update` → error) in v1.
- Frame: `{u32 len, u64 cookie, u32 writable_cap, u16 queue, bytes}` → reply `{u32 len, u64 cookie, bytes}`.
  - `len ≤ 1 MiB + 4 KiB`. The writable capacity of a chain must hold `fuse_out_header`, or the chain is completed
    with used length 0. Linux's driver then fails the request.
  - Total in-flight bytes are capped (e.g. 16 MiB). At the cap the VMM stops popping the queue, so the VMM's memory
    cannot grow without bound (queue_size × 1 MiB would otherwise be 256 MiB).
  - **The server is untrusted input to the VMM too:** a reply longer than `writable_cap`, an unknown or duplicate
    cookie, or a short frame marks the device `DEVICE_NEEDS_RESET` and closes the socket. It never makes an
    out-of-bounds write.
- Patches needed:
  - `VirtioDeviceType` is a closed enum without `Fs` (`devices/virtio/device.rs`), so `VIRTIO_ID_FS` (26) needs a
    variant [src].
  - Metrics need an `fs_<id>` section.
  - Persist enums are needed when snapshots come.
  - No change to guest memory allocation.
- Config space: `struct virtio_fs_config { u8 tag[36]; le32 num_request_queues; }`
  (`include/uapi/linux/virtio_fs.h`) [src]. The tag is validated as UTF-8, ≤36 bytes.
- No FUSE parsing in the VMM, not even `fuse_in_header`: frames are opaque. Rate limiting charges one op per chain plus the readable + writable byte counts, with upstream's `RateLimiter`, as
  block does.
- Transport: upstream's device manager attaches over MMIO or PCI as for its own devices; virtio-fs needs nothing
  transport-specific. DAX would need shared-memory-region support (virtio PCI `VIRTIO_PCI_CAP_SHARED_MEMORY_CFG`,
  MMIO SHM registers; Linux `virtio_get_shm_region` in `virtio_fs_setup_dax`, `virtio_mmio.c` `vm_get_shm_region`).
  Neither upstream transport has it (grep of `transport/mmio.rs`, `transport/pci/`) [src].
- **Claim to prove:** turning fs on adds no system call, Mach trap or mitigation exception to the VMM's narrowed
  sandbox. The socket is connected before narrowing, and read/write on Unix streams is already allowed for vsock
  [inf → test `tools/macos/sandbox-discovery.sh` with an fs device; Windows mitigation profile unchanged].

### 4.2 Server side (`wick-fsd`, its own crate and binary, not linked into `firecracker`)

- **Stage 0** (operator's rights, reads no guest bytes):
  - parse arguments (`--shared-dir`, `--socket`, `--read-only`, limits);
  - open the share root;
  - check the volume: local, not the volume root or a system location, case sensitivity (§7), xattr/EA support;
  - set up the confinement (§6);
  - bind and listen on the socket.
- **Stage 1** (confined):
  - accept **exactly one** connection, then close and unlink the listener;
  - check the peer: Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`/`getpeereid`, Windows `SIO_AF_UNIX_GETPEERPID` (works
    across the AppContainer boundary [meas: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository]) → the expected uid or jail SID;
  - serve until EOF, then exit. Refusing to start is the only answer to a missing control: the server has no
    "unconfined" flag at all (Kata's failure mode).
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
  - Entries hold a directory handle (dirs) or (parent handle, name, identity) re-verified on reopen.
- **Limits, identical on every host:**
  - inode entries;
  - open host handles (self-limited: Windows has no per-process handle limit [meas: `jailer-test.ps1 nofile`]);
  - worker threads; queued requests;
  - name ≤ 255 bytes;
  - xattr value ≤ 64 KiB, list ≤ 64 KiB;
  - READDIR reply ≤ the request size.

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

---

## 5. Threat table

Attacker: a hostile guest kernel sending arbitrary FUSE frames (the Kata PoC builds its own virtqueue from guest
userspace, so even "guest root" suffices). Goal: anything outside "read/write regular files and directories under the
share root with the server user's rights".

| # | Threat | Linux | macOS | Windows | Sources |
| --- | --- | --- | --- | --- | --- |
| 1 | **Traversal by name** (`..`, `/`, absolute name, `a/../..`) | boundary check: one component, not `.`/`..`, no `/` or NUL; operations are `*at(dirfd, name)` only; `openat2 RESOLVE_BENEATH`; pivot_root confinement | same check; `openat` + `O_RESOLVE_BENEATH` (xnu-11417; 15.4+ unconfirmed, §0 row 19) and `AT_RESOLVE_BENEATH` (26+, xnu-12377); XNU returns `ENOTCAPABLE` for `..` at the start dir and for absolute paths (`vfs_lookup.c` `lookup`, `namei`) [src]; Seatbelt `subpath` | same check, plus `\` and `:`; `NtCreateFile` with `RootDirectory` and a single component; rename/link use `FILE_RENAME_INFORMATION.RootDirectory` + simple name, **never** `RootDirectory=NULL` with a full path (allowed by the API [doc]); DACL confinement | Kata GHSA-2gv2-cffp-j227; virtiofsd 6ead577/35f851d; crosvm `validate_path_component`; libkrun (§3.1); [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html) [doc]; [FILE_RENAME_INFORMATION](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information) [doc] |
| 2 | **Symlink/junction swap races (TOCTOU)**, host- or guest-side | `RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS`, `O_NOFOLLOW`, `AT_SYMLINK_NOFOLLOW`; operations on held fds (`fchmod`, `fstat`, `f*xattr` via `/proc/self/fd` only if needed, as virtiofsd) | `O_NOFOLLOW_ANY` (11+) [src: fcntl.h history], `AT_SYMLINK_NOFOLLOW_ANY`, `O_SYMLINK` for link objects, `XATTR_NOFOLLOW` | `OBJ_DONT_REPARSE` ("no reparse points will be followed ... fail with STATUS_REPARSE_POINT_ENCOUNTERED") [doc]; `FILE_OPEN_REPARSE_POINT` on the final component; then `FileAttributeTagInformation`: any reparse tag → not traversed (shown as a symlink or refused) [inf: measure on 20348/26300] | CVE-2016-9602; [OBJECT_ATTRIBUTES](https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_object_attributes) [doc] |
| 3 | **Crossing into another file system** (bind mounts, volume mount points, network mounts, devfs) | `RESOLVE_NO_XDEV`; v1 shows no submounts | compare `st_dev` after open; XNU's `RESOLVE_NOCROSSMOUNT`/`RESOLVE_NODEVFS`/`RESOLVE_LOCAL` are `__APPLE_API_PRIVATE` (`sys/paths.h`) [src], so they are not relied on | volume mount points are reparse points (`IO_REPARSE_TAG_MOUNT_POINT`) → refused by #2 | |
| 4 | **Aliases** that bypass name-based logic: case folding, Unicode normalization, 8.3 names, `/.vol/<dev>/<ino>`, `..namedfork` | identity by `(dev, ino)`; casefold dirs (`FS_CASEFOLD_FL`) checked per directory | APFS is normalization-insensitive, and case-insensitive by default; after each lookup or create, compare the stored name (`fgetattrlist ATTR_CMN_NAME`) with the requested one, and treat a mismatch as ENOENT/EEXIST; never build `/.vol` paths (libkrun does); `/..namedfork/` cannot be reached since `/` is rejected (XNU `RESOLVE_NOXATTRS` is private) [src] | after open, compare `FileNormalizedNameInformation` (long-name form) with the request → catches `PROGRA~1`-style 8.3 aliases [inf: measure]; per-directory case sensitivity via `FileCaseSensitiveInformation` [doc] | [Case sensitivity (WSL docs)](https://learn.microsoft.com/windows/wsl/case-sensitivity) [doc] |
| 5 | **Alternate data streams / EAs as a side channel** (`file:stream`, `dir::$INDEX_ALLOCATION`) | — | — | reject `:` in names (ADS syntax); the metadata EA is never guest-nameable | NTFS stream rules in FILE_RENAME_INFORMATION remarks [doc] |
| 6 | **Special files**: opening host device nodes, FIFOs (blocking), sockets | never open a non-regular, non-directory object (check `fstat` on an `O_PATH` fd before reopening); never call `mknod` | same (`O_NOFOLLOW` + `fstat` before reading); FIFOs opened `O_NONBLOCK` only to stat, never for I/O | no device files on NTFS; `\\.\` names cannot be reached through relative names [inf]; reparse refused | CVE-2020-35517, CVE-2023-2861 |
| 7 | **setuid/setgid/file capabilities** on host objects | server unprivileged, no caps; host modes masked; emulated KILLPRIV semantics in the record (virtiofsd's fallocate/copy_file_range lesson, fc18227) [src] | same | same (no such bits on NTFS) | CVE-2022-0358 |
| 8 | **xattrs/ACLs** | guest xattrs prefixed into `user.`; `security.capability` emulated in the record; POSIX ACLs EOPNOTSUPP | prefixed; `com.apple.*` (quarantine, provenance, ResourceFork, FinderInfo) not guest-settable | EAs are case-insensitive ASCII names, so guest xattrs go into one EA blob; host DACLs are never changed by guest chmod | virtiofsd `--xattrmap` doc [doc] |
| 9 | **Ownership mapping** abused for privilege | emulated only; the server never calls `setresuid`/`fchown` with guest ids | same | same; not WSL's `$LX*` EAs (§3.1) | |
| 10 | **Open by handle/id escapes** (`open_by_handle_at`, `/.vol`, `FILE_OPEN_BY_FILE_ID`) | never use; no `CAP_DAC_READ_SEARCH` (the "shocker" container escape) | never use `/.vol`; Seatbelt subpath still applies [inf: test] | not used with guest-influenced ids; ACL confinement still applies [inf: test] | virtiofsd README on DAC_READ_SEARCH [doc] |
| 11 | **Inode/handle exhaustion**; never-forgotten lookups | inode-table and handle caps (virtiofsd's `GuestFdSemaphore` idea, `guest_fd_limit.rs`) [src]; `RLIMIT_NOFILE` too | caps; `RLIMIT_NOFILE` | caps (no OS handle limit [meas: `jailer-test.ps1 nofile`]) | |
| 12 | **DoS**: huge directories, slow host fs, disk fill, CPU | bounded READDIR pages, bounded worker pool, queue cap; VMM rate limiter; CPU/memory via cgroup | same; jetsam + CPU limit (wick's jailer mechanisms) | same; Job memory/CPU/1-process | disk fill: host quotas only (§10) |
| 13 | **DAX window**: host truncation → fault in the VMM; host page cache mapped into the guest | not offered (ENOSYS) | not offered | not offered (NTFS also refuses to truncate a file with a mapped section, so semantics would differ) [inf] | virtiofsd `setupmapping` [src]; Cloud Hypervisor removed DAX [doc] |
| 14 | **Server access to guest memory** | none in design C | none | none | B would give all of it [doc] |
| 15 | **Guest-controlled lengths/fields** in FUSE frames | decoder bounds, fuzzing (§11); the VMM caps frames | same | same | |
| 16 | **Hostile server → VMM** (a compromised wick-fsd) | VMM validates replies (§4.1); the server cannot reach guest memory or the VMM process | same | same; no `PROCESS_DUP_HANDLE` either way | |
| 17 | **Socket hijack / impersonation** | accept once, `SO_PEERCRED`, unlink | accept once, `LOCAL_PEERCRED` | accept once, `SIO_AF_UNIX_GETPEERPID` → token SID [meas: works across the AppContainer boundary, a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10; the probe is not in the repository] | |
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
  - Landlock first appeared in Linux 5.13 [doc], and upstream supports 5.10 hosts (docs/kernel-policy.md) [src], so it
    is an added layer, never the only one.
- **Resolution:** `openat2(2)` (Linux 5.6+) with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`
  and a single component. `O_PATH` fds for inodes. Reopen through `/proc/self/fd` as virtiofsd does
  (`passthrough/util.rs`), which needs `/proc` inside the namespace, read-only.
- **seccomp:** list like crosvm's `fs_device.policy` [src], minus `mknodat`, `setresuid`/`setresgid` and
  `capset` (ownership is emulated).
- **No** file handles (`name_to_handle_at`), no `CAP_DAC_READ_SEARCH`, no DAX.

### 6.2 macOS (Apple silicon; wick supports macOS 15, 26, 27)

- **Confinement:** stage 0 resolves the share with `realpath` and checks it. Seatbelt subpaths match the
  canonical path; the firmlink forms `/System/Volumes/Data/...` vs `/Users/...` are an open question, and wick has
  hit Seatbelt path pitfalls before.

  Then `sandbox_init` with a profile built like wick's (`overlay/vmm/ext/sandbox.rs`):
  - `(deny default)`;
  - `file-read*`/`file-write*` only `(subpath "<share>")` (read-only shares: `file-read*` only);
  - the inherited socket's read/write;
  - no network, `process-exec`, `process-fork`, IOKit or `mach-lookup` beyond what discovery shows libsystem needs.

  Root drops to the invoking uid. The memory limit is jetsam; the CPU limit uses the jailer's mechanism.
- **Resolution:**
  - `openat(dirfd, name, O_NOFOLLOW|O_NOFOLLOW_ANY|O_CLOEXEC)`, plus `O_RESOLVE_BENEATH` on 15.4+ (unconfirmed, §0 row 19);
  - `*at` calls with `AT_SYMLINK_NOFOLLOW` (+`AT_SYMLINK_NOFOLLOW_ANY`, and `AT_RESOLVE_BENEATH` on 26+);
  - `renameatx_np(RENAME_EXCL|RENAME_SWAP)` for RENAME2;
  - xattrs only through fds (`f*xattr`, `XATTR_NOFOLLOW`), since macOS has no `*at` xattr calls.

  Flag history from XNU's `bsd/sys/fcntl.h`: `O_NOFOLLOW_ANY` in xnu-7195 (macOS 11); `O_RESOLVE_BENEATH` in
  xnu-11417 (taken to be macOS 15.4; unconfirmed, §0 row 19); `AT_RESOLVE_BENEATH` and `O_UNIQUE` in xnu-12377 (macOS 26) [src].

  On releases without `O_RESOLVE_BENEATH` the server refuses to start (decision 5 in §0).
- **No `O_PATH`.** Directories are held as `O_SEARCH` (= `O_EXEC|O_DIRECTORY`) fds. Non-directories are held as
  (parent fd, name, `(st_dev, st_ino)`) and reopened and checked per use. `O_EVTONLY` fds are a candidate O_PATH
  substitute [inf: test access semantics].
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
  - The listening socket and the share-root handle are inherited by the LPAC child. A handle does not bypass access
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
- **Names:** reject `:` and `\`. Escape characters NTFS forbids (`* ? " < > |`, 0x01–0x1F) and trailing dot/space
  into the private-use range, as WSL DrvFs does [inf: confirm WSL's mapping], and round-trip them. NT relative opens
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
| Case | require a case-sensitive root by default; with an explicit operator flag, run on a case-insensitive root with exact-name lookups and EEXIST on case collisions (loud, documented) | ext4/f2fs casefold dirs handled the same way | APFS default is insensitive; use a case-sensitive APFS volume or sparse image (`hdiutil` needs no admin [inf]) | per directory; needs admin |
| Names | UTF-8 only, ≤255 bytes; `EILSEQ`/`ENAMETOOLONG` otherwise | non-UTF-8 host names: open question | APFS requires UTF-8 | escaped (§6.3); total NT path length ~32K characters |
| Locks (`fcntl`, `flock`) | not negotiated, so guest-local only; not visible to host processes | | | |
| mmap coherence | guest page cache (no DAX): coherent inside the guest; host writers show up after cache timeouts; `cache=never` option for shares edited on both sides | | | |
| inotify/fsnotify for host changes | **not delivered**: Linux's virtio-fs driver has only hiprio and request queues, no notification queue (`fs/fuse/virtio_fs.c`, `VQ_HIPRIO`/`VQ_REQUEST`) [src]; guest-side changes do fire in the guest | | | |
| `O_TMPFILE` (FUSE_TMPFILE), POSIX ACLs, ioctls | ENOSYS/EOPNOTSUPP, so applications fall back | | | |
| Sparse files, fallocate, punch hole | supported; wick's `platform::fs` already has hole semantics per host | native | `F_PUNCHHOLE` | `FSCTL_SET_ZERO_DATA` |
| Quotas / free space | `statfs` from the host volume | | | |

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
  `# CONFIG_NET_9P is not set` (all seven `microvm-kernel-ci-*.config`) [src]. wick's images (M6) would add
  `CONFIG_VIRTIO_FS=y`. Option D works with upstream kernels as they are.

---

## 9. What is impossible on which host (and fails loudly)

| Item | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Kernel-enforced path confinement of the server | namespaces + pivot_root (needs userns or root); Landlock 5.13+ | Seatbelt subpath | none as such: DACL grant to an LPAC SID (modifies the share's ACL) |
| Beneath-flag resolution | 5.6+ | `O_RESOLVE_BENEATH` 15.4+ (unconfirmed), `AT_RESOLVE_BENEATH` 26+ | `OBJ_DONT_REPARSE` (version minimum undocumented [inf]) |
| Containment of dirs the host moves out | Landlock (dynamic) [inf] | Seatbelt (dynamic) [inf] | **no** (static ACLs): documented |
| Case-sensitive share without admin | yes | case-sensitive APFS volume/image | **no** for existing dirs (admin + empty dir) |
| Native symlinks without privilege | yes | yes | **no** (privilege or Developer Mode): emulated everywhere |
| Per-process handle limit | `RLIMIT_NOFILE` | `RLIMIT_NOFILE` | **none** [meas: `jailer-test.ps1 nofile`]: self-limit everywhere |
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
   - Seatbelt `subpath` vs `/.vol` and firmlink aliases, and very deep paths;
   - `O_EVTONLY` as an O_PATH stand-in;
   - whether a `sandbox_init`ed (non-App-Sandbox) process's files get `com.apple.quarantine`/`com.apple.provenance`;
   - which macOS release first has `O_RESOLVE_BENEATH` (decision 5 in §0 needs it);
4. **Linux:** where unprivileged userns is disabled, a root launcher that drops (§0, decision 6). Open: how
   non-UTF-8 host names are presented under the parity rule.
5. **Quota:** decided for a byte budget in the server (§0, decision 7).
6. **Performance of C** vs vhost-user (measure before deciding whether a VMM↔server bounce ring, never guest
   memory, is needed).
7. **Patch footprint:** a `VirtioDeviceType::Fs` variant, metrics, and later persist. Can the extension point carry
   these generically for future devices?
8. **Read-only shares on macOS/Windows:** do atime updates on reads (virtiofsd notes this on Linux) matter to
   operators?
9. Share roots: home and system locations are refused by default (§0, decision 8). Open: the exact list per host.

---

## 11. Test plan (none of these tests exists yet, except where marked; each gets its name in the docs once it exists, per `tools/check-claims.py`)

1. **Off by default:**
   - `test_unknown_extension_is_rejected` (exists);
   - a default build has no fs symbols;
   - with the feature but no config: no virtio device 26 in the guest, no socket, no process (a planned boot-test
     stage `fs-off` on each host).
2. **Traversal corpus (host-side harness, no VM, every CI host).** A Rust harness speaks wick-fsd's frame protocol
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
3. **Race suite:**
   - host threads swap directories ↔ symlinks / junctions / mount points and hard links while the harness issues
     operations, 10⁶ iterations, each loop under an alarm so that a hang fails the test;
   - the same assertions as 2.
4. **Fuzzing** (cargo-fuzz in `fuzz/`, CI one minute each like the existing targets, longer nightly):
   - `fs_decode`: frame → request; no panic, bounded allocation;
   - `fs_session`: request sequences against an in-memory backend and a temp-dir backend with canaries;
   - `fs_proxy`: VMM device with hostile descriptor chains **and** hostile server replies.
5. **Guest-level, on each host:**
   - pjdfstest in the guest on the share;
   - an xfstests `generic` subset with `FSTYP=virtiofs`;
   - results compared across hosts with a differences file like `tools/macos/integration-test-differences.txt`
     (each difference with its reason: impossible / emulated / bug).
6. **Raw guest attack:** a guest-root tool that builds its own virtqueue (as in the Kata PoC) and replays corpus 2
   from inside the guest, on all three hosts (Windows on the WHP PC).
7. **Sandbox checks of wick-fsd:**
   - Linux: `/proc/<pid>/status` (`Seccomp: 2`, `NoNewPrivs: 1`, `CapEff: 0`), `/` = the share, an open of an outside
     path fails;
   - macOS: a profile test like `test_unlisted_syscalls_are_denials`, plus `/.vol` and firmlink-alias opens denied;
   - Windows: `TokenIsLessPrivilegedAppContainer`, Job limits, `GetProcessMitigationPolicy`, outside open and
     open-by-id → `ACCESS_DENIED`;
   - all hosts: the server refuses to start when any control cannot be installed (one test per control).
8. **VMM sandbox unchanged:** `tools/macos/sandbox-discovery.sh` with an fs device shows no new entries; the Windows
   profile is identical; Linux seccomp is unchanged.
9. **Limits:** inode/handle/queue caps produce ENFILE/EMFILE/backpressure with the same numbers on every host;
   VMM in-flight bytes stay under the cap with a guest flooding the queue.
10. **Snapshot refusal:** snapshot create with fs attached → API error naming virtio-fs.

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
