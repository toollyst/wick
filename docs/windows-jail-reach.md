# Windows: what a jailed Firecracker reaches outside its files

The detail behind SECURITY.md, "Windows jailer: the jail's token does not confine devices or the system's services".
- What the token a Windows jail runs under reaches on the host, beyond the files and registry keys SECURITY already
  covers: device objects and what a handle to each allows, the system services' RPC endpoints and pipes, shared
  memory sections, names in the session's namespaces, and IP.
- What it does not reach.
- How Linux's jail compares.
- The fix and where it stands.

Every figure names the probe run that gives it.

In short:
- The jail confines the user's files, other processes and (with `--netns`) IP.
- It does not confine the device namespace or the RPC surface of the system's services. There it has about what any
  process of the user has, less what its integrity level stops it writing.
- A Linux jail has four device nodes behind a list of allowed I/O-control numbers.
- These measurements show no step out of the jail, and none was looked for: no driver's or service's own checks were
  attacked. They show how much kernel and service code a compromised VMM can talk to, which on Windows is far more
  than on Linux.

## How it was measured

- **Host.** Windows Server 2022 build 20348 on a GCP VM (8 vCPUs). The host has no Hyper-V, so WHP's own devices
  are not on it; they are measured on CI's runner ("WHP under the jail's SID alone").
- **Jailer.** A debug build of the jailer from the Windows jail code as it is on main. The jail's token construction
  (overlay/jailer/platform/windows/mod.rs, `RESTRICTING_SIDS`, `vm_sid`) has not changed since it was built.
- **The probe.** `tools/windows/fs-probe.rs` (commit 803121f6) carries the jailer's handover mark, as
  `tools/windows/jail-probe.rs` does, so the jailer starts it as the jailed binary: the same token, mandatory label,
  Job Object, jail drive and directory as Firecracker's. It reverts to the jail's lockdown token first, as Firecracker
  does, and applies wick's mitigation profile.
- **The lists.** `fs-probe list-objects <file>` (elevated) lists every named kernel object (1,680: all object
  directories) and named pipe (61) into a file every jail may read. Pipe names come and go, so the list is taken just
  before the run; `devjail` tried all 61, and the pipe it makes itself comes after the list and is not in it.
- **The jailed run:** `jailer --id dj1 --exec-file fs-probe.exe --uid 0 --gid 0 --chroot-base-dir <dir> -- devjail
  <file> 22 8.8.8.8 53`. It ran again with `--netns <dir>`; both gave the same counts but for IP.
- **What `devjail` does with each name:**
  - It opens the name with `MAXIMUM_ALLOWED`: an ALPC port by connecting to it (1 s); a device that refuses its name,
    again by a name beneath it.
  - For each device it opens it records the access Windows granted, the device's type and characteristics, and
    whether the driver dispatches an I/O control that no driver defines (`CTL_CODE(type, 0xFFF, METHOD_BUFFERED,
    FILE_ANY_ACCESS)`, which needs no access right). An answer from the driver shows its I/O-control code is reached.
  - Where read is granted, it reads 512 bytes (cancelled after 1 s; nothing read is printed). Where write is granted,
    it makes a zero-length write.
- **`devjail`'s other checks:**
  - information I/O controls on the disk, the volumes, the mount manager and the serial ports;
  - opens asking `FILE_READ_DATA` of the disk and the volumes;
  - TCP connects (nothing sent) to loopback, to the link-local metadata address 169.254.169.254:80 and to 8.8.8.8:53;
  - making a named pipe and a mailslot;
  - randomness (`BCryptGenRandom`) and the network configuration (`GetAdaptersAddresses`);
  - a System32 DLL loaded, and an HKLM key read, after `RevertToSelf`.
- **The variants.** `fs-probe jail-variants <dir> 8.8.8.8:53` (elevated) runs the same checks under tokens built in
  the probe:
  - `jail-as-now`: the jailer's construction. Its counts equal the real jail's for every kind of object, which is
    what lets the other variants stand for jailer changes;
  - `jail-own-sid-only`: the jail's own SID as the only restricting SID (the fix below);
  - two variants with AppContainer group SIDs, which Windows refuses;
  - since the WHP records, in CI's windows-guest job: the jail's SID with Authenticated Users, with Authenticated
    Users and Everyone, and with the `hypervisorPlatform` capability SID (refused); an AppContainer and two LPACs
    with that capability (option Q), each followed by option Q's own checks (`q_checks`). Not yet run.

- **In CI, the record stage.** `jailer-test.ps1 reach` makes the same record with the jailer's own spawn on CI's
  windows-guest runner (Windows Server 2025 build 26100, with Hyper-V): `jail-probe reachlist` (the operator) lists
  every named object, pipe and mailslot into the jail's root, and `jail-probe reach`, after Firecracker's preload and
  `RevertToSelf`, opens each as `devjail` does (`tools/windows/jail-reach.rs`, the same code) and runs the checks that
  are not names (a DLL loaded and HKLM read after the revert, TCP to loopback, the link-local metadata address and
  8.8.8.8:53, an AF_UNIX bind, a pipe and a mailslot made, the pipes listed). Its output, one `reach` line per name
  reached and a `reach-summary` per type, is the format the fix's allowlist will read; it asserts nothing yet; the fix
  makes it an assertion against one exact allowlist. Then `jail-probe smb` opens this host's own files and pipes
  through the network redirectors, which no device security guards beneath their names (`\Device\Mup` and
  `\Device\RdpDrPort` have no `FILE_DEVICE_SECURE_OPEN`): `C$\Windows\win.ini` by 127.0.0.1, `localhost` and the
  computer's name, `ADMIN$`, `IPC$` and its `srvsvc` pipe, the same through `\Device\LanmanRedirector` and a UNC name,
  and the RDP client drives (`tsclient`), each line the NTSTATUS or the access granted and a read. It runs in the jail
  with `--netns` first, whose filters are the jail's token's while the redirector's connection is the system's, then
  in the jail, then as the operator, the control, last (which of them this host serves itself), with the server
  service's state and the shares. A restricted token shares the operator's logon session, so a jailed open could reuse
  an SMB connection the operator's made; the order keeps any run from finding one this stage made, and the client's
  connections are recorded before each run and after the `--netns` run and the control: a reused connection, or one a
  `--netns` run made, is on the record. The record of the first order (the operator first) could not tell a jailed
  open that made its own connection from one that reused the operator's. Whether a redirector carries the jail's open
  to the host's shares with the user's credentials is what it records, under each token. The records are kept for CI's
  upload (`reach-record.txt`, `reach-objects.txt`). First run: CI.
- **The SMB record's first run, and what it could not tell.** In CI's windows-guest job at c54303cd (the token as
  shipped, the operator's run first), the operator opened 9 of the 12 forms: `C$` by all three names, `ADMIN$`,
  `IPC$`, both `srvsvc` pipes, `C$` through `\Device\LanmanRedirector` and by a UNC name, each granted `0x1f01ff`, and
  `win.ini` read; `tsclient` was refused (`0xc0000022`, no RDP session) and `\Device\RdpDrPort\x` not found
  (`0xc0000039`). The jail opened none: every form through Mup, the LanMan redirector and a UNC name was refused with
  `0xc0000022`. The `--netns` run did not happen (the stage tested whether it was elevated without asking; fixed
  since). The jail opened `\Device\Mup` itself by name (`0x1200a0`, traverse among it), so the device's security did
  not refuse it. But `0xc0000022` (`STATUS_ACCESS_DENIED`) is what a server answers when a share's security refuses
  the session's user (MS-SMB2 3.3.5.7, "Receiving an SMB2 TREE_CONNECT Request") as well as what a refusal on the
  client's side gives, so the record does not say where the jail was refused, and `C$` and `ADMIN$` grant
  administrators, which none of the jail's restricting SIDs is.
- **The second run, in the order above.** In CI's windows-guest job at de8805f4 (the token as shipped) the SMB client
  listed no connection before the `--netns` run, none after it, and none after the jailed run (`Get-SmbConnection`);
  both jailed runs opened none of the 12 forms, each Mup, LanMan redirector and UNC form refused with `0xc0000022` as
  before; the operator's control, last, opened 9 of 12 as before and left connections to `\\127.0.0.1\ADMIN$`, `C$`
  and `IPC$` and `\\localhost\C$` as the runner's administrator, SMB 3.1.1. So the jail was refused with no connection
  there to reuse, and neither of its runs left one: it did not reach a share through a connection of the operator's,
  and `--netns` changed nothing. That points to a refusal on the client's side, before a connection is made, but does
  not prove it: `Get-SmbConnection` lists the connections established (Microsoft Learn, Get-SmbConnection), and an
  attempt the server refused at its session set-up or its tree connect would not be listed either. The share probe
  below adds what tells the two apart: the server's sessions and its event channels for each run's window, and a share
  the jail's restricting SIDs may read. Left for the record under the jail's SID alone (step C): the same opens and
  the share probe under that token. Left for the PC: a share on another machine, which authenticates the user's
  credentials and which CI cannot reach, a medium-integrity user and an account that is not the runner's, and an RDP
  session with a client drive for `tsclient`.
- **The share probe, and what each outcome means.** With `-ReachSmbShare` (CI passes it; elevated only; a run on a
  PC makes no share unless asked) the stage makes a share of its own for the run, temporary, read granted to
  Everyone, over a directory holding only a canary whose ACL grants Everyone read, records the share's security
  (`Get-SmbShareAccess`) and the canary's ACL, and opens the canary by every form `C$` is opened by (Mup by
  127.0.0.1, `localhost` and the computer's name, the LanMan redirector, a UNC name) in the jail with `--netns`, in
  the jail, from `jail-probe low` (the operator's token at low integrity, not restricted) and as the operator, in
  that order. After each run it records the server's sessions and open files (`Get-SmbSession`, `Get-SmbOpenFile`)
  and the entries of the run's window in `Microsoft-Windows-SMBServer/Security` and `/Operational` and
  `Microsoft-Windows-SMBClient/Security` and `/Connectivity`, saying so where a channel is missing or not enabled
  (nothing is enabled). The share and its directory are removed when the stage ends, and the stage fails if the
  share is still there. What each outcome means, written before the first result:
  - Under the token as shipped (restricting SIDs: the jail's, Everyone, Users, Authenticated Users, Interactive;
    integrity below medium):
    - The jail opens the canary: the `C$` refusal was the share's security at the server, which evaluated a token
      without the administrators. Any share the user's groups may read is then reachable from a jail, a remote one
      included, and this is a finding.
    - The jail is refused and the low-integrity run opens it: the token's restriction is what is refused, and the
      server's sessions and events say where: a session or an entry of the server's for the jail's run means the
      server refused it; none means the client did, before the server was asked.
    - The jail and the low-integrity run are both refused and the operator opens it: integrity below medium is
      refused as well (or first), at the place the server's records show.
    - The `--netns` run differs from the jail's: `--netns`'s filters reach the redirector's connection; a connection
      that appears in the client's list during the `--netns` run is that answer by itself.
  - Under the jail's SID alone (step C), the same share: the jail opening it means the server saw a token that holds
    Everyone, which is not the jail's, and is an escape; a refusal is read against the first token's outcome above.
  - The operator refused: the share was not served, and the record shows nothing about a jail.
  - What CI cannot show either way: a share on another machine that authenticates the user's credentials. That stays
    the PC test (a share on another machine, a medium-integrity user, an account that is not the runner's), unless
    the outcome locates the refusal at the client for every token.
  - The probe's parts that need no jailer (the share made and removed, its access and the canary's ACL, the
    low-integrity run and the operator's, the operator's own read of the canary through `\\127.0.0.1`, the server's
    record) also run in CI's windows job, before its build (`jailer-test.ps1 helpers -ReachSmbShare`), so that a
    failure of the share's own is seen there first; that run asserts the operator's read and that each record ended,
    nothing of what opens, and its record is not this record. First run: CI.

## What the jail reaches

All counts are `devjail` under the jailer, unless marked otherwise.

| Kind | Listed | Reached | Which, and what the handle allows |
| --- | --- | --- | --- |
| Device objects | 174 | 87, by name | each driver's create, close and I/O-control code; the groups below |
| ALPC ports | 167 | 147, connected | among them the RPC endpoints of LSA (`lsasspirpc`, `lsapolicylookup`, `lsacap`), SAM (`samss lpc`), the service control manager (`ntsvcs`), the event log, the endpoint mapper, `keysvc`, `protected_storage`, `audit`, `WindowsShutdown`, Terminal Services, DCOM's `OLE…` ports, 43 `LRPC-…` endpoints, csrss's `\Windows\ApiPort` and the desktop window manager's |
| Named pipes | 61 | 17, opened | `lsass`, `spoolss` (granted `0x1201bb`, which includes write), `srvsvc`, `wkssvc`, `atsvc`, `ntsvcs`, `eventlog`, `epmapper`, `InitShutdown`, `scerpc`, `LSM_API_service`, `TermSrv_API_service`, `Ctx_WinStation_API_service`, `SessEnvPublicRpc`, `trkwks`, `W32TIME_ALT`, `openssh-ssh-agent` |
| Sections (shared memory) | 197 | 97 | to read: KnownDlls, code-page tables, the COM catalogue caches, Microsoft Defender's `MpSvcMemory-…`, the MSDTC and WMI counters, `\Windows\SharedSection`. To write: `windows_shell_global_counters` |
| Events | 115 | 30 | to wait on only (no `EVENT_MODIFY_STATE`) |
| Mutexes | 214 | 5 | with `SYNCHRONIZE`, so it can hold them: `DBWinMutex` (global and the session's), `RasPbFile` |
| Symbolic links, directories | 184, 56 | 160, 23 | their names |
| Other | `\REGISTRY` (read), one keyed event | 2 | |
| Filter ports, jobs, sessions, partitions, timers, semaphores | 359 | 0 | |

**Names in the session's namespaces.** It makes a named pipe (`\\.\pipe\…`) and a mailslot (`\\.\mailslot\…`). A
name it makes first is taken from whoever expects it, the pipes SECURITY.md describes for the log, metrics and
serial output included.

**IP.** All by TCP connect:

| Target | Without `--netns` | With `--netns` |
| --- | --- | --- |
| 127.0.0.1:22 | connected | refused, WSA 10013 |
| 169.254.169.254:80 | connected | refused, WSA 10013 |
| 8.8.8.8:53 | connected | refused, WSA 10013 |

`--netns`'s Windows Filtering Platform filters hold against the jail's own token, at all three.

### The 87 devices, by what a handle allows

**Data in and out: the host's serial ports.**
- Devices: `\Device\Serial0`, `\Device\Serial1`, `\Device\Serial2`, and their PnP device objects for COM1, COM3 and
  COM4.
- Measured: granted `0x1201bf`, which includes read and write data. A read is queued and stays pending, so it would
  complete with what arrives. A zero-length write completes. `IOCTL_SERIAL_GET_BAUD_RATE` answers.
- **`--netns` does not close them:** they are not IP. On a cloud VM, a COM port may carry the VM's serial console; on
  a PC, it is any COM port, USB serial adapters included.

**Information about the host.**
- `\Device\Harddisk0\DR0` is granted only `0x1200a0`, which has no read or write data. Through I/O controls that ask
  no access right, it still answers:
  - `IOCTL_STORAGE_QUERY_PROPERTY` with the disk's vendor, model and **serial number** (20 characters here);
  - `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` with the **partition table** (3 partitions).
- `\Device\MountPointManager` answers `IOCTL_MOUNTMGR_QUERY_POINTS` with **every mount point**: drive letters and
  volume GUIDs.
- `\Device\HarddiskVolume1` to `3` give their disk extents.
- `\Device\Nsi` opens. `GetAdaptersAddresses` itself fails in the jail (error 1702, an RPC binding error).

**What Firecracker uses**, the counterparts of Linux's device nodes:
- `\Device\Afd` (sockets);
- `\Device\KsecDD` and `\Device\CNG` (randomness and cryptography; `BCryptGenRandom` works);
- `\Device\Null`;
- `\Device\NamedPipe` (the pipes Firecracker may be given for its log, metrics and serial output).

**Drivers whose I/O-control code is reached, with nothing read or written.** Each of these dispatched the undefined
I/O control: it answered 0xC0000010, 0xC000000D or 0xC0000002, or completed it.
- **Security and platform:**
  - the TPM 2.0 device (granted `0x1f01ff`, full access) and `\Device\PEAuth` (`0x1f01ff`), which a plain
    AppContainer also opens (`fs-probe devices`, a run on the same host);
  - `\Device\WindowsTrustedRT`, `\Device\ahcache` (the application compatibility cache), `\Device\WMIDataDevice`,
    `\Device\Bam`, `\Device\PcwDrv`;
  - the eight processors' devices, the ACPI devices: the fixed-feature button's and the CMOS clock's complete the
    undefined control;
  - the bus enumerators, the PCI bus's `\Device\NTPNP_PCI0001` and `0004`, `\Device\RdpBus`, `\Device\RdpDrPort`.
- **Network:** `\Device\Tcp`, `Tcp6`, `Udp`, `Udp6`, `RawIp`, `RawIp6`, `Tdx`, `Netbios`, `NetBT_Tcpip_{…}`,
  `NetBt_Wins_Export`, `Ndis` (completes the undefined control), `NDMP1`, `LanmanDatagramReceiver`, `Srv2` (completes
  it after pending), `Mup`, `DfsClient`.
- **Storage:** `\Device\PartmgrControl`, `VolMgrControl`, `Spaceport`, the volume manager's and Storage Spaces'
  device objects, the disk's own device object, `FsWrap`, the file systems' control objects (`\Ntfs`, `\Refs`, `\Fat`,
  `\FatCdrom`), `RawDisk`, `RawCdRom`, `RawTape`, the nine file-system recognisers and `\FileSystem\Filters\FltMgr`.
- **Input:** `\Device\KeyboardClass0`, `\Device\PointerClass0` and the PS/2 keyboard's and mouse's device objects. A
  read is refused (`STATUS_PRIVILEGE_NOT_HELD`) for every token, an elevated administrator's included: the class
  drivers give input to the trusted subsystem only (`fs-probe devices`).

**What it does not reach.**
- An open asking `FILE_READ_DATA` of `\Device\Harddisk0\DR0` or of `\Device\HarddiskVolume1` to `3` is refused
  (`STATUS_ACCESS_DENIED`): no raw disk or volume reads.
- `\Device\PhysicalMemory` is not reached.
- No minifilter port, job, session or partition.
- As SECURITY.md describes, no process of the user's, no other jail, and no file of the user's.

**Why.**
- The jail's lockdown token has five restricting SIDs: the jail's own, and Everyone, Users, Authenticated Users and
  Interactive, which every process of the session has (overlay/jailer/platform/windows/mod.rs, `RESTRICTING_SIDS`).
  For a restricted token, "the system performs two access checks: one using the token's enabled SIDs, and another
  using the list of restricting SIDs. Access is granted only if both access checks allow the requested access rights"
  ([Microsoft Learn, Restricted Tokens](https://learn.microsoft.com/windows/win32/secauthz/restricted-tokens); the same
  in [CreateRestrictedToken](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)).
  The device objects, RPC endpoints, pipes and sections above grant one of those four groups, so both checks pass.
- An I/O control whose code asks `FILE_ANY_ACCESS` needs no right on the handle, so any open handle reaches the
  driver's I/O-control code.
- A device created without `FILE_DEVICE_SECURE_OPEN` leaves opens of names beneath it to its driver, without its
  security descriptor
  ([Microsoft Learn, Controlling Device Namespace Access](https://learn.microsoft.com/windows-hardware/drivers/kernel/controlling-device-namespace-access)).
  That is how the token without the four groups still reaches 13 devices (below).
- The jail's integrity level (`S-1-16-6144`, below medium) does not stop the writes above: the serial ports, the
  spooler's pipe, the counters section, and the names it makes. Why the mandatory label does not apply there is not
  determined.

## Against Linux

| | Linux jail: chroot and upstream's seccomp filters | Windows jail: restricted token, integrity 0x1800, Job Object, mitigation profile |
| --- | --- | --- |
| Device nodes | `/dev/kvm`, `/dev/net/tun`, `/dev/urandom`, and `/dev/userfaultfd` and `/dev/nitro_enclaves` where the host has them (src/jailer/src/env.rs, `mknod_and_own_dev`) | 87 device objects |
| I/O controls | a list of allowed numbers per thread: 24 on the VMM thread (KVM, TUN, block sizes, terminal settings, `FIONBIO`, Nitro Enclaves), 19 on vCPU threads (KVM), `FIONBIO` on the API thread (resources/seccomp/x86_64-unknown-linux-musl.json) | none: every `FILE_ANY_ACCESS` I/O control of 87 drivers, and those whose access the handle has |
| Sockets | `socket` only for `AF_UNIX, SOCK_STREAM \| SOCK_CLOEXEC`: no IP after the filter, with or without `--netns` | IP unless `--netns` |
| System services | none in the chroot | 147 RPC/ALPC endpoints and 17 service pipes |
| Names it can make for others | none: its files are in the chroot | named pipes and mailslots in the session's namespace |
| Host serial ports | not in the chroot | read and write |
| Host fingerprint | no `/sys` or `/proc` in the chroot | the disk's serial number, the partition table, every mount point, Defender's shared memory |

## The fix: the jail's own SID as the only restricting SID

**Status: planned.** Measured under the probe's construction; no jailer change yet.

| | Jail as it is (`jail-as-now`) | Own SID only (`jail-own-sid-only`) |
| --- | --- | --- |
| Device objects | 87 | 13, all by a name beneath them, none by name: `\Device\Afd`, the file systems' and RAW control objects (`\Ntfs`, `\Refs`, `\Fat`, `\FatCdrom`, `RawDisk`, `RawCdRom`, `RawTape`), `LanmanDatagramReceiver`, the keyboard and mouse class devices and the PS/2 device objects. These are the devices without `FILE_DEVICE_SECURE_OPEN` |
| ALPC ports, service pipes, sections, events, mutexes, links, directories, keys | 147, 17, 97, 30, 5, 160, 23, 1 | 0 of each |
| Makes a named pipe, a mailslot | yes | no (access denied) |
| Serial ports; the disk's, volumes' and mount manager's I/O controls | yes | no: the opens are denied |
| TCP without `--netns` | connects | still connects, through `\Device\Afd` beneath its name. `--netns` stays the control for IP |
| Unix socket bound in its own jail-labelled directory; `BCryptGenRandom` | yes | yes |
| A System32 DLL loaded after `RevertToSelf` | loads | **fails** (126) |
| An HKLM key read after `RevertToSelf` | allowed | **denied** (5) |

**What it takes.**
- Firecracker reverts to the lockdown token first thing in `main` and loads what it needs later. Every DLL and
  registry key it uses after that must move before the revert, under the initial token, as Chromium's sandbox warms
  up before it locks down. That includes WHP's, Winsock's and anything else loaded lazily. **In place, before the
  token changes:** the steps step 1's trace found (Winsock with an `AF_UNIX` socket, a socket made from another's
  protocol information, Winsock's catalogue, a system error's text, the time zone, `kernel.appcore.dll`, and WHP's
  two DLLs for the VMM) run before the revert in Firecracker and its API process (overlay/vmm/ext/jail_preload.rs,
  shared with `jail-probe`). A step that fails stops the start with an error naming it; nothing is skipped.
- WHP must still work under the new token. Under the jail's SID alone it does not (below, "WHP under the jail's
  SID alone"): either the partition is made before the revert (option P) or the VMM runs in an AppContainer with
  WHP's capability (option Q).
- **How the operator gives a jail a file:** inside the jail's root, copied or hard-linked there, as upstream's jailer
  is used on Linux, and named by its path in the root (`/vmlinux.bin`). Never by a path outside the root: the
  enforcement is the token, and under the jail's SID alone Windows refuses the open (the handoff stage's hold of a
  file in the operator's work directory: os error 5 under that token, step-1 experiment s2e), as a chroot cannot
  name the path (Linux gives `ENOENT` there, no error of its own). No check on path strings is added: a second,
  weaker rule could disagree with the token (relative paths, links, device paths). A hard-linked file gets an entry
  of the jail's SID of its own while the jail runs (`share_with_jail`; what the entry is: "Files a jail shares",
  below). A bind link's backing file, whose
  own security is what Windows checks, is found as a file of the root that Windows names outside it once open
  (`GetFinalPathNameByHandleW`) and gets the same entry by its own name while Firecracker runs, taken off when it
  ends (overlay/jailer/platform/windows/mod.rs, `linked_files`, `test_opens_outside`). `jailer-test.ps1 bindlink`
  checks that entry and that nothing else of the backing file's security changes, during or after: written, never
  run, as no host with `bindlink.dll` is available (Windows 11 build 26300, Windows Server 2025 build 26100).

**Files a jail shares.** A file hard-linked into a jail's root is one file with one security descriptor for all its
names: the operator's, and other jails'. So is a bind link's backing file, which is outside the jail.
- **The entry.** Each jail's SID gets one entry of its own on such a file while the jail runs:
  `FILE_GENERIC_READ | FILE_GENERIC_WRITE` (`0x12019f`). That covers reading and writing data, attributes and
  extended attributes, reading the security descriptor, and waiting on the handle. Firecracker opens a kernel, a
  drive, a pmem backing file or a memory file with Rust's read and write options (`GENERIC_READ | GENERIC_WRITE`),
  which a file maps to exactly these rights. The entry gives no `WRITE_DAC`, `WRITE_OWNER`, `DELETE` or
  `FILE_EXECUTE` (overlay/jailer/platform/windows/mod.rs, `SHARED_FILE_ACCESS`, `explicit_access`,
  `test_a_file_shared_by_two_jails_keeps_both`).
- **The inherited entry goes too.** The jailer sets the jail directory's DACL by name, and Windows then passes the
  directory's inherited entries down to every file in it, a hard-linked one included. That includes the jail SID's
  full access. In the same write through the file's handle, the jailer removes the inherited entries of this jail's
  SID from each shared file, and adds the jail's own entry. A jail's own files, copies included, keep the
  directory's full access, as a Linux jail owns its copies.
- **What the entry was before: full access (`FA`).** The jail directory's inherited full access also stayed on the
  file. By the documented check, a jail's restricted token then passed both of its passes for `WRITE_DAC`,
  `WRITE_OWNER` and `DELETE` on such a file:
  - the normal pass, through the user's entry (the jail directory gives the user full access);
  - the restricting SIDs' pass, through the jail SID's entry
    ([Microsoft Learn, Restricted Tokens](https://learn.microsoft.com/windows/win32/secauthz/restricted-tokens)).
  So a jail could have rewritten the DACL of a file that other jails and the operator hold, taken ownership of it
  for a SID of its token, or deleted it. Not exercised: no build with the old entry was run against it.
  - The owner of an object also has `READ_CONTROL` and `WRITE_DAC` implicitly ([Microsoft Learn, Security
    identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers),
    the OWNER RIGHTS SID: an entry of it makes "the system ignore the implicit READ_CONTROL and WRITE_DAC standard
    access rights for the object owner").
  - Whether Windows also grants those implicit rights in the restricting SIDs' pass is not sourced. The jail's SID
    never owns a shared file, so the narrowed entry does not depend on the answer.
- **When.** Both changes happen under the jailer's ACL lock, right after the directory's DACL is set and before any
  process of the jail exists:
  - The jailer makes the jail's processes, Firecracker and its API process, in `exec_command`, after the chroot
    step.
  - `--daemonize` and `--new-pid-ns` relaunch the jailer before that step, and the relaunched jailer is a process
    of the user's, not of the jail.
  - So there is a window, between setting the directory's DACL and removing the inherited entry. In it, the file
    holds this jail's inherited full access, for a SID that no process holds yet. Other jails' processes hold other
    SIDs: their own entries stay, and their inherited ones are already gone, since a file has one set of inherited
    entries.
- **Failures stop the start.** A file under the root that the jailer cannot look at, or a shared file it cannot
  change, stops the start with an error naming the file, and what was given is taken off again. Before this, such
  a file was left out silently and the jail started: Firecracker was then refused a bound file, or held the
  directory's inherited full access to a hard-linked one.
- **What stays after a jail, on every name of a hard-linked file.** This is a standing property, the operator's name
  included:
  - The last jail directory's inherited entries stay: the system, the administrators and the user. The jails'
    entries of their own are gone, and the file's own entries are as before. Measured on the operator's name
    (`jailer-test.ps1 shared`'s first CI run; docs/COMPATIBILITY.md, `--chroot-base-dir` row): `(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;LA)` after, where the file had the `files`
    directory's `(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1200a9;;;BU)` before (`jailer-test.ps1 shared`).
  - The jail's label, integrity level `0x1800` with no write, read or execute up, is expected to stay as well: the
    jail's root passes it down (`OICI`). Not measured yet. The stage's first run recorded no label: the stage
    looked for icacls's `Mandatory` line, and icacls names a label by its level's account name, which `0x1800`
    (`S-1-16-6144`) is not a well-known one to have, so the line cannot tell an unnamed label from none. The stage
    now reads the label as SDDL with `GetNamedSecurityInfoW` before, while all three jails run, and after, and
    prints the label read while they run beside the integrity level of A's and B's tokens (first run: CI).
  - Why it matters: the jails wrote the file in that run (the guest through its drive, A and B from inside), and a
    file without a label counts as medium, which a process below medium may not write
    ([Microsoft Learn, Mandatory Integrity Control](https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control)).
    The record tells the cases apart. A label of `S-1-16-6144` with the tokens at 6144: the root's label reached
    the file, and the write passed MIC at an equal level. No label with the tokens at 6144: MIC did not stop a write
    up to this file, for a reason not known yet, and the bind-link note below, that the jail cannot write a backing
    file without a label, loses its ground too. Tokens above 6144: the jail's level is not what the jailer sets.

  On Linux, too, a hard-linked inode has one owner and one mode for all its names, so an operator's chown to a
  jail's uid holds for every name. What differs is the label. Mandatory Integrity Control is checked before the DACL,
  and a process of a lower integrity level cannot write to an object of a higher one, whatever the DACL allows
  ([Microsoft Learn, Mandatory Integrity Control](https://learn.microsoft.com/windows/win32/secauthz/mandatory-integrity-control)).
  With the label at `0x1800`:
  - Processes of the user from `0x1800` up to medium (other jails) are held by the DACL alone. The DACL left after
    the jails has no jail SID, which their restricting SIDs' pass needs.
  - Low-integrity processes (`0x1000`) stay kept from writing it. Whether the label's no-read-up also keeps them from
    reading it, where an unlabelled (medium) file allows reading up, is not measured.
- **For operators.** Copy what must keep its security. Hard-link only what is the jails' to share. An operator can
  still give a jail more on a file, as Linux's `chown` gives a jail's uid the owner's rights. The integration
  harness does that for upstream's tests (tools/windows/integration/wick_windows.py, `give_to_jail`, full access).
  The jailer takes the entry off again when Firecracker ends.
- **A bind link's backing file** is outside the jail, so nothing passes down to it, and its security is as before
  after the jail (`jailer-test.ps1 bindlink`, never run). A read-write drive through a bind link probably cannot
  work: the backing file keeps its own label (none, so it is treated as medium), and the jail's token, below medium,
  cannot write up to it. Not measured: the bindlink stage has never run, and its drives are read-only.
- **Test: `jailer-test.ps1 shared`, in CI's windows-guest job.** Passed on its first run (Windows Server 2025
  Datacenter build 26100.33674; the run is in docs/COMPATIBILITY.md's `--chroot-base-dir` row). One file is hard-linked into three jails at once:
  - V, a jailed guest's read-write drive;
  - A and B, two jailed probes, started while V runs.

  It checks:
  - while all three run, the file holds exactly one `0x12019f` entry per jail SID and no inherited entry of any jail
    SID;
  - the guest writes the file before A and B start, and writes and reads it after;
  - from inside A and B, writing is allowed, and opening the file for `WRITE_DAC`, for `WRITE_OWNER`, and for
    `DELETE` through the operator's name are refused. `DELETE` through the jail's own name is printed and not
    checked: Windows grants it through the root's `FILE_DELETE_CHILD`, and it removes the jail's name only;
  - after all three end, no jail SID is left and the file's own entries and owner are as before. The stage's line
    records the inherited entries and the label as they are then.

  That run measured, in A and in B alike: writing allowed; `WRITE_DAC` denied, `WRITE_OWNER` denied and
  `DELETE` by the operator's name denied, each "Access is denied. (os error 5)"; `DELETE` by the jail's own name
  (not checked) allowed. While all three ran, one `0x12019f` entry per jail SID and no inherited entry of a jail
  SID; after, no jail SID left. The guest's writes before and after A's and B's starts reached the file and read
  back.

**WHP under the jail's SID alone.** `fs-probe whp-token` in CI's windows-guest job (Windows Server 2025 build 26100;
the runs are in docs/COMPATIBILITY.md's `--chroot-base-dir` row, the first record and the variants record; the
runner's built-in administrator, not elevated):
- In the probe itself and under the lockdown token as now, every step returned `S_OK` (capability, partition,
  processor count, setup, two memory maps, a vCPU) and the vCPU's one run exited at the guest's HLT. The partition
  opens one device, `\Device\VidExo`, at `WHvSetupPartition`, granted `0x00120089` (read).
- Under the jail's SID alone (the WHP DLLs loaded before the revert), `WHvGetCapability(HypervisorPresent)` returned
  `S_OK` with the answer 0: WHP reports no hypervisor, and `WHvCreatePartition` fails with `0xC0351000`
  (`STATUS_HV_NOT_PRESENT`). Without the DLLs loaded before the revert, `WinHvPlatform.dll` does not load (126).
- `\Device\VidExo`'s security: `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;AU)(A;;0x1201bf;;;S-1-15-3-1024-1350733694-1533467442-3402045280-1710179238-1008639688-2282869650-3611451526-669908847)S:AI(ML;;NW;;;LW)`.
  Read, write and execute go to Authenticated Users and to one capability, which a lockdown token restricted to the
  jail's SID cannot pass: the restricting SIDs' check finds no entry for them ([Microsoft Learn, Restricted
  Tokens](https://learn.microsoft.com/windows/win32/secauthz/restricted-tokens)). The capability's SID is
  `DeriveCapabilitySidsFromName("hypervisorPlatform")`: the SHA-256 of the name in upper case, UTF-16LE, as eight
  sub-authorities after `S-1-15-3-1024` (computed, and checked by the probe against the descriptor).
- `\Device\HvService`: `O:BAD:P(A;;FA;;;SY)(A;;0x1201bf;;;BA)(A;;FR;;;WD)S:AI(ML;;NW;;;LW)`. `\Device\HvSocket`,
  `HvSocketSystem`, `VMBus` and `RootVMBus` refuse the probe's open of the device object itself (`0xC000000D`,
  `0xC000000E`).

**The variants record** (`whp-token`'s second record, each child opening `\Device\VidExo` and `\Device\HvService`
itself after its revert):

| Token after the revert | VidExo | HvService | HypervisorPresent | Partition |
| --- | --- | --- | --- | --- |
| Jail's SID with the four groups (as now) | granted | granted | 1 | every step, HLT |
| Jail's SID alone | denied | denied | 0 | `0xC0351000` |
| With Authenticated Users | granted | denied | 0 | `0xC0351000` |
| With Everyone | denied | granted | 0 | `0xC0351000` |
| With Users | denied | denied | `E_ACCESSDENIED` | `E_ACCESSDENIED` |
| With Interactive | denied | denied | 0 | `0xC0351000` |
| With Authenticated Users and Everyone (third record) | granted | granted | 0 | `0xC0351000` |
| With Authenticated Users and Users (third record) | granted | denied | 1 | every step, HLT |
| With the `hypervisorPlatform` capability SID | `CreateRestrictedToken` refuses the SID as a restricting SID (87): not run | | | |
| Jail's SID alone, partition made and set up before the revert | denied | denied | (1 before) | maps, vCPU, run to HLT after the revert |
| As now, partition made before the revert | granted | granted | (1 before) | the same |
| AppContainer, no capability | denied | denied | `E_ACCESSDENIED` | `E_ACCESSDENIED` |
| AppContainer with `hypervisorPlatform` | granted (`0x120089`; most allowed `0x1201bf`) | denied | 1 | every step, HLT |

What it shows:
- **A capability SID cannot be a restricting SID.** `CreateRestrictedToken` refuses it with 87, as it refuses ALL
  APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES (below). Microsoft's page documents no such limit.
- **Opening the two devices is not what WHP needs.** With Authenticated Users and Everyone both devices open and WHP
  still reports no hypervisor; with Authenticated Users and Users, `\Device\HvService` is denied and WHP runs the
  vCPU to its HLT (the third record). What Users grants that WHP needs is not measured; the next record lists what
  that token reaches (`jail-variants`' `jail-sid-au-users`). It is not a candidate: Users is granted far more than
  WHP.
- **An AppContainer with `hypervisorPlatform` runs WHP fully with VidExo alone**: HvService was denied it, and WHP
  still reported a hypervisor and ran the vCPU to its HLT. Without the capability WHP refuses the AppContainer
  (`E_ACCESSDENIED`), which is what "WHP is refused inside an AppContainer" measured before.
- **A partition made before the revert works with the jail's SID alone.** WHP keeps the handle to VidExo it opened at
  set-up; after the revert the memory maps, the vCPU and its run need no new open, though both devices are denied.

**Option P: the jail's SID alone, the partition made and set up before the revert.** What it takes, from
kvm-ioctls' WHP backend (crates/compat/kvm-ioctls/src/whp/vm.rs, `configure`, `VmFd::create`):
- Every property the backend sets before `WHvSetupPartition` comes from the host, never from the API's
  configuration: `ProcessorCount` (`MAX_VCPUS`), `ProcessorFeaturesBanks` (the partition's own plus the host's
  speculation controls, less WHP's TSC-deadline timer), `ProcessorXsaveFeatures` (every component offered),
  `LocalApicEmulationMode` (by the host's vendor), `ExtendedVmExits` (CPUID, MSR, hypercall; exceptions with gdb)
  and `CpuidExitList` (every basic and extended leaf, and KVM's two). So the partition can be made before
  Firecracker knows its VM.
- Set after set-up already: `ExceptionExitBitmap` (the x2APIC's #GP and the gdb stub's exits, `write_exits`) and
  `X64MsrExitBitmap` (`tsc_write_exit`). Microsoft Learn,
  [WHvSetupPartition](https://learn.microsoft.com/virtualization/api/hypervisor-platform/funcs/whvsetuppartition):
  `ExtendedVmExits`, `ExceptionExitBitmap`, `X64MsrExitBitmap` and `CpuidExitList` "can be modified after" set-up;
  [Partition Property Data Types](https://learn.microsoft.com/virtualization/api/hypervisor-platform/funcs/whvpartitionpropertydatatypes):
  the processor-related properties "can only be configured" before it. Silent on `ProcessorCount` and
  `LocalApicEmulationMode`: the next record sets each again after set-up.
- The guest sees the vCPUs Firecracker makes, not `ProcessorCount`: the backend sets the maximum and makes the
  configured number on every boot today (the ACPI tables and the CPUID topology are Firecracker's, and every CPUID
  leaf exits to it). The next record makes two of four and runs one.
- A second partition after the revert fails (the jail's SID alone: no hypervisor). The backend makes two per
  process: its register probe (`regs::probe`, a partition made, given a vCPU and deleted, before the VM's) and the
  VM's; both would move before the revert. Snapshot restore makes its VM as a boot does, in a process that has made
  none, so it takes the same partition. Upstream lets an `InstanceStart` that failed be tried again in the same
  process; under P that needs the partition used again (its memory unmapped and vCPUs deleted), which the next
  record measures, or a named error.
- Each capability read after the revert must work, or be read before it: `pvclock::tsc_hz` reads the clock
  frequency at first use and answers 0 on a failure. The next record reads every capability code before and after.
- Every call a running VM makes (registers, XSAVE and interrupt-controller state, interrupts, partition time,
  cancel, address translation, dirty bitmap, advice, unmap): the next record makes each after the revert.
- The API process needs none of it: it makes no partition.

**The third record** (`whp-token`'s `jail-own-sid-p`: P's partition made and configured as the backend's before the
revert, the rest of the VM's life after it, under the jail's SID alone):
- Every capability code read after the revert returned `S_OK` with the same bytes as before it (17 codes, the clock
  frequency included).
- Every property read back. After `WHvSetupPartition`, `ProcessorCount`, `LocalApicEmulationMode`,
  `ProcessorXsaveFeatures` and `ProcessorFeaturesBanks` are refused (`0x80070057`); `ExtendedVmExits`,
  `CpuidExitList`, `ExceptionExitBitmap` and `X64MsrExitBitmap` are set. The backend sets the first four before
  set-up only, from the host.
- Three memory maps, one with dirty tracking, and two of four vCPUs: `S_OK`.
- The run of vCPU 0 never returned, and the child was ended at 120 s ("child-exit 0x103 (timed out)"). The probe's
  guest is a HLT at the reset vector, and with the local APIC emulated (`LocalApicEmulationMode` xAPIC) WHP halts the
  vCPU in the hypervisor rather than exiting (the backend's own note: crates/compat/kvm-ioctls/src/whp/vcpu.rs,
  `WHvRunVpExitReasonX64Halt`); the variants that exited at their HLT set no APIC mode. So the calls a running VM
  makes, the second partition and the partition used again were not reached: **P is not settled by this record.**
  The next record's guest exits by an `OUT` to port 0x80, a watchdog cancels a run still in WHP after 5 s, and the
  same life runs under the jail's token as now as its control (`jail-as-now-p`). It also prints what the two
  partitions cost (time, the process's commit, the Job's peak) and the Job's count of 64 MiB of guest memory mapped
  into a partition made under the initial token.

**Option Q: the VMM in an AppContainer (or an LPAC) with `hypervisorPlatform`.** WHP works natively, with no change
to when the partition is made. What it brings, and what the next record (`jail-variants`' `appcontainer-cap`,
`lpac-cap`, `lpac-cap-registry-com`, and `q_checks` after every variant) measures:
- Reach: an AppContainer is granted what ALL APPLICATION PACKAGES (an LPAC: ALL RESTRICTED APPLICATION PACKAGES) is
  granted, besides its own SID and capabilities, and the I/O manager's traverse check closes names beneath devices
  without `FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL`
  ([Microsoft Learn, `DEVICE_OBJECT`](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object)).
  Measured by the same object, pipe and device lists as above.
- Integrity: an AppContainer runs at low integrity, below the jail's label (0x1800, no write up), so the jail's
  directory would be labelled low, which a low-integrity process of the user also passes. Measured
  (`jail-labelled-dir-create`).
- Sockets: the link to the API process (the API process listens, Firecracker connects) and sockets Firecracker binds
  for clients outside. On Windows Server 2022 an AppContainer bound a Unix socket an outside process reached, and an
  LPAC needs `registryRead` and `lpacCom` for Winsock at all (a probe of the Windows sandbox mechanisms, build 20348,
  2026-11-10; not in the repository). Measured again both ways.
- Processes and handles: who may open the VMM (the uffd mirror's reader pulls its handle, the jailer's count reads
  its memory: `process-sddl`, `open-child`); the VMM opening another process (`open-parent-dup-handle`); a section
  the jailer duplicates into it mapped, as large pages are given (a large-page one only where the measuring process
  holds Lock pages in memory). An AppContainer has no privilege to enable, as the jail now.
- A Job and `SECURITY_CAPABILITIES` together: the AppContainer variants of both probes run in a Job, assigned after
  `CreateProcessAsUserW` as the jailer assigns Firecracker (the variants record: it ran); its memory limit is
  checked by `job-commit-300-mib`.
- DLLs: an AppContainer loads System32's; an LPAC only what ALL RESTRICTED APPLICATION PACKAGES may read
  (`load-library-after-revert`). The mitigation profile is applied inside each (`mitigation-*`).
- A profile per jail or none: `appcontainer-cap-bare-sid` runs WHP on a SID from
  `DeriveAppContainerSidFromAppContainerName` with no profile made.

**Option Q in the third record** (`jail-variants`, Windows Server 2025 build 26100; objects reached by name, as above):

| Token | Devices | ALPC ports | Pipes | Sections | IP (TCP) | AF_UNIX out / in | HKLM | win32k lockdown set after start |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| The jail's token as now | 94 | 262 | 19 | 102 | yes | denied | read | yes |
| The jail's SID alone | 10 | 0 | 0 | 0 | yes | denied | denied | yes |
| AppContainer with `hypervisorPlatform` | 7 | 138 | 1 | 97 | denied (10013, 10060) | connect and accept | read | yes |
| LPAC with `hypervisorPlatform` | 4 | 3 | 0 | 83 | no Winsock (10093) | no Winsock | denied | denied (5) |
| LPAC with `hypervisorPlatform`, `registryRead`, `lpacCom` | 4 | 48 | 0 | 85 | denied (10013) | connect and accept | read | denied (5) |

- The LPAC's four devices are `\Device\VidExo`, `KsecDD`, `CNG` and `Afd`, and WHP runs in it to the guest's HLT
  (`whp-token`'s `lpac-cap`). Its three ALPC ports are two of csrss's `ApiPort`s (`\Windows\ApiPort`, the session's)
  and the RPC endpoint mapper (`\RPC Control\epmapper`). Its 83 sections are the 81 image sections of `\KnownDlls`
  and `\KnownDlls32` (granted `0x2000f`: query and map) and the two `SharedSection`s of `\Windows` (granted
  `0x20004`: map for reading). Its other names are the two `KnownDlls` directories and their `KnownDllPath` links,
  the two sessions' `AppContainerNamedObjects` directories, `\KernelObjects`' memory-condition events and links
  (read and wait) and one event of the antimalware service (wait).
- Each AppContainer's memory limit held (a 300 MiB commit refused, 1455), the host opened each (duplicate a handle,
  query, read memory), and the section the host gave was mapped. No large-page section was given: the runner's
  account does not hold "Lock pages in memory".
- In the AppContainers, `jail-labelled-dir-create` answered 1314 (`ERROR_PRIVILEGE_NOT_HELD`), not 5. The jail's
  token as now and the jail's SID alone answered 5 in the same directory, so the check itself is in question; the
  next record prints each directory's security first.
- `appcontainer-cap-bare-sid` (a package SID with no profile): the process did not start (2).
- Next record: an LPAC given the jailer's initial token and Firecracker's preload before its revert, without
  `registryRead` and `lpacCom` (`lpac-cap-preload`); an LPAC with win32k's lockdown set at its creation
  (`lpac-cap-win32k-at-create`), and the policy as each process has it before it is set; an AppContainer of another
  profile against the first's directory and socket (`appcontainer-other`).

**The fourth record, and the decision** (`whp-token` and `jail-variants`, Windows Server 2025 build 26100):
- **Option P runs.** `jail-own-sid-p`'s guest exits by its `OUT`. After the revert every call a running VM makes
  returned `S_OK`: registers, XSAVE and interrupt-controller state, `WHvRequestInterrupt`, suspending and resuming
  partition time, cancelling a run, `WHvTranslateGva`, the dirty bitmap, `WHvAdviseGpaRange` and unmapping. All 17
  capability codes read the same as before the revert. The partition used again ran: its memory unmapped and mapped
  again, a new vCPU, a run to the `OUT`. A second partition made after the revert is refused at
  `WHvSetupPartition` (`0x80070005`; `WHvCreatePartition` returns `S_OK`). Its control, `jail-as-now-p` (the jail's
  token as now), matched it line for line but there: its second partition was set up.
- What the partition costs, made before the revert: the register probe about 4.4 ms and the partition 1.4 ms (4.7
  and 1.4 in the control); the process's private memory 8 KiB more; the Job's peak 192 KiB more for a moment (the
  probe's partition); 64 MiB of guest memory charged to the Job as before (66796 KiB).
- **The jail's SID alone reaches 9 devices** on this host, each by a name beneath it and none with
  `FILE_DEVICE_SECURE_OPEN`: `\Ntfs`, `\Fat`, `\FatCdrom`, `RawDisk`, `RawCdRom`, `RawTape`, `MQAC`,
  `LanmanDatagramReceiver` and `Afd`; no ALPC port, pipe, section, event or key. Under P it holds besides the
  partition's handles to `\Device\VidExo` (`0x120089`), opened under the initial token; neither device opens again
  after the revert (`0xC0000022`). Which of VID's I/O controls that handle reaches beyond WHP's calls is not measured,
  as for an LPAC holding `VidExo`.
- `lpac-cap-preload` printed no line before `0xC00000A5`: an LPAC cannot be given the jailer's initial token, so it
  cannot run the preload (the reading of the record; Microsoft does not document it).
- The 1314 of `jail-labelled-dir-create` comes from the directory's label: the jail's directory carries
  `S:AI(ML;OICI;NWNRNX;;;S-1-16-6144)`, and a low-integrity AppContainer making a file there would give it an
  inherited label above its own level, which needs `SeRelabelPrivilege` (Microsoft Learn, Mandatory Integrity
  Control). Under Q the jail's directory would have to be labelled low.
- `appcontainer-other` is refused the first AppContainer's directory and socket (5, 10013); it reaches 6 devices,
  137 ALPC ports and 97 sections.
- **Decision: option P for Firecracker, and the jail's SID alone, with the preload, for the API process.** P reaches
  the least (no ALPC port, pipe or section), keeps the jail's 0x1800 label and the `low` stage, needs no
  AppContainer profile, and its preload is measured to work. The LPAC reaches 4 devices, but needs 46 to 48 ALPC
  ports for Winsock (with `registryRead` and `lpacCom`; with neither it has no Winsock at all, 10093), a jail
  labelled low, and cannot take the initial token, so not the preload: the Q table above is kept as the measured
  reason it is closed. TCP still connects through `Afd` under P; `--netns` stays the control for IP (the
  AppContainer-network item of Phase 4, open).

**What does not work.**
- `CreateRestrictedToken` refuses ALL APPLICATION PACKAGES (`S-1-15-2-1`), ALL RESTRICTED APPLICATION PACKAGES
  (`S-1-15-2-2`) and the `hypervisorPlatform` capability SID as restricting SIDs with `ERROR_INVALID_PARAMETER` (87)
  (`fs-probe jail-variants`, `fs-probe whp-token`). Microsoft's page does not document that limit; it is measured.
- An AppContainer without the `hypervisorPlatform` capability: WHP refuses it (`E_ACCESSDENIED`).
- A Job Object, the mitigation policies and WFP have no control over devices, I/O controls or RPC. The system's
  device security descriptors are the host's, not wick's to change.

**What stays after the fix.**
- The 13 device namespaces above (9 on Windows Server 2025 build 26100, the fourth record), with `\Device\Afd`
  carrying IP when `--netns` is not given.
- WHP, the counterpart of `/dev/kvm`: under option P the partition's handle to `\Device\VidExo` only (neither
  device opens after the revert); under option Q `\Device\VidExo` through the capability, with what an
  AppContainer is granted besides.
- Objects that have no DACL at all.
- No list of allowed I/O-control numbers. Windows offers none to a user-mode process.

**The plan, in order:**
1. On a host without Hyper-V: a jailer with the jail's SID as the only restricting SID (an experiment, not
   shipped), running Firecracker itself. The API process runs whole and the VMM up to its first WHP call; every late
   load and registry read that fails is recorded, which gives the list to preload.
2. With WHP (CI's Windows runner, else a PC): the same through a boot, snapshot, network, vsock and block devices,
   and WHP's devices and their security.
   Option P's partition, made before the revert: kvm-ioctls parks it (crates/compat/kvm-ioctls/src/whp/park.rs,
   `park_partition`), with the register probe; the VM takes it. A VM dropped gives it back for a start tried again,
   as upstream lets a failed `InstanceStart` be tried again in the same process: its vCPUs deleted, its memory
   unmapped, partition time running, the four properties settable after set-up written back. Then every property
   and the mapped-page counters are read back and compared with the partition as parked; a difference or a failed
   step deletes it, and the process's next VM is an error that says to start it again. A second VM while the first
   has the partition is that error too. A jailed Firecracker parks in `jail::enter` before the revert, in the VMM
   process only, a failure ending the start, named; without a jail it parks when it takes its API socket. Tests:
   `jailer-test.ps1 restart` and `boot-test.ps1 restart` (a start with a file that is not a kernel, failing after
   its VM is made, then one with the kernel in the same Firecracker), and
   `test_a_recycled_partition_is_as_a_fresh_one` in CI's WHP step, alone in its process: a partition given back
   after a VM that ran a guest (an interrupt taken, dirty pages tracked, its memory unmapped and mapped again),
   compared with a fresh one by every property, the mapped pages, vCPUs 0 and 1 as made (every KVM getter, the MSRs
   but three running counters, InterruptControllerState2, the pending interruption, event and activity state) and
   a read of the old memory (first run: CI). Upstream makes a second VM in one process only so, a failed
   `InstanceStart` before its vCPUs start: a failed snapshot load ends the process, and a VM whose vCPUs started
   lives as long as the process; no second VM follows one that ran guest code, so this comparison is the stricter
   test. The two `restart` stages' first run on CI failed on the second guest's serial input, not
   on the partition: both guests reached their shells, which never saw a line, and both Firecrackers logged
   "Failed to register serial input fd: event_manager: file descriptor has already been registered". That is
   upstream's code on every host: `DeviceManager::new`, before `load_kernel`, adds the serial device to the event
   manager with stdin (`device_manager/mod.rs` `setup_serial_device`), the failed start leaves it there, and the
   second's add of stdin is event-manager's `FdAlreadyRegistered`, which upstream only logs
   (`devices/legacy/serial.rs`); the first start's device takes the input. Upstream's tests try a start again only
   after one that failed before the serial device is made (`test_api_machine_config`, at the memory) and read no
   input after it: not tested upstream. The stages now assert that warning as the cause and check the second guest
   without input: `smp` brought up 2 CPUs, init and its shell started, its clock from init to its restart against
   the host's across 3 s idle, and SendCtrlAltDel (the i8042's interrupt reaching the guest, the kernel's restart)
   ending Firecracker with 0 (first run: CI). What WHP does not expose (the hypervisor's translation caches and
   objects of its own) cannot be compared: a parked partition is only ever used again by the same process, for the
   same jail, guest images, devices and principal, and never handed to another process or jail, so that is an
   unknown of correctness, not of isolation.
3. The jailer change, and a stage of `tools/windows/jailer-test.ps1` that fails when the jailed token opens a device
   outside an explicit list, any ALPC port or service pipe, or can make a pipe or a mailslot. Every jailer-test
   configuration is run again. Before it, the stages whose controls read a file outside the jail read one the
   operator gave the jail's SID alone (`isolation`, `links`: jailer-test.ps1's `Invoke-JailedWithGrant`), not
   one every process may read, so that they hold under both tokens; `isolation` records the read of
   `C:\Windows\win.ini` without asserting it; `nofile`'s probe opens a file of its own in its root, not `NUL`, a
   device the jail's SID alone did not open in the fourth record. Checked in the code and holding under both already: `handoff` (the
   file the jailed process holds is in its root), `netns` (each jail's directory of the network grants its SID, the
   network directory is crossed by the traversal privilege the jail keeps), `shared`, `restart` and `bindlink`
   (a file hard-linked into the root gets an entry for the jail's SID from the jailer); every other stage hands the
   jail only paths in its root.
4. This page and SECURITY.md updated with the commit that fixes it and the numbers measured again.

## Not measured yet

- Anything a host with Hyper-V adds to the lists above (this host has no Hyper-V); WHP's devices are measured
  above, on CI's runner.
- A desktop Windows 10 or 11, whose services and drivers differ: rerun `list-objects` and `devjail` there, or
  `jailer-test.ps1 -Stage reach`.
- What the I/O controls of each reached driver accept beyond the undefined one. No driver's or service's own checks
  were attacked.
