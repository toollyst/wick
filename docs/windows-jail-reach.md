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
- Paths the operator gives Firecracker outside its jail would need to grant the jail's SID.

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
| With the `hypervisorPlatform` capability SID | `CreateRestrictedToken` refuses the SID as a restricting SID (87): not run | | | |
| Jail's SID alone, partition made and set up before the revert | denied | denied | (1 before) | maps, vCPU, run to HLT after the revert |
| As now, partition made before the revert | granted | granted | (1 before) | the same |
| AppContainer, no capability | denied | denied | `E_ACCESSDENIED` | `E_ACCESSDENIED` |
| AppContainer with `hypervisorPlatform` | granted (`0x120089`; most allowed `0x1201bf`) | denied | 1 | every step, HLT |

What it shows:
- **A capability SID cannot be a restricting SID.** `CreateRestrictedToken` refuses it with 87, as it refuses ALL
  APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES (below). Microsoft's page documents no such limit.
- **A restricted token needs both devices.** Each group that opens one of them alone leaves WHP reporting no
  hypervisor: Authenticated Users opens VidExo, Everyone HvService, and neither variant made a partition. Whether the
  two together suffice is the next record's `jail-au-everyone` (and `jail-au-users`).
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

**What does not work.**
- `CreateRestrictedToken` refuses ALL APPLICATION PACKAGES (`S-1-15-2-1`), ALL RESTRICTED APPLICATION PACKAGES
  (`S-1-15-2-2`) and the `hypervisorPlatform` capability SID as restricting SIDs with `ERROR_INVALID_PARAMETER` (87)
  (`fs-probe jail-variants`, `fs-probe whp-token`). Microsoft's page does not document that limit; it is measured.
- An AppContainer without the `hypervisorPlatform` capability: WHP refuses it (`E_ACCESSDENIED`).
- A Job Object, the mitigation policies and WFP have no control over devices, I/O controls or RPC. The system's
  device security descriptors are the host's, not wick's to change.

**What stays after the fix.**
- The 13 device namespaces above, with `\Device\Afd` carrying IP when `--netns` is not given.
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
3. The jailer change, and a stage of `tools/windows/jailer-test.ps1` that fails when the jailed token opens a device
   outside an explicit list, any ALPC port or service pipe, or can make a pipe or a mailslot. Every jailer-test
   configuration is run again.
4. This page and SECURITY.md updated with the commit that fixes it and the numbers measured again.

## Not measured yet

- Anything a host with Hyper-V adds to the lists above (this host has no Hyper-V); WHP's devices are measured
  above, on CI's runner.
- A desktop Windows 10 or 11, whose services and drivers differ: rerun `list-objects` and `devjail` there.
- What the I/O controls of each reached driver accept beyond the undefined one. No driver's or service's own checks
  were attacked.
