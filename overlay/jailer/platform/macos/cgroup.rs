// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS backend of upstream's `cgroup` module: the same builder and
//! configuration types, macOS limits behind them.
//!
//! A Firecracker process is alone in its cgroup, so a cgroup limit is a limit
//! on that process. The memory controller's limit (`memory.max` in v2,
//! `memory.limit_in_bytes` in v1) becomes a jetsam limit set at exec: the
//! process is killed when its footprint (guest memory included) reaches it,
//! as the cgroup's OOM killer does. The CPU controller's bandwidth limit
//! (`cpu.max` in v2, `cpu.cfs_quota_us` and `cpu.cfs_period_us` in v1)
//! becomes a CPU limit on the whole process (all its threads), which
//! Firecracker applies to itself when it takes the jail over (an exec starts a
//! new task, which drops the limit; see `vmm::ext::jail`). The kernel then
//! blocks the process's threads once they used their share of each second,
//! as CFS throttles a cgroup once it used its quota of each period.
//! `cpuset.cpus` and `cpuset.mems` naming every CPU and memory node are no
//! restriction, on macOS as on Linux, and so is a limit macOS does not have
//! set to the kernel's word for no limit (`pids.max=max`, `memory.high=max`,
//! `hugetlb.2MB.max=max`, ...: [`no_limit`]). The freezer is upstream's files next to
//! the jail, kept by a supervisor process (`platform::freezer`); as on Linux,
//! `freezer.state=FROZEN|THAWED` is the one freezer value taken at the start
//! (v1: the jailer stops at this step until thawed), and `cgroup.*` is
//! refused as upstream refuses it, `cgroup` being no controller. Every other
//! controller and property is refused with its reason ([`refusal`]), never
//! accepted without effect. macOS has no cgroup hierarchy, so the v2
//! hierarchy is an empty directory: there is no parent cgroup to join. A
//! `--parent-cgroup` the operator names is refused ([`refuse_named_parent`]):
//! on Linux it bounds a group of jails together, and macOS has no limit on
//! several processes together that the jailer could make
//! ([`PARENT_IMPOSSIBLE`]). Upstream's default parent, the exec file's name,
//! is accepted and places nothing, as on Linux when no such parent was made
//! beforehand.

use std::path::{Path, PathBuf};

use crate::JailerError;
use crate::platform::{self, FreezerState, FreezerVersion, HostError, freezer_values};

/// Why a `--parent-cgroup` on the command line is refused. It opens and
/// ends as Windows's text does, so the two hosts refuse alike; the middle is
/// macOS's. XNU (apple-oss-distributions/xnu): the one kernel object that
/// groups processes for resource accounting is a coalition. Its ledger has
/// one entry, logical writes (osfmk/kern/coalition.c
/// `init_coalition_ledgers`), whose I/O monitor is its only limit
/// (bsd/kern/sys_coalition.c `coalition_ledger`); memory and CPU time are
/// summed for reports only (`coalition_resource_usage`). And only a process
/// of a privileged coalition, launchd's, makes one or spawns into one, root
/// or not (`coalition()`: `task_is_in_privileged_coalition`, else `EPERM`;
/// bsd/kern/kern_exec.c, the spawn attribute's coalition). A jetsam limit
/// and a CPU limit are one process's (the limits this file sets).
pub(crate) const PARENT_IMPOSSIBLE: &str = "impossible: a parent cgroup that bounds a group of \
    jails would be a kernel limit on several processes together, which macOS does not have: a \
    coalition, its one grouping of processes, limits neither memory nor CPU and is made by launchd \
    alone, and a jetsam or CPU limit is one process's; leave --parent-cgroup out, and each jail's \
    own --cgroup limits still apply";

/// Refuses a `--parent-cgroup` named on the jailer's command line (`args`,
/// the program first; Firecracker's arguments, after `--`, are not the
/// jailer's). Upstream reads the parent only where the builder is made: with
/// `--cgroup`, or with `--cgroup-version 2` and no `--cgroup` (env.rs), so
/// this runs there; with v1 and no `--cgroup` upstream ignores the parent,
/// and so does macOS. The flag cannot be refused by its value: upstream
/// defaults it to the exec file's name, so every start has one, and the
/// default is accepted. No value can be `--parent-cgroup`: upstream's parser
/// takes no value that starts with `--`.
fn refuse_named_parent<S: AsRef<std::ffi::OsStr>>(args: impl IntoIterator<Item = S>) -> Result<(), JailerError> {
    let named = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .skip(1)
        .take_while(|a| a != "--")
        .any(|a| a == "--parent-cgroup");
    if named {
        return Err(HostError::Unsupported("parent-cgroup", PARENT_IMPOSSIBLE).into());
    }
    Ok(())
}

/// The (empty) cgroup v2 hierarchy on macOS.
const NO_HIERARCHY: &str = "/var/empty";

/// CFS's default period, in microseconds.
const DEFAULT_PERIOD_US: u64 = 100_000;
/// The largest CPU limit macOS enforces, in percent of one CPU.
const MAX_CPU_PERCENT: u64 = 255;

#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    version: u8,
    hierarchy: PathBuf,
    memory_limit_mib: Option<i32>,
    cpu: CpuBandwidth,
    freezer: Option<FreezerState>,
}

/// The CPU bandwidth asked for: quota and period in microseconds, as given.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CpuBandwidth {
    /// `None`: no limit (`max`, `-1`, or not given).
    quota_us: Option<u64>,
    /// `None`: CFS's default.
    period_us: Option<u64>,
}

impl CgroupConfigurationBuilder {
    pub fn new(ver: u8, _proc_mounts_path: &str) -> Result<Self, JailerError> {
        refuse_named_parent(std::env::args_os())?;
        match ver {
            1 | 2 => {
                platform::set_cgroup_version(if ver == 1 { FreezerVersion::V1 } else { FreezerVersion::V2 });
                Ok(CgroupConfigurationBuilder {
                    version: ver,
                    hierarchy: PathBuf::from(NO_HIERARCHY),
                    memory_limit_mib: None,
                    cpu: CpuBandwidth::default(),
                    freezer: None,
                })
            }
            _ => Err(JailerError::CgroupInvalidVersion(ver.to_string())),
        }
    }

    pub fn add_cgroup_property(
        &mut self,
        file: String,
        value: String,
        _id: &str,
        _parent_cg: &Path,
    ) -> Result<(), JailerError> {
        let controller = file.split_once('.').map_or(file.as_str(), |(c, _)| c);
        match (self.version, file.as_str()) {
            // `cgroup` is no controller: upstream finds no hierarchy (v1) or
            // no entry in cgroup.controllers (v2) for it.
            _ if controller == "cgroup" => {
                return Err(JailerError::CgroupControllerUnavailable(controller.to_owned()));
            }
            // v2 has no devices controller, and no freezer controller (its
            // freezer is cgroup.freeze): upstream's error.
            (2, _) if controller == "devices" || controller == "freezer" => {
                return Err(JailerError::CgroupControllerUnavailable(controller.to_owned()));
            }
            (1, "freezer.state") => {
                self.freezer = Some(platform::parse_freezer_start(&value).ok_or_else(|| {
                    HostError::CgroupValue(format!("{file}={value}"), freezer_values::STATE_VALUES)
                })?);
            }
            (1, _) if controller == "freezer" => {
                return Err(HostError::CgroupValue(format!("{file}={value}"), freezer_values::READ_ONLY).into());
            }
            (2, "cpu.max") => self.cpu = cpu_max(&file, &value)?,
            (1, "cpu.cfs_quota_us") => self.cpu.quota_us = cfs_quota(&file, &value)?,
            (1, "cpu.cfs_period_us") => self.cpu.period_us = Some(period(&file, &value)?),
            (_, "cpuset.cpus") => cpuset(&file, &value, host_cpus(), CPUS_ONLY_ALL)?,
            (_, "cpuset.mems") => cpuset(&file, &value, MEMORY_NODES, MEMS_ONLY_ALL)?,
            // A limit macOS does not have, set to no limit: nothing to hold.
            (version, f) if no_limit(version, f, &value) => {}
            (_, f) if hugetlb_size(f).is_some_and(|size| !HUGETLB_SIZES.contains(&size)) => {
                return Err(HostError::UnsupportedCgroup(format!("{file}={value}"), NO_SUCH_HUGETLB_SIZE).into());
            }
            _ => self.memory_limit_mib = memory_limit(self.version, &file, &value)?,
        }
        Ok(())
    }

    pub fn build(self) -> CgroupConfiguration {
        CgroupConfiguration {
            memory_limit_mib: self.memory_limit_mib,
            cpu: self.cpu,
            freezer: self.freezer,
        }
    }

    pub fn get_v2_hierarchy_path(&self) -> Result<&PathBuf, JailerError> {
        match self.version {
            2 => Ok(&self.hierarchy),
            _ => Err(JailerError::CgroupHierarchyMissing("2".to_string())),
        }
    }
}

#[derive(Debug)]
pub struct CgroupConfiguration {
    memory_limit_mib: Option<i32>,
    cpu: CpuBandwidth,
    freezer: Option<FreezerState>,
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        // Checked here, once both v1 properties are known.
        let cpu_percent = cpu_percent(self.cpu)?;
        platform::set_memory_limit_mib(self.memory_limit_mib);
        platform::set_cpu_limit_percent(cpu_percent);
        // Last, as Linux attaches the jailer to its cgroups after writing
        // every property: FROZEN stops the jailer here.
        if let Some(state) = self.freezer {
            platform::freezer_at_cgroup_step(state)?;
        }
        Ok(())
    }
}

/// `cpu.max`: `<quota|max> [<period>]`, in microseconds.
fn cpu_max(file: &str, value: &str) -> Result<CpuBandwidth, JailerError> {
    let cg = || format!("{file}={value}");
    let mut parts = value.split_whitespace();
    let quota = parts.next().ok_or_else(|| HostError::CgroupValue(cg(), "empty"))?;
    let period_us = parts.next().map(|p| period(file, p)).transpose()?;
    if parts.next().is_some() {
        return Err(HostError::CgroupValue(cg(), "expected <quota|max> [<period>]").into());
    }
    let quota_us = match quota {
        "max" => None,
        q => Some(quota_us(&cg(), q)?),
    };
    Ok(CpuBandwidth { quota_us, period_us })
}

/// `cpu.cfs_quota_us`: microseconds, or -1 for no limit.
fn cfs_quota(file: &str, value: &str) -> Result<Option<u64>, JailerError> {
    match value {
        "-1" => Ok(None),
        q => Ok(Some(quota_us(&format!("{file}={value}"), q)?)),
    }
}

fn quota_us(cg: &str, value: &str) -> Result<u64, JailerError> {
    let quota: u64 = value
        .parse()
        .map_err(|_| HostError::CgroupValue(cg.to_owned(), "not a number of microseconds"))?;
    // The kernel's bounds for a quota.
    if quota < 1000 {
        return Err(HostError::CgroupValue(cg.to_owned(), "quota below 1000 microseconds").into());
    }
    Ok(quota)
}

fn period(file: &str, value: &str) -> Result<u64, JailerError> {
    let cg = || format!("{file}={value}");
    let period: u64 = value
        .parse()
        .map_err(|_| HostError::CgroupValue(cg(), "not a number of microseconds"))?;
    // The kernel's bounds for a period.
    if !(1000..=1_000_000).contains(&period) {
        return Err(HostError::CgroupValue(cg(), "period outside 1000 to 1000000 microseconds").into());
    }
    Ok(period)
}

/// The CPU limit in percent of one CPU (`None`: no limit). macOS refills the
/// budget once per second rather than once per period (at most a second), so
/// the share of CPU time is the same, in bursts of up to a second.
fn cpu_percent(cpu: CpuBandwidth) -> Result<Option<u8>, JailerError> {
    let Some(quota) = cpu.quota_us else {
        return Ok(None);
    };
    let period = cpu.period_us.unwrap_or(DEFAULT_PERIOD_US);
    let cg = || format!("cpu quota {quota} us per {period} us");
    // Whole percents: rounding down keeps the limit at or below the one asked for.
    let percent = quota.saturating_mul(100) / period;
    if percent == 0 {
        return Err(HostError::CgroupValue(cg(), "below 1% of one CPU, the finest macOS limit").into());
    }
    if percent > MAX_CPU_PERCENT {
        return Err(HostError::CgroupValue(
            cg(),
            "above 255% of one CPU (2.55 CPUs), the largest limit macOS enforces",
        )
        .into());
    }
    Ok(Some(u8::try_from(percent).expect("at most 255")))
}

/// The memory limit in MiB that `<file>=<value>` sets (`None`: no limit).
fn memory_limit(version: u8, file: &str, value: &str) -> Result<Option<i32>, JailerError> {
    let cg = || format!("{file}={value}");
    let unlimited = match (version, file) {
        (2, "memory.max") => value == "max",
        (1, "memory.limit_in_bytes") => value == "-1",
        _ => return Err(HostError::UnsupportedCgroup(cg(), refusal(file)).into()),
    };
    if unlimited {
        return Ok(None);
    }
    let bytes: u64 = value
        .parse()
        .map_err(|_| HostError::CgroupValue(cg(), "not a number of bytes"))?;
    // Jetsam limits are whole MiB; rounding down keeps the limit at or below
    // the one asked for.
    let mib = bytes >> 20;
    if mib == 0 {
        return Err(HostError::CgroupValue(cg(), "below the 1 MiB granularity").into());
    }
    let mib = i32::try_from(mib)
        .map_err(|_| HostError::CgroupValue(cg(), "above the largest jetsam limit"))?;
    Ok(Some(mib))
}

/// The huge page sizes of an aarch64 Linux host with 4 KiB pages, as the
/// hugetlb controller names them in its files (`hugetlb.<size>.max`): Linux
/// arch/arm64/mm/hugetlbpage.c `hugetlbpage_init` adds PUD_SIZE (1 GiB),
/// CONT_PMD_SIZE (32 MiB), PMD_SIZE (2 MiB) and CONT_PTE_SIZE (64 KiB), and
/// mm/hugetlb_cgroup.c `mem_fmt` writes them `1GB`, `32MB`, `2MB`, `64KB`.
/// A size the host does not have has no file, and upstream's jailer fails
/// writing it.
const HUGETLB_SIZES: [&str; 4] = ["64KB", "2MB", "32MB", "1GB"];
const NO_SUCH_HUGETLB_SIZE: &str = "an aarch64 Linux host with 4 KiB pages has huge pages of 64KB, 2MB, 32MB \
    and 1GB only, so the hugetlb controller has no file of this size there either";

/// The `<size>` of a hugetlb controller file, `hugetlb.<size>.<rest>`.
fn hugetlb_size(file: &str) -> Option<&str> {
    file.strip_prefix("hugetlb.")?.split_once('.').map(|(size, _)| size)
}

/// Whether `<file>=<value>` sets a limit macOS does not have to no limit:
/// valid on Linux, where it restricts nothing, so accepted here, where
/// nothing is to be held (as `cpuset.cpus` naming every CPU is). The files
/// are the ones whose kernel handler takes a word for "no limit", with that
/// word (Linux v6.1; the same in v6.12):
/// - v2, `max`: `memory.high`, `memory.swap.max`, `memory.swap.high`,
///   `memory.zswap.max` (mm/memcontrol.c `memory_high_write`,
///   `swap_max_write`, `swap_high_write`, `zswap_max_write`:
///   `page_counter_memparse(buf, "max", ..)`); `hugetlb.<size>.max` and
///   `hugetlb.<size>.rsvd.max` (mm/hugetlb_cgroup.c
///   `hugetlb_cgroup_write_dfl`);
/// - v1, `-1`: `memory.memsw.limit_in_bytes`, `memory.soft_limit_in_bytes`,
///   `memory.kmem.tcp.limit_in_bytes` (mm/memcontrol.c `mem_cgroup_write`:
///   `page_counter_memparse(buf, "-1", ..)`; the last also switches the
///   cgroup's TCP memory accounting on, `memcg_update_tcp_max`, which has no
///   counterpart here and limits nothing); `hugetlb.<size>.limit_in_bytes`
///   and `hugetlb.<size>.rsvd.limit_in_bytes` (`hugetlb_cgroup_write_legacy`);
/// - both, `max`: `pids.max` (kernel/cgroup/pids.c `pids_max_write`).
///
/// Each handler strips the value's white space first (`strstrip`), so this
/// does. Not here, and so refused as before:
/// - a number, also one so large that the kernel would clamp it to no limit;
/// - `memory.min` and `memory.low`, which are protections, not limits: their
///   `max` is the largest protection, and their default, 0, is not a "no
///   limit" a handler knows;
/// - `memory.kmem.limit_in_bytes`, whose write fails in v6.1 (`-EOPNOTSUPP`)
///   and does nothing in v6.12;
/// - a hugetlb size an aarch64 host does not have ([`HUGETLB_SIZES`]).
fn no_limit(version: u8, file: &str, value: &str) -> bool {
    // The kernel's isspace(): space, \t, \n, \v, \f, \r.
    let value = value.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let word = match (version, file) {
        (_, "pids.max") => "max",
        (2, "memory.high" | "memory.swap.max" | "memory.swap.high" | "memory.zswap.max") => "max",
        (1, "memory.memsw.limit_in_bytes" | "memory.soft_limit_in_bytes" | "memory.kmem.tcp.limit_in_bytes") => "-1",
        _ => {
            let Some(size) = hugetlb_size(file).filter(|size| HUGETLB_SIZES.contains(size)) else {
                return false;
            };
            let rest = &file["hugetlb.".len() + size.len() + 1..];
            match (version, rest) {
                (2, "max" | "rsvd.max") => "max",
                (1, "limit_in_bytes" | "rsvd.limit_in_bytes") => "-1",
                _ => return false,
            }
        }
    };
    value == word
}

/// Memory nodes: Apple silicon's memory is one node (no NUMA).
const MEMORY_NODES: u32 = 1;
const CPUS_ONLY_ALL: &str = "Apple silicon has no CPU affinity: the kernel binds no thread to a CPU \
    (thread_policy_set with THREAD_AFFINITY_POLICY returns KERN_NOT_SUPPORTED), so only every CPU can be named";
const MEMS_ONLY_ALL: &str = "Apple silicon has one memory node, 0";

/// The host's CPUs (`hw.logicalcpu_max`).
fn host_cpus() -> u32 {
    let mut n: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: a NUL-terminated name and an int-sized output buffer.
    let ret = unsafe {
        libc::sysctlbyname(
            c"hw.logicalcpu_max".as_ptr(),
            (&raw mut n).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(ret, 0, "hw.logicalcpu_max: {}", std::io::Error::last_os_error());
    u32::try_from(n).expect("a positive CPU count")
}

/// `cpuset.cpus` and `cpuset.mems`: a list (`0-3,5`) of the host's `count`
/// CPUs or memory nodes. Naming every one is no restriction, which macOS
/// holds as Linux does; naming one the host does not have fails, as writing
/// the file does on Linux; a subset is refused with its reason (`only_all`).
fn cpuset(file: &str, value: &str, count: u32, only_all: &'static str) -> Result<(), JailerError> {
    let cg = || format!("{file}={value}");
    let mut named = vec![false; count as usize];
    for part in value.trim().split(',') {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) else {
            return Err(HostError::CgroupValue(cg(), "expected a list such as 0-3,5").into());
        };
        if lo > hi || hi >= count {
            return Err(HostError::CgroupValue(cg(), "names one the host does not have").into());
        }
        for i in lo..=hi {
            named[i as usize] = true;
        }
    }
    if named.iter().all(|&n| n) {
        Ok(())
    } else {
        Err(HostError::UnsupportedCgroup(cg(), only_all).into())
    }
}

/// Why macOS cannot enforce the cgroup file `file`.
fn refusal(file: &str) -> &'static str {
    let controller = file.split_once('.').map_or(file, |(c, _)| c);
    match (controller, file) {
        (_, "memory.max" | "memory.limit_in_bytes") => {
            "this cgroup version names the memory limit differently"
        }
        (_, "cpu.max" | "cpu.cfs_quota_us" | "cpu.cfs_period_us") => {
            "this cgroup version names the CPU limit differently"
        }
        (_, "cpu.weight" | "cpu.weight.nice" | "cpu.shares" | "cpu.idle") => {
            "macOS schedules threads by priority and has no proportional share of CPU time between \
             groups of processes"
        }
        (_, "cpu.uclamp.min" | "cpu.uclamp.max") => "macOS has no utilisation clamping",
        ("memory", _) => {
            "jetsam, macOS's memory limit, is a hard limit only (memory.max): there is no reclaim \
             threshold, protection or per-process swap limit, so of the other memory limits only \
             their \"no limit\" is accepted (max; -1 in cgroup v1)"
        }
        ("pids", _) => {
            "macOS has no limit on a process's threads (Firecracker can make no process: its sandbox \
             denies fork and posix_spawn), so only pids.max=max, no limit, is accepted"
        }
        ("io" | "blkio", _) => {
            "macOS has no per-process I/O bandwidth, operation or weight limit, only I/O priority \
             tiers (setiopolicy_np)"
        }
        ("hugetlb", _) => {
            "macOS has no hugetlb page pool (docs/PORTING.md row 10), so only \"no limit\" is accepted \
             (max; -1 in cgroup v1)"
        }
        ("cpuset", _) => "only cpuset.cpus and cpuset.mems have a macOS counterpart",
        ("devices", _) => {
            "upstream's jailer cannot set it on Linux either: it first reads the parent cgroup's file, and \
             devices.allow and devices.deny are write-only (EINVAL), devices.list read-only"
        }
        _ => "no macOS counterpart",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(version: u8, props: &[&str]) -> Result<Option<i32>, JailerError> {
        let mut b = CgroupConfigurationBuilder::new(version, "/proc/mounts")?;
        for p in props {
            let (f, v) = p.split_once('=').unwrap();
            b.add_cgroup_property(f.into(), v.into(), "id", Path::new("fc"))?;
        }
        Ok(b.build().memory_limit_mib)
    }

    #[test]
    fn test_memory_limit() {
        assert_eq!(limit(2, &["memory.max=536870912"]).unwrap(), Some(512));
        assert_eq!(limit(1, &["memory.limit_in_bytes=1610612735"]).unwrap(), Some(1535));
        assert_eq!(limit(2, &["memory.max=max"]).unwrap(), None);
        assert_eq!(limit(1, &["memory.limit_in_bytes=-1"]).unwrap(), None);
        for bad in ["memory.limit_in_bytes=1000", "memory.limit_in_bytes=x"] {
            assert!(matches!(limit(1, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))));
        }
    }

    fn cpu(version: u8, props: &[&str]) -> Result<Option<u8>, JailerError> {
        let mut b = CgroupConfigurationBuilder::new(version, "/proc/mounts")?;
        for p in props {
            let (f, v) = p.split_once('=').unwrap();
            b.add_cgroup_property(f.into(), v.into(), "id", Path::new("fc"))?;
        }
        cpu_percent(b.build().cpu)
    }

    #[test]
    fn test_cpu_limit() {
        assert_eq!(cpu(2, &["cpu.max=50000 100000"]).unwrap(), Some(50));
        assert_eq!(cpu(2, &["cpu.max=25000"]).unwrap(), Some(25));
        assert_eq!(cpu(2, &["cpu.max=200000 100000"]).unwrap(), Some(200));
        assert_eq!(cpu(2, &["cpu.max=33333 100000"]).unwrap(), Some(33));
        assert_eq!(cpu(2, &["cpu.max=1000 1000"]).unwrap(), Some(100));
        assert_eq!(cpu(2, &["cpu.max=max"]).unwrap(), None);
        assert_eq!(cpu(2, &["cpu.max=max 100000"]).unwrap(), None);
        assert_eq!(cpu(2, &[]).unwrap(), None);
        // v1: either order, the period defaulting to CFS's.
        assert_eq!(cpu(1, &["cpu.cfs_quota_us=150000", "cpu.cfs_period_us=200000"]).unwrap(), Some(75));
        assert_eq!(cpu(1, &["cpu.cfs_period_us=200000", "cpu.cfs_quota_us=150000"]).unwrap(), Some(75));
        assert_eq!(cpu(1, &["cpu.cfs_quota_us=20000"]).unwrap(), Some(20));
        assert_eq!(cpu(1, &["cpu.cfs_quota_us=-1"]).unwrap(), None);
        assert_eq!(cpu(1, &["cpu.cfs_period_us=50000"]).unwrap(), None);
        // A limit macOS cannot enforce exactly is refused, never loosened.
        for bad in [
            "cpu.max=1000 1000000",
            "cpu.max=256000 100000",
            "cpu.max=999 100000",
            "cpu.max=50000 999",
            "cpu.max=50000 1000001",
            "cpu.max=",
            "cpu.max=x",
            "cpu.max=50000 100000 1",
            "cpu.max=-1",
        ] {
            assert!(
                matches!(cpu(2, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))),
                "{bad}"
            );
        }
        assert!(matches!(
            cpu(1, &["cpu.cfs_quota_us=300000"]).unwrap_err(),
            JailerError::Host(HostError::CgroupValue(..))
        ));
    }

    // Each controller macOS cannot enforce is refused with its reason.
    #[test]
    fn test_other_controllers_are_refused() {
        for (v, p, why) in [
            (1, "cpuset.cpus=0", "no CPU affinity"),
            (2, "cpuset.cpus=0", "no CPU affinity"),
            (1, "cpu.shares=10", "no proportional share"),
            (2, "cpu.weight=10", "no proportional share"),
            (2, "cpu.weight.nice=5", "no proportional share"),
            (2, "cpu.idle=1", "no proportional share"),
            (2, "cpu.uclamp.max=50", "no utilisation clamping"),
            (1, "cpu.max=50000 100000", "names the CPU limit differently"),
            (2, "cpu.cfs_quota_us=50000", "names the CPU limit differently"),
            (2, "memory.limit_in_bytes=1048576", "names the memory limit differently"),
            (1, "memory.max=1048576", "names the memory limit differently"),
            (2, "memory.high=1048576", "hard limit only"),
            (2, "memory.low=1048576", "hard limit only"),
            (2, "memory.swap.max=0", "hard limit only"),
            (1, "memory.memsw.limit_in_bytes=1048576", "hard limit only"),
            (2, "pids.max=10", "no limit on a process's threads"),
            (2, "io.max=8:0 rbps=1048576", "no per-process I/O"),
            (2, "io.weight=100", "no per-process I/O"),
            (1, "blkio.weight=100", "no per-process I/O"),
            (2, "hugetlb.2MB.max=0", "no hugetlb page pool"),
            (2, "cpuset.cpus.exclusive=0", "only cpuset.cpus and cpuset.mems"),
            (2, "rdma.max=x", "no macOS counterpart"),
            (1, "devices.deny=a", "cannot set it on Linux either"),
            (1, "devices.allow=c 1:3 rwm", "devices.allow and devices.deny are write-only"),
            (1, "devices.list=a *:* rwm", "devices.list read-only"),
        ] {
            let err = limit(v, &[p]).unwrap_err();
            assert!(matches!(err, JailerError::Host(HostError::UnsupportedCgroup(..))), "{p}: {err}");
            assert!(err.to_string().contains(why), "{p}: {err}");
        }
        // v2: no devices controller, upstream's own error.
        for p in ["devices.deny=a", "devices.allow=c 1:3 rwm"] {
            assert_eq!(limit(2, &[p]).unwrap_err().to_string(), "Controller devices is unavailable", "{p}");
        }
        assert!(matches!(
            CgroupConfigurationBuilder::new(3, "").unwrap_err(),
            JailerError::CgroupInvalidVersion(_)
        ));
    }

    // A limit macOS does not have, at the kernel's word for "no limit": valid
    // on Linux and no restriction there, so accepted, and nothing is set.
    #[test]
    fn test_no_limit_values_are_accepted() {
        for (v, p) in [
            (2, "pids.max=max"),
            (1, "pids.max=max"),
            (2, "memory.high=max"),
            (2, "memory.swap.max=max"),
            (2, "memory.swap.high=max"),
            (2, "memory.zswap.max=max"),
            (1, "memory.memsw.limit_in_bytes=-1"),
            (1, "memory.soft_limit_in_bytes=-1"),
            (1, "memory.kmem.tcp.limit_in_bytes=-1"),
            (2, "hugetlb.2MB.max=max"),
            (2, "hugetlb.2MB.rsvd.max=max"),
            (2, "hugetlb.64KB.max=max"),
            (2, "hugetlb.32MB.max=max"),
            (2, "hugetlb.1GB.rsvd.max=max"),
            (1, "hugetlb.2MB.limit_in_bytes=-1"),
            (1, "hugetlb.2MB.rsvd.limit_in_bytes=-1"),
            (1, "hugetlb.1GB.limit_in_bytes=-1"),
            // The kernel strips the value's white space (strstrip).
            (2, "pids.max= max\n"),
            (2, "memory.high=\tmax "),
            (1, "memory.memsw.limit_in_bytes=-1\n"),
        ] {
            let b = builder(v, &[p]).unwrap_or_else(|e| panic!("v{v} {p:?}: {e}")).build();
            assert_eq!((b.memory_limit_mib, b.cpu, b.freezer), (None, CpuBandwidth::default(), None), "v{v} {p:?}");
        }
        // Beside real limits, which stay as given.
        let b = builder(2, &["memory.max=536870912", "memory.high=max", "pids.max=max", "cpu.max=50000 100000"])
            .unwrap()
            .build();
        assert_eq!((b.memory_limit_mib, cpu_percent(b.cpu).unwrap()), (Some(512), Some(50)));
    }

    // The same files with anything that would restrict, the other cgroup
    // version's word or file name, a protection, a file the kernel refuses
    // to write, a huge page size Linux does not have on aarch64: refused,
    // each with its reason.
    #[test]
    fn test_only_no_limit_is_accepted_of_a_limit_macos_lacks() {
        for (v, p, why) in [
            (2, "pids.max=10", "only pids.max=max"),
            (1, "pids.max=0", "only pids.max=max"),
            (2, "pids.max=-1", "only pids.max=max"),
            (2, "pids.max=", "only pids.max=max"),
            (2, "pids.max=MAX", "only pids.max=max"),
            (2, "pids.max=4194304", "only pids.max=max"),
            (2, "pids.current=max", "only pids.max=max"),
            (2, "memory.high=1048576", "hard limit only"),
            (2, "memory.high=-1", "hard limit only"),
            (2, "memory.high=9223372036854775807", "hard limit only"),
            (1, "memory.high=max", "hard limit only"),
            (2, "memory.swap.max=0", "hard limit only"),
            (2, "memory.swap.high=1048576", "hard limit only"),
            (2, "memory.zswap.max=0", "hard limit only"),
            (1, "memory.swap.max=max", "hard limit only"),
            (1, "memory.memsw.limit_in_bytes=1048576", "hard limit only"),
            (1, "memory.memsw.limit_in_bytes=max", "hard limit only"),
            (2, "memory.memsw.limit_in_bytes=-1", "hard limit only"),
            (1, "memory.soft_limit_in_bytes=1048576", "hard limit only"),
            (1, "memory.kmem.tcp.limit_in_bytes=1048576", "hard limit only"),
            // Its write fails on Linux v6.1 (-EOPNOTSUPP).
            (1, "memory.kmem.limit_in_bytes=-1", "hard limit only"),
            // Protections, not limits: 0 is their default, max the largest.
            (2, "memory.min=0", "hard limit only"),
            (2, "memory.low=0", "hard limit only"),
            (2, "memory.min=max", "hard limit only"),
            (2, "memory.low=max", "hard limit only"),
            (2, "hugetlb.2MB.max=0", "no hugetlb page pool"),
            (2, "hugetlb.2MB.max=2097152", "no hugetlb page pool"),
            (2, "hugetlb.2MB.max=-1", "no hugetlb page pool"),
            (1, "hugetlb.2MB.limit_in_bytes=max", "no hugetlb page pool"),
            (1, "hugetlb.2MB.limit_in_bytes=0", "no hugetlb page pool"),
            (1, "hugetlb.2MB.max=max", "no hugetlb page pool"),
            (2, "hugetlb.2MB.limit_in_bytes=-1", "no hugetlb page pool"),
            (2, "hugetlb.2MB.current=max", "no hugetlb page pool"),
            (2, "hugetlb.max=max", "no hugetlb page pool"),
            (2, "hugetlb.16MB.max=max", "64KB, 2MB, 32MB and 1GB only"),
            (2, "hugetlb.2mb.max=max", "64KB, 2MB, 32MB and 1GB only"),
            (2, "hugetlb.512MB.rsvd.max=max", "64KB, 2MB, 32MB and 1GB only"),
            (1, "hugetlb.16GB.limit_in_bytes=-1", "64KB, 2MB, 32MB and 1GB only"),
            (2, "hugetlb.4MB.max=0", "64KB, 2MB, 32MB and 1GB only"),
        ] {
            let err = limit(v, &[p]).unwrap_err();
            assert!(matches!(err, JailerError::Host(HostError::UnsupportedCgroup(..))), "v{v} {p}: {err}");
            assert!(err.to_string().contains(why), "v{v} {p}: {err}");
        }
    }

    // cpuset: every CPU and memory node is no restriction, held as on Linux;
    // one the host does not have fails as on Linux; a subset is refused (no
    // CPU affinity, one memory node).
    #[test]
    fn test_cpuset() {
        let n = host_cpus();
        for v in [1, 2] {
            let all = format!("cpuset.cpus=0-{}", n - 1);
            assert_eq!(limit(v, &[&all, "cpuset.mems=0"]).unwrap(), None);
            let listed: Vec<String> = (0..n).map(|i| i.to_string()).collect();
            limit(v, &[&format!("cpuset.cpus={}", listed.join(","))]).unwrap();
            for bad in [format!("cpuset.cpus=0-{n}"), "cpuset.mems=1".into(), "cpuset.cpus=x".into()] {
                let err = limit(v, &[&bad]).unwrap_err();
                assert!(matches!(err, JailerError::Host(HostError::CgroupValue(..))), "{bad}: {err}");
            }
            let err = limit(v, &["cpuset.cpus=0-1"]).unwrap_err();
            assert!(err.to_string().contains("KERN_NOT_SUPPORTED"), "{err}");
        }
    }

    /// The reason `CPUS_ONLY_ALL` gives, measured: XNU's arm
    /// `ml_get_max_affinity_sets` returns 0 (osfmk/arm/cpu_affinity.h), so
    /// `thread_policy_set` and `thread_policy_get` answer `THREAD_AFFINITY_POLICY`
    /// with `KERN_NOT_SUPPORTED` (osfmk/kern/thread_policy.c).
    #[test]
    fn test_no_cpu_affinity() {
        let mut policy = libc::thread_affinity_policy_data_t { affinity_tag: 1 };
        // SAFETY: the calling thread's own port, which needs no release.
        let thread = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) };
        // SAFETY: a policy of THREAD_AFFINITY_POLICY_COUNT integers.
        let set = unsafe {
            libc::thread_policy_set(
                thread,
                libc::THREAD_AFFINITY_POLICY as libc::thread_policy_flavor_t,
                (&raw mut policy).cast(),
                libc::THREAD_AFFINITY_POLICY_COUNT,
            )
        };
        let mut count = libc::THREAD_AFFINITY_POLICY_COUNT;
        let mut get_default: libc::boolean_t = 0;
        // SAFETY: as above, with the count and flag the call writes.
        let get = unsafe {
            libc::thread_policy_get(
                thread,
                libc::THREAD_AFFINITY_POLICY as libc::thread_policy_flavor_t,
                (&raw mut policy).cast(),
                &mut count,
                &mut get_default,
            )
        };
        assert_eq!((set, get), (libc::KERN_NOT_SUPPORTED, libc::KERN_NOT_SUPPORTED));
    }

    fn builder(version: u8, props: &[&str]) -> Result<CgroupConfigurationBuilder, JailerError> {
        let mut b = CgroupConfigurationBuilder::new(version, "/proc/mounts")?;
        for p in props {
            let (f, v) = p.split_once('=').unwrap();
            b.add_cgroup_property(f.into(), v.into(), "id", Path::new("fc"))?;
        }
        Ok(b)
    }

    // The freezer at the start, as upstream's jailer on Linux: v1
    // freezer.state takes FROZEN or THAWED (the kernel refuses any other
    // value written to it, and the other freezer files are read-only);
    // `cgroup` is no controller, with either version (upstream finds no
    // hierarchy or cgroup.controllers entry for it), so v2's cgroup.freeze is
    // refused at the start; v2 has no freezer controller.
    #[test]
    fn test_freezer_at_the_start() {
        for (p, want) in [("freezer.state=FROZEN", FreezerState::Frozen), ("freezer.state=THAWED", FreezerState::Thawed)] {
            assert_eq!(builder(1, &[p]).unwrap().build().freezer, Some(want), "{p}");
        }
        assert_eq!(builder(1, &["memory.limit_in_bytes=-1"]).unwrap().build().freezer, None);
        for p in ["freezer.state=FREEZING", "freezer.state=", "freezer.state=frozen", "freezer.self_freezing=1"] {
            let err = builder(1, &[p]).unwrap_err();
            assert!(matches!(err, JailerError::Host(HostError::CgroupValue(..))), "{p}: {err}");
        }
        for (v, p, controller) in [
            (2, "cgroup.freeze=1", "cgroup"),
            (2, "cgroup.freeze=0", "cgroup"),
            (2, "cgroup.procs=1", "cgroup"),
            (1, "cgroup.freeze=1", "cgroup"),
            (2, "freezer.state=FROZEN", "freezer"),
        ] {
            let err = builder(v, &[p]).unwrap_err();
            assert_eq!(err.to_string(), format!("Controller {controller} is unavailable"), "v{v} {p}");
        }
    }

    // A parent the operator names is refused, with the reason; the default
    // parent (none named) is accepted; a `--parent-cgroup` among
    // Firecracker's arguments, after `--`, is not the jailer's.
    #[test]
    fn test_parent_cgroup_is_refused() {
        let jailer = ["jailer", "--id", "a", "--exec-file", "firecracker", "--cgroup-version", "2"];
        let with = |extra: &[&'static str]| refuse_named_parent(jailer.iter().chain(extra));
        match with(&["--parent-cgroup", "tenants"]) {
            Err(JailerError::Host(HostError::Unsupported("parent-cgroup", why))) => assert_eq!(why, PARENT_IMPOSSIBLE),
            other => panic!("{other:?}"),
        }
        let text = with(&["--cgroup", "memory.max=1G", "--parent-cgroup", "firecracker"]).unwrap_err().to_string();
        assert!(text.starts_with("--parent-cgroup is not supported on macOS: impossible: a parent cgroup that bounds"), "{text}");
        assert!(text.contains("leave --parent-cgroup out, and each jail's own --cgroup limits still apply"), "{text}");
        with(&[]).unwrap();
        with(&["--cgroup", "memory.max=1G"]).unwrap();
        with(&["--", "--parent-cgroup", "x"]).unwrap();
        // The builder is where it is refused (this process's own arguments
        // name no parent).
        CgroupConfigurationBuilder::new(2, "").unwrap();
    }

    #[test]
    fn test_no_parent_cgroup_to_join() {
        let b = CgroupConfigurationBuilder::new(2, "").unwrap();
        let parent = b.get_v2_hierarchy_path().unwrap().join("firecracker");
        assert!(!parent.exists());
    }
}
