// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Windows backend of upstream's `cgroup` module: the same builder and
//! configuration types, a Job Object behind them.
//!
//! A Firecracker process is alone in its cgroup, as it is alone in the job
//! the jailer starts it in (`platform::exec_command`), so a cgroup limit is a
//! job limit:
//!
//! | cgroup v2 | cgroup v1 | Job Object |
//! |---|---|---|
//! | `memory.max` | `memory.limit_in_bytes` | job memory limit (commit; the job's processes fail to allocate past it) |
//! | `cpu.max` (`<quota> [<period>]`) | `cpu.cfs_quota_us`, `cpu.cfs_period_us` | CPU rate hard cap, `quota / period` CPUs of all the host's, from Firecracker's start |
//! | `cpu.weight`, `cpu.weight.nice` | `cpu.shares` | weight-based CPU rate control: the Windows weight (1 to 9) whose share is nearest ([`cpu_weight`]) |
//! | `cpuset.cpus` | `cpuset.cpus` | the job's processor affinity ([`cpu_groups`]) |
//! | `cpuset.mems` | `cpuset.mems` | every memory node of the host: nothing to bind ([`check_mems`]) |
//! | `hugetlb.2MB.max` | `hugetlb.2MB.limit_in_bytes` | the large-page sections the jailer gives Firecracker, in all (`platform::large_pages`) |
//! | `pids.max`, `hugetlb.<size>.max`, `hugetlb.<size>.rsvd.max`, `memory.high`, `memory.swap.max`, `memory.swap.high`, `memory.zswap.max` = `max` | `pids.max` = `max`; `hugetlb.<size>.limit_in_bytes`, `hugetlb.<size>.rsvd.limit_in_bytes`, `memory.memsw.limit_in_bytes`, `memory.soft_limit_in_bytes`, `memory.kmem.tcp.limit_in_bytes` = `-1` | no limit, as on Linux ([`no_limit`]); `<size>` is one an x86_64 Linux has files for ([`linux_hugetlb_size`]) |
//!
//! The CPU rate cap holds from Firecracker's start, as a cgroup's limit
//! holds from the exec. Windows enforces the rate over its own scheduling
//! interval rather than over `period`; the share, `quota / period`, is the
//! same.
//!
//! What Windows cannot do is refused with the reason ([`impossible`]): a
//! limit on threads (`pids.max`), I/O limits per Linux device and per
//! direction (`io`, `blkio`), a large page limit of its own (`hugetlb`),
//! NUMA memory binding (`cpuset.mems` short of every node), exclusive CPUs
//! and the rest. Every other property is refused too, never accepted
//! without effect. Windows has no cgroup hierarchy, so the v2 hierarchy is a
//! path that does not exist, and upstream's own look for the parent's
//! directory there finds none. The parent cgroup is a named Job Object that
//! holds the jails' jobs (`platform::parent`): what the command line says of
//! it is kept where upstream makes this builder, which is where upstream
//! reads the parent (with `--cgroup`, and with `--cgroup-version 2` and no
//! `--cgroup`), and the jail's processes are put in it when they start.
//!
//! The freezer is upstream's files next to the jail, kept by the jailer
//! (`platform::freezer`); as on Linux, `freezer.state=FROZEN|THAWED` is the
//! one freezer value taken at the start (v1: the jailer stops at this step
//! until thawed), and `cgroup.*` is refused as upstream refuses it, `cgroup`
//! being no controller.

use std::path::{Path, PathBuf};

use crate::JailerError;
use crate::platform::cgroup_values::{DEFAULT_PERIOD_US, cpu_groups, cpu_rate, parse_list, strstrip};
use crate::platform::{self, FreezerState, FreezerVersion, HostError, Limits};

/// The (absent) cgroup v2 hierarchy on Windows.
const NO_HIERARCHY: &str = r"\\?\GLOBALROOT\wick-no-cgroup-hierarchy";

#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    version: u8,
    hierarchy: PathBuf,
    limits: Limits,
    /// cgroup v1's quota and period, combined at `build`.
    v1_quota_us: Option<Option<u64>>,
    v1_period_us: Option<u64>,
    /// `freezer.state` (v1) at the start.
    freezer: Option<FreezerState>,
}

impl CgroupConfigurationBuilder {
    pub fn new(ver: u8, _proc_mounts_path: &str) -> Result<Self, JailerError> {
        match ver {
            1 | 2 => {
                // Upstream makes a builder exactly where it reads the
                // parent cgroup (env.rs): the parent is read here too.
                platform::parent::set_plan(ver)?;
                platform::set_cgroup_version(if ver == 1 { FreezerVersion::V1 } else { FreezerVersion::V2 });
                Ok(CgroupConfigurationBuilder {
                    version: ver,
                    hierarchy: PathBuf::from(NO_HIERARCHY),
                    limits: Limits::default(),
                    v1_quota_us: None,
                    v1_period_us: None,
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
        let cg = || format!("{file}={value}");
        let bad = |why| -> JailerError { HostError::CgroupValue(cg(), why).into() };
        let controller = file.split_once('.').map_or(file.as_str(), |(c, _)| c);
        match (self.version, file.as_str()) {
            // `cgroup` is no controller: upstream finds no hierarchy (v1) or
            // no entry in cgroup.controllers (v2) for it.
            _ if controller == "cgroup" => {
                return Err(JailerError::CgroupControllerUnavailable(controller.to_owned()));
            }
            // v2 has no freezer controller (its freezer is cgroup.freeze):
            // upstream's error.
            (2, _) if controller == "freezer" => {
                return Err(JailerError::CgroupControllerUnavailable(controller.to_owned()));
            }
            (1, "freezer.state") => {
                self.freezer = Some(platform::parse_freezer_start(&value).ok_or_else(|| bad(STATE_VALUES))?);
            }
            (1, _) if controller == "freezer" => return Err(bad(READ_ONLY)),
            (2, "memory.max") | (1, "memory.limit_in_bytes") => {
                let value = strstrip(&value);
                let unlimited = if self.version == 2 { value == "max" } else { value == "-1" };
                self.limits.memory_bytes = if unlimited {
                    None
                } else {
                    let bytes: u64 = value.parse().map_err(|_| bad("not a number of bytes"))?;
                    if bytes == 0 {
                        return Err(bad("a limit of 0 bytes"));
                    }
                    Some(bytes)
                };
            }
            (2, "cpu.max") => {
                let mut parts = value.split_whitespace();
                let quota = parts.next().unwrap_or("");
                let period = match parts.next() {
                    Some(p) => p.parse().map_err(|_| bad("not a period in microseconds"))?,
                    None => DEFAULT_PERIOD_US,
                };
                if parts.next().is_some() {
                    return Err(bad("expected <quota> [<period>]"));
                }
                self.limits.cpu_rate = if quota == "max" {
                    None
                } else {
                    let quota = quota.parse().map_err(|_| bad("not a quota in microseconds"))?;
                    Some(cpu_rate(quota, period, host_cpus()).map_err(bad)?)
                };
            }
            (1, "cpu.cfs_quota_us") => {
                self.v1_quota_us = Some(if value == "-1" {
                    None
                } else {
                    Some(value.parse().map_err(|_| bad("not a quota in microseconds"))?)
                });
            }
            (1, "cpu.cfs_period_us") => {
                self.v1_period_us = Some(value.parse().map_err(|_| bad("not a period in microseconds"))?);
            }
            (2, "cpu.weight") => {
                let w: u64 = value.parse().map_err(|_| bad("not a weight"))?;
                if !(1..=10_000).contains(&w) {
                    return Err(bad("a weight outside 1 to 10000"));
                }
                self.limits.cpu_weight = Some(cpu_weight(w as f64 / 100.0).map_err(bad)?);
            }
            (2, "cpu.weight.nice") => {
                let nice: i32 = value.parse().map_err(|_| bad("not a nice value"))?;
                let Some(w) = usize::try_from(nice + 20).ok().and_then(|i| SCHED_PRIO_TO_WEIGHT.get(i)) else {
                    return Err(bad("a nice value outside -20 to 19"));
                };
                self.limits.cpu_weight = Some(cpu_weight(f64::from(*w) / 1024.0).map_err(bad)?);
            }
            (1, "cpu.shares") => {
                let shares: u64 = value.parse().map_err(|_| bad("not a number of shares"))?;
                // Linux clamps to 2..=262144.
                let shares = shares.clamp(2, 262_144);
                self.limits.cpu_weight = Some(cpu_weight(shares as f64 / 1024.0).map_err(bad)?);
            }
            (_, "cpuset.cpus") => {
                self.limits.cpus = if value.trim().is_empty() {
                    // v2: an empty list takes the parent's CPUs, all of them
                    // here; v1: a cpuset without CPUs can hold no task.
                    if self.version == 1 {
                        return Err(bad("no CPUs (a cgroup v1 cpuset without CPUs can hold no process)"));
                    }
                    None
                } else {
                    let cpus = parse_list(&value).map_err(bad)?;
                    Some(cpu_groups(&cpus, &host_groups()).map_err(bad)?)
                };
            }
            (_, "cpuset.mems") => {
                if !(self.version == 2 && value.trim().is_empty()) {
                    let nodes = parse_list(&value).map_err(bad)?;
                    check_mems(&nodes, host_highest_node()).map_err(|e| match e {
                        MemsError::NoSuchNode => bad("no such memory node on this host"),
                        MemsError::Binds => HostError::ImpossibleCgroup(cg(), MEMS_BIND).into(),
                    })?;
                }
            }
            // The host's large page is 2 MiB: its limit is the large-page
            // broker's (`large_pages`); other sizes have no pages here.
            (2, "hugetlb.2MB.max") | (1, "hugetlb.2MB.limit_in_bytes") => {
                let value = strstrip(&value);
                let unlimited = if self.version == 2 { value == "max" } else { value == "-1" };
                self.limits.large_page_bytes = if unlimited {
                    None
                } else {
                    Some(value.parse().map_err(|_| bad("not a number of bytes"))?)
                };
            }
            // A page size Linux has no hugetlb files for: the write fails
            // there (no such file), at any value.
            (_, f) if hugetlb_size(f).is_some_and(|size| !linux_hugetlb_size(size, host_gb_pages())) => {
                return Err(bad(NO_SUCH_PAGE_SIZE));
            }
            // A limit file at the value that sets no limit: nothing to
            // enforce, so nothing is accepted without effect.
            (version, f) if no_limit(version, f, &value) => {}
            (version, f) => {
                return Err(match impossible(version, f) {
                    Some(why) => HostError::ImpossibleCgroup(cg(), why).into(),
                    None => HostError::UnsupportedCgroup(cg()).into(),
                });
            }
        }
        if self.version == 1 {
            if let Some(quota) = self.v1_quota_us {
                let period = self.v1_period_us.unwrap_or(DEFAULT_PERIOD_US);
                self.limits.cpu_rate = match quota {
                    None => None,
                    Some(q) => Some(
                        cpu_rate(q, period, host_cpus())
                            .map_err(|why| HostError::CgroupValue(format!("cpu.cfs_quota_us={q}"), why))?,
                    ),
                };
            }
        }
        if self.limits.cpu_rate.is_some() && self.limits.cpu_weight.is_some() {
            return Err(HostError::ImpossibleCgroup(cg(), CAP_AND_WEIGHT).into());
        }
        Ok(())
    }

    pub fn build(self) -> CgroupConfiguration {
        CgroupConfiguration { limits: self.limits, freezer: self.freezer }
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
    limits: Limits,
    freezer: Option<FreezerState>,
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        platform::set_limits(self.limits.clone());
        // Last, as Linux attaches the jailer to its cgroups after writing
        // every property: FROZEN stops the jailer here.
        if let Some(state) = self.freezer {
            platform::freezer_at_cgroup_step(state)?;
        }
        Ok(())
    }
}

const CAP_AND_WEIGHT: &str = "a Job Object takes a CPU rate cap (cpu.max) or a CPU weight (cpu.weight, \
                              cpu.shares), not both";
const MEMS_BIND: &str = "Windows cannot bind a process's memory to NUMA nodes; only a list of every \
                         memory node of the host, which binds nothing, is accepted";

const NO_SUCH_PAGE_SIZE: &str = "an x86_64 Linux host has no hugetlb files for this page size (only 2MB, and \
                                 1GB where the processor has 1 GiB pages), so the write fails there";

use crate::platform::freezer_values::{READ_ONLY, STATE_VALUES};

/// The page size a `hugetlb.<size>.<what>` file names.
fn hugetlb_size(file: &str) -> Option<&str> {
    file.strip_prefix("hugetlb.")?.split_once('.').map(|(size, _)| size)
}

/// Whether an x86_64 Linux host has hugetlb cgroup files for the page size
/// `size`, spelled as the files spell it. Linux v6.1 makes a cgroup's files
/// per huge page size the kernel has (mm/hugetlb_cgroup.c
/// `hugetlb_cgroup_file_init`: `for_each_hstate`; `mem_fmt` writes the size
/// as `2MB`, `1GB`), and x86_64 has two: 2 MiB always (mm/hugetlb.c
/// `hugetlb_init`: `hugetlb_add_hstate(HUGETLB_PAGE_ORDER)`), and 1 GiB where
/// the processor has 1 GiB pages (arch/x86/mm/hugetlbpage.c
/// `gigantic_pages_init` and `arch_hugetlb_valid_size`:
/// `boot_cpu_has(X86_FEATURE_GBPAGES)`). A file of any other size does not
/// exist, and the jailer's write to it fails.
fn linux_hugetlb_size(size: &str, gb_pages: bool) -> bool {
    size == "2MB" || (size == "1GB" && gb_pages)
}

/// Whether the processor has 1 GiB pages: Linux's `X86_FEATURE_GBPAGES`,
/// CPUID.80000001H:EDX bit 26 (arch/x86/include/asm/cpufeatures.h, word 1).
fn host_gb_pages() -> bool {
    let leaf = 0x8000_0001;
    std::arch::x86_64::__cpuid(0x8000_0000).eax >= leaf && std::arch::x86_64::__cpuid(leaf).edx & (1 << 26) != 0
}

/// Whether `file` = `value` is one of Linux's limit files at the value that
/// sets no limit, the file's default, which the jailer accepts although the
/// host has no such limit: there is nothing to enforce. From Linux v6.1,
/// each handler parsing with `page_counter_memparse(buf, <max>, ..)`
/// (mm/page_counter.c: a string equal to `<max>` is `PAGE_COUNTER_MAX`)
/// unless noted:
///
/// - `pids.max` = `max`, both versions (kernel/cgroup/pids.c
///   `pids_max_write`: `PIDS_MAX_STR`);
/// - v2, `max`: `hugetlb.<size>.max` and `.rsvd.max` (mm/hugetlb_cgroup.c
///   `hugetlb_cgroup_write_dfl`), `memory.high` (mm/memcontrol.c
///   `memory_high_write`), `memory.swap.max` (`swap_max_write`),
///   `memory.swap.high` (`swap_high_write`), `memory.zswap.max`
///   (`zswap_max_write`);
/// - v1, `-1`: `hugetlb.<size>.limit_in_bytes` and `.rsvd.limit_in_bytes`
///   (`hugetlb_cgroup_write_legacy`), `memory.memsw.limit_in_bytes`,
///   `memory.soft_limit_in_bytes` and `memory.kmem.tcp.limit_in_bytes`
///   (mm/memcontrol.c `mem_cgroup_write`; the last also switches the
///   cgroup's TCP memory accounting on, `memcg_update_tcp_max`, which has
///   no counterpart here and limits nothing).
///
/// `memory.max` and `memory.limit_in_bytes`, and `hugetlb.2MB`'s own limit,
/// are limits Windows has, with arms of their own. A hugetlb file of a page
/// size Linux does not have is refused before this is asked
/// ([`linux_hugetlb_size`]). The same files, words and sizes rule as the
/// macOS backend's `no_limit` (its sizes are aarch64's). Not here:
/// `memory.kmem.limit_in_bytes`, whose write fails in v6.1
/// (`mem_cgroup_write`, `_KMEM`: `-EOPNOTSUPP`); a number, also one the
/// kernel would clamp to no limit; and `memory.min`
/// and `memory.low`, whose default is 0; their `max` protects all of a
/// cgroup's memory, which is no absence of a limit.
fn no_limit(version: u8, file: &str, value: &str) -> bool {
    let value = strstrip(value);
    let hugetlb = |suffix: &str| {
        file.strip_prefix("hugetlb.")
            .and_then(|rest| rest.strip_suffix(suffix))
            .is_some_and(|size| !size.is_empty() && !size.contains('.'))
    };
    match version {
        2 => {
            value == "max"
                && (matches!(
                    file,
                    "pids.max" | "memory.high" | "memory.swap.max" | "memory.swap.high" | "memory.zswap.max"
                ) || hugetlb(".max")
                    || hugetlb(".rsvd.max"))
        }
        1 => {
            (file == "pids.max" && value == "max")
                || (value == "-1"
                    && (matches!(
                        file,
                        "memory.memsw.limit_in_bytes" | "memory.soft_limit_in_bytes" | "memory.kmem.tcp.limit_in_bytes"
                    )
                        || hugetlb(".limit_in_bytes")
                        || hugetlb(".rsvd.limit_in_bytes")))
        }
        _ => false,
    }
}

/// Why Windows cannot do what the cgroup file `file` does, for the
/// controllers and files Windows has no counterpart for.
fn impossible(version: u8, file: &str) -> Option<&'static str> {
    let controller = file.split('.').next().unwrap_or("");
    Some(match (version, controller) {
        (_, "memory") => {
            "a Job Object's memory limit is a hard limit only (memory.max, v1: memory.limit_in_bytes): \
             Windows has no reclaim threshold, protection or swap limit for a job, so of the other \
             memory limits only \"no limit\" is accepted (memory.high, memory.swap.max, memory.swap.high, \
             memory.zswap.max = max; v1: memory.memsw.limit_in_bytes, memory.soft_limit_in_bytes, \
             memory.kmem.tcp.limit_in_bytes = -1)"
        }
        (_, "pids") => {
            "a cgroup's pids.max counts threads as well as processes, and Windows cannot limit a \
             process's threads (the system starts thread-pool threads in every process); only \
             pids.max=max is accepted"
        }
        (_, "cpuset") => {
            "Windows cannot give a job processors or memory nodes of its own (exclusive CPUs, \
             partitions, memory spreading or migration); cpuset.cpus and cpuset.mems are accepted"
        }
        (2, "io") | (1, "blkio") => {
            "Windows limits a job's I/O per volume, not per Linux major:minor device, with reads \
             and writes counted together (no separate rbps/wbps/riops/wiops), and has I/O \
             priorities rather than weights or latency targets"
        }
        (_, "hugetlb") => {
            "the host's large pages are 2 MiB: only hugetlb.2MB.max (v1: hugetlb.2MB.limit_in_bytes) \
             limits them; 1 GiB pages and reservations have no limit to set (only max, -1)"
        }
        (2, "rdma") => "Windows has no limit on a job's RDMA resources",
        (2, "misc") => "Windows has no counterpart for the misc controller's resources",
        (1, "devices") => {
            "Windows has no device nodes: what the jailed process opens is decided by the jail's \
             token and ACLs"
        }
        (1, "net_cls" | "net_prio") => {
            "Windows has no network classes or priorities per job"
        }
        (1, "perf_event") => "Windows has no performance event group per job",
        _ => return None,
    })
}

/// Linux's `sched_prio_to_weight`: the CFS weight of nice -20 to 19.
const SCHED_PRIO_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// The CPU share a job of each Windows weight (1 to 9) gets against a job of
/// the default weight (5), both spinning on one processor: measured on
/// Windows Server 2022 (4 s per pair, `jailer-test.ps1 weight` checks one
/// pair through the jailer). Linux gives a cgroup the share its weight bears
/// to its sibling's.
const WINDOWS_WEIGHT_SHARE: [f64; 9] = [0.25, 0.49, 0.69, 0.85, 1.0, 1.20, 1.33, 1.42, 1.81];

/// The Windows weight whose share against the default is nearest to
/// `share`, the share Linux gives a cgroup against one of the default weight
/// (`cpu.weight / 100`, `cpu.shares / 1024`). Refused when even the nearest
/// is more than a quarter off (one nice level): Windows weights span only
/// 0.25 to 1.8 times the default share.
pub(crate) fn cpu_weight(share: f64) -> Result<u32, &'static str> {
    let (i, off) = WINDOWS_WEIGHT_SHARE
        .iter()
        .map(|w| (share / w).ln().abs())
        .enumerate()
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap();
    if off > 1.25f64.ln() + 1e-9 {
        return Err("outside what a Windows CPU weight can give: 0.25 to 1.8 times the share of the default \
                    weight (cpu.weight 20 to 226, cpu.shares 205 to 2316, nice 7 to -3)");
    }
    Ok(u32::try_from(i).unwrap() + 1)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MemsError {
    NoSuchNode,
    Binds,
}

/// Accepts `nodes` only when it is every memory node of a host whose highest
/// node is `highest`: Linux binds a cgroup's memory to its nodes, which
/// Windows cannot do for a process, and every node binds nothing.
pub(crate) fn check_mems(nodes: &[u32], highest: u32) -> Result<(), MemsError> {
    if nodes.iter().any(|&n| n > highest) {
        return Err(MemsError::NoSuchNode);
    }
    if (0..=highest).any(|n| !nodes.contains(&n)) {
        return Err(MemsError::Binds);
    }
    Ok(())
}

/// The host's logical processors, which a job's CPU rate is a share of.
fn host_cpus() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
}

/// The active logical processors of each of the host's processor groups.
fn host_groups() -> Vec<u32> {
    use windows_sys::Win32::System::Threading::{GetActiveProcessorCount, GetActiveProcessorGroupCount};
    // SAFETY: plain queries.
    let groups = unsafe { GetActiveProcessorGroupCount() };
    // SAFETY: as above.
    (0..groups).map(|g| unsafe { GetActiveProcessorCount(g) }).collect()
}

/// The host's highest NUMA node number.
fn host_highest_node() -> u32 {
    use windows_sys::Win32::System::Threading::GetNumaHighestNodeNumber;
    let mut highest = 0u32;
    // SAFETY: an out-parameter.
    if unsafe { GetNumaHighestNodeNumber(&mut highest) } == 0 {
        return 0;
    }
    highest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(version: u8, props: &[&str]) -> Result<Limits, JailerError> {
        let mut b = CgroupConfigurationBuilder::new(version, "")?;
        for p in props {
            let (f, v) = p.split_once('=').unwrap();
            b.add_cgroup_property(f.into(), v.into(), "id", Path::new("fc"))?;
        }
        Ok(b.build().limits)
    }

    fn reason(version: u8, prop: &str) -> &'static str {
        match limits(version, &[prop]) {
            Err(JailerError::Host(HostError::ImpossibleCgroup(cg, why))) => {
                assert_eq!(cg, prop);
                why
            }
            other => panic!("{prop}: {other:?}"),
        }
    }

    #[test]
    fn test_cpu_rate() {
        assert_eq!(cpu_rate(50_000, 100_000, 4), Ok(1250));
        assert_eq!(cpu_rate(400_000, 100_000, 4), Ok(10_000));
        assert_eq!(cpu_rate(800_000, 100_000, 4), Ok(10_000));
        assert!(cpu_rate(1, 100_000, 64).is_err());
        assert!(cpu_rate(1, 0, 1).is_err());
    }

    #[test]
    fn test_limits() {
        let l = limits(2, &["memory.max=536870912", "pids.max=max", "cpu.max=max 100000"]).unwrap();
        assert_eq!(l, Limits { memory_bytes: Some(512 << 20), ..Limits::default() });
        let l = limits(2, &["cpu.max=100000000"]).unwrap();
        assert_eq!(l.cpu_rate, Some(10_000));
        let l = limits(1, &["memory.limit_in_bytes=-1", "cpu.cfs_period_us=1000000", "cpu.cfs_quota_us=1000000000"]).unwrap();
        assert_eq!(l, Limits { cpu_rate: Some(10_000), ..Limits::default() });
        for bad in ["memory.max=x", "memory.max=0", "cpu.max=1 2 3", "cpu.max=x"] {
            assert!(matches!(limits(2, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))), "{bad}");
        }
    }

    /// cpu.weight, cpu.weight.nice and cpu.shares: the Windows weight whose
    /// measured share is nearest; the default is Windows' default (5).
    #[test]
    fn test_cpu_weight() {
        assert_eq!(limits(2, &["cpu.weight=100"]).unwrap().cpu_weight, Some(5));
        assert_eq!(limits(2, &["cpu.weight=50"]).unwrap().cpu_weight, Some(2));
        assert_eq!(limits(2, &["cpu.weight=25"]).unwrap().cpu_weight, Some(1));
        assert_eq!(limits(2, &["cpu.weight=180"]).unwrap().cpu_weight, Some(9));
        assert_eq!(limits(2, &["cpu.weight=120"]).unwrap().cpu_weight, Some(6));
        assert_eq!(limits(2, &["cpu.weight.nice=0"]).unwrap().cpu_weight, Some(5));
        assert_eq!(limits(2, &["cpu.weight.nice=3"]).unwrap().cpu_weight, Some(2));
        assert_eq!(limits(2, &["cpu.weight.nice=-2"]).unwrap().cpu_weight, Some(8));
        assert_eq!(limits(2, &["cpu.weight.nice=-3"]).unwrap().cpu_weight, Some(9));
        assert_eq!(limits(2, &["cpu.weight=20"]).unwrap().cpu_weight, Some(1));
        assert_eq!(limits(2, &["cpu.weight=226"]).unwrap().cpu_weight, Some(9));
        assert_eq!(limits(1, &["cpu.shares=1024"]).unwrap().cpu_weight, Some(5));
        assert_eq!(limits(1, &["cpu.shares=512"]).unwrap().cpu_weight, Some(2));
        // Shares Windows weights cannot give are refused, not rounded.
        for bad in ["cpu.weight=19", "cpu.weight=227", "cpu.weight.nice=8", "cpu.weight.nice=-4", "cpu.weight.nice=-20"] {
            assert!(matches!(limits(2, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))), "{bad}");
        }
        for bad in ["cpu.weight=0", "cpu.weight=10001", "cpu.weight=x", "cpu.weight.nice=20"] {
            assert!(matches!(limits(2, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))), "{bad}");
        }
        assert!(limits(1, &["cpu.shares=100"]).is_err());
        // Every level is reachable, each from the share it was measured at.
        for (i, share) in WINDOWS_WEIGHT_SHARE.iter().enumerate() {
            assert_eq!(cpu_weight(*share), Ok(u32::try_from(i).unwrap() + 1));
        }
    }

    #[test]
    fn test_cpu_weight_and_cap_are_refused_together() {
        for props in [
            &["cpu.max=50000 100000", "cpu.weight=50"][..],
            &["cpu.weight=50", "cpu.max=50000"][..],
            &["cpu.shares=512", "cpu.cfs_quota_us=50000"][..],
        ] {
            let v = if props[0].starts_with("cpu.shares") { 1 } else { 2 };
            assert!(
                matches!(limits(v, props).unwrap_err(), JailerError::Host(HostError::ImpossibleCgroup(_, CAP_AND_WEIGHT))),
                "{props:?}"
            );
        }
        // No cap (max) leaves the weight alone.
        assert_eq!(limits(2, &["cpu.max=max", "cpu.weight=50"]).unwrap().cpu_weight, Some(2));
    }

    #[test]
    fn test_cpuset_cpus() {
        assert_eq!(parse_list("0-3,8, 10-11,2").unwrap(), [0, 1, 2, 3, 8, 10, 11]);
        for bad in ["", "x", "3-1", "0-", "0-100000"] {
            assert!(parse_list(bad).is_err(), "{bad:?}");
        }
        // One group of 8.
        assert_eq!(cpu_groups(&[0, 2, 3], &[8]), Ok(vec![(0, 0b1101)]));
        assert!(cpu_groups(&[8], &[8]).is_err());
        // Two groups (a host with more than 64 logical processors): numbered
        // across them in order.
        assert_eq!(cpu_groups(&[1, 64, 65, 70], &[64, 8]), Ok(vec![(0, 0b10), (1, 0b100_0011)]));
        assert!(cpu_groups(&[72], &[64, 8]).is_err());
        // Through the builder, on this host: CPU 0 exists on every host.
        assert_eq!(limits(2, &["cpuset.cpus=0"]).unwrap().cpus, Some(vec![(0, 1)]));
        assert_eq!(limits(1, &["cpuset.cpus=0"]).unwrap().cpus, Some(vec![(0, 1)]));
        // v2: empty is the parent's, every CPU; v1: no CPUs is refused.
        assert_eq!(limits(2, &["cpuset.cpus="]).unwrap().cpus, None);
        assert!(limits(1, &["cpuset.cpus="]).is_err());
        assert!(matches!(
            limits(2, &["cpuset.cpus=100000"]).unwrap_err(),
            JailerError::Host(HostError::CgroupValue(..))
        ));
    }

    #[test]
    fn test_cpuset_mems() {
        assert_eq!(check_mems(&[0], 0), Ok(()));
        assert_eq!(check_mems(&[0, 1], 1), Ok(()));
        assert_eq!(check_mems(&[1], 1), Err(MemsError::Binds));
        assert_eq!(check_mems(&[0, 2], 1), Err(MemsError::NoSuchNode));
        // Through the builder: every node of this host is accepted (binds
        // nothing); a node it does not have is a bad value.
        let all = format!("cpuset.mems=0-{}", host_highest_node());
        assert_eq!(limits(2, &[all.as_str()]).unwrap(), Limits::default());
        assert!(limits(2, &["cpuset.mems=4000"]).is_err());
        assert_eq!(limits(2, &["cpuset.mems="]).unwrap(), Limits::default());
    }

    #[test]
    fn test_pids_max_counts_threads_and_is_refused() {
        assert!(reason(2, "pids.max=100").contains("threads"));
        assert!(reason(1, "pids.max=1").contains("threads"));
        assert_eq!(limits(2, &["pids.max=max"]).unwrap(), Limits::default());
    }

    // Linux's limit files at the value that sets no limit are accepted,
    // with the white space Linux strips; the same files with a limit, the
    // other version's spelling of no limit, and memory.min and memory.low
    // (whose `max` is no absence of a limit) are refused. The same set as
    // macOS's backend takes.
    #[test]
    fn test_no_limit_values_are_accepted() {
        let v2 = [
            "pids.max",
            "hugetlb.2MB.max",
            "hugetlb.2MB.rsvd.max",
            "memory.high",
            "memory.swap.max",
            "memory.swap.high",
            "memory.zswap.max",
            "memory.max",
        ];
        for f in v2 {
            for v in ["max", " max", "max\n", "\t max \r\n"] {
                assert_eq!(limits(2, &[&format!("{f}={v}")]).unwrap(), Limits::default(), "{f}={v:?}");
            }
            for v in ["-1", "MAX", "ma x", ""] {
                assert!(limits(2, &[&format!("{f}={v}")]).is_err(), "{f}={v:?}");
            }
        }
        let v1 = [
            "hugetlb.2MB.limit_in_bytes",
            "hugetlb.2MB.rsvd.limit_in_bytes",
            "memory.memsw.limit_in_bytes",
            "memory.soft_limit_in_bytes",
            "memory.kmem.tcp.limit_in_bytes",
            "memory.limit_in_bytes",
        ];
        for f in v1 {
            for v in ["-1", " -1", "-1\n"] {
                assert_eq!(limits(1, &[&format!("{f}={v}")]).unwrap(), Limits::default(), "{f}={v:?}");
            }
            for v in ["max", "- 1", ""] {
                assert!(limits(1, &[&format!("{f}={v}")]).is_err(), "{f}={v:?}");
            }
        }
        assert_eq!(limits(1, &["pids.max=max"]).unwrap(), Limits::default());
        assert_eq!(limits(1, &["pids.max= max\n"]).unwrap(), Limits::default());
        assert!(limits(1, &["pids.max=-1"]).is_err());
        // A limit in any of them is refused: Windows has none of these.
        for (v, p) in [
            (2, "memory.high=1048576"),
            (2, "memory.swap.max=0"),
            (2, "memory.swap.high=1048576"),
            (2, "memory.zswap.max=0"),
            (2, "hugetlb.2MB.rsvd.max=2097152"),
            (1, "memory.memsw.limit_in_bytes=1048576"),
            (1, "memory.soft_limit_in_bytes=1048576"),
            (1, "hugetlb.2MB.rsvd.limit_in_bytes=2097152"),
            // The default of these two is 0, and their `max` is the most
            // protection, not none.
            (2, "memory.min=max"),
            (2, "memory.low=max"),
            (2, "memory.min=0"),
            (2, "memory.low=0"),
            // One version's file with the other version.
            (1, "memory.high=max"),
            (1, "memory.swap.max=max"),
            (2, "memory.memsw.limit_in_bytes=-1"),
            (2, "memory.soft_limit_in_bytes=-1"),
            (1, "hugetlb.2MB.max=max"),
            (2, "hugetlb.2MB.limit_in_bytes=-1"),
            // No page size named.
            (2, "hugetlb.max=max"),
            (2, "hugetlb..max=max"),
        ] {
            assert!(limits(v, &[p]).is_err(), "v{v} {p}");
        }
        // A limit, then no limit: the later value holds, as the later write
        // to the file does.
        assert_eq!(limits(2, &["hugetlb.2MB.max=2097152", "hugetlb.2MB.max= max"]).unwrap(), Limits::default());
        assert_eq!(limits(2, &["memory.max=1048576", "memory.max=max\n"]).unwrap(), Limits::default());
        // A limit with white space around it, as Linux takes it.
        assert_eq!(limits(2, &["memory.max= 1048576\n"]).unwrap().memory_bytes, Some(1 << 20));
    }

    // A hugetlb file is taken only for a page size an x86_64 Linux has
    // files for: 2MB, and 1GB where the processor has 1 GiB pages. Any other
    // size is refused at every value, as the write to the missing file
    // fails on Linux; the reason is not one of Windows.
    #[test]
    fn test_hugetlb_page_sizes_are_linuxs() {
        assert_eq!(hugetlb_size("hugetlb.2MB.max"), Some("2MB"));
        assert_eq!(hugetlb_size("hugetlb.1GB.rsvd.limit_in_bytes"), Some("1GB"));
        assert_eq!(hugetlb_size("hugetlb..max"), Some(""));
        assert_eq!(hugetlb_size("hugetlb.max"), None);
        assert_eq!(hugetlb_size("memory.2MB.max"), None);
        for gb_pages in [false, true] {
            assert!(linux_hugetlb_size("2MB", gb_pages));
            assert_eq!(linux_hugetlb_size("1GB", gb_pages), gb_pages);
            // Other architectures' sizes, other spellings, no size.
            for size in ["64KB", "32MB", "512MB", "16GB", "4KB", "2mb", "2M", "2MiB", "2097152", "1G", ""] {
                assert!(!linux_hugetlb_size(size, gb_pages), "{size}");
            }
        }
        let no_such_size = |version: u8, prop: &str| match limits(version, &[prop]) {
            Err(JailerError::Host(HostError::CgroupValue(cg, why))) => {
                assert_eq!(cg, prop);
                assert_eq!(why, NO_SUCH_PAGE_SIZE);
            }
            other => panic!("{prop}: {other:?}"),
        };
        for size in ["64KB", "32MB", "16GB", "2mb", "2M", ""] {
            for what in ["max=max", "rsvd.max=max", "max=2097152", "max= max\n"] {
                no_such_size(2, &format!("hugetlb.{size}.{what}"));
            }
            for what in ["limit_in_bytes=-1", "rsvd.limit_in_bytes=-1", "limit_in_bytes=2097152"] {
                no_such_size(1, &format!("hugetlb.{size}.{what}"));
            }
        }
        // 1 GiB pages, by this processor.
        let v2 = ["hugetlb.1GB.max=max", "hugetlb.1GB.rsvd.max= max\n"];
        let v1 = ["hugetlb.1GB.limit_in_bytes=-1", "hugetlb.1GB.rsvd.limit_in_bytes=-1"];
        if host_gb_pages() {
            assert_eq!(limits(2, &v2).unwrap(), Limits::default());
            assert_eq!(limits(1, &v1).unwrap(), Limits::default());
            // A limit on them is one Windows cannot set.
            assert!(reason(2, "hugetlb.1GB.max=1073741824").contains("2 MiB"));
            assert!(reason(1, "hugetlb.1GB.limit_in_bytes=1073741824").contains("2 MiB"));
        } else {
            for p in v2 {
                no_such_size(2, p);
            }
            for p in v1 {
                no_such_size(1, p);
            }
            no_such_size(2, "hugetlb.1GB.max=1073741824");
        }
        // On record (CI's record step runs this test alone with its
        // output shown): which of the two halves above this processor took.
        println!(
            "HUGETLBTEST 1 GiB pages (CPUID.80000001H:EDX bit 26): {}; hugetlb.1GB files {}",
            host_gb_pages(),
            if host_gb_pages() { "accepted at no limit" } else { "refused as missing" }
        );
    }

    #[test]
    fn test_io_is_refused() {
        assert!(reason(2, "io.max=8:0 rbps=1048576").contains("major:minor"));
        assert!(reason(2, "io.weight=default 100").contains("major:minor"));
        assert!(reason(2, "io.latency=8:0 target=10").contains("major:minor"));
        assert!(reason(1, "blkio.throttle.read_bps_device=8:0 1048576").contains("major:minor"));
        assert!(reason(1, "blkio.weight=500").contains("major:minor"));
    }

    #[test]
    fn test_hugetlb_2mb_limits_the_large_page_broker() {
        assert_eq!(limits(2, &["hugetlb.2MB.max=1073741824"]).unwrap().large_page_bytes, Some(1 << 30));
        assert_eq!(limits(1, &["hugetlb.2MB.limit_in_bytes=1073741824"]).unwrap().large_page_bytes, Some(1 << 30));
        assert_eq!(limits(2, &["hugetlb.2MB.max=max"]).unwrap(), Limits::default());
        assert_eq!(limits(1, &["hugetlb.2MB.limit_in_bytes=-1"]).unwrap(), Limits::default());
    }

    #[test]
    fn test_other_controllers_are_refused_with_the_reason() {
        assert!(reason(2, "rdma.max=mlx4_0 hca_handle=2").contains("RDMA"));
        assert!(reason(2, "misc.max=sev 1").contains("misc"));
        assert!(reason(1, "devices.deny=a").contains("device"));
        assert!(reason(1, "net_cls.classid=1").contains("network"));
        assert!(reason(1, "net_prio.ifpriomap=eth0 1").contains("network"));
        assert!(reason(1, "perf_event.x=1").contains("performance"));
        assert!(reason(2, "cpuset.cpus.exclusive=0").contains("of its own"));
        assert!(reason(2, "cpuset.cpus.partition=root").contains("of its own"));
        assert!(reason(1, "cpuset.cpu_exclusive=1").contains("of its own"));
        assert!(reason(1, "cpuset.memory_migrate=1").contains("migration"));
        // A memory list short of every node cannot be enforced.
        if host_highest_node() == 0 {
            // A single-node host has no node to leave out; the refusal is
            // checked through `check_mems` above.
        } else {
            assert_eq!(reason(2, "cpuset.mems=0"), MEMS_BIND);
        }
    }

    // The freezer at the start, as upstream's jailer on Linux
    // (`tools/linux/jailer-cgroup-check.py`): v1 freezer.state takes FROZEN or
    // THAWED (the kernel refuses any other value written to it, and the other
    // freezer files are read-only); `cgroup` is no controller, with either
    // version (upstream finds no hierarchy or cgroup.controllers entry for
    // it), so v2's cgroup.freeze is refused at the start; v2 has no freezer
    // controller.
    #[test]
    fn test_freezer_at_the_start() {
        let freezer = |v, p: &str| {
            let mut b = CgroupConfigurationBuilder::new(v, "")?;
            let (f, val) = p.split_once('=').unwrap();
            b.add_cgroup_property(f.into(), val.into(), "id", Path::new("fc"))?;
            Ok::<_, JailerError>(b.build().freezer)
        };
        assert_eq!(freezer(1, "freezer.state=FROZEN").unwrap(), Some(FreezerState::Frozen));
        assert_eq!(freezer(1, "freezer.state=THAWED").unwrap(), Some(FreezerState::Thawed));
        assert_eq!(freezer(1, "memory.limit_in_bytes=-1").unwrap(), None);
        for (p, why) in [
            ("freezer.state=FREEZING", STATE_VALUES),
            ("freezer.state=", STATE_VALUES),
            ("freezer.state=frozen", STATE_VALUES),
            ("freezer.self_freezing=1", READ_ONLY),
            ("freezer.parent_freezing=1", READ_ONLY),
        ] {
            match freezer(1, p) {
                Err(JailerError::Host(HostError::CgroupValue(cg, w))) => assert_eq!((cg.as_str(), w), (p, why)),
                other => panic!("{p}: {other:?}"),
            }
        }
        for (v, p, controller) in [
            (2, "cgroup.freeze=1", "cgroup"),
            (2, "cgroup.freeze=0", "cgroup"),
            (2, "cgroup.max.descendants=0", "cgroup"),
            (2, "cgroup.procs=1", "cgroup"),
            (1, "cgroup.freeze=1", "cgroup"),
            (2, "freezer.state=FROZEN", "freezer"),
        ] {
            let err = freezer(v, p).unwrap_err();
            assert_eq!(err.to_string(), format!("Controller {controller} is unavailable"), "v{v} {p}");
        }
    }

    // Of a limit Windows lacks only "no limit" is accepted: the same files
    // with anything that would restrict, the other cgroup version's word or
    // file name, a protection, a file the kernel refuses to write, each
    // with the reason, which says so. The cases of the macOS backend's
    // `test_only_no_limit_is_accepted_of_a_limit_macos_lacks`, but for
    // hugetlb (`test_hugetlb_page_sizes_are_linuxs`,
    // `test_hugetlb_2mb_limits_the_large_page_broker`: Windows has a limit
    // for 2 MiB pages).
    #[test]
    fn test_only_no_limit_is_accepted_of_a_limit_windows_lacks() {
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
            (2, "memory.kmem.tcp.limit_in_bytes=-1", "hard limit only"),
            // Its write fails on Linux v6.1 (-EOPNOTSUPP).
            (1, "memory.kmem.limit_in_bytes=-1", "hard limit only"),
            // Protections, not limits: 0 is their default, max the largest.
            (2, "memory.min=0", "hard limit only"),
            (2, "memory.low=0", "hard limit only"),
            (2, "memory.min=max", "hard limit only"),
            (2, "memory.low=max", "hard limit only"),
            // The other version's name of the limit Windows has.
            (2, "memory.limit_in_bytes=1048576", "hard limit only"),
            (1, "memory.max=1048576", "hard limit only"),
            (2, "hugetlb.2MB.rsvd.max=2097152", "only max, -1"),
            (2, "hugetlb.2MB.current=max", "only max, -1"),
            (2, "hugetlb.max=max", "only max, -1"),
        ] {
            let reason = reason(v, p);
            assert!(reason.contains(why), "v{v} {p}: {reason}");
            assert!(reason.contains("only"), "v{v} {p}: {reason}");
        }
        assert!(reason(2, "memory.high=1048576").contains("only \"no limit\" is accepted"));
    }

    #[test]
    fn test_other_files_are_unsupported() {
        for (v, p) in [
            (2, "cpu.max.burst=1000"),
            (1, "cpu.weight=100"),
            (2, "cpu.shares=1024"),
            (2, "blkio.weight=100"),
            (1, "io.max=8:0 rbps=1"),
        ] {
            assert!(
                matches!(limits(v, &[p]).unwrap_err(), JailerError::Host(HostError::UnsupportedCgroup(_))),
                "{p}"
            );
        }
    }

    // The builder, as upstream makes it, takes a command line without a
    // parent (this test binary's) and keeps no plan for one; what a
    // command line says of the parent is `platform::parent`'s tests.
    #[test]
    fn test_the_builder_reads_the_parent_cgroup() {
        CgroupConfigurationBuilder::new(2, "").unwrap();
        CgroupConfigurationBuilder::new(1, "").unwrap();
        assert!(crate::platform::parent::for_jail().unwrap().is_none());
    }

    #[test]
    fn test_no_parent_cgroup_to_join() {
        let b = CgroupConfigurationBuilder::new(2, "").unwrap();
        assert!(!b.get_v2_hierarchy_path().unwrap().join("firecracker").exists());
    }
}
