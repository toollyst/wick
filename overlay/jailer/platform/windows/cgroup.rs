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
//! | `pids.max`, `hugetlb.<size>.max` = `max` | `pids.max` = `max`, `hugetlb.<size>.limit_in_bytes` = `-1` | no limit, as on Linux |
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
//! path that does not exist: there is no parent cgroup to join.

use std::path::{Path, PathBuf};

use crate::JailerError;
use crate::platform::{self, HostError, Limits};

/// The (absent) cgroup v2 hierarchy on Windows.
const NO_HIERARCHY: &str = r"\\?\GLOBALROOT\wick-no-cgroup-hierarchy";
/// The default CFS period, as Linux's.
const DEFAULT_PERIOD_US: u64 = 100_000;

#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    version: u8,
    hierarchy: PathBuf,
    limits: Limits,
    /// cgroup v1's quota and period, combined at `build`.
    v1_quota_us: Option<Option<u64>>,
    v1_period_us: Option<u64>,
}

impl CgroupConfigurationBuilder {
    pub fn new(ver: u8, _proc_mounts_path: &str) -> Result<Self, JailerError> {
        match ver {
            1 | 2 => Ok(CgroupConfigurationBuilder {
                version: ver,
                hierarchy: PathBuf::from(NO_HIERARCHY),
                limits: Limits::default(),
                v1_quota_us: None,
                v1_period_us: None,
            }),
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
        match (self.version, file.as_str()) {
            (2, "memory.max") | (1, "memory.limit_in_bytes") => {
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
            (_, "pids.max") if value == "max" => {}
            // The host's large page is 2 MiB: its limit is the large-page
            // broker's (`large_pages`); other sizes have no pages here.
            (2, "hugetlb.2MB.max") | (1, "hugetlb.2MB.limit_in_bytes") => {
                let unlimited = if self.version == 2 { value == "max" } else { value == "-1" };
                self.limits.large_page_bytes = if unlimited {
                    None
                } else {
                    Some(value.parse().map_err(|_| bad("not a number of bytes"))?)
                };
            }
            (2, f) if f.starts_with("hugetlb.") && f.ends_with(".max") && value == "max" => {}
            (1, f) if f.starts_with("hugetlb.") && f.ends_with(".limit_in_bytes") && value == "-1" => {}
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
        CgroupConfiguration { limits: self.limits }
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
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        platform::set_limits(self.limits.clone());
        Ok(())
    }
}

const CAP_AND_WEIGHT: &str = "a Job Object takes a CPU rate cap (cpu.max) or a CPU weight (cpu.weight, \
                              cpu.shares), not both";
const MEMS_BIND: &str = "Windows cannot bind a process's memory to NUMA nodes; only a list of every \
                         memory node of the host, which binds nothing, is accepted";

/// Why Windows cannot do what the cgroup file `file` does, for the
/// controllers and files Windows has no counterpart for.
fn impossible(version: u8, file: &str) -> Option<&'static str> {
    let controller = file.split('.').next().unwrap_or("");
    Some(match (version, controller) {
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
             limits them; pages of another size have no limit to set (only max, -1)"
        }
        (2, "rdma") => "Windows has no limit on a job's RDMA resources",
        (2, "misc") => "Windows has no counterpart for the misc controller's resources",
        (1, "freezer") | (2, "cgroup") => {
            "the jailer cannot freeze Firecracker or limit nested cgroups: a Job Object has no \
             freezer and no limit on nested jobs"
        }
        (1, "devices") => {
            "Windows has no device nodes: what the jailed process opens is decided by the jail's \
             token and ACLs"
        }
        (1, "net_cls" | "net_prio") => {
            "Windows has no network classes or priorities per job (and --netns is refused)"
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

/// The numbers of a cpuset list (`0-3,8,10-11`), sorted, without repeats.
fn parse_list(list: &str) -> Result<Vec<u32>, &'static str> {
    let mut out = Vec::new();
    for part in list.trim().split(',') {
        let part = part.trim();
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let lo: u32 = lo.parse().map_err(|_| "not a list such as 0-3,8")?;
        let hi: u32 = hi.parse().map_err(|_| "not a list such as 0-3,8")?;
        if lo > hi {
            return Err("a range that ends below its start");
        }
        if hi - lo > 4096 {
            return Err("a range of more than 4096");
        }
        out.extend(lo..=hi);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// The processors `cpus` (numbered across the host's processor groups in
/// order, as Windows lists logical processors) as an affinity mask per
/// group: `(group, mask)` for each group with one of them. `group_sizes`
/// holds the active processors of each group.
pub(crate) fn cpu_groups(cpus: &[u32], group_sizes: &[u32]) -> Result<Vec<(u16, u64)>, &'static str> {
    let mut out: Vec<(u16, u64)> = Vec::new();
    for &cpu in cpus {
        let mut first = 0u32;
        let mut found = None;
        for (g, &size) in group_sizes.iter().enumerate() {
            if cpu < first + size {
                found = Some((u16::try_from(g).unwrap(), cpu - first));
                break;
            }
            first += size;
        }
        let (group, bit) = found.ok_or("a CPU this host does not have")?;
        match out.iter_mut().find(|(g, _)| *g == group) {
            Some((_, mask)) => *mask |= 1 << bit,
            None => out.push((group, 1 << bit)),
        }
    }
    if out.is_empty() {
        return Err("no CPUs");
    }
    Ok(out)
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

/// The job CPU rate (hundredths of a percent of all `cpus`) for a cgroup
/// quota of `quota` microseconds per `period`: `quota / period` CPUs. Rounded
/// down, so the cap is at or below the one asked for.
fn cpu_rate(quota: u64, period: u64, cpus: u64) -> Result<u32, &'static str> {
    if period == 0 {
        return Err("a period of 0");
    }
    let rate = u128::from(quota) * 10_000 / (u128::from(period) * u128::from(cpus.max(1)));
    if rate == 0 {
        return Err("below the 0.01% of the host's CPUs a job can be capped at");
    }
    Ok(u32::try_from(rate.min(10_000)).unwrap())
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
        assert!(reason(2, "hugetlb.1GB.max=1073741824").contains("2 MiB"));
        assert_eq!(limits(2, &["hugetlb.2MB.max=max"]).unwrap(), Limits::default());
        assert_eq!(limits(1, &["hugetlb.2MB.limit_in_bytes=-1"]).unwrap(), Limits::default());
    }

    #[test]
    fn test_other_controllers_are_refused_with_the_reason() {
        assert!(reason(2, "rdma.max=mlx4_0 hca_handle=2").contains("RDMA"));
        assert!(reason(2, "misc.max=sev 1").contains("misc"));
        assert!(reason(2, "cgroup.freeze=1").contains("freeze"));
        assert!(reason(2, "cgroup.max.descendants=0").contains("nested"));
        assert!(reason(1, "freezer.state=FROZEN").contains("freeze"));
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

    #[test]
    fn test_other_files_are_unsupported() {
        for (v, p) in [
            (2, "cpu.max.burst=1000"),
            (2, "memory.high=1048576"),
            (2, "memory.limit_in_bytes=1048576"),
            (1, "memory.max=1048576"),
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

    #[test]
    fn test_no_parent_cgroup_to_join() {
        let b = CgroupConfigurationBuilder::new(2, "").unwrap();
        assert!(!b.get_v2_hierarchy_path().unwrap().join("firecracker").exists());
    }
}
