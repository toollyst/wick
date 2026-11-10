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
//! as CFS throttles a cgroup once it used its quota of each period. Every
//! other controller and property is refused, never accepted without effect. macOS has no cgroup hierarchy, so
//! the v2 hierarchy is an empty directory: there is no parent cgroup to join.

use std::path::{Path, PathBuf};

use crate::JailerError;
use crate::platform::{self, HostError};

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
        match ver {
            1 | 2 => Ok(CgroupConfigurationBuilder {
                version: ver,
                hierarchy: PathBuf::from(NO_HIERARCHY),
                memory_limit_mib: None,
                cpu: CpuBandwidth::default(),
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
        match (self.version, file.as_str()) {
            (2, "cpu.max") => self.cpu = cpu_max(&file, &value)?,
            (1, "cpu.cfs_quota_us") => self.cpu.quota_us = cfs_quota(&file, &value)?,
            (1, "cpu.cfs_period_us") => self.cpu.period_us = Some(period(&file, &value)?),
            _ => self.memory_limit_mib = memory_limit(self.version, &file, &value)?,
        }
        Ok(())
    }

    pub fn build(self) -> CgroupConfiguration {
        CgroupConfiguration {
            memory_limit_mib: self.memory_limit_mib,
            cpu: self.cpu,
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
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        // Checked here, once both v1 properties are known.
        let cpu_percent = cpu_percent(self.cpu)?;
        platform::set_memory_limit_mib(self.memory_limit_mib);
        platform::set_cpu_limit_percent(cpu_percent);
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
        _ => return Err(HostError::UnsupportedCgroup(cg()).into()),
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

    #[test]
    fn test_other_controllers_are_refused() {
        for (v, p) in [
            (1, "cpuset.cpus=0"),
            (1, "cpu.shares=10"),
            (2, "cpu.weight=10"),
            (2, "cpuset.cpus=0"),
            (1, "cpu.max=50000 100000"),
            (2, "cpu.cfs_quota_us=50000"),
            (2, "memory.limit_in_bytes=1048576"),
            (1, "memory.max=1048576"),
            (2, "pids.max=10"),
        ] {
            assert!(
                matches!(limit(v, &[p]).unwrap_err(), JailerError::Host(HostError::UnsupportedCgroup(_))),
                "{p}"
            );
        }
        assert!(matches!(
            CgroupConfigurationBuilder::new(3, "").unwrap_err(),
            JailerError::CgroupInvalidVersion(_)
        ));
    }

    #[test]
    fn test_no_parent_cgroup_to_join() {
        let b = CgroupConfigurationBuilder::new(2, "").unwrap();
        let parent = b.get_v2_hierarchy_path().unwrap().join("firecracker");
        assert!(!parent.exists());
    }
}
