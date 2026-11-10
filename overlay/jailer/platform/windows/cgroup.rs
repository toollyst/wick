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
//! | `cpu.max` (`<quota> [<period>]`) | `cpu.cfs_quota_us`, `cpu.cfs_period_us` | CPU rate hard cap, `quota / period` CPUs of all the host's, from Firecracker's third CPU-second on (below) |
//! | `pids.max` | `pids.max` | active process limit |
//!
//! The CPU rate cap starts once Firecracker has used two seconds of CPU
//! time (`platform::CPU_CAP_GRACE_100NS`): a guest that boots under the cap
//! calibrates its LAPIC timer while throttled, finds it far too slow and can
//! stop taking interrupts for good.
//!
//! Every other controller and property is refused, never accepted without
//! effect. Windows has no cgroup hierarchy, so the v2 hierarchy is a path that
//! does not exist: there is no parent cgroup to join.

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
        match (self.version, file.as_str()) {
            (2, "memory.max") | (1, "memory.limit_in_bytes") => {
                let unlimited = if self.version == 2 { value == "max" } else { value == "-1" };
                self.limits.memory_bytes = if unlimited {
                    None
                } else {
                    let bytes: u64 = value
                        .parse()
                        .map_err(|_| HostError::CgroupValue(cg(), "not a number of bytes"))?;
                    if bytes == 0 {
                        return Err(HostError::CgroupValue(cg(), "a limit of 0 bytes").into());
                    }
                    Some(bytes)
                };
            }
            (2, "cpu.max") => {
                let mut parts = value.split_whitespace();
                let quota = parts.next().unwrap_or("");
                let period = match parts.next() {
                    Some(p) => p.parse().map_err(|_| HostError::CgroupValue(cg(), "not a period in microseconds"))?,
                    None => DEFAULT_PERIOD_US,
                };
                if parts.next().is_some() {
                    return Err(HostError::CgroupValue(cg(), "expected <quota> [<period>]").into());
                }
                self.limits.cpu_rate = if quota == "max" {
                    None
                } else {
                    let quota = quota
                        .parse()
                        .map_err(|_| HostError::CgroupValue(cg(), "not a quota in microseconds"))?;
                    Some(cpu_rate(quota, period, host_cpus()).map_err(|why| HostError::CgroupValue(cg(), why))?)
                };
            }
            (1, "cpu.cfs_quota_us") => {
                self.v1_quota_us = Some(if value == "-1" {
                    None
                } else {
                    Some(value.parse().map_err(|_| HostError::CgroupValue(cg(), "not a quota in microseconds"))?)
                });
            }
            (1, "cpu.cfs_period_us") => {
                self.v1_period_us =
                    Some(value.parse().map_err(|_| HostError::CgroupValue(cg(), "not a period in microseconds"))?);
            }
            (_, "pids.max") => {
                self.limits.processes = if value == "max" {
                    None
                } else {
                    let n: u32 = value
                        .parse()
                        .map_err(|_| HostError::CgroupValue(cg(), "not a number of processes"))?;
                    if n == 0 {
                        return Err(HostError::CgroupValue(cg(), "a limit of 0 processes").into());
                    }
                    Some(n)
                };
            }
            _ => return Err(HostError::UnsupportedCgroup(cg()).into()),
        }
        if self.version == 1 {
            if let Some(quota) = self.v1_quota_us {
                let period = self.v1_period_us.unwrap_or(DEFAULT_PERIOD_US);
                self.limits.cpu_rate = match quota {
                    None => None,
                    Some(q) => Some(cpu_rate(q, period, host_cpus()).map_err(|why| {
                        HostError::CgroupValue(format!("cpu.cfs_quota_us={q}"), why)
                    })?),
                };
            }
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
        platform::set_limits(self.limits);
        Ok(())
    }
}

/// The host's logical processors, which a job's CPU rate is a share of.
fn host_cpus() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
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
        let l = limits(2, &["memory.max=536870912", "pids.max=4", "cpu.max=max 100000"]).unwrap();
        assert_eq!(l, Limits { memory_bytes: Some(512 << 20), cpu_rate: None, processes: Some(4) });
        let l = limits(2, &["cpu.max=100000000"]).unwrap();
        assert_eq!(l.cpu_rate, Some(10_000));
        let l = limits(1, &["memory.limit_in_bytes=-1", "cpu.cfs_period_us=1000000", "cpu.cfs_quota_us=1000000000"]).unwrap();
        assert_eq!(l, Limits { memory_bytes: None, cpu_rate: Some(10_000), processes: None });
        for bad in ["memory.max=x", "memory.max=0", "pids.max=0", "cpu.max=1 2 3", "cpu.max=x"] {
            assert!(matches!(limits(2, &[bad]).unwrap_err(), JailerError::Host(HostError::CgroupValue(..))), "{bad}");
        }
    }

    #[test]
    fn test_other_controllers_are_refused() {
        for (v, p) in [
            (1, "cpuset.cpus=0"),
            (1, "cpu.shares=10"),
            (2, "cpu.weight=10"),
            (2, "memory.limit_in_bytes=1048576"),
            (1, "memory.max=1048576"),
            (2, "io.max=8:0 rbps=1"),
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
