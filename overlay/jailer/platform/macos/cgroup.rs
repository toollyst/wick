// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS backend of upstream's `cgroup` module: the same builder and
//! configuration types, macOS limits behind them.
//!
//! A Firecracker process is alone in its cgroup, so a cgroup limit is a limit
//! on that process. The memory controller's limit (`memory.max` in v2,
//! `memory.limit_in_bytes` in v1) becomes a jetsam limit set at exec: the
//! process is killed when its footprint (guest memory included) reaches it,
//! as the cgroup's OOM killer does. Every other controller and property is
//! refused, never accepted without effect. macOS has no cgroup hierarchy, so
//! the v2 hierarchy is an empty directory: there is no parent cgroup to join.

use std::path::{Path, PathBuf};

use crate::JailerError;
use crate::platform::{self, HostError};

/// The (empty) cgroup v2 hierarchy on macOS.
const NO_HIERARCHY: &str = "/var/empty";

#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    version: u8,
    hierarchy: PathBuf,
    memory_limit_mib: Option<i32>,
}

impl CgroupConfigurationBuilder {
    pub fn new(ver: u8, _proc_mounts_path: &str) -> Result<Self, JailerError> {
        match ver {
            1 | 2 => Ok(CgroupConfigurationBuilder {
                version: ver,
                hierarchy: PathBuf::from(NO_HIERARCHY),
                memory_limit_mib: None,
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
        self.memory_limit_mib = memory_limit(self.version, &file, &value)?;
        Ok(())
    }

    pub fn build(self) -> CgroupConfiguration {
        CgroupConfiguration {
            memory_limit_mib: self.memory_limit_mib,
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
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        platform::set_memory_limit_mib(self.memory_limit_mib);
        Ok(())
    }
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

    #[test]
    fn test_other_controllers_are_refused() {
        for (v, p) in [
            (1, "cpuset.cpus=0"),
            (1, "cpu.shares=10"),
            (2, "cpu.max=50000 100000"),
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
