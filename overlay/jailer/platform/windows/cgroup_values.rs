// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! How cgroup values become Job Object values, and what a parent cgroup
//! makes of a jail's: the arithmetic alone, without a Windows call, so that
//! the jailer (`cgroup`, `platform::parent`) and the operator's tool for a
//! parent (tools/windows/jail-parent.rs, which includes this file by path)
//! read a value the same way.

/// The default CFS period, as Linux's.
pub const DEFAULT_PERIOD_US: u64 = 100_000;

/// A value as Linux's cgroup files take it: they strip the white space
/// around what is written before they parse it (`strstrip`, lib/string.c,
/// in each write handler named at `cgroup::no_limit`; the kernel's `isspace`
/// is the C locale's, U+00A0 besides, which no value here holds).
pub fn strstrip(value: &str) -> &str {
    value.trim_matches(|c| matches!(c, ' ' | '\t'..='\r'))
}

/// The numbers of a cpuset list (`0-3,8,10-11`), sorted, without repeats.
pub fn parse_list(list: &str) -> Result<Vec<u32>, &'static str> {
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
pub fn cpu_groups(cpus: &[u32], group_sizes: &[u32]) -> Result<Vec<(u16, u64)>, &'static str> {
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

/// The job CPU rate (hundredths of a percent of all `cpus`) for a cgroup
/// quota of `quota` microseconds per `period`: `quota / period` CPUs. Rounded
/// down, so the cap is at or below the one asked for.
pub fn cpu_rate(quota: u64, period: u64, cpus: u64) -> Result<u32, &'static str> {
    if period == 0 {
        return Err("a period of 0");
    }
    let rate = u128::from(quota) * 10_000 / (u128::from(period) * u128::from(cpus.max(1)));
    if rate == 0 {
        return Err("below the 0.01% of the host's CPUs a job can be capped at");
    }
    Ok(u32::try_from(rate.min(10_000)).unwrap())
}

// ---- A parent cgroup ----
//
// On Linux a jail's cgroup is `<base>/<parent>/<id>` (upstream's cgroup.rs,
// `CgroupV1::new`, `CgroupV2::new`). On Windows the parent is a named Job
// Object and the jail's job is nested in it (`platform::parent`). What the
// parent's own values make of the jail's is the kernel's rule on Linux and
// is computed here, because a nested job is given its values relative to
// its parent's or narrowed without a word.

/// The prefix of a parent's job name, in the session's object namespace.
pub const PARENT_JOB_PREFIX: &str = "Local\\wick-cgroup-";

/// Why a parent of more than one path component is refused.
pub const PARENT_ONE_LEVEL: &str = "not done yet: a parent cgroup of one name is a Job Object that holds the \
    jails' jobs; a path of several (a/b), each a job in the one before, is not built";

/// The name of the Job Object that is the parent cgroup `parent`: one path
/// component (upstream has refused `.`, `..` and a leading `/` before this
/// is asked: env.rs, `CgroupInvalidParentPath`). An object name ends at a
/// backslash, and a parent of several components is a job in a job, which
/// is not built: both refused.
pub fn parent_job_name(parent: &str) -> Result<String, &'static str> {
    if parent.is_empty() {
        return Err("an empty name");
    }
    if parent.contains(['/', '\\']) {
        return Err(PARENT_ONE_LEVEL);
    }
    Ok(format!("{PARENT_JOB_PREFIX}{parent}"))
}

/// Why cgroup v1 refuses a cpuset that is not within its parent's.
pub const CPUS_OUTSIDE_PARENT: &str = "CPUs outside the parent cgroup's (a cgroup v1 cpuset must be a subset \
    of its parent's: the write fails with EACCES on Linux)";

/// The processors a jail runs on when it asks for `asked` under a parent
/// that has `parent` (each `(group, mask)`), as Linux v6.1 decides it
/// (kernel/cgroup/cpuset.c):
///
/// - cgroup v1: `asked` must be within the parent's, or the write of
///   `cpuset.cpus` fails with `EACCES` (`validate_change_legacy`: "On legacy
///   hierarchy, we must be a subset of our parent cpuset");
/// - cgroup v2: any list is taken, and the cgroup runs on those of its
///   CPUs its parent has (`compute_effective_cpumask`: `cpus_allowed` and
///   the parent's `effective_cpus`), or on all of the parent's when it has
///   none of them (`update_cpumasks_hier`: "If it becomes empty, inherit
///   the effective mask of the parent").
///
/// Windows gives a job under a parent the same processors as the v2 rule
/// without an error in either case (measured, Windows Server 2025 build
/// 26100: `test_nested_jobs_on_record`), so the v1 refusal is made here,
/// and the v2 set is computed here and given to the job as it is.
pub fn cpus_under_parent(version: u8, asked: &[(u16, u64)], parent: &[(u16, u64)]) -> Result<Vec<(u16, u64)>, &'static str> {
    let of_parent = |group: u16| parent.iter().filter(|(g, _)| *g == group).fold(0u64, |m, (_, mask)| m | mask);
    if version == 1 {
        if asked.iter().any(|&(group, mask)| mask & !of_parent(group) != 0) {
            return Err(CPUS_OUTSIDE_PARENT);
        }
        return Ok(asked.to_vec());
    }
    let common: Vec<(u16, u64)> =
        asked.iter().map(|&(group, mask)| (group, mask & of_parent(group))).filter(|&(_, mask)| mask != 0).collect();
    Ok(if common.is_empty() { parent.to_vec() } else { common })
}

/// Why cgroup v1 refuses a CPU quota above its parent's.
pub const RATE_ABOVE_PARENT: &str = "a CPU quota above the parent cgroup's (cgroup v1 refuses it: the write \
    fails with EINVAL on Linux)";

/// The CPU rate of a jail's job under a parent whose hard cap is `parent`,
/// for a jail that asks for `asked` (both in hundredths of a percent of the
/// host's processors, as [`cpu_rate`] gives them), as Linux v6.1 decides it
/// (kernel/sched/core.c, `tg_cfs_schedulable_down`: "Ensure
/// max(child_quota) <= parent_quota. On cgroup2, always take the min. On
/// cgroup1, only inherit when no limit is set", and a quota above the
/// parent's is `-EINVAL` there).
///
/// A nested job's rate is "its portion of the CPU rate that is allocated to
/// its parent job" (Microsoft Learn, `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`),
/// where a cgroup's quota is of the host whatever its parent's: so the
/// rate given to the job is the jail's share of the parent's, rounded down
/// and never 0.
pub fn rate_under_parent(version: u8, asked: u32, parent: u32) -> Result<u32, &'static str> {
    if parent == 0 {
        return Err("a parent cgroup with a CPU rate of 0");
    }
    if version == 1 && asked > parent {
        return Err(RATE_ABOVE_PARENT);
    }
    let share = u64::from(asked.min(parent)) * 10_000 / u64::from(parent);
    Ok(u32::try_from(share.clamp(1, 10_000)).unwrap())
}

/// The lowest integrity level a parent's job may carry: medium
/// (`SECURITY_MANDATORY_MEDIUM_RID`). A jailed process runs below it
/// (0x1800), and what it creates is labelled with its level.
pub const MEDIUM_INTEGRITY: u32 = 0x2000;

/// Whether a parent's job is one to trust: owned by the jailer's own
/// account (`mine`: its user and its token's owner), by the administrators
/// or by the system, and not labelled below medium integrity (`label`:
/// `None` for an object without a label, which is medium). A job a jailed
/// process made under the parent's name, to have later jails join a job of
/// its own, has that process's level as its label.
pub fn trusted_parent(owner: &str, label: Option<u32>, mine: &[String]) -> Result<(), String> {
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const SYSTEM: &str = "S-1-5-18";
    if let Some(level) = label.filter(|&level| level < MEDIUM_INTEGRITY) {
        return Err(format!(
            "its job has the integrity level {level:#x}, below medium ({MEDIUM_INTEGRITY:#x}): it was not made by \
             the operator (a jailed process runs at 0x1800)"
        ));
    }
    if owner != ADMINISTRATORS && owner != SYSTEM && !mine.iter().any(|sid| sid == owner) {
        return Err(format!("its job is owned by {owner}, not by this account, the administrators or the system"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parent_job_name() {
        assert_eq!(parent_job_name("tenants").unwrap(), "Local\\wick-cgroup-tenants");
        assert_eq!(parent_job_name("firecracker").unwrap(), "Local\\wick-cgroup-firecracker");
        assert_eq!(parent_job_name("a/b").unwrap_err(), PARENT_ONE_LEVEL);
        assert_eq!(parent_job_name("a\\b").unwrap_err(), PARENT_ONE_LEVEL);
        assert_eq!(parent_job_name("").unwrap_err(), "an empty name");
    }

    // Linux's rules for a cpuset under its parent's: v1 refuses what is not
    // a subset; v2 takes any list and runs on the common processors, or on
    // the parent's when there is none.
    #[test]
    fn test_cpus_under_a_parent_are_linuxs() {
        let parent = [(0u16, 0b0011u64)];
        // Within the parent's: as asked, both versions.
        for version in [1, 2] {
            assert_eq!(cpus_under_parent(version, &[(0, 0b01)], &parent).unwrap(), [(0, 0b01)]);
            assert_eq!(cpus_under_parent(version, &[(0, 0b11)], &parent).unwrap(), [(0, 0b11)]);
        }
        // Wider, or apart: v1 EACCES; v2 the common ones, or the parent's.
        assert_eq!(cpus_under_parent(1, &[(0, 0b0111)], &parent).unwrap_err(), CPUS_OUTSIDE_PARENT);
        assert_eq!(cpus_under_parent(1, &[(0, 0b0100)], &parent).unwrap_err(), CPUS_OUTSIDE_PARENT);
        assert_eq!(cpus_under_parent(2, &[(0, 0b0111)], &parent).unwrap(), [(0, 0b0011)]);
        assert_eq!(cpus_under_parent(2, &[(0, 0b0110)], &parent).unwrap(), [(0, 0b0010)]);
        assert_eq!(cpus_under_parent(2, &[(0, 0b0100)], &parent).unwrap(), parent);
        // Another processor group than the parent's.
        assert_eq!(cpus_under_parent(1, &[(1, 0b1)], &parent).unwrap_err(), CPUS_OUTSIDE_PARENT);
        assert_eq!(cpus_under_parent(2, &[(1, 0b1)], &parent).unwrap(), parent);
        assert_eq!(cpus_under_parent(2, &[(0, 0b1), (1, 0b1)], &[(0, 0b1), (1, 0b10)]).unwrap(), [(0, 0b1)]);
        assert_eq!(cpus_under_parent(1, &[(0, 0b1), (1, 0b10)], &[(0, 0b1), (1, 0b10)]).unwrap(), [(0, 0b1), (1, 0b10)]);
    }

    // Linux's rule for a CPU quota under its parent's, as the share of the
    // parent's rate a nested job is given.
    #[test]
    fn test_cpu_rate_under_a_parent_is_linuxs() {
        // Half a host under a parent of a whole host: half of the parent's.
        assert_eq!(rate_under_parent(2, 5000, 10_000).unwrap(), 5000);
        // A quarter of the host under a parent of half: half of the parent's.
        for version in [1, 2] {
            assert_eq!(rate_under_parent(version, 2500, 5000).unwrap(), 5000);
            assert_eq!(rate_under_parent(version, 5000, 5000).unwrap(), 10_000);
        }
        // Above the parent's: v2 the parent's, all of it; v1 EINVAL.
        assert_eq!(rate_under_parent(2, 7500, 5000).unwrap(), 10_000);
        assert_eq!(rate_under_parent(1, 7500, 5000).unwrap_err(), RATE_ABOVE_PARENT);
        // Rounded down, and never no rate at all.
        assert_eq!(rate_under_parent(2, 1, 3).unwrap(), 3333);
        assert_eq!(rate_under_parent(2, 1, 10_000).unwrap(), 1);
        rate_under_parent(2, 1, 0).unwrap_err();
    }

    #[test]
    fn test_a_parent_job_of_a_jail_is_not_trusted() {
        let mine = ["S-1-5-21-1-2-3-1001".to_string()];
        trusted_parent("S-1-5-21-1-2-3-1001", None, &mine).unwrap();
        trusted_parent("S-1-5-21-1-2-3-1001", Some(0x2000), &mine).unwrap();
        trusted_parent("S-1-5-32-544", Some(0x3000), &mine).unwrap();
        trusted_parent("S-1-5-18", None, &mine).unwrap();
        // A jail's process has the user as its token's owner and runs at
        // 0x1800: the label tells its job from the operator's.
        let jail = trusted_parent("S-1-5-21-1-2-3-1001", Some(0x1800), &mine).unwrap_err();
        assert!(jail.contains("integrity level 0x1800, below medium"), "{jail}");
        assert!(trusted_parent("S-1-5-21-1-2-3-1001", Some(0x1000), &mine).is_err());
        let other = trusted_parent("S-1-5-21-1-2-3-1002", None, &mine).unwrap_err();
        assert!(other.contains("owned by S-1-5-21-1-2-3-1002"), "{other}");
    }
}
