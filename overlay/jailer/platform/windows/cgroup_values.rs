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
// Object and the jail's job is nested in it (`platform::parent`); a parent
// of several levels (`a/b`) is a job for each, `a/b`'s nested in `a`'s. What
// the values of the levels above make of a level's, or of the jail's, is the
// kernel's rule on Linux and is computed here, because a nested job is given
// its values relative to its parent's or narrowed without a word:
//
// - memory: a charge is made to the cgroup and to every ancestor, and fails
//   at the first that is over its limit (Linux v6.1 mm/page_counter.c,
//   `page_counter_try_charge`: `for (c = counter; c; c = c->parent)`), so
//   the least limit along the path holds, and no limit is refused for being
//   above its parent's. A nested job is held by each job above it the same
//   way (Microsoft Learn, "Nested Jobs"): nothing is computed;
// - the CPU quota and the cpuset: [`rate_under_levels`], [`cpus_under_parent`],
//   against what the levels above come to (exactly, for the rate:
//   [`exact_rate`]; [`cpus_of_levels`]).

/// The private namespace of the parent cgroups' jobs: its name, which is
/// also the name of its boundary. The boundary holds the account's SID and
/// the medium integrity level ([`MEDIUM_INTEGRITY`]): "A process can create
/// a private namespace only with an integrity level that is equal to or
/// lower than the current integrity level of the process", and "would
/// usually specify a namespace at the same integrity level as the process
/// for protection against squatting attacks by lower integrity-level
/// processes" (Microsoft Learn, `AddIntegrityLabelToBoundaryDescriptor`). A
/// jailed process runs below medium: it makes no namespace of this
/// boundary, and the namespace's own security descriptor
/// ([`parent_namespace_sddl`]) keeps it from opening the one that is there
/// ("a process can open an existing namespace even if it is not within the
/// boundary unless the creator restricted access to the namespace":
/// Microsoft Learn, "Object Namespaces"). In the session's own namespace
/// (`Local\`), where a parent's job was first, whoever may make an object
/// there may take a parent's name before the operator does.
pub const PARENT_NAMESPACE: &str = "wick-cgroup";

/// The security descriptor of the namespace and of each job in it: the
/// system and the account, nothing inherited from above, and a medium label
/// that lets nothing below it read or write. A jail's token is restricted
/// to SIDs this grants nothing, and is below medium.
pub fn parent_namespace_sddl(user: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})S:(ML;;NWNRNX;;;ME)")
}

/// The prefix of a parent's job name: in the private namespace.
pub const PARENT_JOB_PREFIX: &str = "wick-cgroup\\";

/// The names of the Job Objects that are the parent cgroup `parent`, one
/// for each level of its path, the top first: `a/b` is `...-a` and
/// `...-a/b` (upstream has refused `.`, `..` and a leading `/` before this
/// is asked: env.rs, `CgroupInvalidParentPath`). Both separators part
/// levels, as in a path on Windows; an object's name ends at a backslash,
/// so the levels of a name are joined with `/`.
pub fn parent_job_names(parent: &str) -> Result<Vec<String>, &'static str> {
    let mut names = Vec::new();
    let mut path = String::new();
    for level in parent.split(['/', '\\']).filter(|level| !level.is_empty()) {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(level);
        names.push(format!("{PARENT_JOB_PREFIX}{path}"));
    }
    if names.is_empty() {
        return Err("an empty name");
    }
    Ok(names)
}

/// Why a share under a parent cannot be computed: the levels' caps make a
/// fraction whose terms do not fit in 128 bits. Eight capped levels never
/// do (a share's largest term is 10000 to the ninth power, below 2^128);
/// more can, when their caps share no factor with 10000.
pub const RATE_TOO_DEEP: &str = "CPU caps on more levels above than the share under them can be computed exactly for";

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// What the levels of a parent come to, exactly, from each level's own
/// hard cap, the top first (`None`: a level without one): `num / den`
/// hundredths of a percent of the host's processors, in lowest terms;
/// `None` when no level has a cap. A job's rate is a share of what the
/// job above it has, so the levels multiply: a level of 4166 under one of
/// 6000 comes to 2499.6, which neither 2499 nor 2500 is.
fn exact_rate(caps: &[Option<u32>]) -> Result<Option<(u128, u128)>, &'static str> {
    let mut rate: Option<(u128, u128)> = None;
    for &cap in caps.iter().flatten() {
        let (num, den) = match rate {
            None => (u128::from(cap), 1),
            Some((num, den)) => (
                num.checked_mul(u128::from(cap)).ok_or(RATE_TOO_DEEP)?,
                den.checked_mul(10_000).ok_or(RATE_TOO_DEEP)?,
            ),
        };
        let g = gcd(num, den).max(1);
        rate = Some((num / g, den / g));
    }
    Ok(rate)
}

/// The CPU rate, of the host's processors, that the levels of a parent come
/// to, from each level's own hard cap, the top first (`None`: a level
/// without one): the product of the shares ([`exact_rate`]), rounded down
/// once; on Linux it is the cgroup's `hierarchical_quota`
/// (kernel/sched/core.c, `tg_cfs_schedulable_down`). `None` when no level
/// has a cap. What a job below is given is computed against the exact
/// product ([`rate_under_levels`]), not against this.
pub fn rate_of_levels(caps: &[Option<u32>]) -> Result<Option<u32>, &'static str> {
    Ok(exact_rate(caps)?.map(|(num, den)| u32::try_from((num / den).min(10_000)).unwrap()))
}

/// The processors the levels of a parent come to, from each level's own
/// (`None`: Windows reported none for it), the top first: each level within
/// the one above by the cgroup v2 rule, which is also what Windows gives a
/// nested job ([`cpus_under_parent`]). A level made by the operator's tool
/// has its set computed against the levels above already, cgroup v1's
/// refusal made then.
pub fn cpus_of_levels(levels: &[Option<Vec<(u16, u64)>>]) -> Option<Vec<(u16, u64)>> {
    let mut cpus: Option<Vec<(u16, u64)>> = None;
    for level in levels.iter().flatten() {
        cpus = Some(match &cpus {
            None => level.clone(),
            Some(above) => cpus_under_parent(2, level, above).expect("the cgroup v2 rule refuses nothing"),
        });
    }
    cpus
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
    rate_under_levels(version, asked, &[Some(parent)])
}

/// [`rate_under_parent`] under the levels whose hard caps are `caps`, the
/// top first (`None`: a level without one): `asked` itself when no level
/// has a cap. The share is that of what the levels come to exactly
/// ([`exact_rate`]), rounded down: the most a nested job can be given
/// without the product of the shares down to it going above `asked`.
/// Against the levels' product rounded down first (2499 for 2499.6) the
/// share came out above it (1250 of the host gave 5002 of 2499, which is
/// 1250.3 of the host under 6000 and 4166; CI run 43403250054, jail-parent's
/// `test_a_write_to_a_level_reaches_the_processes_running_below`).
///
/// cgroup v1's refusal compares `asked` with the parent's quota, which the
/// levels' product is within one hundredth of a percent below when each
/// level was given its share by this rule: so a quota is above the
/// parent's when it is above the product rounded up.
pub fn rate_under_levels(version: u8, asked: u32, caps: &[Option<u32>]) -> Result<u32, &'static str> {
    let Some((num, den)) = exact_rate(caps)? else { return Ok(asked) };
    if num == 0 {
        return Err("a parent cgroup with a CPU rate of 0");
    }
    let asked_den = u128::from(asked).checked_mul(den).ok_or(RATE_TOO_DEEP)?;
    if version == 1 && asked_den - den >= num {
        return Err(RATE_ABOVE_PARENT);
    }
    let share = if asked_den >= num { 10_000 } else { asked_den.checked_mul(10_000).ok_or(RATE_TOO_DEEP)? / num };
    Ok(u32::try_from(share.clamp(1, 10_000)).unwrap())
}

// ---- A write to a level that is there ----
//
// On Linux a write to a cgroup's `cpu.max` or `cpuset.cpus` is taken at any
// time and the kernel works out again what every cgroup below has
// (kernel/sched/core.c, `tg_set_cfs_bandwidth` walks the tree with
// `tg_cfs_schedulable_down`; kernel/cgroup/cpuset.c, `update_cpumasks_hier`).
// A job under another holds a number worked out once: its rate as a share
// of the job above, its processors already within those above. So whoever
// writes a level writes every job below it again, from what each was asked
// for, which is kept beside each job (`Asked`, in a section named after the
// job), and finds the jobs below by the names in the namespace: a jail's
// job under a parent is named `<level>//<id>` there.

/// What a job, a level's or a jail's, was asked for, in Linux's terms: the
/// CPU rate of the host's processors and the processors, before the levels
/// above made anything of them, and the cgroup version whose rule applies.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Asked {
    pub version: u8,
    pub rate: Option<u32>,
    pub cpus: Option<Vec<(u16, u64)>>,
}

/// The size of the section that keeps an [`Asked`].
pub const ASKED_BYTES: usize = 4096;
const ASKED_MAGIC: &[u8; 4] = b"WCG1";

impl Asked {
    /// The bytes kept in the section: a mark, the version, the rate if
    /// there is one, and the processors by group.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = ASKED_MAGIC.to_vec();
        out.push(self.version);
        out.push(u8::from(self.rate.is_some()));
        out.extend(self.rate.unwrap_or(0).to_le_bytes());
        let cpus = self.cpus.as_deref().unwrap_or(&[]);
        out.push(u8::from(self.cpus.is_some()));
        out.extend(u16::try_from(cpus.len()).unwrap().to_le_bytes());
        for &(group, mask) in cpus {
            out.extend(group.to_le_bytes());
            out.extend(mask.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Asked, &'static str> {
        const BAD: &str = "what the job was asked for, kept beside it, is not readable";
        if bytes.len() < 13 || &bytes[..4] != ASKED_MAGIC || !matches!(bytes[4], 1 | 2) {
            return Err(BAD);
        }
        let rate = (bytes[5] != 0).then(|| u32::from_le_bytes(bytes[6..10].try_into().unwrap()));
        let count = usize::from(u16::from_le_bytes(bytes[11..13].try_into().unwrap()));
        let groups = bytes.get(13..13 + count * 10).ok_or(BAD)?;
        let cpus: Vec<(u16, u64)> = groups
            .chunks_exact(10)
            .map(|g| (u16::from_le_bytes(g[..2].try_into().unwrap()), u64::from_le_bytes(g[2..].try_into().unwrap())))
            .collect();
        Ok(Asked { version: bytes[4], rate, cpus: (bytes[10] != 0).then_some(cpus) })
    }
}

/// The name of a jail's job under the parent level whose job is `level`.
/// No level's name holds `//` ([`parent_job_names`]), and a jail's id is
/// letters, digits and hyphens (upstream's `validate_instance_id`).
pub fn jail_job_name(level: &str, id: &str) -> String {
    format!("{level}//{id}")
}

/// The name of the section that keeps what the job `job` was asked for.
pub fn asked_name(job: &str) -> String {
    if job.contains("//") { format!("{job}#values") } else { format!("{job}//#values") }
}

/// The name of the mutex that whoever reads the levels to give a job its
/// values, or writes a level, holds meanwhile.
pub fn parent_lock_name() -> String {
    format!("{PARENT_JOB_PREFIX}//lock")
}

/// What a job holds: the CPU rate as Windows has it (of the host's
/// processors for a job under none with a cap, a share of the job above
/// otherwise) and its processors; `None`, none of its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Held {
    pub rate: Option<u32>,
    pub cpus: Option<Vec<(u16, u64)>>,
}

/// What the levels above a job come to: the hard cap of each, the top
/// first (`None`: a level without one), whose product is taken exactly
/// ([`rate_under_levels`]), and their processors (`cpus_of_levels`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Above {
    pub caps: Vec<Option<u32>>,
    pub cpus: Option<Vec<(u16, u64)>>,
}

/// A job below the level that is written: its name, what it was asked for
/// and what it holds now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Below {
    pub name: String,
    pub asked: Asked,
    pub now: Held,
}

/// One write to a job: the level's own is job 0, `below[i]` is job `i + 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The CPU rate hard cap; `None` takes it off.
    Rate(usize, Option<u32>),
    Cpus(usize, Vec<(u16, u64)>),
}

/// The name of the job above `name`: a jail's level, or the level above.
fn above_of(name: &str) -> Option<&str> {
    name.rsplit_once("//").or_else(|| name.rsplit_once('/')).map(|(above, _)| above)
}

fn cpus_union(a: &[(u16, u64)], b: &[(u16, u64)]) -> Vec<(u16, u64)> {
    let mut out = a.to_vec();
    for &(group, mask) in b {
        match out.iter_mut().find(|(g, _)| *g == group) {
            Some((_, m)) => *m |= mask,
            None => out.push((group, mask)),
        }
    }
    out.sort_unstable();
    out
}

/// The writes that give the level `name` what it is now asked for and every
/// job below it what Linux would give it then, in an order in which no job
/// has, at any moment, more than Linux gave it before or gives it after.
/// `above`: what the levels above come to. `now`: what the level's job
/// holds.
///
/// What each job is to hold is worked out from the top down, each against
/// what the jobs above it come to, by the rule of its own cgroup version
/// ([`rate_under_parent`], [`cpus_under_parent`]). Where cgroup v1 refuses
/// a job below (a quota above the new one: `tg_cfs_schedulable_down`,
/// `-EINVAL`; processors outside the new ones: `validate_change_legacy`,
/// "Each of our child cpusets must be a subset of us", `-EBUSY`), Linux
/// fails the write to the level, and so does this.
///
/// The order, derived. A job's rate is a share of the job above's, so what
/// it gets is the product of the shares down to it; and Windows keeps, or
/// may keep, a job's processors within the job above's.
///
/// 1. Every job, the top first, is written the lower of the share it holds
///    and the share it is to hold. Each write lowers one factor of some
///    products and raises none: every job has at most what it had.
/// 2. Every job is written the share it is to hold. Each write raises one
///    factor to its final value, and every factor is at or below its final
///    value: every job has at most what it is to have.
///
/// For the processors, a set cannot go through "the lower of the two" (two
/// sets may have nothing in common), so:
///
/// 1. every job, the top first, is written the processors it holds and
///    those it is to hold together: each stays within the job above, which
///    was widened before it;
/// 2. every job, the lowest first, is written those it is to hold: each
///    stays within the job above, which still has both.
///
/// A set that only narrows, or only widens, is never wider than Linux gave
/// before or gives after; one that moves has both for the time between the
/// two passes, and never a processor that is in neither.
pub fn rewrite(above: &Above, name: &str, asked: &Asked, now: &Held, below: &[Below]) -> Result<(Vec<Step>, Vec<Held>), String> {
    // The jobs, the level first, each after the job above it.
    let mut jobs: Vec<(&str, &Asked, &Held)> = vec![(name, asked, now)];
    jobs.extend(below.iter().map(|b| (b.name.as_str(), &b.asked, &b.now)));
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    order.sort_by_key(|&i| (jobs[i].0.len(), i));
    if order[0] != 0 {
        return Err(format!("{}: not a job below {name}", jobs[order[0]].0));
    }
    // What each job is to hold, and what it then comes to with those above.
    let mut held: Vec<Held> = vec![Held::default(); jobs.len()];
    let mut comes_to: Vec<Above> = vec![Above::default(); jobs.len()];
    for &i in &order {
        let (job, asked, _) = jobs[i];
        let up = if i == 0 {
            above.clone()
        } else {
            let parent = above_of(job).and_then(|p| jobs.iter().position(|(n, ..)| *n == p));
            let parent = parent.ok_or_else(|| format!("{job}: the job above it is not among those below {name}"))?;
            comes_to[parent].clone()
        };
        let refused = |why: &str| {
            if i == 0 { format!("{job}: {why}") } else { format!("{job}, below {name}: {why} (Linux fails the write to the level above)") }
        };
        held[i].rate = match asked.rate {
            None => None,
            Some(rate) => Some(rate_under_levels(asked.version, rate, &up.caps).map_err(&refused)?),
        };
        held[i].cpus = match (&asked.cpus, &up.cpus) {
            (None, _) => None,
            (Some(cpus), None) => Some(cpus.clone()),
            (Some(cpus), Some(up)) => Some(cpus_under_parent(asked.version, cpus, up).map_err(&refused)?),
        };
        let mut caps = up.caps;
        caps.push(held[i].rate);
        comes_to[i] = Above { caps, cpus: held[i].cpus.clone().or(up.cpus) };
    }
    // What each job holds as the writes go.
    let same = |a: &Option<Vec<(u16, u64)>>, b: &Option<Vec<(u16, u64)>>| a.as_ref().map(|c| cpus_union(c, &[])) == b.as_ref().map(|c| cpus_union(c, &[]));
    let mut steps = Vec::new();
    let mut has: Vec<Held> = jobs.iter().map(|(_, _, now)| (*now).clone()).collect();
    for &i in &order {
        // The lower of the two shares; no cap at all is the highest, and a
        // cap that is to be taken off stays until the second pass.
        let lower = match (has[i].rate, held[i].rate) {
            (Some(now), Some(to)) => Some(now.min(to)),
            (now, to) => now.or(to),
        };
        if lower != has[i].rate {
            steps.push(Step::Rate(i, lower));
            has[i].rate = lower;
        }
        if let (Some(now), Some(to)) = (&has[i].cpus, &held[i].cpus) {
            let both = Some(cpus_union(now, to));
            if !same(&both, &has[i].cpus) {
                steps.push(Step::Cpus(i, both.clone().unwrap()));
                has[i].cpus = both;
            }
        }
    }
    for &i in order.iter().rev() {
        if has[i].rate != held[i].rate {
            steps.push(Step::Rate(i, held[i].rate));
        }
        match &held[i].cpus {
            Some(to) if !same(&has[i].cpus, &held[i].cpus) => steps.push(Step::Cpus(i, to.clone())),
            _ => {}
        }
    }
    Ok((steps, held))
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
    fn test_parent_job_names() {
        let p = PARENT_JOB_PREFIX;
        assert_eq!(parent_job_names("tenants").unwrap(), [format!("{p}tenants")]);
        // Upstream's own test names a parent of two levels.
        let two = [format!("{p}custom_cgroup"), format!("{p}custom_cgroup/group2")];
        assert_eq!(parent_job_names("custom_cgroup/group2").unwrap(), two);
        assert_eq!(parent_job_names("custom_cgroup\\group2").unwrap(), two);
        assert_eq!(parent_job_names("custom_cgroup//group2/").unwrap(), two);
        assert_eq!(parent_job_names("a/b/c").unwrap().len(), 3);
        assert_eq!(parent_job_names("").unwrap_err(), "an empty name");
        assert_eq!(parent_job_names("/").unwrap_err(), "an empty name");
        // In the private namespace, whose name the prefix starts with.
        assert_eq!(p, format!("{PARENT_NAMESPACE}\\"));
        assert_eq!(parent_namespace_sddl("S-1-5-21-1-2-3-1001"), "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1001)S:(ML;;NWNRNX;;;ME)");
    }

    // What the levels above come to: the rates multiply (each a share of
    // the one above), the processors narrow.
    #[test]
    fn test_levels_come_to_linuxs_hierarchical_values() {
        assert_eq!(rate_of_levels(&[]), Ok(None));
        assert_eq!(rate_of_levels(&[None, None]), Ok(None));
        assert_eq!(rate_of_levels(&[Some(5000)]), Ok(Some(5000)));
        // Half the host, then half of that: a quarter of the host.
        assert_eq!(rate_of_levels(&[Some(5000), Some(5000)]), Ok(Some(2500)));
        assert_eq!(rate_of_levels(&[None, Some(5000), None, Some(10_000)]), Ok(Some(5000)));
        // A hundredth of a percent of a hundredth: rounded down once.
        assert_eq!(rate_of_levels(&[Some(1), Some(1)]), Ok(Some(0)));
        // A level asked for a quarter of the host under one of half is
        // given half of it (`rate_under_parent`), and the two come to the
        // quarter again: a jail under them is measured against that.
        let level = rate_under_parent(2, 2500, 5000).unwrap();
        assert_eq!(rate_of_levels(&[Some(5000), Some(level)]), Ok(Some(2500)));
        assert_eq!(rate_under_levels(1, 1250, &[Some(5000), Some(level)]).unwrap(), 5000);
        assert_eq!(rate_under_levels(1, 5000, &[Some(5000), Some(level)]).unwrap_err(), RATE_ABOVE_PARENT);
        assert_eq!(rate_under_levels(1, 1250, &[None, None]).unwrap(), 1250, "no level with a cap: the jail's own");
        // Under 6000, a level asked for 2500 is given 4166, and the two
        // come to 2499.6 of the host: a jail asked for 1250 is given 5000,
        // which is 1249.8 of it; 5001 would be 1250.05. Rounded down
        // first, the levels came to 2499 and the jail was given 5002, which
        // is 1250.3 (CI run 43403250054).
        let level = rate_under_parent(2, 2500, 6000).unwrap();
        assert_eq!(level, 4166);
        assert_eq!(rate_of_levels(&[Some(6000), Some(level)]), Ok(Some(2499)));
        assert_eq!(rate_under_levels(2, 1250, &[Some(6000), Some(level)]).unwrap(), 5000);
        assert_eq!(rate_under_parent(2, 1250, 2499).unwrap(), 5002);
        // cgroup v1: the level's own 2500 is not above it, 2501 is.
        assert_eq!(rate_under_levels(1, 2500, &[Some(6000), Some(level)]).unwrap(), 10_000);
        assert_eq!(rate_under_levels(1, 2501, &[Some(6000), Some(level)]).unwrap_err(), RATE_ABOVE_PARENT);
        // More levels than 128 bits hold the product of, without a common
        // factor with 10000: refused, not rounded.
        assert_eq!(rate_under_levels(2, 1, &[Some(9999); 10]).unwrap_err(), RATE_TOO_DEEP);

        assert_eq!(cpus_of_levels(&[]), None);
        assert_eq!(cpus_of_levels(&[None]), None);
        assert_eq!(cpus_of_levels(&[Some(vec![(0, 0b1111)]), None, Some(vec![(0, 0b0110)])]), Some(vec![(0, 0b0110)]));
        // A level without a limit of its own reads as every processor.
        assert_eq!(cpus_of_levels(&[Some(vec![(0, 0b0011)]), Some(vec![(0, 0b1111)])]), Some(vec![(0, 0b0011)]));
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
    fn test_what_a_job_was_asked_for_is_kept_whole() {
        for asked in [
            Asked { version: 2, rate: None, cpus: None },
            Asked { version: 1, rate: Some(2500), cpus: Some(vec![(0, 0b1010), (3, u64::MAX)]) },
            Asked { version: 2, rate: Some(10_000), cpus: Some(vec![]) },
        ] {
            let mut section = asked.encode();
            section.resize(ASKED_BYTES, 0);
            assert_eq!(Asked::decode(&section).unwrap(), asked);
        }
        // A section nobody wrote does not read as asked for nothing.
        Asked::decode(&[0; ASKED_BYTES]).unwrap_err();
        Asked::decode(b"WCG1").unwrap_err();
        let p = PARENT_JOB_PREFIX;
        assert_eq!(jail_job_name(&format!("{p}a/b"), "vm-1"), format!("{p}a/b//vm-1"));
        assert_eq!(asked_name(&format!("{p}a/b")), format!("{p}a/b//#values"));
        assert_eq!(asked_name(&format!("{p}a/b//vm-1")), format!("{p}a/b//vm-1#values"));
        assert_eq!(parent_lock_name(), format!("{p}//lock"));
        assert_eq!(above_of("a/b//vm-1"), Some("a/b"));
        assert_eq!(above_of("a/b"), Some("a"));
        assert_eq!(above_of("a"), None);
    }

    // What Linux gives a cgroup, from what each on the path was asked for
    // (cgroup v2): the lowest quota, and the processors in common with
    // those above, or those above's.
    fn linux(above: &Held, name: &str, asked: &Asked, below: &[Below]) -> Vec<Held> {
        // `above`: the levels above as Linux has them (their lowest quota).
        let mut names = vec![(name, asked)];
        names.extend(below.iter().map(|b| (b.name.as_str(), &b.asked)));
        names
            .iter()
            .map(|(job, _)| {
                let mut has = above.clone();
                for (other, asked) in &names {
                    if *job == *other || job.starts_with(&format!("{other}/")) {
                        has.rate = match (has.rate, asked.rate) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, b) => a.or(b),
                        };
                        has.cpus = match (&has.cpus, &asked.cpus) {
                            (Some(up), Some(cpus)) => Some(cpus_under_parent(2, cpus, up).unwrap()),
                            (up, cpus) => cpus.clone().or_else(|| up.clone()),
                        };
                    }
                }
                has
            })
            .collect()
    }

    // What every job has while the jobs hold `held`: the shares down to it
    // (their product, exactly: `exact_rate`), and its processors within
    // those above.
    fn windows(above: &Above, names: &[&str], held: &[Held]) -> Vec<Above> {
        names
            .iter()
            .map(|job| {
                let mut has = above.clone();
                let mut path: Vec<usize> = (0..names.len()).filter(|&i| *job == names[i] || job.starts_with(&format!("{}/", names[i]))).collect();
                path.sort_by_key(|&i| names[i].len());
                for i in path {
                    has.caps.push(held[i].rate);
                    if let Some(cpus) = &held[i].cpus {
                        if let Some(up) = &has.cpus {
                            assert_eq!(cpus_under_parent(1, cpus, up).as_deref(), Ok(cpus.as_slice()), "{job}: {cpus:x?} is not within the job above's {up:x?}");
                        }
                        has.cpus = Some(cpus.clone());
                    }
                }
                has
            })
            .collect()
    }

    fn within(cpus: &Option<Vec<(u16, u64)>>, a: &Option<Vec<(u16, u64)>>, b: &Option<Vec<(u16, u64)>>) -> bool {
        match (cpus, a, b) {
            (Some(cpus), Some(a), Some(b)) => cpus_under_parent(1, cpus, &cpus_union(a, b)).is_ok(),
            (None, Some(_), Some(_)) => false,
            _ => true,
        }
    }

    // Whether shares whose product is `caps` come to at most `most`
    // hundredths of a percent of the host, and to more than `least`.
    fn at_most(caps: &[Option<u32>], most: u32) -> bool {
        exact_rate(caps).unwrap().is_none_or(|(num, den)| num <= u128::from(most) * den)
    }
    fn above_least(caps: &[Option<u32>], least: u32) -> bool {
        exact_rate(caps).unwrap().is_some_and(|(num, den)| num > u128::from(least) * den)
    }

    // The order of the writes: at every write no job has more CPU than
    // Linux gave it before or gives it after, nor a processor Linux gave it
    // neither before nor after, nor processors outside the job above's;
    // and when the writes are done every job has what Linux gives it: its
    // shares' product exactly at most Linux's quota and less than a
    // hundredth of a percent below it (a share is rounded down).
    #[test]
    fn test_a_write_to_a_level_reaches_every_job_below_in_a_safe_order() {
        let job = |name: &str, rate, cpus: Option<u64>| Below {
            name: name.to_string(),
            asked: Asked { version: 2, rate, cpus: cpus.map(|mask| vec![(0, mask)]) },
            now: Held::default(),
        };
        // A level `t` with a level, jails under both, and a level of three.
        let below = [
            job("t//vm-1", Some(2000), Some(0b0011)),
            job("t//vm-2", None, None),
            job("t/a", Some(4000), Some(0b0110)),
            job("t/a//vm-3", Some(1000), Some(0b0100)),
            job("t/a//vm-4", Some(9000), None),
            job("t/a/b", None, Some(0b1100)),
            job("t/a/b//vm-5", Some(3000), Some(0b1000)),
        ];
        let names: Vec<&str> = std::iter::once("t").chain(below.iter().map(|b| b.name.as_str())).collect();
        let level = |rate, cpus: Option<u64>| Asked { version: 2, rate, cpus: cpus.map(|mask| vec![(0, mask)]) };
        let settings = [
            level(Some(5000), Some(0b1111)),
            level(Some(2500), Some(0b0110)),
            level(Some(8000), Some(0b1001)),
            level(None, Some(0b1111)),
            level(Some(100), Some(0b0001)),
            level(Some(10_000), Some(0b1110)),
            level(Some(3000), Some(0b1111)),
        ];
        // Above `t`: no level; a level of 6000; a level of 6000 with one
        // given 4166 for 2500 under it (2499.6 of the host: Linux's 2500).
        let three = Some(vec![(0, 0b0111)]);
        for (above, up) in [
            (Above::default(), Held::default()),
            (Above { caps: vec![Some(6000)], cpus: three.clone() }, Held { rate: Some(6000), cpus: three.clone() }),
            (Above { caps: vec![Some(6000), Some(4166)], cpus: three.clone() }, Held { rate: Some(2500), cpus: three.clone() }),
        ] {
            // Made with the first setting, then written each other one.
            let mut asked = settings[0].clone();
            let (_, mut held) = rewrite(&above, "t", &asked, &Held::default(), &below).unwrap();
            for to in &settings {
                let before = linux(&up, "t", &asked, &below);
                let after = linux(&up, "t", to, &below);
                let now: Vec<Below> = below.iter().zip(&held[1..]).map(|(b, now)| Below { now: now.clone(), ..b.clone() }).collect();
                let (steps, last) = rewrite(&above, "t", to, &held[0], &now).unwrap();
                for step in &steps {
                    match step.clone() {
                        Step::Rate(i, rate) => held[i].rate = rate,
                        Step::Cpus(i, cpus) => held[i].cpus = Some(cpus),
                    }
                    for (i, has) in windows(&above, &names, &held).iter().enumerate() {
                        let most = match (before[i].rate, after[i].rate) {
                            (Some(a), Some(b)) => a.max(b),
                            _ => 10_000,
                        };
                        assert!(at_most(&has.caps, most), "{}: {has:?} above {most} at {step:?}, to {to:?}", names[i]);
                        assert!(within(&has.cpus, &before[i].cpus, &after[i].cpus), "{}: {has:?} at {step:?}, to {to:?}", names[i]);
                    }
                }
                assert_eq!(held, last, "to {to:?}");
                for (i, has) in windows(&above, &names, &held).iter().enumerate() {
                    assert_eq!(has.cpus, after[i].cpus, "{}: to {to:?}", names[i]);
                    match after[i].rate {
                        Some(linux) => assert!(
                            at_most(&has.caps, linux) && above_least(&has.caps, linux - 1),
                            "{}: {:?} for {linux}, to {to:?}",
                            names[i],
                            rate_of_levels(&has.caps)
                        ),
                        None => assert_eq!(exact_rate(&has.caps), Ok(None), "{}: to {to:?}", names[i]),
                    }
                }
                // The same setting again writes nothing.
                let again: Vec<Below> = below.iter().zip(&held[1..]).map(|(b, now)| Below { now: now.clone(), ..b.clone() }).collect();
                assert_eq!(rewrite(&above, "t", to, &held[0], &again).unwrap().0, []);
                asked = to.clone();
            }
        }
    }

    // cgroup v1: a write to a level that a job below could not follow is
    // refused, as Linux fails it, and names the job; a job among those
    // below whose level is not there is refused too.
    #[test]
    fn test_a_write_to_a_level_is_refused_as_linux_fails_it() {
        let v1 = |name: &str, rate, mask| Below {
            name: name.to_string(),
            asked: Asked { version: 1, rate, cpus: Some(vec![(0, mask)]) },
            now: Held::default(),
        };
        let below = [v1("t//vm-1", Some(4000), 0b0011)];
        let level = |rate, mask| Asked { version: 1, rate, cpus: Some(vec![(0, mask)]) };
        rewrite(&Above::default(), "t", &level(Some(5000), 0b0111), &Held::default(), &below).unwrap();
        let quota = rewrite(&Above::default(), "t", &level(Some(3000), 0b0111), &Held::default(), &below).unwrap_err();
        assert!(quota.starts_with("t//vm-1, below t: ") && quota.contains(RATE_ABOVE_PARENT), "{quota}");
        let cpus = rewrite(&Above::default(), "t", &level(Some(5000), 0b0001), &Held::default(), &below).unwrap_err();
        assert!(cpus.starts_with("t//vm-1, below t: ") && cpus.contains(CPUS_OUTSIDE_PARENT), "{cpus}");
        // The level's own write against the levels above it.
        let above = Above { caps: vec![Some(2000)], cpus: None };
        let own = rewrite(&above, "t", &level(Some(5000), 0b0111), &Held::default(), &[]).unwrap_err();
        assert!(own.starts_with("t: ") && own.contains(RATE_ABOVE_PARENT), "{own}");
        let orphan = [v1("t/a//vm-1", None, 0b1)];
        let lost = rewrite(&Above::default(), "t", &level(None, 0b1), &Held::default(), &orphan).unwrap_err();
        assert!(lost.contains("the job above it is not among those below t"), "{lost}");
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
