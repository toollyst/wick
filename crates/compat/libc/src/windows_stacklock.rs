// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The locks of wick's memory code (the region table, the charges, the
//! reclaim's lists and its owed charge, ...), each taken with its stack
//! committed first.
//!
//! A thread whose stack must grow while it holds one of these locks cannot
//! be helped by the reclaim, which takes them (the stack reclaim's design,
//! condition A3). So a lock here commits [`PROBE`] bytes of the caller's
//! stack before it locks: a stack page the job's limit refuses is refused
//! there, with no lock held. The mutexes are private to this module; the
//! only way to take one is [`ProbedMutex::lock`] (or [`ProbedRwLock`]'s
//! `read` and `write`), which probes first. The probe writes nothing: it is
//! a frame of [`PROBE`] uninitialised bytes, whose pages the compiler's stack
//! probe (`__chkstk`) touches one at a time.
//!
//! `test_wicks_memory_locks_are_all_probed` fails on a `static` lock of
//! another kind (a `Mutex` or `RwLock`, in a `OnceLock` or not) declared
//! outside the tests of any of this crate's Windows modules (every
//! `windows_*.rs`, the list checked against the source directory, so a new
//! module is read too): the reclaim runs this crate's code only, and the
//! crate's other modules are macOS's, not built on Windows.
//!
//! In tests a guard also checks, when it drops, that no stack page was
//! committed while it was held (the TEB's StackLimit has not moved since
//! the probe), and a held lock's deepest use of the stack is recorded
//! (STACKLOCK) by painting the probed bytes before the lock and reading back
//! how far they were overwritten.

use std::sync::{LockResult, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// The stack committed below the caller before a lock: the deepest use of
/// the stack while one of these locks is held, nested ones included, with a
/// margin (STACKLOCK's record; the stack reclaim's design, condition A3.4).
pub(crate) const PROBE: usize = 16 << 10;

/// Commits [`PROBE`] bytes of stack below the caller: a frame of that size,
/// which the compiler probes a page at a time (`__chkstk`), so that each
/// page is committed now, in order, through the guard page. The frame is
/// left uninitialised: the probe touches one word a page, and nothing else
/// writes it (`test_the_probes_cost_on_record`).
#[inline(never)]
fn probe() {
    let frame = core::mem::MaybeUninit::<[u8; PROBE]>::uninit();
    core::hint::black_box(&frame);
}

/// The probe as it was first written, which zeroed its frame: for
/// `test_the_probes_cost_on_record`'s comparison only.
#[cfg(test)]
#[inline(never)]
fn probe_zeroing() {
    let frame = core::hint::black_box([0u8; PROBE]);
    core::hint::black_box(&frame);
}

/// What an outermost lock does in tests: watch ([`Watch`], the default), or,
/// for the cost records, only probe, as the product does, with [`probe`]
/// or [`probe_zeroing`].
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Probing {
    Watch,
    Probe,
    Zeroing,
}

#[cfg(test)]
std::thread_local! {
    pub(crate) static PROBING: core::cell::Cell<Probing> = const { core::cell::Cell::new(Probing::Watch) };
}

/// What a guard notes in tests: the lock's name, the TEB's StackLimit after
/// the probe, and the painted range's low end.
#[cfg(test)]
struct Watch {
    name: &'static str,
    at: &'static core::panic::Location<'static>,
    limit: usize,
    /// The painted range, `[low, top)`, and the caller's depth it is
    /// measured from.
    low: usize,
    top: usize,
    here: usize,
}

/// Bytes left unpainted under the probing frame: [`paint`]'s own frame is
/// there.
#[cfg(test)]
const GAP: usize = 2048;

#[cfg(test)]
impl Watch {
    /// Probes, then paints the probed bytes below this frame and notes the
    /// StackLimit.
    #[inline(never)]
    #[track_caller]
    fn start(name: &'static str) -> Self {
        let at = core::panic::Location::caller();
        probe();
        let here = core::ptr::addr_of!(name) as usize;
        let (low, top) = (here - (PROBE - 1024), here - GAP);
        paint(low, top);
        Self { name, at, limit: stack_limit(), low, top, here }
    }
}

#[cfg(test)]
impl Drop for Watch {
    fn drop(&mut self) {
        let now = stack_limit();
        let first = overwritten_from(self.low, self.top);
        record(self.name, self.at, self.here - first);
        if std::thread::panicking() {
            return;
        }
        if now < self.limit {
            panic!(
                "STACKLOCK the stack grew by {} B while {} was held (taken at {}): a stack page was committed under \
                 the lock, which the reclaim cannot help (PROBE is {} B)",
                self.limit - now,
                self.name,
                self.at,
                PROBE
            );
        }
        assert!(
            first > self.low,
            "STACKLOCK {} was held (taken at {}) with all of the probed stack used (PROBE is {} B): raise PROBE",
            self.name,
            self.at,
            PROBE
        );
    }
}

#[cfg(test)]
const PAINT: u8 = 0xa7;

/// Fills `[low, high)` of this thread's stack, committed by [`probe`], with
/// [`PAINT`].
#[cfg(test)]
#[inline(never)]
fn paint(low: usize, high: usize) {
    for a in low..high {
        // SAFETY: committed stack below every live frame of this thread.
        unsafe { core::ptr::write_volatile(a as *mut u8, PAINT) };
    }
}

/// The lowest address of `[low, top)` no longer painted: how deep the held
/// lock's code went (`top` when it stayed above the painted range).
#[cfg(test)]
fn overwritten_from(low: usize, top: usize) -> usize {
    let mut a = low;
    // SAFETY: as in `paint`; reads only.
    while a < top && unsafe { core::ptr::read_volatile(a as *const u8) } == PAINT {
        a += 1;
    }
    a
}

#[cfg(all(test, target_arch = "x86_64"))]
fn stack_limit() -> usize {
    let limit: usize;
    // SAFETY: a read of the thread's own TEB (StackLimit, gs:[0x10]).
    unsafe { core::arch::asm!("mov {0}, gs:[0x10]", out(reg) limit, options(nostack, readonly, preserves_flags)) };
    limit
}

/// The deepest use of the stack recorded under each lock (STACKLOCK), in
/// a fixed table: a record allocates nothing (`test_a_reclaim_allocates_nothing`
/// counts the reclaim's allocations).
#[cfg(test)]
static DEEPEST: Mutex<[(&str, usize); 32]> = Mutex::new([("", 0); 32]);

/// Notes `used` for `name`, and says a new deepest one on standard error
/// (STACKLOCK max), without allocating.
#[cfg(test)]
fn record(name: &'static str, at: &core::panic::Location<'_>, used: usize) {
    let mut d = DEEPEST.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(e) = d.iter_mut().find(|(n, _)| *n == name || n.is_empty()) {
        e.0 = name;
        if used > e.1 {
            e.1 = used;
            crate::windows_mm::say_at_the_limit(format_args!("STACKLOCK max {name}: {used} B below the caller, taken at {at}"));
        }
    }
}

/// STACKLOCK's record so far: each lock's deepest use of the stack.
#[cfg(test)]
pub(crate) fn deepest_uses() -> std::vec::Vec<(&'static str, usize)> {
    DEEPEST.lock().unwrap_or_else(PoisonError::into_inner).iter().copied().filter(|(n, _)| !n.is_empty()).collect()
}

std::thread_local! {
    /// How many of these locks this thread holds: only the first probes, as
    /// its probe covers the deepest nesting (condition A3.4), and a nested
    /// probe would itself commit below the first one.
    static HELD: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// A lock of this module held by this thread ([`HELD`]), with, in tests,
/// the outermost one's watch.
pub(crate) struct Held {
    #[cfg(test)]
    _watch: Option<Watch>,
}

impl Drop for Held {
    fn drop(&mut self) {
        HELD.with(|h| h.set(h.get() - 1));
    }
}

/// A guard of a [`ProbedMutex`] or a [`ProbedRwLock`]: the lock's guard,
/// released first, then [`Held`].
pub(crate) struct Probed<G> {
    guard: G,
    _held: Held,
}

impl<G: core::ops::Deref> core::ops::Deref for Probed<G> {
    type Target = G::Target;
    fn deref(&self) -> &G::Target {
        &self.guard
    }
}

impl<G: core::ops::DerefMut> core::ops::DerefMut for Probed<G> {
    fn deref_mut(&mut self) -> &mut G::Target {
        &mut self.guard
    }
}

impl<'a, T> Probed<MutexGuard<'a, T>> {
    /// [`std::sync::Condvar::wait`] on this guard's mutex: the stack probed
    /// before the lock stays committed through the wait.
    pub(crate) fn wait_on(self, cv: &std::sync::Condvar) -> LockResult<Self> {
        let Probed { guard, _held } = self;
        match cv.wait(guard) {
            Ok(guard) => Ok(Probed { guard, _held }),
            Err(p) => Err(PoisonError::new(Probed { guard: p.into_inner(), _held })),
        }
    }
}

/// Probes if this thread holds none of these locks yet (and in tests starts
/// the watch), then takes the lock with `take`, keeping its poison.
#[track_caller]
fn probed<G>(name: &'static str, take: impl FnOnce() -> LockResult<G>) -> LockResult<Probed<G>> {
    let first = HELD.with(|h| {
        let n = h.get();
        h.set(n + 1);
        n == 0
    });
    #[cfg(test)]
    let held = Held {
        _watch: match (first, PROBING.with(core::cell::Cell::get)) {
            (false, _) => None,
            (true, Probing::Watch) => Some(Watch::start(name)),
            (true, Probing::Probe) => {
                probe();
                None
            }
            (true, Probing::Zeroing) => {
                probe_zeroing();
                None
            }
        },
    };
    #[cfg(not(test))]
    let held = {
        let _ = name;
        if first {
            probe();
        }
        Held {}
    };
    match take() {
        Ok(guard) => Ok(Probed { guard, _held: held }),
        Err(p) => Err(PoisonError::new(Probed { guard: p.into_inner(), _held: held })),
    }
}

/// A mutex of this crate's Windows code, locked with its stack committed first.
pub(crate) struct ProbedMutex<T> {
    name: &'static str,
    inner: Mutex<T>,
}

impl<T> ProbedMutex<T> {
    pub(crate) const fn new(name: &'static str, value: T) -> Self {
        Self { name, inner: Mutex::new(value) }
    }

    /// [`Mutex::lock`], after [`PROBE`] bytes of stack are committed.
    #[track_caller]
    pub(crate) fn lock(&self) -> LockResult<Probed<MutexGuard<'_, T>>> {
        probed(self.name, || self.inner.lock())
    }
}

impl<T: Default> Default for ProbedMutex<T> {
    fn default() -> Self {
        Self::new("unnamed", T::default())
    }
}

/// A reader-writer lock of this crate's Windows code, taken with its stack
/// committed first.
pub(crate) struct ProbedRwLock<T> {
    name: &'static str,
    inner: RwLock<T>,
}

impl<T> ProbedRwLock<T> {
    pub(crate) const fn new(name: &'static str, value: T) -> Self {
        Self { name, inner: RwLock::new(value) }
    }

    #[track_caller]
    pub(crate) fn read(&self) -> LockResult<Probed<RwLockReadGuard<'_, T>>> {
        probed(self.name, || self.inner.read())
    }

    #[track_caller]
    pub(crate) fn write(&self) -> LockResult<Probed<RwLockWriteGuard<'_, T>>> {
        probed(self.name, || self.inner.write())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This crate's Windows modules, each read by
    /// [`test_wicks_memory_locks_are_all_probed`].
    const MODULES: [(&str, &str); 11] = [
        ("windows_errno.rs", include_str!("windows_errno.rs")),
        ("windows_fd.rs", include_str!("windows_fd.rs")),
        ("windows_items.rs", include_str!("windows_items.rs")),
        ("windows_linux.rs", include_str!("windows_linux.rs")),
        ("windows_mm.rs", include_str!("windows_mm.rs")),
        ("windows_nofile.rs", include_str!("windows_nofile.rs")),
        ("windows_sectrec.rs", include_str!("windows_sectrec.rs")),
        ("windows_socket.rs", include_str!("windows_socket.rs")),
        ("windows_stacklock.rs", include_str!("windows_stacklock.rs")),
        ("windows_time.rs", include_str!("windows_time.rs")),
        ("windows_uffd.rs", include_str!("windows_uffd.rs")),
    ];

    /// The `static` locks `text` declares outside its tests that are not
    /// this module's: a line declaring a `static` whose type, less
    /// `ProbedMutex<` and `ProbedRwLock<`, still names `Mutex<` or `RwLock<`
    /// (in a `OnceLock`, a `LazyLock` or alone).
    fn unprobed_locks(file: &str, text: &str) -> std::vec::Vec<std::string::String> {
        let product = text.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let mut bad = std::vec::Vec::new();
        let mut in_test_item = false;
        for (n, line) in product.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test") {
                in_test_item = true;
                continue;
            }
            let other = t.replace("ProbedMutex<", "").replace("ProbedRwLock<", "");
            let declares = (t.starts_with("static ") || t.contains(" static ")) && (other.contains("Mutex<") || other.contains("RwLock<"));
            if declares && !in_test_item {
                bad.push(std::format!("{file}:{}: {}", n + 1, t));
            }
            if !t.starts_with("#[") {
                in_test_item = false;
            }
        }
        bad
    }

    /// Every `static` lock of this crate's Windows modules, outside their
    /// tests, is one of this module's: a `Mutex` or `RwLock` there would be
    /// taken without the probe. The modules read are every `windows_*.rs` in
    /// the source directory ([`MODULES`], checked against it); and a lock
    /// declared the old way is found (the check's own case).
    #[test]
    fn test_wicks_memory_locks_are_all_probed() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut on_disk: std::vec::Vec<std::string::String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("windows_") && n.ends_with(".rs"))
            .collect();
        on_disk.sort();
        let read: std::vec::Vec<&str> = MODULES.iter().map(|m| m.0).collect();
        assert_eq!(on_disk, read, "MODULES must list every windows_*.rs of {}", dir.display());
        for case in [
            "static T: OnceLock<Mutex<HashMap<c_int, Entry>>> = OnceLock::new();",
            "    static L: std::sync::RwLock<u8> = std::sync::RwLock::new(0);",
            "pub(crate) static M: Mutex<()> = Mutex::new(());",
        ] {
            assert_eq!(unprobed_locks("case", case).len(), 1, "{case}");
        }
        assert!(unprobed_locks("case", "static T: OnceLock<ProbedMutex<HashMap<c_int, Entry>>> = OnceLock::new();").is_empty());
        assert!(unprobed_locks("case", "#[cfg(test)]\nstatic M: Mutex<()> = Mutex::new(());").is_empty());
        let bad: std::vec::Vec<_> = MODULES.iter().flat_map(|(file, text)| unprobed_locks(file, text)).collect();
        assert!(bad.is_empty(), "locks taken without the stack probe:\n{}", bad.join("\n"));
    }


    /// A guard's probe commits [`PROBE`] bytes below its caller, and a lock
    /// held while its code uses the stack within them commits nothing more;
    /// one used deeper fails, naming the lock.
    #[test]
    fn test_a_held_lock_commits_no_stack() {
        static L: ProbedMutex<u32> = ProbedMutex::new("test lock", 0);
        {
            let mut g = L.lock().unwrap();
            *g += 1;
            core::hint::black_box(use_stack::<4096>());
        }
        assert!(deepest_uses().iter().any(|&(n, u)| n == "test lock" && u >= 4096), "{:?}", deepest_uses());
        let deep = std::thread::spawn(|| {
            let _g = L.lock().unwrap();
            core::hint::black_box(use_stack::<{ 64 << 10 }>());
        })
        .join();
        let msg = deep.err().and_then(|e| e.downcast_ref::<std::string::String>().cloned()).unwrap_or_default();
        assert!(msg.contains("STACKLOCK the stack grew by") && msg.contains("test lock"), "{msg}");
    }

    /// PROBECOST: an outermost lock's cost, the probe's share of it. The
    /// nanoseconds of a lock and unlock of an uncontended mutex, 100,000
    /// times, alone, with [`probe`] first, and with [`probe_zeroing`] first
    /// (no watch, as in the product), 5 rounds in turn; the least and the
    /// median round of each are printed. Asserted only that the probe that
    /// writes nothing costs less than the one that zeroes 16 KiB. Run with
    /// `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a record: run alone, with --release --ignored --nocapture"]
    fn test_the_probes_cost_on_record() {
        const N: u32 = 100_000;
        static PLAIN: Mutex<u64> = Mutex::new(0);
        static PROBED: ProbedMutex<u64> = ProbedMutex::new("the probe's cost", 0);
        let time = |kind: Option<Probing>| {
            let t = std::time::Instant::now();
            for _ in 0..N {
                match kind {
                    None => *core::hint::black_box(&PLAIN).lock().unwrap() += 1,
                    Some(_) => *core::hint::black_box(&PROBED).lock().unwrap() += 1,
                }
            }
            t.elapsed().as_nanos() as f64 / f64::from(N)
        };
        let kinds = [("plain", None), ("probe", Some(Probing::Probe)), ("zeroing", Some(Probing::Zeroing))];
        let mut ns = [std::vec::Vec::new(), std::vec::Vec::new(), std::vec::Vec::new()];
        let was = PROBING.with(core::cell::Cell::get);
        for _ in 0..5 {
            for (i, &(_, kind)) in kinds.iter().enumerate() {
                PROBING.with(|p| p.set(kind.unwrap_or(Probing::Probe)));
                ns[i].push(time(kind));
            }
        }
        PROBING.with(|p| p.set(was));
        let mut med = [0.0; 3];
        for (i, (name, _)) in kinds.iter().enumerate() {
            ns[i].sort_by(f64::total_cmp);
            med[i] = ns[i][2];
            std::println!("PROBECOST lock {name}: {:.1} ns least, {:.1} ns median, of 5 rounds of {N}", ns[i][0], med[i]);
        }
        assert!(med[1] < med[2], "the uninitialised probe ({:.1} ns) is not cheaper than the zeroing one ({:.1} ns)", med[1], med[2]);
    }

    #[inline(never)]
    fn use_stack<const N: usize>() -> u8 {
        let a = core::hint::black_box([1u8; N]);
        a[N / 2]
    }
}
