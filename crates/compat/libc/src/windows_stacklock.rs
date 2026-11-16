// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The locks of wick's memory code (the region table, the charges, the
//! reclaim's lists, ...), each taken through this
//! module, so that the stack reclaim (its design's step 3) will cover them
//! all.
//!
//! A thread whose stack must grow while it holds one of these locks cannot
//! be helped by the reclaim, which takes them (the stack reclaim's design,
//! condition A3). The design's answer is a probe that commits [`PROBE`]
//! bytes of the caller's stack before an outermost lock, so that a stack
//! page the job's limit refuses is refused there, with no lock held, and
//! the reclaim asked for it. Until that ask exists the probe is in tests
//! only ([`Probing::Guard`], and the cost records): in the product a refused
//! probe ended the VMM with 137 at the limit where the lock without it
//! needed no new page (`test_a_lock_commits_no_stack_before_it_is_taken`;
//! on Windows Server 2025 a userfaultfd's thread releasing its ranges after
//! a refused fill, `test_a_fill_at_the_limit_reclaims_partly_discarded_chunks`),
//! so a lock here takes the stack its own frames use and no more, as a
//! plain `Mutex` does. The mutexes are private to this module; the only
//! way to take one is [`ProbedMutex::lock`] (or [`ProbedRwLock`]'s `read`
//! and `write`). The probe writes nothing: it is a frame of [`PROBE`]
//! uninitialised bytes, whose pages the compiler's stack probe (`__chkstk`)
//! touches one at a time.
//!
//! `test_wicks_memory_locks_are_all_probed` fails on a `static` lock of
//! another kind (a `Mutex` or `RwLock`, in a `OnceLock` or not) declared
//! outside the tests of any of this crate's Windows modules (every
//! `windows_*.rs`, the list checked against the source directory, so a new
//! module is read too): the reclaim runs this crate's code only, and the
//! crate's other modules are macOS's, not built on Windows.
//!
//! In tests a held lock's deepest use of the stack is recorded (STACKLOCK
//! max) by painting the stack already committed below the caller (up to
//! [`PROBE`] bytes, committing none) before the lock and reading back how
//! far it was overwritten, and a stack page committed while it was held
//! (the TEB's StackLimit moved) is recorded too (STACKLOCK grew): what the
//! probe will have to cover. With [`Probing::Guard`] a lock probes first
//! and such a page fails the test, naming the lock.

#[cfg(test)]
use std::sync::PoisonError;
use std::sync::{LockResult, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// The stack committed below the caller before a lock: the deepest use of
/// the stack while one of these locks is held, nested ones included, with a
/// margin (STACKLOCK's record; the stack reclaim's design, condition A3.4).
#[cfg(test)]
pub(crate) const PROBE: usize = 16 << 10;

/// Commits [`PROBE`] bytes of stack below the caller: a frame of that size,
/// which the compiler probes a page at a time (`__chkstk`), so that each
/// page is committed now, in order, through the guard page. The frame is
/// left uninitialised: the probe touches one word a page, and nothing else
/// writes it (`test_the_probes_cost_on_record`). In tests only, until the
/// stack reclaim can answer its refusal (the module's comment).
#[cfg(test)]
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

/// What an outermost lock does in tests: watch, committing nothing, as the
/// product commits nothing ([`Watch`], the default); probe and watch, a
/// page committed under the lock failing the test (`Guard`, the stack
/// reclaim's design); or, for the cost records, only probe, with [`probe`]
/// or [`probe_zeroing`].
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Probing {
    Watch,
    Guard,
    Probe,
    Zeroing,
}

#[cfg(test)]
std::thread_local! {
    pub(crate) static PROBING: core::cell::Cell<Probing> = const { core::cell::Cell::new(Probing::Watch) };
}

/// Whether the locks of every thread of this process are watched as
/// [`PROBING`] says: off, a lock is taken as the product takes it, for the
/// records of the reclaim's stack and time, which the watch's painting
/// would add to (a lock's paint writes up to [`PROBE`] bytes below it).
#[cfg(test)]
pub(crate) static WATCHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// What a guard notes in tests: the lock's name, the TEB's StackLimit after
/// the probe (if any), the painted range, and whether it probed.
#[cfg(test)]
struct Watch {
    name: &'static str,
    at: &'static core::panic::Location<'static>,
    limit: usize,
    guard: bool,
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
    /// Probes if `guard`, then paints the committed stack below this frame
    /// (at most what a probe commits) and notes the StackLimit.
    #[inline(never)]
    #[track_caller]
    fn start(name: &'static str, guard: bool) -> Self {
        let at = core::panic::Location::caller();
        if guard {
            probe();
        }
        let here = core::ptr::addr_of!(name) as usize;
        let limit = stack_limit();
        let top = here - GAP;
        let low = (here - (PROBE - 1024)).max(limit).min(top);
        paint(low, top);
        Self { name, at, limit, guard, low, top, here }
    }
}

#[cfg(test)]
impl Drop for Watch {
    fn drop(&mut self) {
        let now = stack_limit();
        let first = overwritten_from(self.low, self.top);
        // A page committed under the lock: its code went below the
        // committed stack, at most a page under the new limit.
        let used = if now < self.limit { self.here - now } else { self.here - first };
        record(self.name, self.at, used);
        if now < self.limit && !self.guard {
            record_growth(self.name, self.at, self.limit - now);
        }
        if std::thread::panicking() || !self.guard {
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

/// The most stack committed under each lock (STACKLOCK grew), as
/// [`DEEPEST`].
#[cfg(test)]
static GREW: Mutex<[(&str, usize); 32]> = Mutex::new([("", 0); 32]);

/// Notes `grew` bytes committed while `name` was held, and says a new most
/// on standard error (STACKLOCK grew), without allocating.
#[cfg(test)]
fn record_growth(name: &'static str, at: &core::panic::Location<'_>, grew: usize) {
    let mut d = GREW.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(e) = d.iter_mut().find(|(n, _)| *n == name || n.is_empty()) {
        e.0 = name;
        if grew > e.1 {
            e.1 = grew;
            crate::windows_mm::say_at_the_limit(format_args!(
                "STACKLOCK grew {name}: {grew} B of stack committed while it was held, taken at {at}"
            ));
        }
    }
}

/// STACKLOCK's record so far: each lock's deepest use of the stack.
#[cfg(test)]
pub(crate) fn deepest_uses() -> std::vec::Vec<(&'static str, usize)> {
    DEEPEST.lock().unwrap_or_else(PoisonError::into_inner).iter().copied().filter(|(n, _)| !n.is_empty()).collect()
}

std::thread_local! {
    /// How many of these locks this thread holds, or is taking: counted
    /// from before the lock is asked for until its guard drops. A thread
    /// whose stack page the job's limit refused while a reclaim runs waits
    /// for the reclaim only when it holds none
    /// (`windows_mm::stack_page_after_the_reclaim`): the reclaim takes these
    /// locks, so a thread holding one could be what it waits for. In
    /// tests only the first is watched (and, with [`Probing::Guard`],
    /// probes), as its probe covers the deepest nesting (condition A3.4),
    /// and a nested probe would itself commit below the first one. A
    /// const-initialised `Cell` with no destructor: a plain TLS read, from
    /// an exception handler too ([`test_a_lock_taken_in_a_threads_teardown_is_probed`]'s
    /// comment).
    static HELD: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// How many of these locks this thread holds now, or is taking
/// (`wick_uffd::unmapping` asserts 0: no `munmap` or `MAP_FIXED` runs under
/// one of this layer's locks; a refused stack page waits for a reclaim only
/// at 0).
pub(crate) fn held_here() -> u32 {
    HELD.with(core::cell::Cell::get)
}

/// A lock of this module held by this thread, counted in [`HELD`], with,
/// in tests, the outermost one's watch.
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
    /// before the lock stays committed through the wait. Never `Err`: a
    /// mutex poisoned meanwhile ends the process ([`poisoned`]).
    #[track_caller]
    pub(crate) fn wait_on(self, cv: &std::sync::Condvar) -> LockResult<Self> {
        let Probed { guard, _held } = self;
        match cv.wait(guard) {
            Ok(guard) => Ok(Probed { guard, _held }),
            Err(_) => poisoned("the mutex of a condition variable's wait", core::panic::Location::caller()),
        }
    }
}

/// Takes the lock with `take`, a poisoned one ending the process
/// ([`poisoned`]): never `Err`; in tests, if this
/// thread holds none of these locks yet, watched first (see [`Probing`]).
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
            (true, _) if !WATCHING.load(std::sync::atomic::Ordering::Relaxed) => None,
            (true, Probing::Watch) => Some(Watch::start(name, false)),
            (true, Probing::Guard) => Some(Watch::start(name, true)),
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
        let _ = (name, first);
        Held {}
    };
    match take() {
        Ok(guard) => Ok(Probed { guard, _held: held }),
        Err(_) => poisoned(name, core::panic::Location::caller()),
    }
}

/// A lock of this module found poisoned: a thread panicked while it held
/// it, so what it guards (the region table, the charges, the released
/// ranges' records, ...) is in a state no caller can know. The process
/// aborts, the lock named, without allocating; never a panic, which in the
/// exception handler's path (a first access of lazy or released memory)
/// would be a panic inside an exception's dispatch.
#[cold]
#[inline(never)]
fn poisoned(name: &str, at: &core::panic::Location<'_>) -> ! {
    crate::windows_mm::say_at_the_limit(format_args!(
        "wick: the lock {name} was poisoned (a thread panicked while it held it), taken again at {at}: what it guards \
         is in a state not known; the process aborts"
    ));
    std::process::abort()
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

    /// [`Mutex::lock`], after [`PROBE`] bytes of stack are committed (in
    /// tests). Never `Err`: a poisoned mutex ends the process ([`poisoned`]).
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
        // By lines, which end at "\n" or "\r\n" alike: a checkout may have
        // either (`test_the_lock_check_reads_a_crlf_checkout`).
        let lines: std::vec::Vec<&str> = text.lines().collect();
        let tests = lines.windows(2).position(|w| w[0] == "#[cfg(test)]" && w[1].starts_with("mod tests")).unwrap_or(lines.len());
        let mut bad = std::vec::Vec::new();
        let mut in_test_item = false;
        for (n, line) in lines[..tests].iter().enumerate() {
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

    /// The lock check reads a module checked out with CRLF line endings as
    /// it reads one with LF: a lock in the module's tests is the tests' own.
    /// Git for Windows checks text files out with CRLF (its default
    /// `core.autocrlf=true`), and CI's windows job, on such a checkout,
    /// listed every `static` lock of the modules' tests (windows_mm.rs's
    /// `LOCK`, this module's own fixtures, windows_uffd.rs's `ROOM_TAKEN`) as
    /// unprobed, where fc-win's checkout, copied from macOS, has LF: the
    /// tests' start was looked for as "\n#[cfg(test)]\nmod tests".
    #[test]
    fn test_the_lock_check_reads_a_crlf_checkout() {
        let lf = "static A: Mutex<()> = Mutex::new(());\n\n#[cfg(test)]\nmod tests {\n    static B: Mutex<()> = Mutex::new(());\n}\n";
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(unprobed_locks("lf", lf), ["lf:1: static A: Mutex<()> = Mutex::new(());"]);
        assert_eq!(unprobed_locks("crlf", &crlf), ["crlf:1: static A: Mutex<()> = Mutex::new(());"]);
    }

    /// Taking a lock commits no stack beyond what its own frames use, as
    /// the product takes them: a thread with only a few pages of its stack
    /// committed, at the job's limit, must not need a new stack page to
    /// take one. The probe that committed [`PROBE`] bytes first did, and
    /// the limit refused it: in CI run 43800980377 (Windows Server 2025
    /// 26100) a userfaultfd's thread, taking its ranges' lock to release
    /// them, ended the VMM with 137 at the limit after the fill had been
    /// refused (`test_a_fill_at_the_limit_reclaims_partly_discarded_chunks`),
    /// where without the probe it needed no new page. On a new thread, its
    /// stack as it starts (8 KiB committed on record: STACKEND), the TEB's
    /// StackLimit is the same while the lock is held as before it was taken.
    #[test]
    fn test_a_lock_commits_no_stack_before_it_is_taken() {
        static L: ProbedMutex<u32> = ProbedMutex::new("a lock taken on a shallow stack", 0);
        let (before, held) = std::thread::spawn(|| {
            let before = stack_limit();
            let g = L.lock().unwrap();
            let held = stack_limit();
            drop(g);
            (before, held)
        })
        .join()
        .unwrap();
        assert_eq!(held, before, "taking the lock committed {} B of stack", before - held);
    }


    /// With the guard ([`Probing::Guard`], the stack reclaim's design), a
    /// lock's probe commits [`PROBE`] bytes below its caller, and a lock
    /// held while its code uses the stack within them commits nothing more;
    /// one used deeper fails, naming the lock.
    #[test]
    fn test_a_held_lock_commits_no_stack() {
        static L: ProbedMutex<u32> = ProbedMutex::new("test lock", 0);
        let was = PROBING.with(|p| p.replace(Probing::Guard));
        {
            let mut g = L.lock().unwrap();
            *g += 1;
            core::hint::black_box(use_stack::<4096>());
        }
        PROBING.with(|p| p.set(was));
        assert!(deepest_uses().iter().any(|&(n, u)| n == "test lock" && u >= 4096), "{:?}", deepest_uses());
        let deep = std::thread::spawn(|| {
            PROBING.with(|p| p.set(Probing::Guard));
            let _g = L.lock().unwrap();
            core::hint::black_box(use_stack::<{ 64 << 10 }>());
        })
        .join();
        let msg = deep.err().and_then(|e| e.downcast_ref::<std::string::String>().cloned()).unwrap_or_default();
        assert!(msg.contains("STACKLOCK the stack grew by") && msg.contains("test lock"), "{msg}");
    }

    /// Without the guard, as the product takes them, a lock whose code goes
    /// below the committed stack is not refused: the page committed under
    /// it is recorded (STACKLOCK grew), what the probe of the stack
    /// reclaim's step 3 must cover.
    #[test]
    fn test_a_page_committed_under_a_lock_is_on_record() {
        static L: ProbedMutex<u32> = ProbedMutex::new("a lock whose code grows the stack", 0);
        std::thread::spawn(|| {
            let _g = L.lock().unwrap();
            core::hint::black_box(use_stack::<{ 64 << 10 }>());
        })
        .join()
        .unwrap();
        let grew = GREW.lock().unwrap().iter().find(|(n, _)| *n == "a lock whose code grows the stack").map(|e| e.1);
        assert!(grew.is_some_and(|g| g >= 32 << 10), "{grew:?}");
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

    /// A lock of this module taken in a thread's teardown, by one of its
    /// thread-locals' destructors, is watched and taken as anywhere else:
    /// [`HELD`], counted on every lock and read by a refused stack page's
    /// wait for a reclaim (`windows_mm::stack_page_after_the_reclaim`, in
    /// an exception handler), is a const-initialised thread-local of
    /// a type with no destructor, which std on Windows (native TLS, the
    /// target has `has-thread-local`) makes a plain `#[thread_local]`
    /// static, with no registration, no allocation and no destroyed state
    /// (library/std/src/sys/thread_local/native/mod.rs, "For `const`
    /// initialization and `!Drop` types, we simply use `T` directly").
    #[test]
    fn test_a_lock_taken_in_a_threads_teardown_is_probed() {
        static TOOK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        struct TakesALock;
        impl Drop for TakesALock {
            fn drop(&mut self) {
                static L: ProbedMutex<u32> = ProbedMutex::new("a lock taken in teardown", 0);
                let mut g = L.lock().unwrap();
                *g += 1;
                TOOK.store(*g, std::sync::atomic::Ordering::SeqCst);
            }
        }
        std::thread_local! {
            static T: TakesALock = const { TakesALock };
        }
        std::thread::spawn(|| T.with(|_| {})).join().unwrap();
        assert_eq!(TOOK.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(deepest_uses().iter().any(|&(n, _)| n == "a lock taken in teardown"), "{:?}", deepest_uses());
    }

    #[inline(never)]
    fn use_stack<const N: usize>() -> u8 {
        let a = core::hint::black_box([1u8; N]);
        a[N / 2]
    }
}
