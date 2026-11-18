// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd, the file server behind wick's virtio-fs device
//! (docs/design-fs.md): one process per shared host directory, which parses
//! the guest's FUSE requests, never sees guest memory and confines itself
//! before it serves.
//!
//! So far, the same code on every host:
//! - [`fuse`]: the bounded decoder of requests, the encoder of replies and
//!   the rules for guest names;
//! - [`session`]: the server core, over [`dir::ConfinedDir`], with its node
//!   and handle tables ([`inodes`], [`handles`]), [`limits`], the metadata
//!   [`record`] and the [`cache`] modes;
//! - [`memdir`]: an in-memory `ConfinedDir` for tests and fuzzing.
//!
//! The host directory, on Linux and macOS (the Windows one comes with its
//! port): [`host`]'s `HostDir`, over the system calls of the `wick-fs-sys`
//! crate, and `stage0`, the share's checks before anything is served.
//!
//! The server: [`serve`], the loop over one connection's frames, and
//! [`confine`], stage 1's confinement (Linux; macOS's comes with its own
//! commit). The `wick-fsd` binary (`src/main.rs`) puts them together; on a
//! host without confinement it refuses to start.

/// A discovery build (`--cfg wick_fsd_discovery`, built only by
/// tools/macos/fs-server-report.py into a target directory of its own): its
/// macOS profile allows and reports every call it does not list instead of
/// killing it (`confine::macos`), and it says each request it serves on
/// stderr. Never a product: it says so at its start and in `--version`
/// (`test_a_build_says_whether_it_is_a_discovery_build`), and
/// tools/check-tree.py fails a tree that sets the cfg anywhere else.
#[allow(unexpected_cfgs)]
pub const DISCOVERY_BUILD: bool = cfg!(wick_fsd_discovery);

/// What `wick-fsd --version` prints.
pub fn version_line() -> String {
    let build = if DISCOVERY_BUILD {
        " (discovery build: its profile allows and reports what it does not list; never a product)"
    } else {
        ""
    };
    format!("wick-fsd {}{build}", env!("CARGO_PKG_VERSION"))
}

/// A discovery build's clock: the wall clock read once, at its first line
/// (main's, before the profile), and the monotonic clock since. The wall
/// clock's read can be a system call (`gettimeofday`, 116, when the
/// commpage's time is being updated or is a second old: libsyscall
/// `__commpage_gettimeofday_internal`), which the build would then report
/// as its own; the monotonic clock never is one.
static DISCOVERY_CLOCK: std::sync::OnceLock<(std::time::Instant, u128)> = std::sync::OnceLock::new();

/// In a discovery build, `what` on stderr with the time in microseconds
/// since the epoch (`wick-fsd: discovery: <what> at <µs>`), which
/// tools/macos/fs-server-report.py matches with the time of Seatbelt's
/// reports; nothing otherwise. The first call, main's, reads the wall clock.
pub fn discovery_say(what: std::fmt::Arguments<'_>) {
    if DISCOVERY_BUILD {
        let (start, wall) = DISCOVERY_CLOCK.get_or_init(|| {
            let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            (std::time::Instant::now(), wall.as_micros())
        });
        eprintln!("wick-fsd: discovery: {what} at {}", wall + start.elapsed().as_micros());
    }
}

/// In a discovery build, 5 ms spent before each request (a spin on the
/// monotonic clock, which makes no system call): Seatbelt's reports carry
/// the time to the millisecond, so requests this far apart can each be told
/// as the one in flight, give or take one; nothing otherwise.
pub fn discovery_spacing() {
    if DISCOVERY_BUILD {
        let until = std::time::Instant::now() + std::time::Duration::from_millis(5);
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
    }
}

pub mod cache;
pub mod confine;
pub mod dir;
pub mod fuse;
pub mod handles;
pub mod host;
pub mod inodes;
pub mod limits;
pub mod memdir;
pub mod record;
pub mod serve;
pub mod session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod stage0;
