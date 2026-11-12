// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a jail's freezer files hold, the same on every host that keeps them
//! itself (Linux's are the kernel's): the values a write may give, parsed as
//! the kernel parses them, the canonical values it reads back, and the texts
//! of the jailer's refusals and log lines. The files are upstream's cgroup
//! freezer files, kept next to the jail by the host's backend (Windows:
//! `windows::freezer`).
//!
//! The kernel's side (Linux v6.12, the cgroup core and the v1 freezer):
//!
//! - v1 `freezer.state`, `freezer_write` (kernel/cgroup/legacy_freezer.c):
//!   `buf = strstrip(buf)`, then `THAWED` or `FROZEN` exactly, else
//!   `-EINVAL`; `freezer_read` shows `THAWED`, `FREEZING` or `FROZEN` and a
//!   newline. `freezer.self_freezing` and `freezer.parent_freezing` have no
//!   write handler (read-only).
//! - v2 `cgroup.freeze`, `cgroup_freeze_write` (kernel/cgroup/cgroup.c):
//!   `strstrip`, `kstrtoint(buf, 0, &freeze)` (an error is returned as is),
//!   then `freeze < 0 || freeze > 1` is `-ERANGE`; `cgroup_freeze_show`
//!   prints `"%d\n"`. `cgroup.events`, `cgroup_events_show`:
//!   `"populated %d\n"` then `"frozen %d\n"`.

/// The cgroup version whose files a jail has (`--cgroup-version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    /// `freezer.state`.
    V1,
    /// `cgroup.freeze` and `cgroup.events`.
    V2,
}

/// A jail's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Thawed,
    Frozen,
}

/// What the control file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request {
    /// Nothing (yet): a write truncates the file first.
    Empty,
    Set(State),
    /// Not a value the kernel takes, or not a file the jailer can trust.
    Invalid,
}

/// The longest control file read; anything longer is invalid.
pub(crate) const MAX_FILE: usize = 64;
/// How long an empty or invalid control file is left before it is
/// restored to the current state.
pub(crate) const SETTLE_MS: u32 = 200;

/// `cgroup.events`, v2.
pub(crate) const EVENTS: &str = "cgroup.events";

/// `--cgroup freezer.state=<other>`: the kernel refuses the jailer's write.
pub(crate) const STATE_VALUES: &str = "only FROZEN or THAWED: the kernel refuses any other value written to freezer.state";
/// `--cgroup freezer.<other>=` (v1): no file the jailer can write.
pub(crate) const READ_ONLY: &str = "not a file the jailer can write: the kernel refuses its write to it \
                                    (freezer.self_freezing and freezer.parent_freezing are read-only)";
/// The start of the error of a jail whose host's freezer call does not work.
pub(crate) const CANNOT_WORK: &str = "the freezer cannot work on this host";
/// The end of the log line of a request the jailer could not carry out.
pub(crate) const KILLED: &str = "the jail is killed rather than left unfrozen or frozen against the request";

impl Version {
    /// The control file's name.
    pub(crate) fn control(self) -> &'static str {
        match self {
            Version::V1 => "freezer.state",
            Version::V2 => "cgroup.freeze",
        }
    }

    /// The control file's content for `state`, as Linux reads it back.
    pub(crate) fn canonical(self, state: State) -> &'static [u8] {
        match (self, state) {
            (Version::V1, State::Thawed) => b"THAWED\n",
            (Version::V1, State::Frozen) => b"FROZEN\n",
            (Version::V2, State::Thawed) => b"0\n",
            (Version::V2, State::Frozen) => b"1\n",
        }
    }
}

/// `cgroup.events`' content.
pub(crate) fn events(populated: bool, frozen: bool) -> Vec<u8> {
    format!("populated {}\nfrozen {}\n", u8::from(populated), u8::from(frozen)).into_bytes()
}

/// The log line for an empty or invalid control file, restored.
pub(crate) fn ignored(version: Version, request: Request) -> String {
    let what = if request == Request::Empty {
        "empty"
    } else {
        "not a valid value, or not a file the jailer can trust"
    };
    format!(
        "{}: {what}, ignored (Linux refuses such a write); the file reads the current state again",
        version.control()
    )
}

/// The kernel's `strstrip`: `isspace` characters at both ends.
fn strstrip(mut b: &[u8]) -> &[u8] {
    let space = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    while b.first().is_some_and(space) {
        b = &b[1..];
    }
    while b.last().is_some_and(space) {
        b = &b[..b.len() - 1];
    }
    b
}

/// The kernel's `kstrtoint(s, 0)` (lib/kstrtox.c): an optional sign, then
/// `0x` hex, `0` octal or decimal digits, nothing else, within an `int`.
fn kstrtoint(s: &[u8]) -> Option<i32> {
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    // `kstrtoll` strips a `+`, then `kstrtoull` another one.
    let s = if !neg && s.first() == Some(&b'+') { &s[1..] } else { s };
    let (radix, digits) = if s.len() >= 3 && s[0] == b'0' && s[1] | 0x20 == b'x' && s[2].is_ascii_hexdigit() {
        (16, &s[2..])
    } else if s.first() == Some(&b'0') {
        (8, s)
    } else {
        (10, s)
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: i64 = 0;
    for &c in digits {
        let d = char::from(c).to_digit(radix)?;
        v = v.checked_mul(i64::from(radix))?.checked_add(i64::from(d))?;
        if v > i64::from(i32::MAX) + 1 {
            return None;
        }
    }
    i32::try_from(if neg { -v } else { v }).ok()
}

/// What `content` of the control file asks for, as the kernel parses a write
/// to it (module documentation).
pub(crate) fn parse(version: Version, content: &[u8]) -> Request {
    if content.is_empty() {
        return Request::Empty;
    }
    if content.len() > MAX_FILE {
        return Request::Invalid;
    }
    let s = strstrip(content);
    let state = match version {
        Version::V1 => match s {
            b"THAWED" => Some(State::Thawed),
            b"FROZEN" => Some(State::Frozen),
            _ => None,
        },
        Version::V2 => match kstrtoint(s) {
            Some(0) => Some(State::Thawed),
            Some(1) => Some(State::Frozen),
            _ => None,
        },
    };
    state.map_or(Request::Invalid, Request::Set)
}

/// `--cgroup freezer.state=<value>` (v1) at the start: the state, or `None`
/// where the kernel would refuse the jailer's write of it (the jailer writes
/// the value as given, its newline-free argument).
pub(crate) fn parse_start(value: &str) -> Option<State> {
    match parse(Version::V1, value.as_bytes()) {
        Request::Set(state) => Some(state),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each case is what the kernel does with the same write (module
    // documentation): v1 `freezer_write`'s strstrip and exact strings, v2
    // `cgroup_freeze_write`'s strstrip, kstrtoint(…, 0) and range check.
    #[test]
    fn test_parse_as_the_kernel_does() {
        use Request::*;
        use State::*;
        for (content, want) in [
            (&b"FROZEN"[..], Set(Frozen)),
            (b"FROZEN\n", Set(Frozen)),
            (b"  THAWED \t\n", Set(Thawed)),
            (b"frozen", Invalid),
            (b"FREEZING", Invalid),
            (b"FROZEN x", Invalid),
            (b"\n", Invalid),
            (b"", Empty),
        ] {
            assert_eq!(parse(Version::V1, content), want, "v1 {content:?}");
        }
        for (content, want) in [
            (&b"1"[..], Set(Frozen)),
            (b"1\n", Set(Frozen)),
            (b" 0 ", Set(Thawed)),
            (b"+1", Set(Frozen)),
            (b"++1", Set(Frozen)),
            (b"+-1", Invalid),
            (b"01", Set(Frozen)),
            (b"0x1", Set(Frozen)),
            (b"0x0", Set(Thawed)),
            (b"-0", Set(Thawed)),
            (b"2", Invalid),
            (b"-1", Invalid),
            (b"08", Invalid),
            (b"0x", Invalid),
            (b"1 1", Invalid),
            (b"yes", Invalid),
            (b"4294967297", Invalid),
            (b"", Empty),
        ] {
            assert_eq!(parse(Version::V2, content), want, "v2 {content:?}");
        }
        assert_eq!(parse(Version::V2, &[b'1'; MAX_FILE + 1]), Invalid);
    }

    #[test]
    fn test_canonical_values_parse_back() {
        for v in [Version::V1, Version::V2] {
            for s in [State::Thawed, State::Frozen] {
                assert_eq!(parse(v, v.canonical(s)), Request::Set(s));
            }
        }
        assert_eq!(events(true, false), b"populated 1\nfrozen 0\n");
        assert_eq!(events(false, true), b"populated 0\nfrozen 1\n");
    }

    #[test]
    fn test_parse_start() {
        assert_eq!(parse_start("FROZEN"), Some(State::Frozen));
        assert_eq!(parse_start("THAWED"), Some(State::Thawed));
        for bad in ["", "FREEZING", "frozen", "1"] {
            assert_eq!(parse_start(bad), None, "{bad:?}");
        }
    }
}
