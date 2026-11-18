// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `wick-fsd`: one confined file server per shared host directory
//! (docs/design-fs.md §4.2). The jailer starts it, or the operator does, with
//! the same command line:
//!
//! ```text
//! wick-fsd --share-dir DIR --socket PATH --id ID [--read-only]
//!          [--cache auto|never|always] [--cache-timeout-ms N]
//!          [--peer-uid UID] [--uid UID --gid GID] [--ready-fd FD (3 or more)]
//!          [--case-insensitive-ok] [--max-nodes N] [--max-held N] [--max-handles N] [--max-bytes N]
//! ```
//!
//! Stage 0, with the operator's rights and no byte from the VMM: the share's
//! checks, the socket bound and listened on, ready said (a byte on
//! `--ready-fd`, else a `ready` line on stdout), one connection accepted, the
//! listener closed and unlinked, the peer's uid checked against `--peer-uid`
//! (default: this process's). Before all of it, its first step: every
//! descriptor it was started with but the standard streams and
//! `--ready-fd` closed, and standard input made `/dev/null` (wick-fsd reads
//! none), so nothing its launcher left open reaches the confined server
//! (docs/design-fs.md §4.2). Then the confinement, and only then the hellos
//! and the requests, until the VMM closes the connection. Every step is
//! required: there is no option that serves unconfined. On a host without
//! confinement yet (Windows, until its port) the
//! server refuses to start.

use std::path::PathBuf;
use std::process::ExitCode;

use wick_fsd::cache::{CacheMode, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS};
use wick_fsd::limits::Limits;

/// The command line.
#[derive(Debug)]
#[allow(dead_code, reason = "a host without confinement reads the options but serves nothing")]
struct Args {
    share_dir: PathBuf,
    socket: PathBuf,
    id: String,
    read_only: bool,
    cache: CacheMode,
    peer_uid: Option<u32>,
    drop_to: Option<(u32, u32)>,
    ready_fd: Option<i32>,
    case_insensitive_ok: bool,
    limits: Limits,
}

const USAGE: &str = "usage: wick-fsd --share-dir DIR --socket PATH --id ID [--read-only] [--cache auto|never|always] \
                     [--cache-timeout-ms N] [--peer-uid UID] [--uid UID --gid GID] [--ready-fd FD (3 or more)] \
                     [--case-insensitive-ok] [--max-nodes N] [--max-held N] [--max-handles N] [--max-bytes N]";

fn number<T: std::str::FromStr>(flag: &str, v: Option<String>) -> Result<T, String> {
    let v = v.ok_or_else(|| format!("{flag} needs a value"))?;
    v.parse().map_err(|_| format!("{flag}: not a number: {v}"))
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut share_dir, mut socket, mut id) = (None, None, None);
    let (mut read_only, mut case_insensitive_ok) = (false, false);
    let (mut cache, mut timeout) = ("auto".to_string(), DEFAULT_TIMEOUT_MS);
    let (mut peer_uid, mut uid, mut gid, mut ready_fd) = (None, None, None, None);
    let mut limits = Limits::default();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--share-dir" => share_dir = Some(PathBuf::from(it.next().ok_or("--share-dir needs a value")?)),
            "--socket" => socket = Some(PathBuf::from(it.next().ok_or("--socket needs a value")?)),
            "--id" => id = Some(it.next().ok_or("--id needs a value")?),
            "--read-only" => read_only = true,
            "--case-insensitive-ok" => case_insensitive_ok = true,
            "--cache" => cache = it.next().ok_or("--cache needs a value")?,
            "--cache-timeout-ms" => timeout = number(&flag, it.next())?,
            "--peer-uid" => peer_uid = Some(number(&flag, it.next())?),
            "--uid" => uid = Some(number(&flag, it.next())?),
            "--gid" => gid = Some(number(&flag, it.next())?),
            "--ready-fd" => ready_fd = Some(number(&flag, it.next())?),
            "--max-nodes" => limits.max_nodes = number(&flag, it.next())?,
            "--max-held" => limits.max_held = number(&flag, it.next())?,
            "--max-handles" => limits.max_handles = number(&flag, it.next())?,
            "--max-bytes" => limits.max_bytes = number(&flag, it.next())?,
            "--help" | "-h" => return Err(USAGE.into()),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
    }
    // A descriptor of its own: 0 to 2 are the standard streams, which the
    // ready byte's close would free for the next open (the connection or
    // the share's root) to take, and the log would then go there.
    if let Some(fd) = ready_fd
        && fd < 3
    {
        return Err(format!("--ready-fd {fd}: 0 to 2 are the standard streams and below 0 is none; give 3 or more"));
    }
    if timeout > MAX_TIMEOUT_MS {
        return Err(format!("--cache-timeout-ms: at most {MAX_TIMEOUT_MS}"));
    }
    let cache = match cache.as_str() {
        "never" => CacheMode::Never,
        "auto" => CacheMode::Auto { timeout_ms: timeout },
        "always" => CacheMode::Always { timeout_ms: timeout },
        other => return Err(format!("--cache: auto, never or always, not {other}")),
    };
    let id = id.ok_or_else(|| format!("--id is required\n{USAGE}"))?;
    wick_fs_frame::check_id(&id).map_err(|_| format!("--id {id}: 1 to 64 characters of [a-z0-9_-]"))?;
    let drop_to = match (uid, gid) {
        (Some(u), Some(g)) => Some((u, g)),
        (None, None) => None,
        _ => return Err("--uid and --gid go together".into()),
    };
    Ok(Args {
        share_dir: share_dir.ok_or_else(|| format!("--share-dir is required\n{USAGE}"))?,
        socket: socket.ok_or_else(|| format!("--socket is required\n{USAGE}"))?,
        id,
        read_only,
        cache,
        peer_uid,
        drop_to,
        ready_fd,
        case_insensitive_ok,
        limits,
    })
}

/// What the first step leaves this process holding: `--ready-fd`, checked.
#[derive(Debug, Default)]
struct Start {
    #[cfg(unix)]
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code, reason = "a host without confinement says no ready"))]
    ready: Option<std::os::fd::OwnedFd>,
}

/// The first step, before anything is opened: every descriptor but 0 to 2
/// and `--ready-fd` closed, whatever its number, and the kernel's list read
/// back (any left named, a refusal); standard input made
/// `/dev/null`; `--ready-fd` checked to be a pipe's write end or a socket.
/// Standard output and error are kept as given (std's start opens
/// `/dev/null` for any of 0 to 2 that is closed): the operator's channel
/// for `ready` and the log, which the server only writes.
#[cfg(unix)]
fn start(args: &Args) -> Result<Start, String> {
    use std::os::fd::AsFd;

    use wick_fs_sys as sys;

    // Closed, then read back from the kernel's list: anything left (a close
    // that failed, or said done and was not) is named, each by what it is.
    let closed = sys::close_inherited(args.ready_fd);
    let open = sys::open_descriptors().map_err(|e| format!("listing its descriptors: {e:?}"))?;
    let left: Vec<String> = open
        .iter()
        .filter(|&&fd| fd > 2 && Some(fd) != args.ready_fd)
        .map(|&fd| sys::descriptor_described(fd))
        .collect();
    if closed.is_err() || !left.is_empty() {
        return Err(format!(
            "closing the descriptors it was started with ({}), left open: [{}]; wick-fsd does not serve with them",
            closed.map_or_else(|e| format!("{e:?}"), |()| "said done".into()),
            left.join(", ")
        ));
    }
    sys::stdin_from_null().map_err(|e| format!("standard input from /dev/null: {e:?}"))?;
    let ready = match args.ready_fd {
        None => None,
        Some(fd) => {
            let owned = sys::take_inherited(fd).map_err(|e| format!("--ready-fd {fd}: {e:?}"))?;
            if !sys::is_write_channel(owned.as_fd()).map_err(|e| format!("--ready-fd {fd}: {e:?}"))? {
                return Err(format!(
                    "--ready-fd {fd} is not a pipe's write end or a socket ({})",
                    sys::descriptor_described(fd)
                ));
            }
            Some(owned)
        }
    };
    Ok(Start { ready })
}

#[cfg(not(unix))]
fn start(_: &Args) -> Result<Start, String> {
    Ok(Start::default())
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wick-fsd: {e}");
            return ExitCode::from(2);
        }
    };
    let start = match start(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("wick-fsd: {}: {e}", args.id);
            return ExitCode::FAILURE;
        }
    };
    match run(&args, start) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wick-fsd: {}: {e}", args.id);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_: &Args, _: Start) -> Result<(), String> {
    Err("this host has no confinement for wick-fsd yet (Linux and macOS have; Windows comes with its port), and \
         wick-fsd does not serve unconfined"
        .into())
}

/// Stage 0 on a Unix host: the share checked, the soft RLIMIT_NOFILE set,
/// the socket bound, ready said, one connection accepted, the listener
/// unlinked, and the peer checked.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn accept_one(args: &Args, start: Start) -> Result<(wick_fsd::stage0::Checked, std::os::unix::net::UnixStream), String> {
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;

    use wick_fs_sys as sys;
    use wick_fsd::stage0::{self, Share};

    let share = Share {
        dir: args.share_dir.clone(),
        read_only: args.read_only,
        case_insensitive_ok: args.case_insensitive_ok,
        limits: args.limits,
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let checked = stage0::check(&share, home.as_deref()).map_err(|r| r.0)?;
    // The soft RLIMIT_NOFILE set to exactly what the limits may hold open
    // (stage 0 checked the hard one allows it): no more for the server,
    // and the bound of the Linux read-back's walk over its descriptors.
    let need = wick_fsd::limits::descriptors(&args.limits);
    sys::set_nofile(need).map_err(|e| format!("RLIMIT_NOFILE to {need}: {e:?}"))?;
    let (soft, _) = sys::nofile().map_err(|e| format!("RLIMIT_NOFILE: {e:?}"))?;
    if soft != need {
        return Err(format!("the soft RLIMIT_NOFILE is {soft} after setting it to {need}"));
    }
    if args.socket.symlink_metadata().is_ok() {
        return Err(format!("{} exists; wick-fsd never removes what it did not make", args.socket.display()));
    }
    let listener = UnixListener::bind(&args.socket).map_err(|e| format!("{}: {e}", args.socket.display()))?;
    // The ready byte, then `--ready-fd` closed: it is not held after.
    match start.ready {
        Some(fd) => std::fs::File::from(fd).write_all(b"R").map_err(|e| format!("--ready-fd: {e}"))?,
        None => println!("ready"),
    }
    let accepted = listener.accept();
    // Exactly one connection: the listener goes whatever the accept gave.
    drop(listener);
    let _ = std::fs::remove_file(&args.socket);
    let (conn, _) = accepted.map_err(|e| format!("accept: {e}"))?;
    let peer_uid = args.peer_uid.unwrap_or_else(sys::euid);
    #[cfg(target_os = "linux")]
    let (uid, pid) = sys::confine::peer(conn.as_fd()).map_err(|e| format!("SO_PEERCRED: {e:?}"))?;
    #[cfg(target_os = "macos")]
    let (uid, pid) = sys::seatbelt::peer(conn.as_fd()).map_err(|e| format!("LOCAL_PEERCRED: {e:?}"))?;
    if uid != peer_uid {
        return Err(format!("the peer (pid {pid}) is uid {uid}, not --peer-uid {peer_uid}: connection refused"));
    }
    Ok((checked, conn))
}

/// The backend and the session over the confined root.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn session_over(
    args: &Args,
    root: std::os::fd::OwnedFd,
) -> Result<wick_fsd::session::Session<wick_fsd::host::unix::HostDir>, String> {
    use wick_fsd::host::unix::{HostDir, Options};
    use wick_fsd::session::{Config, Session};

    let dir = HostDir::new(
        root,
        Options {
            case_insensitive_ok: args.case_insensitive_ok,
            max_held: args.limits.max_held,
        },
    )
    .map_err(|r| r.0)?;
    let config = Config {
        cache: args.cache,
        read_only: args.read_only,
        limits: args.limits,
        ..Config::default()
    };
    Session::new(dir, config).map_err(|e| format!("the share's root: {e:?}"))
}

/// The hellos and the requests until the VMM closes the connection.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn serve_all(
    args: &Args,
    conn: &mut std::os::unix::net::UnixStream,
    session: &mut wick_fsd::session::Session<wick_fsd::host::unix::HostDir>,
) -> Result<(), String> {
    use wick_fsd::serve;

    serve::hello(conn, &args.id).map_err(|e| e.to_string())?;
    let end = serve::serve(conn, session);
    let c = session.counters();
    eprintln!(
        "wick-fsd: {}: {end}; counters: requests refused {}, nodes refused {}, handles refused {}, bytes refused \
         {}, xattrs refused {}, records refused {}, names skipped {}, layer refusals {}, forgets unmatched {}, \
         replies too long {}",
        args.id,
        c.requests_refused,
        c.nodes_refused,
        c.handles_refused,
        c.bytes_refused,
        c.xattr_refused,
        c.records_refused,
        c.names_skipped,
        c.layer_refusals,
        c.forgets_unmatched,
        c.replies_too_long
    );
    match end {
        serve::End::Closed => Ok(()),
        other => Err(other.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn run(args: &Args, start: Start) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    use wick_fsd::confine::linux::{self as confine, Plan};

    let (checked, conn) = accept_one(args, start)?;
    let plan = Plan {
        read_only: args.read_only,
        drop_to: args.drop_to,
    };
    // The waiting parent drops the connection; only the confined child
    // serves it.
    let conn_fd = conn.as_raw_fd();
    let (root, mut conn, watch) = confine::enter(checked, plan, conn, &[conn_fd]).map_err(|r| r.0)?;
    let root_fd = root.as_raw_fd();
    let mut session = session_over(args, root)?;
    // What it holds when it serves: the connection and the share's root,
    // which the backend keeps (it holds no other descriptor before a
    // request).
    let locked = confine::lock(plan, watch, &[conn_fd, root_fd]).map_err(|r| r.0)?;
    eprintln!(
        "wick-fsd: {}: confined (namespaces, pivot_root, no capabilities, no_new_privs, seccomp{})",
        args.id,
        locked.landlock.map_or_else(String::new, |abi| format!(", Landlock ABI {abi}"))
    );
    serve_all(args, &mut conn, &mut session)
}

#[cfg(target_os = "macos")]
fn run(args: &Args, start: Start) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    use wick_fsd::confine::macos::{self as confine, Plan};

    let (checked, mut conn) = accept_one(args, start)?;
    let plan = Plan {
        read_only: args.read_only,
        drop_to: args.drop_to,
    };
    let canonical = checked.canonical.clone();
    let conn_fd = conn.as_raw_fd();
    let root_fd = checked.root.as_raw_fd();
    let mut session = session_over(args, checked.root)?;
    // What it holds when it serves, as on Linux: the connection and the
    // share's root (the backend holds no other descriptor before a request).
    confine::confine(plan, &canonical, &[conn_fd, root_fd]).map_err(|r| r.0)?;
    eprintln!("wick-fsd: {}: confined (Seatbelt profile of the share, ids dropped)", args.id);
    serve_all(args, &mut conn, &mut session)
}
