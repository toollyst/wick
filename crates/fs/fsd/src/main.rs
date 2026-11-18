// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `wick-fsd`: one confined file server per shared host directory
//! (docs/design-fs.md §4.2). The jailer starts it, or the operator does, with
//! the same command line:
//!
//! ```text
//! wick-fsd --share-dir DIR --socket PATH --id ID [--read-only]
//!          [--cache auto|never|always] [--cache-timeout-ms N]
//!          [--peer-uid UID] [--uid UID --gid GID] [--ready-fd FD]
//!          [--case-insensitive-ok] [--max-nodes N] [--max-held N] [--max-handles N] [--max-bytes N]
//! ```
//!
//! Stage 0, with the operator's rights and no byte from the VMM: the share's
//! checks, the socket bound and listened on, ready said (a byte on
//! `--ready-fd`, else a `ready` line on stdout), one connection accepted, the
//! listener closed and unlinked, the peer's uid checked against `--peer-uid`
//! (default: this process's). Then the confinement, and only then the hellos
//! and the requests, until the VMM closes the connection. Every step is
//! required: there is no option that serves unconfined. On a host without
//! confinement yet (macOS until its commit, Windows until its port) the
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
                     [--cache-timeout-ms N] [--peer-uid UID] [--uid UID --gid GID] [--ready-fd FD] \
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

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wick-fsd: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wick-fsd: {}: {e}", args.id);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_: &Args) -> Result<(), String> {
    Err("this host has no confinement for wick-fsd yet (Linux has; macOS comes with its own commit, Windows with \
         its port), and wick-fsd does not serve unconfined"
        .into())
}

#[cfg(target_os = "linux")]
fn run(args: &Args) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixListener;

    use wick_fs_sys as sys;
    use wick_fsd::confine::linux::{self as confine, Plan};
    use wick_fsd::host::unix::{HostDir, Options};
    use wick_fsd::session::{Config, Session};
    use wick_fsd::stage0::{self, Share};
    use wick_fsd::serve;

    let share = Share {
        dir: args.share_dir.clone(),
        read_only: args.read_only,
        case_insensitive_ok: args.case_insensitive_ok,
        limits: args.limits,
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let checked = stage0::check(&share, home.as_deref()).map_err(|r| r.0)?;
    if args.socket.symlink_metadata().is_ok() {
        return Err(format!("{} exists; wick-fsd never removes what it did not make", args.socket.display()));
    }
    let listener = UnixListener::bind(&args.socket).map_err(|e| format!("{}: {e}", args.socket.display()))?;
    match args.ready_fd {
        Some(fd) => {
            let fd = sys::take_inherited(fd).map_err(|e| format!("--ready-fd {fd}: {e:?}"))?;
            std::fs::File::from(fd).write_all(b"R").map_err(|e| format!("--ready-fd: {e}"))?;
        }
        None => println!("ready"),
    }
    let accepted = listener.accept();
    // Exactly one connection: the listener goes whatever the accept gave.
    drop(listener);
    let _ = std::fs::remove_file(&args.socket);
    let (conn, _) = accepted.map_err(|e| format!("accept: {e}"))?;
    let peer_uid = args.peer_uid.unwrap_or_else(sys::euid);
    let (uid, pid) = sys::confine::peer(conn.as_fd()).map_err(|e| format!("SO_PEERCRED: {e:?}"))?;
    if uid != peer_uid {
        return Err(format!("the peer (pid {pid}) is uid {uid}, not --peer-uid {peer_uid}: connection refused"));
    }
    let plan = Plan {
        read_only: args.read_only,
        drop_to: args.drop_to,
    };
    // The waiting parent drops the connection; only the confined child
    // serves it.
    let (root, mut conn, watch) = confine::enter(checked, plan, conn).map_err(|r| r.0)?;
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
    let mut session = Session::new(dir, config).map_err(|e| format!("the share's root: {e:?}"))?;
    let locked = confine::lock(plan, watch).map_err(|r| r.0)?;
    eprintln!(
        "wick-fsd: {}: confined (namespaces, pivot_root, no capabilities, no_new_privs, seccomp{})",
        args.id,
        locked.landlock.map_or_else(String::new, |abi| format!(", Landlock ABI {abi}"))
    );
    serve::hello(&mut conn, &args.id).map_err(|e| e.to_string())?;
    let end = serve::serve(&mut conn, &mut session);
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
