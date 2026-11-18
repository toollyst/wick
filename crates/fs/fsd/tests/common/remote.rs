// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A wick-fsd process (the binary this crate builds), started on a share and
//! spoken to as the VMM would: over its socket, in frames.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wick_fs_frame::{self as frame, HEADER_LEN, Header, Kind, MAX_PAYLOAD_LEN, Sender};
use wick_fs_sys as sys;

use super::Link;

/// The share id the tests use.
pub const ID: &str = "t";

/// The arguments every test server gets: limits that fit any
/// `RLIMIT_NOFILE`, and, as root, the ids to drop to.
pub fn base_args(share: &Path, socket: &Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "--share-dir",
        share.to_str().unwrap(),
        "--socket",
        socket.to_str().unwrap(),
        "--id",
        ID,
        "--max-nodes",
        "4096",
        "--max-handles",
        "256",
        "--case-insensitive-ok",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if sys::euid() == 0 {
        a.extend(["--uid", "65534", "--gid", "65534"].map(String::from));
    }
    a
}

/// A socket path for a test beneath `base`: `base/fs.sock`, or, where that
/// is longer than a Unix socket's path may be (macOS's temporary directory
/// is deep), one in `/tmp` named for this process and a counter.
pub fn socket_in(base: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let p = base.join("fs.sock");
    if p.as_os_str().len() < 100 {
        return p;
    }
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    PathBuf::from(format!("/tmp/wick-fsd-{}-{n}.sock", std::process::id()))
}

/// As root the server drops to 65534: the share must be its.
pub fn give_share(share: &Path) {
    if sys::euid() == 0 {
        std::os::unix::fs::chown(share, Some(65534), Some(65534)).unwrap();
    }
}

/// Why this host refuses a server that is not root its user namespace, if
/// it does (the sysctls of Ubuntu's AppArmor restriction and of the
/// namespace limit). `WICK_FS_TEST_USERNS_GRANTED=1` says an AppArmor
/// profile grants the built wick-fsd and confine_probe user namespaces
/// whatever the sysctl (the CI fs job's step): then nothing is restricted,
/// and a refusal fails the test.
///
/// `WICK_FS_TEST_SIMULATE_USERNS_RESTRICTED=1` (not root) stands in for such
/// a host where it has none: every server the tests start runs under
/// `confine::simulated_userns_restriction`, which refuses its setgroups
/// write with EACCES as Ubuntu's restriction does, and this says so.
pub fn userns_restricted() -> Option<String> {
    if sys::euid() == 0 || std::env::var_os("WICK_FS_TEST_USERNS_GRANTED").is_some_and(|v| v == "1") {
        return None;
    }
    if simulated_restriction() {
        return Some("simulated (WICK_FS_TEST_SIMULATE_USERNS_RESTRICTED=1: the setgroups write refused, EACCES)".into());
    }
    let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        return Some("kernel.apparmor_restrict_unprivileged_userns = 1".into());
    }
    if read("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        return Some("user.max_user_namespaces = 0".into());
    }
    if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        return Some("kernel.unprivileged_userns_clone = 0".into());
    }
    None
}

/// Whether the tests stand in for a host that restricts user namespaces
/// ([`userns_restricted`]).
fn simulated_restriction() -> bool {
    cfg!(target_os = "linux") && sys::euid() != 0 && std::env::var_os("WICK_FS_TEST_SIMULATE_USERNS_RESTRICTED").is_some_and(|v| v == "1")
}

/// Whether `err` is the refusal of a host that restricts user namespaces:
/// one of the user namespace's steps named (the `unshare`, or a write of
/// its maps or of setgroups, which Ubuntu's AppArmor restriction refuses),
/// and no serving unconfined.
pub fn is_userns_refusal(err: &str) -> bool {
    let step = ["unshare of the namespaces", "/proc/self/setgroups", "/proc/self/uid_map", "/proc/self/gid_map"]
        .iter()
        .any(|s| err.contains(&format!("confinement: {s} failed")));
    step && err.contains("does not serve unconfined")
}

/// A confined server over `share` (given to 65534 as root), connected:
/// `None`, said on stderr, where this host refuses the user namespace a
/// server that is not root needs (the refusal itself is checked by
/// `server.rs`'s `test_userns_restricted_refused`).
pub fn confined_over(share: &Path, socket: &Path) -> Option<Remote> {
    give_share(share);
    match Remote::connect(Server::start(&base_args(share, socket), |_| {})) {
        Ok(r) => Some(r),
        Err((mut server, why)) => {
            let (status, err) = server.wait();
            if let Some(restricted) = userns_restricted() {
                assert!(!status.success() && is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                eprintln!("ran nothing confined: {restricted}; refused at its user namespace, as it must: {err}");
                return None;
            }
            panic!("no confined server ({why}; {status:?}): {err}");
        }
    }
}

/// Ends a confined run: the server must end normally at the close, with no
/// refusal of layer 2 or 3 in its counters.
pub fn finish_clean(r: &mut Remote) {
    let (status, err) = r.finish();
    assert!(status.success(), "the confined server ended {status:?}: {err}");
    assert!(err.contains("layer refusals 0,"), "{err}");
}

/// A running wick-fsd.
#[derive(Debug)]
pub struct Server {
    pub child: Child,
    pub socket: PathBuf,
    stderr: Arc<Mutex<String>>,
}

impl Server {
    /// Starts `wick-fsd args` (with `cmd` changed by `prepare`, as the
    /// refusal tests do) and waits for its `ready` line.
    pub fn start(args: &[String], prepare: impl FnOnce(&mut Command)) -> Server {
        Server::start_from(Path::new(env!("CARGO_BIN_EXE_wick-fsd")), args, prepare)
    }

    /// [`Server::start`] of the wick-fsd at `program` (a copy, where the
    /// built one cannot be reached).
    pub fn start_from(program: &Path, args: &[String], prepare: impl FnOnce(&mut Command)) -> Server {
        let mut s = Server::spawn_from(program, args, prepare);
        let mut line = String::new();
        let _ = BufReader::new(s.child.stdout.take().unwrap()).read_line(&mut line);
        if line.trim() != "ready" {
            let (status, err) = s.wait();
            panic!("wick-fsd did not start ({status:?}): {err}");
        }
        s
    }

    /// Starts `wick-fsd args` as [`Server::start`] does, without waiting
    /// for `ready`: for a server refused before it.
    pub fn spawn(args: &[String], prepare: impl FnOnce(&mut Command)) -> Server {
        Server::spawn_from(Path::new(env!("CARGO_BIN_EXE_wick-fsd")), args, prepare)
    }

    /// [`Server::spawn`] of the wick-fsd at `program`.
    pub fn spawn_from(program: &Path, args: &[String], prepare: impl FnOnce(&mut Command)) -> Server {
        let mut cmd = Command::new(program);
        cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(target_os = "linux")]
        if simulated_restriction() {
            sys::confine::command_with_filter(&mut cmd, sys::confine::simulated_userns_restriction());
        }
        prepare(&mut cmd);
        // A step of the tests' own before the exec says itself on the
        // child's stderr and ends it (sys::confine's helpers): a spawn that
        // fails is the fork or the exec.
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("{}: not started, the fork or the exec failed: {e}", program.display()));
        let stderr = Arc::new(Mutex::new(String::new()));
        // For tools/macos/fs-server-report.py: each server's pid with the
        // test that started it, and its stderr (a discovery build's request
        // lines) as it comes, under WICK_FS_REPORT_DIR.
        let report = std::env::var_os("WICK_FS_REPORT_DIR").map(PathBuf::from);
        if let Some(dir) = &report {
            let test = std::thread::current().name().unwrap_or("?").to_string();
            let mut pids = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("pids")).unwrap();
            pids.write_all(format!("{} {test}\n", child.id()).as_bytes()).unwrap();
        }
        {
            let mut pipe = child.stderr.take().unwrap();
            let into = stderr.clone();
            let mut tee = report.map(|d| std::fs::File::create(d.join(format!("{}.stderr", child.id()))).unwrap());
            std::thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                // A character cut by a read waits for the rest.
                let mut pending = Vec::new();
                while let Ok(n @ 1..) = pipe.read(&mut chunk) {
                    if let Some(f) = tee.as_mut() {
                        let _ = f.write_all(&chunk[..n]);
                    }
                    pending.extend_from_slice(&chunk[..n]);
                    let whole = match std::str::from_utf8(&pending) {
                        Ok(_) => pending.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => pending.len(),
                    };
                    into.lock().unwrap().push_str(&String::from_utf8_lossy(&pending[..whole]));
                    pending.drain(..whole);
                }
                into.lock().unwrap().push_str(&String::from_utf8_lossy(&pending));
            });
        }
        let socket = PathBuf::from(&args[args.iter().position(|a| a == "--socket").unwrap() + 1]);
        Server { child, socket, stderr }
    }

    /// Waits (at most 30 s, then kills it) for the server to end: its status
    /// and everything it wrote to stderr.
    pub fn wait(&mut self) -> (ExitStatus, String) {
        let start = Instant::now();
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = self.child.kill();
                break self.child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // The reader thread ends at the pipe's end.
        std::thread::sleep(Duration::from_millis(50));
        (status, self.stderr.lock().unwrap().clone())
    }

    /// What the server's processes wrote to stderr so far (a confined child
    /// may write after its waiting parent ended).
    #[cfg(target_os = "linux")]
    pub fn stderr_now(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The pid of the confined process: the child the server forked.
    #[cfg(target_os = "linux")]
    pub fn confined_pid(&self) -> Option<i32> {
        let parent = i32::try_from(self.child.id()).unwrap();
        for e in std::fs::read_dir("/proc").ok()? {
            let e = e.ok()?;
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            // "pid (comm) state ppid ...": the fields after the last ')'.
            let rest = &stat[stat.rfind(')')? + 2..];
            if rest.split(' ').nth(1).and_then(|p| p.parse::<i32>().ok()) == Some(parent) {
                return Some(pid);
            }
        }
        None
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The VMM's side of a connection to a wick-fsd.
#[derive(Debug)]
pub struct Remote {
    pub stream: UnixStream,
    pub server: Server,
    cookie: u64,
}

impl Remote {
    /// Connects to `server` and exchanges the hellos.
    pub fn connect(server: Server) -> Result<Remote, (Server, String)> {
        let stream = match UnixStream::connect(&server.socket) {
            Ok(s) => s,
            Err(e) => return Err((server, format!("connect: {e}"))),
        };
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut r = Remote { stream, server, cookie: 0 };
        match r.read_frame() {
            Some((h, p)) if h.kind() == Kind::Hello => {
                let f = frame::Frame { header: h, payload: &p };
                if let Err(e) = frame::check_hello(&f, ID) {
                    return Err((r.server, format!("{e:?}")));
                }
            }
            other => {
                let msg = format!("no hello: {other:?}");
                return Err((r.server, msg));
            }
        }
        r.stream.write_all(&frame::hello_frame(ID).unwrap()).unwrap();
        Ok(r)
    }

    fn read_frame(&mut self) -> Option<(Header, Vec<u8>)> {
        let mut head = [0u8; HEADER_LEN];
        self.stream.read_exact(&mut head).ok()?;
        let h = Header::parse(&head, Sender::Server).unwrap();
        let mut payload = vec![0u8; h.payload_len()];
        self.stream.read_exact(&mut payload).unwrap();
        Some((h, payload))
    }

    /// Closes the connection and waits for the server: its status and
    /// stderr.
    pub fn finish(&mut self) -> (ExitStatus, String) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        self.server.wait()
    }
}

impl Link for Remote {
    fn send(&mut self, req: &[u8], cap: usize) -> Option<Vec<u8>> {
        self.cookie += 1;
        let cap = u32::try_from(cap.min(MAX_PAYLOAD_LEN)).unwrap();
        // A request that gets no reply goes on the hiprio queue, as FORGET
        // does.
        let queue = u16::from(cap != 0);
        let h = Header::request(self.cookie, queue, cap, req.len()).unwrap();
        self.stream.write_all(&h.encode()).unwrap();
        self.stream.write_all(req).unwrap();
        if cap == 0 {
            return None;
        }
        let (h, payload) = self.read_frame().expect("the server ended without a reply");
        assert_eq!((h.kind(), h.cookie()), (Kind::Reply, self.cookie));
        super::check_reply(req, &payload);
        Some(payload)
    }
}
