// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The parent watch (docs/design-fs.md §8, Jailer): wick-fsd lives for the
//! process that started it. Its parent here is this test binary started
//! again on `parent_of_a_server` alone (with posix_spawn on macOS, no fork
//! in a test process: sys/src/unix/launch.rs), which starts the server and
//! then, as root, drops to another uid as the jailer does before it execs
//! Firecracker: the case a parent-death signal could not cover (the kernel
//! sends it as the dying parent, through the kill permission check). The
//! parent is killed in each phase: before the VMM connected, while the
//! server waits for a frame, and while it is held writing READ replies the
//! VMM does not read. Each time the server (on Linux both its processes)
//! must be gone within 5 s, saying why, and its socket gone with it. Also
//! the start's refusals: a parent that is pid 1 unless named, and a
//! `--parent-pid` that is not the parent.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use common::remote::{ID, base_args, give_share, socket_in, userns_restricted};
use common::{H, Link, le32, le64, scratch};
use wick_fs_frame::{self as frame, HEADER_LEN, Header, Kind, MAX_PAYLOAD_LEN, Sender};
use wick_fs_sys as sys;
use wick_fs_sys::launch::{self, Descriptors, Io, Launched};
use wick_fsd::fuse::Opcode;
use wick_fsd::fuse::encode::request;

/// How long a server may take to end after its parent did.
const BOUND: Duration = Duration::from_secs(5);

/// The parent: starts wick-fsd with the arguments in `WICK_FSD_PARENT` (one
/// a line), its standard output and error this process's, says its pid,
/// drops to `WICK_FSD_PARENT_DROP` (`uid:gid`) if given, and waits to be
/// killed. Ignored, and nothing without its variable.
#[test]
#[ignore = "the parent of a server, run by the tests here alone"]
fn parent_of_a_server() {
    let Ok(args) = std::env::var("WICK_FSD_PARENT") else { return };
    let mut child = Command::new(env!("CARGO_BIN_EXE_wick-fsd"))
        .args(args.lines())
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    println!("\nserver {}", child.id());
    std::io::stdout().flush().unwrap();
    if let Ok(ids) = std::env::var("WICK_FSD_PARENT_DROP") {
        let (u, g) = ids.split_once(':').unwrap();
        sys::drop_ids_here(u.parse().unwrap(), g.parse().unwrap()).unwrap();
        println!("\ndropped {ids}");
        std::io::stdout().flush().unwrap();
    }
    // Until it is killed; the server, its child, is reaped if it ends first.
    loop {
        let _ = child.try_wait();
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A server under its own parent, as `parent_of_a_server` starts it.
struct Family {
    parent: Launched,
    server: i32,
    out: std::sync::mpsc::Receiver<String>,
    err: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Family {
    /// Starts the parent with the server's `args`; returns once the server
    /// said `ready` (and, as root, the parent dropped to 65533).
    fn start(args: &[String]) -> Family {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "parent_of_a_server", "--ignored", "--test-threads=1", "--nocapture"])
            .env("WICK_FSD_PARENT", args.join("\n"));
        let root = sys::euid() == 0;
        if root {
            cmd.env("WICK_FSD_PARENT_DROP", "65533:65533");
        }
        let mut parent = launch::launch(&cmd, [Io::Null, Io::Piped, Io::Piped], Descriptors::default()).unwrap();
        let (tx, out) = std::sync::mpsc::channel();
        let mut stdout = parent.stdout.take().unwrap();
        std::thread::spawn(move || {
            let mut text = String::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = stdout.read(&mut chunk) {
                text.push_str(&String::from_utf8_lossy(&chunk[..n]));
                while let Some(i) = text.find('\n') {
                    let line: String = text.drain(..=i).collect();
                    let _ = tx.send(line.trim().to_string());
                }
            }
        });
        let err = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut stderr = parent.stderr.take().unwrap();
        let into = err.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = stderr.read(&mut chunk) {
                into.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        });
        let mut server = None;
        let (mut ready, mut dropped) = (false, !root);
        let mut seen = Vec::new();
        while !(ready && dropped && server.is_some()) {
            let line = out.recv_timeout(Duration::from_secs(30)).unwrap_or_else(|_| {
                panic!("the parent and server did not start: stdout {seen:?}, stderr {}", err.lock().unwrap())
            });
            seen.push(line.clone());
            // libtest's "test parent_of_a_server ... " may lead a line, and
            // the server's `ready` may come after it.
            if let Some((_, p)) = line.rsplit_once("server ")
                && let Ok(p) = p.parse()
            {
                server = Some(p);
            }
            ready |= line == "ready" || line.ends_with(" ready");
            dropped |= line.contains("dropped ");
        }
        Family { parent, server: server.unwrap(), out, err }
    }

    /// Starts the parent with the server's `args` for a server refused at
    /// its start: the server's stderr once it ended (within 30 s).
    fn start_refused(args: &[String]) -> String {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "parent_of_a_server", "--ignored", "--test-threads=1", "--nocapture"])
            .env("WICK_FSD_PARENT", args.join("\n"));
        let mut parent = launch::launch(&cmd, [Io::Null, Io::Piped, Io::Piped], Descriptors::default()).unwrap();
        let mut stdout = parent.stdout.take().unwrap();
        let mut text = String::new();
        let mut chunk = [0u8; 4096];
        let t = Instant::now();
        let server = loop {
            let n = stdout.read(&mut chunk).unwrap();
            assert!(n > 0, "the parent ended: {text}");
            text.push_str(&String::from_utf8_lossy(&chunk[..n]));
            if let Some(p) = text.lines().find_map(|l| l.trim().rsplit_once("server ").and_then(|(_, p)| p.parse().ok())) {
                break p;
            }
            assert!(t.elapsed() < Duration::from_secs(30), "{text}");
        };
        while !gone(server) {
            assert!(t.elapsed() < Duration::from_secs(30), "the server did not end: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }
        parent.kill().unwrap();
        let out = parent.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// The server's processes now: it, and on Linux its confined child.
    fn processes(&self) -> Vec<i32> {
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut, reason = "Linux adds the confined child"))]
        let mut all = vec![self.server];
        #[cfg(target_os = "linux")]
        for e in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
            let after = &stat[stat.rfind(')').unwrap() + 2..];
            if after.split(' ').nth(1).and_then(|p| p.parse::<i32>().ok()) == Some(self.server) {
                all.push(pid);
            }
        }
        all
    }

    /// Kills the parent; then each of `processes` must be gone (or a
    /// zombie: it ended, its reaper not yet there) within [`BOUND`].
    /// Returns the server's stderr.
    fn kill_parent_then_gone(mut self, processes: &[i32]) -> String {
        self.parent.kill().unwrap();
        self.parent.wait().unwrap();
        let t = Instant::now();
        for &p in processes {
            while !gone(p) {
                assert!(t.elapsed() < BOUND, "pid {p} still there {:?} after its parent ended", t.elapsed());
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // Its last lines, once its stderr's writers are gone.
        std::thread::sleep(Duration::from_millis(100));
        drop(self.out);
        self.err.lock().unwrap().clone()
    }
}

/// Whether `pid` has ended: not there, or a zombie (`ps` state Z).
fn gone(pid: i32) -> bool {
    let out = Command::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().unwrap();
    let state = String::from_utf8_lossy(&out.stdout);
    state.trim().is_empty() || state.trim().starts_with('Z')
}

/// A share with `big`, 64 MiB, and the server's arguments over it.
fn share(tag: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, Vec<String>)> {
    if let Some(why) = userns_restricted() {
        eprintln!("{tag}: not run, this host restricts user namespaces ({why})");
        return None;
    }
    let base = scratch(tag);
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    let f = std::fs::File::create(share.join("big")).unwrap();
    f.set_len(64 << 20).unwrap();
    give_share(&share);
    let socket = socket_in(&base);
    let args = base_args(&share, &socket);
    Some((base, socket, args))
}

/// The VMM's side: the connection with the hellos exchanged.
struct Vmm {
    stream: UnixStream,
    cookie: u64,
}

impl Vmm {
    fn connect(socket: &Path) -> Vmm {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let (h, p) = read_frame(&mut stream);
        assert_eq!(h.kind(), Kind::Hello);
        frame::check_hello(&frame::Frame { header: h, payload: &p }, ID).unwrap();
        stream.write_all(&frame::hello_frame(ID).unwrap()).unwrap();
        Vmm { stream, cookie: 0 }
    }

    /// A request sent, its reply not read.
    fn post(&mut self, req: &[u8], cap: usize) {
        self.cookie += 1;
        let cap = u32::try_from(cap.min(MAX_PAYLOAD_LEN)).unwrap();
        let h = Header::request(self.cookie, 1, cap, req.len()).unwrap();
        self.stream.write_all(&h.encode()).unwrap();
        self.stream.write_all(req).unwrap();
    }
}

impl Link for Vmm {
    fn send(&mut self, req: &[u8], cap: usize) -> Option<Vec<u8>> {
        self.post(req, cap);
        let (h, payload) = read_frame(&mut self.stream);
        assert_eq!((h.kind(), h.cookie()), (Kind::Reply, self.cookie));
        Some(payload)
    }
}

fn read_frame(s: &mut UnixStream) -> (Header, Vec<u8>) {
    let mut head = [0u8; HEADER_LEN];
    s.read_exact(&mut head).unwrap();
    let h = Header::parse(&head, Sender::Server).unwrap();
    let mut payload = vec![0u8; h.payload_len()];
    s.read_exact(&mut payload).unwrap();
    (h, payload)
}

/// Before the VMM connected: the server ends, removes its socket, and says
/// so.
#[test]
fn test_parent_ends_before_the_vmm_connected() {
    let Some((base, socket, args)) = share("parent-before") else { return };
    let f = Family::start(&args);
    let p = f.processes();
    let err = f.kill_parent_then_gone(&p);
    assert!(err.contains("ended before the VMM connected; the socket is removed"), "{err}");
    assert!(socket.symlink_metadata().is_err(), "the socket is left");
    cleanup(&base, &socket);
}

/// While the server waits for the next frame.
#[test]
fn test_parent_ends_while_the_server_waits_for_a_frame() {
    let Some((base, socket, args)) = share("parent-idle") else { return };
    let f = Family::start(&args);
    let vmm = Vmm::connect(&socket);
    let mut h = H::over(vmm, base.clone(), base.join("share"), base.join("outside"), Default::default());
    h.lookup(1, b"big").unwrap();
    // Its processes once it serves (on Linux the confined child is there).
    let p = f.processes();
    let err = f.kill_parent_then_gone(&p);
    assert!(err.contains("ended while it served"), "{err}");
    drop(h);
    cleanup(&base, &socket);
}

/// While the server is held writing READ replies the VMM does not read
/// (64 of 1 MiB posted, none read): the bound is one request.
#[test]
fn test_parent_ends_while_the_server_writes_a_large_read() {
    let Some((base, socket, args)) = share("parent-read") else { return };
    let f = Family::start(&args);
    let vmm = Vmm::connect(&socket);
    let mut h = H::over(vmm, base.clone(), base.join("share"), base.join("outside"), Default::default());
    let node = common::u64_at(&h.lookup(1, b"big").unwrap(), 0);
    let fh = h.open(node, 0).unwrap();
    let vmm = &mut h.s;
    for i in 0..64u64 {
        let args = [&le64(fh)[..], &le64(i << 20), &le32(1 << 20), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        let req = request(Opcode::Read as u32, 100 + 2 * i, node, (common::UID, common::GID), &[&args]);
        vmm.post(&req, 2 << 20);
    }
    // The server is writing (the socket's buffer full, nothing read).
    std::thread::sleep(Duration::from_millis(300));
    let p = f.processes();
    let err = f.kill_parent_then_gone(&p);
    assert!(err.contains("ended while it served"), "{err}");
    drop(h);
    cleanup(&base, &socket);
}

/// The start's refusals, before anything is bound: a `--parent-pid` that
/// is not the parent (pid 1, a pid that is none, this test's own pid, which
/// is the parent's parent here), and one below 1. The default's pid-1
/// refusal is the decision's unit test in main.rs (`parent_watch_pid`): a
/// parent that is pid 1 cannot be had here without racing an orphaning.
#[test]
fn test_parent_pid_must_be_the_parent() {
    let Some((base, socket, args)) = share("parent-named") else { return };
    for named in ["1".to_string(), "999999".to_string(), std::process::id().to_string(), "0".to_string()] {
        let mut a = args.clone();
        a.extend(["--parent-pid".to_string(), named.clone()]);
        let f = Family::start_refused(&a);
        if named == "0" {
            assert!(f.contains("--parent-pid 0: a pid is 1 or more"), "{f}");
        } else if named == "999999" {
            assert!(f.contains("the watch on its parent, pid 999999: 3 "), "{f}");
        } else {
            assert!(f.contains(&format!("--parent-pid {named} is not its parent")), "--parent-pid {named}: {f}");
        }
        assert!(socket.symlink_metadata().is_err(), "--parent-pid {named}: bound");
    }
    cleanup(&base, &socket);
}

/// The test's tree, and the socket's own directory where [`socket_in`] made
/// one in /tmp.
fn cleanup(base: &Path, socket: &Path) {
    common::remove(base);
    if let Some(d) = socket.parent()
        && d.to_string_lossy().starts_with("/tmp/wick-fsd-s-")
    {
        common::remove(d);
    }
}
