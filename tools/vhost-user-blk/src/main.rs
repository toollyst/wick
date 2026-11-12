// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A minimal vhost-user-blk backend on the rust-vmm crates, to test Firecracker's
// vhost-user frontend in tools/macos/boot-test.sh and tools/windows/boot-test.ps1
// (QEMU's macOS and Windows builds have no vhost-user-blk export).
//   vhost-user-blk <socket> <image> [--read-only] [--control-socket <path>]
// --read-only: the device is read-only (VIRTIO_BLK_F_RO), writes fail.
// --control-socket: takes the resize requests described below.
// It serves one frontend and exits when it disconnects, as crosvm does.
//
// Run as `crosvm` (the binary's name), it takes the command lines of crosvm's
// that upstream's integration tests give their vhost-user-blk backend
// (tests/framework/utils_drive.py), so that the tests run unchanged where
// crosvm does not build (macOS's tools/macos/integration/bin/crosvm runs it
// with its own command line; Windows names it crosvm):
//   crosvm [--log-level L] devices [--disable-sandbox] [--control-socket CTR]
//          --block vhost=<socket>,path=<image>[,ro]
//   crosvm disk resize <index> <bytes> <CTR>
// The control socket takes `resize <index> <bytes>` (crosvm's) or
// `resize <bytes>`, one line per connection, answered `ok` or an error: the
// image is resized and the device's capacity with it, which Firecracker reads
// again at a PATCH of the drive; a read-only device is not resized. (The
// messages are this backend's, not crosvm's.)
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::sync::{Arc, RwLock};

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use virtio_bindings::virtio_blk::*;
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_queue::QueueOwnedT;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

struct Blk {
    file: File,
    sectors: u64,
    read_only: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    requests: u64,
}

impl Blk {
    fn process(&mut self, vring: &VringRwLock) -> std::io::Result<bool> {
        let mem = self.mem.as_ref().unwrap().memory();
        let chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(mem.clone())
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?
            .collect();
        let mut used = false;
        for chain in chains {
            let head = chain.head_index();
            let descs: Vec<_> = chain.clone().collect();
            let (hdr, rest) = descs.split_first().unwrap();
            let (status, data) = rest.split_last().unwrap();
            let mut h = [0u8; 16];
            mem.read_slice(&mut h, hdr.addr()).unwrap();
            let kind = u32::from_le_bytes(h[0..4].try_into().unwrap());
            let sector = u64::from_le_bytes(h[8..16].try_into().unwrap());
            let mut off = sector * 512;
            let mut written = 0u32;
            let mut st = VIRTIO_BLK_S_OK as u8;
            match kind {
                VIRTIO_BLK_T_IN => {
                    for d in data {
                        let mut buf = vec![0u8; d.len() as usize];
                        read_exact_at(&self.file, &mut buf, off).unwrap_or_else(|_| st = VIRTIO_BLK_S_IOERR as u8);
                        mem.write_slice(&buf, d.addr()).unwrap();
                        off += u64::from(d.len());
                        written += d.len();
                    }
                }
                VIRTIO_BLK_T_OUT if self.read_only => st = VIRTIO_BLK_S_IOERR as u8,
                VIRTIO_BLK_T_OUT => {
                    for d in data {
                        let mut buf = vec![0u8; d.len() as usize];
                        mem.read_slice(&mut buf, d.addr()).unwrap();
                        if write_all_at(&self.file, &buf, off).is_err() {
                            st = VIRTIO_BLK_S_IOERR as u8;
                        }
                        off += u64::from(d.len());
                    }
                }
                VIRTIO_BLK_T_FLUSH => {
                    if self.file.sync_all().is_err() {
                        st = VIRTIO_BLK_S_IOERR as u8;
                    }
                }
                VIRTIO_BLK_T_GET_ID => {
                    if let Some(d) = data.first() {
                        let mut id = [0u8; 20];
                        id[..7].copy_from_slice(b"vub-blk");
                        let n = id.len().min(d.len() as usize);
                        mem.write_slice(&id[..n], d.addr()).unwrap();
                        written += n as u32;
                    }
                }
                _ => st = VIRTIO_BLK_S_UNSUPP as u8,
            }
            mem.write_slice(&[st], status.addr()).unwrap();
            vring.add_used(head, written + 1).unwrap();
            self.requests += 1;
            used = true;
        }
        Ok(used)
    }
}

impl VhostUserBackendMut for Blk {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        1
    }
    fn max_queue_size(&self) -> usize {
        256
    }
    fn features(&self) -> u64 {
        let ro = if self.read_only { 1 << VIRTIO_BLK_F_RO } else { 0 };
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_BLK_F_FLUSH
            | ro
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }
    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }
    fn set_event_idx(&mut self, _enabled: bool) {}
    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let mut config = vec![0u8; 60];
        config[..8].copy_from_slice(&self.sectors.to_le_bytes());
        let end = (offset + size).min(60) as usize;
        config[(offset as usize).min(end)..end].to_vec()
    }
    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> std::io::Result<()> {
        self.mem = Some(mem);
        Ok(())
    }
    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> std::io::Result<()> {
        if evset != EventSet::IN || device_event != 0 {
            return Ok(());
        }
        if self.process(&vrings[0])? {
            vrings[0].signal_used_queue()?;
        }
        Ok(())
    }
}

/// What to serve: the vhost-user socket, the image, read-only, the control
/// socket.
struct Serve {
    socket: String,
    image: String,
    read_only: bool,
    control: Option<String>,
}

/// crosvm's command lines (see the top of the file); `None` for this
/// backend's own.
fn crosvm(args: &[String]) -> Option<Serve> {
    let mut it = args.iter().map(String::as_str).peekable();
    if it.peek() == Some(&"--log-level") {
        it.next();
        it.next();
    }
    match it.next()? {
        "disk" => {
            let rest: Vec<&str> = it.collect();
            let ["resize", index, bytes, ctr] = rest[..] else {
                eprintln!("crosvm disk: only `resize <index> <bytes> <socket>`");
                std::process::exit(2);
            };
            let mut s = wick_os::unix::net::UnixStream::connect(ctr).expect("control socket");
            writeln!(s, "resize {index} {bytes}").unwrap();
            let mut reply = String::new();
            BufReader::new(s).read_line(&mut reply).unwrap();
            if reply.trim() != "ok" {
                eprintln!("crosvm disk resize: {}", reply.trim());
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        "devices" => {
            let (mut block, mut control) = (None, None);
            while let Some(a) = it.next() {
                match a {
                    "--disable-sandbox" => {}
                    "--control-socket" => control = it.next().map(str::to_owned),
                    "--block" => block = it.next().map(str::to_owned),
                    other => {
                        eprintln!("crosvm devices: {other} is not taken");
                        std::process::exit(2);
                    }
                }
            }
            let block = block.expect("--block vhost=<socket>,path=<image>[,ro]");
            let (mut socket, mut image, mut read_only) = (None, None, false);
            for part in block.split(',') {
                match part.split_once('=') {
                    Some(("vhost", v)) => socket = Some(v.to_owned()),
                    Some(("path", v)) => image = Some(v.to_owned()),
                    None if part == "ro" => read_only = true,
                    _ => {
                        eprintln!("crosvm --block: {part} is not taken");
                        std::process::exit(2);
                    }
                }
            }
            Some(Serve { socket: socket.expect("vhost="), image: image.expect("path="), read_only, control })
        }
        _ => None,
    }
}

/// The control socket: `resize <index> <bytes>` resizes the image and the
/// device's capacity.
fn control(path: String, blk: Arc<RwLock<Blk>>) {
    let _ = std::fs::remove_file(&path);
    let listener = wick_os::unix::net::UnixListener::bind(&path).expect("control socket");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let mut line = String::new();
            let mut reader = BufReader::new(conn);
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let reply = match line.split_whitespace().collect::<Vec<_>>()[..] {
                ["resize", "0", bytes] | ["resize", bytes] => match bytes.parse::<u64>() {
                    Ok(_) if blk.read().unwrap().read_only => "error: the device is read-only".to_owned(),
                    Ok(n) => {
                        let mut b = blk.write().unwrap();
                        match b.file.set_len(n) {
                            Ok(()) => {
                                b.sectors = n / 512;
                                "ok".to_owned()
                            }
                            Err(e) => format!("resize: {e}"),
                        }
                    }
                    Err(e) => format!("resize: {e}"),
                },
                _ => format!("not taken: {}", line.trim()),
            };
            let _ = writeln!(reader.get_mut(), "{reply}");
        }
    });
}

/// This backend's own command line (see the top of the file).
fn own(args: &[String]) -> Serve {
    let mut it = args.iter();
    let socket = it.next().expect("socket").clone();
    let image = it.next().expect("image").clone();
    let (mut read_only, mut control) = (false, None);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--read-only" => read_only = true,
            "--control-socket" => control = Some(it.next().expect("--control-socket needs a path").clone()),
            _ => {
                eprintln!("vhost-user-blk: unknown argument {a}");
                std::process::exit(2);
            }
        }
    }
    Serve { socket, image, read_only, control }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = std::path::Path::new(&args[0]).file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let serve = if name == "crosvm" { crosvm(&args[1..]) } else { None };
    let serve = serve.unwrap_or_else(|| own(&args[1..]));
    let (socket, image) = (serve.socket.clone(), serve.image.clone());
    let mut file = OpenOptions::new().read(true).write(!serve.read_only).open(&image).unwrap();
    let len = file.seek(SeekFrom::End(0)).unwrap();
    let mut probe = [0u8; 1];
    file.seek(SeekFrom::Start(0)).unwrap();
    let _ = file.read(&mut probe);
    let blk = Arc::new(RwLock::new(Blk {
        file,
        sectors: len / 512,
        read_only: serve.read_only,
        mem: None,
        requests: 0,
    }));
    if let Some(path) = serve.control {
        control(path, blk.clone());
    }
    let mut daemon = VhostUserDaemon::new(
        "vhost-user-blk".into(),
        blk.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();
    println!("vhost-user-blk: serving {image} ({} sectors) on {socket}", len / 512);
    std::io::stdout().flush().unwrap();
    let r = daemon.serve(&socket);
    println!("vhost-user-blk: done ({} requests): {r:?}", blk.read().unwrap().requests);
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    file.read_exact_at(buf, off)
}

#[cfg(unix)]
fn write_all_at(file: &File, buf: &[u8], off: u64) -> std::io::Result<()> {
    file.write_all_at(buf, off)
}

// Windows' positioned I/O (`seek_read`, `seek_write`) may transfer less.
#[cfg(windows)]
fn read_exact_at(file: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        match file.seek_read(buf, off)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                off += n as u64;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_all_at(file: &File, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        match file.seek_write(buf, off)? {
            0 => return Err(std::io::ErrorKind::WriteZero.into()),
            n => {
                buf = &buf[n..];
                off += n as u64;
            }
        }
    }
    Ok(())
}
