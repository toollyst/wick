// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A minimal vhost-user-blk backend on the rust-vmm crates, to test Firecracker's
// vhost-user frontend in tools/macos/boot-test.sh and tools/windows/boot-test.ps1
// (QEMU's macOS and Windows builds have no vhost-user-blk export), and as
// the backend of tools/macos/integration/bin/crosvm, crosvm's `devices
// --block vhost=...` for upstream's integration tests.
//   vhost-user-blk <socket> <image> [--read-only] [--control-socket <path>]
// --read-only: the device is read-only (VIRTIO_BLK_F_RO), writes fail.
// --control-socket (Unix): takes `resize <bytes>` requests, one line per
//   connection, answered `ok` or `error: <why>`: the image is resized and
//   the device's capacity with it (crosvm's `disk resize`); the frontend
//   reads it again with GET_CONFIG.
// It serves one frontend and exits when it disconnects, as crosvm does.
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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
    read_only: bool,
    sectors: u64,
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

fn main() {
    let mut args = std::env::args().skip(1);
    let socket = args.next().expect("socket");
    let image = args.next().expect("image");
    let mut read_only = false;
    let mut control = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--read-only" => read_only = true,
            "--control-socket" => control = Some(args.next().expect("--control-socket needs a path")),
            _ => {
                eprintln!("vhost-user-blk: unknown argument {a}");
                std::process::exit(2);
            }
        }
    }
    let mut file = OpenOptions::new().read(true).write(!read_only).open(&image).unwrap();
    let len = file.seek(SeekFrom::End(0)).unwrap();
    let mut probe = [0u8; 1];
    file.seek(SeekFrom::Start(0)).unwrap();
    let _ = file.read(&mut probe);
    let blk = Arc::new(RwLock::new(Blk {
        file,
        read_only,
        sectors: len / 512,
        mem: None,
        requests: 0,
    }));
    if let Some(path) = control {
        serve_control(&path, blk.clone());
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

/// The control socket: `resize <bytes>` sets the image's length and the
/// device's capacity (whole sectors).
#[cfg(unix)]
fn serve_control(path: &str, blk: Arc<RwLock<Blk>>) {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap_or_else(|e| panic!("control socket {path}: {e}"));
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut line = String::new();
            if BufReader::new(&conn).read_line(&mut line).is_err() {
                continue;
            }
            let reply = match line.trim().strip_prefix("resize ").map(str::parse::<u64>) {
                Some(Ok(bytes)) => {
                    let mut b = blk.write().unwrap();
                    if b.read_only {
                        "error: the device is read-only".to_string()
                    } else {
                        match b.file.set_len(bytes) {
                            Ok(()) => {
                                b.sectors = bytes / 512;
                                "ok".to_string()
                            }
                            Err(e) => format!("error: {e}"),
                        }
                    }
                }
                _ => format!("error: unknown request {:?}", line.trim()),
            };
            let _ = writeln!(conn, "{reply}");
        }
    });
}

#[cfg(windows)]
fn serve_control(path: &str, _blk: Arc<RwLock<Blk>>) {
    eprintln!("vhost-user-blk: --control-socket {path}: Unix sockets only");
    std::process::exit(2);
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
