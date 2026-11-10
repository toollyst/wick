// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A minimal vhost-user-blk backend on the rust-vmm crates, to test Firecracker's
// vhost-user frontend in tools/macos/boot-test.sh (QEMU's macOS build has no
// vhost-user-blk export).
//   vhost-user-blk <socket> <image>
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
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
                        self.file.read_exact_at(&mut buf, off).unwrap_or_else(|_| st = VIRTIO_BLK_S_IOERR as u8);
                        mem.write_slice(&buf, d.addr()).unwrap();
                        off += u64::from(d.len());
                        written += d.len();
                    }
                }
                VIRTIO_BLK_T_OUT => {
                    for d in data {
                        let mut buf = vec![0u8; d.len() as usize];
                        mem.read_slice(&mut buf, d.addr()).unwrap();
                        if self.file.write_all_at(&buf, off).is_err() {
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
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_BLK_F_FLUSH
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
    let mut file = OpenOptions::new().read(true).write(true).open(&image).unwrap();
    let len = file.seek(SeekFrom::End(0)).unwrap();
    let mut probe = [0u8; 1];
    file.seek(SeekFrom::Start(0)).unwrap();
    let _ = file.read(&mut probe);
    let blk = Arc::new(RwLock::new(Blk {
        file,
        sectors: len / 512,
        mem: None,
        requests: 0,
    }));
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
