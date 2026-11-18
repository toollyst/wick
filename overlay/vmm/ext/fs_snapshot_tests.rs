// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A microVM with a virtio-fs device is not snapshotted, on either
//! transport (docs/design-fs.md row 17): `Vmm::save_state` refuses it before
//! any state is saved (`check_unsnapshottable_devices`), and the device
//! managers' saves, past that refusal, leave the device out with an error
//! line (the `VirtioDeviceType::Fs` arms of device_manager/persist.rs and
//! pci_mngr.rs) and never panic. The device here is a stand-in of type 26:
//! wick-ext's device is outside this crate, and the refusal and the saves
//! look at the type alone.
#![cfg(test)]

use std::sync::{Arc, Mutex};

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::EventFd;

use crate::EventManager;
use crate::builder::tests::{default_kernel_cmdline, default_vmm, default_vmm_with_pci};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::impl_device_type;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

const ID: &str = "wickfs0";

/// A device of type 26 with virtio-fs's two queues and nothing else.
#[derive(Debug)]
struct Share {
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,
    state: DeviceState,
    acked: u64,
}

impl Share {
    fn new() -> Share {
        Share {
            queues: vec![Queue::new(16); 2],
            queue_events: (0..2).map(|_| EventFd::new(libc::EFD_NONBLOCK).unwrap()).collect(),
            state: DeviceState::Inactive,
            acked: 0,
        }
    }
}

impl VirtioDevice for Share {
    impl_device_type!(VirtioDeviceType::Fs);

    fn id(&self) -> &str {
        ID
    }

    fn avail_features(&self) -> u64 {
        0
    }

    fn acked_features(&self) -> u64 {
        self.acked
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.state.active_state().expect("not activated").interrupt.as_ref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        &[]
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: Arc<dyn VirtioInterrupt>) -> Result<(), ActivateError> {
        self.state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.state.is_activated()
    }

    fn deactivate(&mut self) {
        self.state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        true
    }
}

impl MutEventSubscriber for Share {
    fn process(&mut self, _: Events, _: &mut EventOps) {}

    fn init(&mut self, _: &mut EventOps) {}
}

#[test]
fn test_fs_snapshot_refused() {
    for pci in [false, true] {
        let mut vmm = if pci { default_vmm_with_pci() } else { default_vmm() };
        let mut cmdline = default_kernel_cmdline();
        let mut event_manager = EventManager::new().unwrap();
        let before = format!("{:?}", vmm.device_manager.save());
        vmm.device_manager
            .attach_boot_virtio_device(
                &vmm.vm,
                ID.to_string(),
                Arc::new(Mutex::new(Share::new())),
                &mut cmdline,
                &mut event_manager,
                false,
            )
            .unwrap();
        // Refused, by type and id, before any state is saved (the first
        // thing `save_state` does).
        let e = vmm.check_unsnapshottable_devices().unwrap_err().to_string();
        assert!(e.contains(&format!("virtio-fs(id: {ID})")), "pci {pci}: {e}");
        // Past the refusal, the transport's save leaves the device out:
        // the state is the one without it.
        let after = format!("{:?}", vmm.device_manager.save());
        assert!(!after.contains(ID), "pci {pci}: the device was saved");
        assert_eq!(after, before, "pci {pci}");
    }
}
