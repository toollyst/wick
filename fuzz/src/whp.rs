// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the WHP run loop (`crates/compat/kvm-ioctls/src/whp/vcpu.rs`, `run`)
//! hands a guest's port and MMIO accesses to: the user-space interrupt
//! controller (`whp/irqchip.rs`: the I/O APIC, the 8259 PICs, the 8254 PIT),
//! compiled from its source with the two modules it uses from the backend
//! stood in for: `whv` (the WHP types it builds an interrupt request from)
//! and `vm` (the VM its PIT timer raises IRQ 0 on). The run loop's own steps
//! call WHP (registers, the instruction emulator) and run only on a host
//! with it.

/// The WHP items `irqchip` uses, as `windows-sys` defines them.
#[allow(non_snake_case, non_upper_case_globals, non_camel_case_types, dead_code)]
pub mod whv {
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    pub struct WHV_INTERRUPT_CONTROL {
        pub _bitfield: u64,
        pub Destination: u32,
        pub Vector: u32,
    }
    pub type WHV_INTERRUPT_TRIGGER_MODE = i32;
    pub type WHV_INTERRUPT_TYPE = i32;
    pub const WHvX64InterruptTriggerModeEdge: WHV_INTERRUPT_TRIGGER_MODE = 0;
    pub const WHvX64InterruptTriggerModeLevel: WHV_INTERRUPT_TRIGGER_MODE = 1;
    pub const WHvX64InterruptTypeFixed: WHV_INTERRUPT_TYPE = 0;
    pub const WHvX64InterruptTypeLowestPriority: WHV_INTERRUPT_TYPE = 1;
    pub const WHvX64InterruptTypeNmi: WHV_INTERRUPT_TYPE = 4;
    pub const WHvX64InterruptTypeInit: WHV_INTERRUPT_TYPE = 5;
    pub const WHvX64InterruptTypeSipi: WHV_INTERRUPT_TYPE = 6;
}

/// The VM the PIT's timer thread raises IRQ 0 on: counted here.
pub mod vm {
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct VmInner {
        pub raised: AtomicU64,
    }

    impl VmInner {
        pub fn raise_gsi(&self, _gsi: u32, level: bool) {
            if level {
                self.raised.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[allow(dead_code, unreachable_pub, clippy::all)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/irqchip.rs"]
pub mod irqchip;

use std::sync::Arc;

use crate::{
    KVM_IRQ_ROUTING_MSI, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    kvm_irq_routing_entry, kvm_irqchip, kvm_pit_config, kvm_pit_state2,
};

/// What a snapshot holds of the interrupt controller: what Firecracker saves
/// (`KVM_GET_IRQCHIP` for each chip, `KVM_GET_PIT2`), as bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct State {
    pub chips: [Vec<u8>; 3],
    pub pit: Vec<u8>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("pic_master", &&self.chips[0][8..24])
            .field("pic_slave", &&self.chips[1][8..24])
            .field("ioapic", &&self.chips[2][8..240])
            .field("pit", &self.pit)
            .finish()
    }
}

impl State {
    /// The state without what follows the host clock: each PIT channel's
    /// latched count (`latched_count`, the count when the guest latched
    /// it). Two VMs created at different times differ only there.
    pub fn without_clock(&self) -> State {
        let mut s = self.clone();
        let size = std::mem::size_of::<crate::kvm_pit_channel_state>();
        let at = std::mem::offset_of!(crate::kvm_pit_channel_state, latched_count);
        for ch in 0..3 {
            s.pit[ch * size + at..ch * size + at + 2].fill(0);
        }
        s
    }
}

fn bytes<T>(v: &T) -> Vec<u8> {
    // SAFETY: plain C structures, read as bytes.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>()) }.to_vec()
}

/// The interrupt controller of one VM, with its PIT, as the WHP backend
/// creates it for Firecracker (`KVM_CREATE_IRQCHIP`, `KVM_CREATE_PIT2`).
pub struct Chip {
    chip: irqchip::Irqchip,
    vm: Arc<vm::VmInner>,
    routes: Vec<(u32, u64, u32)>,
}

impl Default for Chip {
    fn default() -> Self {
        Self::new()
    }
}

impl Chip {
    pub fn new() -> Self {
        let vm = Arc::new(vm::VmInner::default());
        let mut chip = irqchip::Irqchip::new();
        chip.enable();
        // SAFETY: plain data.
        let config: kvm_pit_config = unsafe { std::mem::zeroed() };
        chip.create_pit(config, &vm);
        Chip { chip, vm, routes: Vec::new() }
    }

    /// Whether the run loop gives an access to `port` to the controller
    /// rather than to Firecracker.
    pub fn handles_pio(&self, port: u16) -> bool {
        self.chip.pio_handles(port)
    }

    pub fn handles_mmio(&self, addr: u64) -> bool {
        self.chip.mmio_handles(addr)
    }

    /// An `IN` of `len` bytes (1, 2 or 4).
    pub fn pio_read(&mut self, port: u16, len: usize) -> u64 {
        let mut b = [0u8; 8];
        self.chip.pio_read(port, &mut b[..len]);
        u64::from_le_bytes(b)
    }

    pub fn pio_write(&mut self, port: u16, value: u64, len: usize) {
        self.chip.pio_write(port, &value.to_le_bytes()[..len], &self.vm);
    }

    pub fn mmio_read(&mut self, addr: u64, len: usize) -> u64 {
        let mut b = [0u8; 8];
        self.chip.mmio_read(addr, &mut b[..len]);
        u64::from_le_bytes(b)
    }

    /// An MMIO write; the interrupt it delivers, as an MSI address and data.
    pub fn mmio_write(&mut self, addr: u64, value: u64, len: usize) -> Option<(u64, u32)> {
        self.chip.mmio_write(addr, &value.to_le_bytes()[..len])
    }

    pub fn raise_gsi(&mut self, gsi: u32, level: bool) -> Option<(u64, u32)> {
        self.chip.raise_gsi(gsi, level)
    }

    /// `KVM_SET_GSI_ROUTING` with MSI routes `(gsi, address, data)`.
    pub fn set_routes(&mut self, routes: &[(u32, u64, u32)]) {
        let entries: Vec<kvm_irq_routing_entry> = routes
            .iter()
            .map(|&(gsi, address, data)| {
                // SAFETY: plain data.
                let mut e: kvm_irq_routing_entry = unsafe { std::mem::zeroed() };
                e.gsi = gsi;
                e.type_ = KVM_IRQ_ROUTING_MSI;
                e.u.msi.address_lo = address as u32;
                e.u.msi.address_hi = (address >> 32) as u32;
                e.u.msi.data = data;
                e
            })
            .collect();
        self.chip.set_gsi_routing(&entries);
        self.routes = routes.to_vec();
    }

    /// The interrupt request the backend makes of an MSI.
    pub fn interrupt(address: u64, data: u32) -> whv::WHV_INTERRUPT_CONTROL {
        irqchip::interrupt_control(address, data)
    }

    pub fn save(&self) -> State {
        let chip = |id| {
            // SAFETY: plain data.
            let mut c: kvm_irqchip = unsafe { std::mem::zeroed() };
            c.chip_id = id;
            self.chip.get_chip(&mut c);
            bytes(&c)
        };
        State {
            chips: [chip(KVM_IRQCHIP_PIC_MASTER), chip(KVM_IRQCHIP_PIC_SLAVE), chip(KVM_IRQCHIP_IOAPIC)],
            pit: bytes(&self.chip.pit_state()),
        }
    }

    /// A new VM restored from `state` (as Firecracker restores one: the
    /// routes set again, then `KVM_SET_IRQCHIP` and `KVM_SET_PIT2`).
    pub fn restore(state: &State, routes: &[(u32, u64, u32)]) -> Self {
        let mut c = Chip::new();
        c.set_routes(routes);
        for bytes in &state.chips {
            // SAFETY: bytes of a kvm_irqchip.
            let chip: kvm_irqchip = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
            c.chip.set_chip(&chip);
        }
        c.set_pit(&state.pit);
        c
    }

    /// `KVM_SET_PIT2` with the bytes of a `kvm_pit_state2` (from a snapshot).
    pub fn set_pit(&mut self, pit: &[u8]) {
        // SAFETY: plain data.
        let mut s: kvm_pit_state2 = unsafe { std::mem::zeroed() };
        let n = pit.len().min(std::mem::size_of::<kvm_pit_state2>());
        // SAFETY: at most the structure's size.
        unsafe { std::ptr::copy_nonoverlapping(pit.as_ptr(), (&raw mut s).cast::<u8>(), n) };
        self.chip.set_pit_state(&s, &self.vm);
    }

    pub fn routes(&self) -> &[(u32, u64, u32)] {
        &self.routes
    }
}
