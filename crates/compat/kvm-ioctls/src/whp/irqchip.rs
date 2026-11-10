// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The user-space interrupt controller: the I/O APIC, the two 8259 PICs and
//! the 8254 PIT that KVM provides in the kernel.
//!
//! The local APIC is WHP's (`WHvX64LocalApicEmulationModeXApic`). What is here
//! is everything in front of it:
//! - the **I/O APIC** at `0xFEC0_0000`: the guest programs its 24 redirection
//!   entries over MMIO; when a GSI is raised (by an `irqfd` or `set_irq_line`)
//!   the matching entry is turned into an interrupt request delivered to the
//!   local APIC with `WHvRequestInterrupt`;
//! - the **8259 PICs** at ports `0x20/0x21` and `0xA0/0xA1` (plus the ELCR at
//!   `0x4D0/0x4D1`): a Firecracker guest boots through the I/O APIC and masks
//!   the PICs, so these are modelled for the init-and-mask sequence and for
//!   save/restore, not for delivery;
//! - the **8254 PIT** at ports `0x40..=0x43` (and the speaker port `0x61`):
//!   channel 0 drives IRQ 0 from a timer thread; channel 2 is readable so the
//!   guest can calibrate against it.
//!
//! Firecracker's MPTable maps ISA IRQ *i* to I/O APIC pin *i* (identity), so a
//! device that registers `irqfd` for GSI *g* is delivered through entry *g*,
//! and the PIT (IRQ 0) is delivered through entry 0.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pic_state, kvm_pit_channel_state, kvm_pit_config,
    kvm_pit_state2, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_IRQ_ROUTING_MSI,
};
use super::whv;

use super::vm::VmInner;

/// Physical base of the I/O APIC MMIO window.
pub(crate) const IOAPIC_BASE: u64 = 0xFEC0_0000;
/// Length of the I/O APIC MMIO window.
const IOAPIC_LEN: u64 = 0x20;
/// Number of I/O APIC redirection entries.
const IOAPIC_PINS: usize = 24;
/// Reported I/O APIC version (82093AA) with max-redirection-entry in 23:16.
const IOAPIC_VER: u32 = 0x0017_0011;

/// PIT input frequency, in Hz.
const PIT_FREQ: u64 = 1_193_182;

/// The I/O APIC.
#[derive(Debug, Clone)]
struct IoApic {
    id: u32,
    ioregsel: u32,
    /// The 24 redirection entries, each the raw 64-bit register value.
    rtbl: [u64; IOAPIC_PINS],
    /// Which pins are currently asserted (for level-triggered re-evaluation).
    asserted: u32,
}

impl IoApic {
    fn new() -> Self {
        IoApic {
            id: 0,
            ioregsel: 0,
            // Entries reset masked (bit 16 set).
            rtbl: [1 << 16; IOAPIC_PINS],
            asserted: 0,
        }
    }

    fn read(&self, reg: u32) -> u32 {
        match reg {
            0x00 => self.id << 24,
            0x01 => IOAPIC_VER,
            0x02 => self.id << 24, // arbitration id
            r if (0x10..0x10 + 2 * IOAPIC_PINS as u32).contains(&r) => {
                let idx = ((r - 0x10) / 2) as usize;
                let hi = (r - 0x10) & 1 == 1;
                if hi {
                    (self.rtbl[idx] >> 32) as u32
                } else {
                    self.rtbl[idx] as u32
                }
            }
            _ => 0,
        }
    }

    fn write(&mut self, reg: u32, value: u32) {
        match reg {
            0x00 => self.id = (value >> 24) & 0xf,
            r if (0x10..0x10 + 2 * IOAPIC_PINS as u32).contains(&r) => {
                let idx = ((r - 0x10) / 2) as usize;
                let hi = (r - 0x10) & 1 == 1;
                let entry = &mut self.rtbl[idx];
                if hi {
                    *entry = (*entry & 0x0000_0000_FFFF_FFFF) | (u64::from(value) << 32);
                } else {
                    // Bits 12 (delivery status) and 14 (remote IRR) are read-only.
                    const RO: u64 = (1 << 12) | (1 << 14);
                    *entry = (*entry & (0xFFFF_FFFF_0000_0000 | RO))
                        | (u64::from(value) & !RO);
                }
            }
            _ => {}
        }
    }

    /// Turns redirection entry `pin` into an interrupt to deliver, if the pin
    /// is unmasked. Returns an `(msi_address, msi_data)` pair.
    fn entry_interrupt(&self, pin: usize) -> Option<(u64, u32)> {
        let rte = self.rtbl[pin];
        if rte & (1 << 16) != 0 {
            return None; // masked
        }
        let vector = (rte & 0xff) as u32;
        let delivery = ((rte >> 8) & 0x7) as u32;
        let dest_mode = ((rte >> 11) & 1) as u32;
        let trigger = ((rte >> 15) & 1) as u32;
        let dest = ((rte >> 56) & 0xff) as u32;
        let address = 0xFEE0_0000 | (dest << 12) | (dest_mode << 2);
        let data = vector | (delivery << 8) | (trigger << 15);
        Some((u64::from(address), data))
    }
}

/// One 8259 PIC, modelled by `kvm_pic_state`.
#[derive(Debug, Clone)]
struct Pic {
    state: kvm_pic_state,
    /// Position in the ICW init sequence (0 = not initialising).
    init_step: u8,
}

impl Pic {
    fn new(elcr_mask: u8) -> Self {
        let mut state: kvm_pic_state = unsafe { std::mem::zeroed() };
        state.imr = 0xff; // all masked at reset
        state.elcr_mask = elcr_mask;
        Pic {
            state,
            init_step: 0,
        }
    }

    /// Command port (0x20 / 0xA0).
    fn write_cmd(&mut self, value: u8) {
        if value & 0x10 != 0 {
            // ICW1: start init.
            self.state = {
                let mut s: kvm_pic_state = unsafe { std::mem::zeroed() };
                s.imr = 0xff;
                s.elcr_mask = self.state.elcr_mask;
                s.init4 = value & 1;
                s
            };
            self.init_step = 1;
        } else if value & 0x08 == 0 {
            // OCW2: EOI / rotate — clear the in-service bit.
            if value & 0x20 != 0 {
                self.state.isr = 0;
            }
        } else {
            // OCW3: read register select.
            self.state.read_reg_select = value & 1;
        }
    }

    /// Data port (0x21 / 0xA1).
    fn write_data(&mut self, value: u8) {
        match self.init_step {
            1 => {
                self.state.irq_base = value & 0xf8;
                self.init_step = 2;
            }
            2 => {
                // ICW3 (cascade) — not modelled beyond sequencing.
                self.init_step = if self.state.init4 != 0 { 3 } else { 0 };
            }
            3 => {
                self.state.auto_eoi = u8::from(value & 0x02 != 0);
                self.init_step = 0;
            }
            _ => self.state.imr = value, // OCW1: interrupt mask
        }
    }

    fn read_cmd(&self) -> u8 {
        if self.state.read_reg_select != 0 {
            self.state.isr
        } else {
            self.state.irr
        }
    }

    fn read_data(&self) -> u8 {
        self.state.imr
    }
}

/// One 8254 counter.
#[derive(Debug, Clone)]
struct PitChannel {
    /// Reload value (0 means 65536).
    reload: u32,
    mode: u8,
    /// Access mode: 1 = lo, 2 = hi, 3 = lo then hi.
    rw_mode: u8,
    /// For `rw_mode == 3`, whether the high byte is next.
    write_hi: bool,
    read_hi: bool,
    latched: Option<u16>,
    gate: bool,
    load_time: Instant,
}

impl PitChannel {
    fn new() -> Self {
        PitChannel {
            reload: 0,
            mode: 0,
            rw_mode: 3,
            write_hi: false,
            read_hi: false,
            latched: None,
            gate: true,
            load_time: Instant::now(),
        }
    }

    fn reload_value(&self) -> u64 {
        if self.reload == 0 {
            0x1_0000
        } else {
            u64::from(self.reload)
        }
    }

    /// The counter's current value, counting down from the reload value at
    /// `PIT_FREQ`.
    fn current_count(&self) -> u16 {
        let reload = self.reload_value();
        let elapsed_ns = self.load_time.elapsed().as_nanos() as u64;
        let ticks = elapsed_ns.saturating_mul(PIT_FREQ) / 1_000_000_000;
        let remaining = reload - (ticks % reload);
        (remaining & 0xffff) as u16
    }

    /// The period of channel 0 in nanoseconds, or `None` if not periodic.
    fn period_ns(&self) -> u64 {
        self.reload_value().saturating_mul(1_000_000_000) / PIT_FREQ
    }
}

/// The 8254 PIT: three channels and a background thread for channel 0.
#[derive(Debug)]
struct Pit {
    channels: [PitChannel; 3],
    speaker: u8,
    flags: u32,
    timer: Option<PitTimer>,
}

/// Command to the channel-0 timer thread.
#[derive(Debug)]
struct TimerCmd {
    period_ns: u64,
    generation: u64,
    stop: bool,
}

#[derive(Debug)]
struct PitTimer {
    shared: Arc<(Mutex<TimerCmd>, Condvar)>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PitTimer {
    fn drop(&mut self) {
        {
            let (lock, cv) = &*self.shared;
            let mut cmd = lock.lock().unwrap();
            cmd.stop = true;
            cv.notify_all();
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Pit {
    fn new(flags: u32) -> Self {
        Pit {
            channels: [PitChannel::new(), PitChannel::new(), PitChannel::new()],
            speaker: 0,
            flags,
            timer: None,
        }
    }

    /// Starts or reprograms the channel-0 timer thread for the current period.
    fn program_timer(&mut self, inner: &Arc<VmInner>) {
        let ch = &self.channels[0];
        // Only periodic modes (2 and 3) drive a repeating IRQ 0.
        let period_ns = if matches!(ch.mode, 2 | 3) {
            ch.period_ns()
        } else {
            0
        };
        if let Some(timer) = &self.timer {
            let (lock, cv) = &*timer.shared;
            let mut cmd = lock.lock().unwrap();
            cmd.period_ns = period_ns;
            cmd.generation += 1;
            cv.notify_all();
            return;
        }
        if period_ns == 0 {
            return;
        }
        let shared = Arc::new((
            Mutex::new(TimerCmd {
                period_ns,
                generation: 0,
                stop: false,
            }),
            Condvar::new(),
        ));
        let thread_shared = shared.clone();
        let weak = Arc::downgrade(inner);
        let join = std::thread::spawn(move || timer_loop(&thread_shared, &weak));
        self.timer = Some(PitTimer {
            shared,
            join: Some(join),
        });
    }
}

/// The channel-0 timer: waits one period, raises IRQ 0, repeats. Reprogrammed
/// by bumping the generation; stops when the VM is gone or `stop` is set.
fn timer_loop(
    shared: &Arc<(Mutex<TimerCmd>, Condvar)>,
    weak: &std::sync::Weak<VmInner>,
) {
    use std::time::Duration;
    let (lock, cv) = &**shared;
    loop {
        let (period, generation) = {
            let cmd = lock.lock().unwrap();
            if cmd.stop {
                return;
            }
            (cmd.period_ns, cmd.generation)
        };
        if period == 0 {
            // Disabled: wait until reprogrammed.
            let cmd = lock.lock().unwrap();
            let _unused = cv
                .wait_while(cmd, |c| c.period_ns == 0 && !c.stop)
                .unwrap();
            continue;
        }
        // Wait out the period, but wake early if reprogrammed or stopped.
        let cmd = lock.lock().unwrap();
        let (cmd, _timeout) = cv
            .wait_timeout_while(cmd, Duration::from_nanos(period), |c| {
                c.generation == generation && !c.stop
            })
            .unwrap();
        if cmd.stop {
            return;
        }
        if cmd.generation != generation {
            continue; // reprogrammed; restart with the new period
        }
        drop(cmd);
        match weak.upgrade() {
            Some(inner) => {
                inner.raise_gsi(0, true);
                inner.raise_gsi(0, false);
            }
            None => return,
        }
    }
}

/// The whole user-space interrupt controller.
#[derive(Debug)]
pub(crate) struct Irqchip {
    enabled: bool,
    ioapic: IoApic,
    pics: [Pic; 2],
    pit: Option<Pit>,
    /// GSI routing entries that are MSIs (`gsi -> (address, data)`); legacy
    /// IOAPIC-pin routes use the I/O APIC entry directly.
    msi_routes: std::collections::HashMap<u32, (u64, u32)>,
    /// Guest clock offset (nanoseconds), for get/set_clock.
    clock_base: Instant,
    clock_offset: u64,
}

impl Irqchip {
    pub(crate) fn new() -> Self {
        Irqchip {
            enabled: false,
            ioapic: IoApic::new(),
            pics: [Pic::new(0xf8), Pic::new(0xde)],
            pit: None,
            msi_routes: std::collections::HashMap::new(),
            clock_base: Instant::now(),
            clock_offset: 0,
        }
    }

    pub(crate) fn enable(&mut self) {
        self.enabled = true;
    }

    pub(crate) fn create_pit(&mut self, pit_config: kvm_pit_config, _inner: &Arc<VmInner>) {
        self.pit = Some(Pit::new(pit_config.flags));
    }

    // ---- GSI delivery ----

    /// Raises or lowers GSI `gsi`. Returns an `(msi_address, msi_data)` pair to
    /// inject on a rising edge, or `None`.
    pub(crate) fn raise_gsi(&mut self, gsi: u32, level: bool) -> Option<(u64, u32)> {
        // A routed MSI takes precedence (PCI/MSI-X vectors).
        if let Some(&msi) = self.msi_routes.get(&gsi) {
            return level.then_some(msi);
        }
        // Otherwise it is an I/O APIC pin.
        let pin = gsi as usize;
        if pin >= IOAPIC_PINS {
            return None;
        }
        let bit = 1u32 << pin;
        if level {
            self.ioapic.asserted |= bit;
            self.ioapic.entry_interrupt(pin)
        } else {
            self.ioapic.asserted &= !bit;
            None
        }
    }

    pub(crate) fn set_gsi_routing(&mut self, entries: &[kvm_bindings::kvm_irq_routing_entry]) {
        self.msi_routes.clear();
        for e in entries {
            if e.type_ == KVM_IRQ_ROUTING_MSI {
                // SAFETY: the entry is tagged as an MSI route.
                let msi = unsafe { e.u.msi };
                let address = u64::from(msi.address_lo) | (u64::from(msi.address_hi) << 32);
                self.msi_routes.insert(e.gsi, (address, msi.data));
            }
        }
    }

    // ---- MMIO (I/O APIC) ----

    pub(crate) fn mmio_handles(&self, addr: u64) -> bool {
        (IOAPIC_BASE..IOAPIC_BASE + IOAPIC_LEN).contains(&addr)
    }

    pub(crate) fn mmio_read(&mut self, addr: u64, data: &mut [u8]) {
        let off = addr - IOAPIC_BASE;
        let value = match off {
            0x00 => self.ioapic.ioregsel,
            0x10 => self.ioapic.read(self.ioapic.ioregsel),
            _ => 0,
        };
        write_le(data, u64::from(value));
    }

    /// Writes an I/O APIC register. Returns a rising-edge interrupt to inject
    /// if re-programming unmasked an already-asserted level pin.
    pub(crate) fn mmio_write(&mut self, addr: u64, data: &[u8]) -> Option<(u64, u32)> {
        let off = addr - IOAPIC_BASE;
        let value = read_le(data) as u32;
        match off {
            0x00 => {
                self.ioapic.ioregsel = value;
                None
            }
            0x10 => {
                let reg = self.ioapic.ioregsel;
                self.ioapic.write(reg, value);
                // If a redirection entry was (re)written while its level line is
                // asserted and it is now unmasked, deliver it.
                if (0x10..0x10 + 2 * IOAPIC_PINS as u32).contains(&reg) {
                    let pin = ((reg - 0x10) / 2) as usize;
                    if self.ioapic.asserted & (1 << pin) != 0 {
                        return self.ioapic.entry_interrupt(pin);
                    }
                }
                None
            }
            _ => None,
        }
    }

    // ---- PIO (PICs, PIT, ELCR) ----

    pub(crate) fn pio_handles(&self, port: u16) -> bool {
        matches!(port,
            0x20 | 0x21 | 0xA0 | 0xA1 |      // PICs
            0x4D0 | 0x4D1 |                   // ELCR
            0x40 | 0x41 | 0x42 | 0x43 |      // PIT
            0x61                             // speaker
        )
    }

    pub(crate) fn pio_read(&mut self, port: u16, data: &mut [u8]) {
        let value: u8 = match port {
            0x20 => self.pics[0].read_cmd(),
            0x21 => self.pics[0].read_data(),
            0xA0 => self.pics[1].read_cmd(),
            0xA1 => self.pics[1].read_data(),
            0x4D0 => self.pics[0].state.elcr,
            0x4D1 => self.pics[1].state.elcr,
            0x40..=0x42 => self.pit_read_counter((port - 0x40) as usize),
            0x61 => self.speaker_read(),
            _ => 0xff,
        };
        if let Some(b) = data.first_mut() {
            *b = value;
        }
        for b in data.iter_mut().skip(1) {
            *b = 0;
        }
    }

    pub(crate) fn pio_write(&mut self, port: u16, data: &[u8], inner: &Arc<VmInner>) {
        let value = data.first().copied().unwrap_or(0);
        match port {
            0x20 => self.pics[0].write_cmd(value),
            0x21 => self.pics[0].write_data(value),
            0xA0 => self.pics[1].write_cmd(value),
            0xA1 => self.pics[1].write_data(value),
            0x4D0 => self.pics[0].state.elcr = value & self.pics[0].state.elcr_mask,
            0x4D1 => self.pics[1].state.elcr = value & self.pics[1].state.elcr_mask,
            0x43 => self.pit_write_control(value, inner),
            0x40..=0x42 => self.pit_write_counter((port - 0x40) as usize, value, inner),
            0x61 => {
                if let Some(pit) = &mut self.pit {
                    pit.speaker = value;
                    pit.channels[2].gate = value & 1 != 0;
                }
            }
            _ => {}
        }
    }

    fn speaker_read(&self) -> u8 {
        let Some(pit) = &self.pit else { return 0 };
        // Bit 5 reflects channel-2 output (toggles as the counter wraps), which
        // the guest polls during TSC calibration.
        let out2 = u8::from(pit.channels[2].current_count() < (pit.channels[2].reload_value() / 2) as u16);
        (pit.speaker & 0x0f) | (out2 << 5)
    }

    fn pit_read_counter(&mut self, ch: usize) -> u8 {
        let Some(pit) = &mut self.pit else { return 0 };
        let channel = &mut pit.channels[ch];
        let count = channel.latched.unwrap_or_else(|| channel.current_count());
        let byte = if channel.read_hi {
            (count >> 8) as u8
        } else {
            count as u8
        };
        match channel.rw_mode {
            1 => {}            // lo only
            2 => {}            // hi only
            _ => channel.read_hi = !channel.read_hi,
        }
        if !channel.read_hi {
            channel.latched = None;
        }
        byte
    }

    fn pit_write_control(&mut self, value: u8, inner: &Arc<VmInner>) {
        let Some(pit) = &mut self.pit else { return };
        let ch = (value >> 6) & 0x3;
        if ch == 3 {
            return; // read-back, not modelled
        }
        let access = (value >> 4) & 0x3;
        let channel = &mut pit.channels[ch as usize];
        if access == 0 {
            // Latch command: snapshot the current count.
            channel.latched = Some(channel.current_count());
            return;
        }
        channel.rw_mode = access;
        channel.mode = (value >> 1) & 0x7;
        channel.write_hi = false;
        channel.read_hi = false;
        channel.latched = None;
        if ch == 0 {
            pit.program_timer(inner);
        }
    }

    fn pit_write_counter(&mut self, ch: usize, value: u8, inner: &Arc<VmInner>) {
        let Some(pit) = &mut self.pit else { return };
        let channel = &mut pit.channels[ch];
        let loaded = match channel.rw_mode {
            1 => {
                channel.reload = u32::from(value);
                true
            }
            2 => {
                channel.reload = u32::from(value) << 8;
                true
            }
            _ => {
                if channel.write_hi {
                    channel.reload = (channel.reload & 0x00ff) | (u32::from(value) << 8);
                    channel.write_hi = false;
                    true
                } else {
                    channel.reload = u32::from(value);
                    channel.write_hi = true;
                    false
                }
            }
        };
        if loaded {
            channel.load_time = Instant::now();
            if ch == 0 {
                pit.program_timer(inner);
            }
        }
    }

    // ---- save / restore ----

    pub(crate) fn pit_state(&self) -> kvm_pit_state2 {
        let mut state: kvm_pit_state2 = unsafe { std::mem::zeroed() };
        if let Some(pit) = &self.pit {
            state.flags = pit.flags;
            for (i, ch) in pit.channels.iter().enumerate() {
                state.channels[i] = kvm_pit_channel_state {
                    count: ch.reload,
                    mode: ch.mode,
                    rw_mode: ch.rw_mode,
                    gate: u8::from(ch.gate),
                    ..unsafe { std::mem::zeroed() }
                };
            }
        }
        state
    }

    pub(crate) fn set_pit_state(&mut self, state: &kvm_pit_state2, inner: &Arc<VmInner>) {
        if self.pit.is_none() {
            self.pit = Some(Pit::new(state.flags));
        }
        if let Some(pit) = &mut self.pit {
            pit.flags = state.flags;
            for (i, ch) in pit.channels.iter_mut().enumerate() {
                let s = &state.channels[i];
                ch.reload = s.count;
                ch.mode = s.mode;
                ch.rw_mode = if s.rw_mode == 0 { 3 } else { s.rw_mode };
                ch.gate = s.gate != 0;
                ch.load_time = Instant::now();
            }
            pit.program_timer(inner);
        }
    }

    pub(crate) fn clock(&self) -> kvm_clock_data {
        let ns = self.clock_offset + self.clock_base.elapsed().as_nanos() as u64;
        kvm_clock_data {
            clock: ns,
            ..unsafe { std::mem::zeroed() }
        }
    }

    pub(crate) fn set_clock(&mut self, clock: &kvm_clock_data) {
        self.clock_offset = clock.clock;
        self.clock_base = Instant::now();
    }

    pub(crate) fn get_chip(&self, irqchip: &mut kvm_irqchip) {
        match irqchip.chip_id {
            KVM_IRQCHIP_PIC_MASTER => irqchip.chip.pic = self.pics[0].state,
            KVM_IRQCHIP_PIC_SLAVE => irqchip.chip.pic = self.pics[1].state,
            KVM_IRQCHIP_IOAPIC => {
                // SAFETY: writing the ioapic arm of the union for an IOAPIC id.
                let ioapic = unsafe { &mut irqchip.chip.ioapic };
                ioapic.base_address = IOAPIC_BASE;
                ioapic.ioregsel = self.ioapic.ioregsel;
                ioapic.id = self.ioapic.id;
                ioapic.irr = self.ioapic.asserted;
                for (i, rte) in self.ioapic.rtbl.iter().enumerate() {
                    ioapic.redirtbl[i].bits = *rte;
                }
            }
            _ => {}
        }
    }

    pub(crate) fn set_chip(&mut self, irqchip: &kvm_irqchip) {
        match irqchip.chip_id {
            // SAFETY: reading the pic arm for a PIC id.
            KVM_IRQCHIP_PIC_MASTER => self.pics[0].state = unsafe { irqchip.chip.pic },
            KVM_IRQCHIP_PIC_SLAVE => self.pics[1].state = unsafe { irqchip.chip.pic },
            KVM_IRQCHIP_IOAPIC => {
                // SAFETY: reading the ioapic arm for an IOAPIC id.
                let ioapic = unsafe { &irqchip.chip.ioapic };
                self.ioapic.ioregsel = ioapic.ioregsel;
                self.ioapic.id = ioapic.id;
                self.ioapic.asserted = ioapic.irr;
                for (i, rte) in self.ioapic.rtbl.iter_mut().enumerate() {
                    // SAFETY: reading the raw bits of each redirection entry.
                    *rte = unsafe { ioapic.redirtbl[i].bits };
                }
            }
            _ => {}
        }
    }
}

/// Builds a `WHV_INTERRUPT_CONTROL` from an MSI address/data pair.
pub(crate) fn interrupt_control(address: u64, data: u32) -> whv::WHV_INTERRUPT_CONTROL {
    let vector = data & 0xff;
    let delivery = (data >> 8) & 0x7;
    let trigger = (data >> 15) & 0x1;
    let dest_mode = (address >> 2) & 0x1;
    let dest = ((address >> 12) & 0xff) as u32;

    let itype: u64 = match delivery {
        1 => whv::WHvX64InterruptTypeLowestPriority,
        4 => whv::WHvX64InterruptTypeNmi,
        5 => whv::WHvX64InterruptTypeInit,
        6 => whv::WHvX64InterruptTypeSipi,
        _ => whv::WHvX64InterruptTypeFixed,
    } as u64;
    let trig: u64 = if trigger == 1 {
        whv::WHvX64InterruptTriggerModeLevel
    } else {
        whv::WHvX64InterruptTriggerModeEdge
    } as u64;

    let bitfield = (itype & 0xff) | (dest_mode << 8) | (trig << 12);
    whv::WHV_INTERRUPT_CONTROL {
        _bitfield: bitfield,
        Destination: dest,
        Vector: vector,
    }
}

/// Reads up to 8 little-endian bytes as a u64.
fn read_le(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = data.len().min(8);
    buf[..n].copy_from_slice(&data[..n]);
    u64::from_le_bytes(buf)
}

/// Writes a u64 as little-endian bytes into `data` (up to its length).
fn write_le(data: &mut [u8], value: u64) {
    let bytes = value.to_le_bytes();
    let n = data.len().min(8);
    data[..n].copy_from_slice(&bytes[..n]);
}
