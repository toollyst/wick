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
//!   channel 0 drives IRQ 0 from a timer thread, periodically in modes 2 and
//!   3 and once per count loaded in modes 0, 1 and 4, as KVM's PIT does (a
//!   Linux guest whose local APIC timer is not used ticks on the PIT in
//!   one-shot mode, mode 4); every channel's count and output read back as
//!   KVM computes them, channel 2's output through the speaker port.
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

    /// The input clock ticks since the count was loaded.
    fn elapsed_ticks(&self) -> u64 {
        let elapsed_ns = u64::try_from(self.load_time.elapsed().as_nanos()).unwrap_or(u64::MAX);
        u64::try_from(u128::from(elapsed_ns) * u128::from(PIT_FREQ) / 1_000_000_000).unwrap_or(u64::MAX)
    }

    /// The counter's current value, `d` input clock ticks after the count was
    /// loaded (KVM's `pit_get_count`).
    fn count_after(&self, d: u64) -> u16 {
        let count = self.reload_value();
        #[allow(clippy::cast_possible_truncation)]
        match self.mode {
            0 | 1 | 4 | 5 => (count.wrapping_sub(d) & 0xffff) as u16,
            3 => (count - (d.wrapping_mul(2) % count)) as u16,
            _ => (count - d % count) as u16,
        }
    }

    /// The counter's output, `d` input clock ticks after the count was loaded
    /// (KVM's `pit_get_out`).
    fn out_after(&self, d: u64) -> bool {
        let count = self.reload_value();
        match self.mode {
            1 => d < count,
            2 => d.is_multiple_of(count) && d != 0,
            3 => d % count < count.div_ceil(2),
            4 | 5 => d == count,
            _ => d >= count,
        }
    }

    /// The counter's current value.
    fn current_count(&self) -> u16 {
        self.count_after(self.elapsed_ticks())
    }

    /// The counter's current output.
    fn out(&self) -> bool {
        self.out_after(self.elapsed_ticks())
    }

    /// The time the loaded count takes to reach zero, in nanoseconds.
    fn period_ns(&self) -> u64 {
        self.reload_value().saturating_mul(1_000_000_000) / PIT_FREQ
    }

    /// What channel 0 does with IRQ 0 for its mode once a count is loaded
    /// (KVM's `kvm_pit_load_count`): `Some(true)` raises it every period
    /// (modes 2 and 3), `Some(false)` once when the count reaches zero
    /// (modes 0, 1 and 4), `None` never (mode 5).
    fn irq_timer(&self) -> Option<bool> {
        match self.mode {
            0 | 1 | 4 => Some(false),
            2 | 3 => Some(true),
            _ => None,
        }
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
    /// 0: disarmed.
    period_ns: u64,
    /// Whether IRQ 0 repeats every period, or is raised once.
    periodic: bool,
    generation: u64,
    stop: bool,
}

/// Raises IRQ 0 (on the timer thread); false once the VM is gone.
type Irq0 = Box<dyn Fn() -> bool + Send>;

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

    /// Starts or reprograms the channel-0 timer thread for the count just
    /// loaded and the channel's mode.
    fn program_timer(&mut self, inner: &Arc<VmInner>) {
        let weak = Arc::downgrade(inner);
        self.program_timer_with(move || {
            Box::new(move || match weak.upgrade() {
                Some(inner) => {
                    inner.raise_gsi(0, true);
                    inner.raise_gsi(0, false);
                    true
                }
                None => false,
            })
        });
    }

    /// [`Self::program_timer`], with `irq0` making what raises IRQ 0 if the
    /// timer thread is started.
    fn program_timer_with(&mut self, irq0: impl FnOnce() -> Irq0) {
        let ch = &self.channels[0];
        let (period_ns, periodic) = match ch.irq_timer() {
            Some(periodic) => (ch.period_ns().max(1), periodic),
            None => (0, false),
        };
        if let Some(timer) = &self.timer {
            let (lock, cv) = &*timer.shared;
            let mut cmd = lock.lock().unwrap();
            cmd.period_ns = period_ns;
            cmd.periodic = periodic;
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
                periodic,
                generation: 0,
                stop: false,
            }),
            Condvar::new(),
        ));
        let thread_shared = shared.clone();
        let irq0 = irq0();
        let join = std::thread::spawn(move || timer_loop(&thread_shared, &irq0));
        self.timer = Some(PitTimer {
            shared,
            join: Some(join),
        });
    }
}

/// The channel-0 timer: waits one period, raises IRQ 0, and repeats in a
/// periodic mode or disarms in a one-shot one. Reprogrammed by bumping the
/// generation; stops when the VM is gone or `stop` is set.
fn timer_loop(shared: &Arc<(Mutex<TimerCmd>, Condvar)>, irq0: &Irq0) {
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
        let mut cmd = cmd;
        if !cmd.periodic {
            // One-shot: done until a count is loaded again.
            cmd.period_ns = 0;
        }
        drop(cmd);
        if !irq0() {
            return;
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
            0x43 => self.pit_write_control(value),
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
        // Bit 5 is channel 2's output, which a guest polls when it
        // calibrates its TSC against the PIT.
        let out2 = u8::from(pit.channels[2].out());
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

    fn pit_write_control(&mut self, value: u8) {
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
        // Modes 6 and 7 are 2 and 3.
        channel.mode = match (value >> 1) & 0x7 {
            m @ 6..=7 => m - 4,
            m => m,
        };
        channel.write_hi = false;
        channel.read_hi = false;
        channel.latched = None;
        // The timer changes when a count is loaded, as in KVM.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn channel(mode: u8, reload: u32) -> PitChannel {
        PitChannel { mode, reload, ..PitChannel::new() }
    }

    /// Counts and outputs as KVM's `pit_get_count` and `pit_get_out` give
    /// them.
    #[test]
    fn test_pit_count_and_out_by_mode() {
        // Mode 0 (interrupt on terminal count): counts down once, then wraps
        // through 0xffff; the output goes high at zero and stays.
        let c = channel(0, 100);
        assert_eq!(c.count_after(0), 100);
        assert_eq!(c.count_after(40), 60);
        assert_eq!(c.count_after(101), 0xffff);
        assert!(!c.out_after(99));
        assert!(c.out_after(100));
        assert!(c.out_after(5000));
        // Mode 4 (software strobe, Linux's one-shot): high for the zero tick only.
        let c = channel(4, 100);
        assert!(!c.out_after(99));
        assert!(c.out_after(100));
        assert!(!c.out_after(101));
        // Mode 2 (rate generator): reloads; the output pulses at each reload.
        let c = channel(2, 100);
        assert_eq!(c.count_after(130), 70);
        assert!(c.out_after(200));
        assert!(!c.out_after(201));
        assert!(!c.out_after(0));
        // Mode 3 (square wave): counts down by two; high for the first half.
        let c = channel(3, 100);
        assert_eq!(c.count_after(10), 80);
        assert!(c.out_after(49));
        assert!(!c.out_after(50));
        // A reload of 0 is 65536.
        let c = channel(2, 0);
        assert_eq!(c.count_after(1), 0xffff);
    }

    #[test]
    fn test_pit_irq_timer_by_mode() {
        for (mode, expect) in [(0, Some(false)), (1, Some(false)), (4, Some(false)), (2, Some(true)), (3, Some(true)), (5, None)] {
            assert_eq!(channel(mode, 1000).irq_timer(), expect, "mode {mode}");
        }
    }

    /// Loads channel 0 of `pit` with `mode` and `reload`, as a guest's OUTs
    /// would, and (re)programs the timer with a counting IRQ 0.
    fn load(pit: &mut Pit, mode: u8, reload: u32, irqs: &Arc<AtomicU32>) {
        pit.channels[0].mode = mode;
        pit.channels[0].reload = reload;
        pit.channels[0].load_time = Instant::now();
        let irqs = irqs.clone();
        pit.program_timer_with(move || {
            Box::new(move || {
                irqs.fetch_add(1, Ordering::SeqCst);
                true
            })
        });
    }

    /// Linux's one-shot PIT clockevent (`pit_set_oneshot`, then a count per
    /// event) gets one IRQ 0 per count, as from KVM's PIT; before, only the
    /// periodic modes raised it and a guest ticking on the PIT in one-shot
    /// mode stopped taking timer interrupts.
    #[test]
    fn test_pit_one_shot_raises_irq0_once_per_count() {
        let mut pit = Pit::new(0);
        let irqs = Arc::new(AtomicU32::new(0));
        // 1193 ticks: 1 ms.
        load(&mut pit, 4, 1193, &irqs);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(irqs.load(Ordering::SeqCst), 1, "mode 4: one IRQ 0 per count");
        load(&mut pit, 4, 1193, &irqs);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(irqs.load(Ordering::SeqCst), 2, "a second count, a second IRQ 0");
        load(&mut pit, 0, 1193, &irqs);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(irqs.load(Ordering::SeqCst), 3, "mode 0 too");
    }

    #[test]
    fn test_pit_periodic_repeats_and_mode_5_stops() {
        let mut pit = Pit::new(0);
        let irqs = Arc::new(AtomicU32::new(0));
        // 11932 ticks: 10 ms.
        load(&mut pit, 2, 11932, &irqs);
        std::thread::sleep(Duration::from_millis(300));
        let n = irqs.load(Ordering::SeqCst);
        assert!(n >= 5, "mode 2 every 10 ms: {n} IRQs in 300 ms");
        // Mode 5 (hardware-triggered strobe, no gate on channel 0): none.
        load(&mut pit, 5, 11932, &irqs);
        let n = irqs.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert!(irqs.load(Ordering::SeqCst) <= n + 1, "mode 5 kept raising IRQ 0");
    }
}
