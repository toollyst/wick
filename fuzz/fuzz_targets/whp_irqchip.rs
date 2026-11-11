// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The WHP backend's interrupt controller (`whp/irqchip.rs`), driven as the
//! WHP run loop drives it: any sequence of guest port and MMIO accesses (the
//! PICs, the ELCR, the PIT and speaker port, the I/O APIC window), interrupt
//! lines raised and lowered (irqfds, `set_irq_line`), MSI routes, and PIT
//! state restored from a snapshot file. Checked:
//! - nothing panics or overflows;
//! - a snapshot holds the guest-visible state: a VM restored from one taken
//!   at any point (as Firecracker restores one: routes, `KVM_SET_IRQCHIP`,
//!   `KVM_SET_PIT2`) saves the same state and answers every later access as
//!   the original does (the PIT's counter bytes, latched counts and channel
//!   2's output aside, which follow the host clock);
//! - the interrupt request made of each MSI carries its vector and
//!   destination.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::whp::Chip;

/// The ports the run loop gives the controller, and two it does not.
const PORTS: [u16; 13] = [0x20, 0x21, 0xA0, 0xA1, 0x4D0, 0x4D1, 0x40, 0x41, 0x42, 0x43, 0x61, 0x80, 0x3f8];
const IOAPIC: u64 = 0xFEC0_0000;

#[derive(Arbitrary, Debug)]
enum Op {
    In { port: u8, len: u8 },
    Out { port: u8, value: u32, len: u8 },
    MmioRead { off: u8, len: u8 },
    MmioWrite { off: u8, value: u64, len: u8 },
    Line { gsi: u8, level: bool },
    Routes(Vec<(u8, u64, u32)>),
    /// PIT state from a snapshot file.
    SetPit(Vec<u8>),
    Snapshot,
}

fn port(p: u8) -> u16 {
    PORTS[p as usize % PORTS.len()]
}

fn io_len(l: u8) -> usize {
    [1, 2, 4][l as usize % 3]
}

fn mmio_len(l: u8) -> usize {
    [1, 2, 4, 8][l as usize % 4]
}

/// Runs `op` on `chip`; what the guest or the VMM sees of it.
fn run(chip: &mut Chip, op: &Op) -> Option<(u64, u64)> {
    match *op {
        Op::In { port: p, len } => {
            let port = port(p);
            if !chip.handles_pio(port) {
                return None;
            }
            let len = io_len(len);
            let v = chip.pio_read(port, len);
            assert!(len == 8 || v >> (8 * len) == 0, "IN {port:#x} of {len} returned {v:#x}");
            // The PIT counters and channel 2's output follow the clock; the
            // speaker data bit is not in a snapshot, on KVM either.
            Some(match port {
                0x40..=0x42 => (0, 0),
                0x61 => (u64::from(port), v & !0x22),
                _ => (u64::from(port), v),
            })
        }
        Op::Out { port: p, value, len } => {
            let port = port(p);
            if chip.handles_pio(port) {
                chip.pio_write(port, u64::from(value), io_len(len));
            }
            None
        }
        Op::MmioRead { off, len } => {
            let addr = IOAPIC + u64::from(off % 0x20);
            assert!(chip.handles_mmio(addr));
            Some((addr, chip.mmio_read(addr, mmio_len(len))))
        }
        Op::MmioWrite { off, value, len } => {
            let addr = IOAPIC + u64::from(off % 0x20);
            chip.mmio_write(addr, value, mmio_len(len)).map(|(a, d)| check_msi(a, d))
        }
        Op::Line { gsi, level } => chip.raise_gsi(u32::from(gsi % 40), level).map(|(a, d)| check_msi(a, d)),
        Op::Routes(ref r) => {
            let routes: Vec<(u32, u64, u32)> =
                r.iter().take(32).map(|&(g, a, d)| (u32::from(g % 40), a, d)).collect();
            chip.set_routes(&routes);
            None
        }
        Op::SetPit(ref b) => {
            chip.set_pit(b);
            None
        }
        Op::Snapshot => None,
    }
}

/// The request the backend makes of an MSI carries its vector and
/// destination.
fn check_msi(address: u64, data: u32) -> (u64, u64) {
    let c = Chip::interrupt(address, data);
    assert_eq!(c.Vector, data & 0xff);
    assert_eq!(u64::from(c.Destination), (address >> 12) & 0xff);
    (address, u64::from(data))
}

fuzz_target!(|ops: Vec<Op>| {
    let mut chip = Chip::new();
    let mut restored: Option<Chip> = None;
    for (i, op) in ops.iter().take(256).enumerate() {
        if matches!(op, Op::Snapshot) && restored.is_none() {
            let state = chip.save();
            let copy = Chip::restore(&state, chip.routes());
            assert_eq!(copy.save(), state, "the restored VM saves another state (op {i})");
            restored = Some(copy);
            continue;
        }
        let seen = run(&mut chip, op);
        if let Some(copy) = &mut restored {
            let theirs = run(copy, op);
            assert_eq!(seen, theirs, "the restored VM answers {op:?} differently (op {i}, {ops:?})");
            assert_eq!(
                copy.save().without_clock(),
                chip.save().without_clock(),
                "the restored VM's state differs after {op:?} (op {i})"
            );
        }
    }
});
