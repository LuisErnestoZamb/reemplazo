//! PIT (8253/8254) channel 0: periodic timer interrupt on IRQ0.
//!
//! Base frequency 1_193_182 Hz; we program a square wave (mode 3) at
//! [`HZ`] so QEMU delivers IRQ0 at a fixed rate.

use crate::port::outb;
use core::sync::atomic::{AtomicU64, Ordering};

const PIT_INPUT_HZ: u32 = 1_193_182;
const PIT_CMD: u16 = 0x43; // command port (channel/Access/mode/bcd)
const PIT_CH0_DATA: u16 = 0x40; // channel 0 data port

/// Timer frequency in Hz.
pub const HZ: u64 = 100;

/// Ticks since [`init`]. IRQ0 handler increments; boot code polls it.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Program channel 0 for [`HZ`] square waves. Call after [`crate::pic::init`]
/// and before `sti`.
pub fn init() {
    // divisor must fit u16: 1_193_182 / 100 = 11_931 ✓ (assert below).
    let divisor = (PIT_INPUT_HZ / HZ as u32) as u16;
    debug_assert!(
        u32::from(divisor) == PIT_INPUT_HZ / HZ as u32,
        "divisor overflow"
    );

    // SAFETY: PIT command/data ports; channel 0, lo/hi access, mode 3
    // (square wave), binary counter. Single-core, IF=0.
    unsafe {
        outb(PIT_CMD, 0x36);
        outb(PIT_CH0_DATA, divisor as u8); // low byte
        outb(PIT_CH0_DATA, (divisor >> 8) as u8); // high byte
    }
}

/// Called from the IRQ0 handler in `idt.rs`.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Current tick count (monotonic since [`init`]).
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}
