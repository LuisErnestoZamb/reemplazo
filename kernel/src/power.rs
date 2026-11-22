//! Machine reset for the hardware bring-up path.
//!
//! The real MacBook has no serial port: if the OS cannot bring its NIC
//! up, the only recovery channel is a reboot back to whatever the
//! bootloader boots next (the installer/GRUB one-shot entry returns to
//! the previous system). [`reboot`] drives the 8042 reset line — the
//! same pulse the firmware itself uses — and, if the machine ignores
//! it, parks forever (the physical power button remains the last
//! resort, documented in `docs/hardware.md` §3).

use crate::port;

/// Busy-wait for `ms` milliseconds on the PIT clock (`clock::now_ms`
/// is monotonic once [`crate::arm_interrupts`] has run).
pub fn wait_ms(ms: u64) {
    let deadline = crate::clock::now_ms().saturating_add(ms);
    while crate::clock::now_ms() < deadline {
        core::hint::spin_loop();
    }
}

/// Pulse the 8042's reset line (command `0xFE` on port `0x64`) and
/// then park. `-> !` keeps every caller fail-closed: a reset that does
/// not take must not fall through into "continue anyway" code.
pub fn reboot() -> ! {
    serial_println!("power: reboot via the 8042 reset line");
    // SAFETY: fixed legacy port write, the firmware-documented reset
    // pulse; no other writer touches 0x64 in this kernel.
    unsafe { port::outb(0x64, 0xFE) };
    // The pulse is asynchronous; if it did not take, halt loudly.
    serial_println!("power: reset line did not take -- halting (power button required)");
    crate::halt()
}
