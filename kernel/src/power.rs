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
    // SAFETY: fixed legacy port writes, the firmware-documented reset
    // pulses; no other writer touches 0x64/0x92 in this kernel.
    unsafe { port::outb(0x64, 0xFE) };
    wait_ms(2_000);
    // Fallback 1: the "alternate" reset via port 0x92 (bit0 = fast
    // INIT) — the 8042 pulse is not guaranteed on every chipset
    // (observed risk on the Apple BIOS emulation).
    serial_println!("power: 8042 reset did not take; trying port 0x92");
    unsafe { port::outb(0x92, 0x01) };
    wait_ms(2_000);
    // Fallback 2: the classic triple fault — load a null IDT and
    // raise an exception; with no handler the CPU resets through the
    // firmware, which re-enters the boot path (and the loader's
    // one-shot entry is already consumed, so the previous OS boots).
    serial_println!("power: port 0x92 did not take; triple faulting");
    // SAFETY: a deliberately invalid IDT base (0, limit 0) followed
    // by an exception — every IDT entry is a gate, so the fault
    // triple-faults by design; interrupts are already off here.
    unsafe {
        let idtr: [u8; 10] = [0; 10];
        core::arch::asm!("lidt [{}]", in(reg) idtr.as_ptr(), options(readonly, nostack, preserves_flags));
        core::arch::asm!("int3", options(nomem, nostack));
    }
    serial_println!("power: triple fault did not take -- halting (power button required)");
    crate::halt()
}
