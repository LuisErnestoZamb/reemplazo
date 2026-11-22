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

/// Wait for `ms` milliseconds on the PIT clock (`clock::now_ms` is
/// monotonic once [`crate::arm_interrupts`] has run), sleeping with
/// [`idle`] instead of burning a core.
pub fn wait_ms(ms: u64) {
    let deadline = crate::clock::now_ms().saturating_add(ms);
    while crate::clock::now_ms() < deadline {
        // The IRQ0-driven clock keeps ticking while the CPU sleeps, so
        // the deadline is hit at the same instant a spin would have
        // hit it — `hlt` only changes how the wait is spent. With
        // IF=0 (`wait_ms` before `arm_interrupts`) `idle` falls back
        // to `spin_loop`, which is exactly the old behaviour: the tick
        // counter is frozen there, so the loop is bounded by nothing
        // but the reset itself either way.
        idle();
    }
}

/// One idle step for a wait loop that made **no progress** this pass:
/// `hlt` until the next interrupt, or `spin_loop` when interrupts are
/// masked.
///
/// With IF=1 the PIT's IRQ0 (100 Hz, `pit::HZ`) wakes the CPU within
/// one tick, so callers keep their millisecond deadlines untouched —
/// `clock::now_ms()` reads the tick counter, which advances during the
/// sleep. Cost for polled I/O: the NIC has no unmasked IRQ line
/// (`pic::init` keeps IRQ0 only), so a frame arriving mid-sleep is
/// noticed on the next `stack.poll()`, i.e. **≤10 ms added latency per
/// idle pass** — the accepted price of a quiet Core2 (at 100% duty the
/// MacBook's fan roars).
pub(crate) fn idle() {
    if interrupts_enabled() {
        // SAFETY: `hlt` with IF=1 sleeps until the next interrupt;
        // harmless if that interrupt already raced in (the caller's
        // loop re-checks its condition). Same pattern as
        // `main::test_interrupts`; the kernel is single-core, so no
        // other context can observe the sleep.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    } else {
        // With IF=0 no maskable interrupt can wake a `hlt` — only an
        // NMI would, and this kernel raises none — so it would sleep
        // forever (the state `reboot` parks in). Spin instead.
        core::hint::spin_loop();
    }
}

/// RFLAGS.IF: is the CPU accepting maskable interrupts right now?
fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq; pop` snapshots RFLAGS into a register; the only
    // memory touched is this function's own frame (hence no
    // `nostack`), and neither instruction modifies the flags read.
    unsafe {
        core::arch::asm!("pushfq", "pop {flags}", flags = out(reg) flags, options(preserves_flags));
    }
    (flags & (1 << 9)) != 0
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
