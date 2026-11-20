//! x86 I/O port access (`in`/`out` instructions).
//!
//! Shared by the serial driver, PIC and PIT. All functions are `unsafe`
//! because the caller must guarantee the port exists and the access width
//! matches the device's contract.

/// Output byte `val` to I/O port `port` (x86 `out` instruction).
///
/// # Safety
/// The caller must ensure the port is a valid, writable I/O port for the
/// device being addressed; out-of-range or wrong-device writes are a
/// hardware-contract violation, not a memory-safety one.
#[inline]
pub(crate) unsafe fn outb(port: u16, val: u8) {
    // SAFETY: forwarded to the caller's contract above; `out` to a port
    // touches I/O space only, never memory.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a byte from I/O port `port` (x86 `in` instruction).
///
/// # Safety
/// The caller must ensure the port is a valid, readable I/O port for the
/// device being addressed.
#[inline]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: forwarded to the caller's contract above; `in` from a port
    // touches I/O space only and the output operand is always initialized.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}
