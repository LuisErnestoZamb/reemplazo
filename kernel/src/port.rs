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

/// Read a word (16 bits) from I/O port `port` (x86 `in` instruction).
/// Needed for the ATA data register (0x1F0): PIO sector transfers are
/// 16 bits wide.
///
/// # Safety
/// Same contract as [`inb`], for 16-bit access width.
#[inline]
pub(crate) unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: forwarded to the caller's contract above; `in` from a port
    // touches I/O space only and the output operand is always initialized.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

/// Output a dword to I/O port `port` (x86 `out` instruction).
/// Needed for PCI configuration (CF8/CFC).
///
/// # Safety
/// Same contract as [`outb`], for 32-bit access width.
#[inline]
pub(crate) unsafe fn outl(port: u16, val: u32) {
    // SAFETY: forwarded to the caller's contract above.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a dword from I/O port `port` (x86 `in` instruction).
///
/// # Safety
/// Same contract as [`inb`], for 32-bit access width.
#[inline]
pub(crate) unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: forwarded to the caller's contract above; output operand is
    // always initialized by the `in` instruction.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            out("eax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}
