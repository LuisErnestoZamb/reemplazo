//! 16550 UART driver for COM1 (0x3F8) — polled TX, no interrupts.
//!
//! Bring-up console: QEMU wires COM1 to `-serial stdio`. The port base is a
//! compile-time constant, so the type is stateless — no `static mut`, no
//! locking; safe to call from `kernel_main` and the panic path alike.

use crate::port::{inb, outb};
use core::fmt;

const COM1_BASE: u16 = 0x3F8;

/// A polled UART at a fixed COM-port base.
#[derive(Clone, Copy)]
pub struct SerialPort {
    _private: (),
}

impl SerialPort {
    pub const COM1: Self = Self { _private: () };

    /// Program the UART: disable interrupts, 8N1, FIFO on, divisor 3
    /// (38400 baud — irrelevant under QEMU, sane for real hardware).
    ///
    /// Idempotent: reprogramming identical register values is harmless, so
    /// the panic path may call it even if `kernel_main` already did.
    pub fn init(self) {
        // SAFETY: COM1_BASE..+8 is the standard 16550 register range; port
        // I/O to a UART cannot violate memory safety. Boot code is
        // single-threaded with interrupts disabled, so no interleaving.
        unsafe {
            outb(COM1_BASE + 1, 0x00); // disable all interrupts
            outb(COM1_BASE + 3, 0x80); // DLAB on
            outb(COM1_BASE, 0x03); // divisor low byte
            outb(COM1_BASE + 1, 0x00); // divisor high byte
            outb(COM1_BASE + 3, 0x03); // 8N1, DLAB off
            outb(COM1_BASE + 2, 0xC7); // FIFO: enable, clear, 14-byte threshold
            outb(COM1_BASE + 4, 0x0B); // RTS/DSR/OUT2 enabled
        }
    }

    /// Write one byte, spinning until the transmit holding register is empty.
    fn write_byte(self, byte: u8) {
        // SAFETY: standard COM1 register range (const above); polled port
        // I/O with interrupts off — no reentrancy.
        unsafe {
            while inb(COM1_BASE + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            outb(COM1_BASE, byte);
        }
    }
}

impl fmt::Write for SerialPort {
    /// Map `\n` to CRLF so terminals and `QEMU -serial file:` output read
    /// sanely. Never returns `Err`.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Print to COM1. `write_str` is infallible, so formatting errors cannot
/// occur; `let _` documents that choice instead of panicking mid-print.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        $crate::guard::check();
        let mut port = $crate::serial::SerialPort::COM1;
        let _ = core::fmt::Write::write_fmt(&mut port, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}
