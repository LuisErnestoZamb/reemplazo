//! 16550 UART driver for COM1 (0x3F8) — polled TX/RX, no interrupts.
//!
//! Bring-up console: QEMU wires COM1 to `-serial stdio`. Register I/O
//! lives in the [`uart_16550`] crate (its `unsafe` stays there); this
//! module keeps the exact public surface the kernel was built on: a
//! zero-sized [`SerialPort`] with [`SerialPort::COM1`], [`SerialPort::init`]
//! at our config (38400 baud, 8N1, FIFO on), polled
//! [`SerialPort::read_byte`], `fmt::Write` mapping `\n` → `\r\n`, and the
//! [`serial_print!`]/[`serial_println!`] macros with the stack-guard check.
//!
//! The type stays stateless — every use constructs a fresh crate handle
//! (no `static mut`, no locking), so a print from the panic/exception path
//! can never alias a `&mut` held by mainline.

use core::fmt;
use uart_16550::backend::PioBackend;
use uart_16550::{BaudRate, Config, Uart16550};

/// COM1 register base (standard PC port).
const COM1_BASE: u16 = 0x3F8;

/// A polled UART at a fixed COM-port base.
#[derive(Clone, Copy)]
pub struct SerialPort {
    _private: (),
}

impl SerialPort {
    pub const COM1: Self = Self { _private: () };

    /// A fresh crate handle for COM1, built per call — deliberately no
    /// shared `static` state: a print from an exception or the panic
    /// handler must never alias a `&mut` held by mainline. Interleaving
    /// is at worst another print between our bytes (lines interleave,
    /// state never corrupts).
    fn uart(self) -> Uart16550<PioBackend> {
        // SAFETY: `COM1_BASE..+8` is the standard 16550 register range
        // (`new_port`'s contract: all 8 registers reachable from the
        // base), and port I/O to a UART cannot violate memory safety.
        // Single-core boot; the handle is a plain value, not shared.
        // Infallible for 0x3F8: `new_port` only rejects u16 overflow of
        // `base + 7`.
        unsafe { Uart16550::new_port(COM1_BASE) }
            .expect("COM1 (0x3F8) always fits the 16550 register range")
    }

    /// Program the UART: disable interrupts, 8N1, FIFO on, divisor 3
    /// (38400 baud — irrelevant under QEMU, sane for real hardware).
    ///
    /// Idempotent: reprogramming identical register values is harmless, so
    /// the panic path may call it even if `kernel_main` already did.
    pub fn init(self) {
        let mut uart = self.uart();
        // `Config::DEFAULT` already matches our old `outb` sequence —
        // IER=0 (no interrupts), 8N1, FIFO enabled with the 14-byte
        // trigger (our old 0xC7), MCR DTR|RTS|OUT2 (our old 0x0B) — and
        // only the baud rate differs from its 9600 default: 38400 is
        // divisor 3 at the crate's 1.8432 MHz clock, exactly what
        // DLAB+DLL/DLM used to program.
        let config = Config {
            baud_rate: BaudRate::from_integer(38_400),
            ..Config::DEFAULT
        };
        // Never halt on failure: a dead UART (`DeviceNotPresent`) must
        // not stop the panic path — output degrades, the kernel does not
        // die. The crate's init also runs a scratch-register presence
        // check and drains stale RX data; both are standard and
        // harmless when repeated.
        let _ = uart.init(config);
    }

    /// Write one byte, spinning until the transmit holding register is
    /// empty (the crate polls `LSR::THR_EMPTY`, the same bit 5 we did).
    fn write_byte(self, byte: u8) {
        self.uart().send_bytes_exact(&[byte]);
    }

    /// Poll for one received byte: `None` when the receiver holding
    /// register is empty — the crate's `try_receive_byte` is exactly our
    /// LSR data-ready check. This is the shell console's input path,
    /// polled like the TX side; interrupt-driven RX arrives with the
    /// keyboard/IRQ milestone.
    pub fn read_byte(self) -> Option<u8> {
        self.uart().try_receive_byte().ok()
    }
}

impl fmt::Write for SerialPort {
    /// Map `\n` to CRLF so terminals and `QEMU -serial file:` output read
    /// sanely. Never returns `Err`. Deliberately *not* the crate's
    /// `Uart16550Tty` wrapper: its `write_str` also echoes backspace,
    /// which must not appear in the log stream.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // netlog (milestone): copy the line into the serial ring so
        // the bring-up mode can serve it over TCP — hooked here, not
        // in the macros, so the panic path is captured too. A bounded
        // copy into a static buffer: no allocation, and `push` never
        // prints, so this cannot recurse into `serial_print!`. Raw
        // `s` (LF only): the CRLF mapping below is a wire detail of
        // the UART, not part of the log text.
        crate::netlog::push(s.as_bytes());
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Print to the console — the COM1 UART **and** the VGA text buffer
/// (real hardware exposes no serial port; see `crate::vga`).
/// `write_str` is infallible, so formatting errors cannot occur;
/// `let _` documents that choice instead of panicking mid-print.
///
/// Both sinks format the arguments independently (each keeps its own
/// temporaries valid — a single bound `format_args!` cannot), so the
/// argument expressions are evaluated **twice**: keep them
/// side-effect free (field reads and arithmetic, as everywhere here).
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        $crate::guard::check();
        $crate::vga::mirror(format_args!($($arg)*));
        let mut port = $crate::serial::SerialPort::COM1;
        let _ = core::fmt::Write::write_fmt(&mut port, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}
