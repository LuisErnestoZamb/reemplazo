//! Hito 3 — the first console-owning user process.
//!
//! `no_std`, no heap, no allocator. It proves the kernel's VGA service
//! round-trip (`USER_CONSOLE_OK`), announces the REPL (`USER_SHELL_OK`),
//! then serves a bounded line-oriented prompt over the new `Read` syscall
//! with the minimal builtins the blueprint allows. Every command comes
//! from COM1 / the i8042-USB keyboard through the kernel's line discipline
//! — the process never sees a hardware address.
//!
//! The smoke harness injects exactly one command (`echo …`) through QEMU's
//! monitor after `USER_SHELL_OK`, so after executing one line this shell
//! exits, letting the kernel emit `USER_RETURN_OK`. The read→execute→repeat
//! loop is real; the one-shot bound is only the smoke's deterministic exit.

#![no_std]
#![no_main]

use userlib as sys;

core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

/// Bounded command line (kernel refuses longer lines with a bell).
const BUF_CAP: usize = 256;
/// Safety valve: give up waiting for the harness's command after this many
/// non-blocking `Read` polls so a broken input wire can never hang boot.
const MAX_POLLS: u32 = 1_000_000;

// Initialised (spaces, not zeros) on purpose: an all-zero static lands in
// .bss, and rust-lld emits a second R|W PT_LOAD for NOBITS that shares the
// .data page — the U1 loader then refuses it as `AlreadyMapped`. Keeping
// the line buffer in .data yields one writable load segment.
static mut BUF: [u8; BUF_CAP] = [b' '; BUF_CAP];

/// Called by `_start` with the kernel-provided user stack aligned.
#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    // The very first syscall is VgaDims: besides claiming console
    // ownership it makes the kernel publish this process's VMAs, so the
    // subsequent Write calls can pass `userptr` validation.
    match sys::console_dims() {
        Some((cols, rows)) if cols > 0 && rows > 0 => {}
        _ => {
            sys::write_str("FATAL: ushell: no VGA text console\n");
            sys::exit(1);
        }
    }

    // Stage one distinctive cell, flush it into 0xb8000 through the
    // kernel's diff service, then read the hardware back. No user code
    // touches the framebuffer directly.
    const GLYPH: u8 = b'U';
    const ATTR: u8 = 0x1f;
    if sys::vga_put_cell(0, 0, GLYPH, ATTR) != 0
        || sys::vga_flush() != 0
        || sys::vga_peek(0, 0) != Some((GLYPH, ATTR))
    {
        sys::write_str("FATAL: ushell: VGA service round-trip failed\n");
        sys::exit(1);
    }
    sys::write_str("USER_CONSOLE_OK\n");
    sys::write_str("USER_SHELL_OK\n");
    sys::write_str("ushell> ");

    let mut polls: u32 = 0;
    loop {
        let n = sys::read(0, line_mut());
        if n > 0 {
            // `n` is a kernel-produced byte count bounded by BUF_CAP.
            let line = line_ref();
            let end = if (n as usize) <= BUF_CAP {
                n as usize
            } else {
                BUF_CAP
            };
            execute(&line[..end]);
            sys::write_str("ushell: bye\n");
            sys::exit(0);
        } else if n < 0 {
            sys::write_str("FATAL: ushell: Read failed\n");
            sys::exit(1);
        } else {
            // Non-blocking Read with no complete line: yield and retry.
            polls = polls.saturating_add(1);
            if polls > MAX_POLLS {
                sys::exit(0);
            }
            let _ = sys::yield_now();
        }
    }
}

fn line_mut() -> &'static mut [u8; BUF_CAP] {
    // SAFETY: single-threaded ring-3 process; the buffer lives in the
    // writable .bss PT_LOAD and no other reference to it is alive here.
    unsafe { &mut *core::ptr::addr_of_mut!(BUF) }
}

fn line_ref() -> &'static [u8; BUF_CAP] {
    // SAFETY: read-only side of the same single-threaded contract, called
    // only after the `Read` syscall has returned and dropped its borrow.
    unsafe { &*core::ptr::addr_of!(BUF) }
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

/// Run one command. Unknown commands only print a hint — never panic,
/// never read outside the line the kernel handed us.
fn execute(raw: &[u8]) {
    let mut split = 0;
    while split < raw.len() && raw[split] != b' ' && raw[split] != b'\t' {
        split += 1;
    }
    let cmd = &raw[..split];
    let mut rest = &raw[split..];
    while let Some((first, tail)) = rest.split_first()
        && (*first == b' ' || *first == b'\t')
    {
        rest = tail;
    }

    if eq(cmd, b"help") {
        sys::write_str("builtins: help echo uptime exit apps\n");
    } else if eq(cmd, b"echo") {
        let _ = sys::write(1, rest);
        sys::write_str("\n");
    } else if eq(cmd, b"uptime") {
        let now = sys::time();
        if now < 0 {
            sys::write_str("uptime: unavailable\n");
        } else {
            sys::write_str("uptime: ");
            write_u64(now as u64);
            sys::write_str(" ms\n");
        }
    } else if eq(cmd, b"apps") {
        sys::write_str("apps: editor ai chat browser git ssh installer (kernel-owned)\n");
    } else if eq(cmd, b"exit") {
        sys::exit(0);
    } else if !cmd.is_empty() {
        sys::write_str("ushell: unknown command (try help)\n");
    }
}

/// Decimal formatting without `alloc` or `unwrap`.
fn write_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    if value == 0 {
        at -= 1;
        digits[at] = b'0';
    }
    while value > 0 {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let _ = sys::write(1, &digits[at..]);
}

/// No unwinding in userland (panic=abort); a panic terminates the process.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(1)
}
