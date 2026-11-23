//! User console syscalls: `Read` + the VGA service dispatch (hito 3).
//!
//! This module is deliberately **additive**: the five milestone-1 numbers
//! stay in [`super::syscall`], and [`dispatch_extra`] is the single hook the
//! integrator adds to that module's match arm:
//!
//! ```text
//! n => crate::userland::console::dispatch_extra(
//!          n, [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
//!      ).unwrap_or(ENOSYS),
//! ```
//!
//! `Read(fd=0, buf, len)` feeds the same two polled input wires the kernel
//! shell uses — COM1 serial and the i8042/USB-keyboard line discipline —
//! through a bounded, echoing line editor owned by the kernel. It is
//! **non-blocking**: with no complete line waiting it returns `0` and the
//! user process is expected to `Yield` before trying again.
//!
//! Console ownership is the PCB's `owns_console` bit one layer up. This
//! module keeps a single-owner token so a second process is refused with
//! `EPERM` for every `Vga*` call; [`set_owner`] lets the scheduler publish
//! the PCB's decision here without touching this file again.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

use super::syscall::{EINVAL, EPERM};
use super::userptr;
use super::vgaservice;

// --- Stable syscall numbers (mirrored in `userlib`) ----------------------
/// `read(fd: u64, buf: *mut u8, len: u64) -> i64` — bytes or `0` (no input).
pub const NR_READ: u64 = 4;
/// `vga_dims() -> i64` — `(cols | rows << 16)`, or an errno.
pub const NR_VGA_DIMS: u64 = 5;
/// `vga_put_cell(x, y, glyph, attr) -> i64` — `0` on success.
pub const NR_VGA_PUT_CELL: u64 = 6;
/// `vga_clear() -> i64` — blank the staged cells.
pub const NR_VGA_CLEAR: u64 = 7;
/// `vga_flush() -> i64` — diff the staged cells into `0xb8000`.
pub const NR_VGA_FLUSH: u64 = 8;
/// `vga_peek(x, y) -> i64` — `(glyph | attr << 8)` from the hardware.
pub const NR_VGA_PEEK: u64 = 9;

/// Nobody owns the console yet. Kept out of the `u32` pid space (pids start
/// at 0 in the scheduler's identity mapping).
const NO_OWNER: u32 = u32::MAX;

static OWNER: AtomicU32 = AtomicU32::new(NO_OWNER);

/// Publish the scheduler's `owns_console` decision (PCB → service).
/// Kernel-only; called on spawn/switch by the integrator.
pub fn set_owner(pid: u32) {
    OWNER.store(pid, Ordering::Relaxed);
}

/// Give the console back (e.g. when the owning process exits).
pub fn release_owner() {
    OWNER.store(NO_OWNER, Ordering::Relaxed);
}

/// Current owner, if one has been published or has claimed by first use.
pub fn owner() -> Option<u32> {
    match OWNER.load(Ordering::Relaxed) {
        NO_OWNER => None,
        pid => Some(pid),
    }
}

/// First-use claim: the first process to touch a `Vga*` call owns the
/// console until the scheduler calls [`set_owner`] / [`release_owner`].
/// Hito 1's `enter_user` leaves `current_pid` at the idle PID0, so this is
/// the bridge that makes the proof self-contained; a real multi-process
/// tree should publish ownership from the PCB instead.
fn claim_or_check() -> i64 {
    let me = super::sched::current_pid();
    match OWNER.load(Ordering::Relaxed) {
        NO_OWNER => {
            let _ = OWNER.compare_exchange(NO_OWNER, me, Ordering::Relaxed, Ordering::Relaxed);
            0
        }
        owner_pid if owner_pid == me => 0,
        _ => EPERM,
    }
}

/// Hito-1 bridge: publish the two VMAs the ELF loader actually maps when
/// no scheduler has done `userptr::set_vm` yet. Without it the first user
/// process cannot pass a buffer to *any* syscall (including `Write`). The
/// real scheduler overwrites this on its first switch; the check is a
/// single relaxed load, so the bridge disappears by itself then.
fn ensure_user_vm() {
    if userptr::vm() != userptr::Vm::NONE {
        return;
    }
    let end = crate::memory::USER_END;
    let stack = crate::memory::USER_STACK_SIZE;
    userptr::set_vm(userptr::Vm {
        brk_base: crate::memory::USER_BASE,
        brk_end: end.saturating_sub(stack),
        stack_base: end.saturating_sub(stack),
        stack_end: end,
    });
}

// --- Bounded kernel input line discipline --------------------------------
/// Bytes kept per line. Matches the shell's 512-byte cap only loosely —
/// user commands are short, and a smaller cap keeps the static tiny.
const LINE_CAP: usize = 256;
/// One ready line can wait while the user process is between `Read`s.
const READY_CAP: usize = LINE_CAP;

struct InputQueue {
    line: [u8; LINE_CAP],
    line_len: usize,
    ready: [u8; READY_CAP],
    ready_len: usize,
    /// The LF half of a serial CRLF pair must not submit twice.
    skip_lf: bool,
}

impl InputQueue {
    const fn new() -> Self {
        Self {
            line: [0; LINE_CAP],
            line_len: 0,
            ready: [0; READY_CAP],
            ready_len: 0,
            skip_lf: false,
        }
    }

    fn feed(&mut self, byte: u8, from_serial: bool) {
        match byte {
            b'\r' => {
                if from_serial {
                    self.skip_lf = true;
                }
                self.submit();
            }
            b'\n' => {
                if from_serial && self.skip_lf {
                    self.skip_lf = false; // LF half of a CRLF pair
                } else {
                    self.submit();
                }
            }
            0x08 | 0x7f => {
                if from_serial {
                    self.skip_lf = false;
                }
                if self.line_len > 0 {
                    self.line_len -= 1;
                    // Erase the echoed glyph, exactly like the shell.
                    serial_print!("\x08 \x08");
                }
            }
            b if b.is_ascii_graphic() || b == b' ' => {
                if from_serial {
                    self.skip_lf = false;
                }
                if self.line_len < LINE_CAP {
                    self.line[self.line_len] = b;
                    self.line_len += 1;
                    serial_print!("{}", char::from(b));
                } else {
                    serial_print!("\x07"); // bell: refuse, never truncate
                }
            }
            _ => {} // other control bytes ignored
        }
    }

    fn submit(&mut self) {
        serial_print!("\n");
        if self.line_len == 0 {
            return;
        }
        if self.ready_len != 0 {
            // A line is already waiting: drop this one. Bounded and
            // non-blocking — the user process drains us on every Read.
            serial_print!("\x07");
            self.line_len = 0;
            return;
        }
        let n = self.line_len.min(READY_CAP);
        self.ready[..n].copy_from_slice(&self.line[..n]);
        self.ready_len = n;
        self.line_len = 0;
    }
}

/// `UnsafeCell` wrapper so the static is `Sync` without pretending the
/// queue has interior mutability of its own.
struct InputCell(UnsafeCell<InputQueue>);

// SAFETY: single core, one console owner, and the queue is touched only
// from syscall dispatch (the `int 0x80` interrupt gate clears IF on entry).
// No IRQ handler reads serial/keyboard here, so no re-entry or aliasing.
unsafe impl Sync for InputCell {}

static INPUT: InputCell = InputCell(UnsafeCell::new(InputQueue::new()));

fn input_mut() -> &'static mut InputQueue {
    // SAFETY: see the `Sync` contract above — unique access for the whole
    // duration of one syscall, IF=0, no nested dispatch.
    unsafe { &mut *INPUT.0.get() }
}

/// Poll one byte from each input wire at most once. Bounded work — a
/// missing byte is simply "no input yet", never a spin.
fn pump() {
    let serial_byte = crate::serial::SerialPort::COM1.read_byte();
    let key = crate::keyboard::next_char().filter(|c| c.is_ascii());
    if let Some(byte) = serial_byte {
        input_mut().feed(byte, true);
    }
    if let Some(ch) = key {
        input_mut().feed(ch as u8, false);
    }
}

// --- Syscall implementations ---------------------------------------------

fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    if let Err(e) = userptr::validate(buf, len as usize) {
        return e;
    }
    if input_mut().ready_len == 0 {
        pump();
        if input_mut().ready_len == 0 {
            return 0; // non-blocking: caller should Yield and retry
        }
    }
    let queue = input_mut();
    let n = queue.ready_len.min(len as usize);
    // SAFETY: `userptr::validate` proved the whole `buf..buf+len` range is
    // inside one registered writable user VMA and within the 64 KiB cap;
    // `n <= len`, and no other thread can be writing that buffer while the
    // interrupt-disabled dispatch copies into it.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, n) };
    dst.copy_from_slice(&queue.ready[..n]);
    queue.ready_len = 0;
    n as i64
}

fn sys_vga_dims() -> i64 {
    let perm = claim_or_check();
    if perm != 0 {
        return perm;
    }
    match vgaservice::dims() {
        Some((cols, rows)) => (cols as u64 | ((rows as u64) << 16)) as i64,
        None => EINVAL,
    }
}

fn sys_vga_put(x: u64, y: u64, glyph: u64, attr: u64) -> i64 {
    let perm = claim_or_check();
    if perm != 0 {
        crate::rtc::trace(0xB1); // EPERM on VgaPutCell
        return perm;
    }
    if x > u16::MAX as u64 || y > u16::MAX as u64 || glyph > u8::MAX as u64 || attr > u8::MAX as u64
    {
        return EINVAL;
    }
    if vgaservice::put(x as usize, y as usize, glyph as u8, attr as u8) {
        crate::rtc::trace(0xB2); // staged ok
        0
    } else {
        crate::rtc::trace(0xB3); // vgaservice::put refused
        EINVAL
    }
}

fn sys_vga_clear() -> i64 {
    let perm = claim_or_check();
    if perm != 0 {
        return perm;
    }
    vgaservice::clear();
    0
}

fn sys_vga_flush() -> i64 {
    let perm = claim_or_check();
    if perm != 0 {
        return perm;
    }
    vgaservice::flush();
    crate::rtc::trace(0xB4); // flushed
    0
}

fn sys_vga_peek(x: u64, y: u64) -> i64 {
    let perm = claim_or_check();
    if perm != 0 {
        return perm;
    }
    if x > u16::MAX as u64 || y > u16::MAX as u64 {
        return EINVAL;
    }
    match vgaservice::peek(x as usize, y as usize) {
        Some((glyph, attr)) => (glyph as u64 | ((attr as u64) << 8)) as i64,
        None => EINVAL,
    }
}

/// Dispatch one of the hito-3 syscall numbers.
///
/// Returns `None` for an unknown number so the caller can fall through to
/// its own `ENOSYS` arm; `Some(result)` for every number owned here.
pub fn dispatch_extra(nr: u64, args: [u64; 6]) -> Option<i64> {
    // The hito-1 loader does not publish the process VMAs yet; do it here
    // so a user buffer is usable from the very first syscall.
    ensure_user_vm();
    let ret = match nr {
        NR_READ => sys_read(args[0], args[1], args[2]),
        NR_VGA_DIMS => sys_vga_dims(),
        NR_VGA_PUT_CELL => sys_vga_put(args[0], args[1], args[2], args[3]),
        NR_VGA_CLEAR => sys_vga_clear(),
        NR_VGA_FLUSH => sys_vga_flush(),
        NR_VGA_PEEK => sys_vga_peek(args[0], args[1]),
        _ => return None,
    };
    Some(ret)
}
