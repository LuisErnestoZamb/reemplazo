//! Syscall ABI dispatch for the `int 0x80` boundary.
//!
//! `m-privilege` owns the privilege transition: GDT6 + TSS, the DPL3 gate at
//! vector 128, the `isr_128` stub and the IDT entry. Its vector-128 path
//! saves the exact [`Frame`](crate::idt::Frame) described in `idt.rs` and
//! calls this module. The only kernel entry point it needs is [`dispatch`]:
//!
//! ```text
//! 128 => { let ret = crate::userland::syscall::dispatch(frame);
//!          frame.rax = ret as u64; }   // isr_common then iretq
//! ```
//!
//! [`dispatch`] also writes `frame.rax` itself, so either convention works.
//! Arguments follow SysV (`rdi, rsi, rdx, r10, r8, r9`), which is exactly the
//! order `isr_common` pushes them. Negative return values are errnos;
//! positive/zero are success. No user pointer is ever dereferenced without
//! passing through [`userptr`].
//!
//! Milestone 1 is cooperative: `yield` returns to the caller and the
//! preemptive tick is milestone 2 (owned by the scheduler agent).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::idt::Frame;

use super::userptr::{self, Vm};

// --- Stable syscall numbers (mirrored in `userlib`) ----------------------
/// `write(fd: u64, buf: *const u8, len: u64) -> i64`
pub const NR_WRITE: u64 = 0;
/// `exit(code: i64) -> !`
pub const NR_EXIT: u64 = 1;
/// `yield() -> i64` (cooperative in milestone 1)
pub const NR_YIELD: u64 = 2;
/// `time() -> i64` (milliseconds since boot)
pub const NR_TIME: u64 = 3;

// --- Errno values (negative returns, mirrored in `userlib`) --------------
pub const EINVAL: i64 = -1;
pub const EFAULT: i64 = -2;
pub const EPERM: i64 = -13;
pub const ENOSYS: i64 = -38;

/// Hard cap per `write` call; matches `userptr::MAX_IO_LEN`.
const MAX_WRITE: u64 = userptr::MAX_IO_LEN as u64;

/// Optional termination hook installed by the scheduler. `0` = no process
/// subsystem yet, in which case `exit` prints and parks the CPU.
static EXIT_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the process-termination callback (kernel-only). The scheduler
/// passes its `terminate_current(code)` here; the default is a safe halt.
pub fn set_exit_hook(hook: extern "C" fn(i64)) {
    EXIT_HOOK.store(hook as usize as u64, Ordering::Relaxed);
}

/// Dispatch one syscall from the saved interrupt frame.
///
/// Called from `m-privilege`'s vector-128 arm. Reads the number from
/// `frame.rax`, the six SysV arguments from the saved GPRs, and returns the
/// result (also stored back into `frame.rax` for either caller convention).
pub fn dispatch(frame: &mut Frame) -> i64 {
    let (ret, _next) = dispatch_inner(frame);
    ret
}

/// Like [`dispatch`], but also returns the frame the caller must resume.
///
/// Ordinary syscalls return the incoming frame. `Yield` returns the frame
/// of the next runnable process, so the `int 0x80` hook can make the switch
/// real by returning *this* value instead of its own `frame` pointer.
///
/// **Integrator action (mod.rs, `syscall_hook`):** replace
/// `syscall::dispatch(f);` with
/// `let resume = syscall::dispatch_resume(f);` and return `resume` at the
/// end of the adapter (keep the `NR_EXIT` arm's `exit_current` path).
pub fn dispatch_resume(frame: &mut Frame) -> *mut Frame {
    let (_ret, next) = dispatch_inner(frame);
    next
}

fn dispatch_inner(frame: &mut Frame) -> (i64, *mut Frame) {
    let nr = frame.rax;
    let ptr: *mut Frame = frame;
    let (ret, next) = match nr {
        NR_WRITE => (sys_write(frame.rdi, frame.rsi, frame.rdx), ptr),
        NR_EXIT => (sys_exit(frame.rdi as i64), ptr),
        NR_YIELD => (0, sys_yield(ptr)),
        NR_TIME => (sys_time(), ptr),
        _ => (ENOSYS, ptr),
    };
    // SAFETY: `ptr` was derived from the live `&mut frame` and is the only
    // handle used again after the match (the Yield arm may have handed the
    // raw pointer to the scheduler). Writing through it keeps that single
    // provenance chain instead of reviving the `&mut`.
    unsafe { (*ptr).rax = ret as u64 };

    // The marker fires on the first real dispatch even if the integrator
    // never calls `selftest()` explicitly. The flag is set before the
    // self-test runs, so the nested dispatch below cannot recurse.
    if !SELFTEST_DONE.load(Ordering::Relaxed) {
        selftest();
    }
    (ret, next)
}

/// `write`: validate the user buffer, then mirror the bytes to the serial
/// console and the VGA text buffer through the kernel's existing print path.
///
/// Milestone 1 is text-only: non-UTF-8 payloads are refused with [`EINVAL`]
/// instead of being reinterpreted. Binary fds are a later milestone.
fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    // stdout (1) and stderr (2) are the same console here; fd 0 is an input
    // fd and is refused. The blueprint's errno table has no EBADF, so an
    // invalid descriptor maps to EINVAL.
    if fd != 1 && fd != 2 {
        return EINVAL;
    }
    if len > MAX_WRITE {
        return EINVAL;
    }
    let bytes = match userptr::validated_slice(buf, len as usize) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let text = match core::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return EINVAL,
    };
    serial_print!("{text}");
    len as i64
}

/// `exit`: end the current process. Until the scheduler installs a hook, the
/// only honest behaviour for a bare kernel is a loud, fail-closed halt.
fn sys_exit(code: i64) -> i64 {
    serial_println!("syscall: exit({code}) — no process scheduler yet");
    let hook = EXIT_HOOK.load(Ordering::Relaxed);
    if hook != 0 {
        // SAFETY: the only writer is `set_exit_hook`, a kernel-only function
        // called with a real `extern "C" fn(i64)`; `0` means "not installed".
        // Single-core, hook is installed before any user process runs.
        let terminate: extern "C" fn(i64) =
            unsafe { core::mem::transmute::<u64, extern "C" fn(i64)>(hook) };
        terminate(code);
    }
    crate::halt()
}

/// `yield`: hand the CPU to the next runnable process through the same
/// scheduler entry point used by the tick (`sched::yield_current`). The
/// returned frame is the one the `int 0x80` hook must resume; `dispatch`
/// (used by the current adapter) still returns only the `0` result.
fn sys_yield(frame: *mut Frame) -> *mut Frame {
    super::sched::yield_current(frame)
}

/// `time`: whole milliseconds since boot, from the PIT-driven monotonic
/// clock (same source smoltcp uses, `crate::clock::now_ms`).
fn sys_time() -> i64 {
    crate::clock::now_ms() as i64
}

// --- Internal proof / SYSCALL_OK marker ----------------------------------
static SELFTEST_DONE: AtomicBool = AtomicBool::new(false);

/// Exercise the complete path once and print `SYSCALL_OK`. Safe to call
/// repeatedly; only the first call does work.
///
/// The integrator should call this from the shell immediately **after**
/// `SHELL_OK` (so the smoke's marker order becomes `… SHELL_OK →
/// SYSCALL_OK → KEYBOARD_OK`). A real first `dispatch` also triggers it.
pub fn selftest() {
    if SELFTEST_DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    run_selftest();
}

fn run_selftest() {
    const TEXT: &[u8] = b"syscall selftest\n";
    let ptr = TEXT.as_ptr() as u64;

    // Save the kernel's real user-window state before borrowing it for the
    // proof. Single-core, no user process is running at this point.
    let (old_lo, old_hi) = userptr::bounds();
    let old_vm = userptr::vm();

    // Temporarily register the static test string as a one-VMA "process":
    // this proves the byte-count return through the *real* dispatch and
    // `copy_from_user` validation without needing a mapped user page yet.
    userptr::set_bounds(0, u64::MAX);
    userptr::set_vm(Vm {
        brk_base: ptr,
        brk_end: ptr + TEXT.len() as u64,
        stack_base: 0,
        stack_end: 0,
    });

    let mut good: Frame = new_frame();
    good.rax = NR_WRITE;
    good.rdi = 1; // stdout
    good.rsi = ptr;
    good.rdx = TEXT.len() as u64;
    let got = dispatch(&mut good);

    let mut bad_ptr: Frame = new_frame();
    bad_ptr.rax = NR_WRITE;
    bad_ptr.rdi = 1;
    bad_ptr.rsi = 0xdead_beef; // not in any registered VMA
    bad_ptr.rdx = 4;
    let refused = dispatch(&mut bad_ptr);

    let mut unknown: Frame = new_frame();
    unknown.rax = u64::MAX;
    let missing = dispatch(&mut unknown);

    // Restore before reporting, so a later real process never inherits the
    // self-test's artificial VMA.
    userptr::set_bounds(old_lo, old_hi);
    userptr::set_vm(old_vm);

    if got != TEXT.len() as i64 || good.rax != got as u64 {
        serial_println!("FATAL: syscall: write returned {got}, want {}", TEXT.len());
        crate::halt();
    }
    if refused != EFAULT || bad_ptr.rax != EFAULT as u64 {
        serial_println!("FATAL: syscall: bad user pointer was not refused ({refused})");
        crate::halt();
    }
    if missing != ENOSYS {
        serial_println!("FATAL: syscall: unknown number was not ENOSYS ({missing})");
        crate::halt();
    }
    serial_println!("SYSCALL_OK"); // machine-checked by `cargo xtask smoke`
}

/// An all-zero `Frame` is a valid starting point: `idt::Frame` is a
/// `#[repr(C)]` bundle of integer registers (no references), so zero is a
/// legal bit pattern for every field.
fn new_frame() -> Frame {
    // SAFETY: see above — every field of `Frame` is a u64 and zero is valid.
    unsafe { core::mem::zeroed::<Frame>() }
}
