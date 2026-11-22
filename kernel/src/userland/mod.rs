//! Userland boundary: syscall dispatch and untrusted user-pointer handling.
//!
//! The privilege transition itself (GDT6 + TSS, the `int 0x80` DPL3 gate,
//! the vector-128 stub and the IDT wiring) belongs to `m-privilege` and lives
//! in `entry.S` / `interrupts.S` / `idt.rs`. This module is deliberately
//! transport-agnostic: [`syscall::dispatch`] receives the already-saved
//! interrupt [`Frame`](crate::idt::Frame) and returns the syscall result.
//!
//! See `docs/syscall-abi.md` for the stable ABI.

// These are the kernel-side integration surface: `m-privilege` calls
// `syscall::dispatch` from the vector-128 arm and `m-scheduler` calls
// `userptr::set_vm`, but neither is wired in this worktree yet. Keep the
// cross-build clean with `-D warnings` until those merges land; remove this
// allow once both call sites exist.
#![allow(dead_code)]

pub mod elf;
pub mod load;
pub mod module;
pub mod process;
pub mod sched;
pub mod syscall;
pub mod userptr;

/// Boot-time proof that the staged user ELF parses and maps (U1).
pub(crate) fn boot_proof() {
    load::boot_proof()
}

/// Adapter: the IDT's syscall hook is `fn(*mut Frame) -> *mut Frame`,
/// while `syscall::dispatch` returns an `i64` result it also writes into
/// `frame.rax`. The same frame resumes in place (hito 1, cooperative).
fn syscall_hook(frame: *mut crate::idt::Frame) -> *mut crate::idt::Frame {
    // SAFETY: the IDT owns the frame for the duration of the interrupt;
    // the hook is called only from vector 0x80 with a live stack frame.
    unsafe {
        let f = &mut *frame;
        if f.rax == syscall::NR_EXIT {
            let code = f.rdi as i64;
            serial_println!("syscall: exit({code}) -> back to idle");
            serial_println!("USER_RETURN_OK"); // `smoke-user` marker: the
            // user process reached Exit through int 0x80 and the dispatch
            // handed control to the scheduler (hito 1, cooperative).
            return sched::exit_current(frame);
        }
        // Hito 2: Yield/Exit may switch tasks inside the dispatch;
        // resume with the frame the scheduler chose (rax handshake in
        // interrupts.S isr_common).
        syscall::dispatch_resume(f)
    }
}

/// Adapter for the PIT tick hook. `sched::on_tick` latches the
/// reschedule request without switching from IRQ context; `take_resched_frame`
/// consumes it at a safe point in a later milestone.
fn tick_hook(frame: *mut crate::idt::Frame) -> *mut crate::idt::Frame {
    sched::on_tick(frame);
    frame
}

/// A fault in CPL3 kills that process and returns to the scheduler; in
/// CPL0 the IDT keeps its `FATAL:`+halt behaviour (see `idt.rs`).
fn fault_hook(frame: *mut crate::idt::Frame, kind: &str) -> *mut crate::idt::Frame {
    sched::on_user_fault(frame, kind)
}

/// Install the userland boundary hooks. Called once after `arm_interrupts`.
pub(crate) fn install_hooks() {
    sched::init();
    crate::idt::register_syscall_hook(syscall_hook);
    crate::idt::register_sched_hooks(tick_hook, fault_hook);
}
