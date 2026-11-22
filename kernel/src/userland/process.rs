//! Process control blocks for the userland milestone.
//!
//! Fixed capacity, static-backed, **no heap**: the array lives in
//! `sched.rs` and is only ever mutated inside its IF=0 critical section.
//! This module deliberately contains no global state and no `unsafe` — it
//! only defines the record type and its constructors, so m-privilege's
//! frame/TSS work and the scheduler's queue work stay independent.
//!
//! The field set follows the architect's blueprint (PID, state, CR3,
//! frames to free, kernel stack, saved context, brk, fds, console
//! ownership). Two extra fields are required by the scheduler itself:
//! `quantum_left` (RR accounting) and `user_stack_top` (the stack a fresh
//! CPL3 frame is synthesized with). Neither changes the ABI — no PCB is
//! ever read by assembly.

// Several fields become live only in milestone 2 (ELF loader, syscalls,
// preemption). Keep them documented in place instead of hiding them behind
// `cfg` so the blueprint's shape stays visible.
#![allow(dead_code)]

use core::ffi::c_void;

/// Hard cap on concurrent processes. Eight 4 KiB kernel stacks = 32 KiB of
/// static RAM — deliberate on a 2.9 GB DDR2 target with a 5400 rpm disk.
pub const MAX_PROCS: usize = 8;

/// Per-process kernel stack, used as `TSS.RSP0` on switch-in. 16-byte
/// aligned by `sched::KernelStack`.
pub const KERNEL_STACK_SIZE: usize = 4096;

/// Open-file table size (reserved for the syscall milestone).
pub const MAX_FDS: usize = 16;

/// Physical frames recorded for release on `exit` (reserved for the ELF
/// loader / mm milestone).
pub const MAX_FREE_FRAMES: usize = 16;

/// PCB lifecycle.
///
/// `Unused` is a free slot (never queued); `Blocked` is skipped by the RR
/// picker without removing the entry from the queue. `Exited` is a
/// tombstone — slots are currently not recycled, which keeps the pid→slot
/// identity trivial and the queue provably bounded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Unused,
    Ready,
    Running,
    Blocked,
    Exited,
}

/// One process. Never crosses an assembly boundary, so no `repr(C)` is
/// needed; `saved_context` is opaque to us (its layout belongs to
/// m-privilege's `idt::Frame`).
#[derive(Clone, Copy)]
pub struct Process {
    /// Slot index and queue key. PID0 is the kernel's ring-0 idle context
    /// (today's shell), which the tick must never switch away from.
    pub pid: u32,
    pub state: State,

    /// CR3 to load on switch-in. For PID0 this is the boot page table
    /// captured in `sched::init`; user processes carry their own.
    pub cr3_phys: u64,

    /// Physical frame numbers to free on exit; `frame_count` is the used
    /// prefix. Bounded so a hostile ELF cannot grow it past the PCB.
    pub frames: [u64; MAX_FREE_FRAMES],
    pub frame_count: usize,

    /// `TSS.RSP0` written by `sched::schedule` on switch-in.
    pub kernel_stack_top: u64,

    /// Opaque pointer to the interrupt frame to restore on switch-in.
    /// Stored/returned without inspection in milestone 1 — that is what
    /// keeps us independent of m-privilege's evolving `Frame` layout.
    pub saved_context: *mut c_void,

    /// ELF `e_entry` (0 for PID0).
    pub user_entry: u64,
    /// Top of the initial user stack, used when synthesizing the first
    /// CPL3 `iretq` frame.
    pub user_stack_top: u64,
    /// Program break (reserved for the `brk` syscall).
    pub brk_end: u64,

    /// Negative means free. Filled in by the syscall milestone.
    pub fds: [i32; MAX_FDS],
    /// True while this process owns the VGA/serial console.
    pub owns_console: bool,

    /// PIT ticks left before RR preemption (milestone 2 only).
    pub quantum_left: u32,
}

impl Process {
    /// Const zero-value for the static table. `-1` marks every fd free
    /// (0 would silently alias stdin).
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            state: State::Unused,
            cr3_phys: 0,
            frames: [0; MAX_FREE_FRAMES],
            frame_count: 0,
            kernel_stack_top: 0,
            saved_context: core::ptr::null_mut(),
            user_entry: 0,
            user_stack_top: 0,
            brk_end: 0,
            fds: [-1; MAX_FDS],
            owns_console: false,
            quantum_left: 0,
        }
    }

    /// Allocate a slot as `Ready`. The scheduler owns the frame and the
    /// kernel stack; callers only supply the address of the synthesized
    /// frame via `sched::install_frame`.
    pub const fn new(
        pid: u32,
        cr3_phys: u64,
        kernel_stack_top: u64,
        user_entry: u64,
        user_stack_top: u64,
    ) -> Self {
        Self {
            pid,
            state: State::Ready,
            cr3_phys,
            frames: [0; MAX_FREE_FRAMES],
            frame_count: 0,
            kernel_stack_top,
            saved_context: core::ptr::null_mut(),
            user_entry,
            user_stack_top,
            brk_end: 0,
            fds: [-1; MAX_FDS],
            owns_console: false,
            quantum_left: 0,
        }
    }

    /// True if this slot holds a live process (anything but `Unused`).
    pub const fn is_allocated(&self) -> bool {
        !matches!(self.state, State::Unused)
    }
}
