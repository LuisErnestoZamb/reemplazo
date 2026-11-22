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
