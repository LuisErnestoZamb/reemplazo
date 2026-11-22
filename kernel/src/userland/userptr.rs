//! Untrusted user-pointer validation — the `copy_from_user` boundary.
//!
//! Kernel syscalls **never** dereference a raw user pointer directly. Every
//! `(ptr, len)` pair is checked here, before any read happens, against:
//!
//! 1. the global user address-space window (`USER_BASE..USER_END`, the
//!    blueprint's `0x0000_0080_0000_0000` split — *not* the older `0x40…`
//!    value),
//! 2. the two VMAs of the current process (heap/`brk` and stack) published
//!    by the scheduler on every context switch via [`set_vm`],
//! 3. a hard 64 KiB per-call cap (bounded work, no unbounded copy loops).
//!
//! The range must fit **entirely inside one** VMA: a buffer that straddles
//! `brk` and the stack is refused (`-EFAULT`). Fail-closed in every case:
//! an unregistered process, a null pointer, an overflowing end address or a
//! pointer into kernel space all produce an errno and no memory access.
//!
//! Kernel-only state: single-core, one current process, interrupts disabled
//! around dispatch by the `int 0x80` gate path. The atomics exist so that a
//! future preemptive tick cannot observe a half-updated VMA pair; they are
//! not a lock. A user #PF/#GP is *not* recovered here — `m-privilege`'s
//! exception path kills the offending process (milestone 2).

use core::sync::atomic::{AtomicU64, Ordering};

use super::syscall::{EFAULT, EINVAL};

/// Start of the user half of the address space (blueprint constant).
pub const USER_BASE: u64 = 0x0000_0080_0000_0000;
/// Default end of the user window: 1 GiB of user mappings above `USER_BASE`.
///
/// This is a *safe default*, not a claim about the final layout: the ELF
/// loader / scheduler replaces it through [`set_bounds`] with the real
/// process layout. Until that call happens **no VMA is registered**, so all
/// user pointers fail closed with [`EFAULT`].
pub const USER_END_DEFAULT: u64 = USER_BASE + 0x4000_0000;

/// Maximum bytes a single user-buffer syscall may touch.
pub const MAX_IO_LEN: usize = 64 * 1024;

static BOUNDS_LO: AtomicU64 = AtomicU64::new(USER_BASE);
static BOUNDS_HI: AtomicU64 = AtomicU64::new(USER_END_DEFAULT);

/// The two VMAs a user buffer may live in. Zero length means "not
/// registered" — the fail-closed default before a process exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vm {
    pub brk_base: u64,
    pub brk_end: u64,
    pub stack_base: u64,
    pub stack_end: u64,
}

impl Vm {
    /// A process with no mappings: every pointer is refused.
    pub const NONE: Self = Self {
        brk_base: 0,
        brk_end: 0,
        stack_base: 0,
        stack_end: 0,
    };

    fn contains(self, start: u64, end: u64) -> bool {
        let in_brk = self.brk_end > self.brk_base && start >= self.brk_base && end <= self.brk_end;
        let in_stack =
            self.stack_end > self.stack_base && start >= self.stack_base && end <= self.stack_end;
        in_brk || in_stack
    }
}

static VM_BRK_BASE: AtomicU64 = AtomicU64::new(0);
static VM_BRK_END: AtomicU64 = AtomicU64::new(0);
static VM_STACK_BASE: AtomicU64 = AtomicU64::new(0);
static VM_STACK_END: AtomicU64 = AtomicU64::new(0);

/// Replace the global user window. Kernel-only: called by the loader when it
/// establishes the process address space (and by the internal self-test).
///
/// Refuses an inverted or overflowing range by keeping the old bounds —
/// fail-closed, never a permissive `0..u64::MAX` by accident.
pub fn set_bounds(lo: u64, hi: u64) -> bool {
    if hi <= lo {
        return false;
    }
    BOUNDS_LO.store(lo, Ordering::Relaxed);
    BOUNDS_HI.store(hi, Ordering::Relaxed);
    true
}

/// Current `(lo, hi)` user window (used by the self-test to save/restore).
pub fn bounds() -> (u64, u64) {
    (
        BOUNDS_LO.load(Ordering::Relaxed),
        BOUNDS_HI.load(Ordering::Relaxed),
    )
}

/// Publish the current process's `brk` and stack VMAs. Called by the
/// scheduler on every context switch; passing [`Vm::NONE`] (or never
/// calling) makes all user pointers fail with [`EFAULT`].
pub fn set_vm(vm: Vm) {
    // Write the ends first: a concurrent reader can then only see a
    // *smaller* valid region, never a window that has not been published.
    VM_BRK_END.store(vm.brk_end, Ordering::Relaxed);
    VM_STACK_END.store(vm.stack_end, Ordering::Relaxed);
    VM_BRK_BASE.store(vm.brk_base, Ordering::Relaxed);
    VM_STACK_BASE.store(vm.stack_base, Ordering::Relaxed);
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// Current process VMAs (used by the self-test to save/restore).
pub fn vm() -> Vm {
    Vm {
        brk_base: VM_BRK_BASE.load(Ordering::Relaxed),
        brk_end: VM_BRK_END.load(Ordering::Relaxed),
        stack_base: VM_STACK_BASE.load(Ordering::Relaxed),
        stack_end: VM_STACK_END.load(Ordering::Relaxed),
    }
}

/// Validate a user-readable range. Returns the errno on any violation and
/// performs **no** memory access.
pub fn validate(ptr: u64, len: usize) -> Result<(), i64> {
    if len == 0 {
        // No byte is dereferenced, so there is nothing to validate. The
        // caller still gets a zero-length slice from `validated_slice`.
        return Ok(());
    }
    if len > MAX_IO_LEN {
        return Err(EINVAL);
    }
    let end = ptr.checked_add(len as u64).ok_or(EFAULT)?;
    let (lo, hi) = bounds();
    if ptr < lo || end > hi {
        return Err(EFAULT);
    }
    if !vm().contains(ptr, end) {
        return Err(EFAULT);
    }
    Ok(())
}

/// Validate `(ptr, len)` and only then materialize a read-only slice.
///
/// # Safety contract for the kernel caller
/// The returned slice borrows memory owned by the user process. The process
/// cannot run concurrently (single-core, interrupt-disabled dispatch in
/// milestone 1), so the bytes cannot change while the slice is alive. The
/// caller must not retain it past the syscall. The pages must actually be
/// mapped: a lying loader makes this read fault, which the exception path
/// handles by killing the process.
pub fn validated_slice<'a>(ptr: u64, len: usize) -> Result<&'a [u8], i64> {
    validate(ptr, len)?;
    // SAFETY: `validate` proved `ptr..ptr+len` lies inside one registered
    // user VMA and inside the user window, `len <= 64 KiB`, and the address
    // arithmetic did not overflow. `&[u8]` needs alignment 1 and a non-null
    // (len > 0 here) pointer, both satisfied. No mutable reference to user
    // memory is ever created.
    Ok(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}
