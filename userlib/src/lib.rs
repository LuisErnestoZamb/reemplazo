//! Minimal `no_std` user-space syscall library — no libc, no dependencies
//! beyond `core`.
//!
//! Every call is a single `int 0x80` against the kernel's DPL3 IDT gate
//! (vector 128). SysV argument registers `rdi, rsi, rdx, r10, r8, r9` carry
//! up to six arguments; `rax` carries the number in and the i64 result out.
//! A negative result is an errno (see the `E*` constants).
//!
//! The kernel-side ABI and its pointer-validation rules live in
//! `docs/syscall-abi.md`. `user/hello/src/sys.rs` may inline the same raw
//! wrapper instead of depending on this crate — the numbers and errnos
//! below are the shared source of truth.

#![no_std]
// `forbid` cannot be scoped down, so we `deny` crate-wide and `allow` only
// inside `arch`, which holds the one `unsafe` asm wrapper (each use has a
// `// SAFETY:` comment). No other unsafe code exists in this crate.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

// --- Stable syscall numbers (mirror kernel/src/userland/syscall.rs) ------
pub const NR_WRITE: u64 = 0;
pub const NR_EXIT: u64 = 1;
pub const NR_YIELD: u64 = 2;
pub const NR_TIME: u64 = 3;

// --- Errnos (mirror kernel/src/userland/syscall.rs) ----------------------
pub const EINVAL: i64 = -1;
pub const EFAULT: i64 = -2;
pub const EPERM: i64 = -13;
pub const ENOSYS: i64 = -38;

/// Write `s` to stdout (fd 1). Returns the byte count, or a negative errno.
#[inline]
pub fn write_str(s: &str) -> i64 {
    write(1, s.as_bytes())
}

/// Write `bytes` to `fd` (1 = stdout, 2 = stderr). Returns the byte count,
/// or a negative errno. The kernel refuses non-UTF-8 payloads today.
#[inline]
pub fn write(fd: u64, bytes: &[u8]) -> i64 {
    arch::syscall3(NR_WRITE, fd, bytes.as_ptr() as u64, bytes.len() as u64)
}

/// Terminate the current process. The kernel hook never returns; if no
/// scheduler is installed, the kernel prints and halts.
#[inline]
pub fn exit(code: i32) -> ! {
    let _ = arch::syscall1(NR_EXIT, code as u64);
    // Defensive: a buggy kernel must not hand control back into user code
    // after an `exit`. Spin (never `hlt` — IF may be clear in user mode).
    loop {
        core::hint::spin_loop();
    }
}

/// Cooperative yield (milestone 1: returns 0 immediately).
///
/// `yield` is a Rust keyword, so the canonical name is the raw identifier
/// `r#yield`; `yield_now` is a convenience alias.
#[inline]
pub fn r#yield() -> i64 {
    arch::syscall0(NR_YIELD)
}

/// Alias for [`r#yield`].
#[inline]
pub fn yield_now() -> i64 {
    r#yield()
}

/// Milliseconds since boot, or a negative errno.
#[inline]
pub fn time() -> i64 {
    arch::syscall0(NR_TIME)
}

/// The one piece of unsafe in this crate: the raw `int 0x80` wrappers.
mod arch {
    #![allow(unsafe_code)]

    /// Invoke a syscall with no arguments.
    #[inline(always)]
    pub fn syscall0(nr: u64) -> i64 {
        // SAFETY: `int 0x80` is the ABI's entry gate; no memory is passed.
        unsafe { raw(nr, 0, 0, 0, 0, 0, 0) }
    }

    /// Invoke a syscall with one argument.
    #[inline(always)]
    pub fn syscall1(nr: u64, a1: u64) -> i64 {
        // SAFETY: a1 is an integer/small scalar; it is the caller's job to
        // pass valid values for the chosen syscall number.
        unsafe { raw(nr, a1, 0, 0, 0, 0, 0) }
    }

    /// Invoke a syscall with three arguments (write's ABI).
    #[inline(always)]
    pub fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        // SAFETY: a2/a3 are a user buffer pointer and length; the kernel
        // validates them with copy_from_user before any dereference. The
        // slice borrow in `write` keeps the buffer alive for the call.
        unsafe { raw(nr, a1, a2, a3, 0, 0, 0) }
    }

    /// Raw gate. `rax` = number in / i64 result out; args in SysV registers.
    ///
    /// # Safety
    /// The caller must use a valid syscall number and arguments; the kernel
    /// validates every user pointer and never trusts the buffer contents.
    #[inline(always)]
    unsafe fn raw(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
        let ret: i64;
        // SAFETY: `int 0x80` transfers control to the kernel's DPL3 gate;
        // `rax`/`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` are the documented ABI
        // registers. No `nomem`: the kernel may read the pointed-to user
        // buffer. `nostack`: the instruction itself does not touch our stack
        // (the CPU switches to the kernel stack for the CPL3→0 transition).
        unsafe {
            core::arch::asm!(
                "int 0x80",
                inlateout("rax") nr as i64 => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                in("r8") a5,
                in("r9") a6,
                options(nostack),
            );
        }
        ret
    }
}
