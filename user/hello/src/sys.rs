//! Minimal ring-3 syscall layer for the hello process.
//!
//! ABI (owned by `m-syscalls`; mirrored here until its `userlib` lands):
//!   rax = syscall number — 0 Write(fd, buf, len), 1 Exit(code),
//!                          2 Yield, 3 Time
//!   arguments follow SysV: rdi, rsi, rdx; return value comes back in rax
//! The entry point is the DPL=3 `int $0x80` IDT gate installed by
//! `m-privilege`, not `syscall`/`sysret`.
#![allow(dead_code)] // ABI-complete on purpose; hello uses only Write/Exit.

pub const SYS_WRITE: usize = 0;
pub const SYS_EXIT: usize = 1;
pub const SYS_YIELD: usize = 2;
pub const SYS_TIME: usize = 3;

/// `Write(fd, buf)` → the kernel's rax response.
#[inline(always)]
pub fn write(fd: usize, buf: &[u8]) -> isize {
    let ret: isize;
    // SAFETY: `int 0x80` enters the kernel through its DPL3 gate. `buf`
    // is a live, readable slice of `buf.len()` bytes for the whole call
    // and the kernel consumes it synchronously. rax is the only output
    // register (the gate restores the rest); `nostack` is correct because
    // the CPU switches to the kernel stack on entry and this asm never
    // touches the user stack.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") SYS_WRITE => ret,
            in("rdi") fd,
            in("rsi") buf.as_ptr(),
            in("rdx") buf.len(),
            options(nostack),
        );
    }
    ret
}

/// `Exit(code)` — terminates the process; never returns.
#[inline(always)]
pub fn exit(code: i32) -> ! {
    // SAFETY: Exit never returns to user mode, so no registers need to be
    // recovered and `noreturn` is truthful. The code is passed in rdi per
    // the SysV argument convention the ABI mandates.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("rax") SYS_EXIT,
            in("rdi") code as usize,
            options(noreturn, nostack),
        );
    }
}
