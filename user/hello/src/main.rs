//! The first userland process: print a line through `Write`, then `Exit`.
//!
//! no_std, no_main, no heap. The C-level prologue lives in `start.S`; the
//! syscall glue in `sys.rs`. The ELF is placed by `user.ld`.
#![no_std]
#![no_main]

mod sys;

// Assembled with the same AT&T option the kernel uses for its .S files.
core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

/// Called by `_start` with the kernel-provided user stack aligned.
#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    const MSG: &[u8] = b"hello from userland\n";
    let _ = sys::write(1, MSG);
    // Hito 2: exercise the real ring-3 `Yield` syscall before exiting. With
    // only this process runnable the scheduler returns the same frame, so
    // the call is a genuine cooperative handoff rather than a no-op stub.
    let _ = sys::yield_now();
    sys::exit(0)
}

/// No unwinding in userland (panic=abort); a panic terminates the process.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(1)
}
