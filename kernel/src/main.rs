//! Kernel skeleton — no_std / no_main entry point.
//! Boot protocol (Multiboot2 header + 32→64-bit trampoline) lands in the
//! boot milestone; this only proves the workspace cross-compiles.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
