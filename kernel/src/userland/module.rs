//! Capture of the `hello` multiboot2 module (the first user ELF).
//!
//! GRUB's module frames are **not** reserved in the Multiboot2 memory map,
//! so the bytes must be copied out before `memory::init` hands those frames
//! to the allocator (same rule as `install::capture_modules` and the
//! `sshd` config). The 4 MiB buffer is a `.bss` static: no heap exists at
//! capture time, and the consumer's hard cap is derived from the loader,
//! never from the module tag.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use multiboot2::BootInformation;

/// Largest user ELF we will copy out of a boot module.
pub const HELLO_MODULE_CAP: usize = 4 * 1024 * 1024;

/// One capture buffer, written once before any reader runs.
struct ModuleBuffer(UnsafeCell<[u8; HELLO_MODULE_CAP]>);

// SAFETY: the only writer is `capture_hello`, called once on the single
// boot core with interrupts still off; readers run after that call and
// only ever take a shared slice. No concurrent access exists.
unsafe impl Sync for ModuleBuffer {}

static HELLO: ModuleBuffer = ModuleBuffer(UnsafeCell::new([0; HELLO_MODULE_CAP]));
static HELLO_LEN: AtomicUsize = AtomicUsize::new(0);

/// Find the module tagged `hello` on the kernel command line, validate its
/// byte range with [`mbi::check_module`] and copy it into our own storage.
/// Silent when the boot carries no such module (the installed-system and
/// diskless boots keep their marker chains); a malformed *present* module
/// is fatal — fail closed, like every other parser in this kernel.
///
/// Returns the captured length, or `None` when no `hello` module exists.
pub(crate) fn capture_hello(info: &BootInformation) -> Option<usize> {
    for tag in info.module_tags() {
        let Ok(name) = tag.cmdline() else {
            continue;
        };
        if name != "hello" {
            continue;
        }
        let Ok(len) = mbi::check_module(tag.start_address(), tag.end_address(), HELLO_MODULE_CAP)
        else {
            serial_println!("FATAL: mbi: hello module range refused");
            crate::halt();
        };
        // SAFETY: `check_module` proved start != 0, end > start and
        // len <= the destination's length; both module addresses are
        // inside the first 4 GiB (identity-mapped by entry.S); the
        // destination is this module's single-use static, and we are
        // single-core with interrupts off during capture.
        unsafe {
            core::ptr::copy_nonoverlapping(
                tag.start_address() as *const u8,
                (*HELLO.0.get()).as_mut_ptr(),
                len,
            )
        };
        HELLO_LEN.store(len, Ordering::Relaxed);
        return Some(len);
    }
    None
}

/// The captured module bytes, or `None` when this boot has no `hello`.
pub(crate) fn hello_bytes() -> Option<&'static [u8]> {
    let len = HELLO_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return None;
    }
    // SAFETY: the buffer is populated once by `capture_hello` before any
    // caller can observe a non-zero HELLO_LEN (release ordering is not
    // needed: single core, and capture happens before the chain starts).
    Some(unsafe { core::slice::from_raw_parts((*HELLO.0.get()).as_ptr(), len) })
}
