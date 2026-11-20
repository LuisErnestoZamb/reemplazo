//! Kernel entry point after the 32→64-bit trampoline in `entry.S`.
//!
//! Flow: init COM1 → validate Multiboot2 magic → parse+report the boot
//! information → arm interrupts (IDT, PIC remap, PIT) → prove exception
//! and timer paths → park the CPU. All user/hardware-provided data is
//! treated as untrusted: bounds-checked by the `bootinfo` crate,
//! `Result`-propagated, no `unwrap`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

#[macro_use]
mod serial;

mod e1000;
mod idt;
mod memory;
mod pci;
mod pic;
mod pit;
mod port;

use bootinfo::{BootInfo, ParseError};
use core::panic::PanicInfo;

core::arch::global_asm!(include_str!("entry.S"), options(att_syntax));

/// Highest `total_size` we'll read from a bootloader-supplied structure.
/// Real Multiboot2 info is a few KiB; 1 MiB is a generous sanity bound
/// that prevents constructing a slice over unrelated memory.
const MBI_MAX_BYTES: usize = 1 << 20;

/// Called from `entry.S` with System V AMD64 args.
///
/// # Safety
/// `mbi_addr` must be the physical address GRUB passed in EBX (boot-time
/// contract from `entry.S`); it is dereferenced only after the range checks
/// below, and the identity map covers the first 4 GiB.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(magic: u32, mbi_addr: u64) -> ! {
    serial::SerialPort::COM1.init();
    serial_println!("reemplazo kernel: long mode, multiboot2 handoff");

    if magic != 0x36d76289 {
        serial_println!("FATAL: bad multiboot2 magic {:#010x}", magic);
        halt();
    }

    match read_mbi(mbi_addr) {
        Ok(info) => {
            report_boot_info(&info);
            memory::init(&info, mbi_addr);
            memory::selftest(&info, mbi_addr);
        }
        Err(e) => {
            serial_println!("FATAL: bad multiboot2 info: {:?}", e);
            halt();
        }
    }

    let scan = crate::pci::scan();
    crate::pci::selftest(&scan);
    if let Some(mut nic) = crate::e1000::init(&scan) {
        nic.selftest();
    }

    arm_and_test_interrupts();

    serial_println!("kernel_main: idle (no scheduler yet)");
    halt()
}

/// Read and validate the Multiboot2 information structure.
///
/// # Safety
/// See [`kernel_main`]: `addr` is the bootloader-provided physical address,
/// identity-mapped, not aliased mutably (single-core boot, interrupts off).
fn read_mbi(addr: u64) -> Result<BootInfo<'static>, ParseError> {
    // The spec places the structure below 4 GiB (EBX is 32-bit);
    // reject anything our identity map or sanity bound wouldn't cover.
    if addr == 0 || addr > 0xFFFF_FFFF {
        return Err(ParseError::TooSmall); // unreachable-by-GRUB: treat as invalid
    }

    // SAFETY: addr < 4 GiB is inside the identity map built in entry.S;
    // reading 4 bytes there cannot fault and no one mutates it concurrently.
    let total = unsafe { core::ptr::read_unaligned((addr as *const u8).cast::<u32>()) } as usize;
    if !(8..=MBI_MAX_BYTES).contains(&total) {
        // Don't build a slice until total_size itself checks out.
        return Err(ParseError::BadTotalSize {
            declared: total as u32,
            available: MBI_MAX_BYTES,
        });
    }

    // SAFETY: total just validated (8..=1 MiB); the identity map covers
    // addr..addr+total (< 4 GiB + 1 MiB... bounded by the check above only
    // if addr <= 4GiB - 1MiB; guard explicitly to keep the slice in-map).
    if addr
        .checked_add(total as u64)
        .is_none_or(|end| end > 0x1_0000_0000)
    {
        return Err(ParseError::TooSmall);
    }
    let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, total) };

    BootInfo::parse(bytes)
}

/// Serial report of what the bootloader told us — the boot milestone's
/// human-readable proof.
fn report_boot_info(info: &BootInfo) {
    match info.bootloader_name() {
        Some(name) => serial_println!("mbi: bootloader '{}'", name),
        None => serial_println!("mbi: bootloader name missing"),
    }
    if let Some((lower, upper)) = info.basic_memory_kb() {
        serial_println!("mbi: memory lower={}K upper={}K", lower, upper);
    }
    match info.memory_map() {
        Some(map) => {
            let mut regions = 0usize;
            let mut available_bytes = 0u64;
            for region in map {
                regions += 1;
                if region.is_available() {
                    available_bytes = available_bytes.saturating_add(region.length);
                }
            }
            serial_println!(
                "mbi: {} mmap regions, {} MiB available RAM",
                regions,
                available_bytes / (1024 * 1024)
            );
        }
        None => serial_println!("mbi: no memory map provided"),
    }
    if let Some(fb) = info.framebuffer() {
        serial_println!(
            "mbi: framebuffer {:#x} {}x{}x{} pitch={} kind={}",
            fb.addr,
            fb.width,
            fb.height,
            fb.bpp,
            fb.pitch,
            fb.kind
        );
    }
    serial_println!("mbi: total_size={} bytes", info.total_size());
    serial_println!("BOOT_OK"); // machine-checked by `cargo xtask smoke`
}

/// Arm interrupts and prove both delivery paths before parking.
fn arm_and_test_interrupts() {
    idt::init(); // build + lidt (needs the GDT64 from entry.S)
    pic::init(); // remap IRQs to 32..=47, mask all but IRQ0
    pit::init(); // PIT channel 0 at HZ
    serial_println!("interrupts: IDT loaded, PIC remapped, PIT {} Hz", pit::HZ);

    // Enable maskable interrupts (IF was off since the trampoline).
    // SAFETY: `sti` is the documented way to enable interrupts after the
    // IDT/PIC are armed; single-core, no races possible yet.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) }

    // Prove the exception path: int3 must hit our handler and return here.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) }
    serial_println!("interrupts: int3 returned to caller");

    // Prove the IRQ path: wait for three timer ticks (hlt sleeps until one).
    let deadline = pit::ticks() + 3;
    while pit::ticks() < deadline {
        // SAFETY: hlt with IF=1 sleeps until the next interrupt; harmless
        // if a tick already raced in (loop re-checks).
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    }
    serial_println!("interrupts: {} PIT ticks received", pit::ticks());
    serial_println!("INT_OK"); // machine-checked by `cargo xtask smoke`
}

/// Park the CPU forever (interrupts off; nothing can wake us).
pub(crate) fn halt() -> ! {
    loop {
        // SAFETY: `hlt` with interrupts disabled is the canonical idle; it
        // cannot violate memory safety.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Re-init is idempotent; the panic may fire before kernel_main did.
    serial::SerialPort::COM1.init();
    serial_println!("PANIC: {}", info);
    halt()
}
