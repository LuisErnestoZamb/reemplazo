//! Kernel entry point after the 32→64-bit trampoline in `entry.S`.
//!
//! Flow: init COM1 → validate Multiboot2 magic → parse+report the boot
//! information → carve/init the kernel heap and prove it (`ALLOC_OK`) →
//! arm interrupts (IDT, PIC remap, PIT) → prove exception and timer
//! paths → park the CPU. All user/hardware-provided data is
//! treated as untrusted: bounds-checked by the `bootinfo` crate,
//! `Result`-propagated, no `unwrap`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// The heap exists, so the `alloc` crate's collections are available
// (kernel/src/heap.rs provides the `#[global_allocator]`).
extern crate alloc;

#[macro_use]
mod serial;

mod dhcp;
mod dns;
mod e1000;
mod entropy;
mod heap;
mod idt;
mod memory;
mod pci;
mod pic;
mod pit;
mod port;
mod rtc;
mod shell;
mod tcp;
mod tls;

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
    guard::arm();
    serial_println!("reemplazo kernel: long mode, multiboot2 handoff");
    init_logger();

    if magic != 0x36d76289 {
        serial_println!("FATAL: bad multiboot2 magic {:#010x}", magic);
        halt();
    }

    match read_mbi(mbi_addr) {
        Ok(info) => {
            report_boot_info(&info);
            memory::init(&info, mbi_addr);
            memory::selftest(&info, mbi_addr); // MEM_OK
            heap::init(); // carve a contiguous run, init the global heap
            heap::prove_alloc(); // ALLOC_OK — before the network chain
        }
        Err(e) => {
            serial_println!("FATAL: bad multiboot2 info: {:?}", e);
            halt();
        }
    }

    arm_interrupts();
    report_rtc(); // pure port I/O: no PCI needed, and RTC_OK precedes PCI_OK
    let scan = crate::pci::scan();
    crate::pci::selftest(&scan);

    let mut nic = crate::e1000::init(&scan);
    let mut lease = None;
    if let Some(nic) = nic.as_mut() {
        let peer = nic.selftest();
        nic.ping_test(peer);
        let net = dhcp::configure(nic);
        let github_ip = dns::resolve(nic, &net, "github.com"); // git's host, per AGENTS.md
        tcp::http_smoke(nic, &net, github_ip, "github.com");
        tls::https_smoke(nic, &net, github_ip, "github.com");
        lease = Some(net);
    }

    test_interrupts();

    // The shell is the kernel's idle state until a scheduler exists;
    // without a NIC there is nothing to drive, so just park.
    match (nic.as_mut(), lease) {
        (Some(nic), Some(net)) => shell::run(nic, &net),
        _ => {
            serial_println!("kernel_main: idle (no scheduler yet)");
            halt()
        }
    }
}

/// Route `log` records to the serial console — embedded-tls's handshake
/// diagnostics, most usefully *why* a certificate was refused. Info and
/// above only: the Trace stream (every state transition) stays off.
fn init_logger() {
    struct SerialLogger;

    impl log::Log for SerialLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                serial_println!("[{}] {}", record.level(), record.args());
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: SerialLogger = SerialLogger;
    let _ = log::set_logger(&LOGGER); // only the first call wins
    log::set_max_level(log::LevelFilter::Info);
}

/// The stack-guard gap declared in `entry.S` (between the page tables
/// and the stack), armed with a canary before any deep call chain runs
/// and verified by every `serial_print!`.
///
/// Why it exists: the TLS handshake is the deepest stack user so far,
/// and an overflow used to reach `pd3` — the page table for the e1000
/// MMIO window — corrupting a PDE and triple-faulting the machine
/// (no IDT is armed yet during the network chain, so there is no
/// handler to catch it). The gap turns that silent paging corruption
/// into a loud `FATAL` on the next print, and the 128 KiB stack makes
/// reaching the gap unlikely in the first place.
mod guard {
    use core::sync::atomic::{AtomicBool, Ordering};

    unsafe extern "C" {
        static guard_start: u8;
        static guard_end: u8;
    }

    const CANARY: u8 = 0xA5;
    static ARMED: AtomicBool = AtomicBool::new(false);

    fn range() -> (*const u8, usize) {
        let start = core::ptr::addr_of!(guard_start);
        let len = (core::ptr::addr_of!(guard_end) as usize) - (start as usize);
        (start, len)
    }

    /// Fill the gap with the canary; call once, before deep calls.
    pub fn arm() {
        let (start, len) = range();
        // SAFETY: guard_start..guard_end is one `.skip` region in
        // entry.S's .bss, inside the identity map; single-core boot
        // with interrupts still off, so nothing aliases it.
        unsafe { core::ptr::write_bytes(start.cast_mut(), CANARY, len) };
        ARMED.store(true, Ordering::Relaxed);
    }

    /// Verify the canary. Called from `serial_print!`; the failure path
    /// writes through the UART directly (never through the macro) and
    /// clears ARMED first, so it cannot recurse.
    pub fn check() {
        if !ARMED.load(Ordering::Relaxed) {
            return;
        }
        let (start, len) = range();
        // SAFETY: the same region as `arm`; read-only here.
        let smashed = unsafe { core::slice::from_raw_parts(start, len) }
            .iter()
            .any(|&b| b != CANARY);
        if smashed {
            ARMED.store(false, Ordering::Relaxed);
            let mut port = crate::serial::SerialPort::COM1;
            use core::fmt::Write as _;
            let _ = writeln!(port, "FATAL: stack overflow (guard gap smashed)");
            crate::halt();
        }
    }
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

/// Read the CMOS clock and report it — the smoke test's `RTC_OK`.
///
/// An unavailable clock is loud but not fatal: boot continues, TLS
/// skips certificate dates (documented in `crate::tls`), and the smoke
/// test fails on the missing marker so a broken RTC cannot pass
/// unnoticed.
fn report_rtc() {
    match rtc::now_epoch() {
        Some(epoch) => {
            let t = rtc::from_epoch(epoch);
            serial_println!(
                "rtc: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC (epoch {epoch})",
                t.year,
                t.month,
                t.day,
                t.hour,
                t.minute,
                t.second
            );
            serial_println!("RTC_OK"); // machine-checked by `cargo xtask smoke`
        }
        None => serial_println!("rtc: unavailable — certificate dates will not be checked"),
    }
}

/// Arm interrupts and prove both delivery paths before parking.
/// Arm IDT, PIC and PIT and enable interrupts **before** anything
/// hardware-facing runs: smoltcp's timers (DHCP/DNS/TCP
/// retransmission) read [`crate::pit::ticks`], interrupt-arrival
/// timing perturbs the entropy pool's jitter sources, and any fault
/// from here on prints a loud `EXC:` line instead of triple-faulting
/// into a silent reboot (the IDT used to load only after the network
/// chain). The delivery tests and the `INT_OK` marker stay after the
/// network chain ([`test_interrupts`]) so the smoke's marker order
/// still reflects the boot flow.
fn arm_interrupts() {
    idt::init(); // build + lidt (needs the GDT64 from entry.S)
    pic::init(); // remap IRQs to 32..=47, mask all but IRQ0
    pit::init(); // PIT channel 0 at HZ
    serial_println!("interrupts: IDT loaded, PIC remapped, PIT {} Hz", pit::HZ);

    // Enable maskable interrupts (IF was off since the trampoline).
    // SAFETY: `sti` is the documented way to enable interrupts after the
    // IDT/PIC are armed; single-core, no races possible yet.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) }
}

/// Prove both delivery paths — the smoke's `INT_OK`, kept after the
/// network chain so marker order matches the flow (RTC_OK … HTTP_OK
/// happen with interrupts already armed; see [`arm_interrupts`]).
fn test_interrupts() {
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
