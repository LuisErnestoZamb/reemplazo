//! Kernel entry point after the 32→64-bit trampoline in `entry.S`.
//!
//! Flow: init COM1 → validate Multiboot2 magic → range-check + load the
//! boot information → carve/init the kernel heap and prove it (`ALLOC_OK`) →
//! arm interrupts (IDT, PIC remap, PIT) → prove exception and timer
//! paths → park the CPU. All user/hardware-provided data is
//! treated as untrusted: range-checked against the identity map
//! (the `mbi` crate), parsed by the `multiboot2` crate,
//! `Result`-propagated, no `unwrap`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// The heap exists, so the `alloc` crate's collections are available
// (kernel/src/heap.rs provides the `#[global_allocator]`).
extern crate alloc;

#[macro_use]
mod serial;

mod e1000;
mod entropy;
mod heap;
mod idt;
mod keyboard;
mod memory;
mod pci;
mod pic;
mod pit;
mod port;
mod rtc;
mod shell;
mod tls;
mod vga;

// The network chain runs on smoltcp (docs/smoltcp-eval.md — M2):
// e1000 is the phy::Device, the old per-protocol drivers are gone.
mod clock;
mod netstack;

use core::panic::PanicInfo;
use multiboot2::{
    BootInformation, BootInformationHeader, FramebufferType, LoadError, MemoryAreaType,
};

core::arch::global_asm!(include_str!("entry.S"), options(att_syntax));

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
    // GRUB i386-pc leaves text mode at 0xb8000 (80×25, pitch 160):
    // mirror every console line there from the very first print — the
    // MacBook exposes no serial port. The multiboot tag re-checks this
    // (`vga::sync`) as soon as the boot information is parsed.
    vga::init(0xB8000, 80, 25, 160);
    serial_println!("reemplazo kernel: long mode, multiboot2 handoff");
    init_logger();

    if magic != 0x36d76289 {
        serial_println!("FATAL: bad multiboot2 magic {:#010x}", magic);
        halt();
    }

    match read_mbi(mbi_addr) {
        Ok(info) => {
            report_boot_info(&info);
            sync_vga(&info);
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

    let mut stack = crate::e1000::init(&scan).map(|dev| {
        // Two draws: smoltcp's random_seed feeds its sPCG32 (TCP ISNs,
        // source ports, DHCP xids) — R1, non-negotiable
        // (docs/smoltcp-eval.md §5).
        let seed = (u64::from(crate::entropy::boot_entropy()) << 32)
            | u64::from(crate::entropy::boot_entropy());
        netstack::Stack::new(dev, seed)
    });

    if let Some(stack) = stack.as_mut() {
        stack.set_static_ipv4();
        stack.prove_ping(); // NET_OK (ARP sniff) + PING_OK
        stack.wait_lease(); // DHCP_OK — slirp values asserted
        // git's host, per AGENTS.md.
        let Some(github_ip) = stack.resolve("github.com") else {
            serial_println!(
                "FATAL: dns: no answer for github.com (internet up? server reachable?)"
            );
            halt();
        };
        serial_println!("DNS_OK"); // machine-checked by `cargo xtask smoke`
        stack.plain_get_smoke(github_ip, "github.com"); // TCP_OK
        tls::https_smoke(stack, github_ip, "github.com"); // TLS_OK + HTTP_OK
    }

    test_interrupts();

    // The shell is the kernel's idle state until a scheduler exists;
    // without a NIC there is nothing to drive, so just park.
    match stack.as_mut() {
        Some(stack) => shell::run(stack),
        None => {
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

/// Why [`read_mbi`] refused the bootloader's handoff — printed with `{:?}`
/// on the `FATAL: bad multiboot2 info` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MbiError {
    /// Our range pre-check rejected the address/size (GRUB data is
    /// untrusted; see [`mbi::RangeError`]).
    Range(mbi::RangeError),
    /// The `multiboot2` crate rejected the structure itself (null,
    /// alignment, malformed tag walk, missing end tag).
    Load(LoadError),
}

/// Reconcile the early VGA mirror with the bootloader's real framebuffer
/// tag and prove the pipeline: the boot banner must be readable back in
/// the text buffer — the smoke's `VGA_OK`.
fn sync_vga(info: &BootInformation) {
    let text = match info.framebuffer_tag() {
        Some(Ok(fb)) => {
            let text = matches!(fb.buffer_type(), Ok(FramebufferType::Text));
            vga::sync(
                fb.address() as usize,
                fb.width() as usize,
                fb.height() as usize,
                fb.pitch() as usize,
                text,
            );
            text
        }
        // A tag we cannot parse: refuse to write (fail-safe).
        Some(Err(_)) => {
            vga::disable();
            false
        }
        // No tag at all: keep the documented GRUB text-mode defaults
        // and verify them below.
        None => true,
    };
    if !text {
        return; // no text console to prove — never on our chain
    }
    if !vga::verify("reemplazo kernel: long mode") {
        serial_println!("FATAL: vga: text buffer does not hold the boot banner");
        halt();
    }
    serial_println!("VGA_OK"); // machine-checked by `cargo xtask smoke`
}

/// Read and validate the Multiboot2 information structure.
///
/// # Safety
/// See [`kernel_main`]: `addr` is the bootloader-provided physical address,
/// identity-mapped, not aliased mutably (single-core boot, interrupts off).
fn read_mbi(addr: u64) -> Result<BootInformation<'static>, MbiError> {
    // The spec places the structure below 4 GiB (EBX is 32-bit); reject
    // anything the identity map or sanity bound wouldn't cover. Runs
    // *before* the first read at `addr` — untrusted pointer first.
    mbi::check_addr(addr).map_err(MbiError::Range)?;

    // SAFETY: `check_addr` proved addr ∈ (0, 4 GiB], inside the identity
    // map built in entry.S; reading 4 bytes there cannot fault and no one
    // mutates it concurrently.
    let total = unsafe { core::ptr::read_unaligned((addr as *const u8).cast::<u32>()) } as usize;

    // `total_size` sanity (8..= mbi::MBI_MAX_BYTES) plus the whole
    // structure inside the map — again before any pointer over it is
    // built (this is the SAFETY contract below, in two steps because the
    // 4-byte read needs the address check first).
    mbi::check_range(addr, total).map_err(MbiError::Range)?;

    // SAFETY — the contract with the crate's pointer API: `load` takes a
    // pointer, not a slice, so it cannot know the real buffer length and
    // trusts us that `addr..addr+total` is valid readable memory. The
    // range pre-checks above are exactly that: `total` ≤
    // `mbi::MBI_MAX_BYTES`, `addr+total` ≤ 4 GiB, identity-mapped,
    // single-core, no concurrent mutation. The crate re-reads
    // `total_size` and validates the tag walk within it.
    // Documented trade-off vs the old slice-based parser: a corrupt
    // `total_size` that is still ≤ 1 MiB and holds a valid tag sequence
    // is now *accepted* where `total > buffer len` used to be rejected —
    // reads stay inside the pre-validated in-map range (no safety issue);
    // `total_size()` may then over-reserve ≤ 1 MiB of frames (bounded,
    // acceptable). That case has no pointer-API test equivalent (the
    // crate cannot know the buffer length): it lives on as this contract
    // comment plus `mbi::check_range`'s unit tests.
    unsafe { BootInformation::load(addr as *const BootInformationHeader) }.map_err(MbiError::Load)
}

/// Serial report of what the bootloader told us — the boot milestone's
/// human-readable proof (line formats kept human-equivalent to the old
/// `bootinfo` report; the smoke asserts the flow, not the text).
fn report_boot_info(info: &BootInformation) {
    match info.boot_loader_name_tag().and_then(|t| t.name().ok()) {
        Some(name) => serial_println!("mbi: bootloader '{}'", name),
        None => serial_println!("mbi: bootloader name missing"),
    }
    if let Some(mem) = info.basic_memory_info_tag() {
        serial_println!(
            "mbi: memory lower={}K upper={}K",
            mem.memory_lower(),
            mem.memory_upper()
        );
    }
    match info.memory_map_tag() {
        Some(map) => {
            let mut regions = 0usize;
            let mut available_bytes = 0u64;
            for area in map.memory_areas() {
                regions += 1;
                if area.typ() == MemoryAreaType::Available {
                    available_bytes = available_bytes.saturating_add(area.size());
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
    // Kind as the old raw byte carried it: 0 indexed, 1 direct RGB,
    // 2 EGA text (§3.6.12). `framebuffer_tag()` only yields `Ok` for
    // known types, so the `Err` arm below is unreachable — printed via
    // `{:?}` rather than inventing a number the crate no longer exposes.
    match info.framebuffer_tag() {
        Some(Ok(fb)) => match fb.buffer_type() {
            Ok(kind) => {
                let kind = match kind {
                    FramebufferType::Indexed { .. } => 0,
                    FramebufferType::RGB { .. } => 1,
                    FramebufferType::Text => 2,
                };
                serial_println!(
                    "mbi: framebuffer {:#x} {}x{}x{} pitch={} kind={}",
                    fb.address(),
                    fb.width(),
                    fb.height(),
                    fb.bpp(),
                    fb.pitch(),
                    kind
                );
            }
            Err(e) => serial_println!(
                "mbi: framebuffer {:#x} {}x{}x{} pitch={} kind={:?}",
                fb.address(),
                fb.width(),
                fb.height(),
                fb.bpp(),
                fb.pitch(),
                e
            ),
        },
        Some(Err(e)) => serial_println!("mbi: framebuffer unknown type ({e:?})"),
        None => {}
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
