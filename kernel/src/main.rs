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

mod ahci;
mod apps;
mod ata;
mod browser;
mod e1000;
mod entropy;
mod fs;
mod git;
mod git_fetch;
mod git_push;
mod git_store;
mod heap;
mod hwtest;
mod idt;
mod install;
mod keyboard;
mod keyfile;
mod memory;
mod pci;
mod pic;
mod pit;
mod port;
mod power;
mod rtc;
mod shell;
mod sky2;
mod ssh;
mod sshd;
mod tls;
mod usb;
mod userland;
mod vga;

// The network chain runs on smoltcp (docs/smoltcp-eval.md — M2):
// e1000 is the phy::Device, the old per-protocol drivers are gone.
mod clock;
mod netlog;
mod netstack;

use core::panic::PanicInfo;
use multiboot2::{
    BootInformation, BootInformationHeader, FramebufferType, LoadError, MemoryAreaType,
};

core::arch::global_asm!(include_str!("entry.S"), options(att_syntax));

/// Multiboot2 module with the command line `sshd`: the hardware
/// bring-up configuration (64 bytes: host seed ‖ authorized key).
/// Copied out of GRUB's memory before the frame allocator exists —
/// module frames are not reserved in the multiboot2 memory map.
const SSHD_MODULE_CAP: usize = 128;
static mut SSHD_MODULE: [u8; SSHD_MODULE_CAP] = [0; SSHD_MODULE_CAP];

fn capture_sshd_module(info: &BootInformation) -> Option<usize> {
    for tag in info.module_tags() {
        let Ok(name) = tag.cmdline() else {
            continue;
        };
        if name != "sshd" {
            continue;
        }
        let Ok(len) = mbi::check_module(tag.start_address(), tag.end_address(), SSHD_MODULE_CAP)
        else {
            serial_println!("FATAL: mbi: sshd module range refused");
            halt();
        };
        // SAFETY: `check_module` proved start != 0, end > start and
        // len <= the destination's length; both addresses are inside
        // the identity map; the destination is this module's
        // single-use static and interrupts are off here.
        unsafe {
            core::ptr::copy_nonoverlapping(
                tag.start_address() as *const u8,
                core::ptr::addr_of_mut!(SSHD_MODULE) as *mut u8,
                len,
            )
        };
        return Some(len);
    }
    None
}

/// True when GRUB passed a `demo` module: a hardware demo mode that
/// skips the slirp-only network proofs (their mocks live at 10.0.2.2
/// and do not exist on the real LAN) and runs the userland + shell
/// directly. Intended for Option/C / GRUB demos, never for CI.
fn demo_mode(info: &BootInformation) -> bool {
    info.module_tags().any(|tag| tag.cmdline() == Ok("demo"))
}

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

    let (payloads, sshd_len, demo) = match read_mbi(mbi_addr) {
        Ok(info) => {
            report_boot_info(&info);
            sync_vga(&info);
            // I1b: copy the installer's multiboot2 modules (GRUB's
            // boot.img+core.img and the kernel payload) out of GRUB's
            // memory **before** the frame allocator exists — module
            // frames are not reserved in the multiboot2 memory map, so
            // they would otherwise be reused by the heap (see
            // `install::capture_modules`). Silent when a boot carries no
            // modules (the installed system's own boot).
            let payloads = crate::install::capture_modules(&info);
            // Hardware bring-up: an `sshd` module turns this boot into
            // the network-only service mode (see `crate::hwtest`).
            // Copied before the frame allocator for the same reason as
            // the installer payloads.
            let sshd_len = capture_sshd_module(&info);
            let demo = demo_mode(&info);
            // U1: capture the userland ELF module before the frame
            // allocator exists — GRUB module frames are not in the MBI
            // memory map (same reason as the sshd/payload modules).
            crate::userland::module::capture_hello(&info);
            memory::init(&info, mbi_addr);
            memory::selftest(&info, mbi_addr); // MEM_OK
            heap::init(); // carve a contiguous run, init the global heap
            heap::prove_alloc(); // ALLOC_OK — before the network chain
            (payloads, sshd_len, demo)
        }
        Err(e) => {
            serial_println!("FATAL: bad multiboot2 info: {:?}", e);
            halt();
        }
    };

    arm_interrupts();
    // Userland boundary (GDT6/TSS + int 0x80 gate already installed by
    // entry.S/idt.rs): register the syscall and scheduler callbacks.
    crate::userland::install_hooks();
    report_rtc(); // pure port I/O: no PCI needed, and RTC_OK precedes PCI_OK
    let scan = crate::pci::scan();
    crate::pci::selftest(&scan);
    // USB HID keyboard milestone (USB_KBD_OK, between PCI_OK and
    // E1000_OK): probe the UHCI companion(s), enumerate and configure
    // the boot keyboard, prove one live interrupt-IN poll. Prints
    // nothing at all when no UHCI exists (the QEMU default before
    // xtask added `-usb -device usb-kbd` — the marker chain there is
    // untouched); `FATAL: usb:` + halt when one is present but broken.
    crate::usb::init(&scan);
    // Installer milestone BLK_OK: prints only when a drive on the legacy
    // primary channel answers IDENTIFY *and* LBA0 carries the installer
    // magic — the main smoke has no disk, so its marker chain is untouched.
    // FS1's FAT_OK stacks on it: mount the volume and read /README.TXT
    // back, byte for byte. FS2's FS_WRITE_OK then writes /RESULT.TXT,
    // re-mounts from scratch and reads it back (plus a README re-check).
    // No drive → `prove` never runs and nothing at all is printed (the
    // diskless neutrality the main smoke requires).
    // The source disk (FS1/FS2's `disk.img`): probed once per transport,
    // kept for the offline proof *and* the network installer at the end
    // of the boot chain (I2 needs the NIC, which is not up yet here).
    let ide_drive = crate::ata::probe(); // BLK_OK — legacy primary channel
    // AHCI milestone: the same probe on the SATA controller (PCI class
    // 01h/06h/01h). Prints `AHCI_OK` only when an AHCI-attached disk
    // carries the installer magic; silent with no controller (the main
    // smoke) or no marked disk. On the real MacBook this is the *only*
    // disk path, so it also serves as the fallback source below.
    let ahci_drive = crate::ahci::probe(&scan); // AHCI_OK — SATA/AHCI port
    // The block layer both drivers sit behind (`ata::Disk`): IDE first,
    // byte-identical to the pre-AHCI history; AHCI only when the legacy
    // channel found nothing (the smoke-install VM has both, so its
    // FS/GPT/install proofs keep running on the IDE disk as before).
    // S5's key files are read **here**, before the IDE drive is moved
    // into that enum: a disk carrying a host key seed + authorized_keys
    // turns this boot into an sshd, one carrying only a client seed
    // makes it run the two-VM probe client. Both reads are silent when
    // the files are absent — the installer smoke's disk (README only)
    // and the diskless `smoke` are completely neutral. The keys live on
    // the **IDE** volume (`smoke-ssh` attaches no AHCI disk), so this
    // read stays on the IDE driver.
    let mut sshd_config = None;
    let mut probe_seed = None;
    if let Some(drive) = ide_drive.as_ref() {
        sshd_config = crate::keyfile::server_config(drive);
        if sshd_config.is_none() {
            probe_seed = crate::keyfile::client_seed(drive);
        }
    }
    let source_disk = ide_drive
        .map(ata::Disk::Ide)
        .or_else(|| ahci_drive.map(ata::Disk::ahci));
    // The install target is probed **once, here** — before either
    // proof runs: the first install rewrites LBA0 (the protective
    // MBR), which is where the `reemplazo-target-v1` wipe marker
    // lives, so re-probing after `INST_OK` could never find it again.
    // No source → never probed; no marked target → `None`, zero
    // output (the diskless/single-disk neutrality both proofs keep).
    // The target is looked for on the *same* transport as the source:
    // a marked disk on the other controller is not silently picked up.
    let target_disk = match source_disk.as_ref() {
        Some(ata::Disk::Ide(drive)) => crate::ata::probe_target(drive.unit()).map(ata::Disk::Ide),
        Some(ata::Disk::Ahci(disk)) => {
            crate::ahci::probe_target(&scan, Some(disk.port())).map(ata::Disk::ahci)
        }
        None => None,
    };
    if let Some(disk) = source_disk.as_ref() {
        crate::fs::prove(disk); // FAT_OK + FS_WRITE_OK — or `FATAL: fs:` + halt
        // Installer I1 (docs/installer.md §8.3): GPT + format p2 +
        // payload copy + byte-exact re-read → INST_OK. Silent when no
        // *marked* target disk is attached (single-disk and diskless
        // boots print nothing extra); with one, every failure is
        // `FATAL: install:` + halt.
        crate::install::prove(disk, target_disk.as_ref(), &payloads);
    }

    // S5 (docs/git-ssh-deps.md §B.4 row S5): the two key-file reads ran
    // above, before the IDE drive entered the block enum.

    // QEMU's e1000 first (byte-identical history: on a machine with
    // an e1000 the sky2 probe never even runs), then the MacBook's
    // sky2 — `sky2::init` prints nothing when the device is absent.
    let nic = crate::e1000::init(&scan)
        .map(netstack::Nic::e1000)
        .or_else(|| crate::sky2::init(&scan).map(netstack::Nic::sky2));
    let mut stack = nic.map(|dev| {
        // Two draws: smoltcp's random_seed feeds its sPCG32 (TCP ISNs,
        // source ports, DHCP xids) — R1, non-negotiable
        // (docs/smoltcp-eval.md §5).
        let seed = (u64::from(crate::entropy::boot_entropy()) << 32)
            | u64::from(crate::entropy::boot_entropy());
        netstack::Stack::new(dev, seed)
    });

    // Hardware bring-up mode: an `sshd` module means "serve sshd on
    // the real LAN instead of running the smoke chain" — the only
    // observability channel this machine has (no serial port).
    if let Some(len) = sshd_len {
        // SAFETY: `SSHD_MODULE` is written once by
        // `capture_sshd_module` before the allocator exists; single
        // core, interrupts still off during capture, read-only here.
        let raw = unsafe {
            core::slice::from_raw_parts(core::ptr::addr_of!(SSHD_MODULE) as *const u8, len)
        };
        match crate::keyfile::module_config(raw) {
            Some(cfg) => match stack.as_mut() {
                Some(stack) => crate::hwtest::run(stack, &cfg), // never returns
                None => crate::hwtest::no_nic(),                // never returns
            },
            None => {
                serial_println!("FATAL: hw: sshd module is malformed (want 64 bytes)");
                halt();
            }
        }
    }

    if demo {
        // Hardware demo: the slirp mocks (10.0.2.2:8099) do not exist on
        // the real LAN, so skip the network proofs and run the staged
        // userland ELF + the interactive shell directly. Still bring up a
        // static address + netlog so a remote operator can watch the
        // markers over TCP (the MacBook has no serial port).
        if let Some(stack) = stack.as_mut() {
            stack.set_static_ipv4_at(hwtest::ADDR, hwtest::PREFIX, hwtest::GW);
            // No netlog in demo mode: with no boot network chain there is
            // no safe place to pump the stack (extra polls corrupt the
            // mock-backed proofs). Use the VGA/serial on hardware and
            // `cargo xtask demo` for a full serial capture in QEMU.
            let _ = stack;
        }
        serial_println!("hw: demo mode — userland + shell, no network proofs");
        crate::rtc::trace(0xA1); // demo entered
        crate::userland::boot_proof();
        crate::rtc::trace(0xA2); // ELF mapped and user process ran
        match stack.as_mut() {
            Some(stack) => shell::run(stack, &payloads),
            None => halt(),
        }
    }

    if let Some(stack) = stack.as_mut() {
        // Hito 5: expose the live network stack to user processes via
        // the syscall boundary (opaque handles only).
        crate::userland::net::register(stack);
        stack.set_static_ipv4();
        stack.prove_ping(); // NET_OK (ARP sniff) + PING_OK
        stack.wait_lease(); // DHCP_OK — slirp values asserted
        // S5: the server VM serves one client before its own network
        // chain continues (the client VM boots in parallel and dials
        // in). No config → no listener, no line.
        if let Some(cfg) = sshd_config.as_ref() {
            crate::sshd::serve_once(stack, cfg); // SSHD_LISTEN_OK … SSHD_SESSION_OK
        }
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
        let head = git::ls_remote(stack, github_ip); // GIT_LSREMOTE_OK
        // G3: the same repo, a second TLS connection: v0 upload-pack
        // want/deepen=1/done → raw pack → `git-pack` decode + tree
        // walk (GIT_FETCH_OK), then — only with a disk attached — the
        // FAT16 checkout + re-mount read-back (GIT_CHECKOUT_OK).
        git_fetch::fetch(stack, github_ip, head, source_disk.as_ref());
        // G6 push (docs/git-ssh-deps.md §A.4): only with an IDE
        // source disk — the push sends the local commit G5 wrote into
        // `.git` (its trees and blobs, read back from the volume), so
        // without a store there is nothing to push and the diskless
        // `smoke` stays exactly 30 markers. Runs **after** `fetch`
        // returns, so the decoded fetch pack is already dropped (peak
        // heap is the push pack + one object). Prints GIT_PUSH_OK only
        // after the mock's `unpack ok` / `ok refs/heads/main` report;
        // every violation is `FATAL: git: push:` + halt. (`git_push`
        // takes the IDE `Drive` — an AHCI-only source skips the store
        // and the push, the documented S5/G-store limitation.)
        if let Some(drive) = source_disk.as_ref().and_then(ata::Disk::ide) {
            crate::git_push::push(stack, drive); // GIT_PUSH_OK
        }
        ssh::kex_smoke(stack, github_ip); // SSH_KEXINIT_OK + SSH_KEX_OK
        // S5: the client VM's half of the two-VM proof — connect to the
        // peer sshd through slirp → hostfwd, authenticate, exec.
        if let Some(seed) = probe_seed {
            ssh::probe_server(stack, seed); // SSHD_OK + SSHD_EXEC_OK
        }
    }

    test_interrupts();

    // A1 screen layer: render + read back the first full-screen frame
    // (TUI_OK — between INT_OK and SHELL_OK), then hand a clean text
    // screen to the shell. Serial output is untouched.
    apps::tui::boot_proof();

    // A2 editor: scripted insert/newline/delete/undo/redo proof, frame
    // read back from 0xb8000 (EDITOR_OK — between TUI_OK and SHELL_OK),
    // then another clean text screen for the shell.
    apps::editor::boot_proof();

    // A3 AI chat: one plain-HTTP POST exchange against xtask's mock
    // (10.0.2.2:8099 via slirp), JSON parsed with aiwire, the reply
    // rendered in the chat pane and read back from 0xb8000
    // (AI_CHAT_OK — between EDITOR_OK and SHELL_OK), then another
    // clean text screen for the shell. Like the TLS/git/SSH phases it
    // needs the network stack; without one it is skipped (and the
    // smoke, which always has a NIC, fails on the missing marker).
    if let Some(stack) = stack.as_mut() {
        apps::ai::boot_proof(stack);
        // B1 browser fetch (docs/browser.md §7): parse the start URL,
        // plain GET → 301 → resolve `Location` → TLS GET → 200, body
        // bounded, up to 5 redirects — BROWSER_FETCH_OK lands between
        // AI_CHAT_OK and AI_EDIT_OK (the smoke asserts markers in
        // order). Like the TLS/git/SSH/AI phases it needs the network
        // stack; without one this block is skipped and the smoke fails
        // on the missing marker. Its serial lines mirror to the text
        // buffer, so fetch_smoke clears the screen at the end — the
        // shell still starts clean.
        browser::fetch_smoke(stack); // BROWSER_FETCH_OK
    }

    // A5 editor ↔ AI (the "opencode-like" moment): seed the retained
    // editor document, quote its cursor line into one mock exchange
    // (10.0.2.2:8099 via slirp, like A3), apply the sanitized reply at
    // the cursor, prove the undo/redo round-trip and the rendered frame
    // read back from 0xb8000 (AI_EDIT_OK — between BROWSER_FETCH_OK
    // and SHELL_OK), then another clean text screen for the shell. The
    // retained document stays resident with the completion applied,
    // which the shell's `edit` / `ai apply` open afterwards. Like the
    // A3 proof it needs the network stack; without one it is skipped
    // (and the smoke, which always has a NIC, fails on the missing
    // marker).
    if let Some(stack) = stack.as_mut() {
        apps::editor::ai_edit_boot_proof(stack);
        // B2 browser render (docs/browser.md §4/§6): fetch a small
        // real page with B1's parameterized fetch, build the `dom`
        // tree over our tokenizer, lay it out for the text viewport,
        // render it through A1's screen layer and read the frame back
        // from 0xb8000 — BROWSER_RENDER_OK lands between AI_EDIT_OK
        // and SHELL_OK (the smoke asserts markers in order). Like the
        // other network phases it needs the stack; without one it is
        // skipped (and the smoke, which always has a NIC, fails on
        // the missing marker). Its proofs clear the screen at the
        // end, so the shell still starts clean.
        browser::render_smoke(stack); // BROWSER_RENDER_OK
        // B3 CSS subset (docs/browser.md §5): the kernel-owned styled
        // fixture rendered with and without its sheet, VGA attribute
        // bytes read back from 0xb8000, plus the real page's own sheet
        // applied as a robustness pass — BROWSER_CSS_OK lands between
        // BROWSER_RENDER_OK and SHELL_OK (the smoke asserts markers in
        // order). It reuses the body sample render_smoke retained, so
        // it costs no network and can sit inside the same `Some(stack)`
        // branch; the screen is cleared after the proof.
        browser::css_smoke(); // BROWSER_CSS_OK
        // B4 navigation (docs/browser.md §8 row B4): the interactive
        // browser's own state driven through the keyboard path — two
        // kernel-owned fixture pages (no network) rendered/followed/back/
        // forward with the history depths asserted, then an unreachable
        // endpoint that must render the error page within the bounded
        // connect deadline (BROWSER_NAV_OK lands between BROWSER_CSS_OK
        // and SHELL_OK). It needs the stack only for that last,
        // deliberately-failing connect; the fixtures are offline. The
        // proof clears the screen afterwards, so the shell starts clean.
        apps::browse::boot_proof(stack); // BROWSER_NAV_OK
    }

    // I2 network installer (docs/installer.md §8.4): fetch
    // `payload.tar` over our own stack (smoltcp + `net::http`, the
    // in-container responder on 10.0.2.2:8080), walk the ustar
    // headers, install onto the marked target, read back byte-exact →
    // NETINST_OK. Gated on the target found above (probed only when
    // the source disk exists) — silently skipped otherwise, so the
    // diskless main smoke's marker chain stays untouched.
    if let (Some(stack), Some(target)) = (stack.as_mut(), target_disk.as_ref()) {
        crate::install::netprove(stack, Some(target), &payloads);
    }

    // The shell is the kernel's idle state until a scheduler exists;
    // without a NIC there is nothing to drive, so just park. The
    // installer's captured ISO modules go along: the guided
    // `install`/`netinstall` builtins write GRUB + the kernel from them.
    match stack.as_mut() {
        Some(stack) => shell::run(stack, &payloads),
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
    // Audit H2: `check_addr` only bounds the address itself; the first
    // read below covers `addr..addr+4`, so require the full 4 bytes to
    // stay inside the identity map (addr == 0xFFFF_FFFF would reach
    // 0x1_0000_0002 — PML4[1] is absent → #PF before `check_range`).
    if addr > 0xFFFF_FFFF - 4 {
        return Err(MbiError::Range(mbi::RangeError::CrossesMap {
            addr,
            total: 4,
        }));
    }
    mbi::check_addr(addr).map_err(MbiError::Range)?;

    // SAFETY: the guards above proved `addr..addr+4` lies inside the
    // identity map built in entry.S (≤ 0xFFFF_FFFF); no one mutates it
    // concurrently (single-core boot, interrupts off).
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
