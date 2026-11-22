//! Console shell: a line-edited REPL on **two input sources — COM1
//! serial and the PS/2 keyboard — feeding one line discipline**, with
//! the minimal builtins the OS needs today (AGENTS.md: minimal builtins
//! only — grown on demand, not a BusyBox/GNU clone).
//!
//! Why both sources: serial (`-serial stdio`) works everywhere we run —
//! headless QEMU in the smoke harness and `cargo xtask run` typing —
//! while the keyboard milestone adds QEMU's i8042 path (`crate::keyboard`,
//! polled: the MacBook's built-in keyboard is USB HID and needs the UHCI
//! milestone). Both deliver plain bytes into [`LineDiscipline::feed`],
//! so echo, editing and execution behave identically whichever source
//! a keystroke arrives on.
//!
//! Line discipline: printable ASCII is echoed, backspace edits, CR or
//! LF executes, input is bounded by [`LINE_CAP`] — overflow rings the
//! bell and drops the byte, never truncates-and-executes. The one
//! source-specific rule is the CRLF pairing (see [`Source`]): serial
//! terminals send Enter as CR+LF (or CR alone) and one Enter must
//! execute exactly once, while the keyboard decoder emits exactly one
//! byte per keypress. Commands are whitespace-split with no quoting yet
//! (documented limit). Every builtin fails soft: a typo or an
//! unreachable host prints a line and returns to the prompt; only an
//! explicit `halt` stops the machine.
//!
//! ## Guided installer builtins
//!
//! `disks` lists the detected drives with their wipe-marker state;
//! `install <device> yes` / `netinstall <device> yes` run the guided
//! installer (docs/installer.md §7.1) against a **wipe-marked** disk
//! only — device line first, explicit `yes` second, the marker check
//! always (see [`guided_cmd`]; `crate::install` holds the flow both
//! share with the boot proofs).

use crate::install::{self, Payloads};
use crate::netstack::{LinkState, Stack};
use crate::{ata, keyboard, memory, pit, serial};
use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::Ipv4Address;

/// Bytes accepted per input line; the rest is refused with a bell.
/// A4 raised this from 128 to 512 so one typed line can carry a key up
/// to the config's 512-byte bound (`ai key <token>`); no marker or
/// builtin depends on the old cap.
const LINE_CAP: usize = 512;

const PROMPT: &str = "reemplazo> ";

/// Which wire a byte arrived on. The line discipline is shared, but the
/// CRLF pairing rule belongs to serial only: `skip_lf` must swallow the
/// LF that follows a serial CR, and must never swallow (or be cleared
/// by) an independent keyboard keystroke — otherwise a keyboard Enter
/// typed between a serial CR and its LF would be lost.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Serial,
    Keyboard,
}

/// Shared line-editing state for both input sources.
struct LineDiscipline<'a> {
    line: [u8; LINE_CAP],
    len: usize,
    /// Swallow the LF that follows a CR (terminals send CR, LF, or the
    /// CRLF pair — one Enter must execute exactly once).
    skip_lf: bool,
    /// The installer's captured ISO modules (`grubpayload` + `payload`),
    /// needed by the `install`/`netinstall` builtins. Captured before
    /// the heap existed (`install::capture_modules`) and read-only from
    /// here on.
    payloads: &'a Payloads,
}

impl<'a> LineDiscipline<'a> {
    const fn new(payloads: &'a Payloads) -> Self {
        Self {
            line: [0u8; LINE_CAP],
            len: 0,
            skip_lf: false,
            payloads,
        }
    }

    /// Feed one byte from either source through the line discipline:
    /// echo, edit, or execute. This is the single byte-handling path —
    /// serial and keyboard behave identically apart from the CRLF rule
    /// in [`Source`].
    fn feed(&mut self, byte: u8, src: Source, stack: &mut Stack) {
        let from_serial = src == Source::Serial;
        match byte {
            b'\r' => {
                // The keyboard decoder never emits CR (Enter → '\n'), so
                // this branch is serial's; execute either way.
                if from_serial {
                    self.skip_lf = true;
                }
                self.submit(stack);
            }
            b'\n' => {
                if from_serial && self.skip_lf {
                    self.skip_lf = false; // the LF half of a CRLF pair
                } else {
                    self.submit(stack);
                }
            }
            0x08 | 0x7F => {
                if from_serial {
                    self.skip_lf = false;
                }
                if self.len > 0 {
                    self.len -= 1;
                    // Erase the echoed character: backspace, space, backspace.
                    serial_print!("\x08 \x08");
                }
            }
            byte if byte.is_ascii_graphic() || byte == b' ' => {
                if from_serial {
                    self.skip_lf = false;
                }
                if self.len < LINE_CAP {
                    self.line[self.len] = byte;
                    self.len += 1;
                    serial_print!("{}", char::from(byte));
                } else {
                    serial_print!("\x07"); // bell: refuse, never truncate
                }
            }
            _ => {} // other control bytes (incl. Ctrl-C) are ignored
        }
    }

    /// Run the current line as a command, then re-prompt.
    fn submit(&mut self, stack: &mut Stack) {
        serial_print!("\n");
        execute(
            stack,
            self.payloads,
            core::str::from_utf8(&self.line[..self.len]).unwrap_or(""),
        );
        self.len = 0;
        serial_print!("{PROMPT}");
    }
}

/// Run the shell forever — the kernel's idle state until a scheduler
/// exists. Brings up the polled PS/2 keyboard first (`keyboard::init`
/// fails soft where there is no i8042 — the MacBook), prints
/// `SHELL_OK` (the smoke test's shell marker) and then serves
/// prompts from **both** input sources until `halt`.
///
/// `payloads` are the installer's captured ISO modules: the guided
/// `install`/`netinstall` builtins need GRUB's boot code and the
/// kernel image from them, and the shell is their only consumer after
/// boot (see `install::capture_modules`).
pub fn run(stack: &mut Stack, payloads: &Payloads) -> ! {
    keyboard::init();
    serial_println!("SHELL_OK"); // machine-checked by `cargo xtask smoke`
    // U1: prove the staged user ELF parses and maps into a user page
    // table. Prints ELF_OK only when the module is present, so the
    // diskless/single-purpose smokes keep their original marker chains.
    crate::userland::boot_proof();
    serial_print!("{PROMPT}");

    let mut disc = LineDiscipline::new(payloads);
    loop {
        // Serial first (it is where the console lives), keyboard as the
        // second feeder into the same line discipline.
        let incoming = serial::SerialPort::COM1
            .read_byte()
            .map(|b| (b, Source::Serial))
            .or_else(|| {
                keyboard::next_char()
                    .filter(|c| c.is_ascii())
                    .map(|c| (c as u8, Source::Keyboard))
            });
        let Some((byte, src)) = incoming else {
            idle();
            continue;
        };
        disc.feed(byte, src, stack);
    }
}

/// One trip through the shell's idle state, called when **both** input
/// sources just reported empty.
///
/// The loop above is itself the pre-sleep drain: it reads the UART and
/// the keyboard (PS/2 + the USB pump) until neither has a byte, so by
/// the time we get here the UART's 16-byte FIFO is empty — nothing
/// pending is left behind *before* we sleep. Then:
///
/// - **`hlt` with RFLAGS.IF set** parks the CPU until the next
///   interrupt. The PIT ticks at [`pit::HZ`] (100 Hz), so a sleep lasts
///   at most ~10 ms and the next keystroke/byte is picked up on the
///   wake-up (both sources are polled, never IRQ-driven — IRQ1/IRQ4
///   stay masked, `crate::keyboard`/`crate::serial` module docs).
/// - **IF clear → `spin_loop`, never `hlt`:** with maskable interrupts
///   disabled nothing would ever wake us, so the guard reads RFLAGS
///   first (that is the whole point of the guard).
///
/// Documented FIFO risk (the note AGENTS.md's optional-idle item asks
/// for): a byte arriving *during* the sleep waits for the tick, and 16
/// bytes at 38400 baud is only ~4 ms of line time — shorter than one
/// 10 ms tick. A sender faster than that (a full-rate paste to a real
/// UART with no flow control) can overrun the FIFO while we sleep;
/// QEMU's chardev back-pressures instead of dropping (so `cargo xtask
/// run` loses nothing), and human typing is orders of magnitude slower
/// than 3840 B/s either way. Interrupt-driven RX is the documented
/// serial milestone that removes the window completely.
fn idle() {
    let rflags: u64;
    // SAFETY: `pushfq`/`pop` is the documented way to read RFLAGS; the
    // output register is written by the `pop` alone, and flags are
    // preserved (`preserves_flags`). No `nostack`: `pushfq` pushes.
    unsafe {
        core::arch::asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
    }
    if rflags & 0x200 != 0 {
        // SAFETY: IF is set (checked above), and the IDT/PIC/PIT were
        // armed before the shell ran — an IRQ0 tick resumes right after
        // this instruction (the `test_interrupts` pattern).
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    } else {
        core::hint::spin_loop();
    }
}

/// Split one input line into a command and its argument text and run
/// the builtin. Never panics: unknown commands and bad arguments only
/// print a hint.
pub(crate) fn execute(stack: &mut Stack, payloads: &Payloads, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let (cmd, rest) = match line.split_once(' ') {
        Some((cmd, rest)) => (cmd, rest.trim_start()),
        None => (line, ""),
    };
    match cmd {
        "help" => serial_println!(
            "commands:\n\
             \x20 help              this list\n\
             \x20 echo <text>       print text\n\
             \x20 clear             clear the screen\n\
             \x20 about             what this system is\n\
             \x20 uptime            time since boot\n\
             \x20 meminfo           free physical memory\n\
             \x20 netinfo           DHCP lease + NIC/link state\n\
             \x20 ping <a.b.c.d>    ICMP echo roundtrip\n\
             \x20 resolve <host>    DNS A lookup\n\
             \x20 disks             list disks: id, model, size, wipe-marker state\n\
             \x20 install <dev> yes guided install onto a wipe-marked disk\n\
             \x20 netinstall <dev> yes  same, payload fetched over the network\n\
             \x20 apps              application launcher (top bar)\n\
             \x20 tui               full-screen TUI demo (Esc quits)\n\
             \x20 edit              in-memory text editor (Esc quits)\n\
             \x20 ai <message>      chat: mock, or the configured endpoint over TLS\n\
             \x20 ai stream <msg>   streaming SSE demo against the in-container mock\n\
             \x20 ai apply          insert a chat completion into the editor\n\
             \x20 ai endpoint <url> https endpoint (RAM only)\n\
             \x20 ai model <name>   model name (RAM only)\n\
             \x20 ai key <token>    API key (RAM only, never printed)\n\
             \x20 ai config         show the chat config (key never shown)\n\
             \x20 ssh-auth <hex|path>  ssh publickey auth to github.com (S3)\n\
             \x20 browse <url>      text browser (Tab links, Enter follow, Esc quits)\n\
             \x20 halt              park the CPU"
        ),
        "echo" => serial_println!("{rest}"),
        "clear" => serial_print!("\x1b[2J\x1b[H"),
        "about" => serial_println!(
            "reemplazo — from-scratch Rust OS for the 2007 MacBook2,1 (see README.md)"
        ),
        "uptime" => {
            let ticks = pit::ticks();
            let secs = ticks / pit::HZ;
            let frac = (ticks % pit::HZ) * 100 / pit::HZ;
            serial_println!(
                "uptime: {secs}.{frac:02} s ({ticks} ticks @ {} Hz)",
                pit::HZ
            );
        }
        "meminfo" => {
            let free = memory::free_count();
            serial_println!("meminfo: {free} frames free ({} KiB)", free * 4);
        }
        "netinfo" => {
            match stack.iface.ip_addrs().first() {
                Some(addr) => serial_println!("netinfo: {addr}"),
                None => serial_println!("netinfo: no address configured"),
            }
            match stack.lease {
                Some(lease) => {
                    let dns0 = lease.dns.first().copied();
                    match (lease.router, dns0) {
                        (Some(router), Some(dns)) => serial_println!(
                            "          router {router} dns {dns} ({} server(s))",
                            lease.dns_count
                        ),
                        (Some(router), None) => {
                            serial_println!("          router {router} (no dns servers)")
                        }
                        (None, Some(dns)) => serial_println!(
                            "          no router, dns {dns} ({} server(s))",
                            lease.dns_count
                        ),
                        (None, None) => serial_println!("          no router, no dns servers"),
                    }
                }
                None => serial_println!("          (static addressing, no lease)"),
            }
            // Which NIC is up and (for the sky2) what its PHY says —
            // the on-hardware observability hook for the MacBook boot
            // (kernel/src/sky2.rs module docs).
            let kind = stack.dev.kind();
            match stack.dev.link() {
                LinkState::Up {
                    speed_mbps,
                    full_duplex,
                } => {
                    let dup = if full_duplex { "full" } else { "half" };
                    serial_println!(
                        "          nic {kind}: link up, {speed_mbps} Mbps {dup} duplex"
                    );
                }
                LinkState::Down => serial_println!("          nic {kind}: link down"),
                LinkState::Unknown => serial_println!("          nic {kind}: link not tracked"),
            }
            if let Some(dropped) = stack.dev.rx_dropped()
                && dropped > 0
            {
                serial_println!("          nic {kind}: {dropped} rx frames dropped");
            }
        }
        "ping" => match net::parse_ipv4(rest) {
            Some(octets) => {
                let ip = Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
                stack.ping(ip);
            }
            None => serial_println!("usage: ping <a.b.c.d>"),
        },
        "resolve" => {
            if rest.is_empty() {
                serial_println!("usage: resolve <host>");
            } else {
                match stack.resolve(rest) {
                    Some(ip) => {
                        serial_println!("{rest} -> {ip}")
                    }
                    None => serial_println!("resolve: no answer for {rest}"),
                }
            }
        }
        // Guided installer (docs/installer.md §7.1): a read-only
        // inventory, then the two write paths — same flow, same
        // fail-closed rules (see `guided_cmd`).
        "disks" => list_disks(),
        "install" => guided_cmd(stack, payloads, "install", rest),
        "netinstall" => guided_cmd(stack, payloads, "netinstall", rest),
        "apps" => crate::apps::launcher::run(stack, payloads),
        "tui" => crate::apps::tui::run(),
        "edit" => crate::apps::editor::run(),
        // B4: the interactive browser. Its navigation errors are pages,
        // never `FATAL` (the fail-closed fetch is only the boot proofs').
        "browse" => crate::apps::browse::run(stack, rest),
        // A5: `ai apply` is the editor-integration builtin (quote the
        // retained document → mock exchange → insert at its cursor);
        // anything else after `ai` is a chat message, exactly as before.
        "ai" if rest == "apply" => crate::apps::ai::apply_cmd(stack),
        "ai" => crate::apps::ai::chat_cmd(stack, rest),
        // S3 manual verification path: `ssh-auth <64-hex-seed>` or
        // `ssh-auth /KEY.BIN` on a mounted FAT volume (keyfile.rs
        // parses the argument, fail-soft; ssh.rs runs the same
        // publickey exchange the boot phase uses, without markers).
        "ssh-auth" => {
            // `keyfile` prints why on every refusal (usage, no disk,
            // bad file) — nothing to add here.
            if let Some(seed) = crate::keyfile::seed(rest) {
                crate::ssh::auth_cmd(stack, seed);
            }
        }
        "halt" => {
            serial_println!("halting.");
            crate::halt();
        }
        other => serial_println!("unknown command: {other} (try `help`)"),
    }
}

// ---------------------------------------------------------------------------
// Guided installer builtins (docs/installer.md §7.1): `disks`,
// `install <device> yes`, `netinstall <device> yes`
// ---------------------------------------------------------------------------

/// What a disk's LBA0 says about the installer's two magics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    /// The installer's *source* volume (`reemplazo-disk-v1`) — listed,
    /// read from, never written by these builtins.
    Source,
    /// The wipe marker (`reemplazo-target-v1`) — the only state an
    /// install may write.
    Target,
    /// Neither magic: a disk the installer knows nothing about.
    Unmarked,
    /// LBA0 could not be read — fail-closed, treated like "no".
    Unreadable,
}

impl Marker {
    /// The word `disks` prints for this state.
    fn as_str(self) -> &'static str {
        match self {
            Marker::Source => "source",
            Marker::Target => "target",
            Marker::Unmarked => "unmarked",
            Marker::Unreadable => "unreadable",
        }
    }
}

/// One disk of the inventory: the id the user types (`ide0`/`ide1`/
/// `ahci<port>`), the block device, and what its LBA0 carries.
struct Entry {
    id: String,
    disk: ata::Disk,
    marker: Marker,
}

/// Read-only inventory behind `disks` and the guided builtins: every
/// drive that answers `IDENTIFY` on the legacy primary channel and on
/// each implemented AHCI port, each with its marker state. Nothing here
/// writes to a disk, and nothing here can fail loudly — a drive that
/// does not answer is simply not listed (`ata::list`/`ahci::list` are
/// the bounded probes the boot proofs already run).
fn inventory() -> Vec<Entry> {
    let mut entries = Vec::new();
    for drive in ata::list().into_iter().flatten() {
        let id = alloc::format!("ide{}", drive.unit());
        let disk = ata::Disk::Ide(drive);
        let marker = marker_of(&disk);
        entries.push(Entry { id, disk, marker });
    }
    // The AHCI side needs the bus for the controller's ABAR — a quiet
    // re-scan: the boot already printed the device list once.
    let scan = crate::pci::scan_quiet();
    for disk in crate::ahci::list(&scan) {
        let id = alloc::format!("ahci{}", disk.port());
        let disk = ata::Disk::ahci(disk);
        let marker = marker_of(&disk);
        entries.push(Entry { id, disk, marker });
    }
    entries
}

/// What LBA0 carries — source magic first (a disk can only be one
/// thing), then the wipe marker. A failed read is [`Marker::Unreadable`]:
/// the guided builtins refuse it instead of assuming a state.
fn marker_of(disk: &ata::Disk) -> Marker {
    let mut sector = [0u8; 512];
    if !disk.read_sectors(0, &mut sector) {
        return Marker::Unreadable;
    }
    if ata::has_magic(&sector) {
        Marker::Source
    } else if ata::has_target_magic(&sector) {
        Marker::Target
    } else {
        Marker::Unmarked
    }
}

/// The `disks` builtin: one line per detected disk, or a single line
/// when there is none. Read-only by construction (see [`inventory`]).
fn list_disks() {
    let entries = inventory();
    if entries.is_empty() {
        serial_println!("disks: no disks detected");
        return;
    }
    for entry in &entries {
        print_entry("disks", entry);
    }
}

/// The one canonical device line — id, model, size, marker state —
/// printed for every disk `disks` lists and for the device the guided
/// builtins resolve, **before** anything may be written (AGENTS.md:
/// show the exact device and its size before acting).
fn print_entry(cmd: &str, entry: &Entry) {
    let mut name_buf = [0u8; 40];
    // Model bytes come from the device (untrusted) and `serial_print!`
    // evaluates its arguments twice, so sanitize into the buffer once
    // and pass the `&str` — `ata::Drive::model_name`'s contract.
    let model = entry.disk.model_name(&mut name_buf);
    let sectors = u64::from(entry.disk.sectors());
    serial_println!(
        "{cmd}: {} '{model}' {sectors} sectors ({} MiB) {}",
        entry.id,
        sectors / 2048,
        entry.marker.as_str(),
    );
}

/// Shared front half of `install` / `netinstall`
/// (docs/installer.md §7.1): parse `<device> [yes]`, resolve the
/// device, show its line, and refuse — **before any write** —
/// everything that is not a confirmed, wipe-marked target. Only then
/// does the real install run (`install::guided_install` or
/// `install::netinstall_run`), which shares the boot proofs' GPT →
/// format → copy → read-back → GRUB flow.
///
/// The rules, in order:
///
/// 1. at most two words — the device id and the literal `yes`; no
///    arguments print the usage line,
/// 2. the id must resolve against the read-only inventory,
/// 3. the disk must carry the `reemplazo-target-v1` wipe marker: an
///    unmarked (or unreadable) disk is refused **even with** the
///    confirmation typed out. This is the fail-closed rule that makes
///    a guided installer safe at all — the machine may only ever
///    format a disk someone deliberately marked (AGENTS.md),
/// 4. the confirmation must be the literal `yes`.
///
/// Every refusal above is a line and a fresh prompt (the shell's
/// fail-soft discipline); only a *disk* failure after the writes start
/// is `FATAL:` + halt inside `install_payload`, exactly like the boot
/// proofs — a half-installed target must never look like a success.
fn guided_cmd(stack: &mut Stack, payloads: &Payloads, cmd: &str, rest: &str) {
    let mut words = rest.split_whitespace();
    let Some(id) = words.next() else {
        serial_println!("usage: {cmd} <device> yes   (list devices with `disks`)");
        return;
    };
    let confirm = words.next();
    if words.next().is_some() {
        serial_println!("usage: {cmd} <device> yes   (list devices with `disks`)");
        return;
    }

    let entries = inventory();
    let Some(entry) = entries.iter().find(|e| e.id == id) else {
        serial_println!("{cmd}: unknown device '{id}' (list devices with `disks`)");
        return;
    };
    // Show the exact device and its size first — before any check
    // decides whether it may be written.
    print_entry(cmd, entry);

    // Rule 1 (hard): only a wipe-marked disk may be formatted, with or
    // without the confirmation.
    match entry.marker {
        Marker::Target => {}
        Marker::Unreadable => {
            serial_println!("{cmd}: cannot read LBA0 of {} — refusing", entry.id);
            return;
        }
        Marker::Source => {
            serial_println!(
                "{cmd}: {} holds the installer source volume — refusing to format it",
                entry.id
            );
            return;
        }
        Marker::Unmarked => {
            serial_println!(
                "{cmd}: {} has no wipe marker ({}) — refusing to format an unmarked disk",
                entry.id,
                ata::TARGET_MARKER_TEXT
            );
            return;
        }
    }

    // Rule 2: explicit confirmation, the literal `yes`.
    if confirm != Some("yes") {
        serial_println!(
            "{cmd}: refusing without confirmation — type `{cmd} {} yes`",
            entry.id
        );
        return;
    }

    // The install itself. The offline path copies the source volume's
    // payload files when one is attached (the boot proof's set); with
    // none — the real-hardware case, DVD ISO plus an empty disk — only
    // `/KERNEL.ELF` goes to p2, which is all the boot path needs.
    let source = entries
        .iter()
        .find(|e| e.marker == Marker::Source)
        .map(|e| &e.disk);
    let result = if cmd == "netinstall" {
        install::netinstall_run(stack, &entry.disk, payloads)
    } else {
        install::guided_install(&entry.disk, payloads, source)
    };
    match result {
        Ok(()) => serial_println!(
            "{cmd}: done — {} now holds GPT + FAT16 + GRUB (reboot from it)",
            entry.id
        ),
        Err(e) => serial_println!("{cmd}: {e}"),
    }
}
