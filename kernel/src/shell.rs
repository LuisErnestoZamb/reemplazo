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

use crate::netstack::Stack;
use crate::{keyboard, memory, pit, serial};
use smoltcp::wire::Ipv4Address;

/// Bytes accepted per input line; the rest is refused with a bell.
const LINE_CAP: usize = 128;

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
struct LineDiscipline {
    line: [u8; LINE_CAP],
    len: usize,
    /// Swallow the LF that follows a CR (terminals send CR, LF, or the
    /// CRLF pair — one Enter must execute exactly once).
    skip_lf: bool,
}

impl LineDiscipline {
    const fn new() -> Self {
        Self {
            line: [0u8; LINE_CAP],
            len: 0,
            skip_lf: false,
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
            core::str::from_utf8(&self.line[..self.len]).unwrap_or(""),
        );
        self.len = 0;
        serial_print!("{PROMPT}");
    }
}

/// Run the shell forever — the kernel's idle state until a scheduler
/// exists. Brings up the polled PS/2 keyboard first (`keyboard::init`
/// fails soft where there is no i8042 — the MacBook), prints
/// `SHELL_OK` (the smoke test's fifteenth marker) and then serves
/// prompts from **both** input sources until `halt`.
pub fn run(stack: &mut Stack) -> ! {
    keyboard::init();
    serial_println!("SHELL_OK"); // machine-checked by `cargo xtask smoke`
    serial_print!("{PROMPT}");

    let mut disc = LineDiscipline::new();
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
            core::hint::spin_loop();
            continue;
        };
        disc.feed(byte, src, stack);
    }
}

/// Split one input line into a command and its argument text and run
/// the builtin. Never panics: unknown commands and bad arguments only
/// print a hint.
fn execute(stack: &mut Stack, line: &str) {
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
             \x20 netinfo           DHCP lease: ip/mask/router/dns\n\
             \x20 ping <a.b.c.d>    ICMP echo roundtrip\n\
             \x20 resolve <host>    DNS A lookup\n\
             \x20 tui               full-screen TUI demo (Esc quits)\n\
             \x20 edit              in-memory text editor (Esc quits)\n\
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
        "tui" => crate::apps::tui::run(),
        "edit" => crate::apps::editor::run(),
        "halt" => {
            serial_println!("halting.");
            crate::halt();
        }
        other => serial_println!("unknown command: {other} (try `help`)"),
    }
}
