//! Serial-console shell: a line-edited REPL on COM1 with the minimal
//! builtins the OS needs today (AGENTS.md: minimal builtins only —
//! grown on demand, not a BusyBox/GNU clone).
//!
//! Why serial and not a keyboard: `-serial stdio` is the only input
//! path that works everywhere we run — headless QEMU in Docker (the
//! smoke harness) and `cargo xtask run` typing — and the MacBook's
//! keyboard is USB (it needs the USB/HID milestone; QEMU's PS/2
//! keyboard comes with the keyboard milestone). Either future input
//! source can feed this same line discipline.
//!
//! Line discipline: printable ASCII is echoed, backspace edits, CR or
//! LF executes (a CRLF pair executes once), input is bounded by
//! [`LINE_CAP`] — overflow rings the bell and drops the byte, never
//! truncates-and-executes. Commands are whitespace-split with no
//! quoting yet (documented limit). Every builtin fails soft: a typo or
//! an unreachable host prints a line and returns to the prompt; only
//! an explicit `halt` stops the machine.

use crate::dhcp::NetConfig;
use crate::e1000::E1000;
use crate::{dns, memory, pit, serial};

/// Bytes accepted per input line; the rest is refused with a bell.
const LINE_CAP: usize = 128;

const PROMPT: &str = "reemplazo> ";

/// Run the shell forever — the kernel's idle state until a scheduler
/// exists. Prints `SHELL_OK` (the smoke test's thirteenth marker) and
/// then serves prompts until `halt`.
pub fn run(nic: &mut E1000, cfg: &NetConfig) -> ! {
    serial_println!("SHELL_OK"); // machine-checked by `cargo xtask smoke`
    serial_print!("{PROMPT}");

    let mut line = [0u8; LINE_CAP];
    let mut len = 0usize;
    // Swallow the LF that follows a CR (terminals send CR, LF, or the
    // CRLF pair — one Enter must execute exactly once).
    let mut skip_lf = false;
    loop {
        let Some(byte) = serial::SerialPort::COM1.read_byte() else {
            core::hint::spin_loop();
            continue;
        };
        match byte {
            b'\r' => {
                skip_lf = true;
                serial_print!("\n");
                execute(nic, cfg, core::str::from_utf8(&line[..len]).unwrap_or(""));
                len = 0;
                serial_print!("{PROMPT}");
            }
            b'\n' => {
                if skip_lf {
                    skip_lf = false;
                } else {
                    serial_print!("\n");
                    execute(nic, cfg, core::str::from_utf8(&line[..len]).unwrap_or(""));
                    len = 0;
                    serial_print!("{PROMPT}");
                }
            }
            0x08 | 0x7F => {
                skip_lf = false;
                if len > 0 {
                    len -= 1;
                    // Erase the echoed character: backspace, space, backspace.
                    serial_print!("\x08 \x08");
                }
            }
            byte if byte.is_ascii_graphic() || byte == b' ' => {
                skip_lf = false;
                if len < LINE_CAP {
                    line[len] = byte;
                    len += 1;
                    serial_print!("{}", char::from(byte));
                } else {
                    serial_print!("\x07"); // bell: refuse, never truncate
                }
            }
            _ => {} // other control bytes (incl. Ctrl-C) are ignored
        }
    }
}

/// Split one input line into a command and its argument text and run
/// the builtin. Never panics: unknown commands and bad arguments only
/// print a hint.
fn execute(nic: &mut E1000, cfg: &NetConfig, line: &str) {
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
            serial_println!(
                "netinfo: ip {}.{}.{}.{}/{}.{}.{}.{}",
                cfg.ip[0],
                cfg.ip[1],
                cfg.ip[2],
                cfg.ip[3],
                cfg.netmask[0],
                cfg.netmask[1],
                cfg.netmask[2],
                cfg.netmask[3]
            );
            serial_println!(
                "          router {}.{}.{}.{} dns {}.{}.{}.{} lease {}s",
                cfg.router[0],
                cfg.router[1],
                cfg.router[2],
                cfg.router[3],
                cfg.dns[0],
                cfg.dns[1],
                cfg.dns[2],
                cfg.dns[3],
                cfg.lease_secs
            );
        }
        "ping" => match net::parse_ipv4(rest) {
            Some(ip) => {
                nic.ping(cfg, ip);
            }
            None => serial_println!("usage: ping <a.b.c.d>"),
        },
        "resolve" => {
            if rest.is_empty() {
                serial_println!("usage: resolve <host>");
            } else {
                match dns::try_resolve(nic, cfg, rest) {
                    Some(ip) => {
                        serial_println!("{} -> {}.{}.{}.{}", rest, ip[0], ip[1], ip[2], ip[3])
                    }
                    None => serial_println!("resolve: no answer for {rest}"),
                }
            }
        }
        "halt" => {
            serial_println!("halting.");
            crate::halt();
        }
        other => serial_println!("unknown command: {other} (try `help`)"),
    }
}
