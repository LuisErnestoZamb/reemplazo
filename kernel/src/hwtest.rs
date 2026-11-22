//! Hardware bring-up mode — the real-machine path with no serial port.
//!
//! When the bootloader passes a multiboot2 module with the command
//! line `sshd` (layout: 64 bytes = host-key seed ‖ authorized key,
//! see [`crate::keyfile::module_config`]), the kernel skips the smoke
//! chain and instead:
//!
//! 1. keeps the NIC the generic probe found (`sky2` on the MacBook),
//! 2. assigns a **static** address on the wired LAN (the smoke's
//!    slirp constants do not apply to real hardware),
//! 3. serves sshd, so an operator can reach the machine over the
//!    network — the only observability channel this hardware has,
//! 4. serves **netlog** on :2224: every serial print since the first
//!    line of boot, streamed over TCP (`crate::netlog`) — the
//!    diagnosis channel for everything sshd cannot show.
//!
//! Failures self-heal: no NIC → [`no_nic`] reboots after a grace
//! period; a NIC that comes up but accepts no client for two accept
//! windows → [`run`] reboots as well. The loader's one-shot entry
//! (`grub-reboot`) then returns the machine to its previous system,
//! so an attempt cannot strand it. If even the reboot does not take,
//! the physical power button is the documented last resort.

use crate::keyfile::ServerConfig;
use crate::netstack::Stack;

/// Static address for the bring-up run: same /24 as the development
/// network the machine lives on, on a host number far from the
/// operator's own. DHCP is deliberately not used: the address must be
/// known without reading the screen.
pub const ADDR: [u8; 4] = [192, 168, 1, 79];
/// Default gateway of that network (any responder is fine; sshd needs
/// only the local segment).
pub const GW: [u8; 4] = [192, 168, 1, 1];
/// Prefix length of the bring-up network.
pub const PREFIX: u8 = 24;

/// Grace period before rebooting when the NIC never came up.
const NO_NIC_GRACE_MS: u64 = 90_000;
/// Total time budget for the serve loop before the watchdog reboots.
/// A *time* budget (not a window count): a failed session must leave
/// room for the operator's next attempt — that second connection is
/// where the server replays the previous failure as a banner, the
/// only remote-readable diagnosis channel this machine has.
const SERVE_BUDGET_MS: u64 = 600_000; // 10 minutes

/// Run the bring-up service loop. Never returns: it either keeps
/// serving connections or reboots the machine.
pub fn run(stack: &mut Stack, cfg: &ServerConfig) -> ! {
    serial_println!("hw: bring-up mode (sshd module present)");
    stack.set_static_ipv4_at(ADDR, PREFIX, GW);
    // QEMU's `hostfwd` targets the slirp guest address (10.0.2.15),
    // which is not our LAN address: claim it as a secondary so the
    // in-QEMU repro harness reaches the same sshd. Harmless on the
    // real LAN — nothing routes to it there.
    stack.add_ipv4(net::SLIRP_GUEST_IP, 24);
    // netlog (serial over TCP, :2224): the observability channel this
    // mode exists for — the ring captured from the first print on,
    // served to one client (history first, then the live tail). Only
    // this bring-up path ever arms it; normal boots never listen.
    if stack.netlog_listen(crate::netlog::PORT) {
        serial_println!(
            "hw: netlog on :{} (serial over TCP) — history + live tail",
            crate::netlog::PORT
        );
    } else {
        serial_println!("hw: netlog could not listen on :{}", crate::netlog::PORT);
    }
    serial_println!(
        "hw: sshd on 192.168.1.79:{} (sky2) — waiting for a client",
        crate::sshd::LISTEN_PORT
    );
    let started = crate::clock::now_ms();
    loop {
        if crate::sshd::serve_once(stack, cfg) {
            // A session ran: the machine is useful — restart the
            // clock. The next round re-listens (see serve_once).
            continue;
        }
        let elapsed = crate::clock::now_ms().saturating_sub(started);
        serial_println!("hw: serve round ended ({elapsed} ms of {SERVE_BUDGET_MS} budget)");
        if elapsed >= SERVE_BUDGET_MS {
            serial_println!(
                "hw: no successful session in the budget; rebooting so the loader returns to the previous system"
            );
            crate::power::reboot();
        }
        // Keep serving within the budget: each new connection gets
        // the previous failure replayed as a banner (the remote
        // diagnosis channel), so retries are cheap and visible.
    }
}

/// No NIC at all: wait a grace period (in case the link training is
/// slow), then reboot. `-> !` keeps the caller honest.
pub fn no_nic() -> ! {
    serial_println!(
        "hw: no NIC came up (sky2 silent) — rebooting in {} s",
        NO_NIC_GRACE_MS / 1000
    );
    crate::power::wait_ms(NO_NIC_GRACE_MS);
    crate::power::reboot()
}
