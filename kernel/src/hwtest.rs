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
//!    network — the only observability channel this hardware has.
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
/// Consecutive accept windows with no client before rebooting.
const IDLE_WINDOWS: u32 = 2;

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
    serial_println!(
        "hw: sshd on 192.168.1.79:{} (sky2) — waiting for a client",
        crate::sshd::LISTEN_PORT
    );
    let mut idle = 0u32;
    loop {
        if crate::sshd::serve_once(stack, cfg) {
            idle = 0;
        } else {
            idle += 1;
            serial_println!("hw: idle accept window {idle}/{IDLE_WINDOWS}");
            if idle >= IDLE_WINDOWS {
                serial_println!(
                    "hw: no client; rebooting so the loader returns to the previous system"
                );
                crate::power::reboot();
            }
        }
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
