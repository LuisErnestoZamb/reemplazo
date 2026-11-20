//! DHCPv4 client (DISCOVER → OFFER → REQUEST → ACK) against QEMU's
//! slirp. Message layouts and option parsing live in the host-tested
//! `net::dhcp` module; this file only drives the NIC and validates the
//! lease.

use crate::e1000::{E1000, RX_POLLS};
use net::dhcp::{self, Reply};

/// A leased network configuration. Held by `kernel_main` for the TCP/DNS
/// milestones; `configure` already validated every field against
/// slirp's documented defaults.
pub struct NetConfig {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub router: [u8; 4],
    pub dns: [u8; 4],
    pub lease_secs: u32,
}

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: dhcp: {msg}");
    crate::halt()
}

fn ip_str(ip: [u8; 4]) -> (u8, u8, u8, u8) {
    (ip[0], ip[1], ip[2], ip[3])
}

/// Poll the RX ring for the next valid DHCP reply of `want_type`
/// (skipping stray frames), bounded by the driver's poll budget.
fn wait_reply(nic: &mut E1000, want_type: u8, timeout: &'static str) -> Reply {
    let mut rx = [0u8; 2048];
    let mut spins = 0u32;
    loop {
        if spins >= RX_POLLS {
            fatal(timeout);
        }
        spins += 1;
        let got = nic.receive(&mut rx);
        if let Some(n) = got
            && let Some(dgram) = net::parse_udp(&rx[..n])
            && dgram.src_port == dhcp::SERVER_PORT
            && dgram.dst_port == dhcp::CLIENT_PORT
            && let Some(reply) = dhcp::parse_reply(dgram.payload, dhcp::XID)
            && reply.msg_type == want_type
        {
            return reply;
        }
        core::hint::spin_loop();
    }
}

fn require(opt: Option<[u8; 4]>, what: &'static str) -> [u8; 4] {
    match opt {
        Some(v) => v,
        None => fatal(what),
    }
}

/// Full DHCP transaction. Returns the lease; prints `DHCP_OK` on success.
///
/// Why the hard assertions below: slirp only ever offers its fixed
/// defaults (10.0.2.15/24, router and DNS = 10.0.2.x). If a value
/// differs, our *parser* decoded the options wrong (slirp rejects a
/// REQUEST whose option 50 doesn't match its offer, so a wrong OFFER
/// decode dies earlier as a timeout) — or the `net` crate constants
/// drifted from reality and must be updated together.
pub fn configure(nic: &mut E1000) -> NetConfig {
    let mac = nic.mac();
    let mut buf = [0u8; 576];

    // DISCOVER → OFFER
    let n = match dhcp::build_discover(&mut buf, mac) {
        Some(n) => n,
        None => fatal("cannot build DISCOVER (buffer bug?)"),
    };
    if let Err(e) = nic.transmit(&buf[..n]) {
        fatal(e);
    }
    serial_println!("dhcp: DISCOVER broadcast -> 255.255.255.255:67");
    let offer = wait_reply(nic, dhcp::DHCPOFFER, "timeout waiting for DHCP OFFER");
    let offered = ip_str(offer.yiaddr);
    serial_println!(
        "dhcp: OFFER {}.{}.{}.{}",
        offered.0,
        offered.1,
        offered.2,
        offered.3
    );
    let server = require(offer.server_id, "OFFER without server identifier");

    // REQUEST → ACK
    let n = match dhcp::build_request(&mut buf, mac, offer.yiaddr, server) {
        Some(n) => n,
        None => fatal("cannot build REQUEST (buffer bug?)"),
    };
    if let Err(e) = nic.transmit(&buf[..n]) {
        fatal(e);
    }
    serial_println!("dhcp: REQUEST for the offered address");
    let ack = wait_reply(nic, dhcp::DHCPACK, "timeout waiting for DHCP ACK");
    if ack.yiaddr != offer.yiaddr {
        fatal("ACK address differs from the OFFER");
    }

    // Validate against slirp's fixed defaults (see doc comment).
    let netmask = require(ack.netmask, "ACK without subnet mask");
    if netmask != [255, 255, 255, 0] {
        fatal("unexpected subnet mask (option decode bug?)");
    }
    let router = require(ack.router, "ACK without router");
    if router != net::SLIRP_GATEWAY {
        fatal("router is not 10.0.2.2 (option decode bug?)");
    }
    let dns = require(ack.dns, "ACK without DNS server");
    if dns != [10, 0, 2, 3] {
        fatal("DNS is not 10.0.2.3 (option decode bug?)");
    }
    if ack.yiaddr != net::SLIRP_GUEST_IP {
        fatal("leased IP differs from net::SLIRP_GUEST_IP (update the constant)");
    }

    let config = NetConfig {
        ip: ack.yiaddr,
        netmask,
        router,
        dns,
        lease_secs: ack.lease_secs.unwrap_or(0),
    };
    let ip = ip_str(config.ip);
    let nm = ip_str(config.netmask);
    let rt = ip_str(config.router);
    let dn = ip_str(config.dns);
    serial_println!(
        "dhcp: lease {}.{}.{}.{}/{}.{}.{}.{} router {}.{}.{}.{} dns {}.{}.{}.{}",
        ip.0,
        ip.1,
        ip.2,
        ip.3,
        nm.0,
        nm.1,
        nm.2,
        nm.3,
        rt.0,
        rt.1,
        rt.2,
        rt.3,
        dn.0,
        dn.1,
        dn.2,
        dn.3
    );
    if config.lease_secs != 0 {
        serial_println!("dhcp: lease time {}s", config.lease_secs);
    }
    serial_println!("DHCP_OK"); // machine-checked by `cargo xtask smoke`
    config
}
