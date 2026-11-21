//! DNS resolver (RFC 1035) over the e1000 driver: resolve one A record
//! through the DHCP-leased name server. Message layouts, the hostile-
//! input parser, and the next-hop rule live in the host-tested `net`
//! crate (`net::dns`, `net::on_subnet`); this file only drives the
//! NIC: ARP for the next hop, transmit, poll for the reply.

use crate::dhcp::NetConfig;
use crate::e1000::{E1000, RX_POLLS};
use crate::entropy::boot_entropy;
use net::dns;

/// Attempts per resolution: UDP can drop a query (slirp rarely does,
/// the real sky2 path can), so retransmit the identical bytes — same
/// transaction id, same source port, as RFC 1035 §2.3 specifies.
const ATTEMPTS: u32 = 3;

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: dns: {msg}");
    crate::halt()
}

/// Resolve `qname` to its first A record, print `DNS_OK`, and return
/// the address. Fatal on failure (no reachable server, no answer after
/// [`ATTEMPTS`] tries): without DNS the git/ssh milestones cannot run,
/// so boot stops here loudly rather than limping on.
///
/// Both the transaction id and the source port come from
/// [`boot_entropy`], and the reply must match *all four* of: source IP
/// = leased DNS server, destination IP = our leased address, source
/// port 53, destination port = the port we asked from — plus the
/// transaction id and an exact question echo inside the payload
/// (`net::dns::parse_a_response`). A stray, late, or forged frame
/// satisfies none of that and is skipped like any other noise.
pub fn resolve(nic: &mut E1000, cfg: &NetConfig, qname: &str) -> [u8; 4] {
    let Some(ip) = try_resolve(nic, cfg, qname) else {
        fatal("timeout waiting for DNS answer (internet up? server reachable?)");
    };
    serial_println!("DNS_OK"); // machine-checked by `cargo xtask smoke`
    ip
}

/// Non-fatal [`resolve`] for the shell: `None` when no answer arrives
/// instead of halting the kernel. Prints the same `dns: host -> ip`
/// line on success; the `DNS_OK` marker belongs to the boot path
/// (printed by [`resolve`]). All the validation rules documented
/// there apply here unchanged.
pub fn try_resolve(nic: &mut E1000, cfg: &NetConfig, qname: &str) -> Option<[u8; 4]> {
    // Next hop (RFC 911 §3.3): on-subnet → ARP the server itself,
    // off-subnet → ARP the router; either way the reply's *source IP*
    // is still cfg.dns, which is what the filters below check.
    let hop_ip = if net::on_subnet(cfg.ip, cfg.netmask, cfg.dns) {
        cfg.dns
    } else {
        cfg.router
    };
    let hop_mac = nic.arp_resolve(cfg.ip, hop_ip);

    let ent = boot_entropy();
    let txid = ent as u16;
    // IANA dynamic/private range 49152..=65535 (RFC 6335 §6): never
    // collides with the well-known server port or with our DHCP client.
    let client_port = 49152u16 + ((ent >> 16) & 0x3FFF) as u16;

    let mut query = [0u8; 512];
    let qlen = match dns::build_query(&mut query, txid, qname) {
        Some(n) => n,
        None => fatal("cannot build DNS query (qname too long?)"),
    };
    let src = net::Endpoint::new(nic.mac(), cfg.ip);
    let dst = net::Endpoint::new(hop_mac, cfg.dns);
    let mut frame = [0u8; 512];
    let flen =
        match net::build_udp_frame(&mut frame, src, dst, client_port, dns::PORT, &query[..qlen]) {
            Some(n) => n,
            None => fatal("cannot frame DNS query (buffer bug?)"),
        };

    let mut rx = [0u8; 2048];
    for attempt in 1..=ATTEMPTS {
        if let Err(e) = nic.transmit(&frame[..flen]) {
            fatal(e);
        }
        serial_println!(
            "dns: query {qname} A -> {}.{}.{}.{}, attempt {attempt}",
            cfg.dns[0],
            cfg.dns[1],
            cfg.dns[2],
            cfg.dns[3]
        );

        let mut spins = 0u32;
        loop {
            if spins >= RX_POLLS {
                break; // this attempt timed out; retransmit
            }
            spins += 1;
            let Some(n) = nic.receive(&mut rx) else {
                core::hint::spin_loop();
                continue;
            };
            let Some(dgram) = net::parse_udp(&rx[..n]) else {
                continue; // not UDP / corrupt — the parser already checked checksums
            };
            if dgram.src_ip != cfg.dns
                || dgram.dst_ip != cfg.ip
                || dgram.src_port != dns::PORT
                || dgram.dst_port != client_port
            {
                continue; // not a reply to this query
            }
            let Some(ip) = dns::parse_a_response(dgram.payload, &query[..qlen]) else {
                continue; // wrong txid, wrong question, or an error response
            };
            serial_println!("dns: {qname} -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            return Some(ip);
        }
    }
    None // no answer within the attempt budget
}
