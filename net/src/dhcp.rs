//! DHCPv4 client messages: DISCOVER → OFFER → REQUEST → ACK against
//! QEMU's slirp server. Layout per RFC 2131/2132: BOOTP fixed part
//! (236 bytes) + magic cookie + TLV options, everything bounds-checked.

use crate::{BROADCAST_MAC, ETHERNET_HDR, IPPROTO_UDP, checksum_with_pseudo, internet_checksum};

/// BOOTP fixed part before the magic cookie (op .. file): 236 octets.
const BOOTP_FIXED: usize = 236;
/// DHCP magic cookie "63.82.53.63" (RFC 2131 §4.1) — those are HEX
/// digits: bytes 0x63,0x82,0x53,0x63 = (99,130,83,99). Writing the
/// decimals (63,82,53,63) instead made slirp reject the cookie, skip
/// option 53, and answer DHCPREQUEST with an ACK — caught only by
/// replaying slirp's dhcp_decode against our bytes.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// DHCP messages are padded to the BOOTP minimum of 300 octets.
const MIN_DHCP_LEN: usize = 300;
const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;

/// DHCP message types (RFC 2131 §3.1 / option 53).
pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPACK: u8 = 5;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

/// Transaction id. No RNG yet — a fixed value is fine because slirp
/// echoes whatever xid we send (ASCII "repl").
pub const XID: u32 = 0x7265_706C;

/// A parsed server reply (OFFER/ACK).
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub msg_type: u8,
    pub yiaddr: [u8; 4],            // offered/assigned address
    pub server_id: Option<[u8; 4]>, // option 54
    pub netmask: Option<[u8; 4]>,   // option 1
    pub router: Option<[u8; 4]>,    // option 3 (first server)
    pub dns: Option<[u8; 4]>,       // option 6 (first server)
    pub lease_secs: Option<u32>,    // option 51
}

/// Broadcast a DHCPDISCOVER (RFC 2131 §4.3.1). Returns the frame length.
pub fn build_discover(buf: &mut [u8], mac: [u8; 6]) -> Option<usize> {
    let mut opts = [0u8; 16];
    let mut i = 0;
    opts[i..i + 3].copy_from_slice(&[53, 1, DHCPDISCOVER]); // message type
    i += 3;
    opts[i..i + 6].copy_from_slice(&[55, 4, 1, 3, 6, 51]); // param request: netmask, router, DNS, lease
    i += 6;
    opts[i] = 255; // option end
    i += 1;
    build_bootp(buf, mac, &opts[..i])
}

/// Broadcast a DHCPREQUEST for `requested_ip` from `server_id`
/// (RFC 2131 §4.3.2, selected-offer case).
pub fn build_request(
    buf: &mut [u8],
    mac: [u8; 6],
    requested_ip: [u8; 4],
    server_id: [u8; 4],
) -> Option<usize> {
    let mut opts = [0u8; 24];
    let mut i = 0;
    opts[i..i + 3].copy_from_slice(&[53, 1, DHCPREQUEST]);
    i += 3;
    opts[i..i + 2].copy_from_slice(&[50, 4]); // requested IP address
    opts[i + 2..i + 6].copy_from_slice(&requested_ip);
    i += 6;
    opts[i..i + 2].copy_from_slice(&[54, 4]); // server identifier
    opts[i + 2..i + 6].copy_from_slice(&server_id);
    i += 6;
    opts[i..i + 6].copy_from_slice(&[55, 4, 1, 3, 6, 51]);
    i += 6;
    opts[i] = 255;
    i += 1;
    build_bootp(buf, mac, &opts[..i])
}

/// eth + IPv4 (0.0.0.0 → 255.255.255.255) + UDP (68 → 67) + BOOTP
/// request with `options`. The whole BOOTP region is zeroed first so no
/// stack junk leaks into sname/file/padding.
fn build_bootp(buf: &mut [u8], mac: [u8; 6], options: &[u8]) -> Option<usize> {
    let payload_len = MIN_DHCP_LEN.max(BOOTP_FIXED + 4 + options.len());
    let total = ETHERNET_HDR + 20 + 8 + payload_len;
    let b = buf.get_mut(..total)?;
    b.fill(0);

    // Ethernet header: broadcast destination.
    b[..6].copy_from_slice(&BROADCAST_MAC);
    b[6..12].copy_from_slice(&mac);
    b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header.
    let ip = &mut b[ETHERNET_HDR..ETHERNET_HDR + 20];
    ip[0] = 0x45; // version 4, IHL 5
    ip[2..4].copy_from_slice(&((20 + 8 + payload_len) as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_UDP;
    ip[16..20].fill(0xFF); // dst 255.255.255.255 (src stays 0.0.0.0)
    let ip_csum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP header (68 → 67); checksum filled in *after* the BOOTP body,
    // because the pseudo-header checksum covers the whole segment —
    // computing it earlier would checksum zeros and break on validation.
    let udp = &mut b[ETHERNET_HDR + 20..ETHERNET_HDR + 20 + 8 + payload_len];
    udp[0..2].copy_from_slice(&CLIENT_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&SERVER_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());

    // BOOTP/DHCP fixed part + cookie + options.
    let d = &mut udp[8..];
    d[0] = OP_BOOTREQUEST;
    d[1] = 1; // htype: Ethernet
    d[2] = 6; // hlen
    d[4..8].copy_from_slice(&XID.to_be_bytes());
    d[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast
    d[28..34].copy_from_slice(&mac); // chaddr
    d[236..240].copy_from_slice(&MAGIC_COOKIE);
    d[240..240 + options.len()].copy_from_slice(options);

    // Now the payload is final: compute and store the UDP checksum.
    let udp_csum = checksum_with_pseudo([0; 4], [0xFF; 4], IPPROTO_UDP, udp);
    udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());
    Some(total)
}

/// Parse a DHCP reply from a UDP payload: op/reply, matching xid, magic
/// cookie, and the option TLVs we care about (53 type, 54 server, 1
/// netmask, 3 router, 6 DNS, 51 lease). Malformed input → `None`.
pub fn parse_reply(payload: &[u8], expect_xid: u32) -> Option<Reply> {
    if *payload.first()? != OP_BOOTREPLY {
        return None;
    }
    let xid = u32::from_be_bytes(payload.get(4..8)?.try_into().ok()?);
    if xid != expect_xid {
        return None;
    }
    if payload.get(236..240)? != MAGIC_COOKIE {
        return None;
    }
    let yiaddr: [u8; 4] = payload.get(16..20)?.try_into().ok()?;

    let opts = payload.get(240..)?;
    let mut msg_type = None;
    let mut server_id = None;
    let mut netmask = None;
    let mut router = None;
    let mut dns = None;
    let mut lease_secs = None;

    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => i += 1,  // padding
            255 => break, // option end
            tag => {
                let len = usize::from(*opts.get(i + 1)?);
                let val = opts.get(i + 2..i + 2 + len)?;
                match (tag, len) {
                    (53, 1) => msg_type = Some(val[0]),
                    (54, 4) => server_id = Some(ip4(val)),
                    (1, 4) => netmask = Some(ip4(val)),
                    (3, len) if len >= 4 => router = Some(ip4(val)),
                    (6, len) if len >= 4 => dns = Some(ip4(val)),
                    (51, 4) => lease_secs = Some(u32::from_be_bytes(val[..4].try_into().ok()?)),
                    _ => {} // ignore unknown/oversized options
                }
                i += 2 + len;
            }
        }
    }

    Some(Reply {
        msg_type: msg_type?,
        yiaddr,
        server_id,
        netmask,
        router,
        dns,
        lease_secs,
    })
}

fn ip4(val: &[u8]) -> [u8; 4] {
    [val[0], val[1], val[2], val[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BROADCAST_MAC, ETHERNET_HDR, IPPROTO_UDP, checksum_with_pseudo, internet_checksum,
    };
    use std::vec;
    use std::vec::Vec;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// Assemble the DHCP reply the way a server would (eth/ip/udp/bootp),
    /// so the parser is tested against hand-built bytes, not its own
    /// builder's output. The message type travels in option 53, which
    /// the caller already puts in `options`.
    fn build_reply(yiaddr: [u8; 4], options: &[u8]) -> Vec<u8> {
        let payload_len = MIN_DHCP_LEN.max(BOOTP_FIXED + 4 + options.len());
        let total = ETHERNET_HDR + 20 + 8 + payload_len;
        let mut b = vec![0u8; total];
        b[..6].copy_from_slice(&MAC); // dst = client
        b[6..12].copy_from_slice(&[0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]); // slirp
        b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut b[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + 8 + payload_len) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&[10, 0, 2, 2]); // src gateway
        ip[16..20].fill(0xFF); // dst broadcast
        let c = internet_checksum(ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        let udp = &mut b[34..34 + 8 + payload_len];
        udp[0..2].copy_from_slice(&SERVER_PORT.to_be_bytes());
        udp[2..4].copy_from_slice(&CLIENT_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        // BOOTP body first; the UDP checksum covers it, so it must be
        // computed last (same ordering rule as build_bootp).
        let d = &mut udp[8..];
        d[0] = OP_BOOTREPLY;
        d[4..8].copy_from_slice(&XID.to_be_bytes());
        d[16..20].copy_from_slice(&yiaddr);
        d[236..240].copy_from_slice(&MAGIC_COOKIE);
        d[240..240 + options.len()].copy_from_slice(options);
        let c = checksum_with_pseudo([10, 0, 2, 2], [0xFF; 4], IPPROTO_UDP, udp);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        b
    }

    fn disc_opts() -> Vec<u8> {
        let mut buf = [0u8; 576];
        let n = build_discover(&mut buf, MAC).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn magic_cookie_is_the_hex_documented_value() {
        // Pins the exact bytes: "63.82.53.63" is hexadecimal notation.
        // A decimal/hex mixup here silently breaks every DHCP exchange
        // (slirp answers ACK instead of OFFER) — this test must never
        // be "fixed" to [63, 82, 53, 63].
        assert_eq!(MAGIC_COOKIE, [0x63, 0x82, 0x53, 0x63]);
        assert_eq!(MAGIC_COOKIE, [99, 130, 83, 99]);
    }

    #[test]
    fn discover_is_well_formed() {
        let frame = disc_opts();
        assert_eq!(frame.len(), 14 + 20 + 8 + 300); // padded to 300
        assert_eq!(&frame[..6], &BROADCAST_MAC); // eth dst
        assert_eq!(&frame[6..12], &MAC); // eth src
        // IPv4 checksum verifies over its own field.
        assert_eq!(internet_checksum(&frame[14..34]), 0);
        assert_eq!(frame[23], 17); // protocol UDP
        // UDP ports + checksum verifies over pseudo-header.
        assert_eq!(&frame[34..36], &68u16.to_be_bytes());
        assert_eq!(&frame[36..38], &67u16.to_be_bytes());
        assert_eq!(
            checksum_with_pseudo([0; 4], [0xFF; 4], IPPROTO_UDP, &frame[34..]),
            0
        );
        // BOOTP: op=REQUEST, xid, broadcast flag, our chaddr, cookie.
        let d = &frame[42..];
        assert_eq!(d[0], OP_BOOTREQUEST);
        assert_eq!(u32::from_be_bytes(d[4..8].try_into().unwrap()), XID);
        assert_eq!(&d[10..12], &0x8000u16.to_be_bytes());
        assert_eq!(&d[28..34], &MAC);
        assert_eq!(&d[236..240], &MAGIC_COOKIE);
        // Options: 53=DISCOVER then 55=param-request, end tag 255.
        assert_eq!(&d[240..243], &[53, 1, DHCPDISCOVER]);
        assert_eq!(d[243], 55);
        assert_eq!(d[249], 255);
        // Everything after the options is zero padding, not stack junk.
        assert!(d[250..].iter().all(|&b| b == 0));
    }

    #[test]
    fn request_carries_offer_and_server() {
        let mut buf = [0u8; 576];
        let n = build_request(&mut buf, MAC, [10, 0, 2, 15], [10, 0, 2, 2]).unwrap();
        let d = &buf[42..n];
        assert_eq!(d[0], OP_BOOTREQUEST);
        // Options must contain 53=REQUEST, 50=offered IP, 54=server id.
        let opts = &d[240..];
        assert!(opts.windows(3).any(|w| w == [53, 1, DHCPREQUEST]));
        assert!(opts.windows(6).any(|w| w == [50, 4, 10, 0, 2, 15]));
        assert!(opts.windows(6).any(|w| w == [54, 4, 10, 0, 2, 2]));
    }

    #[test]
    fn parses_offer_and_ack() {
        // OFFER: type 2, address, server, netmask, router, DNS, lease.
        let mut o = vec![53, 1, DHCPOFFER];
        o.extend_from_slice(&[54, 4, 10, 0, 2, 2]);
        o.extend_from_slice(&[1, 4, 255, 255, 255, 0]);
        o.extend_from_slice(&[3, 4, 10, 0, 2, 2]);
        o.extend_from_slice(&[6, 4, 10, 0, 2, 3]);
        o.extend_from_slice(&[51, 4, 0x00, 0x01, 0x51, 0x80]); // 86400 s
        o.push(255);
        let frame = build_reply([10, 0, 2, 15], &o);
        // Feed the *UDP payload* (what parse_udp hands the DHCP layer).
        let dgram = crate::parse_udp(&frame).expect("reply frame must parse as UDP");
        assert_eq!(dgram.src_port, SERVER_PORT);
        assert_eq!(dgram.dst_port, CLIENT_PORT);
        let reply = parse_reply(dgram.payload, XID).expect("reply must parse");
        assert_eq!(reply.msg_type, DHCPOFFER);
        assert_eq!(reply.yiaddr, [10, 0, 2, 15]);
        assert_eq!(reply.server_id, Some([10, 0, 2, 2]));
        assert_eq!(reply.netmask, Some([255, 255, 255, 0]));
        assert_eq!(reply.router, Some([10, 0, 2, 2]));
        assert_eq!(reply.dns, Some([10, 0, 2, 3]));
        assert_eq!(reply.lease_secs, Some(86400));
    }

    #[test]
    fn reply_rejects_bad_xid_op_and_truncation() {
        let mut o = vec![53, 1, DHCPACK];
        o.push(255);
        let frame = build_reply([10, 0, 2, 15], &o);
        let payload = crate::parse_udp(&frame).unwrap().payload;
        assert!(parse_reply(payload, XID ^ 1).is_none()); // wrong xid
        assert!(parse_reply(payload, XID).is_some()); // control
        assert!(parse_reply(&payload[..20], XID).is_none()); // truncated before cookie
        assert!(parse_reply(&[], XID).is_none()); // empty
        // Missing message-type option (53) → rejected.
        let no_type = build_reply([10, 0, 2, 15], &[255]);
        let p = crate::parse_udp(&no_type).unwrap().payload;
        assert!(parse_reply(p, XID).is_none());
    }
}
