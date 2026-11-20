//! Pure Ethernet/ARP frame construction and parsing: no I/O, no allocator,
//! every length bounds-checked — host-testable like `bootinfo` and `pci`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// EtherType for Address Resolution Protocol (IEEE 802.3).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IP protocol number for ICMP (IANA).
pub const IPPROTO_ICMP: u8 = 1;
/// ARP hardware type: Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type: IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
/// ICMP echo request / reply types (RFC 792).
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Ethernet header size (dst MAC + src MAC + EtherType).
pub const ETHERNET_HDR: usize = 14;
/// Wire size of an ARP request/reply over Ethernet (14 + 28).
pub const ARP_FRAME_LEN: usize = 42;
/// Broadcast destination MAC.
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// QEMU user-mode networking (slirp) defaults — hard-coded until the
/// DHCP client milestone replaces the guest address. slirp answers ARP
/// for its gateway, which is what makes the TX/RX roundtrip test work.
pub const SLIRP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
pub const SLIRP_GATEWAY: [u8; 4] = [10, 0, 2, 2];

/// Write a complete ARP request (42 bytes) into `buf`.
/// Returns `None` when `buf` is too small.
pub fn build_arp_request(
    buf: &mut [u8],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    target_ip: [u8; 4],
) -> Option<usize> {
    let b = buf.get_mut(..ARP_FRAME_LEN)?;
    b[..6].copy_from_slice(&BROADCAST_MAC);
    b[6..12].copy_from_slice(&src_mac);
    b[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    b[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    b[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    b[18] = 6; // hardware address length
    b[19] = 4; // protocol address length
    b[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    b[22..28].copy_from_slice(&src_mac); // sender hardware address
    b[28..32].copy_from_slice(&src_ip); // sender protocol address
    b[32..38].fill(0); // target hardware address (unknown for a request)
    b[38..42].copy_from_slice(&target_ip);
    Some(ARP_FRAME_LEN)
}

/// EtherType of a frame (bytes 12..14, big-endian), `None` if too short.
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = frame.get(12..14)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// ARP opcode (bytes 20..22) of a frame, `None` unless it *is* an ARP frame.
pub fn arp_opcode(frame: &[u8]) -> Option<u16> {
    if ethertype(frame)? != ETHERTYPE_ARP {
        return None;
    }
    let bytes: [u8; 2] = frame.get(20..22)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Destination MAC of a frame (bytes 0..6), `None` if too short.
pub fn dst_mac(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(..6)?.try_into().ok()
}

/// Sender hardware address of an ARP frame (bytes 22..28) — how the
/// caller learns the peer's MAC from a reply. `None` for non-ARP frames.
pub fn arp_sender_mac(frame: &[u8]) -> Option<[u8; 6]> {
    arp_opcode(frame)?; // must be an ARP frame
    frame.get(22..28)?.try_into().ok()
}

/// RFC 1071 internet checksum (one's complement of the one's sum).
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8; // odd tail byte: pad with zero
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A link-layer + network-layer address pair (MAC + IPv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
}

impl Endpoint {
    pub const fn new(mac: [u8; 6], ip: [u8; 4]) -> Self {
        Self { mac, ip }
    }
}

/// An ICMP echo reply, fully validated (see [`parse_icmp_echo_reply`]).
#[derive(Debug, PartialEq, Eq)]
pub struct IcmpEchoReply<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub id: u16,
    pub seq: u16,
    pub payload: &'a [u8],
}

/// Build eth + IPv4 + ICMP echo request. `dst.mac` is the resolved peer
/// (from ARP — slirp's gateway). Returns the total frame length,
/// `None` if `buf` is too small.
pub fn build_icmp_echo(
    buf: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Option<usize> {
    let ip_len = 20usize;
    let icmp_len = 8usize + payload.len();
    let total = ETHERNET_HDR + ip_len + icmp_len;
    let b = buf.get_mut(..total)?;

    // Ethernet header.
    b[..6].copy_from_slice(&dst.mac);
    b[6..12].copy_from_slice(&src.mac);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 header (checksum field zeroed, then computed over it).
    let ip = &mut b[ETHERNET_HDR..ETHERNET_HDR + ip_len];
    ip[0] = 0x45; // version 4, IHL 5 (no options)
    ip[1] = 0x00; // DSCP/ECN
    ip[2..4].copy_from_slice(&((ip_len + icmp_len) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_ICMP;
    ip[10..12].fill(0); // header checksum (placeholder)
    ip[12..16].copy_from_slice(&src.ip);
    ip[16..20].copy_from_slice(&dst.ip);
    let ip_csum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP echo request (checksum placeholder likewise).
    let icmp = &mut b[ETHERNET_HDR + ip_len..];
    icmp[0] = ICMP_ECHO_REQUEST;
    icmp[1] = 0x00; // code
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_csum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    Some(total)
}

/// If `frame` is a valid IPv4 ICMP echo reply, return it: both internet
/// checksums verified, version/IHL and protocol checked, bounds-checked
/// throughout. Anything else (our own traffic, stray frames, corrupt
/// packets) yields `None`.
pub fn parse_icmp_echo_reply(frame: &[u8]) -> Option<IcmpEchoReply<'_>> {
    if ethertype(frame)? != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(ETHERNET_HDR..ETHERNET_HDR + 20)?;
    if ip[0] != 0x45 {
        // version 4, IHL 5 — no options, fixed offsets
        return None;
    }
    if ip[9] != IPPROTO_ICMP {
        return None;
    }
    if internet_checksum(ip) != 0 {
        return None; // corrupt IPv4 header
    }
    let ip_total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip_total < 28 {
        return None; // 20 IP + 8 ICMP minimum for echo
    }
    let icmp = frame.get(ETHERNET_HDR + 20..ETHERNET_HDR + ip_total)?;
    if icmp[0] != ICMP_ECHO_REPLY || icmp[1] != 0x00 {
        return None;
    }
    if internet_checksum(icmp) != 0 {
        return None; // corrupt ICMP
    }
    Some(IcmpEchoReply {
        src_ip: ip[12..16].try_into().ok()?,
        dst_ip: ip[16..20].try_into().ok()?,
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp.get(8..)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    #[test]
    fn arp_request_layout_is_exact() {
        let mut buf = [0u8; 64];
        let n = build_arp_request(&mut buf, OUR_MAC, SLIRP_GUEST_IP, SLIRP_GATEWAY)
            .expect("64-byte buffer must fit a 42-byte request");
        assert_eq!(n, ARP_FRAME_LEN);
        assert_eq!(&buf[..6], &BROADCAST_MAC); // dst = broadcast
        assert_eq!(&buf[6..12], &OUR_MAC); // src = us
        assert_eq!(ethertype(&buf[..n]), Some(ETHERTYPE_ARP));
        assert_eq!(&buf[14..16], &1u16.to_be_bytes()); // htype ethernet
        assert_eq!(&buf[16..18], &0x0800u16.to_be_bytes()); // ptype IPv4
        assert_eq!((buf[18], buf[19]), (6, 4)); // hlen, plen
        assert_eq!(arp_opcode(&buf[..n]), Some(ARP_REQUEST));
        assert_eq!(&buf[22..28], &OUR_MAC); // sender HA = us
        assert_eq!(&buf[28..32], &[10, 0, 2, 15]); // sender IP = guest
        assert_eq!(&buf[32..38], &[0; 6]); // target HA unknown
        assert_eq!(&buf[38..42], &[10, 0, 2, 2]); // target IP = gateway
    }

    #[test]
    fn rejects_tiny_buffer() {
        let mut buf = [0u8; ARP_FRAME_LEN - 1];
        assert_eq!(
            build_arp_request(&mut buf, OUR_MAC, SLIRP_GUEST_IP, SLIRP_GATEWAY),
            None
        );
    }

    #[test]
    fn parses_reply_opcode_and_dst() {
        let mut buf = [0u8; 64];
        let n = build_arp_request(&mut buf, OUR_MAC, SLIRP_GUEST_IP, SLIRP_GATEWAY).unwrap();
        // Turn the request into a reply addressed to us (what slirp sends).
        buf[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        buf[..6].copy_from_slice(&OUR_MAC);
        let frame = &buf[..n];
        assert_eq!(ethertype(frame), Some(ETHERTYPE_ARP));
        assert_eq!(arp_opcode(frame), Some(ARP_REPLY));
        assert_eq!(dst_mac(frame), Some(OUR_MAC));
    }

    #[test]
    fn rejects_non_arp_and_short_frames() {
        let mut ip = [0u8; 64];
        ip[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not ARP
        assert_eq!(ethertype(&ip), Some(0x0800));
        assert_eq!(arp_opcode(&ip), None); // ethertype gate
        assert_eq!(ethertype(&[0u8; 13]), None);
        assert_eq!(arp_opcode(&[0u8; 13]), None);
        assert_eq!(dst_mac(&[0u8; 5]), None);
    }

    #[test]
    fn arp_sender_mac_from_reply() {
        let mut buf = [0u8; 64];
        let n = build_arp_request(&mut buf, OUR_MAC, SLIRP_GUEST_IP, SLIRP_GATEWAY).unwrap();
        // In a *request* the sender is us:
        assert_eq!(arp_sender_mac(&buf[..n]), Some(OUR_MAC));
        // In a reply it is the peer (what we need for ICMP):
        buf[20..22].copy_from_slice(&ARP_REPLY.to_be_bytes());
        let gw = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        buf[22..28].copy_from_slice(&gw);
        assert_eq!(arp_sender_mac(&buf[..n]), Some(gw));
        assert_eq!(arp_sender_mac(&[0u8; 60]), None); // not ARP
    }

    #[test]
    fn rfc1071_checksum_reference_vector() {
        // The canonical RFC 1071 example: 0001 f203 f4f5 f6f7 → 0x220d.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        // Odd length pads the tail byte with a zero.
        assert_eq!(internet_checksum(&[0x12]), 0xEDFF);
    }

    #[test]
    fn icmp_echo_build_and_parse_roundtrip() {
        const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let src = Endpoint::new(OUR_MAC, SLIRP_GUEST_IP);
        let dst = Endpoint::new(GW_MAC, SLIRP_GATEWAY);
        let mut buf = [0u8; 128];
        let n = build_icmp_echo(&mut buf, src, dst, 0x1234, 7, b"pingtest")
            .expect("128-byte buffer must fit the 50-byte frame");
        assert_eq!(n, 14 + 20 + 8 + 8);
        // Both checksums must self-validate over their own fields.
        assert_eq!(internet_checksum(&buf[14..34]), 0);
        assert_eq!(internet_checksum(&buf[34..n]), 0);
        assert_eq!(ethertype(&buf[..n]), Some(ETHERTYPE_IPV4));

        // Turn the request into the reply slirp would send (swap addresses,
        // flip the ICMP type, recompute both checksums) and parse it back.
        buf[..6].copy_from_slice(&OUR_MAC); // dst = us
        buf[6..12].copy_from_slice(&GW_MAC); // src = gateway
        buf[26..30].copy_from_slice(&SLIRP_GATEWAY);
        buf[30..34].copy_from_slice(&SLIRP_GUEST_IP);
        buf[24..26].fill(0);
        let c = internet_checksum(&buf[14..34]);
        buf[24..26].copy_from_slice(&c.to_be_bytes());
        buf[34] = ICMP_ECHO_REPLY;
        buf[36..38].fill(0);
        let c = internet_checksum(&buf[34..n]);
        buf[36..38].copy_from_slice(&c.to_be_bytes());

        let reply = parse_icmp_echo_reply(&buf[..n]).expect("reply must parse");
        assert_eq!(reply.src_ip, SLIRP_GATEWAY);
        assert_eq!(reply.dst_ip, SLIRP_GUEST_IP);
        assert_eq!((reply.id, reply.seq), (0x1234, 7));
        assert_eq!(reply.payload, b"pingtest");
    }

    #[test]
    fn icmp_parse_rejects_corruption() {
        const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let src = Endpoint::new(OUR_MAC, SLIRP_GUEST_IP);
        let dst = Endpoint::new(GW_MAC, SLIRP_GATEWAY);
        let mut buf = [0u8; 128];
        let n = build_icmp_echo(&mut buf, src, dst, 1, 1, b"x").unwrap();
        // Corrupt a payload byte without fixing the checksum.
        buf[42] ^= 0xFF;
        assert_eq!(parse_icmp_echo_reply(&buf[..n]), None);
        // An echo *request* is not a reply.
        buf[42] ^= 0xFF;
        assert_eq!(parse_icmp_echo_reply(&buf[..n]), None);
        // Short/garbage frames are rejected, never panic.
        assert_eq!(parse_icmp_echo_reply(&buf[..10]), None);
        assert_eq!(parse_icmp_echo_reply(&[]), None);
    }
}
