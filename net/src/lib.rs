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
/// IP protocol number for TCP (IANA).
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP (IANA).
pub const IPPROTO_UDP: u8 = 17;
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

/// QEMU user-mode networking (slirp) defaults — asserted by the DHCP
/// client once it exists (a mismatch means this constant drifted from
/// reality). The pre-DHCP tests (ARP/ping) also use them directly.
pub const SLIRP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
pub const SLIRP_GATEWAY: [u8; 4] = [10, 0, 2, 2];

/// True when `ip` and `dst` fall in the same subnet defined by `mask`
/// (RFC 911 §3.3 next-hop selection: on-subnet destinations are
/// reached by direct ARP, off-subnet through the router). Every byte
/// is masked before comparison; `mask = 0.0.0.0` makes everything
/// on-subnet, which is the correct degenerate answer.
pub fn on_subnet(ip: [u8; 4], mask: [u8; 4], dst: [u8; 4]) -> bool {
    ip.iter()
        .zip(mask.iter())
        .zip(dst.iter())
        .all(|((&a, &m), &b)| (a & m) == (b & m))
}

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

/// Sender protocol address (bytes 28..32) of an ARP frame — lets the
/// caller verify a reply actually comes from the address it asked
/// about, instead of trusting any ARP reply that shows up. `None` for
/// non-ARP frames.
pub fn arp_sender_ip(frame: &[u8]) -> Option<[u8; 4]> {
    arp_opcode(frame)?; // must be an ARP frame
    frame.get(28..32)?.try_into().ok()
}

/// Sum big-endian 16-bit words (odd tail byte padded with zero), per
/// RFC 1071 — shared by the plain and pseudo-header checksums.
fn sum_be16_words(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8; // odd tail byte: pad with zero
    }
    sum
}

fn complement(sum: u32) -> u16 {
    let mut s = sum;
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

/// RFC 1071 internet checksum (one's complement of the one's sum).
pub fn internet_checksum(data: &[u8]) -> u16 {
    complement(sum_be16_words(data))
}

/// RFC 768: a UDP checksum that computes to zero is transmitted as
/// all ones — an all-zero field means "no checksum was computed" and
/// receivers (slirp included) skip validation for it entirely.
pub fn udp_csum(computed: u16) -> u16 {
    if computed == 0 { 0xFFFF } else { computed }
}

/// Internet checksum over an IPv4 pseudo-header (RFC 768) + transport
/// segment: used for UDP. `segment` must fit a u16 length field (true
/// for every frame this OS builds).
pub fn checksum_with_pseudo(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, segment: &[u8]) -> u16 {
    let mut sum = sum_be16_words(&src_ip);
    sum += sum_be16_words(&dst_ip);
    sum += u32::from(proto); // pseudo: 0x00 | protocol
    sum += (segment.len() & 0xFFFF) as u32; // pseudo: UDP length
    sum += sum_be16_words(segment);
    complement(sum)
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

/// Write the Ethernet and IPv4 headers of a frame whose transport
/// segment is `transport_len` bytes, zeroing the whole frame region
/// first (no stack junk may leak onto the wire) and storing the IPv4
/// header checksum. `ip_id`/`ip_flags` are the IPv4 identification and
/// flags/fragment fields: UDP/TCP/DHCP leave them zero (single
/// datagrams), ICMP echoes carry the echo id plus DF.
///
/// The caller writes the transport segment *after* this returns — a
/// transport checksum can only be computed once the payload is final
/// (the bug that once broke DHCP). Returns the total frame length, or
/// `None` when a length would overflow `u16` or `buf` is too small.
fn write_eth_ipv4(
    buf: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    transport_len: usize,
    ip_id: u16,
    ip_flags: u16,
) -> Option<usize> {
    let ip_total = u16::try_from(transport_len).ok()?.checked_add(20)?;
    let total = ETHERNET_HDR + usize::from(ip_total);
    let b = buf.get_mut(..total)?;
    b.fill(0); // no stack junk on the wire

    // Ethernet header.
    b[..6].copy_from_slice(&dst.mac);
    b[6..12].copy_from_slice(&src.mac);
    b[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 header.
    let ip = &mut b[ETHERNET_HDR..ETHERNET_HDR + 20];
    ip[0] = 0x45; // version 4, IHL 5
    ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    ip[6..8].copy_from_slice(&ip_flags.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.ip);
    ip[16..20].copy_from_slice(&dst.ip);
    let ip_csum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    Some(total)
}

/// Build eth + IPv4 + UDP around a **final** `payload` and return the
/// frame length, or `None` if `buf` is too small. The checksums are
/// computed last, over the complete segment — passing an unfinished
/// payload here is exactly the bug that once produced an invalid DHCP
/// UDP checksum (see `net::dhcp`).
pub fn build_udp_frame(
    buf: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    // Checked arithmetic: the length fields are u16 (security rule —
    // never truncate a length silently).
    let payload_len = u16::try_from(payload.len()).ok()?;
    let ip_total = payload_len.checked_add(20 + 8)?;
    let transport_len = usize::from(ip_total) - 20;
    let total = write_eth_ipv4(buf, src, dst, IPPROTO_UDP, transport_len, 0, 0)?;

    // UDP header + payload (checksum after the payload is in place).
    let udp = &mut buf[ETHERNET_HDR + 20..total];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(8u16 + payload_len).to_be_bytes());
    udp[8..8 + payload.len()].copy_from_slice(payload);
    let udp_csum = udp_csum(checksum_with_pseudo(src.ip, dst.ip, IPPROTO_UDP, udp));
    udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());
    Some(total)
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
    let icmp_len = 8usize.checked_add(payload.len())?;
    // ICMP echoes carry the echo id as the IPv4 identification field
    // and set DF (no fragmentation of an echo probe).
    let total = write_eth_ipv4(buf, src, dst, IPPROTO_ICMP, icmp_len, id, 0x4000)?;

    // ICMP echo request (checksum placeholder likewise).
    let icmp = &mut buf[ETHERNET_HDR + 20..total];
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

pub mod dhcp;
pub mod dns;

/// A validated UDP datagram carried by an IPv4 frame.
#[derive(Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse eth + IPv4 + UDP from a received frame: version/IHL and
/// protocol checked, IPv4 checksum verified, UDP length bounds-checked,
/// and the UDP checksum verified *when non-zero* (RFC 768: zero means
/// "not computed", which is legal and what some stacks send).
pub fn parse_udp(frame: &[u8]) -> Option<UdpDatagram<'_>> {
    if ethertype(frame)? != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(ETHERNET_HDR..ETHERNET_HDR + 20)?;
    if ip[0] != 0x45 || ip[9] != IPPROTO_UDP {
        return None;
    }
    if internet_checksum(ip) != 0 {
        return None; // corrupt IPv4 header
    }
    let ip_total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let udp = frame.get(ETHERNET_HDR + 20..ETHERNET_HDR + ip_total)?;
    if udp.len() < 8 {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]])); // length field
    if !(8..=udp.len()).contains(&udp_len) {
        return None; // UDP length disagrees with the IP payload
    }
    let src_ip: [u8; 4] = ip[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = ip[16..20].try_into().ok()?;
    let csum = u16::from_be_bytes([udp[6], udp[7]]);
    if csum != 0 && checksum_with_pseudo(src_ip, dst_ip, IPPROTO_UDP, &udp[..udp_len]) != 0 {
        return None; // corrupt UDP checksum
    }
    Some(UdpDatagram {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp.get(8..udp_len)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    #[test]
    fn subnet_membership_decides_next_hop() {
        let me = [10, 0, 2, 15];
        let mask = [255, 255, 255, 0];
        // On-subnet: the DNS server itself (direct ARP).
        assert!(on_subnet(me, mask, [10, 0, 2, 3]));
        // Off-subnet: public DNS → next hop is the router.
        assert!(!on_subnet(me, mask, [8, 8, 8, 8]));
        // Broadcast and network addresses are "on-subnet" by the mask.
        assert!(on_subnet(me, mask, [10, 0, 2, 255]));
        // /0 degenerates to everything on-subnet.
        assert!(on_subnet(me, [0, 0, 0, 0], [1, 2, 3, 4]));
        // Different subnet entirely.
        assert!(!on_subnet([192, 168, 1, 1], mask, [10, 0, 2, 3]));
    }

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
        // Make it a real reply: slirp also fills the sender *protocol*
        // address (bytes 28..32) with its own IP.
        buf[28..32].copy_from_slice(&SLIRP_GATEWAY);
        assert_eq!(arp_sender_ip(&buf[..n]), Some(SLIRP_GATEWAY));
        buf[28..32].copy_from_slice(&[10, 0, 2, 99]); // spoof another IP
        assert_eq!(arp_sender_ip(&buf[..n]), Some([10, 0, 2, 99]));
        assert_eq!(arp_sender_ip(&[0u8; 60]), None); // not ARP
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
    fn rfc768_zero_udp_checksum_becomes_all_ones() {
        // A computed zero must go on the wire as all ones: an all-zero
        // field means "not computed" and the receiver skips validation.
        assert_eq!(udp_csum(0x0000), 0xFFFF);
        // Any other value passes through untouched.
        assert_eq!(udp_csum(0x1234), 0x1234);
        assert_eq!(udp_csum(0xFFFF), 0xFFFF);
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
    fn udp_frame_roundtrip_via_build_and_parse() {
        const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let src = Endpoint::new(OUR_MAC, SLIRP_GUEST_IP);
        let dst = Endpoint::new(GW_MAC, SLIRP_GATEWAY);
        let payload = b"some-udp-payload";
        let mut buf = [0u8; 128];
        let n = build_udp_frame(&mut buf, src, dst, 49152, 53, payload)
            .expect("128-byte buffer must fit the frame");
        assert_eq!(n, 14 + 20 + 8 + payload.len());
        // Both checksums must self-validate over their own fields.
        assert_eq!(internet_checksum(&buf[14..34]), 0);
        let udp = &buf[34..n];
        assert_eq!(
            checksum_with_pseudo(SLIRP_GUEST_IP, SLIRP_GATEWAY, IPPROTO_UDP, udp),
            0
        );

        // The frame must parse back to exactly what was built.
        let dgram = parse_udp(&buf[..n]).expect("frame must parse as UDP");
        assert_eq!(dgram.src_port, 49152);
        assert_eq!(dgram.dst_port, 53);
        assert_eq!(dgram.payload, payload);

        // A too-small buffer yields None, never a partial frame.
        let mut tiny = [0u8; 40];
        assert_eq!(build_udp_frame(&mut tiny, src, dst, 1, 2, payload), None);
        // A payload whose lengths overflow u16 is rejected, not truncated.
        assert_eq!(
            build_udp_frame(&mut buf, src, dst, 1, 2, &[0u8; u16::MAX as usize]),
            None
        );
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
