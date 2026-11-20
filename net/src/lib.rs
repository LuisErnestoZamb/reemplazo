//! Pure Ethernet/ARP frame construction and parsing: no I/O, no allocator,
//! every length bounds-checked — host-testable like `bootinfo` and `pci`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// EtherType for Address Resolution Protocol (IEEE 802.3).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// ARP hardware type: Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type: IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

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
}
