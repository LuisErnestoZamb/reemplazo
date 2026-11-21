//! TCP (RFC 9293) segment construction and validation: pure logic,
//! no I/O, no allocator — host-testable like the rest of `net`.
//!
//! Scope: what an active-open client needs — build (with options),
//! parse (with option skipping), and RFC 1982 sequence comparison.
//! Congestion control and out-of-order reassembly live above (see
//! `kernel::tcp` for this milestone's deliberate limits).

use crate::{
    ETHERNET_HDR, ETHERTYPE_IPV4, Endpoint, IPPROTO_TCP, checksum_with_pseudo, ethertype,
    internet_checksum, write_eth_ipv4,
};

/// TCP header flags (RFC 9293 §3.1.1).
pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

/// MSS option we advertise in SYN: kind=2, len=4, value=1460 (Ethernet
/// MTU minus the 20-byte IP and 20-byte TCP headers).
pub const MSS_OPTION: [u8; 4] = [0x02, 0x04, 0x05, 0xB4];

/// The fixed TCP header fields a sender chooses (the builder fills in
/// data offset, checksum, and urgent pointer itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// A validated TCP segment carried by an IPv4 frame. `payload` borrows
/// from the frame; TCP options are skipped via the data-offset field
/// (this client reads none — it only *sends* MSS).
#[derive(Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

/// RFC 1982 serial comparison: `a < b` in mod-2^32 sequence space.
/// The ambiguous distance-2^31 case returns false — RFC 1982 leaves it
/// undefined and callers only ever compare nearby numbers.
pub fn seq_lt(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) as i32 > 0
}

/// RFC 1982: `a <= b`.
pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// RFC 1982: `a > b`.
pub fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

/// RFC 1982: `a >= b`.
pub fn seq_ge(a: u32, b: u32) -> bool {
    a == b || seq_gt(a, b)
}

/// Build eth + IPv4 + TCP around `options` and `payload` and return the
/// frame length, or `None` if `buf` is too small or the lengths do not
/// fit the header fields (checked, never truncated).
///
/// `options` must be a whole number of 32-bit words and at most 40
/// bytes (RFC 9293 §3.1 data-offset limits); the checksum is computed
/// last, over the pseudo-header and the complete segment — an
/// unfinished payload here would repeat the bug that once broke DHCP.
pub fn build_frame(
    buf: &mut [u8],
    src: Endpoint,
    dst: Endpoint,
    hdr: TcpHeader,
    options: &[u8],
    payload: &[u8],
) -> Option<usize> {
    if options.len() > 40 || !options.len().is_multiple_of(4) {
        return None; // data offset counts whole 32-bit words, ≤ 60 bytes
    }
    let hdr_len = 20 + options.len();
    let transport_len = hdr_len + payload.len();
    // DF: our segments are always far below the MTU; never fragment.
    let total = write_eth_ipv4(buf, src, dst, IPPROTO_TCP, transport_len, 0, 0x4000)?;

    let seg = &mut buf[ETHERNET_HDR + 20..total];
    seg[0..2].copy_from_slice(&hdr.src_port.to_be_bytes());
    seg[2..4].copy_from_slice(&hdr.dst_port.to_be_bytes());
    seg[4..8].copy_from_slice(&hdr.seq.to_be_bytes());
    seg[8..12].copy_from_slice(&hdr.ack.to_be_bytes());
    // Data offset in the high nibble (whole words, ≤ 15); reserved and
    // NS bits stay zero. The checksum and urgent-pointer slots are
    // still zero from `write_eth_ipv4`'s frame-wide fill.
    seg[12] = u8::try_from(hdr_len / 4).ok()? << 4;
    seg[13] = hdr.flags;
    seg[14..16].copy_from_slice(&hdr.window.to_be_bytes());
    seg[20..20 + options.len()].copy_from_slice(options);
    seg[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);

    let csum = checksum_with_pseudo(src.ip, dst.ip, IPPROTO_TCP, seg);
    seg[16..18].copy_from_slice(&csum.to_be_bytes());
    Some(total)
}

/// Parse eth + IPv4 + TCP from a received frame. Every field is
/// validated: IPv4 checksum, protocol, TCP data offset (≥ 20 bytes and
/// within the segment — the same check slirp applies), and the TCP
/// checksum over the pseudo-header and the *complete* segment.
///
/// Unlike UDP there is **no zero-checksum escape**: RFC 9293 makes the
/// TCP checksum mandatory, so a zero field is validated like any other
/// value. Anything else — corrupt frames, foreign traffic, fragments
/// arriving truncated — yields `None` and is dropped by the caller.
pub fn parse_frame(frame: &[u8]) -> Option<TcpSegment<'_>> {
    if ethertype(frame)? != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(ETHERNET_HDR..ETHERNET_HDR + 20)?;
    if ip[0] != 0x45 || ip[9] != IPPROTO_TCP {
        return None; // no IP options (IHL must be 5), must be TCP
    }
    if internet_checksum(ip) != 0 {
        return None; // corrupt IPv4 header
    }
    let ip_total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let tcp = frame.get(ETHERNET_HDR + 20..ETHERNET_HDR + ip_total)?;
    if tcp.len() < 20 {
        return None;
    }
    let data_off = usize::from(tcp[12] >> 4) * 4;
    if data_off < 20 || data_off > tcp.len() {
        return None; // header shorter than the fixed 20 or past the segment
    }
    let src_ip: [u8; 4] = ip[12..16].try_into().ok()?;
    let dst_ip: [u8; 4] = ip[16..20].try_into().ok()?;
    if checksum_with_pseudo(src_ip, dst_ip, IPPROTO_TCP, tcp) != 0 {
        return None; // corrupt TCP header/options/payload
    }
    Some(TcpSegment {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
        ack: u32::from_be_bytes(tcp[8..12].try_into().ok()?),
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        payload: tcp.get(data_off..)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IPPROTO_UDP;

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x03];
    const OUR_IP: [u8; 4] = [10, 0, 2, 15];
    const PEER_IP: [u8; 4] = [140, 82, 112, 3];

    fn hdr(flags: u8) -> TcpHeader {
        TcpHeader {
            src_port: 49152,
            dst_port: 80,
            seq: 0x0102_0304,
            ack: 0x0506_0708,
            flags,
            window: 2048,
        }
    }

    fn endpoints() -> (Endpoint, Endpoint) {
        (
            Endpoint::new(OUR_MAC, OUR_IP),
            Endpoint::new(PEER_MAC, PEER_IP),
        )
    }

    #[test]
    fn syn_frame_layout_is_exact() {
        let (src, dst) = endpoints();
        let mut buf = [0u8; 128];
        let n = build_frame(&mut buf, src, dst, hdr(FLAG_SYN), &MSS_OPTION, &[])
            .expect("128-byte buffer must fit a 58-byte SYN");
        assert_eq!(n, 14 + 20 + 24); // eth + ip + 20-byte hdr + 4-byte MSS

        // Ethernet.
        assert_eq!(&buf[..6], &PEER_MAC);
        assert_eq!(&buf[6..12], &OUR_MAC);
        assert_eq!(&buf[12..14], &0x0800u16.to_be_bytes());

        // IPv4: DF set, protocol TCP, checksum self-validates.
        assert_eq!(buf[14], 0x45);
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 44);
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 0x4000); // DF
        assert_eq!(buf[23], IPPROTO_TCP);
        assert_eq!(internet_checksum(&buf[14..34]), 0);

        // TCP: ports, seq/ack, data offset 6 (24 bytes), flags, window,
        // zero urgent pointer, MSS option, checksum self-validates.
        assert_eq!(u16::from_be_bytes([buf[34], buf[35]]), 49152);
        assert_eq!(u16::from_be_bytes([buf[36], buf[37]]), 80);
        assert_eq!(
            u32::from_be_bytes(buf[38..42].try_into().unwrap()),
            0x0102_0304
        );
        assert_eq!(
            u32::from_be_bytes(buf[42..46].try_into().unwrap()),
            0x0506_0708
        );
        assert_eq!(buf[46], 6 << 4); // data offset 6, reserved/NS zero
        assert_eq!(buf[47], FLAG_SYN);
        assert_eq!(u16::from_be_bytes([buf[48], buf[49]]), 2048);
        // The checksum slot is filled in by the builder (its zeroed
        // placeholder is what gets summed); the self-validating
        // assertion at the end proves the stored value is correct.
        assert_ne!(&buf[50..52], &0u16.to_be_bytes());
        assert_eq!(&buf[52..54], &0u16.to_be_bytes()); // urgent pointer
        assert_eq!(&buf[54..58], &MSS_OPTION);
        assert_eq!(
            checksum_with_pseudo(OUR_IP, PEER_IP, IPPROTO_TCP, &buf[34..n]),
            0
        );
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let (src, dst) = endpoints();
        let payload = b"GET / HTTP/1.1\r\n";
        let mut buf = [0u8; 128];
        let n = build_frame(&mut buf, src, dst, hdr(FLAG_PSH | FLAG_ACK), &[], payload)
            .expect("must fit");
        assert_eq!(n, 14 + 20 + 20 + payload.len());

        let seg = parse_frame(&buf[..n]).expect("must parse");
        assert_eq!(seg.src_ip, OUR_IP);
        assert_eq!(seg.dst_ip, PEER_IP);
        assert_eq!(seg.src_port, 49152);
        assert_eq!(seg.dst_port, 80);
        assert_eq!(seg.seq, 0x0102_0304);
        assert_eq!(seg.ack, 0x0506_0708);
        assert_eq!(seg.flags, FLAG_PSH | FLAG_ACK);
        assert_eq!(seg.window, 2048);
        assert_eq!(seg.payload, payload);
    }

    #[test]
    fn parse_rejects_corruption() {
        let (src, dst) = endpoints();
        let mut buf = [0u8; 128];
        let n = build_frame(&mut buf, src, dst, hdr(FLAG_ACK), &[], b"payload!").expect("must fit");

        // A flipped payload byte breaks the TCP checksum.
        let mut bad = buf;
        bad[n - 1] ^= 0xFF;
        assert_eq!(parse_frame(&bad[..n]), None);

        // A flipped IP field breaks the IPv4 checksum.
        let mut bad = buf;
        bad[22] ^= 0x01; // TTL
        assert_eq!(parse_frame(&bad[..n]), None);

        // Not IPv4, and not TCP (protocol byte patched, checksum repaired
        // so the protocol check itself is what rejects).
        let mut bad = buf;
        bad[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(parse_frame(&bad[..n]), None);
        let mut bad = buf;
        bad[23] = IPPROTO_UDP;
        let ip_csum = internet_checksum(&bad[14..34]);
        bad[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        assert_eq!(parse_frame(&bad[..n]), None);
    }

    #[test]
    fn parse_rejects_every_truncation() {
        let (src, dst) = endpoints();
        let mut buf = [0u8; 128];
        let n = build_frame(&mut buf, src, dst, hdr(FLAG_ACK), &MSS_OPTION, b"hello").expect("f");
        for len in 0..n {
            assert_eq!(parse_frame(&buf[..len]), None, "len={len}");
        }
    }

    #[test]
    fn parse_validates_data_offset() {
        let (src, dst) = endpoints();
        let mut buf = [0u8; 128];
        let n = build_frame(&mut buf, src, dst, hdr(FLAG_ACK), &[], b"xy").expect("must fit");

        // Offset 4 → 16 bytes, below the mandatory 20: rejected even
        // with a repaired checksum (so the offset check is what fires).
        let mut bad = buf;
        bad[46] = 4 << 4;
        repair_tcp_csum(&mut bad[..n]);
        assert_eq!(parse_frame(&bad[..n]), None);

        // Offset 15 → 60 bytes, past the 42-byte segment: rejected.
        let mut bad = buf;
        bad[46] = 15 << 4;
        repair_tcp_csum(&mut bad[..n]);
        assert_eq!(parse_frame(&bad[..n]), None);
    }

    #[test]
    fn build_rejects_bad_options_and_buffers() {
        let (src, dst) = endpoints();
        let mut buf = [0u8; 128];
        // Options must be whole 32-bit words, at most 40 bytes.
        assert_eq!(
            build_frame(&mut buf, src, dst, hdr(FLAG_SYN), &[1, 2, 3], &[]),
            None
        );
        assert_eq!(
            build_frame(&mut buf, src, dst, hdr(FLAG_SYN), &[0; 44], &[]),
            None
        );
        // A payload that overflows the u16 length fields is rejected,
        // never truncated.
        let huge = [0u8; u16::MAX as usize];
        assert_eq!(
            build_frame(&mut buf, src, dst, hdr(FLAG_ACK), &[], &huge),
            None
        );
        // Too-small buffer.
        let mut tiny = [0u8; 40];
        assert_eq!(
            build_frame(&mut tiny, src, dst, hdr(FLAG_SYN), &[], &[]),
            None
        );
    }

    #[test]
    fn seq_comparison_wraps() {
        // Plain ordering.
        assert!(seq_lt(1, 2));
        assert!(!seq_lt(2, 1));
        assert!(!seq_lt(5, 5));
        assert!(seq_le(5, 5));
        assert!(seq_gt(6, 5));
        assert!(seq_ge(5, 5));

        // Across the u32 wrap: 0xFFFFFFF0 is *before* 0x10.
        assert!(seq_lt(0xFFFF_FFF0, 0x10));
        assert!(seq_gt(0x10, 0xFFFF_FFF0));
        assert!(seq_ge(0x10, 0xFFFF_FFF0));
        assert!(!seq_lt(0x10, 0xFFFF_FFF0));

        // The ambiguous distance-2^31 case: RFC 1982 leaves it
        // undefined; we define it as "not less than" and pin that.
        assert!(!seq_lt(0, 0x8000_0000));
        assert!(!seq_gt(0, 0x8000_0000));
    }

    /// Recompute the TCP checksum after a test patched the header, so
    /// the assertion under test is the *only* thing that can reject.
    fn repair_tcp_csum(frame: &mut [u8]) {
        let ip_total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        let src_ip: [u8; 4] = frame[26..30].try_into().unwrap();
        let dst_ip: [u8; 4] = frame[30..34].try_into().unwrap();
        let tcp = &mut frame[34..14 + ip_total];
        tcp[16..18].fill(0);
        let csum = checksum_with_pseudo(src_ip, dst_ip, IPPROTO_TCP, tcp);
        tcp[16..18].copy_from_slice(&csum.to_be_bytes());
    }
}
