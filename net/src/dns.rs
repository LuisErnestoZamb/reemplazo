//! DNS (RFC 1035) — A-record query builder and response parser.
//!
//! Pure logic, no I/O, no allocator — host-testable like the rest of
//! `net`. The security-sensitive part is [`decode_name`]: DNS names use
//! compression pointers that can form loops, so the walker only ever
//! follows pointers to a *strictly earlier* offset and caps the decoded
//! name at 255 bytes. Every loop iteration therefore either decreases
//! the offset or grows the name, and both are bounded — a hostile
//! response cannot hang the parser or overrun a buffer.

/// DNS port (IANA service port for domain name servers).
pub const PORT: u16 = 53;

/// Header size in bytes (RFC 1035 §4.1.1).
const HEADER_LEN: usize = 12;
/// Maximum wire length of a domain name, length octets included
/// (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;
/// Query type A — the only type this resolver asks for.
const TYPE_A: u16 = 1;
/// Query class IN — the only class we accept answers for.
const CLASS_IN: u16 = 1;

// Header flag bits (RFC 1035 §4.1.1).
const FLAG_QR: u16 = 0x8000; // response (1) vs query (0)
const FLAG_TC: u16 = 0x0200; // truncated — no TCP fallback yet, reject
const FLAG_RD: u16 = 0x0100; // recursion desired (set on our queries)
const RCODE_MASK: u16 = 0x000F; // response code (0 = NoError)

/// A decoded domain name in canonical wire form: label-length octets,
/// label bytes, and the root octet — byte-comparable between the
/// question we sent and the one the server echoed back.
#[derive(Debug, PartialEq, Eq)]
struct Name {
    len: usize,
    wire: [u8; MAX_NAME_LEN],
}

fn push(name: &mut Name, byte: u8) -> Option<()> {
    let slot = name.wire.get_mut(name.len)?;
    *slot = byte;
    name.len += 1;
    Some(())
}

/// Walk the domain name starting at `buf[start]`, returning its
/// canonical encoding and the offset just past the name *in the
/// original stream*.
///
/// Termination argument (this parses attacker-controlled bytes):
/// - the root octet ends the walk;
/// - a compression pointer must target a strictly smaller offset
///   (`target >= pos` is rejected), so pointer steps only ever move
///   backward and can happen at most `buf.len()` times between labels;
/// - a regular label appends ≥ 2 bytes to `out`, and `out` is capped at
///   255, so at most 127 labels are ever consumed.
///
/// Together, the walk always terminates. Forward/self pointers and the
/// reserved label types `01`/`10` are rejected outright — no legitimate
/// server emits them, and accepting them would weaken the argument.
fn decode_name(buf: &[u8], start: usize) -> Option<(Name, usize)> {
    let mut out = Name {
        len: 0,
        wire: [0; MAX_NAME_LEN],
    };
    let mut pos = start;
    let mut end = 0usize;
    let mut jumped = false;
    loop {
        let &len = buf.get(pos)?;
        if len == 0 {
            push(&mut out, 0)?;
            if !jumped {
                end = pos + 1;
            }
            return Some((out, end));
        }
        if len & 0xC0 == 0xC0 {
            let target = (usize::from(len & 0x3F) << 8) | usize::from(*buf.get(pos + 1)?);
            if target >= pos {
                return None; // forward or self pointer: reject
            }
            if !jumped {
                end = pos + 2; // the name ends here in the original stream
                jumped = true;
            }
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None; // reserved label type (RFC 1035 §3.1)
        }
        let next = pos.checked_add(1 + usize::from(len))?;
        let label = buf.get(pos + 1..next)?;
        push(&mut out, len)?;
        for &b in label {
            push(&mut out, b)?;
        }
        if !jumped {
            end = next;
        }
        pos = next;
    }
}

/// Build a standard recursive A-record query for `qname` ("github.com")
/// into `buf`, returning the query length.
///
/// Rejects (returns `None`) any name that violates RFC 1035: an empty
/// label — which also rejects the trailing-dot form, callers must pass
/// `example.com` — a label longer than 63 bytes, a wire name longer
/// than 255 bytes, or a buffer too small for header + name + type/class.
pub fn build_query(buf: &mut [u8], txid: u16, qname: &str) -> Option<usize> {
    // Validate every label first so a rejected name writes nothing.
    let mut name_len = 1usize; // root octet
    for label in qname.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return None;
        }
        name_len = name_len.checked_add(1 + len)?;
    }
    if name_len > MAX_NAME_LEN {
        return None;
    }

    let total = HEADER_LEN.checked_add(name_len)?.checked_add(4)?;
    let b = buf.get_mut(..total)?;
    b.fill(0); // zero NSCOUNT/ARCOUNT and leave no stack junk in the frame

    // Header: txid, RD=1 + opcode QUERY, QDCOUNT=1, everything else 0.
    b[0..2].copy_from_slice(&txid.to_be_bytes());
    b[2..4].copy_from_slice(&FLAG_RD.to_be_bytes());
    b[4..6].copy_from_slice(&1u16.to_be_bytes());

    let mut pos = HEADER_LEN;
    for label in qname.split('.') {
        // Validated above: 1..=63, so the u8 length octet cannot truncate.
        b[pos] = label.len() as u8;
        b[pos + 1..pos + 1 + label.len()].copy_from_slice(label.as_bytes());
        pos += 1 + label.len();
    }
    b[pos] = 0; // root octet
    pos += 1;
    b[pos..pos + 2].copy_from_slice(&TYPE_A.to_be_bytes());
    b[pos + 2..pos + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    Some(total)
}

/// Parse an A-record answer out of a complete DNS response, validating
/// it against the exact `query` we transmitted (slice it with the
/// length [`build_query`] returned).
///
/// Accepts only a response that: carries our transaction id, is a
/// non-truncated response (QR=1, TC=0) with RCODE NoError, echoes
/// `query`'s question section (same canonical name — case-sensitive,
/// we query lowercase and servers echo it — plus same QTYPE/QCLASS),
/// and contains an answer of type A, class IN, RDLENGTH 4 with a
/// non-zero address. Any mismatch, truncation, or malformed byte
/// anywhere in the walk yields `None` — never a panic: every read is
/// bounds-checked and every length is computed with `checked_add`.
///
/// The answer's *owner* name is deliberately not compared with the
/// question: a CNAME chain (www.github.com → github.com → A) ends in an
/// A record owned by a different name, and the question echo plus
/// transaction id already ties the response to our query.
pub fn parse_a_response(buf: &[u8], query: &[u8]) -> Option<[u8; 4]> {
    let qh = query.get(..HEADER_LEN)?;
    let rh = buf.get(..HEADER_LEN)?;
    if rh[0..2] != qh[0..2] {
        return None; // not our transaction id
    }
    let flags = u16::from_be_bytes([rh[2], rh[3]]);
    if flags & FLAG_QR == 0 || flags & FLAG_TC != 0 {
        return None; // not a response, or truncated (no TCP fallback yet)
    }
    if flags & RCODE_MASK != 0 {
        return None; // NXDOMAIN / SERVFAIL / ...
    }
    if u16::from_be_bytes([rh[4], rh[5]]) != 1 {
        return None; // our queries always ask exactly one question
    }

    // The response must echo our question verbatim (canonically).
    let (our_name, our_end) = decode_name(query, HEADER_LEN)?;
    let (resp_name, resp_end) = decode_name(buf, HEADER_LEN)?;
    if our_name != resp_name {
        return None;
    }
    let our_tc = query.get(our_end..our_end + 4)?;
    let resp_tc = buf.get(resp_end..resp_end + 4)?;
    if our_tc != resp_tc {
        return None; // QTYPE/QCLASS echo differs from what we asked
    }
    let mut pos = resp_end.checked_add(4)?;

    let ancount = u16::from_be_bytes([rh[6], rh[7]]);
    for _ in 0..ancount {
        let (_, next) = decode_name(buf, pos)?;
        let rr = buf.get(next..next.checked_add(10)?)?;
        let rtype = u16::from_be_bytes([rr[0], rr[1]]);
        let rclass = u16::from_be_bytes([rr[2], rr[3]]);
        let rdlen = usize::from(u16::from_be_bytes([rr[8], rr[9]]));
        let rdata = buf.get(next + 10..next.checked_add(10 + rdlen)?)?;
        if rtype == TYPE_A && rclass == CLASS_IN && rdlen == 4 {
            let ip: [u8; 4] = rdata.try_into().ok()?;
            if ip == [0, 0, 0, 0] {
                return None; // 0.0.0.0 is never a usable answer
            }
            return Some(ip);
        }
        pos = next.checked_add(10 + rdlen)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const TXID: u16 = 0x7265;

    /// A well-formed query for "github.com" (28 bytes).
    fn query() -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = build_query(&mut buf, TXID, "github.com").expect("fits");
        buf[..n].to_vec()
    }

    /// A response echoing `query`'s question with the given answer
    /// section bytes (answer count inferred from `answers_len` by the
    /// caller passing `ancount` explicitly).
    fn response(query: &[u8], ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&query[0..2]); // txid echo
        v.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA
        v.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        v.extend_from_slice(&ancount.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        v.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        v.extend_from_slice(&query[HEADER_LEN..]); // question echo
        v.extend_from_slice(answers);
        v
    }

    /// One answer: owner name as a pointer to the question (0xC00C),
    /// type A, class IN, TTL 60, RDLENGTH 4, the address.
    fn a_record(ip: [u8; 4]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&[0xC0, 0x0C]);
        a.extend_from_slice(&TYPE_A.to_be_bytes());
        a.extend_from_slice(&CLASS_IN.to_be_bytes());
        a.extend_from_slice(&60u32.to_be_bytes());
        a.extend_from_slice(&4u16.to_be_bytes());
        a.extend_from_slice(&ip);
        a
    }

    #[test]
    fn query_layout_is_exact() {
        let q = query();
        assert_eq!(q.len(), 28); // 12 header + 12 name + 4 type/class
        assert_eq!(&q[0..2], &TXID.to_be_bytes());
        assert_eq!(&q[2..4], &FLAG_RD.to_be_bytes()); // RD=1, opcode QUERY
        assert_eq!(&q[4..6], &1u16.to_be_bytes()); // QDCOUNT=1
        assert_eq!(&q[6..12], &[0u8; 6]); // AN/NS/AR = 0
        assert_eq!(&q[12..19], b"\x06github");
        assert_eq!(&q[19..23], b"\x03com");
        assert_eq!(q[23], 0); // root
        assert_eq!(&q[24..28], &[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    }

    #[test]
    fn query_rejects_bad_names_and_buffers() {
        let mut buf = [0u8; 64];
        assert_eq!(build_query(&mut buf, TXID, ""), None); // empty
        assert_eq!(build_query(&mut buf, TXID, "a..b"), None); // empty label
        assert_eq!(build_query(&mut buf, TXID, "github.com."), None); // trailing dot
        assert_eq!(build_query(&mut buf, TXID, &"x".repeat(64)), None); // label > 63
        // 4 x 63-byte labels: 4*64 + 1 = 257 > 255 wire bytes.
        let label = "y".repeat(63);
        let long = vec![label; 4].join(".");
        assert_eq!(build_query(&mut buf, TXID, &long), None);
        // Fits the name but not the buffer: 12 + 12 + 4 = 28 > 20.
        assert_eq!(build_query(&mut buf[..20], TXID, "github.com"), None);
    }

    #[test]
    fn parses_a_complete_response() {
        let q = query();
        let ip = [140, 82, 112, 3];
        let resp = response(&q, 1, &a_record(ip));
        assert_eq!(parse_a_response(&resp, &q), Some(ip));
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let q = query();
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[0] ^= 0xFF; // corrupt txid
        assert_eq!(parse_a_response(&resp, &q), None);
    }

    #[test]
    fn rejects_query_echo_and_flags() {
        let q = query();
        let other = {
            let mut b = [0u8; 64];
            let n = build_query(&mut b, TXID, "evil.example").expect("fits");
            b[..n].to_vec()
        };
        // Response to a *different* question.
        let resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        assert_eq!(parse_a_response(&resp, &other), None);
        // Not a response (QR=0).
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[2] &= 0x7F;
        assert_eq!(parse_a_response(&resp, &q), None);
        // Truncated (TC=1) — no TCP fallback yet.
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[2] |= 0x02;
        assert_eq!(parse_a_response(&resp, &q), None);
        // RCODE = NXDOMAIN.
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[3] |= 3;
        assert_eq!(parse_a_response(&resp, &q), None);
        // QDCOUNT = 0 (we always ask exactly one question).
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse_a_response(&resp, &q), None);
    }

    #[test]
    fn truncation_never_panics() {
        let q = query();
        let resp = response(&q, 1, &a_record([9, 9, 9, 9]));
        // Every strict prefix must be rejected without panicking.
        for len in 0..resp.len() {
            assert_eq!(parse_a_response(&resp[..len], &q), None, "len={len}");
        }
        // And a truncated buffer as the *query* is rejected too.
        for len in 0..q.len() {
            assert_eq!(parse_a_response(&resp, &q[..len]), None, "qlen={len}");
        }
    }

    #[test]
    fn pointer_loops_terminate() {
        let q = query();
        // Self-pointer as the question name: 0xC00C at offset 12.
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[12..14].copy_from_slice(&[0xC0, 0x0C]);
        assert_eq!(parse_a_response(&resp, &q), None);
        // The nastier cycle: a label at 12 walks forward to 28 — where
        // the answer's own 0xC00C pointer sits — and that pointer jumps
        // back to 12, repeating. Each round appends 16 bytes to the
        // decode buffer, so the 255-byte cap breaks the cycle after ~15
        // rounds: this test completing at all is the point; it must
        // return None, not hang.
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        resp[12] = 15; // label of 15 bytes: 12 + 1 + 15 = 28
        assert_eq!(parse_a_response(&resp, &q), None);
        // Reserved label type 0x40 in an answer name (offset 28: the
        // answer section starts right after the 16-byte question).
        let mut resp = response(&q, 1, &a_record([1, 2, 3, 4]));
        let at = resp.len() - 16;
        resp[at] = 0x40;
        resp[at + 1] = 0x00;
        assert_eq!(parse_a_response(&resp, &q), None);
    }

    #[test]
    fn skips_cname_chain_to_reach_a() {
        let q = query();
        // Answer 1: CNAME (type 5) with a 3-byte rdata we must skip.
        let mut cname = Vec::new();
        cname.extend_from_slice(&[0xC0, 0x0C]);
        cname.extend_from_slice(&5u16.to_be_bytes()); // type CNAME
        cname.extend_from_slice(&CLASS_IN.to_be_bytes());
        cname.extend_from_slice(&60u32.to_be_bytes());
        cname.extend_from_slice(&3u16.to_be_bytes()); // rdlen
        cname.extend_from_slice(&[1, 2, 3]);
        // Answer 2: the A record, owned by an explicit *different* name
        // (the canonical target of the chain) — must still be accepted.
        let mut a = Vec::new();
        a.extend_from_slice(b"\x06github\x03com\0"); // owner: github.com
        a.extend_from_slice(&TYPE_A.to_be_bytes());
        a.extend_from_slice(&CLASS_IN.to_be_bytes());
        a.extend_from_slice(&60u32.to_be_bytes());
        a.extend_from_slice(&4u16.to_be_bytes());
        a.extend_from_slice(&[140, 82, 112, 3]);
        let mut answers = cname;
        answers.extend_from_slice(&a);
        let resp = response(&q, 2, &answers);
        assert_eq!(parse_a_response(&resp, &q), Some([140, 82, 112, 3]));
    }

    #[test]
    fn rejects_bad_answers() {
        let q = query();
        // No answers at all.
        let resp = response(&q, 0, &[]);
        assert_eq!(parse_a_response(&resp, &q), None);
        // Answer claims rdlen=4 but the message ends early.
        let mut a = a_record([1, 2, 3, 4]);
        a.truncate(a.len() - 2);
        let resp = response(&q, 1, &a);
        assert_eq!(parse_a_response(&resp, &q), None);
        // Type AAAA (28) instead of A: skipped, nothing left.
        let mut a = a_record([1, 2, 3, 4]);
        a[2..4].copy_from_slice(&28u16.to_be_bytes());
        let resp = response(&q, 1, &a);
        assert_eq!(parse_a_response(&resp, &q), None);
        // Class CH (3) instead of IN.
        let mut a = a_record([1, 2, 3, 4]);
        a[4..6].copy_from_slice(&3u16.to_be_bytes());
        let resp = response(&q, 1, &a);
        assert_eq!(parse_a_response(&resp, &q), None);
        // The all-zero address is rejected even though it parses.
        let resp = response(&q, 1, &a_record([0, 0, 0, 0]));
        assert_eq!(parse_a_response(&resp, &q), None);
        // ANCOUNT claims 0xFFFF answers but the only one present is a
        // non-A record: after skipping it the walk runs off the end of
        // the message and must yield None instead of reading past it.
        let mut a = a_record([1, 2, 3, 4]);
        a[2..4].copy_from_slice(&28u16.to_be_bytes()); // type AAAA
        let resp = response(&q, 0xFFFF, &a);
        assert_eq!(parse_a_response(&resp, &q), None);
        // Overclaimed ANCOUNT with a valid A first is harmless: the
        // walk returns the answer it already has and never reaches the
        // phantom entries.
        let resp = response(&q, 0xFFFF, &a_record([1, 2, 3, 4]));
        assert_eq!(parse_a_response(&resp, &q), Some([1, 2, 3, 4]));
    }
}
