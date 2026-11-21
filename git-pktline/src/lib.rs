//! git wire framing: **pkt-line** decoding/encoding and the v0
//! smart-HTTP `git-upload-pack` advertisement, for the `git ls-remote`
//! milestone (G1 of docs/git-ssh-deps.md).
//!
//! From-scratch under the skill's exception (a): `gix-packetline` is
//! std-only (`bstr`/`faster-hex` force it) and the no_std-looking
//! alternatives are weeks old and unaudited (docs/git-ssh-deps.md
//! §A.2). The format is fully specified by git's pack-protocol and
//! http-protocol docs; every path here is adversarially tested —
//! [`decode`] is fed one byte at a time in the tests.
//!
//! No allocator: everything parses into slices of the caller's body
//! buffer (the kernel bounds that buffer before calling in).

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// A decoded pkt-line. The four-hex length counts the payload only;
/// `0000` is flush, `0001` is the response delimiter (protocol v1+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkt<'a> {
    /// A data line — payload of `len - 4` bytes (may be empty).
    Data(&'a [u8]),
    /// `0000` — flush-pkt: ends a section.
    Flush,
    /// `0001` — response-end/delimiter.
    Delim,
}

/// Why a pkt-line stream was refused. Fail-closed: an error means
/// "discard the whole response", never "skip the bad line and hope".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not four hex digits, or a data length of `0002`/`0003` (no
    /// meaning in either protocol direction).
    InvalidHeader,
    /// The body ended mid-line — the caller declared the HTTP body
    /// complete, so this is truncation, not a partial read.
    Truncated,
    /// A response delimiter (`0001`) where only v0 data/flush is legal.
    UnexpectedDelim,
    /// First line was not `# service=git-upload-pack\n`, or its
    /// section was malformed (service line not followed by flush).
    WrongService,
    /// The body starts with a flush — the service header is missing.
    MissingServiceHeader,
    /// A ref line without `<40-hex-oid> <name>`.
    MalformedRef,
    /// Bytes after the final flush of a well-formed advertisement.
    TrailingGarbage,
}

/// Result of one [`decode`] step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<'a> {
    /// Need more bytes (feed again).
    Incomplete,
    /// One complete line consumed from the front of the buffer.
    Done { consumed: usize, pkt: Pkt<'a> },
    /// The stream is malformed — stop.
    Failed(Error),
}

/// Decode the pkt-line at the front of `buf`. Strict: exactly four
/// ASCII hex digits (either case); `0000`/`0001` are control lines;
/// `0002`/`0003` are corrupt (they cannot encode a payload).
pub fn decode(buf: &[u8]) -> Step<'_> {
    if buf.len() < 4 {
        return Step::Incomplete;
    }
    let mut digits = [0u8; 4];
    for (slot, &byte) in digits.iter_mut().zip(&buf[..4]) {
        match hex(byte) {
            Ok(digit) => *slot = digit,
            Err(e) => return Step::Failed(e),
        }
    }
    let len = usize::from(digits[0]) * 4096
        + usize::from(digits[1]) * 256
        + usize::from(digits[2]) * 16
        + usize::from(digits[3]);
    match len {
        0 => Step::Done {
            consumed: 4,
            pkt: Pkt::Flush,
        },
        1 => Step::Done {
            consumed: 4,
            pkt: Pkt::Delim,
        },
        2 | 3 => Step::Failed(Error::InvalidHeader),
        _ => {
            if buf.len() < len {
                Step::Incomplete
            } else {
                Step::Done {
                    consumed: len,
                    pkt: Pkt::Data(&buf[4..len]),
                }
            }
        }
    }
}

fn hex(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidHeader),
    }
}

/// Encode one data pkt-line (payload ≤ 65_531) into `out`; `None` when
/// it does not fit. The four-hex header counts payload + 4.
pub fn encode_data(payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = payload.len().checked_add(4)?;
    if total > 0xFFFF {
        return None;
    }
    let out = out.get_mut(..total)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let len = u16::try_from(total).ok()?; // total ≤ 0xFFFF checked above
    out[0] = HEX[usize::from(len >> 12)];
    out[1] = HEX[usize::from((len >> 8) & 0xF)];
    out[2] = HEX[usize::from((len >> 4) & 0xF)];
    out[3] = HEX[usize::from(len & 0xF)];
    out[4..].copy_from_slice(payload);
    Some(total)
}

/// Encode a flush-pkt (`0000`) into `out`.
pub fn encode_flush(out: &mut [u8]) -> Option<usize> {
    out.get_mut(..4)?.copy_from_slice(b"0000");
    Some(4)
}

/// One advertised reference of a v0 upload-pack advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ref<'a> {
    /// The target object id — exactly 40 hex digits (validated).
    pub oid: &'a str,
    /// The reference name (bytes after the first space; for the first
    /// line, up to the NUL that introduces the capabilities).
    pub name: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Expecting `# service=git-upload-pack\n`.
    Service,
    /// Expecting the flush that ends the service header.
    ServiceFlush,
    /// Expecting refs until the final flush.
    Refs,
    /// Cleanly finished.
    Done,
}

/// Iterator over the refs of a **complete** v0 smart-HTTP
/// advertisement body (service header → flush → refs → flush). The
/// caller must only pass a body the HTTP layer declared complete —
/// an incomplete body surfaces as [`Error::Truncated`], never as a
/// partial ref list.
pub struct Refs<'a> {
    buf: &'a [u8],
    pos: usize,
    stage: Stage,
    /// Capabilities from the first ref line (after the NUL).
    caps: Option<&'a [u8]>,
}

impl<'a> Refs<'a> {
    /// Start parsing a complete advertisement body.
    pub fn new(body: &'a [u8]) -> Self {
        Refs {
            buf: body,
            pos: 0,
            stage: Stage::Service,
            caps: None,
        }
    }

    /// Capabilities of the server — only available after the first
    /// [`Refs::next`] call (they ride on the first ref line).
    pub fn capabilities(&self) -> Option<&'a [u8]> {
        self.caps
    }

    /// Next reference: `Ok(None)` = clean end (final flush), `Err` =
    /// the stream is malformed (stop parsing — never skip a line).
    /// Deliberately not called `next`: this type is not an Iterator
    /// (clippy's `should_implement_trait` and readers both agree).
    pub fn next_ref(&mut self) -> Result<Option<Ref<'a>>, Error> {
        loop {
            if self.stage == Stage::Done {
                return Ok(None);
            }
            let step = decode(&self.buf[self.pos..]);
            let pkt = match step {
                Step::Incomplete => return Err(Error::Truncated),
                Step::Failed(e) => return Err(e),
                Step::Done { consumed, pkt } => {
                    self.pos += consumed;
                    pkt
                }
            };
            match (self.stage, pkt) {
                (Stage::Service, Pkt::Data(line)) => {
                    if line != b"# service=git-upload-pack\n" {
                        return Err(Error::WrongService);
                    }
                    self.stage = Stage::ServiceFlush;
                }
                (Stage::Service, Pkt::Flush) => return Err(Error::MissingServiceHeader),
                (Stage::Service, Pkt::Delim) | (Stage::ServiceFlush, Pkt::Delim) => {
                    return Err(Error::UnexpectedDelim);
                }
                (Stage::ServiceFlush, Pkt::Flush) => self.stage = Stage::Refs,
                (Stage::ServiceFlush, Pkt::Data(_)) => return Err(Error::WrongService),
                (Stage::Refs, Pkt::Data(line)) => {
                    let parsed = parse_ref(line)?;
                    if self.caps.is_none() {
                        self.caps = parsed.caps;
                    }
                    return Ok(Some(Ref {
                        oid: parsed.oid,
                        name: parsed.name,
                    }));
                }
                (Stage::Refs, Pkt::Flush) => {
                    if self.pos != self.buf.len() {
                        return Err(Error::TrailingGarbage);
                    }
                    self.stage = Stage::Done;
                    return Ok(None);
                }
                (Stage::Refs, Pkt::Delim) => return Err(Error::UnexpectedDelim),
                (Stage::Done, _) => return Ok(None),
            }
        }
    }
}

/// The pieces of one `<40-hex-oid> <name>[\0<capabilities>]` ref line.
struct ParsedRef<'a> {
    oid: &'a str,
    name: &'a [u8],
    caps: Option<&'a [u8]>,
}

/// Split a ref line; the capabilities (spec: only ever on the first
/// line) come back separately so the name never includes them.
fn parse_ref(line: &[u8]) -> Result<ParsedRef<'_>, Error> {
    let space = line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(Error::MalformedRef)?;
    let oid_bytes = &line[..space];
    if oid_bytes.len() != 40 || !oid_bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::MalformedRef);
    }
    let oid = core::str::from_utf8(oid_bytes).map_err(|_| Error::MalformedRef)?;
    let rest = &line[space + 1..];
    let (name, caps) = match rest.iter().position(|&b| b == 0) {
        Some(nul) => (&rest[..nul], Some(&rest[nul + 1..])),
        None => (rest, None),
    };
    if name.is_empty() {
        return Err(Error::MalformedRef);
    }
    Ok(ParsedRef { oid, name, caps })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `payload` in a pkt-line with the correct four-hex length.
    fn pkt(payload: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec![0u8; 4 + payload.len()];
        let n = encode_data(payload, &mut out).expect("fits");
        out.truncate(n);
        out
    }

    fn adv_body() -> std::vec::Vec<u8> {
        let mut body = std::vec::Vec::new();
        body.extend_from_slice(&pkt(b"# service=git-upload-pack\n"));
        body.extend_from_slice(b"0000");
        let mut first = b"0123456789abcdef0123456789abcdef01234567 refs/heads/main\0".to_vec();
        first.extend_from_slice(b"multi_ack_detailed side-band-64k symref=HEAD:refs/heads/main");
        body.extend_from_slice(&pkt(&first));
        body.extend_from_slice(&pkt(
            b"fedcba9876543210fedcba9876543210fedcba98 refs/tags/v0.1",
        ));
        body.extend_from_slice(b"0000");
        body
    }

    #[test]
    fn decode_feeds_one_byte_at_a_time() {
        let line = pkt(b"hello world");
        for split in 0..=line.len() {
            let mut decoder_input = std::vec::Vec::new();
            decoder_input.extend_from_slice(&line[..split]);
            let step = decode(&decoder_input);
            if split < line.len() {
                assert_eq!(step, Step::Incomplete, "split {split} of {}", line.len());
            } else {
                match step {
                    Step::Done {
                        consumed,
                        pkt: Pkt::Data(payload),
                    } => {
                        assert_eq!(consumed, line.len());
                        assert_eq!(payload, b"hello world");
                    }
                    other => panic!("expected Done, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn decode_control_lines_and_corruption() {
        assert_eq!(
            decode(b"0000"),
            Step::Done {
                consumed: 4,
                pkt: Pkt::Flush
            }
        );
        assert_eq!(
            decode(b"0001"),
            Step::Done {
                consumed: 4,
                pkt: Pkt::Delim
            }
        );
        // "0009" =9 total = "extra" (5) payload.
        assert_eq!(
            decode(b"0009extra"),
            Step::Done {
                consumed: 9,
                pkt: Pkt::Data(&b"extra"[..])
            }
        );
        //0002/0003 cannot encode a payload; non-hex is refused; short
        // prefixes wait.
        assert_eq!(decode(b"0002"), Step::Failed(Error::InvalidHeader));
        assert_eq!(decode(b"0003"), Step::Failed(Error::InvalidHeader));
        assert_eq!(decode(b"zzzz"), Step::Failed(Error::InvalidHeader));
        assert_eq!(decode(b"000g"), Step::Failed(Error::InvalidHeader));
        assert_eq!(decode(b"000"), Step::Incomplete);
        assert_eq!(decode(b""), Step::Incomplete);
        // Uppercase hex is legal.
        match decode(b"0009EXTRA") {
            Step::Done {
                consumed,
                pkt: Pkt::Data(payload),
            } => {
                assert_eq!((consumed, payload), (9, &b"EXTRA"[..]))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn decode_waits_for_a_declared_but_missing_payload() {
        let mut buf = std::vec::Vec::from(&b"000c"[..]);
        buf.extend_from_slice(b"abc"); // declares8 payload bytes, only3 here
        assert_eq!(decode(&buf), Step::Incomplete);
        buf.extend_from_slice(b"defgh"); // now exactly8 payload bytes
        match decode(&buf) {
            Step::Done {
                consumed,
                pkt: Pkt::Data(payload),
            } => {
                assert_eq!((consumed, payload), (12, &b"abcdefgh"[..]));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn encode_roundtrips_and_bounds() {
        let mut out = [0u8; 64];
        let n = encode_data(b"payload!", &mut out[..]).expect("fits");
        assert_eq!(&out[..4], b"000c");
        match decode(&out[..n]) {
            Step::Done {
                consumed,
                pkt: Pkt::Data(payload),
            } => {
                assert_eq!((consumed, payload), (12, &b"payload!"[..]))
            }
            other => panic!("{other:?}"),
        }
        let n = encode_flush(&mut out[..]).expect("fits");
        assert_eq!((&out[..n], n), (b"0000".as_slice(), 4));
        // Payload too large for the four-hex length / buffer too small.
        let big = [0u8; 65_532];
        assert_eq!(encode_data(&big, &mut out[..]), None); // total > 0xFFFF
        assert_eq!(encode_data(b"12345678", &mut [0u8; 6][..]), None);
    }

    #[test]
    fn max_length_edge_case() {
        // "ffff" = 65535 total = 65531 payload bytes.
        let mut buf = [0u8; 4];
        buf.copy_from_slice(b"ffff");
        let mut full = std::vec::Vec::from(&buf[..]);
        full.extend(core::iter::repeat_n(b'x', 65_531));
        match decode(&full) {
            Step::Done {
                consumed,
                pkt: Pkt::Data(payload),
            } => {
                assert_eq!((consumed, payload.len()), (65_535, 65_531))
            }
            other => panic!("{other:?}"),
        }
        // One byte short stays Incomplete — never a partial payload.
        full.pop();
        assert_eq!(decode(&full), Step::Incomplete);
    }

    #[test]
    fn advertisement_lists_refs_with_capabilities() {
        let body = adv_body();
        let mut refs = Refs::new(&body);
        let first = refs.next_ref().expect("ref1").expect("parses");
        assert_eq!(first.oid, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(first.name, b"refs/heads/main");
        // Capabilities ride on the first line, after the NUL.
        assert_eq!(
            refs.capabilities(),
            Some(&b"multi_ack_detailed side-band-64k symref=HEAD:refs/heads/main"[..])
        );
        let second = refs.next_ref().expect("ref2").expect("parses");
        assert_eq!(second.oid, "fedcba9876543210fedcba9876543210fedcba98");
        assert_eq!(second.name, b"refs/tags/v0.1");
        assert_eq!(refs.next_ref(), Ok(None));
        assert_eq!(refs.next_ref(), Ok(None)); // idempotent after the end
    }

    #[test]
    fn advertisement_rejects_wrong_service_header() {
        let mut body = pkt(b"# service=git-receive-pack\n");
        body.extend_from_slice(b"0000");
        let mut refs = Refs::new(&body);
        assert_eq!(refs.next_ref(), Err(Error::WrongService));
    }

    #[test]
    fn advertisement_rejects_missing_service_header() {
        let mut body = std::vec::Vec::from(b"0000".as_slice());
        body.extend_from_slice(&pkt(
            b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef refs/heads/main",
        ));
        body.extend_from_slice(b"0000");
        let mut refs = Refs::new(&body);
        assert_eq!(refs.next_ref(), Err(Error::MissingServiceHeader));
    }

    #[test]
    fn advertisement_rejects_malformed_refs() {
        // Not40 hex, missing space, empty name, non-hex oid.
        for bad in [
            &b"0123456789abcdef0123456789abcdef0123456 refs/heads/main"[..], //39 hex
            b"0123456789abcdef0123456789abcdef01234567refs/heads/main",      // no space
            b"0123456789abcdef0123456789abcdef01234567 ",                    // empty name
            b"0123456789abcdef0123456789abcdef0123456Z refs/heads/main",     // non-hex
        ] {
            let mut body = pkt(b"# service=git-upload-pack\n");
            body.extend_from_slice(b"0000");
            body.extend_from_slice(&pkt(bad));
            body.extend_from_slice(b"0000");
            let mut refs = Refs::new(&body);
            assert_eq!(
                refs.next_ref(),
                Err(Error::MalformedRef),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn advertisement_rejects_truncation_and_trailing_garbage() {
        // Body cut mid-ref-line: the caller declared completeness, so
        // this is truncation.
        let mut body = pkt(b"# service=git-upload-pack\n");
        body.extend_from_slice(b"0000");
        body.extend_from_slice(&pkt(
            b"0123456789abcdef0123456789abcdef01234567 refs/heads/main",
        ));
        body.pop(); // cut before the final flush
        let mut refs = Refs::new(&body);
        assert_eq!(refs.next_ref().err(), Some(Error::Truncated));
        // Bytes after the final flush.
        let mut body = adv_body();
        body.extend_from_slice(b"junk");
        let mut refs = Refs::new(&body);
        assert!(refs.next_ref().expect("ref1").is_some());
        assert!(refs.next_ref().expect("ref2").is_some());
        assert_eq!(refs.next_ref(), Err(Error::TrailingGarbage));
    }

    #[test]
    fn advertisement_rejects_delim_and_empty_body() {
        let mut body = pkt(b"# service=git-upload-pack\n");
        body.extend_from_slice(b"0001"); // v1 delimiter
        let mut refs = Refs::new(&body);
        assert_eq!(refs.next_ref(), Err(Error::UnexpectedDelim));
        // Empty body: incomplete at byte0 — the caller passed a
        // "complete" body that holds nothing.
        let mut refs = Refs::new(b"");
        assert_eq!(refs.next_ref(), Err(Error::Truncated));
    }
}
