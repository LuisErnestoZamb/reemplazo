//! Pure HTTP/1.1 response handling for the client milestones (browser,
//! git, AI client): head parsing on top of `httparse` — a known,
//! battle-tested, `no_std` crate (skill policy: use known crates) —
//! plus the incremental **body framer** the clients need.
//!
//! `httparse` parses heads only; the framer here covers the three body
//! codings of RFC 9112 §6.3:
//!
//! - `Content-Length` — exactly that many bytes, then complete;
//! - `Transfer-Encoding: chunked` — chunk extensions and trailers,
//!   with **strict CRLF** everywhere in the framing (a bare LF is
//!   refused, not accepted);
//! - close-delimited — no framing headers; the body ends at EOF.
//!
//! Framing selection is the smuggling defense (RFC 9112 §6.3):
//! `Transfer-Encoding` present ⇒ `Content-Length` is *ignored*; two
//! different `Content-Length` values are an error rather than a guess;
//! a transfer coding we cannot decode fails closed instead of handing
//! encoded bytes to the caller as plain text. Statuses that never
//! carry a body (1xx/204/304) complete immediately, discarding
//! anything after the head.
//!
//! This framer is from-scratch under the skill's exception (a): no
//! maintained `no_std` body-framing crate exists (httparse is
//! head-only; `http-body` and friends need std/alloc).
//!
//! Adversarial tests below feed every message **one byte at a time**
//! as well as whole, so no split point can hide a state bug.

use httparse::{EMPTY_HEADER, Header, Response, Status};

/// Maximum accumulated head (status line + headers). A larger head is
/// refused with [`Error::HeadTooLarge`] — never truncated.
pub const HEAD_CAP: usize = 8192;
/// Header slots handed to httparse; more lines than this surface as
/// [`Error::TooManyHeaders`].
const MAX_HEADERS: usize = 64;
/// Longest chunk-size line (hex digits + extension) buffered.
const LINE_CAP: usize = 128;

/// Why a response was refused. Every variant is fail-closed: an error
/// means "stop and discard", never "best effort".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The head grew past [`HEAD_CAP`] without its terminating blank line.
    HeadTooLarge,
    /// The head was rejected (bad status line, bad header…).
    Malformed,
    /// More than [`MAX_HEADERS`] header lines.
    TooManyHeaders,
    /// A `Content-Length` that is not a plain decimal `u64`, or two
    /// different values for it.
    BadContentLength,
    /// A `Transfer-Encoding` we cannot decode (anything whose last
    /// coding is not `chunked`): encoded bytes must never reach the
    /// caller as if they were plain.
    UnsupportedTransferEncoding,
    /// Malformed chunked encoding (bad size line, bare LF, overflow…).
    BadChunk,
    /// The transport ended before the declared framing was satisfied.
    UnexpectedEof,
    /// `body_out` was smaller than `input`: the caller would lose
    /// bytes. Pass a buffer of at least `input.len()`.
    BodyBufferTooSmall,
}

/// What one [`ResponseParser::feed`] accomplished.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Body bytes written into `body_out` during this call.
    pub body: usize,
    /// The response is fully framed; no more body bytes will arrive.
    pub complete: bool,
}

/// How the body ends (RFC 9112 §6.3, applied in this order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    ContentLength(u64),
    Chunked,
    CloseDelimited,
    /// No body at all (1xx/204/304).
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Head,
    Body,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Reading the next chunk-size line.
    Size,
    /// This chunk has `remaining` payload bytes left.
    Data { remaining: u64 },
    /// Expect the CR of the chunk's terminating CRLF.
    DataCr,
    /// Expect the LF of the chunk's terminating CRLF.
    DataLf,
    /// Skipping trailer lines until the empty one.
    Trailers,
}

/// Incremental response parser: feed decrypted transport bytes in, get
/// body bytes out. One instance per response; `new()` is `const` so it
/// can live in a kernel `static`.
pub struct ResponseParser {
    /// Accumulated head until httparse completes it.
    head: [u8; HEAD_CAP],
    head_len: usize,
    /// Length of the completed head (status line + headers); set when
    /// the head parses — `head_len` may already include body bytes.
    head_end: usize,
    phase: Phase,
    status: Option<u16>,
    framing: Framing,
    /// Bytes left of a `ContentLength` body.
    remaining: u64,
    chunk: Chunk,
    /// Current chunk-size line being accumulated (strict CRLF).
    line: [u8; LINE_CAP],
    line_len: usize,
    /// A CR was seen and must be followed by LF (strict CRLF).
    pending_cr: bool,
    /// Any content byte seen on the current trailer line (for the
    /// blank-line check).
    line_dirty: bool,
}

impl ResponseParser {
    /// An empty parser, ready for the first bytes of a response head.
    pub const fn new() -> Self {
        ResponseParser {
            head: [0; HEAD_CAP],
            head_len: 0,
            head_end: 0,
            phase: Phase::Head,
            status: None,
            framing: Framing::CloseDelimited,
            remaining: 0,
            chunk: Chunk::Size,
            line: [0; LINE_CAP],
            line_len: 0,
            pending_cr: false,
            line_dirty: false,
        }
    }

    /// Reset for a new response: the kernel keeps one parser `static`
    /// and runs sequential exchanges through it, so each must start
    /// fresh instead of inheriting the previous head/framing state
    /// (a leaked `status`/`Content-Type` would validate the wrong
    /// response). Field-by-field — no whole-struct temporary, the
    /// kernel boot stack is 16 KiB and `head` alone is 8 KiB.
    pub fn reset(&mut self) {
        self.head_len = 0;
        self.head_end = 0;
        self.phase = Phase::Head;
        self.status = None;
        self.framing = Framing::CloseDelimited;
        self.remaining = 0;
        self.chunk = Chunk::Size;
        self.line_len = 0;
        self.pending_cr = false;
        self.line_dirty = false;
    }

    /// The response status code, once the head has been parsed.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// The complete response head (status line + headers) — valid
    /// once [`ResponseParser::status`] is `Some`; feed it to
    /// [`header_value`] for header assertions.
    pub fn head(&self) -> &[u8] {
        &self.head[..self.head_end]
    }

    /// The declared body length for `Content-Length` responses (the
    /// framer guarantees exactly this many bytes before `complete`).
    pub fn content_length(&self) -> Option<u64> {
        match self.framing {
            Framing::ContentLength(n) => Some(n),
            _ => None,
        }
    }

    /// Feed transport bytes. `body_out` receives the decoded payload
    /// and **must hold at least `input.len()` bytes** (the framer
    /// never expands: decoded ≤ input), unless the parser is already
    /// done. Returns how much body came out and whether the response
    /// is complete. All of `input` is consumed unless an error is
    /// returned; bytes after a completed response are discarded.
    pub fn feed(&mut self, input: &[u8], body_out: &mut [u8]) -> Result<Progress, Error> {
        let mut offset = 0usize;
        let mut written = 0usize;

        // Head phase: accumulate until httparse sees the blank line.
        if self.phase == Phase::Head {
            while offset < input.len() {
                let space = HEAD_CAP - self.head_len;
                if space == 0 {
                    return Err(Error::HeadTooLarge); // never truncated
                }
                let take = space.min(input.len() - offset);
                let input_start = offset;
                let head_before = self.head_len;
                self.head[self.head_len..self.head_len + take]
                    .copy_from_slice(&input[offset..offset + take]);
                self.head_len += take;
                offset += take;
                match parse_head(&self.head[..self.head_len])? {
                    Some((status, framing, head_bytes)) => {
                        // Only `head_bytes` of the accumulated buffer
                        // is really head — anything appended past it
                        // is body and must go to the framer below.
                        offset = input_start + (head_bytes - head_before);
                        self.head_end = head_bytes;
                        self.status = Some(status);
                        self.framing = framing;
                        self.phase = match framing {
                            // Nothing to read: finish now and discard
                            // anything after the head (a hostile
                            // server cannot append a body to a 204).
                            Framing::Empty | Framing::ContentLength(0) => Phase::Done,
                            Framing::ContentLength(n) => {
                                self.remaining = n;
                                Phase::Body
                            }
                            Framing::Chunked => {
                                self.chunk = Chunk::Size;
                                self.line_len = 0;
                                self.line_dirty = false;
                                Phase::Body
                            }
                            Framing::CloseDelimited => Phase::Body,
                        };
                        break;
                    }
                    None => {
                        if offset == input.len() {
                            return Ok(Progress {
                                body: 0,
                                complete: false,
                            }); // need more head bytes
                        }
                        // Head buffer filled to CAP mid-input but the
                        // head still parses as partial → the next
                        // iteration hits `space == 0` above.
                    }
                }
            }
        }

        // The caller's buffer must fit every body byte this call can
        // still carry (head bytes never touch it); refusing up front
        // beats silently losing payload.
        if self.phase != Phase::Done && input.len() - offset > body_out.len() {
            return Err(Error::BodyBufferTooSmall);
        }

        // Body phase: run the framer over whatever is left.
        while offset < input.len() && self.phase == Phase::Body {
            match self.framing {
                Framing::Empty | Framing::ContentLength(0) => {
                    self.phase = Phase::Done;
                }
                Framing::ContentLength(_) => {
                    let take = (self.remaining as usize).min(input.len() - offset);
                    body_out[written..written + take]
                        .copy_from_slice(&input[offset..offset + take]);
                    written += take;
                    offset += take;
                    self.remaining -= take as u64;
                    if self.remaining == 0 {
                        self.phase = Phase::Done;
                    }
                }
                Framing::CloseDelimited => {
                    let take = input.len() - offset;
                    body_out[written..written + take]
                        .copy_from_slice(&input[offset..offset + take]);
                    written += take;
                    offset = input.len();
                }
                Framing::Chunked => {
                    let (consumed, produced) =
                        self.feed_chunked(&input[offset..], &mut body_out[written..])?;
                    offset += consumed;
                    written += produced;
                }
            }
        }

        Ok(Progress {
            body: written,
            complete: self.phase == Phase::Done,
        })
    }

    /// Signal transport EOF. Close-delimited and already-complete
    /// responses finish here; a `Content-Length`/chunked body that is
    /// still short is [`Error::UnexpectedEof`] — never "close enough".
    pub fn eof(&mut self) -> Result<(), Error> {
        match self.phase {
            Phase::Done => Ok(()),
            Phase::Head => Err(Error::UnexpectedEof),
            Phase::Body => match self.framing {
                Framing::CloseDelimited | Framing::Empty => {
                    self.phase = Phase::Done;
                    Ok(())
                }
                Framing::ContentLength(_) | Framing::Chunked => Err(Error::UnexpectedEof),
            },
        }
    }

    /// Run the chunked framer over `input`, writing decoded payload
    /// into `body_out` (the caller guarantees `body_out.len() >=
    /// input.len()`), returning `(consumed, produced)`. Partial lines
    /// and a pending CR survive in the struct across calls, so any
    /// split point is safe.
    fn feed_chunked(&mut self, input: &[u8], body_out: &mut [u8]) -> Result<(usize, usize), Error> {
        let mut offset = 0usize;
        let mut written = 0usize;
        while offset < input.len() && self.phase == Phase::Body {
            match self.chunk {
                Chunk::Size => {
                    let (consumed, ended) = self.push_size_line(&input[offset..])?;
                    offset += consumed;
                    if ended {
                        let size = parse_chunk_size(&self.line[..self.line_len])?;
                        self.line_len = 0;
                        self.chunk = if size == 0 {
                            self.line_dirty = false;
                            Chunk::Trailers
                        } else {
                            Chunk::Data { remaining: size }
                        };
                    }
                }
                Chunk::Data { remaining } => {
                    let take = (remaining as usize).min(input.len() - offset);
                    body_out[written..written + take]
                        .copy_from_slice(&input[offset..offset + take]);
                    written += take;
                    offset += take;
                    let left = remaining - take as u64;
                    self.chunk = if left == 0 {
                        Chunk::DataCr
                    } else {
                        Chunk::Data { remaining: left }
                    };
                }
                Chunk::DataCr => {
                    if input[offset] != b'\r' {
                        return Err(Error::BadChunk);
                    }
                    offset += 1;
                    self.chunk = Chunk::DataLf;
                }
                Chunk::DataLf => {
                    if input[offset] != b'\n' {
                        return Err(Error::BadChunk);
                    }
                    offset += 1;
                    self.chunk = Chunk::Size;
                }
                Chunk::Trailers => {
                    let byte = input[offset];
                    offset += 1;
                    if self.pending_cr {
                        if byte != b'\n' {
                            return Err(Error::BadChunk);
                        }
                        self.pending_cr = false;
                        if self.line_dirty {
                            self.line_dirty = false; // skip this trailer
                        } else {
                            self.phase = Phase::Done; // blank line: end
                        }
                    } else if byte == b'\r' {
                        self.pending_cr = true;
                    } else if byte == b'\n' {
                        return Err(Error::BadChunk); // bare LF
                    } else {
                        self.line_dirty = true;
                    }
                }
            }
        }
        Ok((offset, written))
    }

    /// Accumulate one strict-CRLF line (the chunk-size line) into
    /// `line`, returning `(consumed, line_ended)`. A bare LF, a CR not
    /// followed by LF, or a line past [`LINE_CAP`] is [`Error::BadChunk`].
    fn push_size_line(&mut self, input: &[u8]) -> Result<(usize, bool), Error> {
        let mut consumed = 0usize;
        while consumed < input.len() {
            let byte = input[consumed];
            consumed += 1;
            if self.pending_cr {
                if byte != b'\n' {
                    return Err(Error::BadChunk);
                }
                self.pending_cr = false;
                return Ok((consumed, true));
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => return Err(Error::BadChunk), // bare LF
                _ => {
                    if self.line_len == LINE_CAP {
                        return Err(Error::BadChunk);
                    }
                    self.line[self.line_len] = byte;
                    self.line_len += 1;
                }
            }
        }
        Ok((consumed, false))
    }
}

impl Default for ResponseParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a complete head out of `head`; `Ok(None)` means "partial so
/// far" (feed more bytes), `Err` is permanent. The third field is how
/// many bytes of `head` the head actually occupies.
fn parse_head(head: &[u8]) -> Result<Option<(u16, Framing, usize)>, Error> {
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut response = Response::new(&mut headers);
    match response.parse(head) {
        Ok(Status::Complete(consumed)) => {
            let status = response.code.ok_or(Error::Malformed)?;
            let framing = framing_of(status, response.headers)?;
            Ok(Some((status, framing, consumed)))
        }
        Ok(Status::Partial) => Ok(None),
        Err(httparse::Error::TooManyHeaders) => Err(Error::TooManyHeaders),
        Err(_) => Err(Error::Malformed),
    }
}

/// Choose the body framing from the status line and headers
/// (RFC 9112 §6.3 order, with the smuggling defenses).
fn framing_of(status: u16, headers: &[Header<'_>]) -> Result<Framing, Error> {
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Framing::Empty);
    }
    let mut last_transfer_coding: Option<&[u8]> = None;
    let mut content_length: Option<u64> = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            // RFC 9112 §6.3: the LAST coding must be `chunked`.
            let mut start = 0;
            for (index, &byte) in header.value.iter().enumerate() {
                if byte == b',' {
                    start = index + 1;
                }
            }
            last_transfer_coding = Some(trim_ascii(&header.value[start..]));
        } else if header.name.eq_ignore_ascii_case("content-length") {
            let value = parse_content_length(header.value)?;
            match content_length {
                None => content_length = Some(value),
                Some(previous) if previous == value => {}
                Some(_) => return Err(Error::BadContentLength), // smuggling
            }
        }
    }
    if let Some(coding) = last_transfer_coding {
        if coding.eq_ignore_ascii_case(b"chunked") {
            // RFC 9112 §6.3: Transfer-Encoding wins — Content-Length
            // is ignored, never mixed with chunk sizes.
            return Ok(Framing::Chunked);
        }
        // Some other coding (gzip, …): refuse rather than hand
        // encoded bytes to the caller as plain text.
        return Err(Error::UnsupportedTransferEncoding);
    }
    if let Some(length) = content_length {
        return Ok(Framing::ContentLength(length));
    }
    Ok(Framing::CloseDelimited)
}

/// Strict decimal `Content-Length`: digits only, no sign, no spaces,
/// no overflow.
fn parse_content_length(value: &[u8]) -> Result<u64, Error> {
    if value.is_empty() {
        return Err(Error::BadContentLength);
    }
    let mut total: u64 = 0;
    for &byte in value {
        let digit = byte.checked_sub(b'0').ok_or(Error::BadContentLength)?;
        if digit > 9 {
            return Err(Error::BadContentLength);
        }
        total = total
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
            .ok_or(Error::BadContentLength)?;
    }
    Ok(total)
}

/// The chunk-size line: `1*HEXDIG` up to the first `;` (extension),
/// strict hex, no whitespace, overflow refused.
fn parse_chunk_size(line: &[u8]) -> Result<u64, Error> {
    let hex = match line.iter().position(|&byte| byte == b';') {
        Some(index) => &line[..index],
        None => line,
    };
    if hex.is_empty() {
        return Err(Error::BadChunk);
    }
    let mut size: u64 = 0;
    for &byte in hex {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Error::BadChunk),
        };
        size = size
            .checked_mul(16)
            .and_then(|size| size.checked_add(u64::from(digit)))
            .ok_or(Error::BadChunk)?;
    }
    Ok(size)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// Assemble `GET <path> HTTP/1.1` with the `Host` header, `headers`
/// (each a complete `Name: value` line, no CRLF), and
/// `Connection: close` into `buf`, returning its length — `None` when
/// `buf` is too small (the caller decides whether that is a bug).
/// Shared by the plain-HTTP, TLS-smoke and git paths.
pub fn build_request(buf: &mut [u8], host: &str, path: &str, headers: &[&str]) -> Option<usize> {
    const MIDDLE: &[u8] = b" HTTP/1.1\r\nHost: ";
    const CONN: &[u8] = b"\r\nConnection: close";
    const END: &[u8] = b"\r\n\r\n";
    let mut total = b"GET ".len() + path.len() + MIDDLE.len() + host.len() + CONN.len() + END.len();
    for h in headers {
        total = total.checked_add(2 + h.len())?; // CRLF + line
    }
    let out = buf.get_mut(..total)?;
    let mut off = 0usize;
    for part in [
        b"GET ".as_slice(),
        path.as_bytes(),
        MIDDLE,
        host.as_bytes(),
        CONN,
    ] {
        out[off..off + part.len()].copy_from_slice(part);
        off += part.len();
    }
    for h in headers {
        out[off..off + 2].copy_from_slice(b"\r\n");
        out[off + 2..off + 2 + h.len()].copy_from_slice(h.as_bytes());
        off += 2 + h.len();
    }
    out[off..off + END.len()].copy_from_slice(END);
    Some(total)
}

/// [`build_request`] without extra headers — the plain-HTTP and
/// TLS-smoke paths.
pub fn build_get(buf: &mut [u8], host: &str, path: &str) -> Option<usize> {
    build_request(buf, host, path, &[])
}

/// Value of `name` (ASCII case-insensitive) in a **complete** raw
/// response head (status line … blank line), with surrounding OWS
/// trimmed — `None` when absent or the head is malformed. Used to
/// assert the git advertisement's `Content-Type`.
pub fn header_value<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    // Skip the status line.
    let mut rest = &head[head.iter().position(|&b| b == b'\n')? + 1..];
    loop {
        let nl = rest.iter().position(|&b| b == b'\n')?;
        let line = rest[..nl].strip_suffix(b"\r").unwrap_or(&rest[..nl]);
        if line.is_empty() {
            return None; // end of headers, name not found
        }
        let colon = line.iter().position(|&b| b == b':')?;
        let key = &line[..colon];
        if key.len() == name.len() && key.eq_ignore_ascii_case(name) {
            return Some(trim_ascii(&line[colon + 1..]));
        }
        rest = &rest[nl + 1..];
    }
}

/// True once the head-terminating empty line (`\r\n\r\n`) is present
/// (requests and responses alike).
pub fn headers_complete(head: &[u8]) -> bool {
    head.windows(4).any(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::vec::Vec;

    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";

    /// Feed `input` one byte at a time, returning the concatenated
    /// body and the final progress — the split-point torture test.
    fn feed_bytewise(parser: &mut ResponseParser, input: &[u8]) -> (Vec<u8>, Progress) {
        let mut body = Vec::new();
        let mut last = Progress::default();
        for byte in input {
            let mut out = [0u8; 1];
            let progress = parser.feed(&[*byte], &mut out[..]).expect("feed");
            body.extend_from_slice(&out[..progress.body]);
            last = progress;
        }
        (body, last)
    }

    fn feed_whole(parser: &mut ResponseParser, input: &[u8]) -> (Vec<u8>, Progress) {
        let mut out = [0u8; 4096];
        let progress = parser.feed(input, &mut out[..]).expect("feed");
        (out[..progress.body].to_vec(), progress)
    }

    #[test]
    fn reset_between_responses_does_not_leak_the_previous_head() {
        // Regression: the kernel keeps ONE parser static and runs
        // sequential exchanges through it — without reset, the second
        // response inherited the first one's status/Content-Type and
        // validated the wrong head (caught in the git smoke).
        let mut parser = ResponseParser::new();
        let first =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let (body, progress) = feed_bytewise(&mut parser, first);
        assert!(progress.complete);
        assert_eq!(&body[..], b"hello");
        assert_eq!(parser.status(), Some(200));
        assert_eq!(
            header_value(parser.head(), b"content-type"),
            Some(&b"text/plain"[..])
        );

        parser.reset();
        assert_eq!(parser.status(), None);
        assert_eq!(parser.head(), b"");

        let second = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 2\r\n\r\nok";
        let (body, progress) = feed_whole(&mut parser, second);
        assert!(progress.complete);
        assert_eq!(&body[..], b"ok");
        assert_eq!(parser.status(), Some(200));
        assert_eq!(
            header_value(parser.head(), b"content-type"),
            Some(&b"application/x-git-upload-pack-advertisement"[..])
        );
    }

    #[test]
    fn content_length_reassembles_at_any_split() {
        let mut message = HEAD.to_vec();
        message.extend_from_slice(b"hello");

        let mut one = ResponseParser::new();
        let (body, progress) = feed_whole(&mut one, &message);
        assert_eq!(body, b"hello");
        assert!(progress.complete);
        assert_eq!(one.status(), Some(200));
        assert_eq!(one.content_length(), Some(5));

        let mut many = ResponseParser::new();
        let (body, progress) = feed_bytewise(&mut many, &message);
        assert_eq!(body, b"hello");
        assert!(progress.complete);
        assert_eq!(many.status(), Some(200));
    }

    #[test]
    fn premature_eof_is_rejected() {
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        let progress = parser.feed(head, &mut out[..]).unwrap();
        assert!(!progress.complete);
        assert_eq!(progress.body, 3);
        assert_eq!(parser.eof(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn content_length_mismatch_stops_at_the_declared_count() {
        let mut parser = ResponseParser::new();
        let mut message = HEAD.to_vec();
        message.extend_from_slice(b"helloEXTRA");
        // One extra byte past Content-Length: the response completes
        // at 5 and the rest is discarded, never delivered.
        let (body, progress) = feed_whole(&mut parser, &message);
        assert_eq!(body, b"hello");
        assert!(progress.complete);
        // And a later feed is inert.
        let (body, progress) = feed_whole(&mut parser, b"more");
        assert!(body.is_empty());
        assert!(progress.complete);
    }

    #[test]
    fn conflicting_content_lengths_are_rejected() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        assert_eq!(
            parser.feed(head, &mut out[..]),
            Err(Error::BadContentLength)
        );
    }

    #[test]
    fn duplicate_identical_content_lengths_are_accepted() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhi";
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        let progress = parser.feed(head, &mut out[..]).unwrap();
        assert_eq!(progress.body, 2);
        assert_eq!(parser.content_length(), Some(5));
    }

    #[test]
    fn malformed_content_lengths_are_rejected() {
        // Note: `Content-Length: 5 ` (trailing OWS) and ` 5` are NOT
        // here — RFC 9110 field-value OWS is trimmed by httparse
        // before we ever see it, which is the correct behavior (see
        // the next test).
        for value in ["", "-1", "+5", "0x10", "5a", "99999999999999999999999"] {
            let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n\r\n");
            let mut parser = ResponseParser::new();
            let mut out = [0u8; 64];
            assert_eq!(
                parser.feed(&head, &mut out[..]),
                Err(Error::BadContentLength),
                "accepted CL {value:?}"
            );
        }
    }

    #[test]
    fn content_length_ows_is_trimmed_before_parsing() {
        // RFC 9110: optional whitespace around a field value is not
        // part of the value — httparse strips it, so `5 ` is a valid
        // Content-Length of 5, not a malformed one.
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        let progress = parser
            .feed(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5 \r\n\r\nhi",
                &mut out[..],
            )
            .unwrap();
        assert_eq!(parser.content_length(), Some(5));
        assert_eq!(progress.body, 2);
    }

    #[test]
    fn transfer_encoding_wins_over_content_length() {
        // Smuggling shape: CL says 4, TE says chunked. The body must
        // be parsed as chunks — "5\r\nhello\r\n0\r\n\r\n" — and the
        // Content-Length ignored (a proxy disagreeing here is the
        // classic desync; we never mix them).
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
        let mut message = head.to_vec();
        message.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let mut parser = ResponseParser::new();
        let (body, progress) = feed_whole(&mut parser, &message);
        assert_eq!(body, b"hello");
        assert!(progress.complete);
        assert_eq!(parser.content_length(), None); // CL was ignored
    }

    #[test]
    fn undecodable_transfer_encoding_fails_closed() {
        for coding in ["gzip", "chunked, gzip", "identity"] {
            let mut head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ".to_vec();
            head.extend_from_slice(coding.as_bytes());
            head.extend_from_slice(b"\r\n\r\n");
            let mut parser = ResponseParser::new();
            let mut out = [0u8; 64];
            assert_eq!(
                parser.feed(&head, &mut out[..]),
                Err(Error::UnsupportedTransferEncoding),
                "accepted TE {coding:?}"
            );
        }
    }

    #[test]
    fn chunked_with_extension_and_trailers_reassembles_bytewise() {
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend_from_slice(b"5;ext=1\r\nhello\r\n");
        message.extend_from_slice(b"6\r\n world\r\n");
        message.extend_from_slice(b"0\r\nX-Trailer: yes\r\n\r\n");
        let mut parser = ResponseParser::new();
        let (body, progress) = feed_bytewise(&mut parser, &message);
        assert_eq!(body, b"hello world");
        assert!(progress.complete);
        assert_eq!(parser.status(), Some(200));
    }

    #[test]
    fn chunked_rejects_bad_size_lines() {
        for bad in [
            &b"zz\r\nhello\r\n0\r\n\r\n"[..],
            &b"-1\r\nhello\r\n0\r\n\r\n"[..],
            &b"5 \r\nhello\r\n0\r\n\r\n"[..], // space before CR
            &b"fffffffffffffffff\r\n0\r\n\r\n"[..], // u64 overflow
            &b"\r\n0\r\n\r\n"[..],            // empty size
        ] {
            let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            message.extend_from_slice(bad);
            let mut parser = ResponseParser::new();
            let mut out = [0u8; 64];
            assert_eq!(
                parser.feed(&message, &mut out[..]),
                Err(Error::BadChunk),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn chunked_requires_strict_crlf() {
        // Bare LF in the chunk framing must be refused (lenient
        // parsers here are how request smuggling starts).
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend_from_slice(b"5\nhello\n0\n\r\n");
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        assert_eq!(parser.feed(&message, &mut out[..]), Err(Error::BadChunk));
    }

    #[test]
    fn chunked_premature_eof_is_rejected() {
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        let progress = parser.feed(head, &mut out[..]).unwrap();
        assert_eq!(progress.body, 3);
        assert_eq!(parser.eof(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn close_delimited_completes_only_at_eof() {
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 64];
        let progress = parser
            .feed(b"HTTP/1.1 200 OK\r\n\r\nsome body", &mut out[..])
            .unwrap();
        assert_eq!(progress.body, b"some body".len());
        assert!(!progress.complete, "close-delimited needs EOF");
        parser.eof().expect("EOF completes it");
        assert_eq!(parser.feed(b"ignored", &mut [0u8; 8][..]).unwrap().body, 0);
    }

    #[test]
    fn status_without_body_completes_immediately() {
        for head in [
            &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
            &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n"[..],
            &b"HTTP/1.1 100 Continue\r\n\r\n"[..],
        ] {
            let mut message = head.to_vec();
            message.extend_from_slice(b"smuggled body bytes");
            let mut parser = ResponseParser::new();
            let (body, progress) = feed_whole(&mut parser, &message);
            assert!(body.is_empty(), "body delivered for {head:?}");
            assert!(progress.complete, "not complete for {head:?}");
        }
    }

    #[test]
    fn zero_content_length_completes_immediately() {
        let mut parser = ResponseParser::new();
        let (body, progress) = feed_whole(
            &mut parser,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\njunk",
        );
        assert!(body.is_empty());
        assert!(progress.complete);
    }

    #[test]
    fn oversized_head_is_refused_not_truncated() {
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 16];
        // A valid head prefix with one header line that never ends:
        // it must be refused at HEAD_CAP — never truncated into
        // something that would parse.
        let prefix = b"HTTP/1.1 200 OK\r\nX-Big: ";
        let progress = parser.feed(prefix, &mut out[..]).unwrap();
        assert!(!progress.complete);
        let chunk = [b'a'; 1024];
        let error = loop {
            match parser.feed(&chunk, &mut out[..]) {
                Ok(progress) => assert!(!progress.complete),
                Err(error) => break error,
            }
        };
        assert_eq!(error, Error::HeadTooLarge);
    }

    #[test]
    fn malformed_heads_are_rejected() {
        for head in [
            &b"HTTP/1.1 abc\r\n\r\n"[..],
            &b"NOT-HTTP\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nBad Header Name: x\r\n\r\n"[..],
        ] {
            let mut parser = ResponseParser::new();
            let mut out = [0u8; 64];
            let error = parser.feed(head, &mut out[..]).unwrap_err();
            assert_eq!(error, Error::Malformed, "accepted {head:?}");
        }
    }

    #[test]
    fn too_many_headers_are_rejected() {
        let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
        for index in 0..MAX_HEADERS + 1 {
            head.extend_from_slice(format!("X-H{index}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 16];
        assert_eq!(parser.feed(&head, &mut out[..]), Err(Error::TooManyHeaders));
    }

    #[test]
    fn small_body_buffer_is_refused() {
        let mut parser = ResponseParser::new();
        let mut tiny = [0u8; 4];
        // The head fits any buffer, but five body bytes into a
        // four-byte buffer would lose one: refuse instead.
        let error = parser
            .feed(b"HTTP/1.1 200 OK\r\n\r\nbody!", &mut tiny[..])
            .unwrap_err();
        assert_eq!(error, Error::BodyBufferTooSmall);
    }

    #[test]
    fn status_line_without_reason_phrase_is_accepted() {
        let mut parser = ResponseParser::new();
        let mut out = [0u8; 16];
        let progress = parser.feed(b"HTTP/1.1 204\r\n\r\n", &mut out[..]).unwrap();
        assert_eq!(parser.status(), Some(204));
        assert!(progress.complete);
    }

    #[test]
    fn build_get_produces_a_complete_request() {
        let mut buf = [0u8; 256];
        let n = build_get(&mut buf, "github.com", "/robots.txt")
            .expect("256 bytes must fit a small GET");
        let req = &buf[..n];
        assert!(req.starts_with(b"GET /robots.txt HTTP/1.1\r\nHost: github.com\r\n"));
        assert!(req.ends_with(b"Connection: close\r\n\r\n"));
        // The head terminator check is generic (request or response).
        assert!(headers_complete(req));
        // Too-small buffer: `None`, never a partial request.
        let mut tiny = [0u8; 8];
        assert_eq!(build_get(&mut tiny, "github.com", "/"), None);
    }

    #[test]
    fn build_request_appends_extra_headers_before_the_terminator() {
        let mut buf = [0u8; 512];
        let n = build_request(
            &mut buf,
            "github.com",
            "/repo.git/info/refs?service=git-upload-pack",
            &["User-Agent: reemplazo-git/0.1", "X-Test: yes"],
        )
        .expect("fits");
        let req = &buf[..n];
        assert!(req.starts_with(
            b"GET /repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: github.com\r\n"
        ));
        assert!(req.ends_with(b"User-Agent: reemplazo-git/0.1\r\nX-Test: yes\r\n\r\n"));
        // Every header line is CRLF-terminated and the blank line closes.
        assert!(headers_complete(req));
        // Overflow: `None`, never truncated.
        let mut tiny = [0u8; 32];
        assert_eq!(
            build_request(&mut tiny, "github.com", "/", &["X-Long: 1234567890"]),
            None
        );
    }

    #[test]
    fn header_value_finds_case_insensitively_with_ows_trimmed() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-type:  Application/x-Git-Upload-Pack-Advertisement ; charset=utf-8\r\nX-A: 1\r\n\r\n";
        assert_eq!(
            header_value(head, b"content-type"),
            Some(&b"Application/x-Git-Upload-Pack-Advertisement ; charset=utf-8"[..])
        );
        assert_eq!(header_value(head, b"Content-Length"), Some(&b"5"[..]));
        assert_eq!(header_value(head, b"CONTENT-LENGTH"), Some(&b"5"[..]));
        assert_eq!(header_value(head, b"x-a"), Some(&b"1"[..]));
        assert_eq!(header_value(head, b"missing"), None);
        // Header that never appears before the blank line.
        assert_eq!(header_value(head, b"transfer-encoding"), None);
        // Malformed head: no status line / no terminator → None.
        assert_eq!(header_value(b"", b"content-type"), None);
        assert_eq!(header_value(b"HTTP/1.1 200 OK\r\n", b"content-type"), None);
    }

    #[test]
    fn headers_complete_needs_the_full_terminator() {
        assert!(!headers_complete(b"HTTP/1.1 200 OK\r\n\r"));
        assert!(!headers_complete(b"HTTP/1.1 200 OK\r\n"));
        assert!(headers_complete(b"HTTP/1.1 200 OK\r\n\r\n"));
    }
}
