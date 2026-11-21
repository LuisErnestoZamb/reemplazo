//! TLS 1.3 client (`embedded-tls`, blocking mode) over the smoltcp
//! TCP stack: prove a full HTTPS exchange against `github.com:443` —
//! handshake with certificate validation, HTTP GET, `close_notify`
//! shutdown — the smoke test's `TLS_OK` + `HTTP_OK`.
//!
//! Crypto is never hand-rolled here (skill rule): `embedded-tls` at a
//! pinned git rev provides the protocol, `rustls-webpki` builds the
//! certificate path, and the primitives are RustCrypto crates via
//! `embassy-crypto` (AES-128-GCM, SHA-256, HMAC-SHA256, P-256/P-384
//! ECDH/ECDSA), each audited — the review is recorded in the commit.
//!
//! Trust model: the chain must terminate at the pinned
//! `USERTrust ECC Certification Authority` root (`usertrust_ecc_ca.der`,
//! SHA-256 `4ff460d5…`), verified against `openssl verify` when this
//! landed. Certificate dates come from the CMOS RTC ([`RtcClock`]): when
//! the clock is unavailable the check degrades to "dates not verified"
//! (embedded-tls still enforces that the chain's validity periods
//! overlap), and the smoke test's `RTC_OK` marker guarantees the clock
//! itself keeps working. Hostname, chain, signatures and EKU are always
//! checked.
//!
//! Transport: a thin [`Stream`] over one smoltcp `TcpSocket`
//! (docs/smoltcp-eval.md §11) — every call pumps the stack and honors
//! a per-operation deadline; smoltcp owns retransmission, reassembly,
//! windows and Reno congestion control, so the old stash/wait_ack
//! machinery is gone. The response body is bounded by [`READ_CAP`] for
//! the smoke (the framer itself trusts the declared `Content-Length`).

use crate::clock;
use crate::netstack::{E1000Phy, OP_DEADLINE_MS, Stack};
use core::cmp::min;
use core::ptr::addr_of_mut;
use embedded_io::{ErrorKind, Read, Write};
use embedded_tls::TlsError;
use embedded_tls::blocking::{
    Aes128GcmSha256, Certificate, TlsClock, TlsConfig, TlsConnection, TlsContext,
};
use embedded_tls::webpki::CertVerifier;
use net::http::{self, ResponseParser};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

/// Pinned trust anchor: USERTrust ECC Certification Authority (DER).
/// sha256 = 4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a
const ROOT_CA: &[u8] = include_bytes!("usertrust_ecc_ca.der");
/// Encrypted-record buffer: the TLS maximum (16640) per `embedded-tls`.
const READ_BUF: usize = 16640;
/// Write-record buffer: our records are small (ClientHello ≈ 400 B,
/// ClientFinished ≈ 80 B, GET ≈ 250 B) — 4 KiB leaves room to grow.
const WRITE_BUF: usize = 4096;
/// `CertVerifier` keeps a copy of the server's own certificate: the
/// github.com leaf is 1016 B DER; 2048 leaves room for a renewal.
const CERT_SIZE: usize = 2048;
/// First bytes of the body kept for content validation (any valid
/// robots.txt declares its user agent inside the first few lines).
const BODY_HEAD_CAP: usize = 512;
/// Response-body bound for the smoke: robots.txt is ~30 KiB, and a
/// stuck or hostile server cannot keep us reading forever (the smoke
/// test has a 30 s budget).
const READ_CAP: usize = 64 * 1024;
/// One read/parse chunk: decrypted bytes in, body staging out (the
/// framer never expands, so this size fits both).
const SCRATCH: usize = 1460;
/// Local port of the TLS connection (the plain-HTTP proof owns49152;
/// a socket in TIME-WAIT cannot be reused for10 s, so TLS gets its
/// own port and its own socket).
const LOCAL_PORT: u16 = 49160;

/// Record buffers and parser state live in `static`s: 21+ KiB would
/// not fit the stack alongside the handshake frames. Written only
/// from `https_smoke`, which runs once on a single core — the only
/// handler in play (IRQ0) does not touch these statics.
static mut READ_STORAGE: [u8; READ_BUF] = [0; READ_BUF];
static mut WRITE_STORAGE: [u8; WRITE_BUF] = [0; WRITE_BUF];
static mut PARSER: ResponseParser = ResponseParser::new();
static mut STAGING: [u8; SCRATCH] = [0; SCRATCH];
static mut BODY_HEAD: [u8; BODY_HEAD_CAP] = [0; BODY_HEAD_CAP];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: tls: {msg}");
    crate::halt()
}

/// Certificate-date checking through the CMOS clock: `None` when the
/// clock is unavailable (UIP stuck, implausible year) makes
/// embedded-tls skip date validation — the documented degradation,
/// kept honest by the `RTC_OK` smoke marker.
struct RtcClock;

impl TlsClock for RtcClock {
    fn now() -> Option<u64> {
        crate::rtc::now_epoch()
    }
}

/// `embedded_io` transport over one smoltcp `TcpSocket`
/// (docs/smoltcp-eval.md §11): every call pumps the stack once per
/// loop iteration and honors a per-operation deadline. smoltcp owns
/// retransmission, reassembly, windows and Reno congestion control —
/// no stash, no ACK-wait, no retransmit bookkeeping here.
pub(crate) struct Stream<'a> {
    iface: &'a mut Interface,
    dev: &'a mut E1000Phy,
    socks: &'a mut SocketSet<'static>,
    handle: SocketHandle,
}

impl Stream<'_> {
    fn pump(&mut self) {
        self.iface.poll(clock::now(), self.dev, self.socks);
    }

    fn tcp(&mut self) -> &mut tcp::Socket<'static> {
        self.socks.get_mut(self.handle)
    }
}

impl embedded_io::ErrorType for Stream<'_> {
    type Error = TlsError;
}

impl Read for Stream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            self.pump();
            let tcp = self.tcp();
            if tcp.can_recv() {
                return tcp
                    .recv_slice(buf)
                    .map_err(|_| TlsError::Io(ErrorKind::Other));
            }
            if !tcp.may_recv() && tcp.recv_queue() == 0 {
                return Ok(0); // peer FIN → transport EOF
            }
            if clock::now_ms() > deadline {
                return Err(TlsError::Io(ErrorKind::TimedOut));
            }
        }
    }
}

impl Write for Stream<'_> {
    fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        let mut sent = 0;
        while sent < data.len() {
            self.pump();
            // A full socket buffer comes back as a short/zero write
            // (only `InvalidState` is an error), so polling continues
            // until the deadline.
            match self.tcp().send_slice(&data[sent..]) {
                Ok(n) => sent += n,
                Err(_) => return Err(TlsError::Io(ErrorKind::Other)), // not connected/finished
            }
            if clock::now_ms() > deadline {
                return Err(TlsError::Io(ErrorKind::TimedOut));
            }
        }
        Ok(sent)
    }

    fn flush(&mut self) -> Result<(), TlsError> {
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        while self.tcp().send_queue() > 0 {
            self.pump();
            if clock::now_ms() > deadline {
                return Err(TlsError::Io(ErrorKind::TimedOut));
            }
        }
        Ok(())
    }
}

/// Open a TLS 1.3 connection to `ip:443` from `local_port` on socket
/// `handle` and complete the handshake against the pinned root —
/// shared by [`https_smoke`] and the `git ls-remote` fetch. The
/// returned connection borrows the stack and the static record
/// buffers until [`tls_fetch`] consumes it (sequential connections:
/// TIME-WAIT forbids reusing a socket for10 s, so each caller owns a
/// different handle and local port).
pub(crate) fn tls_open<'a>(
    stack: &'a mut Stack,
    handle: SocketHandle,
    ip: Ipv4Address,
    host: &str,
    local_port: u16,
) -> TlsConnection<'a, Stream<'a>, Aes128GcmSha256> {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if let Err(e) = sock.connect(stack.iface.context(), (ip, 443u16), local_port) {
            serial_println!("tls: connect rejected: {e:?}");
            crate::halt();
        }
    }
    loop {
        stack.poll();
        if stack.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established {
            break;
        }
        if clock::now_ms() > deadline {
            fatal("tcp connect timeout");
        }
    }
    serial_println!("tls: connected to {ip}:443");

    // Split the stack into the three fields the Stream needs.
    let Stack {
        iface,
        dev,
        sockets,
        ..
    } = stack;
    let stream = Stream {
        iface,
        dev,
        socks: sockets,
        handle,
    };

    // SAFETY: single-use buffers (see `READ_STORAGE`); taken as `&mut`
    // through raw pointers to avoid `static_mut_refs` on a shared name.
    let read_buf = unsafe { &mut *addr_of_mut!(READ_STORAGE) };
    let write_buf = unsafe { &mut *addr_of_mut!(WRITE_STORAGE) };
    let mut tls: TlsConnection<'a, Stream<'a>, Aes128GcmSha256> =
        TlsConnection::new(stream, read_buf, write_buf);

    let verifier: CertVerifier<'_, Aes128GcmSha256, RtcClock, CERT_SIZE> =
        CertVerifier::new(Certificate::X509(ROOT_CA));
    let config = TlsConfig::new().with_server_name(host);
    if let Err(e) = tls.open(TlsContext::new(&config, verifier)) {
        serial_println!("FATAL: tls: handshake failed: {e:?}");
        crate::halt();
    }
    serial_println!("tls: handshake ok (TLS 1.3, pinned USERTrust ECC root)");
    tls
}

/// One full HTTPS exchange over an open connection: send the GET
/// (with `headers` inserted before the terminating blank line), frame
/// the whole response into `body` — bytes past `body.len()` are
/// validated and counted, not stored — assert `expect_ct` against the
/// `Content-Type` when given, then close both layers cleanly.
/// Returns `(status, total_body_bytes)`; a non-200 status, a missing
/// or mismatched `Content-Type`, a truncated body or a shutdown that
/// never settles is `fatal`, never a partial result.
pub(crate) fn tls_fetch(
    tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>,
    host: &str,
    path: &str,
    headers: &[&str],
    expect_ct: Option<&[u8]>,
    body: &mut [u8],
) -> (u16, usize) {
    let mut tls = tls;
    // HTTP/1.1 GET over the established channel; `Connection: close`
    // makes the server finish with close_notify + FIN.
    let mut req = [0u8; 512];
    let Some(req_len) = http::build_request(&mut req, host, path, headers) else {
        fatal("GET request does not fit the buffer");
    };
    if let Err(e) = tls.write_all(&req[..req_len]) {
        serial_println!("FATAL: tls: write failed: {e:?}");
        crate::halt();
    }
    if let Err(e) = tls.flush() {
        serial_println!("FATAL: tls: flush failed: {e:?}");
        crate::halt();
    }

    // Read the decrypted stream through the HTTP response parser:
    // httparse parses the head, the RFC 9112 framer the body
    // (content-length / chunked / close-delimited).
    // SAFETY: single-use statics (see `READ_STORAGE`). The parser is
    // shared by every connection in sequence, so it must start each
    // response fresh — otherwise the previous response's completed
    // head (status, Content-Type) would leak into this one's checks.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let mut status = 0u16;
    let mut status_checked = false;
    let mut ct_checked = expect_ct.is_none();
    let mut body_total = 0usize;
    let mut body_stored = 0usize;
    let mut scratch = [0u8; SCRATCH];
    loop {
        match tls.read(&mut scratch) {
            Ok(0) => fatal("transport EOF without close_notify (truncated response)"),
            Ok(n) => {
                let progress = match parser.feed(&scratch[..n], staging) {
                    Ok(progress) => progress,
                    Err(e) => {
                        serial_println!("FATAL: tls: HTTP response refused: {e:?}");
                        crate::halt();
                    }
                };
                if !status_checked && let Some(s) = parser.status() {
                    status_checked = true;
                    status = s;
                    // A parsed u16 — inherently safe to log (no
                    // log-injection surface like raw text lines).
                    serial_println!("http: status {s}");
                    if s != 200 {
                        fatal("unexpected HTTP status (expected 200)");
                    }
                    if let Some(expected) = expect_ct {
                        // Header values come off the wire: compared,
                        // never logged.
                        match http::header_value(parser.head(), b"content-type") {
                            Some(value) if ct_matches(value, expected) => {}
                            Some(_) => fatal("unexpected Content-Type"),
                            None => fatal("response has no Content-Type"),
                        }
                        ct_checked = true;
                    }
                }
                if progress.body > 0 {
                    let take = min(body.len() - body_stored, progress.body);
                    body[body_stored..body_stored + take].copy_from_slice(&staging[..take]);
                    body_stored += take;
                    body_total += progress.body;
                    if body_total > READ_CAP {
                        fatal("response body exceeds the byte bound");
                    }
                }
                if progress.complete {
                    break;
                }
            }
            Err(TlsError::ConnectionClosed) => {
                // The authenticated shutdown doubles as EOF for
                // close-delimited bodies; a framed body ending here
                // was truncated and must fail, not "finish".
                if let Err(e) = parser.eof() {
                    serial_println!("FATAL: tls: response truncated: {e:?}");
                    crate::halt();
                }
                break;
            }
            Err(e) => {
                serial_println!("FATAL: tls: read failed: {e:?}");
                crate::halt();
            }
        }
    }
    if !ct_checked {
        fatal("response head never parsed (Content-Type unchecked)");
    }

    // Orderly shutdown: close_notify (best-effort — the server's own
    // close_notify already authenticated everything we read; a failure
    // here cannot retroactively corrupt it), then the TCP close.
    let mut stream = match tls.close() {
        Ok(stream) => stream,
        Err((stream, e)) => {
            serial_println!("tls: close_notify not sent: {e:?}");
            stream
        }
    };
    stream.tcp().close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stream.pump();
        let state = stream.tcp().state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            serial_println!("tls: connection closed cleanly ({state})");
            return (status, body_total);
        }
        if clock::now_ms() > deadline {
            fatal("timeout closing connection (never reached TimeWait/Closed)");
        }
    }
}

/// Content-Type match with parameters allowed: the value must start
/// with `expected` (ASCII case-insensitive) and continue with `;` /
/// whitespace, or end there.
fn ct_matches(value: &[u8], expected: &[u8]) -> bool {
    value.len() >= expected.len()
        && value[..expected.len()].eq_ignore_ascii_case(expected)
        && matches!(
            value.get(expected.len()),
            None | Some(&b';') | Some(&b' ') | Some(&b'\t')
        )
}

/// Prove the whole HTTPS client path on the smoltcp stack: connect
/// the second TCP socket to `ip:443` and handshake ([`tls_open`]),
/// GET `/robots.txt` and frame the response ([`tls_fetch`]), validate
/// the body, print `TLS_OK` then `HTTP_OK`.
pub fn https_smoke(stack: &mut Stack, ip: Ipv4Address, host: &str) {
    let handle = stack.tcp2_handle;
    let tls = tls_open(stack, handle, ip, host, LOCAL_PORT);
    serial_println!("TLS_OK"); // machine-checked by `cargo xtask smoke`

    // A real, fully-framed body with real content: any valid
    // robots.txt declares its user agent inside the first few lines
    // (bytes past `BODY_HEAD` are counted by tls_fetch, not stored).
    // SAFETY: single-use static (see `BODY_HEAD`).
    let body_head = unsafe { &mut *addr_of_mut!(BODY_HEAD) };
    let (_status, body_total) = tls_fetch(tls, host, "/robots.txt", &[], None, body_head);
    if body_total == 0 {
        fatal("empty response body");
    }
    if !body_head
        .windows(b"User-agent:".len())
        .any(|window| window == b"User-agent:")
    {
        fatal("body does not look like robots.txt (no User-agent)");
    }
    serial_println!("http: {body_total} bytes framed");
    serial_println!("HTTP_OK"); // machine-checked by `cargo xtask smoke`
}
