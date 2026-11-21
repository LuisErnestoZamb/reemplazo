//! TLS 1.3 client (`embedded-tls`, blocking mode) over the e1000/TCP
//! stack: prove a full HTTPS exchange against `github.com:443` —
//! handshake with certificate validation, HTTP GET, `close_notify`
//! shutdown — the smoke test's `TLS_OK`.
//!
//! Crypto is never hand-rolled here (skill rule): `embedded-tls` at a
//! pinned git rev provides the protocol, `rustls-webpki` builds the
//! certificate path, and the primitives are RustCrypto crates via
//! `embassy-crypto` (AES-128-GCM, SHA-256, HMAC-SHA256, P-256
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
//! Scope of this milestone (documented limits, not hidden bugs):
//! `Conn`'s one-outstanding-segment rule is upheld by `Socket`, which
//! waits for each segment's ACK before sending the next and stashes
//! any payload that arrives meanwhile (a stall that exhausts the stash
//! aborts loudly rather than dropping bytes); the response body is
//! bounded by `READ_CAP` for the smoke (the framer itself trusts the
//! declared `Content-Length`).

use crate::dhcp::NetConfig;
use crate::e1000::E1000;
use crate::tcp::{ATTEMPTS, Conn, MAX_SEND, build_get};
use core::cmp::min;
use embedded_io::{ErrorKind, Read, Write};
use embedded_tls::TlsError;
use embedded_tls::blocking::{
    Aes128GcmSha256, Certificate, TlsClock, TlsConfig, TlsConnection, TlsContext,
};
use embedded_tls::webpki::CertVerifier;
use net::http::ResponseParser;

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
/// Held bytes a stalled write may accumulate: the residue of the last
/// read (≤ one MSS) plus payload pumped while waiting for an ACK.
/// Overflow aborts loudly — never silently drops.
const STASH_CAP: usize = 8192;

/// Record buffers live in `static`s: 21 KiB would not fit the 64 KiB
/// stack alongside the handshake frames. Both are written only from
/// `https_smoke`, which runs once on a single core — the only handler
/// in play (IRQ0) does not touch these statics.
static mut READ_STORAGE: [u8; READ_BUF] = [0; READ_BUF];
static mut WRITE_STORAGE: [u8; WRITE_BUF] = [0; WRITE_BUF];
/// The receive stash and last-sent segment are static for the same
/// reason: `Socket` lives inside `TlsConnection` on `https_smoke`'s
/// stack, and the handshake is the deepest call chain in the kernel
/// (see `crate::guard` for what an overflow used to hit).
static mut STASH: [u8; STASH_CAP] = [0; STASH_CAP];
static mut LAST: [u8; MAX_SEND] = [0; MAX_SEND];
/// HTTP parser state (head accumulation + framer), the body staging
/// area for one feed (≤ one MSS of decrypted bytes) and the body
/// prefix kept for content checks — static for the same stack-headroom
/// reason as above; `ResponseParser::new` is `const`.
static mut PARSER: ResponseParser = ResponseParser::new();
static mut STAGING: [u8; MAX_SEND] = [0; MAX_SEND];
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

/// Prove the whole HTTPS client path: open TCP to `remote_ip:443`,
/// complete a TLS 1.3 handshake against the pinned root, GET
/// `/robots.txt` with `Connection: close`, parse and frame the
/// response with `net::http` (httparse head + RFC 9112 body framer),
/// validate the body, close both layers, print `TLS_OK` then
/// `HTTP_OK`.
pub fn https_smoke(nic: &mut E1000, cfg: &NetConfig, remote_ip: [u8; 4], host: &str) {
    let mut conn = Conn::open(nic, cfg, remote_ip, 443);

    // SAFETY: single-use buffers (see `READ_STORAGE`); taken as `&mut`
    // through raw pointers to avoid `static_mut_refs` on a shared name.
    let socket = Socket::new(&mut conn, nic);
    let read_buf = unsafe { &mut *core::ptr::addr_of_mut!(READ_STORAGE) };
    let write_buf = unsafe { &mut *core::ptr::addr_of_mut!(WRITE_STORAGE) };
    let mut tls: TlsConnection<_, Aes128GcmSha256> =
        TlsConnection::new(socket, read_buf, write_buf);

    let verifier: CertVerifier<'_, Aes128GcmSha256, RtcClock, CERT_SIZE> =
        CertVerifier::new(Certificate::X509(ROOT_CA));
    let config = TlsConfig::new().with_server_name(host);
    if let Err(e) = tls.open(TlsContext::new(&config, verifier)) {
        serial_println!("FATAL: tls: handshake failed: {e:?}");
        crate::halt();
    }
    serial_println!("tls: handshake ok (TLS 1.3, pinned USERTrust ECC root)");
    serial_println!("TLS_OK"); // machine-checked by `cargo xtask smoke`

    // HTTP/1.1 GET over the established channel; `Connection: close`
    // makes the server finish with close_notify + FIN.
    let mut req = [0u8; 256];
    let req_len = build_get(&mut req, host, "/robots.txt");
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
    // SAFETY: single-use statics (see `READ_STORAGE`).
    let parser = unsafe { &mut *core::ptr::addr_of_mut!(PARSER) };
    let staging = unsafe { &mut *core::ptr::addr_of_mut!(STAGING) };
    let body_head = unsafe { &mut *core::ptr::addr_of_mut!(BODY_HEAD) };
    let mut body_head_len = 0usize;
    let mut body_total = 0usize;
    let mut status_checked = false;
    let mut scratch = [0u8; MAX_SEND];
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
                if !status_checked && let Some(status) = parser.status() {
                    status_checked = true;
                    // A parsed u16 — inherently safe to log (no
                    // log-injection surface like raw text lines).
                    serial_println!("http: status {status}");
                    if status != 200 {
                        fatal("unexpected HTTP status (expected 200)");
                    }
                }
                if progress.body > 0 {
                    if body_head_len < body_head.len() {
                        let take = min(body_head.len() - body_head_len, progress.body);
                        body_head[body_head_len..body_head_len + take]
                            .copy_from_slice(&staging[..take]);
                        body_head_len += take;
                    }
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

    // A real, fully-framed body with real content: any valid
    // robots.txt declares its user agent.
    if body_total == 0 {
        fatal("empty response body");
    }
    if !body_head[..body_head_len]
        .windows(b"User-agent:".len())
        .any(|window| window == b"User-agent:")
    {
        fatal("body does not look like robots.txt (no User-agent)");
    }
    serial_println!("http: {body_total} bytes framed");
    serial_println!("HTTP_OK"); // machine-checked by `cargo xtask smoke`

    // Orderly shutdown: close_notify (best-effort — the server's own
    // close_notify already authenticated everything we read; a failure
    // here cannot retroactively corrupt it) then TCP FIN.
    let socket = match tls.close() {
        Ok(socket) => socket,
        Err((socket, e)) => {
            serial_println!("tls: close_notify not sent: {e:?}");
            socket
        }
    };
    let Socket {
        conn: conn_ref,
        nic: nic_ref,
        ..
    } = socket;
    conn_ref.close(nic_ref);
}

/// `embedded_io` transport over one TCP connection.
///
/// - `read` drains a small stash first, then blocks on `Conn::recv`
///   with the same stall/retransmit budget the plain-HTTP smoke uses;
///   payload that arrives while TLS asks for a shorter slice (record
///   headers are 5 bytes; segments are up to one MSS) is stashed, not
///   dropped.
/// - `write` sends at most one MSS per segment and waits for the
///   previous segment's ACK first (`Conn` allows one outstanding
///   segment); payload received while waiting lands in the stash.
struct Socket<'a> {
    conn: &'a mut Conn,
    nic: &'a mut E1000,
    /// Received bytes not yet handed to the TLS reader (static: see
    /// `STASH`).
    stash: &'a mut [u8; STASH_CAP],
    stash_len: usize,
    stash_pos: usize,
    /// Last transmitted segment, for retransmission on stall (static:
    /// see `LAST`).
    last: &'a mut [u8; MAX_SEND],
    last_len: usize,
}

impl<'a> Socket<'a> {
    fn new(conn: &'a mut Conn, nic: &'a mut E1000) -> Self {
        // SAFETY: the stash/last statics are single-use, taken once by
        // `https_smoke` on a single core; the only handler in play
        // (IRQ0) never touches them.
        let stash = unsafe { &mut *core::ptr::addr_of_mut!(STASH) };
        let last = unsafe { &mut *core::ptr::addr_of_mut!(LAST) };
        Socket {
            conn,
            nic,
            stash,
            stash_len: 0,
            stash_pos: 0,
            last,
            last_len: 0,
        }
    }

    /// Append received bytes to the stash, aborting loudly if it would
    /// overflow (a bounded, documented failure — never a silent drop).
    fn stash_push(&mut self, data: &[u8]) {
        let free = STASH_CAP - self.stash_len;
        if data.len() > free {
            fatal("receive stash overflow while waiting for an ACK");
        }
        self.stash[self.stash_len..self.stash_len + data.len()].copy_from_slice(data);
        self.stash_len += data.len();
    }

    /// Serve from the stash first (bytes are already released from the
    /// connection's window); `None` when the stash is empty.
    fn stash_take(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.stash_pos == self.stash_len {
            self.stash_len = 0;
            self.stash_pos = 0;
            return None;
        }
        let n = min(buf.len(), self.stash_len - self.stash_pos);
        buf[..n].copy_from_slice(&self.stash[self.stash_pos..self.stash_pos + n]);
        self.stash_pos += n;
        Some(n)
    }

    /// Retransmit the outstanding segment while nothing new arrives.
    fn resend_stalled(&mut self, stalls: u32) -> Result<(), TlsError> {
        if stalls > ATTEMPTS {
            return Err(TlsError::Io(ErrorKind::TimedOut));
        }
        if self.conn.has_unacked() {
            if self.last_len == 0 {
                return Err(TlsError::Io(ErrorKind::TimedOut));
            }
            let last_len = self.last_len;
            self.conn.resend(self.nic, &self.last[..last_len]);
        }
        Ok(())
    }

    /// Pump the connection until everything we sent is acknowledged,
    /// retransmitting on stall; any payload received on the way is
    /// stashed. This is what keeps `Conn`'s one-outstanding-segment
    /// invariant true across back-to-back writes (e.g. the
    /// middlebox-compat CCS + Finished pair).
    fn wait_ack(&mut self) -> Result<(), TlsError> {
        let mut scratch = [0u8; MAX_SEND];
        let mut stalls: u32 = 0;
        while self.conn.has_unacked() {
            match self.conn.recv(self.nic, &mut scratch) {
                Some(0) => stalls = stalls.saturating_add(1), // FIN: keep waiting for the ACK
                Some(n) => {
                    self.conn.release(n);
                    self.stash_push(&scratch[..n]);
                    stalls = 0;
                }
                None => {
                    stalls += 1;
                    self.resend_stalled(stalls)?;
                }
            }
        }
        Ok(())
    }
}

impl embedded_io::ErrorType for Socket<'_> {
    type Error = TlsError;
}

impl Read for Socket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(n) = self.stash_take(buf) {
            return Ok(n);
        }
        let mut scratch = [0u8; MAX_SEND];
        let mut stalls: u32 = 0;
        loop {
            match self.conn.recv(self.nic, &mut scratch) {
                Some(0) => return Ok(0), // peer FIN: transport EOF
                Some(n) => {
                    self.conn.release(n);
                    self.stash_push(&scratch[..n]);
                    // Invariant: stash was empty above and holds ≤ MSS
                    // now, so this always yields ≥ 1 byte.
                    return Ok(self.stash_take(buf).unwrap_or(0));
                }
                None => {
                    stalls += 1;
                    self.resend_stalled(stalls)?;
                }
            }
        }
    }
}

impl Write for Socket<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut sent = 0;
        while sent < buf.len() {
            self.wait_ack()?;
            let n = min(MAX_SEND, buf.len() - sent);
            self.conn.send(self.nic, &buf[sent..sent + n]);
            self.last[..n].copy_from_slice(&buf[sent..sent + n]);
            self.last_len = n;
            sent += n;
        }
        Ok(sent)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.wait_ack()
    }
}
