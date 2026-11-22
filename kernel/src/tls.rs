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

/// [`fatal`] with the caller's prefix: the legacy paths pass `"tls"`
/// (byte-identical messages), B1's browser fetch passes `"browser"`.
fn fatal_as(who: &str, msg: &str) -> ! {
    serial_println!("FATAL: {who}: {msg}");
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

/// Validation policy for one exchange through [`exchange`] — the
/// legacy strict mode ([`tls_fetch`]: status must be 200 at head-parse
/// time, optional `Content-Type` assertion, [`READ_CAP`] bound) vs the
/// browser's redirect mode ([`tls_fetch_any`]: the status goes back to
/// the caller, which follows 3xx or asserts 200 itself).
struct Policy<'a> {
    /// Refuse any status ≠ 200 as soon as the head parses.
    require_200: bool,
    /// Assert `Content-Type` starts with these bytes (legacy only).
    expect_ct: Option<&'a [u8]>,
    /// Total-body bound: bytes past it are fatal, never truncated.
    cap: usize,
    /// `FATAL: {who}: …` prefix for failures inside the exchange
    /// (the legacy paths pass `"tls"`, the browser passes `"browser"`).
    who: &'a str,
}

/// Caller bounds for [`tls_fetch_any`] (the B1 redirect fetch): a
/// total-body cap and the `FATAL:` prefix its failures carry. The
/// buffers stay with the caller so the browser's plain and TLS hops
/// share one set of statics.
pub(crate) struct FetchCfg<'a> {
    /// Total-body bound for the hop (a hostile server cannot exhaust
    /// the heap — bytes past the caller's head sample are counted).
    pub cap: usize,
    /// `FATAL: {who}: …` — the browser passes `"browser"`.
    pub who: &'a str,
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
    let policy = Policy {
        require_200: true,
        expect_ct,
        cap: READ_CAP,
        who: "tls",
    };
    let mut req = [0u8; 512];
    let Some(req_len) = http::build_request(&mut req, host, path, headers) else {
        fatal_as(policy.who, "GET request does not fit the buffer");
    };
    let (status, body_total, _loc_len) = exchange(tls, &req[..req_len], policy, body, &mut []);
    (status, body_total)
}

/// A smart-HTTP request body and its media type (the `tls_post`
/// argument bundle — keeps the call under clippy's argument budget).
pub(crate) struct Post<'a> {
    /// Request path (`/owner/repo.git/git-upload-pack`).
    pub path: &'a str,
    /// `Content-Type` of the request body.
    pub content_type: &'a str,
    /// The pkt-line request stream.
    pub body: &'a [u8],
}

/// POST variant of [`tls_fetch`] for the smart-HTTP git fetch (G3):
/// the identical framing/validation policy, but the request is a
/// `POST` whose body is the pkt-line want/deepen/done stream
/// (http-protocol: "the client can request ... POST ... with the
/// body"), and the response bound is the caller's — a pack is far
/// larger than [`READ_CAP`]. Always requires a 200 and the
/// `application/x-git-upload-pack-result` media type; any other
/// response is fatal (see [`crate::git_fetch`]).
pub(crate) fn tls_post(
    tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>,
    host: &str,
    post: Post<'_>,
    expect_ct: &[u8],
    cap: usize,
    body: &mut [u8],
) -> (u16, usize) {
    let policy = Policy {
        require_200: true,
        expect_ct: Some(expect_ct),
        cap,
        who: "git",
    };
    let mut req = [0u8; 1024];
    // The accept header is what tells http-backend to hand back the
    // raw `git-upload-pack-result` rather than anything re-encoded.
    let Some(req_len) = http::build_post(
        &mut req,
        host,
        post.path,
        post.content_type,
        post.body,
        &[
            "Accept: application/x-git-upload-pack-result",
            "User-Agent: reemplazo-git/0.1",
        ],
    ) else {
        fatal_as(policy.who, "POST request does not fit the buffer");
    };
    let (status, body_total, _loc_len) = exchange(tls, &req[..req_len], policy, body, &mut []);
    (status, body_total)
}

/// One event from a **fallible** POST (A4's user-driven chat): the
/// response head as soon as it parses, then each decoded body chunk in
/// arrival order. Wire bytes (`content_type`, `Body`) are valid only
/// for the duration of the callback — callers copy what they keep and
/// never log them raw (the `ct_matches`/`sanitize` rule).
pub(crate) enum PostEvent<'a> {
    /// The head parsed: status code and the raw `Content-Type` value.
    Head {
        status: u16,
        content_type: Option<&'a [u8]>,
    },
    /// One decoded body chunk (`Content-Length`, chunked and
    /// close-delimited framing all arrive through here).
    Body(&'a [u8]),
}

/// What a [`PostEvent`] callback wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFlow {
    /// Keep reading.
    Continue,
    /// The caller has everything it needs (a stream's `[DONE]`): stop
    /// reading now and recycle the connection.
    Stop,
}

/// Request buffer for [`tls_post_soft`]: path + headers + the chat JSON
/// body. A static (not a stack local) because this runs on the shell's
/// stack alongside the TLS session; the bound is generous for a
/// chat request (a 512-byte message can double under JSON escaping).
const SOFT_REQ_CAP: usize = 8192;
static mut SOFT_REQ: [u8; SOFT_REQ_CAP] = [0; SOFT_REQ_CAP];

/// Fallible [`tls_open`] for **user-driven** work (A4's chat).
///
/// Why a second entry exists: [`tls_open`] (and [`tls_fetch`] /
/// [`tls_post`]) are **fail-closed by design** — they `FATAL:` + halt,
/// which is right for every boot proof (a broken TLS chain must stop
/// the smoke loudly) but wrong for a shell builtin, where the contract
/// is "print/render one error and return to the prompt"
/// (`shell.rs`). This entry therefore duplicates the connect +
/// handshake sequence and returns every failure as `Err`, aborting the
/// TCP socket on the way out so the next attempt finds a connectable
/// socket. The boot paths are untouched and byte-identical.
///
/// Trust is unchanged: the same pinned USERTrust ECC root, the same
/// hostname/chain/EKU checks. An endpoint whose chain does not
/// terminate there (Let's Encrypt, Amazon, …) therefore fails closed
/// with an error, not a fallback — the documented single-root caveat
/// until the multi-root store lands.
pub(crate) fn tls_open_soft<'a>(
    stack: &'a mut Stack,
    handle: SocketHandle,
    ip: Ipv4Address,
    host: &str,
    local_port: u16,
) -> Result<TlsConnection<'a, Stream<'a>, Aes128GcmSha256>, &'static str> {
    // A previous user attempt may have died mid-handshake: reset the
    // socket so `connect` can own it (`connect` refuses an open socket).
    if stack.sockets.get::<tcp::Socket>(handle).is_open() {
        stack.sockets.get_mut::<tcp::Socket>(handle).abort();
        stack.poll();
    }
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if sock
            .connect(stack.iface.context(), (ip, 443u16), local_port)
            .is_err()
        {
            return Err("tcp connect rejected");
        }
    }
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        match stack.sockets.get::<tcp::Socket>(handle).state() {
            tcp::State::Established => break,
            tcp::State::Closed => return Err("connection refused or reset"),
            _ => {}
        }
        if clock::now_ms() > deadline {
            stack.sockets.get_mut::<tcp::Socket>(handle).abort();
            stack.poll();
            return Err("tcp connect timeout");
        }
    }

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
    // SAFETY: the same single-use record buffers as `tls_open` —
    // sequential TLS sessions on the single core, IRQ0 never touches
    // them (module SAFETY note above `READ_STORAGE`).
    let read_buf = unsafe { &mut *addr_of_mut!(READ_STORAGE) };
    let write_buf = unsafe { &mut *addr_of_mut!(WRITE_STORAGE) };
    let mut tls: TlsConnection<'a, Stream<'a>, Aes128GcmSha256> =
        TlsConnection::new(stream, read_buf, write_buf);

    let verifier: CertVerifier<'_, Aes128GcmSha256, RtcClock, CERT_SIZE> =
        CertVerifier::new(Certificate::X509(ROOT_CA));
    let config = TlsConfig::new().with_server_name(host);
    if let Err(e) = tls.open(TlsContext::new(&config, verifier)) {
        // Never a halt on the user path. Recycle the transport: close
        // is best-effort (a failed handshake has nothing to notify),
        // then RST so no TIME-WAIT holds the port.
        serial_println!("tls: soft handshake failed: {e:?}");
        let mut stream = match tls.close() {
            Ok(stream) => stream,
            Err((stream, _)) => stream,
        };
        stream.tcp().abort();
        stream.pump();
        return Err("TLS handshake failed (endpoint chain vs pinned USERTrust root)");
    }
    serial_println!("tls: handshake ok (TLS 1.3, pinned USERTrust ECC root)");
    Ok(tls)
}

/// Fallible POST for **user-driven** work (A4): identical framing and
/// validation to [`tls_post`], but every failure is an `Err` instead of
/// `FATAL:` + halt, the status is returned rather than required to be
/// 200 (the caller renders it), and the decoded body streams into
/// `on` as it arrives — that is what makes SSE rendering incremental
/// (`ResponseParser::feed` already emits body bytes per transport
/// read; close-delimited, chunked and `Content-Length` responses all
/// work).
///
/// `cap` bounds the **total** body; bytes past it are refused, never
/// truncated. A callback returning [`ReadFlow::Stop`] (SSE `[DONE]`)
/// ends the read immediately; the connection is then closed with
/// close_notify best-effort plus an RST, so a user session can open the
/// next one without a 10-second TIME-WAIT. Returns
/// `(status, total_body_bytes)`.
pub(crate) fn tls_post_soft<F>(
    tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>,
    host: &str,
    post: Post<'_>,
    extra_headers: &[&str],
    cap: usize,
    mut on: F,
) -> Result<(u16, usize), &'static str>
where
    F: FnMut(PostEvent<'_>) -> Result<ReadFlow, &'static str>,
{
    // SAFETY: single-use static request buffer (module SAFETY note).
    let req = unsafe { &mut *addr_of_mut!(SOFT_REQ) };
    let Some(req_len) = http::build_post(
        req,
        host,
        post.path,
        post.content_type,
        post.body,
        extra_headers,
    ) else {
        soft_shutdown(tls);
        return Err("POST request does not fit the buffer");
    };

    let mut tls = tls;
    if tls.write_all(&req[..req_len]).is_err() || tls.flush().is_err() {
        soft_shutdown(tls);
        return Err("TLS write failed");
    }

    // SAFETY: single-use statics (module SAFETY note). Reset first: the
    // parser serves every sequential exchange in this module.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let mut status = 0u16;
    let mut head_sent = false;
    let mut body_total = 0usize;
    let mut scratch = [0u8; SCRATCH];
    loop {
        match tls.read(&mut scratch) {
            Ok(0) => {
                soft_shutdown(tls);
                return Err("transport EOF without close_notify (truncated response)");
            }
            Ok(n) => {
                let progress = match parser.feed(&scratch[..n], staging) {
                    Ok(progress) => progress,
                    Err(_) => {
                        soft_shutdown(tls);
                        return Err("HTTP response refused");
                    }
                };
                if !head_sent && let Some(s) = parser.status() {
                    head_sent = true;
                    status = s;
                    // A parsed u16 — safe to log (no log-injection
                    // surface, the same line the boot paths print).
                    serial_println!("http: status {s}");
                    let content_type = http::header_value(parser.head(), b"content-type");
                    match on(PostEvent::Head {
                        status: s,
                        content_type,
                    }) {
                        Ok(ReadFlow::Continue) => {}
                        Ok(ReadFlow::Stop) => break,
                        Err(e) => {
                            soft_shutdown(tls);
                            return Err(e);
                        }
                    }
                }
                if progress.body > 0 {
                    // Disjoint borrows of two statics are fine, but the
                    // framer wrote `progress.body` bytes into `staging`.
                    let chunk = &staging[..progress.body];
                    body_total = body_total.saturating_add(progress.body);
                    if body_total > cap {
                        soft_shutdown(tls);
                        return Err("response body exceeds the byte bound");
                    }
                    match on(PostEvent::Body(chunk)) {
                        Ok(ReadFlow::Continue) => {}
                        Ok(ReadFlow::Stop) => break,
                        Err(e) => {
                            soft_shutdown(tls);
                            return Err(e);
                        }
                    }
                }
                if progress.complete {
                    break;
                }
            }
            Err(TlsError::ConnectionClosed) => {
                // Authenticated shutdown: EOF for close-delimited
                // bodies; a short framed body is truncated, never
                // "close enough".
                if parser.eof().is_err() {
                    soft_shutdown(tls);
                    return Err("response truncated");
                }
                break;
            }
            Err(_) => {
                soft_shutdown(tls);
                return Err("TLS read failed");
            }
        }
    }
    if !head_sent {
        soft_shutdown(tls);
        return Err("response head never parsed");
    }
    soft_shutdown(tls);
    Ok((status, body_total))
}

/// Best-effort close for the fallible path: `close_notify`, then an RST.
/// The response is already fully framed when this is called on success
/// (or deliberately abandoned on an error); the RST skips TIME-WAIT so
/// the next user-driven connection is immediate — the same reasoning as
/// the browser's intermediate-hop close.
fn soft_shutdown(tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>) {
    let mut stream = match tls.close() {
        Ok(stream) => stream,
        Err((stream, _)) => stream,
    };
    stream.tcp().abort();
    stream.pump();
    serial_println!("tls: soft connection closed (RST, no TIME-WAIT)");
}

/// B1's redirect-aware exchange (docs/browser.md §7): like
/// [`tls_fetch`] but the **status is returned, not asserted** — the
/// caller follows a 3xx or accepts the 200 — the raw `Location`
/// header value is copied into `loc` (the returned `usize` is the
/// value's full length: `0` = absent, and a value longer than `loc`
/// is the caller's to refuse before using it), the body bound and the
/// `FATAL:` prefix come from `cfg`, and the close is
/// redirect-aware: a **3xx aborts** (close_notify best-effort, then
/// RST — no TIME-WAIT, so the socket and its local port recycle for
/// the next hop immediately), everything else closes gracefully
/// (close_notify + FIN + wait for TimeWait/Closed, the historical
/// clean close of the final hop). Returns
/// `(status, total_body_bytes, location_len)`.
pub(crate) fn tls_fetch_any(
    tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>,
    host: &str,
    path: &str,
    headers: &[&str],
    body: &mut [u8],
    loc: &mut [u8],
    cfg: FetchCfg<'_>,
) -> (u16, usize, usize) {
    let policy = Policy {
        require_200: false,
        expect_ct: None,
        cap: cfg.cap,
        who: cfg.who,
    };
    let mut req = [0u8; 512];
    let Some(req_len) = http::build_request(&mut req, host, path, headers) else {
        fatal_as(policy.who, "GET request does not fit the buffer");
    };
    exchange(tls, &req[..req_len], policy, body, loc)
}

/// The exchange all entry points share: send `request` (a complete
/// HTTP/1.1 head plus any POST body), frame the response through the
/// module's `PARSER` static (reset first — one parser runs every
/// sequential exchange), bound the body, extract `Location`, then close
/// per [`Policy`] + status. Every failure is
/// `FATAL: {policy.who}: …` + [`crate::halt`] — a partial result is
/// never returned.
fn exchange(
    tls: TlsConnection<'_, Stream<'_>, Aes128GcmSha256>,
    request: &[u8],
    policy: Policy<'_>,
    body: &mut [u8],
    loc: &mut [u8],
) -> (u16, usize, usize) {
    let mut tls = tls;
    // `Connection: close` in the request makes the server finish with
    // close_notify + FIN.
    if let Err(e) = tls.write_all(request) {
        serial_println!("FATAL: {}: write failed: {:?}", policy.who, e);
        crate::halt();
    }
    if let Err(e) = tls.flush() {
        serial_println!("FATAL: {}: flush failed: {:?}", policy.who, e);
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
    let mut ct_checked = policy.expect_ct.is_none();
    let mut body_total = 0usize;
    let mut body_stored = 0usize;
    let mut loc_len = 0usize;
    let mut scratch = [0u8; SCRATCH];
    loop {
        match tls.read(&mut scratch) {
            Ok(0) => fatal_as(
                policy.who,
                "transport EOF without close_notify (truncated response)",
            ),
            Ok(n) => {
                let progress = match parser.feed(&scratch[..n], staging) {
                    Ok(progress) => progress,
                    Err(e) => {
                        serial_println!("FATAL: {}: HTTP response refused: {:?}", policy.who, e);
                        crate::halt();
                    }
                };
                if !status_checked && let Some(s) = parser.status() {
                    status_checked = true;
                    status = s;
                    // A parsed u16 — inherently safe to log (no
                    // log-injection surface like raw text lines).
                    serial_println!("http: status {s}");
                    if policy.require_200 && s != 200 {
                        fatal_as(policy.who, "unexpected HTTP status (expected 200)");
                    }
                    if let Some(expected) = policy.expect_ct {
                        // Header values come off the wire: compared,
                        // never logged.
                        match http::header_value(parser.head(), b"content-type") {
                            Some(value) if ct_matches(value, expected) => {}
                            Some(_) => fatal_as(policy.who, "unexpected Content-Type"),
                            None => fatal_as(policy.who, "response has no Content-Type"),
                        }
                        ct_checked = true;
                    }
                    // Redirect resolution input (B1): copy the raw
                    // `Location` value out of the head while it is
                    // still current. Wire bytes — the caller sanitizes
                    // before printing and refuses an over-long value.
                    if let Some(value) = http::header_value(parser.head(), b"location") {
                        loc_len = value.len();
                        let take = min(loc.len(), value.len());
                        loc[..take].copy_from_slice(&value[..take]);
                    }
                }
                if progress.body > 0 {
                    let take = min(body.len() - body_stored, progress.body);
                    body[body_stored..body_stored + take].copy_from_slice(&staging[..take]);
                    body_stored += take;
                    body_total += progress.body;
                    if body_total > policy.cap {
                        fatal_as(policy.who, "response body exceeds the byte bound");
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
                    serial_println!("FATAL: {}: response truncated: {:?}", policy.who, e);
                    crate::halt();
                }
                break;
            }
            Err(e) => {
                serial_println!("FATAL: {}: read failed: {:?}", policy.who, e);
                crate::halt();
            }
        }
    }
    if !ct_checked {
        fatal_as(
            policy.who,
            "response head never parsed (Content-Type unchecked)",
        );
    }

    // Orderly TLS shutdown: close_notify (best-effort — the server's
    // own close_notify already authenticated everything we read; a
    // failure here cannot retroactively corrupt it), then the TCP
    // close per the hop's role in a redirect chain.
    let mut stream = match tls.close() {
        Ok(stream) => stream,
        Err((stream, e)) => {
            serial_println!("{}: close_notify not sent: {:?}", policy.who, e);
            stream
        }
    };
    if (300..400).contains(&status) {
        // Intermediate hop: RST instead of FIN. smoltcp sends the RST
        // on the very next poll (an aborted socket with a tuple
        // reports `PollAt::Now`, then forgets the tuple) and never
        // enters TIME-WAIT, so the socket recycles for the next
        // redirect hop immediately — the 30 s smoke has no budget for
        // a 10 s TIME-WAIT. The response was fully framed before we
        // got here; nothing in flight is lost.
        stream.tcp().abort();
        stream.pump();
        serial_println!("{}: connection aborted (RST, no TIME-WAIT)", policy.who);
        return (status, body_total, loc_len);
    }
    stream.tcp().close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stream.pump();
        let state = stream.tcp().state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            serial_println!("{}: connection closed cleanly ({state})", policy.who);
            return (status, body_total, loc_len);
        }
        if clock::now_ms() > deadline {
            fatal_as(
                policy.who,
                "timeout closing connection (never reached TimeWait/Closed)",
            );
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
