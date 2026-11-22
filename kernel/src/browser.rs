//! B1 of docs/browser.md (§3 URL handling, §7 networking): URL
//! parsing/resolution through the `url` crate plus a
//! redirect-following HTTP(S) GET — the smoke test's
//! `BROWSER_FETCH_OK`. B2 (§4/§6) adds [`render_smoke`]: the same
//! fetch parameterized for a second URL, feeding the `dom` tree
//! builder and the text-layout viewport proof (`BROWSER_RENDER_OK`).
//!
//! Chain proven on every boot: parse [`START_URL`]
//! (`http://github.com/…`), plain-HTTP GET → `301 + Location`
//! (`Content-Length: 0`) → resolve the reference against the base URL
//! through `url::Url::join` → TLS GET → `200` with a ~290 KiB chunked
//! HTML body. Up to [`MAX_REDIRECTS`] redirects are followed (docs §7
//! N=5); https→http downgrades, non-http(s) schemes, a 3xx without
//! `Location`, an unresolvable reference and the hop cap are all
//! fail-closed (`FATAL: browser:` + [`crate::halt`]).
//!
//! Sockets (the repo's TIME-WAIT discipline): one plain connection
//! ([`netstack::Storage::tcp6`], local port [`PLAIN_PORT`]) and one
//! TLS connection ([`netstack::Storage::tcp7`], [`TLS_PORT`]). An
//! **intermediate hop aborts** — close_notify best-effort, then RST —
//! so smoltcp never enters TIME-WAIT and the socket recycles for the
//! next hop of its class immediately; the **final hop closes
//! gracefully** (FIN, proven to reach TimeWait/Closed). Both classes
//! share the same rule, so a chain of any http/https mix reuses at
//! most those two sockets (the 30 s smoke has no TIME-WAIT budget).
//!
//! The body is bounded by [`BODY_CAP`] with only a [`BODY_SAMPLE`]-byte
//! head kept (bytes past it are counted, never stored) — a hostile
//! server cannot exhaust the heap. Wire data (URLs, `Location`, hosts)
//! reaches the serial log and the VGA mirror only through
//! [`sanitize`], and `serial_println!` evaluates its arguments twice,
//! so every logged expression stays side-effect free.
//!
//! # B4: one pipeline, two front-ends
//!
//! The hop loop is **fallible** ([`NavError`]) and has two callers: the
//! boot proofs ([`fetch`], [`FetchPolicy::BOOT`] — TLS allowed, a 10 s
//! connect bound, any error `FATAL: browser:` + [`crate::halt`], the
//! semantics the B1/B2 markers were proven with), and the interactive
//! browser app ([`navigate`], [`FetchPolicy::NAV`] — the error goes back
//! to the caller, which renders it as a page; a 3 s connect bound so a
//! dead endpoint cannot stall the UI; **no TLS hop**: `tls::tls_open`
//! is fail-closed by design and `tls.rs` is outside B4's change set, so
//! the app refuses `https` with a page instead of risking a halt — see
//! `docs/browser.md` §8 row B4).
//!
//! The app also resets a stale socket before connecting: a hop that hit
//! its deadline can leave the socket open, and navigation must never
//! inherit that state. Wire detail (`{:?}` of a parser error, the port
//! that refused) goes to its own `browser:` serial line; the page text
//! and the `FATAL:` line carry only the fixed [`NavError`] wording.
//!
//! A browser navigates the same page many times, so the app's policy
//! also differs at the socket: it **resets** after every hop (RST — the
//! body is already framed) instead of proving the graceful close, and it
//! rotates through 64 local ports, so neither our TIME-WAIT nor the
//! peer's can swallow the next SYN to the same host:port. Both are
//! [`FetchPolicy`] fields; [`FetchPolicy::BOOT`] keeps B1/B2 exactly as
//! they were.

use crate::clock;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use crate::tls::{self, FetchCfg};
use core::cmp::min;
use core::fmt;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use net::http::{self, ResponseParser};
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;
use url::Url;

/// Start URL: plain `http://github.com/…` — a real, stable host whose
/// http endpoint 301s to https, so every boot exercises a plain hop,
/// a redirect resolution and a TLS hop (docs/browser.md §7 row B1).
const START_URL: &str = "http://github.com/LuisErnestoZamb/reemplazo";
/// B2's render URL (docs/browser.md §7 row B2): a real, stable,
/// ~600-byte page with a direct `200` and no redirect.
///
/// **Why plain `http`, not `https`** (documented deviation): today's
/// `example.com` is served by Cloudflare with a chain that terminates
/// at `AAA Certificate Services` (leaf → Cloudflare TLS Issuing ECC
/// CA 3 → SSL.com Transit → SSL.com Root → Comodo AAA), while
/// `tls.rs` pins exactly **one** trust anchor — the USERTrust ECC CA —
/// and `tls.rs` is outside B2's change set. The TLS hop would refuse
/// the chain fail-closed, so the render proof fetches the identical
/// page over plain HTTP (verified: `http://example.com` answers `200`
/// directly, no redirect, `Content-Length` framed). Revisit when
/// `tls.rs` grows a multi-root store.
const RENDER_URL: &str = "http://example.com";
/// Redirects followed before refusing (docs §7: N=5). A chain still
/// redirecting after five hops is refused, never looped.
const MAX_REDIRECTS: usize = 5;
/// Total-body bound for one hop: the start URL's final page measured
/// 290 843 bytes (identity encoding, 2026-11-22), and only
/// [`BODY_SAMPLE`] bytes are ever stored — the cap buys time-bounded
/// reading, not memory. Over it is fatal, never truncated.
const BODY_CAP: usize = 1024 * 1024;
/// Head of the final body kept for assertions (bytes past it are
/// counted, not stored).
const BODY_SAMPLE: usize = 4096;
/// One read/parse chunk for the plain hop: the framer never expands,
/// so the staging buffer must hold a full read (`feed` refuses
/// `body_out` smaller than its input).
const SCRATCH: usize = 1460;
/// `Location` slot: the fetch returns the value's full length, and a
/// value longer than this is refused before any use of it.
const LOC_CAP: usize = 512;
/// Local port of the plain hop (`netstack::Storage::tcp6`).
const PLAIN_PORT: u16 = 49164;
/// Local port of the TLS hop (`netstack::Storage::tcp7`).
const TLS_PORT: u16 = 49165;
/// Default port of the plain scheme — the `Host` header drops it
/// (RFC 9110 §7.2 SHOULD NOT include the default port).
const HTTP_PORT: u16 = 80;
/// Request headers (docs §7): our own `User-Agent`, no
/// `Accept-Encoding` (so no gzip to decode), an HTML-first `Accept`.
const HEADERS: [&str; 2] = [
    "User-Agent: reemplazo-browser/0.1",
    "Accept: text/html,*/*;q=0.5",
];
/// Printable-ASCII bound for one sanitized log line (URLs, hosts,
/// `Location` values are display-only: longer ones are truncated with
/// `?`-fill, never wrapped or rejected because of the log).
const SANITIZE_CAP: usize = 240;
/// Connect bound of the **navigation app** (B4): the boot proofs keep
/// [`OP_DEADLINE_MS`] (10 s — a slow real network is fine at boot), but
/// an interactive navigation must turn a dead endpoint into a page
/// quickly. Every loop that uses it is deadline-bounded, so this is an
/// upper bound on the app's stall, never a hang.
const NAV_CONNECT_MS: u64 = 3_000;

/// Why one navigation attempt failed. The **app** renders [`Display`]
/// (`fmt::Display`) as the error page's cause line; the boot proofs
/// print the same text as `FATAL: browser: {e}`. Every variant carries
/// fixed, printable-ASCII wording (or a parsed status number) — never
/// wire bytes, so the page and the log are injection-free by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NavError {
    /// URL-level refusal: parse, scheme, host, port, request target.
    Url(&'static str),
    /// The resolver produced no answer for the host.
    Dns,
    /// The connection never came up (refused, reset, timeout) or died
    /// while the request was being sent.
    Connect,
    /// The HTTP response could not be framed/read to completion.
    Http(&'static str),
    /// The redirect chain was refused (cap, missing/malformed Location,
    /// protocol downgrade).
    Redirect(&'static str),
    /// A final status outside `200`/`3xx`.
    Status(u16),
    /// The body exceeded [`BODY_CAP`].
    TooLarge,
    /// `200` with a zero-length body.
    Empty,
    /// `https` cannot be navigated from the app in this build — see the
    /// module docs and `docs/browser.md` §8 row B4.
    TlsUnavailable,
}

impl fmt::Display for NavError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(why) | Self::Http(why) | Self::Redirect(why) => f.write_str(why),
            Self::Dns => f.write_str("dns: no answer for the host"),
            Self::Connect => f.write_str("connection failed or timed out"),
            Self::Status(status) => write!(f, "unexpected HTTP status {status}"),
            Self::TooLarge => f.write_str("response body exceeds the byte bound"),
            Self::Empty => f.write_str("empty response body"),
            Self::TlsUnavailable => f.write_str(
                "https is not navigable in this session (single pinned trust anchor; \
                 see docs/browser.md)",
            ),
        }
    }
}

/// How one fetch behaves — the only difference between the boot proofs
/// and the navigation app.
#[derive(Clone, Copy)]
struct FetchPolicy {
    /// May the loop enter the fail-closed TLS hop? (`tls.rs` is outside
    /// B4's change set; the app says no and renders a page instead.)
    tls: bool,
    /// Connect-phase bound in milliseconds.
    connect_ms: u64,
    /// Close the final hop gracefully (FIN + wait for TimeWait/Closed)?
    /// The boot proofs do — that close is one of their proofs. The app
    /// **resets** instead (after the body is fully framed): a browser
    /// navigates repeatedly, a graceful close leaves this 4-tuple in
    /// TIME-WAIT on both sides, and the next SYN to the same host:port
    /// is then answered from the server's TIME-WAIT entry (observed: a
    /// connect timeout on a second visit to the same page). RST tears
    /// the peer's TCB down immediately.
    graceful_close: bool,
    /// Pick a fresh local port for every hop instead of the fixed boot
    /// port: the app must never collide with a 4-tuple the boot chain
    /// (or a previous session) left in the peer's TIME-WAIT — e.g.
    /// `browse http://example.com` right after the B2 proof, which used
    /// the same source port. Cheap (64 ports, round-robin) and it makes
    /// the first navigation deterministic.
    rotate_port: bool,
}

impl FetchPolicy {
    /// The boot proofs: the exact pre-B4 semantics.
    const BOOT: Self = Self {
        tls: true,
        connect_ms: OP_DEADLINE_MS,
        graceful_close: true,
        rotate_port: false,
    };
    /// The navigation app: errors become pages, no TLS hop, short
    /// connect bound, RST close and a rotating source port (repeat
    /// navigation).
    const NAV: Self = Self {
        tls: false,
        connect_ms: NAV_CONNECT_MS,
        graceful_close: false,
        rotate_port: true,
    };
}

/// The app's rotating local-port range: 64 ports, away from the
/// documented fixed ports (49152 plain smoke, 49160–49166 TLS/git/ssh/
/// AI/browser/fetch).
const NAV_PORT_BASE: u16 = 49300;
const NAV_PORT_COUNT: u16 = 64;
/// Round-robin counter behind [`next_nav_port`] (single core, no IRQ
/// touches it; only the app fetches use it).
static NAV_SEQ: AtomicU16 = AtomicU16::new(0);

/// The next local port for an app hop (see
/// [`FetchPolicy::rotate_port`]).
fn next_nav_port() -> u16 {
    let step = NAV_SEQ.fetch_add(1, Ordering::Relaxed) % NAV_PORT_COUNT;
    NAV_PORT_BASE.wrapping_add(step)
}

/// Single-use statics — the `READ_STORAGE` idiom of `tls.rs`: written
/// once from `fetch_smoke` on a single core; the only handler in play
/// (IRQ0) never touches them.
///
/// Response parser for the **plain** hop (the TLS hop runs `tls.rs`'s
/// own parser inside `tls_fetch_any`; each response resets the parser
/// it goes through, so the two can never mix heads).
static mut PARSER: ResponseParser = ResponseParser::new();
/// Body staging for the plain hop — `feed` writes decoded payload
/// here before the head-sample copy.
static mut STAGING: [u8; SCRATCH] = [0; SCRATCH];
/// Final-body head sample, shared by both hop classes (sequential).
static mut BODY: [u8; BODY_SAMPLE] = [0; BODY_SAMPLE];
/// Raw `Location` value of the current hop (wire bytes; the caller
/// sanitizes before printing and validates before resolving).
static mut LOC: [u8; LOC_CAP] = [0; LOC_CAP];
/// Stored length of [`BODY`]'s head after the last [`fetch`] — read by
/// the B3 CSS proof, which reuses the page B2 just rendered instead of
/// spending a second network round-trip.
static STORED: AtomicUsize = AtomicUsize::new(0);

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: browser: {msg}");
    crate::halt()
}

/// Copy `src` into `buf` as printable ASCII, returning the str — raw
/// wire bytes (URLs, hosts, `Location`) never reach the serial log or
/// the VGA mirror (the same log-injection rule as `git::sanitize`).
fn sanitize<'a>(src: &[u8], buf: &'a mut [u8]) -> &'a str {
    let n = src.len().min(buf.len());
    for (slot, &b) in buf[..n].iter_mut().zip(&src[..n]) {
        *slot = if b.is_ascii_graphic() || b == b' ' {
            b
        } else {
            b'?'
        };
    }
    // ASCII by construction → valid UTF-8; `unwrap_or` is fail-closed
    // anyway (a `?`-only string can never fail this).
    core::str::from_utf8(&buf[..n]).unwrap_or("?")
}

/// The request target `path [ "?" query ]` for the request line — the
/// fragment never leaves the client (RFC 3986 §3.3). `None` when it
/// does not fit `buf` or carries a non-ASCII byte: a URL we cannot
/// request faithfully is not fetched (fail-closed).
fn request_target<'a>(url: &Url, buf: &'a mut [u8]) -> Option<&'a str> {
    let path = url.path();
    let query_len = match url.query() {
        Some(query) => query.len().checked_add(1)?, // the '?' prefix
        None => 0,
    };
    let total = path.len().checked_add(query_len)?;
    let out = buf.get_mut(..total)?;
    out[..path.len()].copy_from_slice(path.as_bytes());
    if let Some(query) = url.query() {
        out[path.len()] = b'?';
        out[path.len() + 1..].copy_from_slice(query.as_bytes());
    }
    if out.iter().any(|&b| !b.is_ascii()) {
        return None;
    }
    core::str::from_utf8(out).ok()
}

/// The `Host` header value: `host`, plus `:port` when the port is not
/// the scheme's default (RFC 9110 §7.2 — a non-default port must be
/// shown so the server can route the virtual host). `None` when the
/// composed value does not fit `buf`.
fn host_header<'a>(
    host: &'a str,
    port: u16,
    default_port: u16,
    buf: &'a mut [u8],
) -> Option<&'a str> {
    if port == default_port {
        return Some(host);
    }
    let mut digits = 1usize;
    let mut scale = port / 10;
    while scale > 0 {
        digits += 1;
        scale /= 10;
    }
    let total = host.len().checked_add(1)?.checked_add(digits)?;
    let out = buf.get_mut(..total)?;
    out[..host.len()].copy_from_slice(host.as_bytes());
    out[host.len()] = b':';
    let mut value = port;
    for slot in out[host.len() + 1..].iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    core::str::from_utf8(out).ok()
}

/// One plain hop's request parameters (a struct instead of eight
/// positional arguments): where to connect, what to ask for, and the
/// caller-owned body/`Location` buffers.
struct Hop<'a> {
    /// Resolved endpoint.
    ip: Ipv4Address,
    /// `Host` header value source (already validated as ASCII by `url`).
    host: &'a str,
    /// Destination port (the `Host` header drops the scheme default).
    port: u16,
    /// `path ["?" query]` for the request line.
    target: &'a str,
    /// Head sample of the body (`BODY`).
    body: &'a mut [u8],
    /// `Location` value storage.
    loc: &'a mut [u8],
}

/// One plain-HTTP hop on the browser's `tcp6` socket: reset a stale
/// socket, connect, GET with [`HEADERS`], frame the response through
/// this module's `PARSER` static, then close per the hop's role — a 3xx
/// (or any hop under [`FetchPolicy::NAV`]) `abort()`s (RST, no
/// TIME-WAIT → the socket recycles), a boot proof's final hop closes
/// gracefully and must reach TimeWait/Closed. Returns
/// `(status, total_body_bytes, location_len)` or the [`NavError`] the
/// caller turns into a `FATAL:` line (boot) or a page (app). Every loop
/// is deadline-bounded; no path can hang.
fn plain_fetch(
    stack: &mut Stack,
    hop: Hop<'_>,
    policy: FetchPolicy,
) -> Result<(u16, usize, usize), NavError> {
    let Hop {
        ip,
        host,
        port,
        target,
        body,
        loc,
    } = hop;

    let handle = stack.tcp6_handle;
    // Navigation may run after a hop that hit its deadline mid-flight
    // (socket still SynSent/Established). `is_open` is false only for
    // Closed/TimeWait, so this resets exactly the states `connect`
    // would reject; the poll flushes the pending RST and forgets the
    // tuple. At boot the socket is Closed and this is a no-op.
    if stack.sockets.get::<tcp::Socket>(handle).is_open() {
        stack.sockets.get_mut::<tcp::Socket>(handle).abort();
        stack.poll();
    }
    let local_port = if policy.rotate_port {
        next_nav_port()
    } else {
        PLAIN_PORT
    };
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if let Err(e) = sock.connect(stack.iface.context(), (ip, port), local_port) {
            serial_println!("browser: connect rejected: {e:?}");
            return Err(NavError::Connect);
        }
    }
    let deadline = clock::now_ms() + policy.connect_ms;
    loop {
        stack.poll();
        let state = stack.sockets.get::<tcp::Socket>(handle).state();
        if state == tcp::State::Established {
            break;
        }
        // A refused endpoint answers with RST: `SynSent` → `Closed`
        // immediately, which is an error *now*, not after the deadline.
        if state == tcp::State::Closed {
            serial_println!("browser: connection refused or reset by {ip}:{port}");
            return Err(NavError::Connect);
        }
        if clock::now_ms() > deadline {
            serial_println!("browser: connect timeout to {ip}:{port}");
            abandon(stack);
            return Err(NavError::Connect);
        }
    }
    serial_println!("browser: connected to {ip}:{port}");

    let mut hbuf = [0u8; 600];
    let Some(host_hdr) = host_header(host, port, HTTP_PORT, &mut hbuf) else {
        abandon(stack);
        return Err(NavError::Http("Host header does not fit the buffer"));
    };
    let mut req = [0u8; 512];
    let Some(req_len) = http::build_request(&mut req, host_hdr, target, &HEADERS) else {
        abandon(stack);
        return Err(NavError::Http("GET request does not fit the buffer"));
    };
    let mut sent = 0usize;
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    while sent < req_len {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&req[sent..])
        {
            Ok(n) => sent += n,
            Err(_) => {
                serial_println!("browser: tcp send rejected (connection lost)");
                abandon(stack);
                return Err(NavError::Connect);
            }
        }
        if clock::now_ms() > deadline {
            serial_println!("browser: tcp send timeout");
            abandon(stack);
            return Err(NavError::Connect);
        }
    }

    // Frame the response — content-length / chunked / close-delimited
    // through the shared RFC 9112 framer.
    // SAFETY: single-use statics (see `PARSER`/`STAGING`); this is the
    // only plain-hop exchange in flight and IRQ0 never touches them.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset(); // one parser, sequential responses: start fresh
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let mut status = 0u16;
    let mut status_checked = false;
    let mut body_total = 0usize;
    let mut body_stored = 0usize;
    let mut loc_len = 0usize;
    let mut scratch = [0u8; SCRATCH];
    // Idle bound that re-arms per received chunk (the TLS path's
    // Stream works the same way): a single whole-response deadline
    // would misfire on a slow but healthy body.
    let mut deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        let (can_recv, may_recv, queued, closed) = {
            let sock = stack.sockets.get::<tcp::Socket>(handle);
            (
                sock.can_recv(),
                sock.may_recv(),
                sock.recv_queue(),
                sock.state() == tcp::State::Closed,
            )
        };
        if can_recv {
            let n = stack
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .recv_slice(&mut scratch)
                .unwrap_or(0);
            let progress = match parser.feed(&scratch[..n], staging) {
                Ok(progress) => progress,
                Err(e) => {
                    serial_println!("browser: HTTP response refused: {e:?}");
                    abandon(stack);
                    return Err(NavError::Http("HTTP response refused"));
                }
            };
            deadline = clock::now_ms() + OP_DEADLINE_MS;
            if !status_checked && let Some(s) = parser.status() {
                status_checked = true;
                status = s;
                // The per-hop status line (the TLS hops print the very
                // same `http: status` from `tls_fetch_any`'s loop).
                serial_println!("http: status {s}");
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
                body_total = body_total.saturating_add(progress.body);
                if body_total > BODY_CAP {
                    abandon(stack);
                    return Err(NavError::TooLarge);
                }
            }
            if progress.complete {
                break;
            }
            continue;
        }
        if (!may_recv && queued == 0) || closed {
            // Server FIN (or reset): close-delimited bodies finish
            // here; a framed body still short is refused as truncated.
            if let Err(e) = parser.eof() {
                serial_println!("browser: response truncated: {e:?}");
                abandon(stack);
                return Err(NavError::Http("response truncated"));
            }
            break;
        }
        if clock::now_ms() > deadline {
            serial_println!("browser: timeout waiting for the HTTP response");
            abandon(stack);
            return Err(NavError::Http("timeout waiting for the HTTP response"));
        }
    }
    if !status_checked {
        abandon(stack);
        return Err(NavError::Http("response head never parsed"));
    }

    // Close per the hop's role (the TLS path applies the same rule in
    // `tls_fetch_any`): a 3xx is intermediate → abort with RST, no
    // TIME-WAIT, reusable immediately; anything else is final →
    // graceful FIN close, proven to settle below — unless the policy
    // asks for the app's RST close (repeat navigation, see
    // [`FetchPolicy::graceful_close`]); the response is fully framed
    // either way.
    if (300..400).contains(&status) || !policy.graceful_close {
        stack.sockets.get_mut::<tcp::Socket>(handle).abort();
        // Dispatch the RST now: an aborted socket with a tuple
        // reports `PollAt::Now`, so this poll puts it on the wire and
        // smoltcp then forgets the tuple (`connect` resets the
        // buffers anyway on reuse).
        stack.poll();
        serial_println!("browser: connection aborted (RST, no TIME-WAIT)");
    } else {
        stack.sockets.get_mut::<tcp::Socket>(handle).close();
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            stack.poll();
            let state = stack.sockets.get::<tcp::Socket>(handle).state();
            if state == tcp::State::TimeWait || state == tcp::State::Closed {
                serial_println!("browser: connection closed cleanly ({state})");
                break;
            }
            if clock::now_ms() > deadline {
                serial_println!("browser: timeout closing connection");
                abandon(stack);
                return Err(NavError::Connect);
            }
        }
    }
    Ok((status, body_total, loc_len))
}

/// Reset the browser's plain socket to `Closed` (an aborted socket with
/// a tuple reports `PollAt::Now`, so the poll puts the RST on the wire
/// and forgets the tuple — the same dance the 3xx close uses).
fn abandon(stack: &mut Stack) {
    let handle = stack.tcp6_handle;
    stack.sockets.get_mut::<tcp::Socket>(handle).abort();
    stack.poll();
}

/// One TLS hop on the browser's `tcp7` socket (local port
/// [`TLS_PORT`]): [`tls::tls_open`] + [`tls::tls_fetch_any`] — the
/// primitives directly, bypassing `https_smoke` (that fn owns the
/// robots proof). The redirect-aware close (3xx → abort, else
/// graceful) lives inside `tls_fetch_any`. Returns
/// `(status, total_body_bytes, location_len)`.
fn tls_hop(
    stack: &mut Stack,
    ip: Ipv4Address,
    host: &str,
    target: &str,
    body: &mut [u8],
    loc: &mut [u8],
) -> (u16, usize, usize) {
    let handle = stack.tcp7_handle;
    let conn = tls::tls_open(stack, handle, ip, host, TLS_PORT);
    tls::tls_fetch_any(
        conn,
        host,
        target,
        &HEADERS,
        body,
        loc,
        FetchCfg {
            cap: BODY_CAP,
            who: "browser",
        },
    )
}

/// What one [`fetch`] handed back: the final URL, how many head bytes
/// of the body are stored in [`BODY`] (`min(total, BODY_SAMPLE)`), and
/// the total body size on the wire.
pub(crate) struct Fetched {
    /// Final URL after the redirect chain (absolute, parsed).
    pub url: Url,
    /// Stored head-sample length (`min(total, BODY_SAMPLE)`).
    pub stored: usize,
    /// Total body bytes on the wire (counted, not necessarily stored).
    pub total: usize,
}

/// Fetch `start`, following up to [`MAX_REDIRECTS`] redirects — the
/// shared hop loop behind the B1 proof ([`FetchPolicy::BOOT`], via
/// [`fetch`]) and the B4 navigation app ([`FetchPolicy::NAV`], via
/// [`navigate`]). Every failure is a [`NavError`]; only [`fetch`] turns
/// one into a fatal line, so the app can render a page instead.
///
/// Its serial lines mirror to the VGA text buffer — callers hand the
/// shell a clean screen afterwards (see [`fetch_smoke`]).
fn hop_loop(stack: &mut Stack, start: &str, policy: FetchPolicy) -> Result<Fetched, NavError> {
    // A failed fetch must not leave the previous page's sample looking
    // current (`sample` reads `STORED`).
    STORED.store(0, Ordering::Relaxed);
    let mut url = match Url::parse(start) {
        Ok(url) => url,
        Err(e) => {
            serial_println!("browser: cannot parse the URL: {e:?}");
            return Err(NavError::Url("cannot parse the URL"));
        }
    };
    // SAFETY: single-use statics (see `BODY`/`LOC`); one fetch at a
    // time on a single core, IRQ0 never touches them.
    let body = unsafe { &mut *addr_of_mut!(BODY) };
    let loc = unsafe { &mut *addr_of_mut!(LOC) };
    let mut buf = [0u8; SANITIZE_CAP];
    let start = sanitize(url.as_str().as_bytes(), &mut buf);
    serial_println!("browser: start {start}");

    let mut redirects = 0usize;
    let mut hops = 0usize;
    let (final_url, body_total) = loop {
        hops += 1;
        // Only http/https are fetchable — a hostile Location
        // pointing at `ftp:`, `data:`, … is refused before any I/O.
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(NavError::Url("unsupported URL scheme (only http/https)"));
        }
        // The app's policy: no TLS hop at all (module docs). The check
        // sits before any socket work, so the page is instant.
        if scheme == "https" && !policy.tls {
            return Err(NavError::TlsUnavailable);
        }
        let Some(host) = url.host_str() else {
            return Err(NavError::Url("URL has no host"));
        };
        let Some(port) = url.port_or_known_default() else {
            return Err(NavError::Url("URL has no usable port"));
        };
        // `tls_open` connects to :443 (the pinned-HTTPS port), so a
        // https URL anywhere else is refused rather than silently
        // misconnected — and the `Host` header then matches SNI.
        if scheme == "https" && port != 443 {
            return Err(NavError::Url("unsupported https port (only 443)"));
        }
        let mut tbuf = [0u8; 512];
        let Some(target) = request_target(&url, &mut tbuf) else {
            return Err(NavError::Url("request target too long or not ASCII"));
        };
        let mut gbuf = [0u8; SANITIZE_CAP];
        let shown = sanitize(url.as_str().as_bytes(), &mut gbuf);
        serial_println!("browser: hop {hops} GET {shown}");

        // An IPv4 literal needs no DNS query (`browse http://10.0.2.2:…`).
        let ip = match net::parse_ipv4(host) {
            Some([a, b, c, d]) => Ipv4Address::new(a, b, c, d),
            None => match stack.resolve(host) {
                Some(ip) => ip,
                None => {
                    let mut hbuf = [0u8; SANITIZE_CAP];
                    let hshown = sanitize(host.as_bytes(), &mut hbuf);
                    serial_println!("browser: dns: no answer for {hshown}");
                    return Err(NavError::Dns);
                }
            },
        };
        let (status, got, loc_full) = if scheme == "https" {
            tls_hop(stack, ip, host, target, body, loc)
        } else {
            plain_fetch(
                stack,
                Hop {
                    ip,
                    host,
                    port,
                    target,
                    body,
                    loc,
                },
                policy,
            )?
        };

        match status {
            200 => break (url, got),
            300..=399 => {
                if redirects == MAX_REDIRECTS {
                    return Err(NavError::Redirect("redirect cap exceeded (max 5)"));
                }
                if loc_full == 0 {
                    return Err(NavError::Redirect("redirect without a Location header"));
                }
                if loc_full > loc.len() {
                    return Err(NavError::Redirect(
                        "redirect Location longer than the buffer",
                    ));
                }
                let raw = &loc[..loc_full];
                let reference = match core::str::from_utf8(raw) {
                    Ok(reference) => reference,
                    Err(_) => {
                        return Err(NavError::Redirect("redirect Location is not valid UTF-8"));
                    }
                };
                let mut lbuf = [0u8; SANITIZE_CAP];
                let lshown = sanitize(raw, &mut lbuf);
                serial_println!("browser: hop {hops} location {lshown}");

                let next = match url.join(reference) {
                    Ok(next) => next,
                    Err(e) => {
                        serial_println!("browser: malformed redirect Location: {e:?}");
                        return Err(NavError::Redirect("malformed redirect Location"));
                    }
                };
                if next.scheme() != "http" && next.scheme() != "https" {
                    return Err(NavError::Redirect(
                        "redirect to an unsupported scheme (only http/https)",
                    ));
                }
                if url.scheme() == "https" && next.scheme() == "http" {
                    return Err(NavError::Redirect("refusing https -> http downgrade"));
                }
                redirects += 1;
                url = next;
            }
            _ => {
                serial_println!("browser: unexpected HTTP status {status}");
                return Err(NavError::Status(status));
            }
        }
    };

    if body_total == 0 {
        return Err(NavError::Empty);
    }
    let stored = min(body_total, BODY_SAMPLE);
    STORED.store(stored, Ordering::Relaxed);
    let mut fbuf = [0u8; SANITIZE_CAP];
    let final_shown = sanitize(final_url.as_str().as_bytes(), &mut fbuf);
    serial_println!(
        "browser: fetched {final_shown} — {body_total} bytes after {redirects} redirect(s)"
    );
    Ok(Fetched {
        url: final_url,
        // The sample is filled head-first by both hop classes, so the
        // stored prefix is exactly `min(total, BODY_SAMPLE)`.
        stored,
        total: body_total,
    })
}

/// The boot proofs' front-end: [`hop_loop`] under
/// [`FetchPolicy::BOOT`], any error `FATAL: browser:` + halt (never a
/// partial result). Its serial lines mirror to the VGA text buffer, so
/// callers hand the shell a clean screen afterwards.
fn fetch(stack: &mut Stack, start: &str) -> Fetched {
    match hop_loop(stack, start, FetchPolicy::BOOT) {
        Ok(fetched) => fetched,
        Err(e) => {
            serial_println!("FATAL: browser: {e}");
            crate::halt();
        }
    }
}

/// B4: one navigation fetch for the interactive browser — the same hop
/// loop as the boot proofs, but the error comes back as a [`NavError`]
/// for the app to render and the policy refuses TLS (module docs).
/// Success stores the bounded body sample exactly like [`fetch`], so
/// [`sample`] is the caller's next read.
pub(crate) fn navigate(stack: &mut Stack, start: &str) -> Result<Fetched, NavError> {
    hop_loop(stack, start, FetchPolicy::NAV)
}

/// The head of the last successful fetch's body (`min(total,
/// BODY_SAMPLE)` bytes) — the render input for the proofs and the app.
///
/// The reference is valid until the next fetch starts; callers build
/// their owned tree before fetching again (one navigation at a time).
pub(crate) fn sample() -> &'static [u8] {
    let stored = STORED.load(Ordering::Relaxed);
    // SAFETY: single-use static — the `READ_STORAGE` contract of
    // `render_smoke`: fetches are sequential on one core, IRQ0 never
    // touches `BODY`, and every `&mut` taken by a fetch is gone by the
    // time this shared reference is created.
    let body = unsafe { &*core::ptr::addr_of!(BODY) };
    body.get(..stored.min(body.len())).unwrap_or(&[])
}

/// The B1 proof: fetch [`START_URL`] following up to
/// [`MAX_REDIRECTS`] redirects, assert the final 200 with a non-empty
/// bounded body, print what came back — `BROWSER_FETCH_OK`.
///
/// Runs after the A3 chat proof so the marker lands between
/// `AI_CHAT_OK` and `AI_EDIT_OK` (the smoke asserts markers in order).
/// Its serial lines mirror to the VGA text buffer, so the screen is
/// cleared at the end — exactly like the A1/A2/A3 proofs — and the
/// shell still starts clean.
pub fn fetch_smoke(stack: &mut Stack) {
    // `total` is only informational here — `fetch` already refused an
    // empty body and printed the summary line.
    let fetched = fetch(stack, START_URL);
    debug_assert!(fetched.total > 0 && fetched.stored > 0);
    serial_println!("BROWSER_FETCH_OK"); // machine-checked by `cargo xtask smoke`
    // The serial lines above mirrored to the text buffer; hand the
    // shell the same clean screen the A1/A2/A3 proofs leave behind.
    crate::vga::clear_screen();
}

/// The B2 proof (docs/browser.md §4/§6/§7): fetch [`RENDER_URL`] with
/// the parameterized B1 fetch, then hand the bounded body sample to
/// [`crate::apps::browser::boot_proof`] — which builds the `dom` tree
/// over our tokenizer, lays it out for the text viewport, renders it
/// through A1's screen layer, reads the frame back from `0xb8000` and
/// prints `BROWSER_RENDER_OK` (fail-closed `FATAL: browser:` +
/// [`crate::halt`] on any mismatch). Clears the screen afterwards so
/// the shell starts clean, like every neighboring proof. Needs the
/// network stack — `kernel_main` only calls this inside its
/// `Some(stack)` branch (the smoke always has a NIC, so a skip shows
/// up as a missing marker).
pub fn render_smoke(stack: &mut Stack) {
    let fetched = fetch(stack, RENDER_URL);
    let mut sbuf = [0u8; SANITIZE_CAP];
    // The URL is wire data: sanitize once into a local, then reuse it
    // (the log line and the status bar share the printable-ASCII view).
    let status = sanitize(fetched.url.as_str().as_bytes(), &mut sbuf);
    serial_println!(
        "browser: rendering {status} ({} stored bytes)",
        fetched.stored
    );
    // SAFETY: single-use statics — the same contract as
    // `fetch_smoke`: sequential use on one core, IRQ0 never touches
    // `BODY`, and `fetch` has returned (its `&mut` is gone).
    let body = unsafe { &*core::ptr::addr_of!(BODY) };
    let Some(html) = body.get(..fetched.stored) else {
        fatal("body sample out of range");
    };
    crate::apps::browser::boot_proof(html, status);
}

/// The B3 proof (docs/browser.md §5/§7): render the kernel-owned CSS
/// fixture with and without its stylesheet and read the VGA attribute
/// bytes back from `0xb8000`, then apply the **real page's** own sheet
/// (the body sample [`render_smoke`] just fetched — no extra network)
/// as a robustness pass. Prints `BROWSER_CSS_OK` between
/// `BROWSER_RENDER_OK` and `SHELL_OK`; fail-closed
/// (`FATAL: browser:` + [`crate::halt`]) on any fixture mismatch.
///
/// `kernel_main` calls this immediately after [`render_smoke`], so
/// [`BODY`]/[`STORED`] still hold that fetch's sample. A missing or
/// empty sample simply skips the real-page pass (the fixture proof is
/// kernel-owned and still runs).
pub fn css_smoke() {
    let stored = STORED.load(Ordering::Relaxed);
    // SAFETY: single-use static — the same `READ_STORAGE` contract as
    // `render_smoke`: `fetch` has returned (its `&mut` is gone),
    // sequential use on one core, IRQ0 never touches `BODY`.
    let body = unsafe { &*core::ptr::addr_of!(BODY) };
    let real = body.get(..stored.min(body.len())).filter(|h| !h.is_empty());
    crate::apps::browser::css_boot_proof(real);
}
