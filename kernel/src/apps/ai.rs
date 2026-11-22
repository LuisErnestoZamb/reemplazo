//! Milestones A3/A4 (docs/ai-client.md §3, §6, §7): the AI chat client —
//! OpenAI-compatible `POST /v1/chat/completions`.
//!
//! - Wire types live in the `aiwire` crate (serde/serde_json request +
//!   response + SSE + `StreamText` accumulation, host-tested —
//!   exceptions/review in that crate and in the A3/A4 commits). This
//!   module is the transport + pane glue, the same split as
//!   `git-pktline` ↔ `git.rs`.
//! - Transport, A3 (smoke): **plain HTTP** on a fifth TCP socket
//!   (`tcp5`, local port 49163 — 49152 plain, 49160 robots-TLS, 49161
//!   git, 49162 ssh), `net::http::build_post` + `ResponseParser`
//!   (`reset()` per response, the sequential-exchange discipline from
//!   `tls.rs`), then `aiwire::ChatResponse`. Status must be 200 and
//!   `Content-Type` `application/json` — fail-closed, compared via
//!   `header_value`, never logged.
//! - Transport, A4 (user-driven): the endpoint configured with
//!   `ai endpoint <https-url>` is reached through
//!   `tls::tls_open_soft` + `tls::tls_post_soft` — the **fallible**
//!   TLS entries (a boot proof halts on a broken chain; a shell
//!   builtin renders the failure and returns to the prompt). The
//!   request asks for `stream: true`; a `text/event-stream` reply is
//!   parsed incrementally (`aiwire::Sse` → `StreamText`) and each
//!   `delta.content` is drawn into the chat pane as it arrives, while
//!   an `application/json` reply (an endpoint that ignores `stream`)
//!   still takes the non-streaming path. `data: [DONE]` ends the
//!   stream. **No default endpoint**: without `ai endpoint` the
//!   one-shot builtins keep using the A3 mock; a key is optional
//!   (negative: "require an explicit endpoint").
//! - Config lives **in RAM only** ([`Config`], bounded: URL ≤ 256 B,
//!   model ≤ 64 B, key ≤ 512 B). The key is never printed, rendered or
//!   logged — `ai config` reports only whether it is set and its
//!   length. Caveat, the S3 (`keyfile.rs`) precedent: the shell line
//!   discipline **echoes what is typed**, so an `ai key <token>` line
//!   remains visible on the console and in the shell's line buffer
//!   until overwritten; there is no no-echo input mode yet
//!   (documented in docs/ai-client.md §7 A4).
//! - Mock reachability: the smoke runs QEMU inside the
//!   `reemplazo-tools` container, so `10.0.2.2:8099` from the guest
//!   is libslirp's host-loopback translation (`sotranslate_out4`:
//!   guest→gateway connects land on *QEMU's host* 127.0.0.1 — here,
//!   the container's loopback where the mock listens). A4 adds a
//!   second canned response on `:8098` (`text/event-stream`, three
//!   deltas + `[DONE]`) so the streaming path is proved keylessly.
//! - [`boot_proof`]: the scripted `AI_CHAT_OK` proof (JSON exchange →
//!   assert status/Content-Type/shape → render → read back from
//!   `0xb8000`, then the **streaming SSE exchange** against `:8098`:
//!   deltas rendered as they arrive, `[DONE]`, the streamed text read
//!   back from `0xb8000` — same marker, same position), run between
//!   `EDITOR_OK` and `SHELL_OK`. Fail-closed: `FATAL:` + `halt()`.
//! - [`chat_cmd`]: the optional `ai <message>` shell builtin, fail-soft
//!   like every other builtin; [`run_endpoint`] is its TLS/streaming
//!   pane. [`stream_cmd`] (`ai stream <message>`) is the keyless SSE
//!   demo against the in-container mock.
//! - A5 (docs/ai-client.md §7): [`one_shot`] is the sanitized exchange
//!   all three callers share (the two builtins and A5's `AI_EDIT_OK`
//!   proof in `apps::editor`), [`apply_cmd`] is the `ai apply` builtin —
//!   quote the editor's retained document, exchange, insert the reply
//!   through `apps::editor::apply_completion` — and [`is_canned`] is the
//!   proof's reply-content check. No transport code is duplicated: the
//!   apply path *is* [`exchange`].
//!
//! # Where the code lives
//!
//! Transport + pane in one module (`apps::ai`): A3 is one exchange and
//! one pane; A4 adds the endpoint config, the fallible TLS transport
//! and the streaming render here, while the pure SSE/JSON work stays
//! in `aiwire`. Documented so the choice is deliberate.

use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use crate::clock;
use crate::keyboard::Key;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use crate::tls::{self, Post, PostEvent, ReadFlow};
use aiwire::{ChatRequest, ChatResponse, Sse, SseEvent, StreamFlow, StreamText};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr::addr_of_mut;
use net::http::{self, ResponseParser};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;
use url::Url;

/// Mock endpoint port. QEMU's slirp maps guest connections to
/// `10.0.2.2:<port>` onto QEMU's *host* loopback (libslirp
/// `sotranslate_out4`), i.e. inside the smoke's Docker container —
/// where xtask's bounded `nc` loop listens (see `qemu_invocation`).
const MOCK_PORT: u16 = 8099;
/// `Host:` header (URL-form, includes the port).
const HOST: &str = "10.0.2.2:8099";
/// A4: the mock's **streaming** endpoint — same slirp mapping, a
/// second canned `nc` response (`text/event-stream`: three deltas +
/// `[DONE]`). Keeps the SSE path provable without credentials or
/// internet, inside the unchanged `AI_CHAT_OK` proof.
const MOCK_SSE_PORT: u16 = 8098;
const MOCK_SSE_HOST: &str = "10.0.2.2:8098";
/// OpenAI-compatible path (docs/ai-client.md §6).
const PATH: &str = "/v1/chat/completions";
/// Local port of the chat connection (TIME-WAIT: every sequential
/// connection owns a port — 49152 plain, 49160 robots-TLS, 49161 git,
/// 49162 ssh, 49163 chat).
const LOCAL_PORT: u16 = 49163;
/// A4: local port of the user-driven TLS chat (`tcp5` again, a
/// different remote). Kept apart from the mock's 49163 so a stray
/// TIME-WAIT tuple from the A3 proof cannot collide.
const TLS_LOCAL_PORT: u16 = 49168;
/// Mock model name (pinned by the canned request/response pair).
const MODEL: &str = "reemplazo-mock";
/// System prompt of the boot proof's fixed conversation.
const SYSTEM_PROMPT: &str = "You are reemplazo's assistant.";
/// Fixed user message of the boot proof (printable ASCII by
/// construction — it is also rendered).
const BOOT_MSG: &str = "hello from reemplazo";
/// The mock must answer with `application/json`; anything else is
/// refused (compared, never logged).
const EXPECT_CT: &[u8] = b"application/json";
/// A4: the streaming media type (`data:` events).
const EXPECT_SSE: &[u8] = b"text/event-stream";
/// A4: total SSE/response stream bound for the **user** path. The
/// `ResponseParser` framing and `aiwire`'s line/event caps bound the
/// rest; bytes past this are refused, never truncated silently.
const STREAM_CAP: usize = 64 * 1024;
/// A4: rendered reply bound in the pane. The wire stream may be larger;
/// extra deltas are counted and dropped by `aiwire::StreamText`
/// (its own 4 KiB cap), so the heap stays flat.
const REPLY_CAP: usize = aiwire::STREAM_TEXT_CAP;
/// A4: canned streaming reply — the three mock deltas concatenated.
/// Byte-identical to what xtask writes into
/// `target/iso-root/chat-mock-sse-response.txt` (duplicated like
/// [`CANNED_REPLY`], same reason).
const STREAM_REPLY: &str = "reemplazo: streamed reply ok";
/// A4: the streaming exchange must observe exactly this many content
/// deltas in the mock (role-only chunks do not count).
const STREAM_DELTAS: usize = 3;
/// Config bounds (RAM only — see [`Config`]).
const ENDPOINT_CAP: usize = 256;
const MODEL_CAP: usize = 64;
const KEY_CAP: usize = 512;
/// `Authorization: Bearer <key>` header capacity (prefix + key).
const AUTH_CAP: usize = KEY_CAP + 32;
/// Response-body bound: a hostile/absurd reply cannot exhaust the
/// heap; bytes past it are counted and refused, never stored.
const BODY_CAP: usize = 64 * 1024;
/// One read chunk: bytes in, body staging out (the framer never
/// expands, so this size fits both).
const SCRATCH: usize = 1460;
/// Serialized request bound (head + small JSON body).
const REQ_CAP: usize = 2048;
/// The canned mock reply (byte-identical to the JSON body xtask
/// writes into `target/iso-root/chat-mock-response.txt` — duplicated
/// here the same way `DISK_MAGIC` is, because xtask cannot depend on
/// the `no_std` kernel crate). The boot proof refuses any other
/// answer: a 200 with the wrong content fails as loudly as a 500.
const CANNED_REPLY: &str = "reemplazo: mock reply ok";
/// Printable-ASCII cap for rendered model/user text (display bound,
/// not a wire bound — the wire body has its own [`BODY_CAP`]).
const SANITIZE_CAP: usize = 512;
/// Status bar style (white on blue) as the VGA attribute byte the boot
/// proof asserts: fg 15 | bg 4 << 4 (same encoding as `tui`/`editor`).
const STATUS_ATTR: u8 = 0x4F;
/// Status bar — the ASCII tail is what the readback asserts.
const STATUS: &str = "ai (mock) · Enter send · Esc quit";
/// A4 streaming proof's status bar (same attribute byte).
const STREAM_STATUS: &str = "ai sse (mock) · Esc quit";
/// Smallest geometry the proof needs: the longest rendered line is
/// `assistant: reemplazo: mock reply ok` (34); two conversation rows
/// plus input row plus status row.
const MIN_COLS: usize = 40;
const MIN_ROWS: usize = 4;

// ---------------------------------------------------------------------------
// A4 configuration — RAM only, never persisted, key never printed
// ---------------------------------------------------------------------------

/// The runtime chat configuration: **in RAM only** (docs/ai-client.md
/// §7 A4 — persistence waits for the filesystem milestone).
///
/// Access is the repo's single-`static mut` idiom (the shell's own
/// mainline stack is the only consumer; IRQ0 never touches it). The key
/// lives here because there is nowhere safer yet; it is never copied
/// into a log, a rendered cell or an error string — [`config_cmd`]
/// reports only `set`/`unset` and the length.
struct Config {
    endpoint: [u8; ENDPOINT_CAP],
    endpoint_len: usize,
    model: [u8; MODEL_CAP],
    model_len: usize,
    key: [u8; KEY_CAP],
    key_len: usize,
}

impl Config {
    const fn new() -> Self {
        Config {
            endpoint: [0; ENDPOINT_CAP],
            endpoint_len: 0,
            model: [0; MODEL_CAP],
            model_len: 0,
            key: [0; KEY_CAP],
            key_len: 0,
        }
    }
}

static mut CONFIG: Config = Config::new();
/// The `Authorization` header built from [`CONFIG`] once per real
/// exchange. A static (not a `String`) so the secret has exactly one
/// heap-free home and no copy is left to be freed unzeroed.
static mut AUTH_HEADER: [u8; AUTH_CAP] = [0; AUTH_CAP];

/// SAFETY: single-consumer `static mut` (module docs); every access is
/// a short, non-reentrant read/write on the shell's mainline stack.
fn config_mut() -> &'static mut Config {
    unsafe { &mut *addr_of_mut!(CONFIG) }
}

fn config_ref() -> &'static Config {
    unsafe { &*addr_of_mut!(CONFIG) }
}

/// HTTP response parser shared by sequential exchanges — the
/// `tls.rs`/git discipline: one `static`, `reset()` before each
/// response so a previous head (status, `Content-Type`) can never
/// validate the current one. `ResponseParser` is ~8 KiB, so it must
/// not live on the boot stack.
static mut PARSER: ResponseParser = ResponseParser::new();
/// Per-read staging buffer for [`ResponseParser::feed`] (the kernel's
/// boot stack is small; see `tls.rs`'s `STAGING`).
static mut STAGING: [u8; SCRATCH] = [0; SCRATCH];
/// Framed response body — bounded by [`BODY_CAP`] (the `READ_STORAGE`
/// idiom: single-use, written only from this module's exchange on a
/// single core; IRQ0 never touches it).
static mut BODY: [u8; BODY_CAP] = [0; BODY_CAP];
/// Serialized POST request (head + body), written once per exchange.
static mut REQ: [u8; REQ_CAP] = [0; REQ_CAP];

// ---------------------------------------------------------------------------
// The exchange: plain-HTTP POST over tcp5
// ---------------------------------------------------------------------------

/// One full chat exchange against the mock: serialize the request,
/// connect `tcp5` (local port [`LOCAL_PORT`]) to `10.0.2.2:8099`,
/// POST, frame the response through [`ResponseParser`], require status
/// 200 + `Content-Type: application/json` + body ≤ [`BODY_CAP`],
/// parse the JSON with `aiwire`, and close cleanly (TimeWait — the
/// pattern from `tls.rs`/`netstack.rs`). Returns the first choice's
/// message content; every failure is an `Err`, never a partial result.
///
/// Error paths abort the socket so a failed exchange cannot wedge the
/// next one (the `ai` builtin reuses `tcp5`).
pub fn exchange(stack: &mut Stack, request: &ChatRequest) -> Result<String, &'static str> {
    let result = run(stack, request);
    if result.is_err() {
        teardown(stack);
    }
    result
}

/// The exchange proper (see [`exchange`]).
fn run(stack: &mut Stack, request: &ChatRequest) -> Result<String, &'static str> {
    // (1) Serialize and build the POST (heap: the request is small;
    // ALLOC_OK precedes this code on every boot).
    let json = request
        .to_json()
        .map_err(|_| "cannot serialize chat request")?;
    let req = unsafe { &mut *addr_of_mut!(REQ) };
    let req_len = http::build_post(req, HOST, PATH, "application/json", &json, &[])
        .ok_or("POST request does not fit the buffer")?;

    // (2) Connect. A leftover mid-handshake socket (a previous failed
    // exchange) is aborted first; TimeWait/Closed are what `connect`
    // accepts, so a clean previous run needs no special casing.
    let handle = stack.tcp5_handle;
    let ip = gateway();
    connect(stack, handle, ip, MOCK_PORT, LOCAL_PORT)?;

    // (3) Send the whole request (bounded, poll-driven — the
    // `plain_get_smoke` pattern; smoltcp owns retransmission).
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut sent = 0usize;
    while sent < req_len {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&req[sent..])
        {
            Ok(n) => sent += n,
            Err(_) => return Err("tcp send rejected (connection lost)"),
        }
        if clock::now_ms() > deadline {
            return Err("tcp send timeout");
        }
    }

    // (4) Read + frame the response. See the module docs: `reset()`
    // first (sequential exchanges share the parser), status and
    // Content-Type asserted once the head parses, body bounded.
    let (body_len, body_total) = read_response(stack, handle)?;

    // (5) Parse with aiwire and take the first reply — JSON shape is
    // fail-closed inside `from_slice` (adversarial suite in aiwire).
    // SAFETY: single-use static (module SAFETY note); `body_len` is
    // what the framer stored (≤ BODY_CAP — enforced above).
    let body = unsafe { &*addr_of_mut!(BODY) };
    let response =
        ChatResponse::from_slice(&body[..body_len]).map_err(|_| "chat response JSON refused")?;
    let reply = response.reply().ok_or("response carried no choices")?;
    serial_println!("ai: {} bytes framed", body_total);

    // (6) Clean close: FIN → TimeWait/Closed, the same teardown proof
    // as `plain_get_smoke`/`tls_fetch` (RST-only would not prove the
    // orderly path).
    stack.sockets.get_mut::<tcp::Socket>(handle).close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        let state = stack.sockets.get::<tcp::Socket>(handle).state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            return Ok(reply.to_string());
        }
        if clock::now_ms() > deadline {
            return Err("timeout closing connection (never reached TimeWait/Closed)");
        }
    }
}

/// Establish the connection, retrying a bounded number of times: the
/// mock is a respawnable `nc` loop, and a SYN answered with RST lands
/// the socket in `Closed` (smoltcp resets `SynSent` on RST) — a
/// rendezvous race must not fail the boot on its first shot, but three
/// refusals mean the mock is down, which is fail-closed.
fn connect(
    stack: &mut Stack,
    handle: smoltcp::iface::SocketHandle,
    ip: Ipv4Address,
    port: u16,
    local_port: u16,
) -> Result<(), &'static str> {
    // A socket left mid-handshake by a previous failed attempt is
    // reset first (`connect` refuses an open socket; Closed/TimeWait
    // are fine and `connect` resets them itself).
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if sock.is_open() {
            sock.abort();
        }
    }
    stack.poll();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut attempts = 0u8;
    loop {
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if let Err(e) = sock.connect(stack.iface.context(), (ip, port), local_port) {
                serial_println!("ai: connect rejected: {e:?}");
                return Err("tcp connect rejected");
            }
        }
        // Wait for the handshake (or its refusal).
        loop {
            stack.poll();
            let state = stack.sockets.get::<tcp::Socket>(handle).state();
            match state {
                tcp::State::Established => return Ok(()),
                tcp::State::Closed => break, // refused/RST → retry below
                _ => {}
            }
            if clock::now_ms() > deadline {
                return Err("tcp connect timeout");
            }
        }
        attempts += 1;
        if attempts >= 3 {
            return Err("connection refused by the mock (nc loop down?)");
        }
        serial_println!("ai: connect refused, retrying ({attempts}/3)");
    }
}

/// Frame one HTTP response into the [`BODY`] static: status 200 and
/// `Content-Type: application/json` asserted fail-closed (compared,
/// never logged), total body ≤ [`BODY_CAP`]. Returns
/// `(body_stored, body_total)` — equal unless the cap refused the
/// response (an error above, so equal here).
fn read_response(
    stack: &mut Stack,
    handle: smoltcp::iface::SocketHandle,
) -> Result<(usize, usize), &'static str> {
    // SAFETY: single-use statics (module SAFETY note). The parser is
    // shared with no other module (crate::tls has its own) but still
    // reset: defensive against a half-read previous exchange.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let body = unsafe { &mut *addr_of_mut!(BODY) };
    let mut scratch = [0u8; SCRATCH];
    let mut stored = 0usize;
    let mut total = 0usize;
    let mut ct_checked = false;
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
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
            let progress = parser
                .feed(&scratch[..n], staging)
                .map_err(|_| "HTTP response refused")?;
            // Head assertions as soon as it parses (once per response).
            if !ct_checked && let Some(status) = parser.status() {
                if status != 200 {
                    return Err("unexpected HTTP status (expected 200)");
                }
                match http::header_value(parser.head(), b"content-type") {
                    Some(value) if ct_matches(value, EXPECT_CT) => {}
                    Some(_) => return Err("unexpected Content-Type"),
                    None => return Err("response has no Content-Type"),
                }
                ct_checked = true;
            }
            if progress.body > 0 {
                let take = min(body.len() - stored, progress.body);
                body[stored..stored + take].copy_from_slice(&staging[..take]);
                stored += take;
                total += progress.body;
                if total > BODY_CAP {
                    return Err("response body exceeds the byte bound");
                }
            }
            if progress.complete {
                break;
            }
            continue;
        }
        if (!may_recv && queued == 0) || closed {
            // Server FIN: for Content-Length framing this completes an
            // already-done response and fails a truncated one.
            parser.eof().map_err(|_| "truncated response")?;
            break;
        }
        if clock::now_ms() > deadline {
            return Err("timeout waiting for the chat response");
        }
    }
    if !ct_checked {
        return Err("response head never parsed (Content-Type unchecked)");
    }
    Ok((stored, total))
}

/// Best-effort teardown of a failed exchange: an open socket is
/// aborted (RST) so the next `ai` exchange finds `tcp5` connectable —
/// TimeWait/Closed need nothing (`connect` accepts both).
fn teardown(stack: &mut Stack) {
    let handle = stack.tcp5_handle;
    let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
    if sock.is_open() {
        sock.abort();
    }
}

/// The slirp gateway — the mock runs on QEMU's host, reached through
/// it (see the module docs).
fn gateway() -> Ipv4Address {
    Ipv4Address::new(
        net::SLIRP_GATEWAY[0],
        net::SLIRP_GATEWAY[1],
        net::SLIRP_GATEWAY[2],
        net::SLIRP_GATEWAY[3],
    )
}

/// Content-Type match with parameters allowed: the value must start
/// with `expected` (ASCII case-insensitive) and continue with `;` /
/// whitespace, or end there. Compared only — header values are wire
/// bytes and never logged (same rule as `tls.rs`).
fn ct_matches(value: &[u8], expected: &[u8]) -> bool {
    value.len() >= expected.len()
        && value[..expected.len()].eq_ignore_ascii_case(expected)
        && matches!(
            value.get(expected.len()),
            None | Some(&b';') | Some(&b' ') | Some(&b'\t')
        )
}

/// Printable-ASCII policy for text that came off the wire or from the
/// user before it reaches the pane or the serial log — the `git.rs`
/// sanitizing rule: graphic ASCII and space pass, everything else
/// (controls, CRLF, non-ASCII → no log-injection, no surprise glyphs)
/// becomes `?`. UTF-8 display is a documented later refinement
/// (docs/ai-client.md §8). Bounded by [`SANITIZE_CAP`].
fn sanitize_text(text: &str) -> String {
    sanitize_bounded(text, SANITIZE_CAP)
}

/// [`sanitize_text`] with an explicit bound — A4's streamed reply may
/// be longer than the one-shot display cap, so the pane raises the
/// limit to [`REPLY_CAP`] while the policy (printable ASCII only) is
/// identical. The bound is on the produced string: a multi-byte or
/// control character can never expand it.
fn sanitize_bounded(text: &str, cap: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.len() >= cap {
            break;
        }
        out.push(if ch.is_ascii_graphic() || ch == ' ' {
            ch
        } else {
            '?'
        });
    }
    out
}

// ---------------------------------------------------------------------------
// The chat pane
// ---------------------------------------------------------------------------

/// Who said what. The pane renders the role as a tag before the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    User,
    Assistant,
    /// A failure rendered in the pane (A4: user actions fail soft —
    /// endpoint errors are a pane line, never `FATAL`).
    Error,
}

/// One rendered conversation line.
#[derive(Debug, Clone)]
struct Turn {
    role: Role,
    text: String,
}

impl Turn {
    fn user(text: String) -> Self {
        Turn {
            role: Role::User,
            text,
        }
    }

    fn assistant(text: String) -> Self {
        Turn {
            role: Role::Assistant,
            text,
        }
    }

    fn error(text: String) -> Self {
        Turn {
            role: Role::Error,
            text,
        }
    }
}

/// Render one frame: conversation rows (role-tagged lines) on top, the
/// input line below, status bar last. Geometry comes from
/// `Frame::area()` (the live text geometry) — never a hardcoded
/// 80×25. Lines are clipped, not wrapped (documented limit: a reply
/// longer than the screen width shows its head; wrapping is later
/// polish).
fn render(frame: &mut Frame, turns: &[Turn], input: &str, status: &str) {
    let area = frame.area();
    if area.width < 8 {
        return; // degenerate geometry: draw nothing, never panic
    }
    // Two rows below the conversation: input + status.
    let Some(convo_h) = area.height.checked_sub(2) else {
        return;
    };
    let mut lines: Vec<Line> = Vec::with_capacity(turns.len());
    for turn in turns {
        let (tag, fg) = match turn.role {
            Role::User => ("user: ", Color::Cyan),
            Role::Assistant => ("assistant: ", Color::LightGreen),
            Role::Error => ("error: ", Color::LightRed),
        };
        lines.push(Line::from(vec![
            Span::styled(tag, Style::new().fg(fg)),
            Span::raw(turn.text.as_str()),
        ]));
    }
    let convo_area = Rect::new(area.x, area.y, area.width, convo_h);
    frame.render_widget(Paragraph::new(Text::from(lines)), convo_area);

    let input_y = area.y.saturating_add(convo_h);
    let input_area = Rect::new(area.x, input_y, area.width, 1);
    frame.render_widget(Paragraph::new(format!("> {input}")), input_area);

    let status_y = input_y.saturating_add(1);
    let status_area = Rect::new(area.x, status_y, area.width, 1);
    frame.render_widget(
        Paragraph::new(status).style(Style::new().fg(Color::White).bg(Color::Blue)),
        status_area,
    );
}

// ---------------------------------------------------------------------------
// The boot proof: AI_CHAT_OK
// ---------------------------------------------------------------------------

/// Script the A3 proof: run one real exchange against xtask's mock,
/// assert the JSON shape and the canned content, render the
/// conversation through the A1 path, read it back from `0xb8000` —
/// the smoke test's `AI_CHAT_OK` (printed between `EDITOR_OK` and
/// `SHELL_OK`). On any mismatch: `FATAL:` + [`crate::halt`], like every
/// other boot proof; a genuinely absent text console just skips the
/// proof (the same way `TUI_OK` does). Afterwards the screen is
/// cleared and the console cursor reset, so the shell starts clean —
/// serial output is never reordered or suppressed.
///
/// Needs the network stack (the mock exchange is the proof); without
/// one it skips with a note, exactly as the TLS/git/SSH boot phases do
/// — and the smoke, which always has a NIC, then fails on the missing
/// marker.
pub fn boot_proof(stack: &mut Stack) {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: ai: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove(stack) {
        serial_println!("FATAL: ai: {why}");
        crate::halt();
    }
    // A4: the same proof also drives the streaming SSE path against the
    // mock's second canned response (`:8098`) — same marker, same
    // position in the chain, no new marker and no credentials.
    if let Err(why) = prove_stream(stack) {
        serial_println!("FATAL: ai: {why}");
        crate::halt();
    }
    serial_println!("AI_CHAT_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// The scripted exchange + render + readback. Fail-closed: every
/// error string becomes a `FATAL:` line.
fn prove(stack: &mut Stack) -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the chat frame (min 40x4)");
    }

    // The real exchange: request built → mock 200 + application/json
    // → aiwire parse — all inside `exchange` (fail-closed there).
    let request = ChatRequest::new(MODEL).system(SYSTEM_PROMPT).user(BOOT_MSG);
    let reply = sanitize_text(&exchange(stack, &request)?);
    // JSON shape passed (`reply()` returned Some above); the *content*
    // must be the canned answer — a 200 carrying anything else fails
    // the proof as loudly as a transport error would.
    if !is_canned(&reply) {
        return Err("mock reply content mismatch");
    }

    let turns = vec![Turn::user(sanitize_text(BOOT_MSG)), Turn::assistant(reply)];
    let mut terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
    terminal
        .draw(|frame| render(frame, &turns, BOOT_MSG, STATUS))
        .map_err(|_| "chat frame failed")?;

    // Readback from the actual text buffer — after `flush_diff` the
    // buffer and the screen agree cell by cell, so the frame must be
    // there (TUI_OK/EDITOR_OK read theirs the same way).
    if !screen_holds(CANNED_REPLY.as_bytes()) {
        return Err("canned reply missing from the screen");
    }
    if !screen_holds(BOOT_MSG.as_bytes()) {
        return Err("user turn missing from the screen");
    }
    let status_row = rows.checked_sub(1).ok_or("no status row")?;
    // "Esc quit" — the ASCII tail of STATUS (the middle dot is CP437).
    if !row_holds(status_row, b"Esc quit") {
        return Err("status bar missing from the last row");
    }
    if !row_holds_attr(status_row, STATUS_ATTR) {
        return Err("status attribute missing from the last row");
    }
    Ok(())
}

/// The A4 streaming half of the `AI_CHAT_OK` proof: one
/// `stream: true` exchange against the mock's SSE response
/// (`10.0.2.2:8098`), every `delta.content` rendered into the pane as
/// it arrives, `[DONE]` required, the accumulated text asserted
/// **byte-exactly** and read back from `0xb8000`. Fail-closed: any
/// mismatch is a `FATAL:` line.
fn prove_stream(stack: &mut Stack) -> Result<(), &'static str> {
    // A second `Terminal` in the same screen session starts from a
    // blank buffer (ratatui never sends default cells), so the staged
    // cells from the JSON proof above must be cleared first —
    // `screen::open` blanks the staged buffer and the next flush then
    // overwrites every differing cell on the real screen.
    screen::open().map_err(|_| "screen re-open failed")?;
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the chat frame (min 40x4)");
    }
    let request = ChatRequest::new(MODEL)
        .system(SYSTEM_PROMPT)
        .user(BOOT_MSG)
        .stream(true);
    let mut pane = Pane::new("", STREAM_STATUS)?;
    pane.ask(BOOT_MSG);
    pane.start_reply();
    pane.draw()?;

    let (deltas, done) = stream_mock(stack, &request, &mut pane)?;
    if deltas != STREAM_DELTAS {
        return Err("mock SSE delta count mismatch");
    }
    if !done {
        return Err("mock SSE stream did not end with [DONE]");
    }
    let text = pane
        .turns
        .last()
        .map(|turn| turn.text.as_str())
        .ok_or("no assistant turn after streaming")?;
    if text != STREAM_REPLY {
        return Err("streamed reply text mismatch");
    }
    // The screen must hold what the pane accumulated (the deltas were
    // flushed as they arrived; the last frame is the final text).
    if !screen_holds(STREAM_REPLY.as_bytes()) {
        return Err("streamed reply missing from the screen");
    }
    let status_row = rows.checked_sub(1).ok_or("no status row")?;
    if !row_holds(status_row, b"Esc quit") {
        return Err("stream status bar missing from the last row");
    }
    if !row_holds_attr(status_row, STATUS_ATTR) {
        return Err("stream status attribute missing from the last row");
    }
    serial_println!("ai: sse streamed {deltas} deltas");
    Ok(())
}

/// Does row `y` of the *actual* text buffer hold `needle` as
/// consecutive glyph bytes? (The `VGA_OK`/`TUI_OK`/`EDITOR_OK`
/// readback style.)
fn row_holds(y: usize, needle: &[u8]) -> bool {
    let Some((cols, rows)) = screen::dims() else {
        return false;
    };
    if y >= rows || needle.is_empty() || needle.len() > cols {
        return false;
    }
    for x in 0..=cols - needle.len() {
        let mut holds = true;
        for (i, want) in needle.iter().enumerate() {
            match crate::vga::peek_cell(x + i, y) {
                Some((glyph, _)) if glyph == *want => {}
                _ => {
                    holds = false;
                    break;
                }
            }
        }
        if holds {
            return true;
        }
    }
    false
}

/// Does *any* row of the actual text buffer hold `needle`?
fn screen_holds(needle: &[u8]) -> bool {
    let Some((_, rows)) = screen::dims() else {
        return false;
    };
    (0..rows).any(|y| row_holds(y, needle))
}

/// Does any cell of row `y` of the actual text buffer carry `attr`?
fn row_holds_attr(y: usize, attr: u8) -> bool {
    let Some((cols, rows)) = screen::dims() else {
        return false;
    };
    if y >= rows {
        return false;
    }
    (0..cols).any(|x| crate::vga::peek_cell(x, y).is_some_and(|(_, a)| a == attr))
}

// ---------------------------------------------------------------------------
// A4: configuration, endpoints, the live pane, streaming transports
// ---------------------------------------------------------------------------

/// One parsed chat endpoint: the `Host:` header/SNI value and the
/// request target (path + query). `:443` is implicit (the TLS transport
/// always dials 443 and the URL validator refuses any other port).
struct Target {
    host: String,
    path: String,
}

/// Parse and validate an `https` endpoint. Fail-soft: every refusal is
/// a short reason the caller prints (a config command) or renders (a
/// chat). Only an explicit `https://` URL is accepted — there is no
/// default endpoint and no silent downgrade (docs/ai-client.md §7 A4).
fn parse_endpoint(raw: &str) -> Result<Target, &'static str> {
    if raw.len() > ENDPOINT_CAP {
        return Err("endpoint is longer than 256 bytes");
    }
    let url = Url::parse(raw).map_err(|_| "endpoint is not a valid URL")?;
    if url.scheme() != "https" {
        return Err("endpoint must be an https:// URL");
    }
    if url.port().is_some_and(|port| port != 443) {
        return Err("only https port 443 is supported (the TLS transport dials 443)");
    }
    let host = url.host_str().ok_or("endpoint has no host")?;
    let plain_host = !host.is_empty()
        && host.len() <= 128
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !plain_host {
        return Err("endpoint host is not a plain DNS name");
    }
    let mut path = String::from(url.path());
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.len() > 1024 || !path.is_ascii() {
        return Err("endpoint path is not ASCII or too long");
    }
    Ok(Target {
        host: String::from(host),
        path,
    })
}

/// The configured endpoint as a heap copy (config is RAM-only; copying
/// the non-secret string keeps borrows simple across the session).
fn endpoint_value() -> Option<String> {
    let cfg = config_ref();
    let bytes = cfg.endpoint.get(..cfg.endpoint_len)?;
    core::str::from_utf8(bytes).ok().map(String::from)
}

fn model_value() -> Option<String> {
    let cfg = config_ref();
    let bytes = cfg.model.get(..cfg.model_len)?;
    core::str::from_utf8(bytes).ok().map(String::from)
}

/// Store/validate an endpoint. Never partially stores: the URL parser
/// run here is the same one the chat uses, so a config accepted now
/// cannot fail at request time.
fn set_endpoint(raw: &str) -> Result<(), &'static str> {
    parse_endpoint(raw)?;
    let cfg = config_mut();
    let dst = cfg
        .endpoint
        .get_mut(..raw.len())
        .ok_or("endpoint is longer than 256 bytes")?;
    dst.copy_from_slice(raw.as_bytes());
    cfg.endpoint_len = raw.len();
    Ok(())
}

fn set_model(raw: &str) -> Result<(), &'static str> {
    if raw.is_empty() {
        return Err("usage: ai model <name>");
    }
    if raw.len() > MODEL_CAP {
        return Err("model name is longer than 64 bytes");
    }
    if !raw.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("model name must be printable ASCII with no spaces");
    }
    let cfg = config_mut();
    let dst = cfg
        .model
        .get_mut(..raw.len())
        .ok_or("model name is longer than 64 bytes")?;
    dst.copy_from_slice(raw.as_bytes());
    cfg.model_len = raw.len();
    Ok(())
}

/// Store a token **in RAM only**. The value is never echoed by this
/// module (the shell already echoed the typed line — documented caveat)
/// and never appears in a log or a rendered cell.
fn set_key(raw: &str) -> Result<(), &'static str> {
    if raw.is_empty() {
        return Err("usage: ai key <token>   (or: ai key -  to clear)");
    }
    if raw.len() > KEY_CAP {
        return Err("key is longer than 512 bytes");
    }
    if !raw.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("key must be printable ASCII with no spaces");
    }
    let cfg = config_mut();
    let dst = cfg
        .key
        .get_mut(..raw.len())
        .ok_or("key is longer than 512 bytes")?;
    dst.copy_from_slice(raw.as_bytes());
    cfg.key_len = raw.len();
    Ok(())
}

fn clear_key() {
    let cfg = config_mut();
    // Overwrite before "removing": leaving the old bytes behind would
    // keep a stale secret in RAM for no reason (best effort — see
    // `keyfile.rs`'s note on what scrubbing is worth).
    if let Some(slot) = cfg.key.get_mut(..) {
        slot.fill(0);
    }
    cfg.key_len = 0;
}

/// Build `Authorization: Bearer <key>` into the module's static header
/// buffer, or `None` when no key is configured (keyless endpoints are
/// first-class: local servers need no credentials). The secret appears
/// only here and in the request the TLS layer writes.
fn auth_header() -> Option<&'static str> {
    let key_len = config_ref().key_len;
    if key_len == 0 {
        return None;
    }
    const PREFIX: &[u8] = b"Authorization: Bearer ";
    let cfg = config_ref();
    let key = cfg.key.get(..key_len)?;
    // SAFETY: single-use static (module SAFETY note); the header is
    // rebuilt at the start of every user exchange.
    let buf = unsafe { &mut *addr_of_mut!(AUTH_HEADER) };
    let total = PREFIX.len().checked_add(key_len)?;
    let out = buf.get_mut(..total)?;
    out.get_mut(..PREFIX.len())?.copy_from_slice(PREFIX);
    out.get_mut(PREFIX.len()..)?.copy_from_slice(key);
    core::str::from_utf8(buf.get(..total)?).ok()
}

/// The chat pane with live text (A4): a ratatui terminal plus the
/// conversation it renders. [`Pane::set_reply`] replaces the streaming
/// assistant turn from the bounded accumulator and [`Pane::draw`]
/// flushes the cell diff into `0xb8000`, so every `delta.content` is
/// visible as it arrives — this is the A4 "streaming into the pane"
/// requirement, not a batch render at the end.
struct Pane {
    terminal: Terminal<VgaBackend>,
    turns: Vec<Turn>,
    input: String,
    status: String,
}

impl Pane {
    fn new(input: &str, status: &str) -> Result<Self, &'static str> {
        Ok(Pane {
            terminal: Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?,
            turns: Vec::new(),
            input: String::from(input),
            status: String::from(status),
        })
    }

    fn ask(&mut self, text: &str) {
        self.turns
            .push(Turn::user(sanitize_bounded(text, SANITIZE_CAP)));
    }

    /// Begin the assistant turn the stream appends into.
    fn start_reply(&mut self) {
        self.turns.push(Turn::assistant(String::new()));
    }

    fn set_reply(&mut self, raw: &str) {
        if let Some(turn) = self.turns.last_mut() {
            turn.text = sanitize_bounded(raw, REPLY_CAP);
        }
    }

    fn fail(&mut self, why: &str) {
        self.turns
            .push(Turn::error(sanitize_bounded(why, SANITIZE_CAP)));
    }

    fn set_status(&mut self, status: String) {
        self.status = status;
    }

    fn draw(&mut self) -> Result<(), &'static str> {
        let Pane {
            terminal,
            turns,
            input,
            status,
        } = self;
        terminal
            .draw(|frame| render(frame, turns.as_slice(), input.as_str(), status.as_str()))
            .map(|_| ())
            .map_err(|_| "chat frame failed")
    }
}

/// Consume the SSE events dispatched by one read chunk: parse each
/// `data:` payload as a chunk, append `delta.content` to `text` (the
/// bounded [`StreamText`]) and re-render the pane after every delta.
/// `data: [DONE]` returns [`StreamFlow::Done`].
fn consume_events(
    events: &mut Vec<SseEvent>,
    text: &mut StreamText,
    pane: &mut Pane,
) -> Result<StreamFlow, &'static str> {
    for event in events.drain(..) {
        let flow = text
            .push(&event)
            .map_err(|_| "SSE payload is not a completion chunk")?;
        if flow == StreamFlow::Done {
            return Ok(flow);
        }
        pane.set_reply(text.text());
        pane.draw()?;
    }
    Ok(StreamFlow::Continue)
}

/// Which body framing the endpoint chose (decided from `Content-Type`
/// when the head parses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyMode {
    Unknown,
    Sse,
    Json,
}

fn resolve_host(stack: &mut Stack, host: &str) -> Option<Ipv4Address> {
    match net::parse_ipv4(host) {
        Some([a, b, c, d]) => Some(Ipv4Address::new(a, b, c, d)),
        None => stack.resolve(host),
    }
}

/// One **streaming** exchange against the in-container SSE mock (plain
/// HTTP, `10.0.2.2:8098` — the A4 keyless proof path): send the
/// `stream: true` request, frame the reply through `ResponseParser`,
/// feed `Sse` → `StreamText`, and re-render `pane` after every delta.
/// Returns `(content_deltas, saw_done)`; every bound (total stream,
/// SSE line/event, rendered text) is enforced, and the socket is
/// recycled (RST) on every exit path.
fn stream_mock(
    stack: &mut Stack,
    request: &ChatRequest,
    pane: &mut Pane,
) -> Result<(usize, bool), &'static str> {
    let json = request
        .to_json()
        .map_err(|_| "cannot serialize chat request")?;
    // SAFETY: single-use static (module SAFETY note).
    let req = unsafe { &mut *addr_of_mut!(REQ) };
    let req_len = http::build_post(
        req,
        MOCK_SSE_HOST,
        PATH,
        "application/json",
        &json,
        &["Accept: text/event-stream"],
    )
    .ok_or("POST request does not fit the buffer")?;

    let handle = stack.tcp5_handle;
    connect(stack, handle, gateway(), MOCK_SSE_PORT, LOCAL_PORT)?;
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut sent = 0usize;
    while sent < req_len {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&req[sent..])
        {
            Ok(n) => sent += n,
            Err(_) => {
                teardown(stack);
                return Err("tcp send rejected (connection lost)");
            }
        }
        if clock::now_ms() > deadline {
            teardown(stack);
            return Err("tcp send timeout");
        }
    }

    // SAFETY: single-use statics (module SAFETY note); reset first.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let mut sse = Sse::new();
    let mut text = StreamText::new();
    let mut events: Vec<SseEvent> = Vec::new();
    let mut scratch = [0u8; SCRATCH];
    let mut total = 0usize;
    let mut ct_checked = false;
    let mut done = false;
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
                Err(_) => {
                    teardown(stack);
                    return Err("HTTP response refused");
                }
            };
            deadline = clock::now_ms() + OP_DEADLINE_MS;
            if !ct_checked && let Some(status) = parser.status() {
                if status != 200 {
                    teardown(stack);
                    return Err("mock SSE status is not 200");
                }
                match http::header_value(parser.head(), b"content-type") {
                    Some(value) if ct_matches(value, EXPECT_SSE) => {}
                    _ => {
                        teardown(stack);
                        return Err("mock SSE Content-Type is not text/event-stream");
                    }
                }
                ct_checked = true;
            }
            if progress.body > 0 {
                total = total.saturating_add(progress.body);
                if total > STREAM_CAP {
                    teardown(stack);
                    return Err("streamed body exceeds the byte bound");
                }
                if sse.feed(&staging[..progress.body], &mut events).is_err() {
                    teardown(stack);
                    return Err("SSE stream refused (line or event over the cap)");
                }
                match consume_events(&mut events, &mut text, pane) {
                    Ok(StreamFlow::Done) => {
                        done = true;
                        break;
                    }
                    Ok(StreamFlow::Continue) => {}
                    Err(why) => {
                        teardown(stack);
                        return Err(why);
                    }
                }
            }
            if progress.complete {
                break;
            }
            continue;
        }
        if (!may_recv && queued == 0) || closed {
            if parser.eof().is_err() {
                teardown(stack);
                return Err("truncated response");
            }
            break;
        }
        if clock::now_ms() > deadline {
            teardown(stack);
            return Err("timeout waiting for the mock stream");
        }
    }
    if !ct_checked {
        teardown(stack);
        return Err("response head never parsed (Content-Type unchecked)");
    }
    teardown(stack);
    Ok((text.deltas(), done || text.is_done()))
}

/// One **user-driven TLS chat**: resolve the configured host, open the
/// fallible TLS connection (pinned root), POST the `stream: true`
/// request and render the reply live. `text/event-stream` streams
/// deltas into `pane`; `application/json` (an endpoint that ignores
/// `stream`) still parses the whole body — the non-streaming fallback.
///
/// Returns a short observation for the status bar/serial log, or the
/// error the pane should show. Never halts (fail-soft), never logs the
/// key, and never renders raw wire bytes (only the sanitized reply and
/// the fixed error wording).
fn tls_chat(
    stack: &mut Stack,
    target: &Target,
    model: &str,
    message: &str,
    pane: &mut Pane,
) -> Result<String, String> {
    let request = ChatRequest::new(model)
        .system(SYSTEM_PROMPT)
        .user(sanitize_text(message))
        .stream(true);
    let json = request
        .to_json()
        .map_err(|_| String::from("cannot serialize the chat request"))?;

    let auth = auth_header();
    let mut headers: [&str; 3] = [
        "Accept: text/event-stream",
        "User-Agent: reemplazo-ai/0.4",
        "",
    ];
    let mut header_count = 2usize;
    if let Some(auth) = auth
        && let Some(slot) = headers.get_mut(2)
    {
        *slot = auth;
        header_count = 3;
    }
    let headers = headers.get(..header_count).ok_or("header list overflow")?;

    let ip = resolve_host(stack, &target.host)
        .ok_or_else(|| format!("no DNS answer for {}", target.host))?;
    let handle = stack.tcp5_handle;
    let conn = tls::tls_open_soft(stack, handle, ip, &target.host, TLS_LOCAL_PORT)
        .map_err(String::from)?;

    let post = Post {
        path: &target.path,
        content_type: "application/json",
        body: &json,
    };
    let mut sse = Sse::new();
    let mut text = StreamText::new();
    let mut events: Vec<SseEvent> = Vec::new();
    let mut mode = ReplyMode::Unknown;
    let mut head_status = 0u16;
    let mut head_problem: Option<&'static str> = None;
    let mut body_stored = 0usize;

    let result = tls::tls_post_soft(conn, &target.host, post, headers, STREAM_CAP, |event| {
        match event {
            PostEvent::Head {
                status,
                content_type,
            } => {
                head_status = status;
                if status != 200 {
                    head_problem = Some("endpoint answered a non-200 status");
                    return Err("endpoint answered a non-200 status");
                }
                mode = match content_type {
                    Some(value) if ct_matches(value, EXPECT_SSE) => ReplyMode::Sse,
                    Some(value) if ct_matches(value, EXPECT_CT) => ReplyMode::Json,
                    _ => {
                        head_problem = Some(
                            "unexpected Content-Type (want application/json or text/event-stream)",
                        );
                        return Err(
                            "unexpected Content-Type (want application/json or text/event-stream)",
                        );
                    }
                };
                Ok(ReadFlow::Continue)
            }
            PostEvent::Body(chunk) => match mode {
                ReplyMode::Sse => {
                    if sse.feed(chunk, &mut events).is_err() {
                        return Err("SSE stream refused (line or event over the cap)");
                    }
                    match consume_events(&mut events, &mut text, pane) {
                        Ok(StreamFlow::Done) => Ok(ReadFlow::Stop),
                        Ok(StreamFlow::Continue) => Ok(ReadFlow::Continue),
                        Err(why) => Err(why),
                    }
                }
                ReplyMode::Json => {
                    // SAFETY: single-use static (module SAFETY note).
                    let body = unsafe { &mut *addr_of_mut!(BODY) };
                    let room = body.len().saturating_sub(body_stored);
                    let take = min(room, chunk.len());
                    if let (Some(dst), Some(src)) = (
                        body.get_mut(body_stored..body_stored + take),
                        chunk.get(..take),
                    ) {
                        dst.copy_from_slice(src);
                        body_stored = body_stored.saturating_add(take);
                    }
                    Ok(ReadFlow::Continue)
                }
                ReplyMode::Unknown => Err("response body before the head?"),
            },
        }
    });

    match result {
        Ok((status, total)) => {
            if status != 200 {
                return Err(match head_status {
                    0 => String::from("endpoint answered a non-200 status"),
                    status => format!("endpoint answered HTTP {status}"),
                });
            }
            match mode {
                ReplyMode::Sse => {
                    if !text.is_done() {
                        return Err(String::from("SSE stream ended without [DONE]"));
                    }
                    pane.set_reply(text.text());
                    pane.draw().map_err(String::from)?;
                    Ok(format!(
                        "{} deltas streamed · {} bytes",
                        text.deltas(),
                        total
                    ))
                }
                ReplyMode::Json => {
                    // SAFETY: single-use static (module SAFETY note).
                    let body = unsafe { &*addr_of_mut!(BODY) };
                    let slice = body.get(..body_stored).ok_or("body index lost")?;
                    let response = ChatResponse::from_slice(slice)
                        .map_err(|_| String::from("chat response JSON refused"))?;
                    let reply = response
                        .reply()
                        .ok_or("response carried no choices")?
                        .to_string();
                    pane.set_reply(&reply);
                    pane.draw().map_err(String::from)?;
                    Ok(format!("reply {total} bytes (non-streaming fallback)"))
                }
                ReplyMode::Unknown => Err(String::from("endpoint sent no reply")),
            }
        }
        Err(why) => {
            if head_problem.is_some() {
                Err(format!(
                    "endpoint answered HTTP {head_status} (Content-Type or status refused)"
                ))
            } else {
                Err(String::from(why))
            }
        }
    }
}

/// The `ai <message>` path with an endpoint configured: open the chat
/// pane, stream the reply, then wait for `Esc`. Fail-soft everywhere —
/// a bad URL, a missing model, a refused chain or a non-200 becomes a
/// rendered error line and one serial line, never `FATAL`.
fn run_endpoint(stack: &mut Stack, message: &str) {
    let Some(endpoint) = endpoint_value() else {
        serial_println!("ai: no endpoint configured (ai endpoint <https-url>)");
        return;
    };
    let Some(model) = model_value() else {
        serial_println!("ai: no model configured (ai model <name>)");
        return;
    };
    let target = match parse_endpoint(&endpoint) {
        Ok(target) => target,
        Err(why) => {
            serial_println!("ai: {why}");
            return;
        }
    };
    // Endpoint is user input but validated ASCII; sanitize anyway (the
    // log-injection rule applies to everything printed).
    let shown = sanitize_text(&endpoint);
    serial_println!("ai: POST {shown} over TLS (stream: true)");

    if let Err(why) = screen::open() {
        serial_println!("ai: {why}");
        return;
    }
    let Some((cols, rows)) = screen::dims() else {
        serial_println!("ai: no text console");
        return;
    };
    if cols < MIN_COLS || rows < MIN_ROWS {
        serial_println!("ai: text screen too small for the chat frame (min 40x4)");
        return;
    }
    let mut pane = match Pane::new("", "streaming...") {
        Ok(pane) => pane,
        Err(why) => {
            serial_println!("ai: {why}");
            return;
        }
    };
    pane.ask(message);
    pane.start_reply();
    if let Err(why) = pane.draw() {
        serial_println!("ai: {why}");
        return;
    }

    match tls_chat(stack, &target, &model, message, &mut pane) {
        Ok(stats) => {
            pane.set_status(format!("Esc quit · {stats}"));
            serial_println!("ai: {stats}");
        }
        Err(why) => {
            pane.fail(&why);
            pane.set_status(String::from("Esc quit (error)"));
            serial_println!("ai: {why}");
        }
    }
    if pane.draw().is_err() {
        // The frame could not be drawn: still let the user read the
        // serial line and return to the prompt.
        serial_println!("ai: chat frame failed");
        crate::vga::clear_screen();
        return;
    }
    session_wait();
    crate::vga::clear_screen();
}

/// Block until `Esc` arrives on either input source. Deliberately
/// minimal (no scrolling/keys yet): the A4 pane is a transcript, and
/// its bounded exchange is already over when this is called.
fn session_wait() {
    loop {
        if let Some(key) = crate::keyboard::next_event()
            && key == Key::Esc
        {
            return;
        }
        if let Some(byte) = crate::serial::SerialPort::COM1.read_byte()
            && byte == 0x1B
        {
            return;
        }
        core::hint::spin_loop();
    }
}

/// The `ai stream <message>` shell builtin (A4, keyless): the same
/// streaming path as the boot proof, against the in-container mock
/// (`10.0.2.2:8098`), rendered live in the pane. It exists so the SSE
/// transport can be demonstrated manually without credentials or
/// internet (docs/ai-client.md §7 A4).
pub fn stream_cmd(stack: &mut Stack, args: &str) {
    let message = args.trim();
    if message.is_empty() {
        serial_println!(
            "usage: ai stream <message>   (keyless SSE demo against the in-container mock)"
        );
        return;
    }
    if let Err(why) = screen::open() {
        serial_println!("ai: {why}");
        return;
    }
    let Some((cols, rows)) = screen::dims() else {
        serial_println!("ai: no text console");
        return;
    };
    if cols < MIN_COLS || rows < MIN_ROWS {
        serial_println!("ai: text screen too small for the chat frame (min 40x4)");
        return;
    }
    let mut pane = match Pane::new("", "streaming (mock sse)...") {
        Ok(pane) => pane,
        Err(why) => {
            serial_println!("ai: {why}");
            return;
        }
    };
    pane.ask(message);
    pane.start_reply();
    if pane.draw().is_err() {
        serial_println!("ai: chat frame failed");
        return;
    }
    let request = ChatRequest::new(MODEL)
        .system(SYSTEM_PROMPT)
        .user(sanitize_text(message))
        .stream(true);
    match stream_mock(stack, &request, &mut pane) {
        Ok((deltas, done)) => {
            pane.set_status(format!(
                "Esc quit · {deltas} deltas{}",
                if done { "" } else { " (no [DONE])" }
            ));
            serial_println!("ai: {deltas} deltas streamed (mock)");
        }
        Err(why) => {
            pane.fail(why);
            pane.set_status(String::from("Esc quit (error)"));
            serial_println!("ai: {why}");
        }
    }
    if pane.draw().is_err() {
        serial_println!("ai: chat frame failed");
        crate::vga::clear_screen();
        return;
    }
    session_wait();
    crate::vga::clear_screen();
}

/// Config/status subcommands (`ai endpoint`, `ai model`, `ai key`,
/// `ai config`). Fail-soft, and **never prints the key**: only whether
/// it is set and how long it is.
fn config_cmd(action: &str, rest: &str) {
    match action {
        "endpoint" => {
            if rest.is_empty() {
                match endpoint_value() {
                    Some(endpoint) => serial_println!("ai endpoint: {endpoint}"),
                    None => serial_println!("ai endpoint: (none; ai endpoint <https-url>)"),
                }
                return;
            }
            match set_endpoint(rest) {
                Ok(()) => serial_println!("ai: endpoint stored (RAM only): {rest}"),
                Err(why) => serial_println!("ai: {why}"),
            }
        }
        "model" => {
            if rest.is_empty() {
                match model_value() {
                    Some(model) => serial_println!("ai model: {model}"),
                    None => serial_println!("ai model: (none; ai model <name>)"),
                }
                return;
            }
            match set_model(rest) {
                Ok(()) => serial_println!("ai: model stored (RAM only): {rest}"),
                Err(why) => serial_println!("ai: {why}"),
            }
        }
        "key" => {
            if rest.is_empty() {
                let len = config_ref().key_len;
                if len == 0 {
                    serial_println!("ai key: not set (keyless endpoints work)");
                } else {
                    serial_println!("ai key: set ({len} bytes, never printed)");
                }
                return;
            }
            if rest == "-" || rest == "clear" {
                clear_key();
                serial_println!("ai key: cleared");
                return;
            }
            match set_key(rest) {
                Ok(()) => {
                    serial_println!("ai: key stored in RAM (never printed; typed lines are echoed)")
                }
                Err(why) => serial_println!("ai: {why}"),
            }
        }
        _ => serial_println!("ai: unknown config command"),
    }
}

/// `ai config`: the whole non-secret state in four lines. The key is
/// reported by presence and length only.
fn config_summary() {
    match endpoint_value() {
        Some(endpoint) => serial_println!("ai: endpoint {endpoint}"),
        None => serial_println!("ai: endpoint (none)"),
    }
    match model_value() {
        Some(model) => serial_println!("ai: model {model}"),
        None => serial_println!("ai: model (none)"),
    }
    let len = config_ref().key_len;
    if len == 0 {
        serial_println!("ai: key (none) · caps: url 256 B, model 64 B, key 512 B");
    } else {
        serial_println!(
            "ai: key (set, {len} B, never printed) · caps: url 256 B, model 64 B, key 512 B"
        );
    }
    serial_println!(
        "ai: trust: pinned USERTrust ECC root only (other chains fail closed until the multi-root store)"
    );
}

/// Split `<word> <rest>` / bare `<word>` out of the builtin's argument
/// text. `None` when the first word is something else.
fn subcommand<'a>(args: &'a str, word: &str) -> Option<&'a str> {
    let rest = args.strip_prefix(word)?;
    match rest {
        "" => Some(""),
        _ => rest.strip_prefix(' ').map(|tail| tail.trim_start()),
    }
}

// ---------------------------------------------------------------------------
// The `ai` builtin: one-shot exchange, printed as text
// ---------------------------------------------------------------------------

/// One sanitized mock exchange for `message` — the shared body behind
/// the `ai <message>` builtin, A5's [`apply_cmd`] and A5's
/// `AI_EDIT_OK` proof (`apps::editor::ai_edit_boot_proof`), so all
/// three build the request and read the reply through exactly one
/// path. Both directions go through [`sanitize_text`] (the
/// printable-ASCII policy): nothing off the wire reaches a caller, the
/// editor document or the serial log verbatim.
pub fn one_shot(stack: &mut Stack, message: &str) -> Result<String, &'static str> {
    let request = ChatRequest::new(MODEL)
        .system(SYSTEM_PROMPT)
        .user(sanitize_text(message));
    exchange(stack, &request).map(|reply| sanitize_text(&reply))
}

/// A5's reply-content check for the boot proof: is this the canned mock
/// answer? (`AI_CHAT_OK`'s policy — a 200 with the wrong body fails as
/// loudly as a transport error would; the builtin paths deliberately do
/// not use this — A4's real endpoint answers with real text.)
pub fn is_canned(reply: &str) -> bool {
    reply.contains(CANNED_REPLY)
}

/// The `ai` shell builtin — configuration, the legacy one-shot mock
/// exchange, and the A4 real/streaming paths. Fails soft throughout
/// (shell.rs's contract): every refusal prints one line and returns to
/// the prompt.
///
/// - `ai endpoint <https-url>` / `ai model <name>` / `ai key <token>` /
///   `ai config` — RAM-only configuration (key never printed).
/// - `ai stream <message>` — keyless SSE demo against the in-container
///   mock, rendered live in the pane.
/// - `ai <message>` — with an endpoint configured: TLS POST, streaming
///   reply in the pane (A4). Without one: the A3 non-streaming mock
///   exchange printed as text (unchanged, and what A5's manual path
///   uses).
pub fn chat_cmd(stack: &mut Stack, args: &str) {
    let args = args.trim();
    if args.is_empty() {
        serial_println!(
            "usage: ai <message> | ai stream <message> | ai apply\n\
             \x20      ai endpoint <https-url> | ai model <name> | ai key <token> | ai config"
        );
        return;
    }
    if let Some(rest) = subcommand(args, "endpoint") {
        config_cmd("endpoint", rest);
        return;
    }
    if let Some(rest) = subcommand(args, "model") {
        config_cmd("model", rest);
        return;
    }
    if let Some(rest) = subcommand(args, "key") {
        config_cmd("key", rest);
        return;
    }
    if args == "config" {
        config_summary();
        return;
    }
    if let Some(rest) = subcommand(args, "stream") {
        stream_cmd(stack, rest);
        return;
    }
    // A4: an explicit endpoint selects the real TLS/streaming path; no
    // endpoint keeps the A3 mock (never a default cloud endpoint).
    if endpoint_value().is_some() {
        run_endpoint(stack, args);
        return;
    }
    match one_shot(stack, args) {
        // The serial macros evaluate their arguments twice (VGA +
        // UART), so every argument stays a plain side-effect-free local
        // — `one_shot` already returned the sanitized reply.
        Ok(reply) => serial_println!("ai: {reply}"),
        Err(why) => serial_println!("ai: {why}"),
    }
}

/// The A5 `ai apply` shell builtin — the "opencode-like" apply step:
/// quote the retained editor document's cursor line
/// ([`crate::apps::editor::quote_cursor_line`]), run one mock exchange
/// on it, and insert the sanitized reply at the document's cursor
/// ([`crate::apps::editor::apply_completion`], one undo entry — the
/// editor's undo removes exactly this completion). Fails soft (shell
/// contract): a dead mock or a refused insert prints one line and
/// returns to the prompt, touching nothing.
pub fn apply_cmd(stack: &mut Stack) {
    let Some(context) = crate::apps::editor::quote_cursor_line() else {
        serial_println!("ai: no document to apply into (no editor buffer yet)");
        return;
    };
    let prompt = format!("complete this line: {context}");
    match one_shot(stack, &prompt) {
        Ok(reply) => match crate::apps::editor::apply_completion(&reply) {
            // Plain locals only: side-effect-free macro arguments.
            Ok(()) => serial_println!("ai: applied `{reply}` at the editor cursor"),
            Err(why) => serial_println!("ai: apply refused: {why}"),
        },
        Err(why) => serial_println!("ai: {why}"),
    }
}
