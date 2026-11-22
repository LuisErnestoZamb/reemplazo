//! Milestone A3 (docs/ai-client.md §3, §6, §7): the AI chat client —
//! OpenAI-compatible `POST /v1/chat/completions` against xtask's
//! **mock**, the reply parsed and rendered in a chat pane.
//!
//! - Wire types live in the `aiwire` crate (serde/serde_json request +
//!   response + SSE, host-tested — exceptions/review in that crate and
//!   in the A3 commit). This module is the transport + pane glue, the
//!   same split as `git-pktline` ↔ `git.rs`.
//! - Transport: **plain HTTP** on a fifth TCP socket (`tcp5`, local
//!   port 49163 — 49152 plain, 49160 robots-TLS, 49161 git, 49162
//!   ssh), `net::http::build_post` + `ResponseParser` (`reset()` per
//!   response, the sequential-exchange discipline from `tls.rs`), then
//!   `aiwire::ChatResponse`. Status must be 200 and `Content-Type`
//!   `application/json` — fail-closed, compared via `header_value`,
//!   never logged. The mock is **plain HTTP by design** (A3): xtask's
//!   `nc` loop inside the QEMU container speaks no TLS, and the
//!   pinned-root TLS path (`crate::tls`) is untouched here — A4 wraps
//!   this exchange in TLS for real endpoints.
//! - Mock reachability: the smoke runs QEMU inside the
//!   `reemplazo-tools` container, so `10.0.2.2:8099` from the guest
//!   is libslirp's host-loopback translation (`sotranslate_out4`:
//!   guest→gateway connects land on *QEMU's host* 127.0.0.1 — here,
//!   the container's loopback where the mock listens).
//! - [`boot_proof`]: the scripted `AI_CHAT_OK` proof (exchange →
//!   assert status/Content-Type/JSON shape → render the conversation →
//!   read the canned reply back from `0xb8000`), run between
//!   `EDITOR_OK` and `SHELL_OK`. Fail-closed: `FATAL:` + `halt()`.
//! - [`chat_cmd`]: the optional `ai <message>` shell builtin, fail-soft
//!   like every other builtin (the real endpoint config is A4).
//!
//! # Where the code lives
//!
//! Transport + pane in one module (`apps::ai`), not a separate
//! `chat.rs`: A3 is one exchange and one pane; A4 (endpoint/key
//! config, TLS) is what will split configuration out. Documented here
//! so the choice is deliberate, not accidental.

use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use crate::clock;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use aiwire::{ChatRequest, ChatResponse};
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

/// Mock endpoint port. QEMU's slirp maps guest connections to
/// `10.0.2.2:<port>` onto QEMU's *host* loopback (libslirp
/// `sotranslate_out4`), i.e. inside the smoke's Docker container —
/// where xtask's bounded `nc` loop listens (see `qemu_invocation`).
const MOCK_PORT: u16 = 8099;
/// `Host:` header (URL-form, includes the port).
const HOST: &str = "10.0.2.2:8099";
/// OpenAI-compatible path (docs/ai-client.md §6).
const PATH: &str = "/v1/chat/completions";
/// Local port of the chat connection (TIME-WAIT: every sequential
/// connection owns a port — 49152 plain, 49160 robots-TLS, 49161 git,
/// 49162 ssh, 49163 chat).
const LOCAL_PORT: u16 = 49163;
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
/// Response-body bound: a hostile/absurd reply cannot exhaust the
/// heap; bytes past it are counted and refused, never stored.
const BODY_CAP: usize = 64 * 1024;
/// One read chunk: bytes in, body staging out (the framer never
/// expands, so this size fits both).
const SCRATCH: usize = 1460;
/// Serialized request bound (head + small JSON body).
const REQ_CAP: usize = 1024;
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
/// Smallest geometry the proof needs: the longest rendered line is
/// `assistant: reemplazo: mock reply ok` (34); two conversation rows
/// plus input row plus status row.
const MIN_COLS: usize = 40;
const MIN_ROWS: usize = 4;

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
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if sock.is_open() {
            sock.abort();
        }
    }
    connect(stack, handle, ip)?;

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
) -> Result<(), &'static str> {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut attempts = 0u8;
    loop {
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if let Err(e) = sock.connect(stack.iface.context(), (ip, MOCK_PORT), LOCAL_PORT) {
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
    let mut out = String::new();
    for ch in text.chars().take(SANITIZE_CAP) {
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
    if !reply.contains(CANNED_REPLY) {
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
// The `ai` builtin: one-shot exchange, printed as text
// ---------------------------------------------------------------------------

/// The `ai <message>` shell builtin: one exchange against the mock
/// (the real endpoint configuration is A4) with the reply printed as
/// sanitized text. Fails soft — a typo, a dead mock or a bad response
/// prints one line and returns to the prompt (shell.rs's contract).
pub fn chat_cmd(stack: &mut Stack, args: &str) {
    let message = args.trim();
    if message.is_empty() {
        serial_println!("usage: ai <message>   (mock endpoint; real endpoint: milestone A4)");
        return;
    }
    let request = ChatRequest::new(MODEL).system(SYSTEM_PROMPT).user(message);
    match exchange(stack, &request) {
        Ok(reply) => {
            // Sanitize into a local first: the serial macros evaluate
            // their arguments twice (VGA + UART), so the expression
            // must stay side-effect free.
            let reply = sanitize_text(&reply);
            serial_println!("ai: {reply}");
        }
        Err(why) => serial_println!("ai: {why}"),
    }
}
