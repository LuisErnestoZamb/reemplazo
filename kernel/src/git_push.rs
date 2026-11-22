//! `git push` over smart HTTP — milestone **G5** of the agent plan
//! (docs/git-ssh-deps.md §A.4 row **G6**, `GIT_PUSH_OK`).
//!
//! # What it does
//!
//! G4/G5 have already written a real `.git` to the FAT16 volume and made
//! one local commit on top of the fetched head. This module pushes that
//! commit:
//!
//! 1. [`crate::git_store::plan_push`] reads `/.git/refs/heads/main` and
//!    walks commit → trees → blob ids **from disk** (nothing is trusted
//!    from the earlier in-memory fetch).
//! 2. `GET /info/refs?service=git-receive-pack` fetches the v0
//!    advertisement (the service header, a flush, the ref line with its
//!    capability list, a flush) and takes the advertised `old` oid plus
//!    `report-status`. The server name is validated to be exactly
//!    `refs/heads/main`; every id is 40 lowercase hex before it reaches
//!    the log (`crate::git::sanitize` for anything else).
//! 3. The command list is the classic v0 form
//!    `<old> SP <new> SP refs/heads/main NUL report-status LF`, a
//!    flush-pkt, then the pack. **No side-band**: the reply is plain
//!    pkt-lines, which is also what the fetch asks for
//!    ([pack-protocol §Packfile Negotiation](https://git-scm.com/docs/pack-protocol)).
//! 4. [`crate::git_store::write_push_pack`] appends the pack directly
//!    after those bytes, one loose object at a time (full non-delta
//!    objects — legal for `receive-pack`; delta encoding is deferred).
//! 5. `POST /git-receive-pack` with
//!    `application/x-git-receive-pack-request`; the reply must be
//!    `application/x-git-receive-pack-result`, and its `report-status`
//!    pkt-lines must be exactly `unpack ok`, `ok refs/heads/main`, flush
//!    — anything else is a protocol violation and fatal.
//!
//! # Transport
//!
//! The proof server is xtask's in-container receive-pack mock on
//! QEMU's host loopback (`10.0.2.2`, slirp): plain HTTP, like the AI
//! mock, so no TLS is involved. It is not a repository — it advertises a
//! **fixed placeholder `old`** id (a static `nc` cannot know github's
//! HEAD), ACKs the pack and keeps the received request bytes for the
//! host-side validation that runs after QEMU exits (the pack is decoded
//! with `git-pack` and with real host `git`; see xtask). Real GitHub
//! needs credentials and a real certificate path, so that push stays
//! pending (docs/git-ssh-deps.md §A.4).
//!
//! # Bounds
//!
//! Advertisement ≤ [`AD_CAP`], report ≤ [`RESULT_CAP`], pack ≤
//! [`PACK_CAP`] (enforced by the writer *before* it appends), one
//! object ≤ 4 MiB, objects ≤ 10 000, request/body ≤ pack + 1 KiB of
//! pkt-lines. Peak heap is the pack plus its POST copy (≈ 2 × 1 MiB on
//! this repo) and one loose object at a time; the fetch's decoded pack
//! has already been dropped when this runs (it is called from
//! `kernel_main` *after* `git_fetch::fetch` returns). Every loop is
//! deadline-bounded and every protocol parse is checked.

use crate::clock;
use crate::git::sanitize;
use crate::netstack::Stack;
use alloc::vec::Vec;
use core::ptr::addr_of_mut;
use git_pktline::{Pkt, Step, decode, encode_data, encode_flush};
use net::http::{self, ResponseParser};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

/// The receive-pack mock's advertisement port (xtask's in-container
/// `nc` responder; slirp maps guest→10.0.2.2 to QEMU's host loopback).
const AD_PORT: u16 = 8090;
/// The mock's receive-pack POST port. Split from [`AD_PORT`] because a
/// shell `nc` loop cannot choose its canned response by request method
/// (documented deviation from one-origin smart HTTP; the client is
/// parameterized, a real server uses one port).
const POST_PORT: u16 = 8091;
/// `Host` header values (the port is part of the authority the mock
/// serves; the connection address is [`gateway`]).
const AD_HOST: &str = "10.0.2.2:8090";
const POST_HOST: &str = "10.0.2.2:8091";
/// v0 smart-HTTP endpoints (http-protocol).
const AD_PATH: &str = "/info/refs?service=git-receive-pack";
const POST_PATH: &str = "/git-receive-pack";
const AD_ACCEPT: &str = "Accept: application/x-git-receive-pack-advertisement";
/// Media types the two replies must carry (asserted, never assumed).
const AD_CT: &[u8] = b"application/x-git-receive-pack-advertisement";
const RESULT_CT: &[u8] = b"application/x-git-receive-pack-result";
/// Request media type for the POST body.
const REQ_CT: &str = "application/x-git-receive-pack-request";
/// Local ports (49168 advertisement, 49169 POST — TIME-WAIT forbids
/// reusing one; the fetch's own 49166 is untouched).
const AD_LOCAL_PORT: u16 = 49168;
const POST_LOCAL_PORT: u16 = 49169;
/// Advertisement body cap: service header + one ref + flush, far below.
const AD_CAP: usize = 8 * 1024;
/// `report-status` body cap.
const RESULT_CAP: usize = 4 * 1024;
/// Pack cap: mirrored from `git_store::PUSH_PACK_CAP` (asserted below)
/// and re-checked here before the POST so the two cannot drift.
const PACK_CAP: usize = 2 * 1024 * 1024;
/// Whole-request cap: pack + command pkt-lines + small slack.
const REQUEST_CAP: usize = PACK_CAP + 1024;
/// The ref this proof pushes (git's default branch here; a real client
/// would take it from HEAD).
const REF_NAME: &[u8] = b"refs/heads/main";
/// Capability the client asks for and needs to read a report back.
const CAP_REPORT_STATUS: &[u8] = b"report-status";
/// Idle deadline for connect/send/receive steps.
const OP_DEADLINE_MS: u64 = 15_000;
/// Connect retries (the mock is a respawnable `nc` loop; a SYN answered
/// with RST lands the socket in `Closed`).
const CONNECT_ATTEMPTS: u8 = 3;
/// Printable-ASCII sanitizer buffer for wire text in the log.
const SANITIZE_CAP: usize = 128;

/// HTTP response parser shared by the two sequential exchanges — one
/// `static`, `reset()` before each (the `tls.rs`/`ai.rs` discipline; it
/// is ~8 KiB, too big for the boot stack).
static mut PARSER: ResponseParser = ResponseParser::new();
/// Per-read staging buffer for [`ResponseParser::feed`].
static mut STAGING: [u8; 4096] = [0; 4096];
/// Framed response body (advertisement, then the report) — written and
/// consumed one exchange at a time on a single core; IRQ0 never touches
/// it.
static mut BODY: [u8; AD_CAP] = [0; AD_CAP];

// The pack bound the writer enforces must be this module's bound too:
// a `const` assertion keeps the two crates from drifting.
const _: () = assert!(crate::git_store::PUSH_PACK_CAP == PACK_CAP);

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: git: push: {msg}");
    crate::halt()
}

/// Push the local `refs/heads/main` to the mock and print
/// `GIT_PUSH_OK`. Any failure is `FATAL: git: push: …` + halt — a push
/// that cannot prove its report is not a push.
pub(crate) fn push(stack: &mut Stack, drive: &crate::ata::Drive) {
    if let Err(msg) = run(stack, drive) {
        fatal(msg);
    }
}

fn run(stack: &mut Stack, drive: &crate::ata::Drive) -> Result<(), &'static str> {
    // 1. What to send, from the store on disk.
    let plan = crate::git_store::plan_push(drive);
    if plan.count() == 0 {
        return Err("the on-disk store holds no objects for the ref");
    }
    let mut local_hex = [0u8; 40];
    local_hex.copy_from_slice(&git_store::hex_oid(&plan.local));
    let local_hex = core::str::from_utf8(&local_hex).map_err(|_| "object id is not ASCII")?;
    let mut base_hex = [0u8; 40];
    base_hex.copy_from_slice(&git_store::hex_oid(&plan.base));
    let base_hex = core::str::from_utf8(&base_hex).map_err(|_| "object id is not ASCII")?;
    serial_println!(
        "git: push: local refs/heads/main {local_hex} (parent/shallow boundary {base_hex}), {} object(s) to send",
        plan.count()
    );

    // 2. Advertisement.
    let old = advertisement(stack)?;
    let mut old_hex = [0u8; 40];
    old_hex.copy_from_slice(&git_store::hex_oid(&old));
    let old_hex = core::str::from_utf8(&old_hex).map_err(|_| "object id is not ASCII")?;
    serial_println!("git: push: advertised old {old_hex} refs/heads/main (report-status)");
    if old == plan.local {
        return Err("the advertised ref already equals the local commit");
    }

    // 3. Command list + flush + pack, appended into one buffer (no
    //    double copy of the pack: the writer starts at the flush's end).
    let mut request: Vec<u8> = Vec::new();
    request
        .try_reserve_exact(REQUEST_CAP)
        .map_err(|_| "request allocation refused")?;
    push_command(&mut request, &old, &plan.local)?;
    let pack_len = crate::git_store::write_push_pack(drive, &mut request, &plan);
    if pack_len > PACK_CAP || request.len() > REQUEST_CAP {
        return Err("pack or request exceeds its bound");
    }
    serial_println!(
        "git: push: pack {pack_len} bytes ({}, full objects, no deltas), request {} bytes",
        plan.count(),
        request.len()
    );

    // 4. POST it (plain HTTP: the request buffer is head + the body we
    //    just built, so this is the one unavoidable pack copy).
    push_pack_request(stack, &request)?;

    serial_println!(
        "git: push: {} object(s) in {pack_len} bytes accepted by the mock",
        plan.count()
    );
    serial_println!("GIT_PUSH_OK"); // machine-checked by `cargo xtask smoke-install`
    Ok(())
}

/// Build the HTTP POST wire bytes (head + body) into a fresh `Vec` whose
/// capacity is the body plus 1 KiB of headroom — the head is < 200
/// bytes, so [`http::build_post`] can never refuse this buffer.
fn post_scratch(body_len: usize) -> Result<Vec<u8>, &'static str> {
    let cap = body_len.checked_add(1024).ok_or("request size overflow")?;
    let mut wire: Vec<u8> = Vec::new();
    wire.try_reserve_exact(cap)
        .map_err(|_| "request allocation refused")?;
    Ok(wire)
}

/// Fetch and parse the v0 receive-pack advertisement; returns its `old`
/// object id. Requires the service header, exactly one
/// `refs/heads/main` line carrying `report-status`, and a clean flush.
fn advertisement(stack: &mut Stack) -> Result<[u8; 20], &'static str> {
    connect(stack, AD_PORT, AD_LOCAL_PORT)?;
    let handle = stack.tcp8_handle;
    let mut req = [0u8; 512];
    let req_len = http::build_request(&mut req, AD_HOST, AD_PATH, &[AD_ACCEPT])
        .ok_or("advertisement request does not fit")?;
    send_all(stack, handle, &req[..req_len])?;
    let (stored, _total) = read_response(stack, AD_CT, AD_CAP)?;
    close(stack, handle)?;

    // SAFETY: single-use static (see `BODY`); `stored` ≤ AD_CAP.
    let body = unsafe { &*addr_of_mut!(BODY) };
    let body = body
        .get(..stored)
        .ok_or("advertisement exceeds its bound")?;
    parse_advertisement(body)
}

/// Send the pack and read the `report-status` reply, asserting both
/// lines. The `request` buffer already holds the pkt-lines **and** the
/// pack; this builds the HTTP envelope once (the documented copy) and
/// drives the socket.
fn push_pack_request(stack: &mut Stack, request: &[u8]) -> Result<(), &'static str> {
    connect(stack, POST_PORT, POST_LOCAL_PORT)?;
    let handle = stack.tcp8_handle;
    let mut wire = post_scratch(request.len())?;
    let cap = request
        .len()
        .checked_add(1024)
        .ok_or("request size overflow")?;
    wire.resize(cap, 0);
    let wire_len = http::build_post(&mut wire, POST_HOST, POST_PATH, REQ_CT, request, &[])
        .ok_or("POST request does not fit its buffer")?;
    wire.truncate(wire_len);
    serial_println!("git: push: POST {wire_len} bytes to {POST_HOST}{POST_PATH}");
    send_all(stack, handle, &wire)?;
    let (stored, _total) = read_response(stack, RESULT_CT, RESULT_CAP)?;
    close(stack, handle)?;

    // SAFETY: single-use static (see `BODY`); `stored` ≤ AD_CAP.
    let body = unsafe { &*addr_of_mut!(BODY) };
    let body = body.get(..stored).ok_or("report exceeds its bound")?;
    parse_report(body)
}

/// Append the v0 command pkt-line and the flush that ends the command
/// section.
fn push_command(out: &mut Vec<u8>, old: &[u8; 20], new: &[u8; 20]) -> Result<(), &'static str> {
    let mut line = [0u8; 128];
    let old_hex = git_store::hex_oid(old);
    let new_hex = git_store::hex_oid(new);
    let parts: [&[u8]; 7] = [
        &old_hex,
        b" ",
        &new_hex,
        b" ",
        REF_NAME,
        b"\0report-status",
        b"\n",
    ];
    let mut len = 0usize;
    for part in parts {
        let end = len.checked_add(part.len()).ok_or("command overflow")?;
        line.get_mut(len..end)
            .ok_or("command line exceeds its buffer")?
            .copy_from_slice(part);
        len = end;
    }
    let mut pkt = [0u8; 160];
    let pkt_len = encode_data(line.get(..len).ok_or("command line truncated")?, &mut pkt)
        .ok_or("command pkt-line does not fit")?;
    out.extend_from_slice(pkt.get(..pkt_len).ok_or("pkt-line truncated")?);
    let mut flush = [0u8; 4];
    let flush_len = encode_flush(&mut flush).ok_or("flush does not fit")?;
    out.extend_from_slice(flush.get(..flush_len).ok_or("flush truncated")?);
    Ok(())
}

/// Parse the complete advertisement body (http-protocol + pack-protocol
/// v0): service header, flush, one ref line, flush.
fn parse_advertisement(body: &[u8]) -> Result<[u8; 20], &'static str> {
    let mut pos = 0usize;
    if expect_data(body, &mut pos)? != b"# service=git-receive-pack\n" {
        return Err("advertisement has the wrong service header");
    }
    expect_flush(body, &mut pos)?;
    let line = expect_data(body, &mut pos)?;
    let space = line
        .iter()
        .position(|&b| b == b' ')
        .ok_or("ref line has no object id separator")?;
    let oid_hex = line.get(..space).ok_or("ref line object id missing")?;
    let rest = line.get(space + 1..).ok_or("ref line name missing")?;
    let (name, caps) = match rest.iter().position(|&b| b == 0) {
        Some(nul) => (
            rest.get(..nul).ok_or("ref line name truncated")?,
            Some(rest.get(nul + 1..).ok_or("capability list truncated")?),
        ),
        None => (rest, None),
    };
    if name != REF_NAME {
        let mut buf = [0u8; SANITIZE_CAP];
        serial_println!("git: push: advertised ref: {}", sanitize(name, &mut buf));
        return Err("advertisement does not name refs/heads/main");
    }
    let caps = caps.ok_or("advertisement carries no capabilities")?;
    let caps = caps.strip_suffix(b"\n").unwrap_or(caps);
    if !has_capability(caps, CAP_REPORT_STATUS) {
        return Err("advertisement does not offer report-status");
    }
    let oid = git_store::parse_oid(oid_hex).map_err(|_| "advertised id is not 40 hex")?;
    expect_flush(body, &mut pos)?;
    if pos != body.len() {
        return Err("advertisement has trailing bytes");
    }
    Ok(oid)
}

/// Parse the complete `report-status` body: `unpack ok`, `ok
/// refs/heads/main`, flush.
fn parse_report(body: &[u8]) -> Result<(), &'static str> {
    let mut pos = 0usize;
    let unpack = expect_data(body, &mut pos)?;
    if unpack != b"unpack ok\n" {
        let mut buf = [0u8; SANITIZE_CAP];
        serial_println!("git: push: status: {}", sanitize(unpack, &mut buf));
        return Err("server reported an unpack failure");
    }
    let ok = expect_data(body, &mut pos)?;
    if ok != b"ok refs/heads/main\n" {
        let mut buf = [0u8; SANITIZE_CAP];
        serial_println!("git: push: status: {}", sanitize(ok, &mut buf));
        return Err("server did not accept refs/heads/main");
    }
    expect_flush(body, &mut pos)?;
    if pos != body.len() {
        return Err("report-status has trailing bytes");
    }
    serial_println!("git: push: unpack ok; ok refs/heads/main");
    Ok(())
}

/// Capability token search (`caps` is the NUL-terminated list, LF
/// stripped): exact token match, never a substring.
fn has_capability(caps: &[u8], want: &[u8]) -> bool {
    caps.split(|&b| b == b' ' || b == 0)
        .any(|token| token == want)
}

/// Next pkt-line, advancing `pos` past it.
fn next_pkt<'a>(body: &'a [u8], pos: &mut usize) -> Result<Pkt<'a>, &'static str> {
    let slice = body.get(*pos..).ok_or("pkt-line section truncated")?;
    match decode(slice) {
        Step::Done { consumed, pkt } => {
            *pos = pos
                .checked_add(consumed)
                .ok_or("pkt-line offset overflow")?;
            Ok(pkt)
        }
        Step::Incomplete => Err("pkt-line section truncated"),
        Step::Failed(_) => Err("malformed pkt-line"),
    }
}

fn expect_data<'a>(body: &'a [u8], pos: &mut usize) -> Result<&'a [u8], &'static str> {
    match next_pkt(body, pos)? {
        Pkt::Data(line) => Ok(line),
        _ => Err("expected a data pkt-line"),
    }
}

fn expect_flush(body: &[u8], pos: &mut usize) -> Result<(), &'static str> {
    match next_pkt(body, pos)? {
        Pkt::Flush => Ok(()),
        _ => Err("expected a flush-pkt"),
    }
}

/// Connect the fetch's socket (`tcp8`, idle in TIME-WAIT after G3) to
/// the mock on `port`, with a bounded retry for a listener that is
/// between `nc` invocations.
fn connect(stack: &mut Stack, port: u16, local_port: u16) -> Result<(), &'static str> {
    let handle = stack.tcp8_handle;
    let ip = gateway();
    for attempt in 1..=CONNECT_ATTEMPTS {
        // A socket left mid-handshake by an earlier failure accepts no
        // `connect`; aborting is the documented reset (`ai.rs`).
        if stack.sockets.get::<tcp::Socket>(handle).is_open() {
            stack.sockets.get_mut::<tcp::Socket>(handle).abort();
            stack.poll();
        }
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if let Err(e) = sock.connect(stack.iface.context(), (ip, port), local_port) {
                serial_println!("git: push: connect rejected: {e:?}");
                return Err("tcp connect rejected");
            }
        }
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            stack.poll();
            match stack.sockets.get::<tcp::Socket>(handle).state() {
                tcp::State::Established => return Ok(()),
                tcp::State::Closed => break, // refused/RST — retry
                _ => {}
            }
            if clock::now_ms() > deadline {
                return Err("tcp connect timeout");
            }
        }
        if attempt < CONNECT_ATTEMPTS {
            serial_println!("git: push: connect refused, retrying ({attempt}/{CONNECT_ATTEMPTS})");
        }
    }
    Err("connection refused by the mock (nc loop down?)")
}

/// Send `bytes` in poll-driven slices; the deadline re-arms on progress
/// (a large pack is not a hung socket).
fn send_all(stack: &mut Stack, handle: SocketHandle, bytes: &[u8]) -> Result<(), &'static str> {
    let mut sent = 0usize;
    let mut deadline = clock::now_ms() + OP_DEADLINE_MS;
    while sent < bytes.len() {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&bytes[sent..])
        {
            Ok(n) if n > 0 => {
                sent = sent.checked_add(n).ok_or("send offset overflow")?;
                deadline = clock::now_ms() + OP_DEADLINE_MS;
            }
            Ok(_) => {}
            Err(_) => return Err("tcp send rejected (connection lost)"),
        }
        if clock::now_ms() > deadline {
            return Err("tcp send timeout");
        }
    }
    Ok(())
}

/// Frame one HTTP response into `BODY`: status 200 and `expect_ct`
/// asserted as soon as the head parses, total body ≤ `cap`.
fn read_response(
    stack: &mut Stack,
    expect_ct: &[u8],
    cap: usize,
) -> Result<(usize, usize), &'static str> {
    let handle = stack.tcp8_handle;
    // SAFETY: single-use statics (see `PARSER`/`STAGING`/`BODY`); reset
    // because the advertisement and the report share them.
    let parser = unsafe { &mut *addr_of_mut!(PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(STAGING) };
    let body = unsafe { &mut *addr_of_mut!(BODY) };
    let mut scratch = [0u8; 1024];
    let mut stored = 0usize;
    let mut total = 0usize;
    let mut checked = false;
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
            let progress = parser
                .feed(&scratch[..n], staging)
                .map_err(|_| "HTTP response refused")?;
            deadline = clock::now_ms() + OP_DEADLINE_MS;
            if !checked && let Some(status) = parser.status() {
                if status != 200 {
                    return Err("unexpected HTTP status (expected 200)");
                }
                match http::header_value(parser.head(), b"content-type") {
                    Some(value) if ct_matches(value, expect_ct) => {}
                    Some(_) => return Err("unexpected Content-Type"),
                    None => return Err("response has no Content-Type"),
                }
                checked = true;
            }
            if progress.body > 0 {
                let take = core::cmp::min(body.len() - stored, progress.body);
                body.get_mut(stored..stored + take)
                    .ok_or("response body exceeds its buffer")?
                    .copy_from_slice(staging.get(..take).ok_or("response staging truncated")?);
                stored += take;
                total = total.checked_add(progress.body).ok_or("body overflow")?;
                if total > cap {
                    return Err("response body exceeds its bound");
                }
            }
            if progress.complete {
                break;
            }
            continue;
        }
        if (!may_recv && queued == 0) || closed {
            parser.eof().map_err(|_| "truncated response")?;
            break;
        }
        if clock::now_ms() > deadline {
            return Err("timeout waiting for the mock's response");
        }
    }
    if !checked {
        return Err("response head never parsed (Content-Type unchecked)");
    }
    Ok((stored, total))
}

/// Clean close: FIN → TimeWait/Closed (the pattern every sequential
/// smoke connection uses).
fn close(stack: &mut Stack, handle: SocketHandle) -> Result<(), &'static str> {
    stack.sockets.get_mut::<tcp::Socket>(handle).close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        let state = stack.sockets.get::<tcp::Socket>(handle).state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            return Ok(());
        }
        if clock::now_ms() > deadline {
            return Err("timeout closing the connection");
        }
    }
}

/// The slirp gateway = QEMU's host loopback (see `net::SLIRP_GATEWAY`).
fn gateway() -> Ipv4Address {
    Ipv4Address::new(
        net::SLIRP_GATEWAY[0],
        net::SLIRP_GATEWAY[1],
        net::SLIRP_GATEWAY[2],
        net::SLIRP_GATEWAY[3],
    )
}

/// Content-Type match with parameters allowed (the `ai.rs` rule).
fn ct_matches(value: &[u8], expected: &[u8]) -> bool {
    value.len() >= expected.len()
        && value[..expected.len()].eq_ignore_ascii_case(expected)
        && matches!(
            value.get(expected.len()),
            None | Some(&b';') | Some(&b' ') | Some(&b'\t')
        )
}
