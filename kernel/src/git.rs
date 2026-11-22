//! `git ls-remote` over smart HTTP — milestone G2 of
//! docs/git-ssh-deps.md: TLS to `github.com`, GET the
//! `git-upload-pack` advertisement of our public repo, parse it with
//! the `git-pktline` crate, print the refs — the smoke test's
//! `GIT_LSREMOTE_OK`. The chosen start oid (`HEAD`, else
//! `refs/heads/main`) is returned to the caller for G3's fetch
//! ([`crate::git_fetch::fetch`]).
//!
//! TLS trust, framing and shutdown all come from [`crate::tls`]
//! (pinned USERTrust root, RFC 9112 body framer); the pkt-line state
//! machine is `git-pktline` (from-scratch under dependency-policy
//! exception (a), justified and adversarially tested in its docs).
//! This module only assembles the request, asserts the endpoint's
//! `Content-Type`, and bounds the body.

use crate::netstack::Stack;
use crate::tls;
use core::ptr::addr_of_mut;
use git_pktline::Refs;
use smoltcp::wire::Ipv4Address;

/// Local port of the git connection: a socket in TIME-WAIT cannot be
/// reused for10 s, so every sequential connection owns a port (plain
/// HTTP 49152, robots TLS 49160, git TLS 49161).
const LOCAL_PORT: u16 = 49161;
/// SNI + certificate hostname for the connection.
const HOST: &str = "github.com";
/// Our public repo — `gh repo view` reports `visibility: PUBLIC`, so
/// `ls-remote` needs no credentials.
const PATH: &str = "/LuisErnestoZamb/reemplazo.git/info/refs?service=git-upload-pack";
/// The smart-HTTP advertisement's media type: http-protocol **requires**
/// it on the `?service=` response, so asserting it proves we reached
/// git's endpoint (not an HTML error page wearing a 200).
const EXPECT_CT: &[u8] = b"application/x-git-upload-pack-advertisement";
/// Body bound for the advertisement: this repo advertises a handful of
/// refs (far under 16 KiB); [`tls::tls_fetch`] counts every framed
/// byte, and the total is compared against this cap before parsing —
/// over the bound is refused, never truncated silently.
const BODY_CAP: usize = 16 * 1024;
/// Ref names and capability lists are wire bytes: print only printable
/// ASCII (anything else → `?`), the same log-injection reasoning as
/// the parser's strict CRLF.
const SANITIZE_CAP: usize = 200;

/// Single-use advertisement buffer (the `READ_STORAGE` idiom: written
/// once from `ls_remote` on a single core; IRQ0 never touches it).
static mut BODY: [u8; BODY_CAP] = [0; BODY_CAP];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: git: {msg}");
    crate::halt()
}

/// Copy `name` into `buf` as printable ASCII, returning the str — raw
/// wire bytes never reach the serial log (or the VGA mirror).
pub(crate) fn sanitize<'a>(name: &[u8], buf: &'a mut [u8]) -> &'a str {
    let n = name.len().min(buf.len());
    for (slot, &b) in buf[..n].iter_mut().zip(&name[..n]) {
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

/// Fetch and print the advertised refs of [`PATH`], proving the whole
/// git-client wire path end to end (TLS → smart HTTP → pkt-line).
/// Any protocol violation is `fatal` — a git client that skips a bad
/// line is a git client that lies about what the server said.
///
/// Returns the object id the clone starts from: `HEAD` when the
/// advertisement has one, else `refs/heads/main` — the input to the
/// G3 fetch ([`crate::git_fetch::fetch`]).
pub fn ls_remote(stack: &mut Stack, ip: Ipv4Address) -> [u8; 20] {
    let handle = stack.tcp3_handle;
    let tls = tls::tls_open(stack, handle, ip, HOST, LOCAL_PORT);

    // SAFETY: single-use static (see `BODY`).
    let body_buf = unsafe { &mut *addr_of_mut!(BODY) };
    let (status, body_total) = tls::tls_fetch(
        tls,
        HOST,
        PATH,
        &["User-Agent: reemplazo-git/0.1"],
        Some(EXPECT_CT),
        body_buf,
    );
    debug_assert_eq!(status, 200); // tls_fetch already refuses ≠ 200
    if body_total > body_buf.len() {
        fatal("advertisement exceeds the body bound");
    }
    let body = &body_buf[..body_total];

    // Parse the v0 advertisement: service header → flush → refs →
    // flush. The HTTP layer declared the body *complete*, which is
    // exactly the precondition `Refs` documents — truncation is an
    // error, never a partial ref list.
    let mut refs = Refs::new(body);
    let mut name_buf = [0u8; SANITIZE_CAP];
    let mut count = 0usize;
    let mut head: Option<[u8; 20]> = None;
    let mut main_branch: Option<[u8; 20]> = None;
    loop {
        match refs.next_ref() {
            Ok(Some(r)) => {
                // Advertisement ref lines end with LF (the pkt-line
                // payload includes it); strip it before comparing or
                // logging, so names stay exact and the log clean.
                let raw_name = r.name.strip_suffix(b"\n").unwrap_or(r.name);
                // Sanitize before the macro: the serial macros
                // evaluate their arguments twice (VGA + UART), so the
                // expression must stay side-effect free.
                let name = sanitize(raw_name, &mut name_buf);
                serial_println!("git: {name} {}", r.oid); // oid is 40 hex
                let oid = parse_oid(r.oid);
                if raw_name == b"HEAD" {
                    head = oid;
                } else if raw_name == b"refs/heads/main" {
                    main_branch = oid;
                }
                count += 1;
            }
            Ok(None) => break,
            Err(e) => {
                serial_println!("FATAL: git: bad advertisement: {e:?}");
                crate::halt();
            }
        }
    }
    // Capabilities ride on the first ref line: no caps means the
    // advertisement carried no refs at all.
    let Some(caps) = refs.capabilities() else {
        fatal("advertisement carried no refs (no capabilities)");
    };
    let caps = sanitize(caps, &mut name_buf);
    serial_println!("git: {count} refs, capabilities: {caps}");

    let Some(start) = head.or(main_branch) else {
        fatal("advertisement has neither HEAD nor refs/heads/main");
    };

    serial_println!("GIT_LSREMOTE_OK"); // machine-checked by `cargo xtask smoke`
    start
}

/// 40 hex digits → the 20-byte object id. `None` on any non-hex byte
/// (the parser already enforced the length); fail-closed, no indexing.
pub(crate) fn parse_oid(hex: &str) -> Option<[u8; 20]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 40 {
        return None;
    }
    let mut oid = [0u8; 20];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, pair) in oid.iter_mut().zip(pairs) {
        *slot = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(oid)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
