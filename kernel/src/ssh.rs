//! SSH milestone S1 (docs/git-ssh-deps.md §B.4): banner exchange +
//! `SSH_MSG_KEXINIT` negotiation against `github.com:22` — plaintext
//! algorithm intersection only, **no crypto** (key exchange, host-key
//! verification and encryption are S2). The smoke's
//! `SSH_KEXINIT_OK`.
//!
//! All wire parsing/encoding lives in the `ssh-wire` crate
//! (from-scratch under dependency-policy exception (a) — justified in
//! docs/git-ssh-deps.md §B.2 and in that crate's docs; zero
//! dependencies, adversarially tested on the host). This module only
//! drives the fourth TCP socket through the same fail-closed,
//! every-loop-bounded pattern as `netstack::plain_get_smoke`:
//!
//! 1. connect `tcp4` to `ip:22`,
//! 2. send our banner, read + validate the server's banner line
//!    (RFC4253 §4.2: ≤ 255 bytes including CRLF — a hostile server
//!    cannot stream past that cap),
//! 3. send our KEXINIT (cookie drawn from the kernel's CSPRNG),
//! 4. read the server's KEXINIT binary packet into a fixed 4 KiB
//!    buffer (framing + payload validated by `ssh-wire`),
//! 5. intersect the name-lists, print the agreed algorithms, and
//!    refuse to continue unless every must-have from §B.3 was agreed
//!    — negotiation failure is `FATAL`, never "continue anyway",
//! 6. print `SSH_KEXINIT_OK` and close the connection cleanly.
//!
//! Refused lines/packets/overflows print `FATAL: ssh: …` and halt:
//! an SSH client that skips a malformed byte is a client that lies
//! about what the server said.

use crate::clock;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use core::ptr::addr_of_mut;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

/// Local port of the SSH connection: a socket in TIME-WAIT cannot be
/// reused for 10 s, so every sequential connection owns a port (plain
/// HTTP 49152, robots TLS 49160, git TLS 49161, ssh 49162).
const LOCAL_PORT: u16 = 49162;
/// The IANA `ssh` port.
const REMOTE_PORT: u16 = 22;
/// Receive buffer for the server's KEXINIT packet: GitHub's offer is
/// well under 1 KiB, and every read here is bounded by this cap —
/// `Incomplete` at a full buffer means a declared packet larger than
/// the bound, which is fatal, never an unbounded read.
const KEX_CAP: usize = 4096;
/// Wire bytes reaching the log are copied through this as printable
/// ASCII first (same log-injection reasoning as `git.rs::sanitize`).
const SANITIZE_CAP: usize = 200;

/// Single-use server-KEXINIT accumulator (the `READ_STORAGE` idiom:
/// written once by `kexinit_smoke` on a single core; IRQ0 never
/// touches it).
static mut KEX_RX: [u8; KEX_CAP] = [0; KEX_CAP];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: ssh: {msg}");
    crate::halt()
}

/// Copy `bytes` into `buf` as printable ASCII, returning the str —
/// raw wire bytes never reach the serial log (or the VGA mirror).
fn sanitize<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    let n = bytes.len().min(buf.len());
    for (slot, &b) in buf[..n].iter_mut().zip(&bytes[..n]) {
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

/// A negotiated choice for the log: every field is checked by
/// `ssh_wire::check_must_have` before printing, but stay defensive.
fn choice_bytes(choice: Option<&'static str>) -> &'static [u8] {
    match choice {
        Some(name) => name.as_bytes(),
        None => b"(none)",
    }
}

/// What one bounded read attempt saw.
enum Chunk {
    /// `n` bytes copied into the caller's destination.
    Ready(usize),
    /// The peer closed (FIN with nothing queued) or reset — the
    /// caller was waiting for data that will never come.
    Closed,
    /// Nothing ready this poll — the caller checks its deadline.
    Idle,
}

/// One stack poll + whatever the socket has ready for `dst`. Every
/// network wait in this module goes through it, so every wait is
/// bounded by a deadline check in the caller's loop.
fn recv_ready(stack: &mut Stack, handle: SocketHandle, dst: &mut [u8]) -> Chunk {
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
            .recv_slice(dst)
            .unwrap_or(0);
        Chunk::Ready(n)
    } else if closed || (!may_recv && queued == 0) {
        Chunk::Closed
    } else {
        Chunk::Idle
    }
}

/// Send every byte of `data`, or `fatal` — the same bounded send loop
/// as `netstack::plain_get_smoke`.
fn send_all(stack: &mut Stack, handle: SocketHandle, data: &[u8]) {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut sent = 0usize;
    while sent < data.len() {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&data[sent..])
        {
            Ok(n) => sent += n,
            Err(_) => fatal("tcp send rejected (connection lost)"),
        }
        if clock::now_ms() > deadline {
            fatal("tcp send timeout");
        }
    }
}

/// SSH S1: banner exchange + `SSH_MSG_KEXINIT` negotiation against
/// `ip:22`, ending in the smoke's `SSH_KEXINIT_OK`. Every loop is
/// deadline-bounded, every refusal is fail-closed (`FATAL` + halt).
pub fn kexinit_smoke(stack: &mut Stack, ip: Ipv4Address) {
    let handle = stack.tcp4_handle;

    // 1. Connect (plain_get_smoke's deadline loop: bounded, no panic).
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if let Err(e) = sock.connect(stack.iface.context(), (ip, REMOTE_PORT), LOCAL_PORT) {
            serial_println!("ssh: connect rejected: {e:?}");
            crate::halt();
        }
    }
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        if stack.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established {
            break;
        }
        if clock::now_ms() > deadline {
            fatal("tcp connect timeout");
        }
    }
    serial_println!("ssh: connected to {ip}:{REMOTE_PORT}");

    // SAFETY: single-use static (see `KEX_RX`); single core and the
    // IRQ0 handler never touches it.
    let kex = unsafe { &mut *addr_of_mut!(KEX_RX) };

    // 2. Our banner first: RFC4253 §4.2 requires both identification
    // strings before any packet, so this goes out before we read.
    send_all(stack, handle, ssh_wire::OUR_BANNER);

    // The server's identification line, into a 255-byte line buffer
    // (RFC4253 §4.2 bound, CRLF included): past it, not SSH.
    let mut line = [0u8; ssh_wire::BANNER_MAX];
    let mut got = 0usize;
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let (consumed, ident) = loop {
        match recv_ready(stack, handle, &mut line[got..]) {
            Chunk::Ready(n) => got += n,
            Chunk::Closed => fatal("connection closed before the server banner"),
            Chunk::Idle => {}
        }
        match ssh_wire::decode_banner(&line[..got]) {
            ssh_wire::BannerStep::Incomplete => {}
            ssh_wire::BannerStep::Failed(e) => {
                serial_println!("ssh: bad server banner: {e:?}");
                crate::halt();
            }
            ssh_wire::BannerStep::Done { consumed, ident } => break (consumed, ident),
        }
        if clock::now_ms() > deadline {
            fatal("timeout waiting for the server banner");
        }
    };
    // Sanitize before the macro: the serial macros evaluate their
    // arguments twice (VGA + UART), so the expression must stay
    // side-effect free.
    let mut sbuf = [0u8; SANITIZE_CAP];
    let banner = sanitize(ident, &mut sbuf);
    serial_println!("ssh: server: {banner}");

    // Bytes past the CRLF are the start of the server's KEXINIT (a
    // server may pipeline banner + first packet in one segment) —
    // preserve them for phase 4 instead of dropping them.
    let mut kex_got = 0usize;
    let leftover = got - consumed;
    if leftover > 0 {
        kex[..leftover].copy_from_slice(&line[consumed..got]);
        kex_got = leftover;
    }

    // 3. Our KEXINIT — the cookie is 16 bytes of CSPRNG output
    // (RFC4253 §7.1 "RANDOM values"; never zeros — see entropy.rs).
    let mut cookie = [0u8; 16];
    for word in cookie.chunks_mut(4) {
        word.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
    }
    let mut wire = [0u8; ssh_wire::KEXINIT_WIRE_MAX];
    let Some(wire_len) = ssh_wire::encode_kexinit(&cookie, &mut wire) else {
        fatal("our KEXINIT does not fit the buffer");
    };
    send_all(stack, handle, &wire[..wire_len]);

    // 4. The server's KEXINIT binary packet: accumulate into the
    // fixed buffer (smoltcp hands us whatever is ready — payloads
    // arrive split across reads) and validate the framing on every
    // step, so a bad declared length fails before it is waited on.
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let payload = loop {
        match recv_ready(stack, handle, &mut kex[kex_got..]) {
            Chunk::Ready(n) => kex_got += n,
            Chunk::Closed => fatal("connection closed before the server KEXINIT"),
            Chunk::Idle => {}
        }
        match ssh_wire::decode_packet(&kex[..kex_got]) {
            ssh_wire::PacketStep::Incomplete => {
                if kex_got >= kex.len() {
                    fatal("server KEXINIT exceeds the receive buffer");
                }
            }
            ssh_wire::PacketStep::Failed(e) => {
                serial_println!("ssh: bad server packet: {e:?}");
                crate::halt();
            }
            ssh_wire::PacketStep::Done { payload, .. } => break payload,
        }
        if clock::now_ms() > deadline {
            fatal("timeout waiting for the server KEXINIT");
        }
    };

    // 5. Parse the KEXINIT, intersect per RFC4253 §7.1, and refuse
    // to continue unless every §B.3 must-have was agreed on.
    let server = match ssh_wire::parse_kexinit(payload) {
        Ok(k) => k,
        Err(e) => {
            serial_println!("ssh: malformed KEXINIT: {e:?}");
            crate::halt();
        }
    };
    let negotiated = ssh_wire::intersect(&server);
    if let Err(missing) = ssh_wire::check_must_have(&negotiated) {
        // Fail closed — and say what the server actually offered
        // (sanitized, bounded) so the failure is diagnosable.
        let mut offered = [0u8; SANITIZE_CAP];
        let lists: [(&str, &[u8]); 8] = [
            ("kex", server.kex_algorithms),
            ("host key", server.server_host_key_algorithms),
            ("enc c2s", server.encryption_algorithms_c2s),
            ("enc s2c", server.encryption_algorithms_s2c),
            ("mac c2s", server.mac_algorithms_c2s),
            ("mac s2c", server.mac_algorithms_s2c),
            ("comp c2s", server.compression_algorithms_c2s),
            ("comp s2c", server.compression_algorithms_s2c),
        ];
        for (label, list) in lists {
            let names = sanitize(list, &mut offered);
            serial_println!("ssh: server offers {label}: {names}");
        }
        let need = missing.as_str();
        serial_println!("ssh: no agreement on {need}");
        fatal("algorithm negotiation failed");
    }

    // Print the agreed algorithms — sanitize into stack buffers first
    // (side-effect-free macro arguments, log-injection guard).
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    let v = sanitize(choice_bytes(negotiated.kex), &mut a);
    serial_println!("ssh: negotiated kex: {v}");
    let v = sanitize(choice_bytes(negotiated.host_key), &mut a);
    serial_println!("ssh: negotiated host key: {v}");
    let c2s = sanitize(choice_bytes(negotiated.enc_c2s), &mut a);
    let s2c = sanitize(choice_bytes(negotiated.enc_s2c), &mut b);
    serial_println!("ssh: negotiated enc: {c2s} (c2s) / {s2c} (s2c)");
    let c2s = sanitize(choice_bytes(negotiated.mac_c2s), &mut a);
    let s2c = sanitize(choice_bytes(negotiated.mac_s2c), &mut b);
    serial_println!("ssh: negotiated mac: {c2s} (c2s) / {s2c} (s2c)");
    let c2s = sanitize(choice_bytes(negotiated.comp_c2s), &mut a);
    let s2c = sanitize(choice_bytes(negotiated.comp_s2c), &mut b);
    serial_println!("ssh: negotiated compression: {c2s} (c2s) / {s2c} (s2c)");

    serial_println!("SSH_KEXINIT_OK"); // machine-checked by `cargo xtask smoke`

    // 6. Orderly teardown (plain_get_smoke's close proof): FIN, then
    // require the socket to reach TimeWait or Closed.
    stack.sockets.get_mut::<tcp::Socket>(handle).close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        let state = stack.sockets.get::<tcp::Socket>(handle).state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            serial_println!("ssh: connection closed cleanly ({state})");
            return;
        }
        if clock::now_ms() > deadline {
            fatal("timeout closing connection (never reached TimeWait/Closed)");
        }
    }
}
