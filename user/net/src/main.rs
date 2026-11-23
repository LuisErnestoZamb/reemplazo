//! Hito 5 — the network stack exercised from a **CPL3 process**.
//!
//! No kernel objects cross the boundary: the only artefacts are opaque
//! handles and bounded byte buffers. This process
//!   1. resolves the mock DNS address (`10.0.2.3`) through syscall 16 and
//!      checks the packed IPv4 result plus the four written octets,
//!   2. refuses a non-whitelisted hostname (fail-closed) and malformed
//!      arguments,
//!   3. connects to the chat mock on `10.0.2.2:8099`, sends one minimal
//!      HTTP request, receives the canned reply with bounded `Yield` polls
//!      (`SockRecv` returns `EAGAIN` when nothing is ready), compares it
//!      byte-exactly and prints `USER_NET_OK`,
//!   4. closes the handle and calls `exit(0)` — no infinite kernel-level
//!      loops, exactly like the hito-4 editor.
//!
//! The hito-3 console and hito-4 FS/editor proofs run first (see `legacy`)
//! because the U1 loader has a single capture slot; the marker order in
//! `smoke-user` is unchanged except for the new `USER_NET_OK`.

#![no_std]
#![no_main]

use userlib as sys;

core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

mod legacy;

const RESP_CAP: usize = 1024;
const MAX_POLLS: u32 = 500_000;
const OP_MS: i64 = 4_000;

const DNS_NAME: &[u8] = b"10.0.2.3";
const PEER: [u8; 4] = [10, 0, 2, 2];
const PEER_PORT: u16 = 8099;
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: mock\r\nConnection: close\r\n\r\n";
const STATUS: &[u8] = b"HTTP/1.1 200";
const REPLY: &[u8] = b"reemplazo: mock reply ok";

// Non-zero initial bytes keep these statics in .data: an all-zero static
// lands in .bss and rust-lld emits a second R|W PT_LOAD the loader refuses.
static mut IP_OUT: [u8; 4] = [b' '; 4];
static mut BAD_OUT: [u8; 4] = [b' '; 4];
static mut RESPONSE: [u8; RESP_CAP] = [b' '; RESP_CAP];

fn ip_out() -> &'static mut [u8; 4] {
    // SAFETY: single-threaded CPL3 process, one live borrow at a time;
    // the kernel's DnsResolve copy completes before the next call.
    unsafe { &mut *core::ptr::addr_of_mut!(IP_OUT) }
}

fn bad_out() -> &'static mut [u8; 4] {
    // SAFETY: see `ip_out()`.
    unsafe { &mut *core::ptr::addr_of_mut!(BAD_OUT) }
}

fn response() -> &'static mut [u8; RESP_CAP] {
    // SAFETY: single-threaded, one live borrow; `SockRecv`'s user-buffer
    // write returns and drops its borrow before the next accessor call.
    unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE) }
}

fn die(what: &[u8]) -> ! {
    sys::write_str("FATAL: unet: ");
    let _ = sys::write(2, what);
    sys::write_str("\n");
    sys::exit(1)
}

fn expect(ok: bool, what: &[u8]) {
    if !ok {
        die(what);
    }
}

fn write_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    if value == 0 {
        at -= 1;
        digits[at] = b'0';
    }
    while value > 0 {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let _ = sys::write(1, &digits[at..]);
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    legacy::prove();
    net_proof();
    sys::exit(0)
}

fn net_proof() {
    // (1) DNS: an IPv4 literal is answered locally by the kernel (no
    // outbound query), so this part of the proof needs no internet.
    let packed = sys::dns_resolve(DNS_NAME, ip_out());
    expect(packed == 0x0a00_0203, b"DNS result");
    expect(
        ip_out()[0] == 10 && ip_out()[1] == 0 && ip_out()[2] == 2 && ip_out()[3] == 3,
        b"DNS octets",
    );
    // A name outside the kernel's whitelist must be refused without any
    // resolver work (the pinned-root TLS policy uses the same list).
    expect(
        sys::dns_resolve(b"evil.example", bad_out()) == sys::EPERM,
        b"non-whitelisted host resolved",
    );
    expect(
        sys::dns_resolve(b"10.0.2.3", &mut [0u8; 3][..]) == sys::EINVAL,
        b"short DNS output accepted",
    );

    // (2) Connect. A three-byte IP is not an address; a bogus handle is
    // never mistaken for a kernel socket.
    expect(
        sys::sock_connect(&[10, 0, 2], 80) == sys::EINVAL,
        b"short IP accepted",
    );
    expect(sys::sock_send(0, REQUEST) == sys::EINVAL, b"fd 0 sent");
    expect(sys::sock_close(0) == sys::EINVAL, b"fd 0 closed");

    expect(
        sys::sock_recv(-1, response()) == sys::EINVAL,
        b"bogus handle read",
    );

    // (3) Non-blocking receive: EAGAIN means yield and retry. The mock is
    // a respawnable one-shot `nc` loop, so a connection can land between
    // two listeners; retry the whole exchange a bounded number of times.
    // Every attempt has a poll cap and a wall-clock deadline.
    let mut polls = 0u32;
    let mut ok = false;
    for attempt in 0..3 {
        polls = 0;
        let handle = sys::sock_connect(&PEER, PEER_PORT);
        if handle <= 0 {
            continue;
        }
        let sent = sys::sock_send(handle, REQUEST);
        if sent != REQUEST.len() as i64 {
            let _ = sys::sock_close(handle);
            continue;
        }
        let mut total = 0usize;
        let deadline = sys::time() + OP_MS;
        while total < RESP_CAP && polls < MAX_POLLS && sys::time() < deadline {
            if contains(&response()[..total], STATUS) && contains(&response()[..total], REPLY) {
                break; // complete reply — the mock keeps the socket open
            }
            match sys::sock_recv(handle, &mut response()[total..]) {
                n if n > 0 => total += n as usize,
                sys::EAGAIN => {
                    polls = polls.saturating_add(1);
                    let _ = sys::yield_now();
                }
                0 => break, // peer FIN with no (more) data
                e => {
                    sys::write_str("FATAL: unet: recv errno ");
                    write_u64(e as u64);
                    sys::exit(1);
                }
            }
        }
        ok = contains(&response()[..total], STATUS) && contains(&response()[..total], REPLY);
        expect(sys::sock_close(handle) == 0, b"close socket");
        if ok {
            break;
        }
        if attempt < 2 {
            let _ = sys::yield_now();
        }
    }
    expect(ok, b"chat mock reply not received");

    sys::write_str("USER_NET_OK polls=");
    write_u64(polls as u64);
    sys::write_str("\n");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    sys::write_str("FATAL: unet panic at ");
    if let Some(loc) = info.location() {
        sys::write_str(loc.file());
        sys::write_str(":");
        write_u64(loc.line() as u64);
    }
    sys::write_str("\n");
    sys::exit(1)
}
