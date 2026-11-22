//! SSH **server** — milestone S5 of docs/git-ssh-deps.md §B.4: the
//! mirror image of `kernel/src/ssh.rs`.
//!
//! Up to [`SESSIONS_PER_CALL`] sequential sessions on guest TCP port
//! **2222**, and only
//! when the attached FAT16 volume carries a server key set
//! (`/HOST.BIN` + `/AUTH.KEY`, see `crate::keyfile`). With no disk —
//! the 30-marker `cargo xtask smoke` — or with the installer smoke's
//! disk (README only) this module is never called: no listener, no log
//! line, nothing on the wire.
//!
//! [`serve_once`] accepts up to [`SESSIONS_PER_CALL`] connections
//! sequentially: the smoke path calls it once, so `cargo xtask
//! smoke-ssh` gets VM2's own client first and then its **OpenSSH
//! interop** phase (a real `ssh` from the tools container), which is
//! what prints `SSHD_INTEROP_OK`. The hardware bring-up loop
//! (`hwtest::run`) already called it repeatedly; the second window
//! only widens the same bounded accept budget there.
//!
//! Protocol shape (RFC4253, RFC4252, RFC4254):
//!
//! 1. the server sends its identification banner **first** (RFC4253
//!    §4.2), then its `KEXINIT` (`curve25519-sha256`, `ssh-ed25519`,
//!    `aes128-ctr`, `hmac-sha2-256`, `none`),
//! 2. receive the client's banner + `KEXINIT`, intersect as the
//!    responder and refuse anything but the exact set we implement,
//! 3. `SSH_MSG_KEXDH_INIT` → X25519 with our ephemeral secret, the
//!    exchange hash `H` over the RFC4253 §8 field order, and
//!    `SSH_MSG_KEXDH_REPLY` whose signature is ed25519 over `H` with
//!    the **host key seed from disk** (the one secret this module
//!    holds; never printed),
//! 4. `NEWKEYS` both ways, then AES-CTR + HMAC-SHA2-256 in both
//!    directions,
//! 5. `ssh-userauth` service request/accept; `none` is answered with
//!    `USERAUTH_FAILURE(publickey)`, the `publickey` probe with
//!    `PK_OK` when the key matches `authorized_keys`, and the signed
//!    request verified over `string session_id ‖ request`
//!    (RFC4252 §7) before `USERAUTH_SUCCESS`,
//! 6. (S5b) one `session` channel: an `exec` request runs the tiny
//!    internal handler (`echo …`), and its output is sent as channel
//!    data with `exit-status`, EOF and close.
//!
//! ## Fail-closed, bounded, never fatal
//!
//! The client's policy is `FATAL` + halt (a lying server must not look
//! like a passing smoke). The server's policy is the opposite: **drop
//! the connection** with one bounded reason line, then fall through to
//! the rest of the boot. Every receive has a deadline, every buffer a
//! cap, every parser is `ssh-wire`'s (host-tested); `Err(&'static str)`
//! is the only failure type, so the reason text is ours and no wire
//! byte can reach the log unsanitized.
//!
//! Two connections per [`serve_once`] call at most: smoltcp hands a
//! listening socket one connection at a time, so each is accepted,
//! served and closed before the next window opens, and every window
//! waits a bounded 45 s. A real concurrent accept loop is a later
//! milestone (it needs the shell/scheduler to run beside it); this is
//! the end-to-end proof our client and the OpenSSH interop need.

use crate::clock;
use crate::keyfile::ServerConfig;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use crate::power::idle;
use crate::ssh;
use core::ptr::addr_of_mut;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use x25519_dalek::{PublicKey, StaticSecret};

/// Guest-side listener port (the two-VM harness forwards the
/// container's loopback :2222 to it — see `cargo xtask smoke-ssh`).
pub(crate) const LISTEN_PORT: u16 = 2222;
/// How long each accept window waits for its client (`smoke-ssh`
/// starts both VMs together; the client needs ~20 s to finish its own
/// boot).
const ACCEPT_DEADLINE_MS: u64 = 45_000;
/// Connections served per [`serve_once`] call. The smoke path calls
/// it once, so this is the whole budget `cargo xtask smoke-ssh` gets:
/// window 0 is VM2's own client (the original S5 phase), window 1 is
/// the **OpenSSH interop** phase — a real `ssh` run by xtask from
/// inside the tools container against the same sshd, which is what
/// prints `SSHD_INTEROP_OK`. Each window gets its own bounded accept
/// deadline, so the interop client can never wedge the boot.
const SESSIONS_PER_CALL: u32 = 2;
/// Per-receive budget inside a session: a client that stalls is
/// dropped, never wedged into the boot.
const STEP_DEADLINE_MS: u64 = OP_DEADLINE_MS;
/// Connection receive buffer: the same bound as the client's.
const RX_CAP: usize = 4096;
/// Largest single encrypted payload the server will handle; the
/// packets of this protocol are all far smaller (bounds the copy-out
/// buffer used before any parser runs).
const PAYLOAD_CAP: usize = 1024;
/// Wire bytes reaching the log are copied through this first.
const SANITIZE_CAP: usize = 200;
/// Authentication attempts before the connection is dropped.
const AUTH_ATTEMPTS_MAX: u32 = 3;
/// The channel window we advertise (bytes) and the largest data packet
/// we promise to receive. The toy `exec` output is a few dozen bytes.
const CHANNEL_WINDOW: u32 = 64 * 1024;
const MAX_PACKET: u32 = 32 * 1024;
/// Server-side channel id for the one session channel.
const SERVER_CHANNEL: u32 = 0;

/// Single-use session receive buffer (the `ssh::RX` idiom: single core,
/// IRQ0 never touches it, one connection at a time).
static mut RX: [u8; RX_CAP] = [0; RX_CAP];

/// Serve up to [`SESSIONS_PER_CALL`] clients, each inside its own
/// bounded accept window, or give up after [`ACCEPT_DEADLINE_MS`].
/// Returns `true` when at least one session ran to completion — the
/// hardware bring-up loop counts `false` as an idle window
/// (`hwtest::run`). Called from the boot chain only when a disk
/// carried a server key.
/// Last session-failure reason, replayed as an `SSH_MSG_USERAUTH_BANNER`
/// on the *next* connection. A keyboard-less, serial-less machine has
/// no other way to tell a remote operator why a session died — the
/// banner is the one channel OpenSSH prints verbatim on stderr.
/// Single core; written from the serve path, IRQ0 never touches it.
const LAST_FAIL_CAP: usize = 160;
static mut LAST_FAIL: [u8; LAST_FAIL_CAP] = [0; LAST_FAIL_CAP];
static mut LAST_FAIL_LEN: usize = 0;

/// Store a failure reason (truncated to the buffer) for the next
/// connection's banner.
fn remember_fail(reason: &str) {
    let bytes = reason.as_bytes();
    let n = bytes.len().min(LAST_FAIL_CAP);
    // SAFETY: single-core serve path, the only writer/reader; the
    // length never exceeds the buffer it indexes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::addr_of_mut!(LAST_FAIL) as *mut u8,
            n,
        );
        LAST_FAIL_LEN = n;
    }
}

/// Take the stored reason (one-shot: the banner is sent once).
fn take_fail() -> Option<&'static [u8]> {
    // SAFETY: as `remember_fail`; cleared immediately after the read,
    // so no aliasing outlives this call.
    unsafe {
        let n = LAST_FAIL_LEN;
        LAST_FAIL_LEN = 0;
        if n == 0 || n > LAST_FAIL_CAP {
            None
        } else {
            Some(core::slice::from_raw_parts(
                core::ptr::addr_of!(LAST_FAIL) as *const u8,
                n,
            ))
        }
    }
}

pub(crate) fn serve_once(stack: &mut Stack, cfg: &ServerConfig) -> bool {
    // The fingerprint is public material: it is what an operator
    // compares out of band. The seed behind it is never printed.
    let mut host_seed = cfg.host_seed;
    let signing = SigningKey::from_bytes(&host_seed);
    host_seed.fill(0);
    let mut blob = [0u8; ssh_wire::ED25519_KEY_BLOB_LEN];
    let blob_len = match ssh_wire::ed25519_key_blob(&signing.verifying_key().to_bytes(), &mut blob)
    {
        Some(n) => n,
        None => {
            serial_println!("sshd: host key blob does not fit");
            return false;
        }
    };
    ssh::print_public_key("sshd: host key (ssh-ed25519)", &blob[..blob_len]);

    if !stack.listen_ssh(LISTEN_PORT) {
        serial_println!("sshd: cannot listen on :{LISTEN_PORT}; not serving");
        return false;
    }
    serial_println!(
        "sshd: listening on :{LISTEN_PORT} (up to {SESSIONS_PER_CALL} connections, {} s per window)",
        ACCEPT_DEADLINE_MS / 1000
    );
    // machine-checked by `cargo xtask smoke-ssh` (server VM)
    serial_println!("SSHD_LISTEN_OK");

    let handle = stack.listen_handle;
    let mut served = false;
    for window in 0..SESSIONS_PER_CALL {
        // Window ≥ 1 starts from the previous session's socket, which
        // may still be closing (or dead mid-close): `listen_ssh`
        // aborts whatever is open before listening again.
        if window > 0 && !stack.listen_ssh(LISTEN_PORT) {
            serial_println!("sshd: cannot re-listen on :{LISTEN_PORT}");
            break;
        }
        let deadline = clock::now_ms() + ACCEPT_DEADLINE_MS;
        let mut connected = false;
        loop {
            stack.poll();
            let state = stack.sockets.get::<tcp::Socket>(handle).state();
            if state == tcp::State::Established {
                connected = true;
                break;
            }
            // A SYN that immediately resets leaves the socket closed;
            // put it back into Listen (bounded by the window deadline).
            if matches!(state, tcp::State::Closed | tcp::State::TimeWait)
                && !stack.listen_ssh(LISTEN_PORT)
            {
                serial_println!("sshd: cannot re-listen on :{LISTEN_PORT}");
                return served;
            }
            if clock::now_ms() > deadline {
                break;
            }
            // Nothing to accept and no reset to re-arm this pass: sleep
            // a tick instead of spinning the Core2 at 100%. `hlt` with
            // IF=1 (armed by `arm_interrupts` long before the serve
            // path) wakes on IRQ0 within one tick, so `clock::now_ms`
            // keeps the window deadline exact — SAFETY as in
            // `main::test_interrupts`. The NIC is polled (IRQ0 is the
            // only unmasked line), so a packet arriving mid-sleep is
            // noticed on the next poll: ≤10 ms added latency per idle
            // pass, the accepted price of a quiet machine for SSH.
            idle();
        }
        if !connected {
            if window == 0 {
                serial_println!(
                    "sshd: no client within {} s; not serving",
                    ACCEPT_DEADLINE_MS / 1000
                );
                return false;
            }
            serial_println!(
                "sshd: no second client within {} s; interop window expired",
                ACCEPT_DEADLINE_MS / 1000
            );
            break;
        }

        if let Some(remote) = stack.sockets.get::<tcp::Socket>(handle).remote_endpoint() {
            serial_println!("sshd: client connected from {remote}");
        } else {
            serial_println!("sshd: client connected");
        }

        match session(stack, handle, &signing, &blob[..blob_len], cfg) {
            Ok(()) => {
                served = true;
                serial_println!("sshd: session complete");
                // machine-checked by `cargo xtask smoke-ssh` (server VM)
                serial_println!("SSHD_SESSION_OK");
                if window == 1 {
                    // Window 1 of the smoke path is `cargo xtask
                    // smoke-ssh`'s OpenSSH interop phase (VM2's own
                    // client had window 0): a real `ssh` authenticated
                    // and ran its exec to completion.
                    serial_println!("SSHD_INTEROP_OK");
                }
            }
            Err(reason) => {
                serial_println!("sshd: connection dropped: {reason}");
                remember_fail(reason);
                return served;
            }
        }

        // Orderly close: FIN if the peer is still there; a dead
        // connection is simply released.
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if sock.is_open() {
                sock.close();
            }
        }
        let deadline = clock::now_ms() + STEP_DEADLINE_MS;
        loop {
            stack.poll();
            let state = stack.sockets.get::<tcp::Socket>(handle).state();
            if matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
                break;
            }
            if clock::now_ms() > deadline {
                break; // release anyway: one session, then the next window
            }
            // FIN not acknowledged yet: sleep a tick (as in the accept
            // loop above) rather than spin until the close completes.
            idle();
        }
    }
    served
}

/// One wire failure reason — ours, static, safe to log.
type Wire = Result<(), &'static str>;

/// The whole server-side session. Returns `Ok(())` only after an
/// authenticated `exec` finished and the channel closed.
fn session(
    stack: &mut Stack,
    handle: SocketHandle,
    signing: &SigningKey,
    host_key_blob: &[u8],
    cfg: &ServerConfig,
) -> Wire {
    // SAFETY: single-use static (see `RX`); single core, one connection.
    let rx = unsafe { &mut *addr_of_mut!(RX) };

    // 1. Banner first (RFC4253 §4.2), then our KEXINIT — a server may
    //    pipeline them; both peers send their identification before
    //    anything else either way.
    send_all(stack, handle, ssh_wire::OUR_BANNER)?;
    let mut cookie = [0u8; 16];
    for word in cookie.chunks_mut(4) {
        word.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
    }
    let mut kexinit_wire = [0u8; ssh_wire::KEXINIT_WIRE_MAX];
    let kexinit_len = match ssh_wire::encode_kexinit_server(&cookie, &mut kexinit_wire) {
        Some(n) => n,
        None => return Err("server KEXINIT does not fit its buffer"),
    };
    send_all(stack, handle, &kexinit_wire[..kexinit_len])?;
    let mut seq_tx = 1u32; // KEXINIT was packet 0
    let mut seq_rx = 0u32;

    // 2. Client banner (≤255 bytes including CRLF), then whatever it
    //    pipelined after it — normally its KEXINIT.
    let mut line = [0u8; ssh_wire::BANNER_MAX];
    let (ident_len, leftover) = recv_banner(stack, handle, &mut line, rx)?;
    let mut got = leftover;
    let mut xh = Sha256::new();
    ssh::hash_string(&mut xh, &line[..ident_len]);
    let v_s = ssh_wire::OUR_BANNER
        .strip_suffix(b"\r\n")
        .unwrap_or(ssh_wire::OUR_BANNER);
    ssh::hash_string(&mut xh, v_s);

    // 3. I_S (our KEXINIT payload as sent, message byte included, no
    //    framing) is hashed after I_C — RFC4253 §8's field order is
    //    V_C, V_S, I_C, I_S. Extract it now, hash it below.
    let i_s = match ssh_wire::decode_packet(&kexinit_wire[..kexinit_len]) {
        ssh_wire::PacketStep::Done { payload, .. } => payload,
        _ => return Err("server KEXINIT does not decode (encoder bug)"),
    };

    // 4. Client KEXINIT: parse, hash I_C then I_S, intersect as
    //    responder.
    let (s, e, used) = recv_plain(stack, handle, rx, &mut got)?;
    let negotiated = {
        let Some(payload) = rx.get(s..e) else {
            return Err("KEXINIT payload range out of bounds");
        };
        let client = match ssh_wire::parse_kexinit(payload) {
            Ok(k) => k,
            Err(e) => {
                serial_println!("sshd: malformed client KEXINIT: {e:?}");
                return Err("malformed client KEXINIT");
            }
        };
        ssh::hash_string(&mut xh, payload);
        ssh::hash_string(&mut xh, i_s);
        let negotiated = ssh_wire::intersect_as_server(&client);
        if let Err(missing) = ssh_wire::check_must_have(&negotiated) {
            serial_println!("sshd: no agreement on {}", missing.as_str());
            return Err("algorithm negotiation failed");
        }
        // Print only names from our own lists (never client bytes).
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let kex = ssh::sanitize(choice(negotiated.kex), &mut a);
        serial_println!("sshd: negotiated kex: {kex}");
        let enc = ssh::sanitize(choice(negotiated.enc_c2s), &mut b);
        let mac = ssh::sanitize(choice(negotiated.mac_c2s), &mut a);
        serial_println!("sshd: negotiated enc/mac: {enc} / {mac}");
        // machine-checked by `cargo xtask smoke-ssh` (server VM)
        serial_println!("SSHD_KEXINIT_OK");
        negotiated
    };
    consume_plain(rx, &mut got, used);
    seq_rx += 1;

    // 5. SSH_MSG_KEXDH_INIT → shared secret, exchange hash, signature.
    let (s, e, used) = recv_plain(stack, handle, rx, &mut got)?;
    let (derived, session_id) = {
        let Some(payload) = rx.get(s..e) else {
            return Err("KEXDH_INIT payload range out of bounds");
        };
        let e_pub = match ssh_wire::parse_kexdh_init(payload) {
            Ok(e) => e,
            Err(e) => {
                serial_println!("sshd: malformed KEXDH_INIT: {e:?}");
                return Err("malformed KEXDH_INIT");
            }
        };

        let mut priv_bytes = [0u8; 32];
        for chunk in priv_bytes.chunks_mut(4) {
            chunk.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
        }
        let secret = StaticSecret::from(priv_bytes);
        priv_bytes.fill(0);
        let f = *PublicKey::from(&secret).as_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(e_pub));
        if ssh_wire::ct_eq(shared.as_bytes(), &[0u8; 32]) {
            return Err("all-zero shared secret (small-order client value)");
        }

        // H = SHA256(string(V_C) || string(V_S) || string(I_C) ||
        //     string(I_S) || string(K_S) || string(e) || string(f) ||
        //     mpint(K))
        ssh::hash_string(&mut xh, host_key_blob);
        ssh::hash_string(&mut xh, &e_pub);
        ssh::hash_string(&mut xh, &f);
        let mut kbuf = [0u8; 40];
        let Some(klen) = ssh_wire::encode_mpint(shared.as_bytes(), &mut kbuf) else {
            return Err("shared secret does not fit the mpint buffer");
        };
        xh.update(&kbuf[..klen]);
        let h: [u8; 32] = xh.finalize().into();

        // Sign H with the host key (RFC4253 §8: ed25519 signs H
        // directly). The signature blob is re-validated by the encoder.
        let signature = signing.sign(&h);
        let mut sig_blob = [0u8; ssh_wire::ED25519_SIG_BLOB_LEN];
        let Some(sig_len) = ssh_wire::ed25519_signature_blob(&signature.to_bytes(), &mut sig_blob)
        else {
            return Err("signature blob does not fit its buffer");
        };
        let mut reply = [0u8; 512];
        let Some(reply_len) =
            ssh_wire::kexdh_reply_payload(host_key_blob, &f, &sig_blob[..sig_len], &mut reply)
        else {
            return Err("KEXDH_REPLY does not fit its buffer");
        };
        // Payload → framed packet (RFC4253 §6): the reply is its own
        // binary packet, not raw payload bytes.
        send_plain(stack, handle, &reply[..reply_len])?;
        seq_tx += 1;
        serial_println!("sshd: key exchange complete (host-key signature sent)");

        let k = shared.as_bytes();
        let key_len = match negotiated.enc_c2s {
            Some("aes128-ctr") => 16usize,
            _ => return Err("negotiated cipher has no key length"),
        };
        let mut d = ssh::Derived {
            iv_c2s: [0; 16],
            iv_s2c: [0; 16],
            key_c2s: [0; 32],
            key_s2c: [0; 32],
            mac_c2s: [0; 32],
            mac_s2c: [0; 32],
            key_len_c2s: key_len,
            key_len_s2c: key_len,
        };
        for (letter, out) in [
            (b'A', &mut d.iv_c2s[..]),
            (b'B', &mut d.iv_s2c[..]),
            (b'C', &mut d.key_c2s[..key_len]),
            (b'D', &mut d.key_s2c[..key_len]),
            (b'E', &mut d.mac_c2s[..]),
            (b'F', &mut d.mac_s2c[..]),
        ] {
            if let Err(e) = ssh::kdf_checked(letter, k, &h, out) {
                serial_println!("sshd: key derivation refused: {e:?}");
                return Err("key derivation failed");
            }
        }
        (d, h)
    };
    consume_plain(rx, &mut got, used);
    seq_rx += 1;

    // 6. NEWKEYS: ours goes out plaintext, then our transmit keys are
    //    live; the client's flips the receive side. Leftover bytes
    //    after it are already ciphertext — `EncryptedRx` starts there.
    send_plain(stack, handle, &[ssh_wire::SSH_MSG_NEWKEYS])?;
    seq_tx += 1;
    let (s, e, used) = recv_plain(stack, handle, rx, &mut got)?;
    {
        let Some(payload) = rx.get(s..e) else {
            return Err("NEWKEYS payload range out of bounds");
        };
        if payload != [ssh_wire::SSH_MSG_NEWKEYS] {
            return Err("expected a bare SSH_MSG_NEWKEYS from the client");
        }
    }
    consume_plain(rx, &mut got, used);
    seq_rx += 1;

    // Server transmit = s2c; server receive = c2s.
    let mut tx_dir = ssh::direction(
        &derived.key_s2c[..derived.key_len_s2c],
        &derived.iv_s2c,
        derived.mac_s2c,
    );
    let mut rx_dir = ssh::direction(
        &derived.key_c2s[..derived.key_len_c2s],
        &derived.iv_c2s,
        derived.mac_c2s,
    );
    let mut enc_rx = ssh_wire::EncryptedRx::new(&mut rx[..], got);

    // 7. Encrypted phase: service request → auth → one channel.
    let mut wire = Conn {
        handle,
        tx_dir: &mut tx_dir,
        rx_dir: &mut rx_dir,
        enc_rx: &mut enc_rx,
        seq_tx: &mut seq_tx,
        seq_rx: &mut seq_rx,
    };
    let mut service_accepted = false;
    let mut failures = 0u32;
    let mut payload = [0u8; PAYLOAD_CAP];
    loop {
        let plen = wire.recv_into(stack, &mut payload)?;
        let p = &payload[..plen];
        let Some(&msg) = p.first() else {
            return Err("empty encrypted payload");
        };
        match msg {
            ssh_wire::SSH_MSG_SERVICE_REQUEST => {
                let Ok(name) = ssh_wire::parse_service_request(p) else {
                    return Err("malformed SERVICE_REQUEST");
                };
                if name != b"ssh-userauth" {
                    return Err("SERVICE_REQUEST named an unknown service");
                }
                let mut buf = [0u8; 64];
                let Some(n) = ssh_wire::service_accept_payload(b"ssh-userauth", &mut buf) else {
                    return Err("SERVICE_ACCEPT does not fit");
                };
                wire.send(stack, &buf[..n])?;
                service_accepted = true;
                // One-shot diagnostics: replay the previous session's
                // failure reason as a userauth banner (RFC4252 §5.4) —
                // OpenSSH prints it on stderr, so a remote operator
                // sees *why* the last attempt died without a screen.
                if let Some(msg) = take_fail() {
                    let mut bbuf = [0u8; 192];
                    match ssh_wire::userauth_banner_payload(msg, &mut bbuf) {
                        Some(n) => {
                            serial_println!("sshd: replaying last failure as banner");
                            if let Err(e) = wire.send(stack, &bbuf[..n]) {
                                serial_println!("sshd: banner not sent: {e}");
                            }
                        }
                        None => serial_println!("sshd: banner does not fit"),
                    }
                }
            }
            ssh_wire::SSH_MSG_USERAUTH_REQUEST => {
                if !service_accepted {
                    return Err("USERAUTH_REQUEST before the service request");
                }
                match auth_request(stack, &mut wire, p, &session_id, cfg)? {
                    AuthOutcome::Accepted => break,
                    AuthOutcome::ProbeAccepted => {}
                    AuthOutcome::Rejected => {
                        failures += 1;
                        if failures >= AUTH_ATTEMPTS_MAX {
                            return Err("too many authentication failures");
                        }
                    }
                }
            }
            other => {
                serial_println!("sshd: unexpected message {other} before authentication");
                return Err("unexpected pre-auth message");
            }
        }
    }

    // 8. S5b: one `session` channel with an `exec` request.
    channel_phase(stack, &mut wire)
}

enum AuthOutcome {
    /// A signed publickey request verified: the client is in.
    Accepted,
    /// `none`, or an unauthorized key, or a bad signature.
    Rejected,
    /// A `publickey` probe for an authorized key: `PK_OK` was sent.
    ProbeAccepted,
}

/// Handle one `SSH_MSG_USERAUTH_REQUEST` payload. Sends the answer;
/// never halts. `Ok(Rejected)` means "answered FAILURE", `Err` means
/// the payload itself was illegal (drop the connection).
fn auth_request(
    stack: &mut Stack,
    wire: &mut Conn<'_, '_>,
    payload: &[u8],
    session_id: &[u8; 32],
    cfg: &ServerConfig,
) -> Result<AuthOutcome, &'static str> {
    let req = match ssh_wire::parse_userauth_request(payload) {
        Ok(req) => req,
        Err(e) => {
            serial_println!("sshd: malformed USERAUTH_REQUEST: {e:?}");
            return Err("malformed USERAUTH_REQUEST");
        }
    };
    if req.service != ssh_wire::AUTH_SERVICE {
        return Err("USERAUTH_REQUEST named a different service");
    }

    if req.method == b"none" {
        serial_println!("sshd: auth method none refused (publickey only)");
        send_failure(stack, wire)?;
        return Ok(AuthOutcome::Rejected);
    }

    // publickey (the parser already restricted method + algorithm).
    let Ok(key) = ssh_wire::parse_ed25519_key_blob(req.key_blob) else {
        return Err("publickey request carried a malformed key blob");
    };
    if !ssh_wire::ct_eq(&key, &cfg.client_key) {
        let mut sbuf = [0u8; SANITIZE_CAP];
        let user = ssh::sanitize(req.user, &mut sbuf);
        serial_println!("sshd: user {user}: key is not in authorized_keys");
        send_failure(stack, wire)?;
        return Ok(AuthOutcome::Rejected);
    }

    if !req.has_signature {
        let mut buf = [0u8; 128];
        let Some(n) = ssh_wire::userauth_pk_ok_payload(req.key_blob, &mut buf) else {
            return Err("PK_OK does not fit its buffer");
        };
        wire.send(stack, &buf[..n])?;
        serial_println!("sshd: authorized key probe accepted (PK_OK)");
        return Ok(AuthOutcome::ProbeAccepted);
    }

    // The client signs `string session_id || request-without-signature`
    // (RFC4252 §7 — the session id is an RFC4251 `string`, so it is
    // length-prefixed). Buffers are bounded by the parser's own caps.
    let mut signed = [0u8; 4 + 32 + PAYLOAD_CAP];
    let Some(n) = ssh_wire::userauth_signed_data(session_id, req.signed_prefix, &mut signed) else {
        return Err("signed-data buffer is too small");
    };
    let Ok(sig) = ssh_wire::parse_ed25519_signature_blob(req.signature) else {
        return Err("publickey request carried a malformed signature blob");
    };
    let Ok(vk) = VerifyingKey::from_bytes(&key) else {
        return Err("authorized key is not a valid ed25519 key");
    };
    if vk
        .verify(&signed[..n], &Signature::from_bytes(&sig))
        .is_err()
    {
        serial_println!("sshd: publickey signature does not verify");
        send_failure(stack, wire)?;
        return Ok(AuthOutcome::Rejected);
    }

    let mut buf = [0u8; 8];
    let Some(n) = ssh_wire::userauth_success_payload(&mut buf) else {
        return Err("USERAUTH_SUCCESS does not fit");
    };
    wire.send(stack, &buf[..n])?;
    let mut sbuf = [0u8; SANITIZE_CAP];
    let user = ssh::sanitize(req.user, &mut sbuf);
    serial_println!("sshd: user {user}: authenticated with publickey (ssh-ed25519)");
    Ok(AuthOutcome::Accepted)
}

/// `USERAUTH_FAILURE` listing the one method we support.
fn send_failure(stack: &mut Stack, wire: &mut Conn<'_, '_>) -> Wire {
    let mut buf = [0u8; 64];
    let Some(n) = ssh_wire::userauth_failure_payload(b"publickey", false, &mut buf) else {
        return Err("USERAUTH_FAILURE does not fit");
    };
    wire.send(stack, &buf[..n])
}

/// S5b: wait for `CHANNEL_OPEN(session)`, then one `exec` request, run
/// the internal handler and send its output with EOF/exit-status/close.
fn channel_phase(stack: &mut Stack, wire: &mut Conn<'_, '_>) -> Wire {
    let mut payload = [0u8; PAYLOAD_CAP];
    let mut buf = [0u8; 512];

    // 1. Channel open.
    let plen = wire.recv_into(stack, &mut payload)?;
    let client_channel = {
        let p = &payload[..plen];
        if p.first() != Some(&ssh_wire::SSH_MSG_CHANNEL_OPEN) {
            return Err("expected CHANNEL_OPEN after authentication");
        }
        let open = match ssh_wire::parse_channel_open(p) {
            Ok(open) => open,
            Err(e) => {
                serial_println!("sshd: malformed CHANNEL_OPEN: {e:?}");
                return Err("malformed CHANNEL_OPEN");
            }
        };
        if open.channel_type != b"session" {
            return Err("CHANNEL_OPEN type is not session");
        }
        open.sender_channel
    };

    let Some(n) = ssh_wire::channel_open_confirmation_payload(
        client_channel,
        SERVER_CHANNEL,
        CHANNEL_WINDOW,
        MAX_PACKET,
        &mut buf,
    ) else {
        return Err("CHANNEL_OPEN_CONFIRMATION does not fit");
    };
    wire.send(stack, &buf[..n])?;
    serial_println!("sshd: session channel open (client channel {client_channel})");

    // 2. The exec request (window adjust/EOF before it are tolerated).
    enum Found {
        /// A non-exec request: reply with FAILURE only if asked.
        Other(bool),
        /// The `exec` request.
        Exec(bool),
    }
    let mut command = [0u8; ssh_wire::EXEC_COMMAND_MAX];
    let mut command_len = 0usize;
    let want_reply;
    loop {
        let plen = wire.recv_into(stack, &mut payload)?;
        let mut found: Option<Found> = None;
        {
            let p = &payload[..plen];
            let Some(&msg) = p.first() else {
                return Err("empty channel payload");
            };
            match msg {
                ssh_wire::SSH_MSG_CHANNEL_REQUEST => {
                    let req = match ssh_wire::parse_channel_request(p) {
                        Ok(req) => req,
                        Err(e) => {
                            serial_println!("sshd: malformed CHANNEL_REQUEST: {e:?}");
                            return Err("malformed CHANNEL_REQUEST");
                        }
                    };
                    if req.recipient_channel != SERVER_CHANNEL {
                        return Err("channel request names another channel");
                    }
                    if req.request_type != b"exec" {
                        found = Some(Found::Other(req.want_reply));
                    } else {
                        let Some(dst) = command.get_mut(..req.exec_command.len()) else {
                            return Err("exec command exceeds the handler buffer");
                        };
                        dst.copy_from_slice(req.exec_command);
                        command_len = req.exec_command.len();
                        found = Some(Found::Exec(req.want_reply));
                    }
                }
                ssh_wire::SSH_MSG_CHANNEL_WINDOW_ADJUST | ssh_wire::SSH_MSG_CHANNEL_EOF => {}
                other => {
                    serial_println!("sshd: unexpected message {other} before exec");
                    return Err("unexpected message before exec");
                }
            }
        }
        match found {
            None => {}
            Some(Found::Other(reply)) => {
                if reply {
                    let Some(n) = ssh_wire::channel_number_payload(
                        ssh_wire::SSH_MSG_CHANNEL_FAILURE,
                        SERVER_CHANNEL,
                        &mut buf,
                    ) else {
                        return Err("CHANNEL_FAILURE does not fit");
                    };
                    wire.send(stack, &buf[..n])?;
                }
            }
            Some(Found::Exec(reply)) => {
                want_reply = reply;
                break;
            }
        }
    }

    // 3. Accept the request, then run the tiny internal handler.
    if want_reply {
        let Some(n) = ssh_wire::channel_number_payload(
            ssh_wire::SSH_MSG_CHANNEL_SUCCESS,
            SERVER_CHANNEL,
            &mut buf,
        ) else {
            return Err("CHANNEL_SUCCESS does not fit");
        };
        wire.send(stack, &buf[..n])?;
    }
    let mut sbuf = [0u8; SANITIZE_CAP];
    let text = ssh::sanitize(&command[..command_len], &mut sbuf);
    serial_println!("sshd: exec request: {text}");
    let (out, out_len, status) = run_command(&command[..command_len]);

    // 4. Data, EOF, exit-status, close.
    let Some(n) = ssh_wire::channel_data_payload(SERVER_CHANNEL, &out[..out_len], &mut buf) else {
        return Err("exec output does not fit the channel data packet");
    };
    wire.send(stack, &buf[..n])?;
    let Some(n) =
        ssh_wire::channel_number_payload(ssh_wire::SSH_MSG_CHANNEL_EOF, SERVER_CHANNEL, &mut buf)
    else {
        return Err("CHANNEL_EOF does not fit");
    };
    wire.send(stack, &buf[..n])?;
    let Some(n) = ssh_wire::channel_exit_status_payload(SERVER_CHANNEL, status, &mut buf) else {
        return Err("exit-status does not fit");
    };
    wire.send(stack, &buf[..n])?;
    let Some(n) =
        ssh_wire::channel_number_payload(ssh_wire::SSH_MSG_CHANNEL_CLOSE, SERVER_CHANNEL, &mut buf)
    else {
        return Err("CHANNEL_CLOSE does not fit");
    };
    wire.send(stack, &buf[..n])?;
    serial_println!("sshd: exec status {status}, channel closing");

    // 5. Wait (bounded) for the client's close; either way we are done.
    loop {
        let plen = wire.recv_into(stack, &mut payload)?;
        let done = {
            let p = &payload[..plen];
            match p.first() {
                Some(&ssh_wire::SSH_MSG_CHANNEL_CLOSE) => true,
                Some(&ssh_wire::SSH_MSG_CHANNEL_EOF)
                | Some(&ssh_wire::SSH_MSG_CHANNEL_WINDOW_ADJUST) => false,
                _ => return Err("expected CHANNEL_CLOSE"),
            }
        };
        if done {
            return Ok(());
        }
    }
}

/// The S5b internal command handler: `echo <args>` only. A real shell
/// (pipes, builtins, git-upload-pack) is the later shell/session
/// milestone; this exists so bytes demonstrably cross the channel.
fn run_command(command: &[u8]) -> ([u8; ssh_wire::EXEC_COMMAND_MAX], usize, u32) {
    const UNKNOWN: &[u8] = b"sshd: unknown command (echo|reboot)\n";
    let mut out = [0u8; ssh_wire::EXEC_COMMAND_MAX];
    let rest = command.trim_ascii();
    if let Some(args) = rest.strip_prefix(b"echo")
        && (args.is_empty() || args[0] == b' ')
    {
        let msg = args.trim_ascii_start();
        let len = msg.len().min(out.len().saturating_sub(1));
        out[..len].copy_from_slice(&msg[..len]);
        out[len] = b'\n';
        return (out, len + 1, 0);
    }
    if rest == b"reboot" {
        // Remote recovery: the operator can always return the machine
        // to the loader's next entry (the one-shot GRUB cycle).
        serial_println!("sshd: reboot requested over ssh");
        crate::power::reboot();
    }
    let n = UNKNOWN.len().min(out.len());
    out[..n].copy_from_slice(&UNKNOWN[..n]);
    (out, n, 127)
}

fn choice(choice: Option<&'static str>) -> &'static [u8] {
    match choice {
        Some(name) => name.as_bytes(),
        None => b"(none)",
    }
}

/// Wait for the client banner. Reads through the caller's 255-byte
/// `line`, copies any bytes past its CRLF into `rx`'s front (a client
/// may pipeline its KEXINIT) and returns `(ident_len, leftover_len)` —
/// `line[..ident_len]` is the identification without CRLF, and
/// `rx[..leftover_len]` already holds the pipelined bytes.
fn recv_banner(
    stack: &mut Stack,
    handle: SocketHandle,
    line: &mut [u8; ssh_wire::BANNER_MAX],
    rx: &mut [u8],
) -> Result<(usize, usize), &'static str> {
    let mut got = 0usize;
    let deadline = clock::now_ms() + STEP_DEADLINE_MS;
    loop {
        match ssh::recv_ready(stack, handle, &mut line[got..]) {
            ssh::Chunk::Ready(n) => got += n,
            ssh::Chunk::Closed => return Err("connection closed before the client banner"),
            // Nothing queued: sleep a tick instead of spinning. The
            // deadline check below still fires on time — the clock
            // runs on IRQ0 while the CPU sleeps.
            ssh::Chunk::Idle => idle(),
        }
        match ssh_wire::decode_banner(&line[..got]) {
            ssh_wire::BannerStep::Incomplete => {}
            ssh_wire::BannerStep::Failed(e) => {
                serial_println!("sshd: bad client banner: {e:?}");
                return Err("malformed client banner");
            }
            ssh_wire::BannerStep::Done { consumed, ident } => {
                let ident_len = ident.len();
                let mut sbuf = [0u8; SANITIZE_CAP];
                let printable = ssh::sanitize(ident, &mut sbuf);
                serial_println!("sshd: client banner: {printable}");
                let leftover = got - consumed;
                let Some(dst) = rx.get_mut(..leftover) else {
                    return Err("banner leftover exceeds the receive buffer");
                };
                dst.copy_from_slice(&line[consumed..got]);
                return Ok((ident_len, leftover));
            }
        }
        if clock::now_ms() > deadline {
            return Err("timeout waiting for the client banner");
        }
    }
}

/// Drop the plaintext packet the last [`recv_plain`] returned.
fn consume_plain(rx: &mut [u8], got: &mut usize, consumed: usize) {
    rx.copy_within(consumed..*got, 0);
    *got -= consumed;
}

/// Wait for one plaintext (pre-`NEWKEYS`) packet with a per-step
/// deadline. Returns `(payload_start, payload_end, wire_len)`.
fn recv_plain(
    stack: &mut Stack,
    handle: SocketHandle,
    rx: &mut [u8],
    got: &mut usize,
) -> Result<(usize, usize, usize), &'static str> {
    let deadline = clock::now_ms() + STEP_DEADLINE_MS;
    loop {
        match ssh_wire::decode_packet_block(&rx[..*got], ssh_wire::BLOCK_SIZE) {
            ssh_wire::PacketStep::Done { consumed, payload } => {
                return Ok((5, 5 + payload.len(), consumed));
            }
            ssh_wire::PacketStep::Incomplete => {
                if *got >= rx.len() {
                    return Err("plaintext packet exceeds the receive buffer");
                }
            }
            ssh_wire::PacketStep::Failed(_) => return Err("malformed plaintext packet"),
        }
        if clock::now_ms() > deadline {
            return Err("timeout waiting for a plaintext packet");
        }
        match ssh::recv_ready(stack, handle, &mut rx[*got..]) {
            ssh::Chunk::Ready(n) => *got += n,
            ssh::Chunk::Closed => return Err("connection closed mid-handshake"),
            // No bytes this pass: sleep a tick rather than spin (the
            // deadline above keeps counting on IRQ0).
            ssh::Chunk::Idle => idle(),
        }
    }
}

/// One authenticated connection's live wire state (the server mirror
/// of `ssh::AuthWire`).
struct Conn<'a, 'b> {
    handle: SocketHandle,
    tx_dir: &'a mut ssh::Direction,
    rx_dir: &'a mut ssh::Direction,
    enc_rx: &'a mut ssh_wire::EncryptedRx<'b>,
    seq_tx: &'a mut u32,
    seq_rx: &'a mut u32,
}

impl Conn<'_, '_> {
    fn send(&mut self, stack: &mut Stack, payload: &[u8]) -> Wire {
        let mut buf = [0u8; 512];
        let Some(n) = ssh_wire::seal_packet(
            payload,
            ssh::fill_random,
            self.tx_dir,
            *self.seq_tx,
            &mut buf,
        ) else {
            return Err("sealed outgoing packet does not fit");
        };
        send_all(stack, self.handle, &buf[..n])?;
        *self.seq_tx += 1;
        Ok(())
    }

    /// Receive the next encrypted packet and copy its payload into
    /// `out` (bounded by `out.len()`), releasing the buffer before the
    /// caller parses or answers — no borrow of the socket survives into
    /// a `send`.
    fn recv_into(&mut self, stack: &mut Stack, out: &mut [u8]) -> Result<usize, &'static str> {
        let (s, e) = self.recv(stack)?;
        let bytes = self.enc_rx.bytes();
        let Some(p) = bytes.get(s..e) else {
            return Err("encrypted payload range out of bounds");
        };
        let Some(dst) = out.get_mut(..p.len()) else {
            return Err("encrypted payload exceeds the copy buffer");
        };
        dst.copy_from_slice(p);
        let len = p.len();
        self.enc_rx.consume();
        Ok(len)
    }

    /// Next encrypted packet's payload range; a MAC failure drops the
    /// connection. [`Self::recv_into`] is the normal caller.
    fn recv(&mut self, stack: &mut Stack) -> Result<(usize, usize), &'static str> {
        let deadline = clock::now_ms() + STEP_DEADLINE_MS;
        loop {
            match self.enc_rx.next(self.rx_dir, *self.seq_rx) {
                Ok(Some(range)) => {
                    *self.seq_rx += 1;
                    return Ok(range);
                }
                Ok(None) => {}
                Err(ssh_wire::OpenError::MacMismatch) => {
                    return Err("encrypted packet MAC mismatch");
                }
                Err(ssh_wire::OpenError::Full) | Err(ssh_wire::OpenError::TooLarge) => {
                    return Err("encrypted packet exceeds the receive buffer");
                }
                Err(ssh_wire::OpenError::Packet(_)) => return Err("malformed encrypted packet"),
            }
            if clock::now_ms() > deadline {
                return Err("timeout waiting for an encrypted packet");
            }
            let n = match self.enc_rx.spare() {
                Ok(space) => match ssh::recv_ready(stack, self.handle, space) {
                    ssh::Chunk::Ready(n) => Some(n),
                    ssh::Chunk::Closed => return Err("connection closed"),
                    ssh::Chunk::Idle => None,
                },
                Err(_) => return Err("receive buffer full before the packet completed"),
            };
            match n {
                // Bytes landed: loop closed, no sleep (throughput).
                Some(n) if n > 0 => self.enc_rx.commit(n),
                // `Idle` (or a 0-byte read): nothing to parse this
                // pass — sleep a tick instead of spinning. The
                // deadline above still fires on time (IRQ0 clock).
                _ => idle(),
            }
        }
    }
}

/// Frame one plaintext packet and send it.
fn send_plain(stack: &mut Stack, handle: SocketHandle, payload: &[u8]) -> Wire {
    let mut buf = [0u8; 512];
    let Some(n) =
        ssh_wire::encode_packet(payload, ssh_wire::BLOCK_SIZE, ssh::fill_random, &mut buf)
    else {
        return Err("outgoing packet does not fit");
    };
    send_all(stack, handle, &buf[..n])
}

/// Send every byte or fail (bounded).
fn send_all(stack: &mut Stack, handle: SocketHandle, data: &[u8]) -> Wire {
    let deadline = clock::now_ms() + STEP_DEADLINE_MS;
    let mut sent = 0usize;
    while sent < data.len() {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&data[sent..])
        {
            // TX buffer full (peer window shut or data still unacked):
            // no progress, so sleep a tick until the next poll's ACK
            // frees room instead of spinning. A closed connection still
            // returns `Err` here, and the deadline below bounds a
            // stalled peer either way.
            Ok(0) => idle(),
            Ok(n) => sent += n,
            Err(_) => return Err("tcp send rejected (connection lost)"),
        }
        if clock::now_ms() > deadline {
            return Err("tcp send timeout");
        }
    }
    Ok(())
}
