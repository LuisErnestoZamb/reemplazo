//! SSH milestones S2+S3 (+ S5's harness client) (docs/git-ssh-deps.md §B.4): full key exchange
//! over **one** TCP connection against `github.com:22` — banners →
//! `SSH_MSG_KEXINIT` negotiation (the smoke's `SSH_KEXINIT_OK`, at
//! the same point as S1) → `curve25519-sha256` KEX → `ssh-ed25519`
//! host-key signature verification **and pinning** → RFC4253 §7.2 key
//! derivation → `NEWKEYS` → encrypted `aes128/256-ctr` +
//! `hmac-sha2-256` → `SSH_MSG_SERVICE_REQUEST`/`ACCEPT` → a
//! `publickey`-method `none` auth probe whose
//! `SSH_MSG_USERAUTH_FAILURE` proves the whole path — the smoke's
//! `SSH_KEX_OK` — then (S3) the `publickey` exchange itself:
//! `SSH_MSG_USERAUTH_REQUEST` with an ed25519 key, first as the
//! RFC4252 §7 *probe* (boolean FALSE) and, when the server answers
//! `SSH_MSG_USERAUTH_PK_OK`, as the signed request (`session_id ||
//! probe`, ed25519) — then a clean close.
//!
//! All wire parsing/encoding lives in the `ssh-wire` crate
//! (from-scratch under dependency-policy exception (a) — justified in
//! docs/git-ssh-deps.md §B.2 and in that crate's docs; zero
//! dependencies for its shipped code, adversarially tested on the
//! host). This module drives the fourth TCP socket through the same
//! fail-closed, every-loop-bounded pattern as `netstack::plain_get_smoke`,
//! and implements [`ssh_wire::PacketProtector`] over audited
//! primitives only — SHA-256, HMAC-SHA256, AES-CTR, X25519, Ed25519
//! come from `sha2`/`hmac`/`aes`+`ctr`/`x25519-dalek`/`ed25519-dalek`
//! (§B.1, reviewed in the S2 commit); the KDF, mpint encoding, packet
//! framing and MAC composition are RFC glue, never hand-rolled crypto.
//!
//! Protocol shape (RFC4253 §8/§7.2/§6, RFC8731 §3, RFC8308):
//!
//! 1. banners: `V_C`/`V_S` are hashed **without** their CRLF (RFC4253
//!    §8: "CR and LF excluded"),
//! 2. KEXINIT exchange: `I_C`/`I_S` are the KEXINIT *payloads*
//!    (message byte included, no framing) hashed as `string`s — the
//!    exact construction OpenSSH's `kex_gen_hash` uses,
//! 3. `SSH_MSG_KEXDH_INIT` (our 32-byte X25519 public) →
//!    `SSH_MSG_KEXDH_REPLY` (`K_S`, `f`, signature), with `f` length-
//!    checked and the shared secret checked for all-zero (RFC8731 §3),
//! 4. `H = SHA256(string(V_C) || string(V_S) || string(I_C) ||
//!    string(I_S) || string(K_S) || string(e) || string(f) || mpint(K))`
//!    (e/f as `string`s per RFC8731, K as `mpint` per RFC8731 §3.1),
//! 5. verify the ed25519 signature over `H`, then pin the raw key
//!    against [`GITHUB_ED25519_KEY`] — both fail-closed,
//! 6. RFC4253 §7.2 KDF → IVs/keys/MAC keys; sequence numbers are
//!    per-direction and never reset (§6.4),
//! 7. `SSH_MSG_NEWKEYS` both ways (plaintext), then every packet is
//!    sealed: MAC over the *plaintext* packet with the sequence
//!    number, AES-CTR keystream continuous across packets (§6.3),
//! 8. tolerate `SSH_MSG_EXT_INFO` (RFC8308 — we offer `ext-info-c`),
//!    then service request/accept and the `none` auth probe,
//! 9. S3: the `publickey` probe with a per-boot ed25519 key (see
//!    [`AuthKey`]) — GitHub answers `USERAUTH_FAILURE` because that
//!    key is not registered anywhere, which is the expected boot
//!    outcome and still exercises the full request/blob/framing path;
//!    a registered key gets `USERAUTH_PK_OK`, the signed request goes
//!    out, and `USERAUTH_SUCCESS` follows (the same code path the
//!    manual `ssh-auth` builtin drives with a real key).
//!
//! S5 adds the **client half of the two-VM sshd proof**:
//! [`probe_server`] dials a peer `sshd` at the slirp gateway
//! (`10.0.2.2:2222`, QEMU `hostfwd`), trusts that peer's host key
//! **for the session only** (TOFU — the signature is verified against
//! the presented key and the key plus its SHA-256 fingerprint are
//! printed, but nothing is persisted), authenticates with the seed on
//! this VM's disk and execs one command on a `session` channel,
//! printing `SSHD_OK` and `SSHD_EXEC_OK` when the bytes come back.
//! A persisted `known_hosts` and the "host key changed" warning need
//! the filesystem milestone.
//!
//! Refused lines/packets/MACs print `FATAL: ssh: …` and halt: an SSH
//! client that skips a malformed byte — or accepts a bad tag — is a
//! client that lies about what the server said. Key material (the
//! shared secret `K`, every derived key, the private scalar, the
//! ed25519 seed) is never printed or logged; only public blobs and
//! their SHA-256 fingerprints are.

use crate::clock;
use crate::netstack::{OP_DEADLINE_MS, Stack};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes256};
use core::ptr::addr_of_mut;
use ctr::Ctr128BE;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;
use ssh_wire::PacketProtector;
use x25519_dalek::{PublicKey, StaticSecret};

/// Local port of the SSH connection: a socket in TIME-WAIT cannot be
/// reused for 10 s, so every sequential connection owns a port (plain
/// HTTP 49152, robots TLS 49160, git TLS 49161, ssh 49162).
const LOCAL_PORT: u16 = 49162;
/// The IANA `ssh` port.
const REMOTE_PORT: u16 = 22;
/// The sshd harness' guest-side listener port (S5).
const SSHD_PROBE_PORT: u16 = 2222;
/// Local port of the S5 probe connection: its own socket (TIME-WAIT),
/// like every sequential connection here.
const PROBE_LOCAL_PORT: u16 = 49167;
/// How long the S5 probe keeps retrying while the peer VM's sshd is
/// still booting (`cargo xtask smoke-ssh` starts both VMs at once).
const PROBE_RETRY_MS: u64 = 20_000;
/// Receive buffer for the whole connection: every server packet
/// (plaintext or encrypted) is accumulated here, bounded — GitHub's
/// packets are all well under 1 KiB, a declared packet that could not
/// fit (plus its 32-byte tag) is refused from the header alone, and
/// `Incomplete` at a full buffer is fatal, never an unbounded read.
const RX_CAP: usize = 4096;
/// Wire bytes reaching the log are copied through this as printable
/// ASCII first (same log-injection reasoning as `git.rs::sanitize`).
const SANITIZE_CAP: usize = 200;
/// How many `SSH_MSG_USERAUTH_BANNER` packets an auth step tolerates
/// before the real answer (RFC4252 §5.4 has no limit; a server that
/// sends more than this is not answering).
const AUTH_BANNER_MAX: usize = 4;

/// Single-use connection receive buffer (the `READ_STORAGE` idiom:
/// written once by `kex_smoke` on a single core; IRQ0 never touches
/// it).
static mut RX: [u8; RX_CAP] = [0; RX_CAP];

/// github.com's pinned `ssh-ed25519` host key (raw 32 bytes).
///
/// Obtained 2026-11-21 from two independent sources that agree:
/// - `ssh-keyscan -t ed25519 github.com` → blob
///   `AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl`
///   (51-byte blob = `string "ssh-ed25519" || string` key), whose
///   SHA256 fingerprint I computed myself (base64, no padding):
///   `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` — matching
///   both `ssh-keygen -lf` on the scan and
/// - GitHub's published fingerprints page
///   (docs.github.com/…/githubs-ssh-key-fingerprints), which lists the
///   identical `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`
///   (Ed25519) **and** the identical known_hosts line.
///
/// Key rotation fails the smoke loudly — the same class of fail-closed
/// check as the TLS root pin (`tls::usertrust_ecc_ca.der`). Generic
/// TOFU/`known_hosts` needs the filesystem milestone (`ssh-key`
/// parsing is S3, post-heap).
const GITHUB_ED25519_KEY: [u8; 32] = [
    0xe3, 0x2a, 0xaa, 0x79, 0x15, 0xce, 0xb9, 0xb4, 0x49, 0xd1, 0xba, 0x50, 0xea, 0x2a, 0x28, 0xbb,
    0x1a, 0x6e, 0x01, 0xf9, 0x0b, 0xda, 0x24, 0x5a, 0x2d, 0x1d, 0x87, 0x69, 0x7d, 0x18, 0xa2, 0x65,
];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: ssh: {msg}");
    crate::halt()
}

/// Copy `bytes` into `buf` as printable ASCII, returning the str —
/// raw wire bytes never reach the serial log (or the VGA mirror).
pub(crate) fn sanitize<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
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
pub(crate) enum Chunk {
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
pub(crate) fn recv_ready(stack: &mut Stack, handle: SocketHandle, dst: &mut [u8]) -> Chunk {
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

/// Random padding for outgoing packets, drawn from the kernel CSPRNG
/// (RFC4253 §6: padding "SHOULD be random" — a hard requirement once
/// it rides inside the ciphertext). S1's KEXINIT encoder still
/// zero-fills: that packet is plaintext and carries no secrets.
pub(crate) fn fill_random(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(4) {
        let word = crate::entropy::boot_entropy().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}

/// Feed `bytes` into the exchange hash as an RFC4251 `string`
/// (uint32 length prefix + bytes). The impossible length overflow is
/// fail-closed — never an unwrap.
pub(crate) fn hash_string(hasher: &mut Sha256, bytes: &[u8]) {
    let Ok(n) = u32::try_from(bytes.len()) else {
        fatal("string too long for the exchange hash");
    };
    hasher.update(n.to_be_bytes());
    hasher.update(bytes);
}

/// One negotiated cipher direction as AES-CTR: the keystream object
/// (continuous across packets — RFC4253 §6.3 says IVs pass from one
/// packet to the next, so it is never re-created per packet) plus the
/// HMAC-SHA256 key. `aes128-ctr` and `aes256-ctr` are both negotiable
/// (§B.3), hence the two arms.
pub(crate) enum AesCtr {
    C128(Ctr128BE<Aes128>),
    C256(Ctr128BE<Aes256>),
}

impl AesCtr {
    fn new(key: &[u8], iv: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Ctr128BE::<Aes128>::new_from_slices(key, iv)
                .ok()
                .map(Self::C128),
            32 => Ctr128BE::<Aes256>::new_from_slices(key, iv)
                .ok()
                .map(Self::C256),
            _ => None,
        }
    }

    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::C128(c) => c.apply_keystream(buf),
            Self::C256(c) => c.apply_keystream(buf),
        }
    }
}

/// One direction's live keys (RFC4253 §7.2 output + §6.4 MAC).
pub(crate) struct Direction {
    ctr: AesCtr,
    mac_key: [u8; 32],
}

/// Build a [`Direction`] from its derived key/IV, or `fatal` — every
/// length here comes from our own KDF, so a rejection is a bug, not a
/// wire condition, but it still halts instead of unwrapping.
pub(crate) fn direction(key: &[u8], iv: &[u8], mac_key: [u8; 32]) -> Direction {
    let ctr = match AesCtr::new(key, iv) {
        Some(ctr) => ctr,
        None => fatal("AES-CTR rejected the derived key/IV length"),
    };
    Direction { ctr, mac_key }
}

impl PacketProtector for Direction {
    fn block_size(&self) -> usize {
        ssh_wire::ENC_BLOCK
    }

    fn open(&mut self, buf: &mut [u8]) {
        self.ctr.apply(buf);
    }

    fn seal(&mut self, buf: &mut [u8]) {
        self.ctr.apply(buf);
    }

    fn tag(&mut self, seq: u32, packet: &[u8]) -> [u8; ssh_wire::TAG_LEN] {
        // RFC4253 §6.4: MAC(key, sequence_number || unencrypted_packet).
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.mac_key) {
            Ok(mac) => mac,
            Err(_) => fatal("HMAC-SHA256 rejected the derived MAC key"),
        };
        mac.update(&seq.to_be_bytes());
        mac.update(packet);
        mac.finalize().into_bytes().into()
    }
}

/// Every key material byte from one key exchange, plus the negotiated
/// per-direction cipher-key lengths (`aes128-ctr` = 16,
/// `aes256-ctr` = 32; IVs are always the 16-byte AES block, MAC keys
/// always the 32-byte HMAC-SHA256 output).
pub(crate) struct Derived {
    pub(crate) iv_c2s: [u8; 16],
    pub(crate) iv_s2c: [u8; 16],
    pub(crate) key_c2s: [u8; 32],
    pub(crate) key_s2c: [u8; 32],
    pub(crate) mac_c2s: [u8; 32],
    pub(crate) mac_s2c: [u8; 32],
    pub(crate) key_len_c2s: usize,
    pub(crate) key_len_s2c: usize,
}

/// RFC4253 §7.2 with `HASH = SHA-256`, fed to the audited `sha2`
/// crate — the glue (mpint(K) || H || X || session_id chaining) is
/// `ssh_wire::kdf`, tested against a known-answer vector on the host.
fn kdf_or_fatal(letter: u8, k: &[u8], h: &[u8], out: &mut [u8]) {
    let hash = |data: &[u8]| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };
    if let Err(e) = ssh_wire::kdf(hash, k, h, letter, h, out) {
        serial_println!("ssh: key derivation refused: {e:?}");
        crate::halt();
    }
}

/// The same derivation without the client's halt policy, so the
/// server (which drops a connection instead of dying) can share it.
/// A refusal here can only be a bug on our side — every input comes
/// from our own KDF call sites.
pub(crate) fn kdf_checked(
    letter: u8,
    k: &[u8],
    h: &[u8],
    out: &mut [u8],
) -> Result<(), ssh_wire::KdfError> {
    let hash = |data: &[u8]| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };
    ssh_wire::kdf(hash, k, h, letter, h, out)
}

/// Wait for the next **plaintext** (pre-`NEWKEYS`) packet; returns the
/// payload's range in `rx` and the packet's total wire length. The
/// caller parses inside the borrow, then calls [`consume_plain`].
/// Every read is deadline-bounded and split-tolerant (smoltcp hands
/// over whatever is ready).
fn recv_plain(
    stack: &mut Stack,
    handle: SocketHandle,
    rx: &mut [u8],
    got: &mut usize,
    block: usize,
) -> (usize, usize, usize) {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        match ssh_wire::decode_packet_block(&rx[..*got], block) {
            ssh_wire::PacketStep::Done { consumed, payload } => {
                // The packet always sits at the buffer front: every
                // consume shifts the remainder down (payload follows
                // the 4-byte length + padding_length byte).
                return (5, 5 + payload.len(), consumed);
            }
            ssh_wire::PacketStep::Incomplete => {
                if *got >= rx.len() {
                    fatal("server packet exceeds the receive buffer");
                }
            }
            ssh_wire::PacketStep::Failed(e) => {
                serial_println!("ssh: bad server packet: {e:?}");
                crate::halt();
            }
        }
        if clock::now_ms() > deadline {
            fatal("timeout waiting for a server packet");
        }
        match recv_ready(stack, handle, &mut rx[*got..]) {
            Chunk::Ready(n) => *got += n,
            Chunk::Closed => fatal("connection closed while waiting for a server packet"),
            Chunk::Idle => {}
        }
    }
}

/// Drop the plaintext packet [`recv_plain`] just returned.
fn consume_plain(rx: &mut [u8], got: &mut usize, consumed: usize) {
    rx.copy_within(consumed..*got, 0);
    *got -= consumed;
}

/// Wait for the next **encrypted** packet: decrypts up to the
/// ciphertext boundary as bytes arrive, verifies the MAC over the
/// plaintext with `seq`, and returns the payload's range in
/// `enc_rx.bytes()` — read it, then call `enc_rx.consume()`. Refusals
/// are fail-closed (`FATAL: ssh: …` + halt): a bad MAC, a hostile
/// declared length, a full buffer, a timeout.
fn recv_enc(
    stack: &mut Stack,
    handle: SocketHandle,
    enc_rx: &mut ssh_wire::EncryptedRx<'_>,
    dir: &mut Direction,
    seq: u32,
) -> (usize, usize) {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        match enc_rx.next(dir, seq) {
            Ok(Some(range)) => return range,
            Ok(None) => {}
            Err(ssh_wire::OpenError::Packet(e)) => {
                serial_println!("ssh: bad encrypted packet: {e:?}");
                crate::halt();
            }
            Err(ssh_wire::OpenError::MacMismatch) => {
                fatal("encrypted packet MAC verification failed")
            }
            Err(ssh_wire::OpenError::Full) | Err(ssh_wire::OpenError::TooLarge) => {
                fatal("encrypted packet exceeds the receive buffer")
            }
        }
        if clock::now_ms() > deadline {
            fatal("timeout waiting for an encrypted packet");
        }
        // Read more into the free space — the borrow of `enc_rx`
        // ends with this statement, before `commit` takes it again.
        let n = match enc_rx.spare() {
            Ok(space) => match recv_ready(stack, handle, space) {
                Chunk::Ready(n) => Some(n),
                Chunk::Closed => fatal("connection closed while waiting for an encrypted packet"),
                Chunk::Idle => None,
            },
            Err(_) => fatal("receive buffer full before the packet completed"),
        };
        if let Some(n) = n {
            enc_rx.commit(n);
        }
    }
}

/// Frame `payload` (random padding) for the plaintext phase and send
/// it — `SSH_MSG_KEXDH_INIT`, `SSH_MSG_NEWKEYS`.
fn send_plain(stack: &mut Stack, handle: SocketHandle, payload: &[u8], block: usize) {
    let mut buf = [0u8; 512];
    let Some(n) = ssh_wire::encode_packet(payload, block, fill_random, &mut buf) else {
        fatal("outgoing packet does not fit the transmit buffer");
    };
    send_all(stack, handle, &buf[..n]);
}

/// Seal `payload` for the encrypted phase (frame → MAC the plaintext
/// with `seq` → AES-CTR → append the tag) and send it.
fn send_sealed(
    stack: &mut Stack,
    handle: SocketHandle,
    payload: &[u8],
    dir: &mut Direction,
    seq: u32,
) {
    let mut buf = [0u8; 512];
    let Some(n) = ssh_wire::seal_packet(payload, fill_random, dir, seq, &mut buf) else {
        fatal("sealed outgoing packet does not fit the transmit buffer");
    };
    send_all(stack, handle, &buf[..n]);
}

/// Parse and record an `SSH_MSG_EXT_INFO` (RFC8308): `server-sig-algs`
/// is printed sanitized (values are wire bytes — log-injection rules
/// apply); other extensions are counted, never logged raw. The count
/// and every string are bounded by `ssh-wire`'s parser.
fn handle_ext_info(payload: &[u8]) {
    let mut info = match ssh_wire::parse_ext_info(payload) {
        Ok(info) => info,
        Err(e) => {
            serial_println!("ssh: malformed EXT_INFO: {e:?}");
            crate::halt();
        }
    };
    let mut buf = [0u8; SANITIZE_CAP];
    loop {
        match info.next_entry() {
            Ok(Some((name, value))) => {
                if name == b"server-sig-algs" {
                    // Sanitize before the macro: serial macros
                    // evaluate their arguments twice.
                    let v = sanitize(value, &mut buf);
                    serial_println!("ssh: ext-info server-sig-algs: {v}");
                }
            }
            Ok(None) => break,
            Err(e) => {
                serial_println!("ssh: malformed EXT_INFO entry: {e:?}");
                crate::halt();
            }
        }
    }
    if let Err(e) = info.finish() {
        serial_println!("ssh: malformed EXT_INFO trailer: {e:?}");
        crate::halt();
    }
}

/// SSH S2/S3: one connection, every phase bounded, every refusal fatal.
/// Prints `SSH_KEXINIT_OK` at the S1 point (negotiation agreed) and
/// `SSH_KEX_OK` once the `none` auth probe has come back as
/// `SSH_MSG_USERAUTH_FAILURE` over the encrypted channel — then runs
/// the S3 `publickey` exchange and closes. The boot smoke's key is
/// ephemeral, so the auth verdict is `USERAUTH_FAILURE` (see
/// [`AuthKey`]); the manual `ssh-auth` path passes a real seed.
pub fn kex_smoke(stack: &mut Stack, ip: Ipv4Address) {
    let ep = Endpoint::github(ip, stack.tcp4_handle);
    if let Err(e) = connect(stack, &ep) {
        fatal(e);
    }
    session(stack, &ep, AuthKey::Ephemeral, true, None)
}

/// Manual S3 path (`ssh-auth <seed>` in the shell): authenticate to
/// github.com with an operator-supplied ed25519 seed. Same code as the
/// boot path — the only differences are where the seed comes from and
/// that no smoke markers are printed. A successful run prints
/// `ssh: authenticated with publickey (ssh-ed25519)` and closes the
/// connection (the session channel / `exec` is S4).
///
/// Fail-soft entry points only (no DNS answer → one line, return); the
/// wire phases keep S2's fail-closed `FATAL` behaviour.
pub fn auth_cmd(stack: &mut Stack, seed: [u8; 32]) {
    let Some(ip) = stack.resolve("github.com") else {
        serial_println!("ssh-auth: no DNS answer for github.com (network up?)");
        return;
    };
    let ep = Endpoint::github(ip, stack.tcp4_handle);
    if let Err(e) = connect(stack, &ep) {
        serial_println!(
            "ssh-auth: {e} (a previous connection may still be in TIME-WAIT, retry in ~10 s)"
        );
        return;
    }
    session(stack, &ep, AuthKey::Seed(seed), false, None);
}

/// The SSH server proof harness' client (docs/git-ssh-deps.md §B.4 row
/// S5): connect to the peer VM's sshd at the slirp gateway
/// (`10.0.2.2:2222` — QEMU's `hostfwd` on the container loopback
/// forwards it to the server VM's guest :2222), authenticate with the
/// key on this VM's disk, `exec echo SSHD_EXEC_OK` and print the
/// returned bytes. Prints `SSHD_OK` once authenticated and
/// `SSHD_EXEC_OK` once the exec output came back intact — the
/// `cargo xtask smoke-ssh` markers.
///
/// Connect is **retried** for up to [`PROBE_RETRY_MS`]: both VMs boot
/// concurrently, so the server may still be a few seconds away from
/// `listen()`. Everything after the TCP handshake keeps S2/S3's
/// fail-closed `FATAL` policy — a broken handshake must fail the
/// smoke loudly, not be retried.
pub fn probe_server(stack: &mut Stack, seed: [u8; 32]) {
    let ep = Endpoint::loopback_sshd(stack.tcp9_handle);
    let deadline = clock::now_ms() + PROBE_RETRY_MS;
    loop {
        match connect(stack, &ep) {
            Ok(()) => break,
            Err(e) => {
                if clock::now_ms() > deadline {
                    serial_println!("sshd-probe: {e} (peer sshd never came up)");
                    fatal("timeout connecting to the peer sshd");
                }
                serial_println!("sshd-probe: {e}; retrying");
                // Bounded: the retry loop is the whole point of the
                // deadline above. A short pause keeps the log readable.
                let pause = clock::now_ms() + 500;
                while clock::now_ms() < pause {
                    stack.poll();
                }
            }
        }
    }
    session(
        stack,
        &ep,
        AuthKey::Seed(seed),
        false,
        Some(b"echo SSHD_EXEC_OK"),
    );
}

/// Where a session connects and what host-key policy it applies. The
/// boot/manual GitHub paths pin; only the two-VM sshd harness accepts a
/// key it has never seen (see [`HostKey::Tofu`]).
struct Endpoint {
    ip: Ipv4Address,
    port: u16,
    local_port: u16,
    host_key: HostKey,
    handle: SocketHandle,
}

/// Host-key policy for one connection.
enum HostKey {
    /// The raw ed25519 key must equal this pin (github.com).
    Pinned([u8; 32]),
    /// Trust-on-first-use **for this session only**: the signature is
    /// verified against the key the server presented (so the peer
    /// proved possession of the private half), the key and its
    /// fingerprint are printed so the operator sees what was trusted,
    /// and nothing is persisted. A `known_hosts` file plus the
    /// "host key changed!" warning needs the filesystem milestone —
    /// see docs/git-ssh-deps.md §B.4 row S5.
    Tofu,
}

impl Endpoint {
    fn github(ip: Ipv4Address, handle: SocketHandle) -> Self {
        Endpoint {
            ip,
            port: REMOTE_PORT,
            local_port: LOCAL_PORT,
            host_key: HostKey::Pinned(GITHUB_ED25519_KEY),
            handle,
        }
    }

    /// The sshd harness peer: QEMU's slirp gateway is the container's
    /// loopback, where the server VM's `hostfwd` listens on :2222.
    fn loopback_sshd(handle: SocketHandle) -> Self {
        Endpoint {
            ip: Ipv4Address::new(
                net::SLIRP_GATEWAY[0],
                net::SLIRP_GATEWAY[1],
                net::SLIRP_GATEWAY[2],
                net::SLIRP_GATEWAY[3],
            ),
            port: SSHD_PROBE_PORT,
            local_port: PROBE_LOCAL_PORT,
            host_key: HostKey::Tofu,
            handle,
        }
    }
}

/// Once per connect attempt: reset a stale socket, dial and wait for
/// `Established`. Every failure is a bounded, printable reason — the
/// caller decides whether that is fatal (boot/manual) or retryable
/// (the two-VM probe).
fn connect(stack: &mut Stack, ep: &Endpoint) -> Result<(), &'static str> {
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(ep.handle);
        if sock.is_open() {
            sock.abort(); // RST: no TIME-WAIT, so the retry is immediate
        }
        if sock
            .connect(stack.iface.context(), (ep.ip, ep.port), ep.local_port)
            .is_err()
        {
            return Err("tcp connect rejected (local port busy?)");
        }
    }
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        match stack.sockets.get::<tcp::Socket>(ep.handle).state() {
            tcp::State::Established => {
                serial_println!("ssh: connected to {}:{}", ep.ip, ep.port);
                return Ok(());
            }
            tcp::State::Closed if clock::now_ms() + 50 < deadline => {
                // A RST (peer not listening yet) closes the socket;
                // report it rather than spin to the deadline.
                return Err("tcp connection reset before establishment");
            }
            _ => {}
        }
        if clock::now_ms() > deadline {
            return Err("tcp connect timeout");
        }
    }
}

/// Where the ed25519 seed for the S3 `publickey` exchange comes from.
///
/// - [`AuthKey::Ephemeral`] (the boot path): a fresh key per boot from
///   the kernel CSPRNG. It is deliberately **not** registered on
///   GitHub, so GitHub answers `SSH_MSG_USERAUTH_FAILURE` — the
///   expected, non-fatal verdict that still proves the request
///   encoding, the blob shapes and the encrypted framing on every
///   boot.
/// - [`AuthKey::Seed`] (the manual `ssh-auth` builtin): a real key
///   whose public half is registered on the account. GitHub then
///   answers `SSH_MSG_USERAUTH_PK_OK`, the signed request
///   (`session_id || probe`, ed25519 per RFC4252 §7) goes out, and
///   `SSH_MSG_USERAUTH_SUCCESS` follows — the *same* code path, which
///   is how full end-to-end auth is verified without embedding any
///   secret in this repository.
///
/// The seed is secret key material: it is copied into a `SigningKey`
/// and the local copy is scrubbed best-effort (a dead store LLVM is
/// free to elide — the real guarantee is what *does* hold: the seed is
/// never printed, formatted, hashed into a log line or stored anywhere
/// outside the `SigningKey`).
enum AuthKey {
    Ephemeral,
    Seed([u8; 32]),
}

fn session(stack: &mut Stack, ep: &Endpoint, keys: AuthKey, markers: bool, exec: Option<&[u8]>) {
    let handle = ep.handle;

    // SAFETY: single-use static (see `RX`); single core and the IRQ0
    // handler never touch it.
    let rx = unsafe { &mut *addr_of_mut!(RX) };
    let mut got = 0usize;

    // 2. Our banner first (RFC4253 §4.2), then the server's line into
    //    the 255-byte bound, CRLF included.
    send_all(stack, handle, ssh_wire::OUR_BANNER);
    let mut line = [0u8; ssh_wire::BANNER_MAX];
    let mut line_got = 0usize;
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let (consumed, ident) = loop {
        match recv_ready(stack, handle, &mut line[line_got..]) {
            Chunk::Ready(n) => line_got += n,
            Chunk::Closed => fatal("connection closed before the server banner"),
            Chunk::Idle => {}
        }
        match ssh_wire::decode_banner(&line[..line_got]) {
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
    let mut sbuf = [0u8; SANITIZE_CAP];
    let banner = sanitize(ident, &mut sbuf);
    serial_println!("ssh: server: {banner}");

    // Exchange-hash prefix: V_C/V_S as `string`s, **without** their
    // CRLF (RFC4253 §8: "CR and LF excluded").
    let mut xh = Sha256::new();
    let v_c = ssh_wire::OUR_BANNER
        .strip_suffix(b"\r\n")
        .unwrap_or(ssh_wire::OUR_BANNER);
    hash_string(&mut xh, v_c);
    hash_string(&mut xh, ident);

    // Bytes past the CRLF may already hold the server's KEXINIT (a
    // server may pipeline banner + first packet) — keep them.
    let leftover = line_got - consumed;
    if leftover > 0 {
        rx[..leftover].copy_from_slice(&line[consumed..line_got]);
        got = leftover;
    }

    // Sequence numbers: per-direction, starting at zero for each
    // side's first packet, incremented after every packet regardless
    // of encryption (RFC4253 §6.4) — never reset, never shared.
    let mut seq_tx = 0u32;
    let mut seq_rx = 0u32;

    // 3. Our KEXINIT — cookie from the CSPRNG (RFC4253 §7.1 "RANDOM
    //    values"; never zeros — see entropy.rs).
    let mut cookie = [0u8; 16];
    for word in cookie.chunks_mut(4) {
        word.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
    }
    let mut wire = [0u8; ssh_wire::KEXINIT_WIRE_MAX];
    let Some(wire_len) = ssh_wire::encode_kexinit(&cookie, &mut wire) else {
        fatal("our KEXINIT does not fit the buffer");
    };
    // I_C = the entire KEXINIT payload as sent (message byte included,
    // no framing) — hashed as a `string`, exactly like OpenSSH's
    // `kex_gen_hash` "fake header" (RFC4253 §8: "the payload of the
    // client's SSH_MSG_KEXINIT").
    match ssh_wire::decode_packet(&wire[..wire_len]) {
        ssh_wire::PacketStep::Done { payload, .. } => hash_string(&mut xh, payload),
        _ => fatal("our KEXINIT does not decode (encoder bug)"),
    }
    send_all(stack, handle, &wire[..wire_len]);
    seq_tx += 1;

    // 4. The server's KEXINIT: accumulate (smoltcp hands us whatever
    //    is ready), validate framing on every step, hash I_S, then
    //    intersect per RFC4253 §7.1 — refuse to continue unless every
    //    §B.3 must-have was agreed (`FATAL`, never "continue anyway").
    let (s, e, consumed) = recv_plain(stack, handle, rx, &mut got, ssh_wire::BLOCK_SIZE);
    let negotiated = {
        let Some(payload) = rx.get(s..e) else {
            fatal("server KEXINIT payload range out of bounds");
        };
        hash_string(&mut xh, payload);
        let server = match ssh_wire::parse_kexinit(payload) {
            Ok(k) => k,
            Err(err) => {
                serial_println!("ssh: malformed KEXINIT: {err:?}");
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
        // Print the agreed algorithms — sanitize into stack buffers
        // first (side-effect-free macro arguments, log-injection guard).
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
        negotiated
    };
    consume_plain(rx, &mut got, consumed);
    seq_rx += 1;

    if markers {
        // machine-checked by `cargo xtask smoke`
        serial_println!("SSH_KEXINIT_OK");
    }

    // 5. SSH_MSG_KEXDH_INIT: a fresh X25519 keypair per connection
    //    from the boot CSPRNG (32 bytes = 8 draws — never
    //    `random_from_rng`, which would drag in rand_core feature/
    //    version juggling; docs §B.1).
    let mut priv_bytes = [0u8; 32];
    for chunk in priv_bytes.chunks_mut(4) {
        chunk.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
    }
    let secret = StaticSecret::from(priv_bytes);
    let e_bytes = *PublicKey::from(&secret).as_bytes();
    let mut payload = [0u8; 64];
    let Some(plen) = ssh_wire::kexdh_init_payload(&e_bytes, &mut payload) else {
        fatal("KEXDH_INIT does not fit the buffer");
    };
    send_plain(stack, handle, &payload[..plen], ssh_wire::BLOCK_SIZE);
    seq_tx += 1;

    // 6. SSH_MSG_KEXDH_REPLY: parse + DH + finish H + verify the
    //    signature + pin the host key + derive every key, all while
    //    the reply payload is borrowed.
    let key_len_c2s = match negotiated.enc_c2s {
        Some("aes256-ctr") => 32usize,
        _ => 16,
    };
    let key_len_s2c = match negotiated.enc_s2c {
        Some("aes256-ctr") => 32usize,
        _ => 16,
    };
    let (s, e, consumed) = recv_plain(stack, handle, rx, &mut got, ssh_wire::BLOCK_SIZE);
    let (derived, session_id) = {
        let Some(payload) = rx.get(s..e) else {
            fatal("KEXDH_REPLY payload range out of bounds");
        };
        let reply = match ssh_wire::parse_kexdh_reply(payload) {
            Ok(r) => r,
            Err(err) => {
                serial_println!("ssh: malformed KEXDH_REPLY: {err:?}");
                crate::halt();
            }
        };
        // Lengths were validated by the parser (32/32/64); the
        // conversions are still checked, never unwrapped.
        let Ok(f_arr) = <[u8; 32]>::try_from(reply.f) else {
            fatal("server public value is not 32 bytes");
        };
        let Ok(hk_arr) = <[u8; 32]>::try_from(reply.host_key_bytes) else {
            fatal("server host key is not 32 bytes");
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(reply.signature_bytes) else {
            fatal("server signature is not 64 bytes");
        };

        // X25519 with the audited dalek crate; RFC8731 §3: abort on
        // an all-zero shared secret (small-order server value).
        let shared = secret.diffie_hellman(&PublicKey::from(f_arr));
        if ssh_wire::ct_eq(shared.as_bytes(), &[0u8; 32]) {
            fatal("all-zero shared secret (small-order server value)");
        }

        // H = SHA256(string(V_C) || string(V_S) || string(I_C) ||
        //     string(I_S) || string(K_S) || string(e) || string(f) ||
        //     mpint(K)) — V_* and I_* were hashed during the phases
        //     above; e/f are `string`s (RFC8731), K is `mpint`
        //     (RFC8731 §3.1: big-endian, high bit handled).
        hash_string(&mut xh, reply.host_key);
        hash_string(&mut xh, &e_bytes);
        hash_string(&mut xh, reply.f);
        let mut kbuf = [0u8; 40];
        let Some(klen) = ssh_wire::encode_mpint(shared.as_bytes(), &mut kbuf) else {
            fatal("shared secret does not fit the mpint buffer");
        };
        xh.update(&kbuf[..klen]);
        let h: [u8; 32] = xh.finalize().into();

        // Host-key verification first, then pinning — both
        // fail-closed. The signature is over H itself (Ed25519
        // signs the message directly; RFC4253 §8).
        let vk = match VerifyingKey::from_bytes(&hk_arr) {
            Ok(vk) => vk,
            Err(_) => fatal("server host key is not a valid ed25519 key"),
        };
        if vk.verify(&h, &Signature::from_bytes(&sig_arr)).is_err() {
            fatal("host key signature does not verify over the exchange hash");
        }
        match ep.host_key {
            HostKey::Pinned(key) => {
                if hk_arr != key {
                    fatal("server host key does not match the pinned github.com key");
                }
                serial_println!("ssh: host key verified (ssh-ed25519, pinned)");
            }
            HostKey::Tofu => {
                // The signature was verified against the presented
                // key, so the peer proved possession of the private
                // half. Print what we accepted — never persist it.
                serial_println!("ssh: host key verified (ssh-ed25519, TOFU)");
                print_public_key("ssh: TOFU host key (session only)", reply.host_key);
            }
        }

        // RFC4253 §7.2: six derivations, session_id = H for the
        // first (only) key set.
        let k = shared.as_bytes();
        let mut d = Derived {
            iv_c2s: [0; 16],
            iv_s2c: [0; 16],
            key_c2s: [0; 32],
            key_s2c: [0; 32],
            mac_c2s: [0; 32],
            mac_s2c: [0; 32],
            key_len_c2s,
            key_len_s2c,
        };
        kdf_or_fatal(b'A', k, &h, &mut d.iv_c2s);
        kdf_or_fatal(b'B', k, &h, &mut d.iv_s2c);
        kdf_or_fatal(b'C', k, &h, &mut d.key_c2s[..key_len_c2s]);
        kdf_or_fatal(b'D', k, &h, &mut d.key_s2c[..key_len_s2c]);
        kdf_or_fatal(b'E', k, &h, &mut d.mac_c2s);
        kdf_or_fatal(b'F', k, &h, &mut d.mac_s2c);
        (d, h)
    };
    consume_plain(rx, &mut got, consumed);
    seq_rx += 1;

    // 7. NEWKEYS both ways: ours goes out plaintext and everything
    //    after it is sealed (RFC4253 §7.3); the server's arrives
    //    plaintext and flips the receive side. Whatever bytes follow
    //    it in the buffer (a pipelined encrypted EXT_INFO) stay
    //    undecrypted — `EncryptedRx` picks them up from offset zero.
    send_plain(
        stack,
        handle,
        &[ssh_wire::SSH_MSG_NEWKEYS],
        ssh_wire::BLOCK_SIZE,
    );
    seq_tx += 1;
    let (s, e, consumed) = recv_plain(stack, handle, rx, &mut got, ssh_wire::BLOCK_SIZE);
    {
        let Some(payload) = rx.get(s..e) else {
            fatal("NEWKEYS payload range out of bounds");
        };
        if payload.len() != 1 || payload.first() != Some(&ssh_wire::SSH_MSG_NEWKEYS) {
            serial_println!("ssh: expected a bare SSH_MSG_NEWKEYS from the server");
            crate::halt();
        }
    }
    consume_plain(rx, &mut got, consumed);
    seq_rx += 1;

    // Keys live from each side's NEWKEYS on — ours already went out,
    // the server's just arrived.
    let mut tx_dir = direction(
        &derived.key_c2s[..derived.key_len_c2s],
        &derived.iv_c2s,
        derived.mac_c2s,
    );
    let mut rx_dir = direction(
        &derived.key_s2c[..derived.key_len_s2c],
        &derived.iv_s2c,
        derived.mac_s2c,
    );
    let mut enc_rx = ssh_wire::EncryptedRx::new(&mut rx[..], got);

    // 8. Encrypted SSH_MSG_SERVICE_REQUEST → expect (possibly after
    //    an RFC8308 EXT_INFO) SSH_MSG_SERVICE_ACCEPT for
    //    "ssh-userauth".
    let mut payload = [0u8; 64];
    let Some(plen) = ssh_wire::service_request_payload(&mut payload) else {
        fatal("SERVICE_REQUEST does not fit the buffer");
    };
    send_sealed(stack, handle, &payload[..plen], &mut tx_dir, seq_tx);
    seq_tx += 1;

    #[derive(PartialEq, Eq)]
    enum SvcStep {
        ExtInfo,
        Accepted,
    }
    loop {
        let (s, e) = recv_enc(stack, handle, &mut enc_rx, &mut rx_dir, seq_rx);
        let step = {
            let bytes = enc_rx.bytes();
            let Some(p) = bytes.get(s..e) else {
                fatal("encrypted payload range out of bounds");
            };
            let Some(&msg) = p.first() else {
                fatal("empty encrypted payload");
            };
            match msg {
                // RFC8308: GitHub may answer our `ext-info-c` signal
                // with EXT_INFO as the first encrypted packet.
                ssh_wire::SSH_MSG_EXT_INFO => {
                    handle_ext_info(p);
                    SvcStep::ExtInfo
                }
                ssh_wire::SSH_MSG_SERVICE_ACCEPT => match ssh_wire::parse_service_accept(p) {
                    Ok(name) if name == b"ssh-userauth" => SvcStep::Accepted,
                    Ok(_) => fatal("SERVICE_ACCEPT names a different service"),
                    Err(err) => {
                        serial_println!("ssh: malformed SERVICE_ACCEPT: {err:?}");
                        crate::halt();
                    }
                },
                other => {
                    serial_println!("ssh: unexpected message {other} before SERVICE_ACCEPT");
                    crate::halt();
                }
            }
        };
        enc_rx.consume();
        seq_rx += 1;
        if step == SvcStep::Accepted {
            break;
        }
    }

    // 9. The `none` auth probe: user "git", method "none" — GitHub
    //    never accepts it, so SSH_MSG_USERAUTH_FAILURE with
    //    partial_success = false IS the success signal (any other
    //    message, especially USERAUTH_SUCCESS, is fatal: something
    //    would be very wrong).
    let mut payload = [0u8; 64];
    let Some(plen) = ssh_wire::userauth_none_payload(&mut payload) else {
        fatal("USERAUTH_REQUEST does not fit the buffer");
    };
    send_sealed(stack, handle, &payload[..plen], &mut tx_dir, seq_tx);
    seq_tx += 1;
    let (s, e) = recv_enc(stack, handle, &mut enc_rx, &mut rx_dir, seq_rx);
    {
        let bytes = enc_rx.bytes();
        let Some(p) = bytes.get(s..e) else {
            fatal("encrypted payload range out of bounds");
        };
        let Some(&msg) = p.first() else {
            fatal("empty encrypted payload");
        };
        match msg {
            52 => fatal("none auth unexpectedly succeeded (SSH_MSG_USERAUTH_SUCCESS)"),
            ssh_wire::SSH_MSG_USERAUTH_FAILURE => {}
            other => {
                serial_println!("ssh: unexpected message {other} during the auth probe");
                crate::halt();
            }
        }
        match ssh_wire::parse_userauth_failure(p) {
            Ok(f) => {
                if f.partial_success {
                    fatal("none auth probe returned partial_success");
                }
                // The offered methods are a wire name-list: sanitize
                // before the macro (evaluates args twice).
                let mut mbuf = [0u8; SANITIZE_CAP];
                let methods = sanitize(f.methods, &mut mbuf);
                serial_println!("ssh: auth methods offered: {methods}");
            }
            Err(err) => {
                serial_println!("ssh: malformed USERAUTH_FAILURE: {err:?}");
                crate::halt();
            }
        }
    }
    enc_rx.consume();
    // Both counters stay live: S3 sends `publickey` requests next, and
    // every packet (bidirectional, encrypted or not) consumes one
    // sequence number (RFC4253 §6.4) — including the `none` answer we
    // just consumed.
    seq_rx += 1;

    if markers {
        // machine-checked by `cargo xtask smoke`
        serial_println!("SSH_KEX_OK");
    }

    // 10. S3: the `publickey` exchange (RFC4252 §7). Boot path: an
    //     ephemeral key → the expected `USERAUTH_FAILURE`. Manual path:
    //     an operator key → `PK_OK` → signed request → `SUCCESS`.
    let mut wire = AuthWire {
        handle,
        tx_dir: &mut tx_dir,
        rx_dir: &mut rx_dir,
        enc_rx: &mut enc_rx,
        seq_tx: &mut seq_tx,
        seq_rx: &mut seq_rx,
    };
    let authenticated = publickey_step(stack, &mut wire, &session_id, &keys);

    // 11. S5: the two-VM sshd proof continues past the auth verdict.
    //     `SSHD_OK` is printed only on the harness path (an `exec`
    //     command was asked for), never on the GitHub paths.
    if let Some(command) = exec {
        if !authenticated {
            fatal("sshd probe: authentication was refused");
        }
        // machine-checked by `cargo xtask smoke-ssh`
        serial_println!("SSHD_OK");
        exec_step(stack, &mut wire, command);
    }

    // 12. Orderly teardown (plain_get_smoke's close proof): FIN, then
    //     require the socket to reach TimeWait or Closed.
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

/// The live wire state of an authenticated phase: per-direction keys,
/// the shared receive buffer and both sequence counters. Grouped so a
/// user-auth step borrows one value instead of six; the counters belong
/// to the connection and are never reset (RFC4253 §6.4).
struct AuthWire<'a, 'b> {
    handle: SocketHandle,
    tx_dir: &'a mut Direction,
    rx_dir: &'a mut Direction,
    enc_rx: &'a mut ssh_wire::EncryptedRx<'b>,
    seq_tx: &'a mut u32,
    seq_rx: &'a mut u32,
}

impl AuthWire<'_, '_> {
    /// Seal and send one payload, advancing the transmit counter.
    fn send(&mut self, stack: &mut Stack, payload: &[u8]) {
        send_sealed(stack, self.handle, payload, self.tx_dir, *self.seq_tx);
        *self.seq_tx += 1;
    }

    /// Receive one user-auth answer, skipping up to [`AUTH_BANNER_MAX`]
    /// `SSH_MSG_USERAUTH_BANNER` packets first (RFC4252 §5.4 lets a
    /// server send them at any point during authentication). Banners
    /// are parsed, printed sanitized and bounded — never treated as an
    /// answer.
    ///
    /// Returns the payload's range in [`Self::bytes`]; the caller reads
    /// it, then calls [`Self::consume`]. The receive counter advances
    /// for **every** packet received, the returned one included.
    fn recv_answer(&mut self, stack: &mut Stack) -> (usize, usize) {
        let mut banners = 0usize;
        loop {
            let (s, e) = recv_enc(stack, self.handle, self.enc_rx, self.rx_dir, *self.seq_rx);
            *self.seq_rx += 1;
            let bytes = self.enc_rx.bytes();
            let Some(p) = bytes.get(s..e) else {
                fatal("encrypted payload range out of bounds");
            };
            let Some(&msg) = p.first() else {
                fatal("empty encrypted payload");
            };
            if msg != ssh_wire::SSH_MSG_USERAUTH_BANNER {
                return (s, e);
            }
            if banners >= AUTH_BANNER_MAX {
                fatal("too many USERAUTH_BANNER packets (auth answer never came)");
            }
            banners += 1;
            match ssh_wire::parse_userauth_banner(p) {
                Ok(banner) => {
                    if !banner.message.is_empty() {
                        // Wire bytes: sanitize before the macro (it
                        // evaluates its arguments twice).
                        let mut sbuf = [0u8; SANITIZE_CAP];
                        let text = sanitize(banner.message, &mut sbuf);
                        serial_println!("ssh: server banner: {text}");
                    }
                }
                Err(err) => {
                    serial_println!("ssh: malformed USERAUTH_BANNER: {err:?}");
                    crate::halt();
                }
            }
            self.enc_rx.consume();
        }
    }

    /// The decrypted payload bytes of the last received packet.
    fn bytes(&self) -> &[u8] {
        self.enc_rx.bytes()
    }

    /// Release the last received packet.
    fn consume(&mut self) {
        self.enc_rx.consume();
    }
}

/// Print an ed25519 public blob and its SHA-256 fingerprint — the only
/// key material that ever reaches the log. `key_blob` is public by
/// construction (RFC4252 §7: the blob is sent on the wire in the clear
/// to every server).
pub(crate) fn print_public_key(prefix: &str, key_blob: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(key_blob);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut fp = [0u8; ssh_wire::FINGERPRINT_LEN];
    let n = match ssh_wire::write_fingerprint(&digest, &mut fp) {
        Some(n) => n,
        None => return, // unreachable: the buffer is the exact size
    };
    let text = core::str::from_utf8(&fp[..n]).unwrap_or("?");

    let mut b64 = [0u8; 96];
    let text64 = match ssh_wire::base64_encode(key_blob, true, &mut b64) {
        Some(m) => core::str::from_utf8(&b64[..m]).unwrap_or("?"),
        None => "?",
    };
    serial_println!("{prefix} ssh-ed25519 {text64} ({text})");
}

/// S3 (docs/git-ssh-deps.md §B.4): probe-then-sign `publickey` auth.
///
/// 1. derive the ed25519 key from the seed ([`AuthKey`]),
/// 2. send the RFC4252 §7 **probe** — `boolean FALSE`, no signature,
/// 3. `SSH_MSG_USERAUTH_PK_OK` → sign `session_id || probe` (the probe
///    bytes are exactly the signed request's prefix, boolean FALSE
///    included — RFC4252 §7) and send the signed request; then
///    `SUCCESS` (authenticated) or `FAILURE` (key registered nowhere),
/// 4. `SSH_MSG_USERAUTH_FAILURE` → the boot path's expected verdict:
///    the request encoding, blob shapes and framing were all accepted
///    by the server, the key is simply not authorized.
///
/// Nothing here halts on a *verdict* — only on a message that is not a
/// legal answer, a `PK_OK` for someone else's key, or an impossible
/// `SUCCESS` without a signature.
fn publickey_step(
    stack: &mut Stack,
    wire: &mut AuthWire<'_, '_>,
    session_id: &[u8; 32],
    keys: &AuthKey,
) -> bool {
    // The seed never outlives this function: `SigningKey` keeps its
    // own copy of the scalar.
    let mut seed = match keys {
        AuthKey::Seed(seed) => *seed,
        AuthKey::Ephemeral => {
            let mut seed = [0u8; 32];
            for chunk in seed.chunks_mut(4) {
                chunk.copy_from_slice(&crate::entropy::boot_entropy().to_le_bytes());
            }
            seed
        }
    };
    let signing = SigningKey::from_bytes(&seed);
    // Best-effort scrub (see `AuthKey`'s docs for what is and is not
    // guaranteed); the `SigningKey` already holds its own copy.
    seed.fill(0);

    let public = signing.verifying_key().to_bytes();
    let mut key_blob = [0u8; ssh_wire::ED25519_KEY_BLOB_LEN];
    let blob_len = match ssh_wire::ed25519_key_blob(&public, &mut key_blob) {
        Some(n) => n,
        None => fatal("public key blob does not fit its buffer"),
    };
    print_public_key("ssh: publickey", &key_blob[..blob_len]);

    // 1. The probe: "would this key be acceptable?" — the bytes the
    //    signed request will sign, minus the session-id prefix.
    let mut probe = [0u8; 256];
    let probe_len = match ssh_wire::userauth_publickey_payload(
        ssh_wire::AUTH_USER,
        &key_blob[..blob_len],
        None,
        &mut probe,
    ) {
        Some(n) => n,
        None => fatal("USERAUTH_REQUEST/publickey probe does not fit"),
    };
    wire.send(stack, &probe[..probe_len]);

    let (s, e) = wire.recv_answer(stack);
    let wants_signature = {
        let bytes = wire.bytes();
        let Some(p) = bytes.get(s..e) else {
            fatal("encrypted payload range out of bounds");
        };
        let Some(&msg) = p.first() else {
            fatal("empty encrypted payload");
        };
        match msg {
            ssh_wire::SSH_MSG_USERAUTH_PK_OK => {
                let ok = match ssh_wire::parse_userauth_pk_ok(p) {
                    Ok(ok) => ok,
                    Err(err) => {
                        serial_println!("ssh: malformed USERAUTH_PK_OK: {err:?}");
                        crate::halt();
                    }
                };
                if ok.key_blob != key_blob.get(..blob_len).unwrap_or(&[]) {
                    // The server answered about a key we did not send:
                    // refuse to sign anything for it.
                    fatal("USERAUTH_PK_OK echoes a different public key");
                }
                serial_println!("ssh: server accepts the public key (PK_OK), signing");
                true
            }
            ssh_wire::SSH_MSG_USERAUTH_FAILURE => {
                match ssh_wire::parse_userauth_failure(p) {
                    Ok(f) => {
                        if f.partial_success {
                            fatal("publickey probe returned partial_success");
                        }
                        let mut mbuf = [0u8; SANITIZE_CAP];
                        let methods = sanitize(f.methods, &mut mbuf);
                        serial_println!("ssh: auth methods offered: {methods}");
                    }
                    Err(err) => {
                        serial_println!("ssh: malformed USERAUTH_FAILURE: {err:?}");
                        crate::halt();
                    }
                }
                false
            }
            ssh_wire::SSH_MSG_USERAUTH_SUCCESS => {
                fatal("publickey probe succeeded without a signature (impossible)")
            }
            other => {
                serial_println!("ssh: unexpected message {other} during publickey auth");
                crate::halt();
            }
        }
    };
    wire.consume();

    if !wants_signature {
        // The expected boot outcome: the encoding was accepted, the key
        // is not registered on any account. Not an error — and not a
        // marker (the chain stays at 29; see docs/git-ssh-deps.md
        // §B.4 row S3).
        serial_println!("ssh: publickey refused (key not registered on the account)");
        return false;
    }

    // 2. The signed request: ed25519 over `session_id || request`
    //    where `request` is the signed form (boolean TRUE) with its
    //    signature field omitted — RFC4252 §7. Signing the probe
    //    (boolean FALSE) is *not* what the RFC specifies and no server
    //    accepts it; `userauth_signed_prefix` builds the exact bytes.
    let mut prefix = [0u8; 256];
    let prefix_len = match ssh_wire::userauth_signed_prefix(
        ssh_wire::AUTH_USER,
        &key_blob[..blob_len],
        &mut prefix,
    ) {
        Some(n) => n,
        None => fatal("signed-request prefix does not fit"),
    };
    let mut signed = [0u8; 256];
    let signed_len =
        match ssh_wire::userauth_signed_data(session_id, &prefix[..prefix_len], &mut signed) {
            Some(n) => n,
            None => fatal("signed-data buffer is too small"),
        };
    let signature = signing.sign(&signed[..signed_len]);
    let mut sig_blob = [0u8; ssh_wire::ED25519_SIG_BLOB_LEN];
    let sig_len = match ssh_wire::ed25519_signature_blob(&signature.to_bytes(), &mut sig_blob) {
        Some(n) => n,
        None => fatal("signature blob does not fit its buffer"),
    };
    let mut request = [0u8; 512];
    let request_len = match ssh_wire::userauth_publickey_payload(
        ssh_wire::AUTH_USER,
        &key_blob[..blob_len],
        Some(&sig_blob[..sig_len]),
        &mut request,
    ) {
        Some(n) => n,
        None => fatal("signed USERAUTH_REQUEST does not fit"),
    };
    wire.send(stack, &request[..request_len]);

    let (s, e) = wire.recv_answer(stack);
    let mut ok = false;
    {
        let bytes = wire.bytes();
        let Some(p) = bytes.get(s..e) else {
            fatal("encrypted payload range out of bounds");
        };
        let Some(&msg) = p.first() else {
            fatal("empty encrypted payload");
        };
        match msg {
            ssh_wire::SSH_MSG_USERAUTH_SUCCESS => {
                if let Err(err) = ssh_wire::parse_userauth_success(p) {
                    serial_println!("ssh: malformed USERAUTH_SUCCESS: {err:?}");
                    crate::halt();
                }
                serial_println!("ssh: authenticated with publickey (ssh-ed25519)");
                ok = true;
            }
            ssh_wire::SSH_MSG_USERAUTH_FAILURE => {
                // A registered-but-unauthorized key, or GitHub's
                // attempt limit: the crypto path is correct either way.
                match ssh_wire::parse_userauth_failure(p) {
                    Ok(f) => {
                        if f.partial_success {
                            fatal("signed publickey request returned partial_success");
                        }
                        let mut mbuf = [0u8; SANITIZE_CAP];
                        let methods = sanitize(f.methods, &mut mbuf);
                        serial_println!("ssh: auth methods offered: {methods}");
                    }
                    Err(err) => {
                        serial_println!("ssh: malformed USERAUTH_FAILURE: {err:?}");
                        crate::halt();
                    }
                }
                serial_println!("ssh: signed publickey request refused");
            }
            other => {
                serial_println!("ssh: unexpected message {other} after the signed request");
                crate::halt();
            }
        }
    }
    wire.consume();
    ok
}

/// S5b (docs/git-ssh-deps.md §B.4 row S5): the harness' `exec` leg.
/// Open a `session` channel, send `exec <command>`, collect the
/// returned channel data (bounded), read `exit-status` and the close,
/// then print the output and the `SSHD_EXEC_OK` marker **only when**
/// the expected token came back with status 0. Any other shape is
/// fail-closed (`FATAL`) — this leg exists to prove bytes crossed the
/// channel, not to be lenient about what crossed it.
fn exec_step(stack: &mut Stack, wire: &mut AuthWire<'_, '_>, command: &[u8]) {
    /// Our sender channel id (the only client channel we open).
    const CLIENT_CHANNEL: u32 = 0;
    const WINDOW: u32 = 64 * 1024;
    const MAX_PACKET: u32 = 32 * 1024;
    const OUT_CAP: usize = 1024;

    let mut buf = [0u8; 512];
    let n = match ssh_wire::channel_open_session_payload(
        CLIENT_CHANNEL,
        WINDOW,
        MAX_PACKET,
        &mut buf,
    ) {
        Some(n) => n,
        None => fatal("CHANNEL_OPEN does not fit the buffer"),
    };
    wire.send(stack, &buf[..n]);

    let (s, e) = wire.recv_answer(stack);
    let server_channel = {
        let bytes = wire.bytes();
        let Some(p) = bytes.get(s..e) else {
            fatal("channel payload range out of bounds");
        };
        let Some(&msg) = p.first() else {
            fatal("empty channel payload");
        };
        match msg {
            ssh_wire::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                let conf = match ssh_wire::parse_channel_open_confirmation(p) {
                    Ok(conf) => conf,
                    Err(err) => {
                        serial_println!("ssh: malformed CHANNEL_OPEN_CONFIRMATION: {err:?}");
                        crate::halt();
                    }
                };
                if conf.recipient_channel != CLIENT_CHANNEL {
                    fatal("CHANNEL_OPEN_CONFIRMATION names another channel");
                }
                serial_println!(
                    "ssh: session channel open (server channel {})",
                    conf.sender_channel
                );
                conf.sender_channel
            }
            ssh_wire::SSH_MSG_CHANNEL_OPEN_FAILURE => fatal("server refused the session channel"),
            other => {
                serial_println!("ssh: unexpected message {other} for CHANNEL_OPEN");
                crate::halt();
            }
        }
    };
    wire.consume();

    let n = match ssh_wire::channel_request_exec_payload(server_channel, command, true, &mut buf) {
        Some(n) => n,
        None => fatal("exec CHANNEL_REQUEST does not fit the buffer"),
    };
    wire.send(stack, &buf[..n]);

    let mut out = [0u8; OUT_CAP];
    let mut out_len = 0usize;
    let mut exit_status = None;
    loop {
        let (s, e) = wire.recv_answer(stack);
        let close = {
            let bytes = wire.bytes();
            let Some(p) = bytes.get(s..e) else {
                fatal("channel payload range out of bounds");
            };
            let Some(&msg) = p.first() else {
                fatal("empty channel payload");
            };
            match msg {
                ssh_wire::SSH_MSG_CHANNEL_SUCCESS => {
                    let channel = match ssh_wire::parse_channel_number(
                        p,
                        ssh_wire::SSH_MSG_CHANNEL_SUCCESS,
                    ) {
                        Ok(channel) => channel,
                        Err(err) => {
                            serial_println!("ssh: malformed CHANNEL_SUCCESS: {err:?}");
                            crate::halt();
                        }
                    };
                    if channel != server_channel {
                        fatal("CHANNEL_SUCCESS names another channel");
                    }
                    serial_println!("ssh: exec request accepted");
                    false
                }
                ssh_wire::SSH_MSG_CHANNEL_FAILURE => fatal("server refused the exec request"),
                ssh_wire::SSH_MSG_CHANNEL_DATA => {
                    let (channel, data) = match ssh_wire::parse_channel_data(p) {
                        Ok(pair) => pair,
                        Err(err) => {
                            serial_println!("ssh: malformed CHANNEL_DATA: {err:?}");
                            crate::halt();
                        }
                    };
                    if channel != server_channel {
                        fatal("CHANNEL_DATA names another channel");
                    }
                    let Some(space) = out.get_mut(out_len..out_len + data.len()) else {
                        fatal("exec output exceeds the receive buffer");
                    };
                    space.copy_from_slice(data);
                    out_len += data.len();
                    false
                }
                ssh_wire::SSH_MSG_CHANNEL_EOF => false,
                ssh_wire::SSH_MSG_CHANNEL_WINDOW_ADJUST => false,
                ssh_wire::SSH_MSG_CHANNEL_REQUEST => match ssh_wire::parse_channel_exit_status(p) {
                    Ok((channel, status)) if channel == server_channel => {
                        exit_status = Some(status);
                        false
                    }
                    Ok(_) => fatal("exit-status names another channel"),
                    Err(err) => {
                        serial_println!("ssh: malformed channel request: {err:?}");
                        crate::halt();
                    }
                },
                ssh_wire::SSH_MSG_CHANNEL_CLOSE => true,
                other => {
                    serial_println!("ssh: unexpected message {other} on the session channel");
                    crate::halt();
                }
            }
        };
        wire.consume();
        if close {
            // RFC4254 §5.3: answer the peer's close with ours.
            let n = match ssh_wire::channel_number_payload(
                ssh_wire::SSH_MSG_CHANNEL_CLOSE,
                server_channel,
                &mut buf,
            ) {
                Some(n) => n,
                None => fatal("CHANNEL_CLOSE does not fit the buffer"),
            };
            wire.send(stack, &buf[..n]);
            break;
        }
    }

    let mut sbuf = [0u8; SANITIZE_CAP];
    let text = sanitize(&out[..out_len], &mut sbuf);
    serial_println!("ssh: exec output: {text}");
    match exit_status {
        Some(0) => {}
        Some(status) => {
            serial_println!("ssh: exec exit-status {status}");
            crate::halt();
        }
        None => fatal("exec closed without an exit-status"),
    }
    if !out[..out_len]
        .windows(b"SSHD_EXEC_OK".len())
        .any(|w| w == b"SSHD_EXEC_OK")
    {
        fatal("exec output does not contain SSHD_EXEC_OK");
    }
    // machine-checked by `cargo xtask smoke-ssh`
    serial_println!("SSHD_EXEC_OK");
}
